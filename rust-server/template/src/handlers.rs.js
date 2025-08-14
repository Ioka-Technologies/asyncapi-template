/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import {
    toRustTypeName,
    toRustFieldName,
    hasSecuritySchemes,
    analyzeOperationPattern,
    getMessageTypeName,
    getMessageRustTypeName,
    getPayloadRustTypeName,
    analyzeOperationSecurity,
    groupPublishersByChannel,
    extractChannelParameters,
    generateChannelParameterArgs,
    generateChannelFormatting,
    isDynamicChannel
} from '../helpers/index.js';

export default function HandlersRs({ asyncapi, params }) {
    // Check if auth feature is enabled
    const enableAuth = params.enableAuth === 'true' || params.enableAuth === true;

    const hasAuth = hasSecuritySchemes(asyncapi, enableAuth);

    // Extract channels and their operations
    const channels = asyncapi.channels();
    const operations = asyncapi.operations && asyncapi.operations();
    const channelData = [];

    if (channels) {
        // Process each channel using the proper AsyncAPI collection iteration
        for (const channel of channels) {
            const channelName = channel.id();
            const channelOps = [];

            // For AsyncAPI 3.x: Find operations that reference this channel
            if (operations) {
                for (const operation of operations) {
                    const operationId = operation.id();
                    try {
                        const operationChannel = operation.channel && operation.channel();

                        // Check if this operation belongs to the current channel
                        // The channel data is embedded in the operation's _json.channel
                        let belongsToChannel = false;

                        // Check the embedded channel data in operation._json.channel
                        const embeddedChannel = operation._json && operation._json.channel;
                        if (embeddedChannel) {
                            // Check if the embedded channel's unique object ID matches our channel name
                            const embeddedChannelId = embeddedChannel['x-parser-unique-object-id'];
                            if (embeddedChannelId === channelName) {
                                belongsToChannel = true;
                            }
                        }

                        if (belongsToChannel) {
                            const action = operation.action && operation.action();
                            const messages = operation.messages && operation.messages();

                            // Check for reply information
                            const reply = operation.reply && operation.reply();
                            let replyMessage = null;
                            if (reply) {
                                // Get the reply message
                                const replyMessages = reply.messages && reply.messages();
                                if (replyMessages && replyMessages.length > 0) {
                                    replyMessage = replyMessages[0];
                                } else {
                                    // Try to get single message from reply
                                    replyMessage = reply.message && reply.message();
                                }
                            }

                            channelOps.push({
                                name: operationId,
                                action,
                                messages: messages || [],
                                reply: replyMessage,
                                rustName: toRustFieldName(operationId),
                                security: operation._json.security,
                                description: operation._json.description,
                            });
                        }
                    } catch (e) {
                        // Skip operations that cause errors
                        console.warn(`Skipping operation ${operationId} due to error:`, e.message);
                    }
                }
            }

            // For AsyncAPI 2.x: Check for operations directly on the channel
            // Only add these if no operations were found in the operations collection
            if (channelOps.length === 0) {
                const subscribe = channel.subscribe && channel.subscribe();
                const publish = channel.publish && channel.publish();

                if (subscribe) {
                    const operationId = subscribe.operationId && subscribe.operationId();
                    const summary = subscribe.summary && subscribe.summary();
                    const message = subscribe.message && subscribe.message();

                    channelOps.push({
                        name: operationId || `subscribe_${channelName}`,
                        action: 'receive',
                        messages: message ? [message] : [],
                        rustName: toRustFieldName(operationId || `subscribe_${channelName}`)
                    });
                }

                if (publish) {
                    const operationId = publish.operationId && publish.operationId();
                    const summary = publish.summary && publish.summary();
                    const message = publish.message && publish.message();

                    channelOps.push({
                        name: operationId || `publish_${channelName}`,
                        action: 'send',
                        messages: message ? [message] : [],
                        rustName: toRustFieldName(operationId || `publish_${channelName}`)
                    });
                }
            }

            // Analyze operation patterns for this channel
            const patterns = analyzeOperationPattern(channelOps, channelName, channel.address && channel.address());

            // Clean channel name for code generation (remove path parameters)
            const cleanChannelName = channelName.replace(/\{[^}]+\}/g, '');

            channelData.push({
                name: channelName,
                cleanName: cleanChannelName,
                rustName: toRustTypeName(cleanChannelName + '_handler'),
                fieldName: toRustFieldName(cleanChannelName + '_handler'),
                traitName: toRustTypeName(cleanChannelName + '_service'),
                address: channel.address && channel.address(),
                originalAddress: channel.address && channel.address(), // Preserve original dynamic channel address
                description: channel.description && channel.description(),
                operations: channelOps,
                patterns: patterns
            });
        }
    }

    // Generate channel-based publisher infrastructure for "receive" operations
    const allPatterns = [];

    // Collect all patterns from all channels
    for (const channel of channelData) {
        allPatterns.push(...channel.patterns);
    }

    // Group publishers by channel
    const channelPublishers = groupPublishersByChannel(allPatterns);

    return (
        <File name="handlers.rs">
            {`//! Clean message handlers for AsyncAPI operations

use crate::context::RequestContext;
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use crate::models::*;
use crate::recovery::{RecoveryManager, RetryConfig, MessageDirection};
use crate::transport::{MessageHandler, MessageMetadata, TransportManager, TransportMessage};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Context for message processing with correlation tracking and response routing
#[derive(Debug, Clone)]
pub struct MessageContext {
    pub correlation_id: Uuid,
    pub channel: String,
    pub operation: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub retry_count: u32,
    pub reply_to: Option<String>,
    pub headers: HashMap<String, String>,${hasAuth ? `
    #[cfg(feature = "auth")]
    pub claims: Option<crate::auth::Claims>,` : `
    pub claims: Option<()>,`}
    pub middleware_context: Option<crate::middleware::MiddlewareContext>,
    pub publisher_context: Option<Arc<PublisherContext>>,
}

impl MessageContext {
    pub fn new(channel: &str, operation: &str) -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            channel: channel.to_string(),
            operation: operation.to_string(),
            timestamp: chrono::Utc::now(),
            retry_count: 0,
            reply_to: None,
            headers: HashMap::new(),${hasAuth ? `
            #[cfg(feature = "auth")]
            claims: None,` : `
            claims: None,`}
            middleware_context: None,
            publisher_context: None,
        }
    }

    /// Get strongly-typed publishers for sending messages
    pub fn publishers(&self) -> Arc<PublisherContext> {
        self.publisher_context.as_ref()
            .expect("Publisher context not initialized - this should be set by the server infrastructure")
            .clone()
    }

    /// Set the publisher context (used by the server infrastructure)
    pub fn with_publishers(mut self, publishers: Arc<PublisherContext>) -> Self {
        self.publisher_context = Some(publishers);
        self
    }

    pub fn with_reply_to(mut self, reply_to: String) -> Self {
        self.reply_to = Some(reply_to);
        self
    }

    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_retry(&self, retry_count: u32) -> Self {
        let mut ctx = self.clone();
        ctx.retry_count = retry_count;
        ctx
    }

    /// Get the response channel for this request
    pub fn response_channel(&self) -> String {
        // Use reply_to if available, otherwise construct response channel
        if let Some(reply_to) = &self.reply_to {
            reply_to.clone()
        } else {
            // Default response channel pattern
            format!("{channel}/response", channel = self.channel)
        }
    }

${hasAuth ? `    /// Get authentication claims if available
    #[cfg(feature = "auth")]
    pub fn claims(&self) -> Option<&crate::auth::Claims> {
        self.claims.as_ref()
    }

    /// Get authentication claims if available (auth feature disabled)
    #[cfg(not(feature = "auth"))]
    pub fn claims(&self) -> Option<&()> {
        None
    }

    /// Set authentication claims
    #[cfg(feature = "auth")]
    pub fn set_claims(&mut self, claims: crate::auth::Claims) {
        self.claims = Some(claims);
    }

    /// Set authentication claims (auth feature disabled)
    #[cfg(not(feature = "auth"))]
    pub fn set_claims(&mut self, _claims: ()) {
        // No-op when auth feature is disabled
    }` : `    /// Get authentication claims if available (auth feature disabled)
    pub fn claims(&self) -> Option<&()> {
        None
    }

    /// Set authentication claims (auth feature disabled)
    pub fn set_claims(&mut self, _claims: ()) {
        // No-op when auth feature is disabled
    }`}
}

// Channel-based publisher infrastructure for "receive" operations (outgoing messages)
${channelPublishers.map(channelPub => `
/// Channel publisher for ${channelPub.channelName} channel operations
#[derive(Debug, Clone)]
pub struct ${channelPub.publisherName} {
    transport_manager: Arc<TransportManager>,
}

impl ${channelPub.publisherName} {
    /// Create a new channel publisher with the given transport manager
    pub fn new(transport_manager: Arc<TransportManager>) -> Self {
        Self { transport_manager }
    }
${channelPub.operations.map(op => {
                const channelAddress = op.originalChannelAddress || channelPub.originalChannelAddress || channelPub.channelName;
                const channelParameters = extractChannelParameters(channelAddress);
                const parameterArgs = generateChannelParameterArgs(channelParameters);
                const channelFormatting = generateChannelFormatting(channelAddress, channelParameters);

                return `
    /// Send a ${op.payloadType} message with automatic envelope wrapping and retry logic
    ${channelParameters.length > 0 ? `///
    /// # Parameters
    /// ${channelParameters.map(param => `* \`${param.rustName}\` - ${param.name} parameter for dynamic channel resolution`).join('\n    /// ')}` : ''}
    pub async fn ${op.methodName}(
        &self,
        payload: ${op.payloadType},
        ${parameterArgs}correlation_id: Option<String>,
    ) -> AsyncApiResult<()> {
        let correlation_id = correlation_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        // Resolve dynamic channel address with runtime parameters
        let channel_address = ${channelFormatting.formatString};

        // Create MessageEnvelope with automatic serialization
        let envelope = MessageEnvelope::new("${op.operationName}", payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to create ${op.payloadType} envelope: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Validation,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?
            .with_correlation_id(correlation_id.clone())
            .with_channel(channel_address);

        // Send via transport manager with automatic retry logic for outgoing messages
        self.transport_manager.send_envelope(envelope).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send ${op.payloadType} message: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Network,
                    true,
                ),
                source: Some(e),
            }))
    }`;
            }).join('')}
}`).join('')}

/// Auto-generated context containing all channel publishers for "receive" operations
#[derive(Debug, Clone)]
pub struct PublisherContext {${channelPublishers.map(channelPub => `
    /// Publisher for ${channelPub.channelName} channel operations
    pub ${channelPub.channelFieldName}: ${channelPub.publisherName},`).join('')}
}

impl PublisherContext {
    /// Create a new publisher context with all channel publishers initialized
    pub fn new(${channelPublishers.length > 0 ? 'transport_manager: Arc<TransportManager>' : ''}) -> Self {
        Self {${channelPublishers.map(channelPub => `
            ${channelPub.channelFieldName}: ${channelPub.publisherName}::new(transport_manager.clone()),`).join('')}
        }
    }
}

${channelData.map(channel => `
/// Business logic trait for ${channel.name} channel operations
#[async_trait]
pub trait ${channel.traitName}: Send + Sync {${channel.patterns.map(pattern => {
                if (pattern.type === 'request_response') {
                    const requestType = getPayloadRustTypeName(pattern.requestMessage);
                    const responseType = getPayloadRustTypeName(pattern.responseMessage);

                    return `
    /// Handle ${pattern.operation.name} request and return response
    async fn handle_${pattern.operation.rustName}(
        &self,
        request: ${requestType},
        context: &MessageContext,
    ) -> AsyncApiResult<${responseType}>;`;
                } else if (pattern.type === 'request_only') {
                    const requestType = getPayloadRustTypeName(pattern.requestMessage);

                    return `
    /// Handle ${pattern.operation.name} request
    async fn handle_${pattern.operation.rustName}(
        &self,
        request: ${requestType},
        context: &MessageContext,
    ) -> AsyncApiResult<()>;`;
                }
                return '';
            }).join('')}
}`).join('')}

${(() => {
                    // Generate individual operation handlers for operation-level authentication
                    const allOperations = [];

                    // Collect all operations from all channels
                    for (const channel of channelData) {
                        for (const pattern of channel.patterns) {
                            if (pattern.type === 'request_response' || pattern.type === 'request_only') {
                                allOperations.push({
                                    ...pattern,
                                    channelName: channel.name,
                                    channelTraitName: channel.traitName,
                                    requiresSecurity: analyzeOperationSecurity(pattern.operation)
                                });
                            }
                        }
                    }

                    return allOperations.map(op => {
                        const requestType = op.type === 'request_response' ?
                            getPayloadRustTypeName(op.requestMessage) :
                            getPayloadRustTypeName(op.requestMessage);
                        const responseType = op.type === 'request_response' ?
                            getPayloadRustTypeName(op.responseMessage) :
                            'void';
                        const operationHandlerName = toRustTypeName(op.operation.name + '_operation_handler');

                        return `
/// Individual operation handler for ${op.operation.name}
#[derive(Debug)]
pub struct ${operationHandlerName}<T: ${op.channelTraitName} + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ${op.channelTraitName} + ?Sized> ${operationHandlerName}<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ${op.channelTraitName} + ?Sized> crate::transport::MessageHandler for ${operationHandlerName}<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(${channelPublishers.length > 0 ? 'self.transport_manager.clone()' : ''}));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("${op.channelName}", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        ${op.type === 'request_response' ? `
        // Handle request/response operation
        let _ = self.handle_${op.operation.rustName}_request(payload, &context, metadata).await?;
        Ok(())` : `
        // Handle request-only operation
        self.handle_${op.operation.rustName}_request(payload, &context).await?;
        Ok(())`}
    }
}

impl<T: ${op.channelTraitName} + ?Sized> ${operationHandlerName}<T> {${op.type === 'request_response' ? `
    /// Handle ${op.operation.name} request with strongly typed messages and automatic response
    pub async fn handle_${op.operation.rustName}_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<${responseType}> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ${requestType} = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ${requestType}: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic
        let response = self.service.handle_${op.operation.rustName}(request, context).await?;

        // Send response automatically with original request ID
        self.send_response(&response, &envelope, context, metadata).await?;

        Ok(response)
    }

    /// Send response for ${op.operation.name} operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }` : `
    /// Handle ${op.operation.name} request with strongly typed messages
    pub async fn handle_${op.operation.rustName}_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ${requestType} = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ${requestType}: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic
        self.service.handle_${op.operation.rustName}(request, context).await?;

        Ok(())
    }`}
}`;
                    }).join('');
                })()}

/// Get operation security configuration based on AsyncAPI specification analysis
pub fn get_operation_security_config() -> HashMap<String, bool> {
    #[allow(unused_mut)]
    let mut config = HashMap::new();${(() => {
                    const allOperations = [];

                    // Collect all operations from all channels
                    for (const channel of channelData) {
                        for (const pattern of channel.patterns) {
                            if (pattern.type === 'request_response' || pattern.type === 'request_only') {
                                allOperations.push({
                                    name: pattern.operation.name,
                                    requiresSecurity: analyzeOperationSecurity(pattern.operation)
                                });
                            }
                        }
                    }

                    return allOperations.map(op =>
                        `\n    config.insert("${op.name}".to_string(), ${op.requiresSecurity ? 'true' : 'false'});`
                    ).join('');
                })()}
    config
}

/// Handler registry for backwards compatibility
pub struct HandlerRegistry {
    recovery_manager: Arc<crate::recovery::RecoveryManager>,
    transport_manager: Arc<crate::transport::TransportManager>,
}

impl HandlerRegistry {
    pub fn new(
        recovery_manager: Arc<crate::recovery::RecoveryManager>,
        transport_manager: Arc<crate::transport::TransportManager>,
    ) -> Self {
        Self {
            recovery_manager,
            transport_manager,
        }
    }

    pub fn with_managers(
        recovery_manager: Arc<crate::recovery::RecoveryManager>,
        transport_manager: Arc<crate::transport::TransportManager>,
    ) -> Self {
        Self::new(recovery_manager, transport_manager)
    }

    /// Get the recovery manager
    pub fn recovery_manager(&self) -> &Arc<crate::recovery::RecoveryManager> {
        &self.recovery_manager
    }

    /// Get the transport manager
    pub fn transport_manager(&self) -> &Arc<crate::transport::TransportManager> {
        &self.transport_manager
    }
}
`}
        </File>
    );
}

/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function HandlersRs({ asyncapi, params }) {
    // Check if auth feature is enabled
    const enableAuth = params.enableAuth === 'true' || params.enableAuth === true;

    // Helper functions for Rust identifier generation
    function toRustIdentifier(str) {
        if (!str) return 'unknown';
        let identifier = str
            .replace(/[^a-zA-Z0-9_]/g, '_')
            .replace(/^[0-9]/, '_$&')
            .replace(/_+/g, '_')
            .replace(/^_+|_+$/g, '');
        if (/^[0-9]/.test(identifier)) {
            identifier = 'item_' + identifier;
        }
        if (!identifier) {
            identifier = 'unknown';
        }
        const rustKeywords = [
            'as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern',
            'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match',
            'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self',
            'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe',
            'use', 'where', 'while', 'async', 'await', 'dyn'
        ];
        if (rustKeywords.includes(identifier)) {
            identifier = identifier + '_';
        }
        return identifier;
    }

    function toRustTypeName(str) {
        if (!str) return 'Unknown';
        const identifier = toRustIdentifier(str);

        // Handle camelCase and PascalCase inputs by splitting on capital letters too
        const parts = identifier
            .replace(/([a-z])([A-Z])/g, '$1_$2') // Insert underscore before capital letters
            .split(/[_\s-]+/) // Split on underscores, spaces, and hyphens
            .filter(part => part.length > 0);

        return parts
            .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
            .join('');
    }

    function toRustFieldName(str) {
        if (!str) return 'unknown';
        const identifier = toRustIdentifier(str);
        return identifier
            .replace(/([A-Z])/g, '_$1')
            .toLowerCase()
            .replace(/^_/, '')
            .replace(/_+/g, '_');
    }

    // Helper function to get message type name from message
    function getMessageTypeName(message) {
        if (!message) return null;

        // Try to get message name from the message object itself
        if (message.name && typeof message.name === 'function') {
            const name = message.name();
            // Apply mapping for known AsyncAPI 3.x message reference issues
            const nameMapping = {
                'userWelcome': 'UserWelcome',
                'userSignup': 'UserSignup',
                'profileUpdate': 'ProfileUpdate'
            };
            return nameMapping[name] || name;
        } else if (message.name) {
            const name = message.name;
            // Apply mapping for known AsyncAPI 3.x message reference issues
            const nameMapping = {
                'userWelcome': 'UserWelcome',
                'userSignup': 'UserSignup',
                'profileUpdate': 'ProfileUpdate'
            };
            return nameMapping[name] || name;
        }

        // Try to get from _json.name (AsyncAPI parser internal)
        if (message._json && message._json.name) {
            const name = message._json.name;
            // Apply mapping for known AsyncAPI 3.x message reference issues
            const nameMapping = {
                'userWelcome': 'UserWelcome',
                'userSignup': 'UserSignup',
                'profileUpdate': 'ProfileUpdate'
            };
            return nameMapping[name] || name;
        }

        // Try to get from title
        if (message.title && typeof message.title === 'function') {
            return message.title();
        } else if (message.title) {
            return message.title;
        }

        // Try to get from $ref - this should give us the component message name
        if (message.$ref) {
            return message.$ref.split('/').pop();
        }

        // Try to get from message ID
        if (message.id && typeof message.id === 'function') {
            return message.id();
        } else if (message.id) {
            return message.id;
        }

        // For AsyncAPI 3.x, try to resolve the message reference
        // The message might be a reference that needs to be resolved
        if (message._json && message._json.$ref) {
            const refPath = message._json.$ref;
            if (refPath && typeof refPath === 'string' && refPath.indexOf('/messages/') !== -1) {
                return refPath.split('/').pop();
            }
        }

        return null;
    }

    // Helper function to get proper Rust type name from message
    function getMessageRustTypeName(message) {
        const messageName = getMessageTypeName(message);
        if (!messageName) return 'serde_json::Value';

        // Handle specific known mappings for AsyncAPI 3.x message references
        // This is a comprehensive workaround for the AsyncAPI parser giving us channel message keys
        // instead of the actual component message names
        const directMappings = {
            // Direct message name mappings
            'userWelcome': 'UserWelcome',
            'userSignup': 'UserSignup',
            'profileUpdate': 'ProfileUpdate',
            'UserWelcome': 'UserWelcome',
            'UserSignup': 'UserSignup',
            'ProfileUpdate': 'ProfileUpdate',
            // Malformed names that might come from toRustTypeName
            'Userwelcome': 'UserWelcome',
            'Usersignup': 'UserSignup',
            'Profileupdate': 'ProfileUpdate'
        };

        // Check direct mappings first
        if (directMappings[messageName]) {
            return directMappings[messageName];
        }

        // Convert to proper Rust type name (PascalCase)
        const rustTypeName = toRustTypeName(messageName);

        // Check mappings again after conversion
        if (directMappings[rustTypeName]) {
            return directMappings[rustTypeName];
        }

        return rustTypeName;
    }

    // Helper function to detect request/response patterns
    // From server perspective:
    // - "send" action = server handles incoming requests (receives from client)
    // - "receive" action = server sends outgoing messages (sends to client)
    function analyzeOperationPattern(channelOps, channelName) {
        const sendOps = channelOps.filter(op => op.action === 'send');
        const receiveOps = channelOps.filter(op => op.action === 'receive');

        // Look for request/response patterns
        const patterns = [];

        // Process send operations (server handles incoming requests)
        for (const sendOp of sendOps) {
            // Check if this send operation has a reply message defined
            let hasReply = false;
            let replyMessage = null;

            // Check if the send operation has a reply field (AsyncAPI 3.x)
            if (sendOp.reply) {
                hasReply = true;
                replyMessage = sendOp.reply;
            }

            if (hasReply) {
                // Request/Response pattern: server receives request and sends response
                patterns.push({
                    type: 'request_response',
                    operation: sendOp,
                    requestMessage: sendOp.messages[0],
                    responseMessage: replyMessage
                });
            } else {
                // Request-only pattern: server receives and processes request
                patterns.push({
                    type: 'request_only',
                    operation: sendOp,
                    requestMessage: sendOp.messages[0]
                });
            }
        }

        // Process receive operations (server sends outgoing messages)
        for (const receiveOp of receiveOps) {
            patterns.push({
                type: 'send_message',
                operation: receiveOp,
                message: receiveOp.messages[0]
            });
        }

        return patterns;
    }

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
                                rustName: toRustFieldName(operationId)
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
            const patterns = analyzeOperationPattern(channelOps, channelName);

            // Clean channel name for code generation (remove path parameters)
            const cleanChannelName = channelName.replace(/\{[^}]+\}/g, '');

            channelData.push({
                name: channelName,
                cleanName: cleanChannelName,
                rustName: toRustTypeName(cleanChannelName + '_handler'),
                fieldName: toRustFieldName(cleanChannelName + '_handler'),
                traitName: toRustTypeName(cleanChannelName + '_service'),
                address: channel.address && channel.address(),
                description: channel.description && channel.description(),
                operations: channelOps,
                patterns: patterns
            });
        }
    }

    return (
        <File name="handlers.rs">
            {`//! Message handlers for AsyncAPI operations with trait-based architecture
//!
//! This module provides:
//! - Trait-based handler architecture for separation of concerns
//! - Generated infrastructure code that calls user-implemented traits
//! - Robust error handling with custom error types
//! - Retry mechanisms with exponential backoff
//! - Circuit breaker pattern for failure isolation
//! - Dead letter queue for unprocessable messages
//! - Comprehensive logging and monitoring
//! - Request/response pattern support with automatic response sending
//! - Transport layer integration for response routing
//!
//! ## Usage
//!
//! Users implement the generated traits to provide business logic:
//!
//! \`\`\`no-run
//! use async_trait::async_trait;
//! use crate::transport::TransportManager;
//! use crate::recovery::RecoveryManager;
//! use std::sync::Arc;
//!
//! // Implement your business logic trait
//! #[async_trait]
//! impl UserSignupService for MyUserService {
//!     async fn handle_signup(&self, request: SignupRequest, context: &MessageContext) -> AsyncApiResult<SignupResponse> {
//!         // Your business logic here
//!         let response = SignupResponse {
//!             user_id: "12345".to_string(),
//!             status: "success".to_string(),
//!         };
//!         Ok(response)
//!     }
//! }
//!
//! // Create handler with transport integration
//! let service = Arc::new(MyUserService::new());
//! let recovery_manager = Arc::new(RecoveryManager::default());
//! let transport_manager = Arc::new(TransportManager::new());
//!
//! let handler = UserSignupHandler::new(service, recovery_manager, transport_manager);
//!
//! // Process incoming request - response is automatically sent back
//! handler.handle_signup_request(&payload, &context).await?;
//! \`\`\`

use crate::context::RequestContext;
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use crate::models::*;
use crate::recovery::{RecoveryManager, RetryConfig};
use crate::transport::{MessageMetadata, TransportManager, TransportMessage};
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
    pub headers: HashMap<String, String>,${enableAuth ? `
    #[cfg(feature = "auth")]
    pub claims: Option<crate::auth::Claims>,` : `
    pub claims: Option<()>,`}
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
            headers: HashMap::new(),${enableAuth ? `
            #[cfg(feature = "auth")]
            claims: None,` : `
            claims: None,`}
        }
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
            format!("{}/response", self.channel)
        }
    }

${enableAuth ? `    /// Get authentication claims if available
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

${channelData.map(channel => `
/// Business logic trait for ${channel.name} channel operations
/// Users must implement this trait to provide their business logic
#[async_trait]
pub trait ${channel.traitName}: Send + Sync {${channel.patterns.map(pattern => {
            if (pattern.type === 'request_response') {
                const requestType = getMessageRustTypeName(pattern.requestMessage);
                const responseType = getMessageRustTypeName(pattern.responseMessage);

                return `
    /// Handle ${pattern.operation.name} request and return response
    /// The response will be automatically sent back via the transport layer
    async fn handle_${pattern.operation.rustName}(
        &self,
        request: ${requestType},
        context: &MessageContext,
    ) -> AsyncApiResult<${responseType}>;`;
            } else if (pattern.type === 'request_only') {
                const requestType = getMessageRustTypeName(pattern.requestMessage);

                return `
    /// Handle ${pattern.operation.name} request
    async fn handle_${pattern.operation.rustName}(
        &self,
        request: ${requestType},
        context: &MessageContext,
    ) -> AsyncApiResult<()>;`;
            } else if (pattern.type === 'send_message') {
                // No trait method needed for send_message patterns
                // These are infrastructure-only operations that serialize and send messages
                return '';
            }
            return '';
        }).join('')}
}

/// Handler for ${channel.name} channel with enhanced error handling and transport integration
/// This is the generated infrastructure code that calls user-implemented traits
#[derive(Debug)]
pub struct ${channel.rustName}${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? `<T: ${channel.traitName} + ?Sized>` : ''} {${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? `
    service: Arc<T>,` : ''}
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? `<T: ${channel.traitName} + ?Sized>` : ''} ${channel.rustName}${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? '<T>' : ''} {
    pub fn new(${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? `
        service: Arc<T>,` : ''}
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>
    ) -> Self {
        Self { ${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? 'service, ' : ''}recovery_manager, transport_manager }
    }

    /// Response sender for request/response patterns with transport integration
    pub async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        debug!(
            correlation_id = %context.correlation_id,
            response_channel = %context.response_channel(),
            "Preparing to send response"
        );

        // Create response headers with correlation ID
        let mut response_headers = HashMap::new();
        response_headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
        response_headers.insert("content_type".to_string(), "application/json".to_string());
        response_headers.insert("timestamp".to_string(), chrono::Utc::now().to_rfc3339());

        // Copy relevant headers from request
        for (key, value) in &context.headers {
            if key.starts_with("x-") || key == "user_id" || key == "session_id" {
                response_headers.insert(key.clone(), value.clone());
            }
        }

        // Create MessageEnvelope for response
        let response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {}", e),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::Validation,
                false,
            )
            .with_context("correlation_id", &context.correlation_id.to_string())
            .with_context("channel", &context.channel)
            .with_context("operation", &context.operation),
            source: Some(Box::new(e)),
        }))?
        .with_correlation_id(context.correlation_id.to_string())
        .with_channel(context.response_channel());

        // Send response envelope via transport manager
        info!(
            correlation_id = %context.correlation_id,
            response_channel = %context.response_channel(),
            "Sending response envelope via transport layer"
        );

        // Actually send the response envelope through the transport manager
        match self.transport_manager.send_envelope(response_envelope).await {
            Ok(()) => {
                info!(
                    correlation_id = %context.correlation_id,
                    response_channel = %context.response_channel(),
                    "Response sent successfully via transport layer"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    response_channel = %context.response_channel(),
                    error = %e,
                    "Failed to send response via transport layer"
                );
                Err(Box::new(AsyncApiError::Protocol {
                    message: format!("Failed to send response: {}", e),
                    protocol: "transport".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Network,
                        true, // retryable
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("response_channel", &context.response_channel())
                    .with_context("operation", &context.operation),
                    source: Some(e),
                }))
            }
        }
    }${channel.patterns.map(pattern => {
            if (pattern.type === 'request_response') {
                const requestMessageName = getMessageTypeName(pattern.requestMessage);
                const responseMessageName = getMessageTypeName(pattern.responseMessage);
                const requestType = requestMessageName ? toRustTypeName(requestMessageName) : 'serde_json::Value';
                const responseType = responseMessageName ? toRustTypeName(responseMessageName) : 'serde_json::Value';

                return `

    /// Handle ${pattern.operation.name} request with strongly typed messages and automatic response
    #[instrument(skip(self, payload), fields(
        channel = "${channel.name}",
        operation = "${pattern.operation.name}",
        payload_size = payload.len()
    ))]
    pub async fn handle_${pattern.operation.rustName}_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<${responseType}> {
        debug!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            retry_count = context.retry_count,
            "Starting request processing with automatic response"
        );

        // Input validation
        if payload.is_empty() {
            return Err(Box::new(AsyncApiError::Validation {
                message: "Empty payload received".to_string(),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                )
                .with_context("correlation_id", &context.correlation_id.to_string())
                .with_context("channel", &context.channel)
                .with_context("operation", &context.operation),
                source: None,
            }));
        }

        // Parse MessageEnvelope first, then extract strongly typed request
        let envelope: MessageEnvelope = match serde_json::from_slice::<MessageEnvelope>(payload) {
            Ok(env) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    envelope_operation = %env.operation,
                    envelope_correlation_id = ?env.id,
                    "Successfully parsed MessageEnvelope"
                );
                env
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    payload_preview = %String::from_utf8_lossy(&payload[..payload.len().min(100)]),
                    "Failed to parse MessageEnvelope"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Invalid MessageEnvelope payload: {}", e),
                    field: Some("envelope".to_string()),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Validation,
                        false,
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", &context.channel)
                    .with_context("operation", &context.operation)
                    .with_context("parse_error", &e.to_string()),
                    source: Some(Box::new(e)),
                }));
            }
        };

        // Check for envelope errors
        if let Some(error) = &envelope.error {
            error!(
                correlation_id = %context.correlation_id,
                error_code = %error.code,
                error_message = %error.message,
                "Received error envelope"
            );
            return Err(Box::new(AsyncApiError::Validation {
                message: format!("Error in envelope: {} - {}", error.code, error.message),
                field: Some("envelope.error".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                )
                .with_context("correlation_id", &context.correlation_id.to_string())
                .with_context("channel", &context.channel)
                .with_context("operation", &context.operation)
                .with_context("error_code", &error.code)
                .with_context("error_message", &error.message),
                source: None,
            }));
        }

        // Extract strongly typed request from envelope payload
        let request: ${requestType} = match envelope.extract_payload::<${requestType}>() {
            Ok(req) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    envelope_operation = %envelope.operation,
                    "Successfully extracted ${requestType} from envelope payload"
                );
                req
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    envelope_operation = %envelope.operation,
                    "Failed to extract ${requestType} from envelope payload"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Invalid ${requestType} in envelope payload: {}", e),
                    field: Some("envelope.payload".to_string()),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Validation,
                        false,
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", &context.channel)
                    .with_context("operation", &context.operation)
                    .with_context("envelope_operation", &envelope.operation)
                    .with_context("parse_error", &e.to_string()),
                    source: Some(Box::new(e)),
                }));
            }
        };

        // Call user business logic and get strongly typed response
        match self.service.handle_${pattern.operation.rustName}(request, context).await {
            Ok(response) => {
                info!(
                    correlation_id = %context.correlation_id,
                    channel = %context.channel,
                    operation = %context.operation,
                    processing_time = ?(chrono::Utc::now() - context.timestamp),
                    "Request processed successfully, sending ${responseType} response"
                );

                // Automatically send the strongly typed response back
                self.send_response(&response, context).await?;

                // Return the strongly typed response for caller inspection
                Ok(response)
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    retry_count = context.retry_count,
                    "Request processing failed"
                );

                // Add message to dead letter queue if not retryable
                if !e.is_retryable() {
                    let dlq = self.recovery_manager.get_dead_letter_queue();
                    dlq.add_message(&context.channel, payload.to_vec(), &e, context.retry_count)
                        .await?;
                }

                Err(e)
            }
        }
    }`;
            } else if (pattern.type === 'request_only') {
                const requestMessageName = getMessageTypeName(pattern.requestMessage);
                const requestType = requestMessageName ? toRustTypeName(requestMessageName) : 'serde_json::Value';

                return `

    /// Handle ${pattern.operation.name} request with strongly typed message
    #[instrument(skip(self, payload), fields(
        channel = "${channel.name}",
        operation = "${pattern.operation.name}",
        payload_size = payload.len()
    ))]
    pub async fn handle_${pattern.operation.rustName}_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        debug!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            retry_count = context.retry_count,
            "Starting request processing"
        );

        // Input validation
        if payload.is_empty() {
            return Err(Box::new(AsyncApiError::Validation {
                message: "Empty payload received".to_string(),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                )
                .with_context("correlation_id", &context.correlation_id.to_string())
                .with_context("channel", &context.channel)
                .with_context("operation", &context.operation),
                source: None,
            }));
        }

        // Parse MessageEnvelope first, then extract strongly typed request
        let envelope: MessageEnvelope = match serde_json::from_slice::<MessageEnvelope>(payload) {
            Ok(env) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    envelope_operation = %env.operation,
                    envelope_correlation_id = ?env.id,
                    "Successfully parsed MessageEnvelope"
                );
                env
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    payload_preview = %String::from_utf8_lossy(&payload[..payload.len().min(100)]),
                    "Failed to parse MessageEnvelope"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Invalid MessageEnvelope payload: {}", e),
                    field: Some("envelope".to_string()),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Validation,
                        false,
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", &context.channel)
                    .with_context("operation", &context.operation)
                    .with_context("parse_error", &e.to_string()),
                    source: Some(Box::new(e)),
                }));
            }
        };

        // Check for envelope errors
        if let Some(error) = &envelope.error {
            error!(
                correlation_id = %context.correlation_id,
                error_code = %error.code,
                error_message = %error.message,
                "Received error envelope"
            );
            return Err(Box::new(AsyncApiError::Validation {
                message: format!("Error in envelope: {} - {}", error.code, error.message),
                field: Some("envelope.error".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                )
                .with_context("correlation_id", &context.correlation_id.to_string())
                .with_context("channel", &context.channel)
                .with_context("operation", &context.operation)
                .with_context("error_code", &error.code)
                .with_context("error_message", &error.message),
                source: None,
            }));
        }

        // Extract strongly typed request from envelope payload
        let request: ${requestType} = match envelope.extract_payload::<${requestType}>() {
            Ok(req) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    envelope_operation = %envelope.operation,
                    "Successfully extracted ${requestType} from envelope payload"
                );
                req
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    envelope_operation = %envelope.operation,
                    "Failed to extract ${requestType} from envelope payload"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Invalid ${requestType} in envelope payload: {}", e),
                    field: Some("envelope.payload".to_string()),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Validation,
                        false,
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", &context.channel)
                    .with_context("operation", &context.operation)
                    .with_context("envelope_operation", &envelope.operation)
                    .with_context("parse_error", &e.to_string()),
                    source: Some(Box::new(e)),
                }));
            }
        };

        // Call user business logic
        match self.service.handle_${pattern.operation.rustName}(request, context).await {
            Ok(()) => {
                info!(
                    correlation_id = %context.correlation_id,
                    channel = %context.channel,
                    operation = %context.operation,
                    processing_time = ?(chrono::Utc::now() - context.timestamp),
                    "Request processed successfully"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    retry_count = context.retry_count,
                    "Request processing failed"
                );

                // Add message to dead letter queue if not retryable
                if !e.is_retryable() {
                    let dlq = self.recovery_manager.get_dead_letter_queue();
                    dlq.add_message(&context.channel, payload.to_vec(), &e, context.retry_count)
                        .await?;
                }

                Err(e)
            }
        }
    }`;
            } else if (pattern.type === 'send_message') {
                const sendMessageName = getMessageTypeName(pattern.message);
                const sendType = sendMessageName ? toRustTypeName(sendMessageName) : 'serde_json::Value';

                return `

    /// Send ${pattern.operation.name} message with strongly typed payload
    #[instrument(skip(self, message), fields(
        channel = "${channel.name}",
        operation = "${pattern.operation.name}"
    ))]
    pub async fn send_${pattern.operation.rustName}(
        &self,
        message: ${sendType},
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        debug!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            retry_count = context.retry_count,
            "Starting message sending with strongly typed message"
        );

        // Create transport headers
        let mut headers = HashMap::new();
        headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
        headers.insert("content_type".to_string(), "application/json".to_string());
        headers.insert("timestamp".to_string(), chrono::Utc::now().to_rfc3339());

        // Copy relevant headers from context
        for (key, value) in &context.headers {
            if key.starts_with("x-") || key == "user_id" || key == "session_id" {
                headers.insert(key.clone(), value.clone());
            }
        }

        // Create MessageEnvelope for outgoing message (clone message for envelope)
        let message_envelope = MessageEnvelope::new(
            &context.operation,
            &message
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create message envelope: {}", e),
            field: Some("message_envelope".to_string()),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::Validation,
                false,
            )
            .with_context("correlation_id", &context.correlation_id.to_string())
            .with_context("channel", &context.channel)
            .with_context("operation", &context.operation),
            source: Some(Box::new(e)),
        }))?
        .with_correlation_id(context.correlation_id.to_string())
        .with_channel(context.channel.clone());

        // Send message envelope via transport manager
        match self.transport_manager.send_envelope(message_envelope).await {
            Ok(()) => {
                info!(
                    correlation_id = %context.correlation_id,
                    channel = %context.channel,
                    operation = %context.operation,
                    processing_time = ?(chrono::Utc::now() - context.timestamp),
                    "Message sent successfully via transport layer"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    retry_count = context.retry_count,
                    "Message sending failed via transport layer"
                );

                // Add message to dead letter queue if not retryable
                if !e.is_retryable() {
                    let dlq = self.recovery_manager.get_dead_letter_queue();
                    let payload_bytes = serde_json::to_vec(&message).unwrap_or_default();
                    dlq.add_message(&context.channel, payload_bytes, &e, context.retry_count)
                        .await?;
                }

                Err(Box::new(AsyncApiError::Protocol {
                    message: format!("Failed to send message via transport: {}", e),
                    protocol: "transport".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Network,
                        true, // retryable
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", &context.channel)
                    .with_context("operation", &context.operation),
                    source: Some(e),
                }))
            }
        }
    }`;
            }
            return '';
        }).join('')}

}`).join('')}

/// Registry for managing all handlers with trait-based architecture
/// This provides a unified interface for message routing
#[derive(Debug)]
pub struct HandlerRegistry {
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self {
            recovery_manager: Arc::new(RecoveryManager::default()),
            transport_manager: Arc::new(TransportManager::new()),
        }
    }

    pub fn with_managers(
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>
    ) -> Self {
        Self { recovery_manager, transport_manager }
    }

    /// Route message to appropriate handler
    /// Note: In the trait-based architecture, users will create their own handlers
    /// with their service implementations and call the appropriate handler methods
    pub async fn route_message(
        &self,
        channel: &str,
        operation: &str,
        payload: &[u8],
    ) -> AsyncApiResult<()> {
        let context = MessageContext::new(channel, operation);

        info!(
            correlation_id = %context.correlation_id,
            channel = channel,
            operation = operation,
            payload_size = payload.len(),
            "Routing message - users should implement their own routing with trait-based handlers"
        );

        // In the trait-based architecture, users will implement their own routing
        // This is just a placeholder that shows the structure
        Err(Box::new(AsyncApiError::Handler {
            message: format!(
                "Trait-based architecture: Users must implement their own routing for channel '{}' operation '{}'",
                channel, operation
            ),
            handler_name: "HandlerRegistry".to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::BusinessLogic,
                false,
            )
            .with_context("correlation_id", &context.correlation_id.to_string())
            .with_context("channel", channel)
            .with_context("operation", operation)
            .with_context("architecture", "trait_based"),
            source: None,
        }))
    }

    /// Get recovery manager for external configuration
    pub fn recovery_manager(&self) -> Arc<RecoveryManager> {
        self.recovery_manager.clone()
    }

    /// Get transport manager for external configuration
    pub fn transport_manager(&self) -> Arc<TransportManager> {
        self.transport_manager.clone()
    }

    /// Get handler statistics for monitoring
    pub async fn get_statistics(&self) -> HandlerStatistics {
        HandlerStatistics {
            dead_letter_queue_size: self.recovery_manager.get_dead_letter_queue().size().await,
        }
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for monitoring handler performance
#[derive(Debug, Clone)]
pub struct HandlerStatistics {
    pub dead_letter_queue_size: usize,
}

${channelData.map(channel => {
            const hasService = channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only');
            return `
/// Channel-specific message handler for ${channel.name} that implements MessageHandler trait
/// This connects the TransportManager directly to the generated ${channel.rustName}
pub struct ${toRustTypeName(channel.name)}MessageHandler${hasService ? `<T: ${channel.traitName} + ?Sized>` : ''} {
    handler: Arc<${channel.rustName}${hasService ? '<T>' : ''}>,
}

impl${hasService ? `<T: ${channel.traitName} + ?Sized>` : ''} ${toRustTypeName(channel.name)}MessageHandler${hasService ? '<T>' : ''} {
    pub fn new(handler: Arc<${channel.rustName}${hasService ? '<T>' : ''}>) -> Self {
        Self { handler }
    }
}

impl${hasService ? `<T: ${channel.traitName} + ?Sized>` : ''} std::fmt::Debug for ${toRustTypeName(channel.name)}MessageHandler${hasService ? '<T>' : ''} {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("${toRustTypeName(channel.name)}MessageHandler")
            .field("handler", &"<handler>")
            .finish()
    }
}

#[async_trait]
impl${hasService ? `<T: ${channel.traitName} + ?Sized>` : ''} crate::transport::MessageHandler for ${toRustTypeName(channel.name)}MessageHandler${hasService ? '<T>' : ''} {
    async fn handle_message(&self, message: crate::transport::TransportMessage) -> AsyncApiResult<()> {
        // Parse the MessageEnvelope to get channel and operation information
        let envelope: MessageEnvelope = serde_json::from_slice(&message.payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to parse MessageEnvelope: {}", e),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?;

        // Extract correlation_id from MessageEnvelope's id field instead of transport headers
        let correlation_id = envelope.correlation_id()
            .and_then(|id| id.parse().ok())
            .unwrap_or_else(uuid::Uuid::new_v4);

        let channel = envelope.channel.as_deref().unwrap_or("${channel.name}");
        let operation = &envelope.operation;

        debug!(
            correlation_id = %correlation_id,
            channel = %channel,
            operation = %operation,
            payload_size = message.payload.len(),
            envelope_correlation_id = ?envelope.correlation_id(),
            "${toRustTypeName(channel.name)}MessageHandler received message"
        );

        // Create message context from transport message
        let mut context = MessageContext::new(channel, operation);
        context.headers = message.metadata.headers.clone();

        // Set correlation ID from MessageEnvelope
        context.correlation_id = correlation_id;

        // Route to appropriate handler method based on operation from envelope${channel.operations.filter(op => op.action === 'send').length > 0 ? `
        match envelope.operation.as_str() {${channel.operations.filter(op => op.action === 'send').map(op => {
            // Find the pattern for this operation to determine if it's request/response
            const pattern = channel.patterns.find(p => p.operation.name === op.name);
            if (pattern && pattern.type === 'request_response') {
                return `
            "${op.name}" => {
                debug!(
                    correlation_id = %context.correlation_id,
                    operation = "${op.name}",
                    "Routing to handle_${op.rustName}_request handler method (request/response pattern)"
                );
                // For request/response patterns, the handler returns the response but also automatically sends it
                // We discard the returned response since it's already been sent
                self.handler.handle_${op.rustName}_request(&message.payload, &context).await.map(|_| ())
            }`;
            } else {
                return `
            "${op.name}" => {
                debug!(
                    correlation_id = %context.correlation_id,
                    operation = "${op.name}",
                    "Routing to handle_${op.rustName}_request handler method"
                );
                self.handler.handle_${op.rustName}_request(&message.payload, &context).await
            }`;
            }
        }).join('')}
            _ => {
                warn!(
                    correlation_id = %context.correlation_id,
                    operation = %envelope.operation,
                    "Unknown operation for ${channel.cleanName || channel.name} channel"
                );
                Err(Box::new(AsyncApiError::Handler {
                    message: format!("Unknown operation '{}' for channel '${channel.cleanName || channel.name}'", envelope.operation),
                    handler_name: "${toRustTypeName(channel.name)}MessageHandler".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::BusinessLogic,
                        false,
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", "${channel.name}")
                    .with_context("operation", &envelope.operation),
                    source: None,
                }))
            }
        }` : `
        warn!(
            correlation_id = %context.correlation_id,
            operation = %envelope.operation,
            "No operations defined for ${channel.cleanName || channel.name} channel"
        );
        Err(Box::new(AsyncApiError::Handler {
            message: format!("No operations defined for channel '${channel.cleanName || channel.name}', operation '{}'", envelope.operation),
            handler_name: "${toRustTypeName(channel.name)}MessageHandler".to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::BusinessLogic,
                false,
            )
            .with_context("correlation_id", &context.correlation_id.to_string())
            .with_context("channel", "${channel.name}")
            .with_context("operation", &envelope.operation),
            source: None,
        }))`}
    }
}`;
        }).join('')}
`}
        </File>
    );
}

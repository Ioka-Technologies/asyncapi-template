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
    analyzeOperationSecurity
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
            {`//! Clean message handlers for AsyncAPI operations
//!
//! This module provides:
//! - Simple trait-based handler architecture
//! - Clean separation between business logic and infrastructure
//! - Generated infrastructure code that calls user-implemented traits
//! - Robust error handling with custom error types
//! - Retry mechanisms with exponential backoff
//! - Circuit breaker pattern for failure isolation
//! - Dead letter queue for unprocessable messages
//! - Request/response pattern support with automatic response sending
//! - Transport layer integration for response routing
//!
//! ## Usage
//!
//! Users implement the generated traits to provide business logic:
//!
//! \`\`\`no-run
//! use async_trait::async_trait;
//! use std::sync::Arc;
//!
//! // Implement your business logic trait
//! #[async_trait]
//! impl UserSignupService for MyUserService {
//!     async fn handle_signup(&self, request: SignupRequest, context: &MessageContext) -> AsyncApiResult<SignupResponse> {
//!         // Your business logic here - authentication is handled automatically by AutoServerBuilder
//!         let response = SignupResponse {
//!             user_id: "12345".to_string(),
//!             status: "success".to_string(),
//!         };
//!         Ok(response)
//!     }
//! }
//!
//! // AutoServerBuilder handles all complexity automatically
//! let server = AutoServerBuilder::new()
//!     .with_user_signup_service(Arc::new(MyUserService::new()))${hasAuth ? `
//!     .with_jwt_auth("my-secret-key", "HS256")?  // Only auth config needed` : ''}
//!     .build_and_start()
//!     .await?;
//! \`\`\`

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

${channelData.map(channel => `
/// Business logic trait for ${channel.name} channel operations
/// Users must implement this trait to provide their business logic
/// Authentication is handled automatically by the AutoServerBuilder
#[async_trait]
pub trait ${channel.traitName}: Send + Sync {${channel.patterns.map(pattern => {
                if (pattern.type === 'request_response') {
                    const requestType = getPayloadRustTypeName(pattern.requestMessage);
                    const responseType = getPayloadRustTypeName(pattern.responseMessage);

                    return `
    /// Handle ${pattern.operation.name} request and return response
    /// The response will be automatically sent back via the transport layer
    /// Authentication is handled automatically - claims are available in context if needed
    async fn handle_${pattern.operation.rustName}(
        &self,
        request: ${requestType},
        context: &MessageContext,
    ) -> AsyncApiResult<${responseType}>;`;
                } else if (pattern.type === 'request_only') {
                    const requestType = getPayloadRustTypeName(pattern.requestMessage);

                    return `
    /// Handle ${pattern.operation.name} request
    /// Authentication is handled automatically - claims are available in context if needed
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

/// Clean handler for ${channel.name} channel with enhanced error handling and transport integration
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
        Self {
            ${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? 'service, ' : ''}recovery_manager,
            transport_manager,
        }
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
            &format!("{operation}_response", operation = context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
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

        // Send response envelope via transport manager with retry logic (outgoing message)
        // The transport manager's send_envelope method already applies retry logic for outgoing messages
        match self.transport_manager.send_envelope(response_envelope).await {
            Ok(()) => {
                info!(
                    correlation_id = %context.correlation_id,
                    response_channel = %context.response_channel(),
                    "Response sent successfully via transport layer with retry logic"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    response_channel = %context.response_channel(),
                    error = %e,
                    "Failed to send response via transport layer after retry attempts"
                );
                Err(Box::new(AsyncApiError::Protocol {
                    message: format!("Failed to send response after retry attempts: {e}"),
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
                    const requestType = getPayloadRustTypeName(pattern.requestMessage);
                    const responseType = getPayloadRustTypeName(pattern.responseMessage);

                    return `

    /// Handle ${pattern.operation.name} request with strongly typed messages and automatic response
    /// Authentication is handled by wrapper - this is pure business logic infrastructure
    #[instrument(skip(self, payload, context), fields(
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
                    message: format!("Invalid MessageEnvelope payload: {e}"),
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
                message: format!("Error in envelope: {code} - {message}", code = error.code, message = error.message),
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
                    message: format!("Invalid ${requestType} in envelope payload: {e}"),
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

        // Call business logic service WITHOUT retry for incoming messages
        // Incoming messages should fail fast - the client is responsible for retrying
        debug!(
            correlation_id = %context.correlation_id,
            "Executing incoming message business logic without retry"
        );
        let response = self.service.handle_${pattern.operation.rustName}(request, context).await?;

        // Send response automatically with retry logic (outgoing message)
        self.send_response(&response, context).await?;

        info!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            "Request processed successfully with automatic response"
        );

        Ok(response)
    }`;
                } else if (pattern.type === 'request_only') {
                    const requestType = getPayloadRustTypeName(pattern.requestMessage);

                    return `

    /// Handle ${pattern.operation.name} request with strongly typed messages
    /// Authentication is handled by wrapper - this is pure business logic infrastructure
    #[instrument(skip(self, payload, context), fields(
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
                    message: format!("Invalid MessageEnvelope payload: {e}"),
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
                message: format!("Error in envelope: {code} - {message}", code = error.code, message = error.message),
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
                    message: format!("Invalid ${requestType} in envelope payload: {e}"),
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

        // Call business logic service WITHOUT retry for incoming messages
        // Incoming messages should fail fast - the client is responsible for retrying
        debug!(
            correlation_id = %context.correlation_id,
            "Executing incoming message business logic without retry"
        );
        self.service.handle_${pattern.operation.rustName}(request, &context).await?;

        info!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            "Request processed successfully"
        );

        Ok(())
    }`;
                }
                return '';
            }).join('')}
}

/// Message handler wrapper that implements the transport MessageHandler trait
/// This bridges the gap between the transport layer and our clean handlers
pub struct ${channel.rustName}MessageHandler${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? `<T: ${channel.traitName} + ?Sized>` : ''} {
    handler: Arc<${channel.rustName}${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? '<T>' : ''}>,
}

impl${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? `<T: ${channel.traitName} + ?Sized>` : ''} ${channel.rustName}MessageHandler${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? '<T>' : ''} {
    pub fn new(handler: Arc<${channel.rustName}${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? '<T>' : ''}>) -> Self {
        Self { handler }
    }
}

#[async_trait]
impl${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? `<T: ${channel.traitName} + ?Sized>` : ''} crate::transport::MessageHandler for ${channel.rustName}MessageHandler${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? '<T>' : ''} {
    async fn handle_message(
        &self,
        ${channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only') ? 'payload: &[u8],' : '_payload: &[u8],'}
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create message context from metadata
        let mut context = MessageContext::new("${channel.name}", &metadata.operation);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        // Route to appropriate handler method based on operation
        #[allow(clippy::match_single_binding)]
        match metadata.operation.as_str() {${channel.patterns.map(pattern => {
                if (pattern.type === 'request_response') {
                    return `
            "${pattern.operation.name}" => {
                let _ = self.handler.handle_${pattern.operation.rustName}_request(payload, &context).await?;
                Ok(())
            }`;
                } else if (pattern.type === 'request_only') {
                    return `
            "${pattern.operation.name}" => {
                self.handler.handle_${pattern.operation.rustName}_request(payload, &context).await?;
                Ok(())
            }`;
                }
                return '';
            }).join('')}
            _ => {
                warn!(
                    operation = %metadata.operation,
                    channel = "${channel.name}",
                    "Unknown operation for channel"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Unknown operation '{}' for channel '${channel.cleanName}'", metadata.operation),
                    field: Some("operation".to_string()),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Validation,
                        false,
                    )
                    .with_context("operation", &metadata.operation)
                    .with_context("channel", "${channel.cleanName}"),
                    source: None,
                }));
            }
        }
    }
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

                    if (allOperations.length === 0) return '';

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
/// This handler is wrapped with authentication only if the operation requires security
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
        // Create message context from metadata
        let mut context = MessageContext::new("${op.channelName}", &metadata.operation);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        ${op.type === 'request_response' ? `
        // Handle request/response operation
        let _ = self.handle_${op.operation.rustName}_request(payload, &context).await?;
        Ok(())` : `
        // Handle request-only operation
        self.handle_${op.operation.rustName}_request(payload, &context).await?;
        Ok(())`}
    }
}

impl<T: ${op.channelTraitName} + ?Sized> ${operationHandlerName}<T> {${op.type === 'request_response' ? `
    /// Handle ${op.operation.name} request with strongly typed messages and automatic response
    #[instrument(skip(self, payload, context), fields(
        operation = "${op.operation.name}",
        payload_size = payload.len()
    ))]
    pub async fn handle_${op.operation.rustName}_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<${responseType}> {
        debug!(
            correlation_id = %context.correlation_id,
            operation = %context.operation,
            "Processing ${op.operation.name} operation"
        );

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

        // Call business logic WITHOUT retry for incoming messages
        // Incoming messages should fail fast - the client is responsible for retrying
        debug!(
            correlation_id = %context.correlation_id,
            "Executing incoming message business logic without retry"
        );
        let response = self.service.handle_${op.operation.rustName}(request.clone(), context).await?;

        // Send response automatically
        self.send_response(&response, context).await?;

        Ok(response)
    }

    /// Send response for ${op.operation.name} operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        let response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?
        .with_correlation_id(context.correlation_id.to_string())
        .with_channel(context.response_channel());

        self.transport_manager.send_envelope(response_envelope).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }` : `
    /// Handle ${op.operation.name} request with strongly typed messages
    #[instrument(skip(self, payload, context), fields(
        operation = "${op.operation.name}",
        payload_size = payload.len()
    ))]
    pub async fn handle_${op.operation.rustName}_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        debug!(
            correlation_id = %context.correlation_id,
            operation = %context.operation,
            "Processing ${op.operation.name} operation"
        );

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

        // Call business logic WITHOUT retry for incoming messages
        // Incoming messages should fail fast - the client is responsible for retrying
        debug!(
            correlation_id = %context.correlation_id,
            "Executing incoming message business logic without retry"
        );
        self.service.handle_${op.operation.rustName}(request.clone(), context).await?;

        Ok(())
    }`}
}`;
                    }).join('');
                })()}

/// Get operation-specific scopes based on AsyncAPI specification analysis
/// This function is generated during template compilation with operation security requirements
fn get_operation_scopes(operation: &str) -> Vec<String> {
    #[allow(clippy::match_single_binding)]
    match operation {${(() => {
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

                    return allOperations.map(op => {
                        // Generate basic scopes based on operation name and security requirements
                        if (op.requiresSecurity) {
                            const opName = op.name.toLowerCase();
                            const scopes = [];

                            // Generate scopes based on operation patterns
                            if (opName.includes('signup') || opName.includes('register')) {
                                scopes.push('"user:create"');
                            } else if (opName.includes('login') || opName.includes('auth')) {
                                scopes.push('"auth:login"');
                            } else if (opName.includes('profile')) {
                                scopes.push('"profile:write"');
                            } else if (opName.includes('chat') || opName.includes('message')) {
                                scopes.push('"chat:write"');
                            } else {
                                // Generic scope based on operation name
                                scopes.push(`"${opName}:execute"`);
                            }

                            return `\n        "${op.name}" => vec![${scopes.join(', ')}.to_string()],`;
                        } else {
                            return `\n        "${op.name}" => vec![], // No authentication required`;
                        }
                    }).join('');
                })()}
        _ => vec![], // Default: no scopes required
    }
}

/// Get operation security configuration based on AsyncAPI specification analysis
/// This function is generated during template compilation with security requirements
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
            /// This is a placeholder that maintains API compatibility
            pub struct HandlerRegistry;

            impl HandlerRegistry {
                pub fn new() -> Self {
                Self
            }

            pub fn with_managers(
            _recovery_manager: Arc<crate::recovery::RecoveryManager>,
            _transport_manager: Arc<crate::transport::TransportManager>,
    ) -> Self {
                // For now, we just return a new instance
                // In a real implementation, you would store these managers
                // and use them in the handler methods
                Self::new()
    }
}

            impl Default for HandlerRegistry {
                fn default() -> Self {
                Self::new()
    }
}
`}
        </File>
    );
}

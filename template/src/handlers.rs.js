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
        return identifier
            .split('_')
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

        // Try to get message name
        if (message.name && typeof message.name === 'function') {
            return message.name();
        } else if (message.name) {
            return message.name;
        }

        // Try to get from $ref
        if (message.$ref) {
            return message.$ref.split('/').pop();
        }

        return null;
    }

    // Helper function to detect request/response patterns
    function analyzeOperationPattern(channelOps, channelName) {
        const sendOps = channelOps.filter(op => op.action === 'send');
        const receiveOps = channelOps.filter(op => op.action === 'receive');

        // Look for request/response patterns
        const patterns = [];

        // Check send operations for reply patterns (AsyncAPI 3.x)
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
                patterns.push({
                    type: 'request_response',
                    request: sendOp,  // The send operation is the request
                    response: null,   // Reply is handled automatically
                    requestMessage: sendOp.messages[0],
                    responseMessage: replyMessage
                });
            } else {
                // Check if there's a corresponding receive operation that could be a response
                const potentialResponses = receiveOps.filter(receiveOp => {
                    // Simple heuristic: if operation names suggest request/response
                    const sendName = sendOp.name.toLowerCase();
                    const receiveName = receiveOp.name.toLowerCase();

                    return (
                        receiveName.includes('response') ||
                        receiveName.includes('reply') ||
                        (sendName.includes('request') && receiveName.includes(sendName.replace('request', ''))) ||
                        (sendName.includes('command') && receiveName.includes('event'))
                    );
                });

                if (potentialResponses.length > 0) {
                    patterns.push({
                        type: 'request_response',
                        request: sendOp,
                        response: potentialResponses[0],
                        requestMessage: sendOp.messages[0],
                        responseMessage: potentialResponses[0].messages[0]
                    });
                } else {
                    patterns.push({
                        type: 'send_only',
                        send: sendOp,
                        sendMessage: sendOp.messages[0]
                    });
                }
            }
        }

        // Add receive-only operations (only those not already part of request/response patterns)
        for (const receiveOp of receiveOps) {
            const isPartOfRequestResponse = patterns.some(p =>
                p.type === 'request_response' && p.response && p.response.name === receiveOp.name
            );

            if (!isPartOfRequestResponse) {
                patterns.push({
                    type: 'request_only',
                    request: receiveOp,
                    requestMessage: receiveOp.messages[0]
                });
            }
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

            channelData.push({
                name: channelName,
                rustName: toRustTypeName(channelName + '_handler'),
                fieldName: toRustFieldName(channelName + '_handler'),
                traitName: toRustTypeName(channelName + '_service'),
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
use crate::transport::{TransportManager, TransportMessage, MessageMetadata};
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
    pub claims: Option<crate::auth::Claims>,` : ''}
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
            claims: None,` : ''}
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
                const requestMessageName = getMessageTypeName(pattern.requestMessage);
                const responseMessageName = getMessageTypeName(pattern.responseMessage);
                const requestType = requestMessageName ? toRustTypeName(requestMessageName) : 'serde_json::Value';
                const responseType = responseMessageName ? toRustTypeName(responseMessageName) : 'serde_json::Value';

                return `
    /// Handle ${pattern.request.name} request and return response
    /// The response will be automatically sent back via the transport layer
    async fn handle_${pattern.request.rustName}(
        &self,
        request: ${requestType},
        context: &MessageContext,
    ) -> AsyncApiResult<${responseType}>;`;
            } else if (pattern.type === 'request_only') {
                const requestMessageName = getMessageTypeName(pattern.requestMessage);
                const requestType = requestMessageName ? toRustTypeName(requestMessageName) : 'serde_json::Value';

                return `
    /// Handle ${pattern.request.name} request
    async fn handle_${pattern.request.rustName}(
        &self,
        request: ${requestType},
        context: &MessageContext,
    ) -> AsyncApiResult<()>;`;
            } else if (pattern.type === 'send_only') {
                const sendMessageName = getMessageTypeName(pattern.sendMessage);
                const sendType = sendMessageName ? toRustTypeName(sendMessageName) : 'serde_json::Value';

                return `
    /// Send ${pattern.send.name} message
    async fn send_${pattern.send.rustName}(
        &self,
        message: ${sendType},
        context: &MessageContext,
    ) -> AsyncApiResult<()>;`;
            }
            return '';
        }).join('')}
}

/// Handler for ${channel.name} channel with enhanced error handling and transport integration
/// This is the generated infrastructure code that calls user-implemented traits
#[derive(Debug)]
pub struct ${channel.rustName}<T: ${channel.traitName}> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ${channel.traitName}> ${channel.rustName}<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>
    ) -> Self {
        Self { service, recovery_manager, transport_manager }
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

        // Serialize response to JSON
        let response_payload = serde_json::to_vec(&response)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response: {}", e),
                field: Some("response".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Validation,
                    false,
                )
                .with_context("correlation_id", &context.correlation_id.to_string())
                .with_context("channel", &context.channel)
                .with_context("operation", &context.operation),
                source: Some(Box::new(e)),
            }))?;

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

        // Create transport message for response
        let response_message = TransportMessage {
            metadata: MessageMetadata {
                channel: context.response_channel(),
                operation: format!("{}_response", context.operation),
                content_type: Some("application/json".to_string()),
                headers: response_headers,
                timestamp: chrono::Utc::now(),
            },
            payload: response_payload,
        };

        // Send response via transport manager
        info!(
            correlation_id = %context.correlation_id,
            response_channel = %context.response_channel(),
            payload_size = response_message.payload.len(),
            "Sending response via transport layer"
        );

        // Actually send the response through the transport manager
        match self.transport_manager.send_message(response_message).await {
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

    /// Handle ${pattern.request.name} request with strongly typed messages and automatic response
    #[instrument(skip(self, payload), fields(
        channel = "${channel.name}",
        operation = "${pattern.request.name}",
        payload_size = payload.len()
    ))]
    pub async fn handle_${pattern.request.rustName}_request(
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

        // Parse to strongly typed request
        let request: ${requestType} = match serde_json::from_slice::<${requestType}>(payload) {
            Ok(req) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    "Successfully parsed ${requestType} request"
                );
                req
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    payload_preview = %String::from_utf8_lossy(&payload[..payload.len().min(100)]),
                    "Failed to parse ${requestType} request"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Invalid ${requestType} payload: {}", e),
                    field: Some("payload".to_string()),
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

        // Call user business logic and get strongly typed response
        match self.service.handle_${pattern.request.rustName}(request, context).await {
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

    /// Handle ${pattern.request.name} request with strongly typed message
    #[instrument(skip(self, payload), fields(
        channel = "${channel.name}",
        operation = "${pattern.request.name}",
        payload_size = payload.len()
    ))]
    pub async fn handle_${pattern.request.rustName}_request(
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

        // Parse to strongly typed request
        let request: ${requestType} = match serde_json::from_slice::<${requestType}>(payload) {
            Ok(req) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    "Successfully parsed ${requestType} request"
                );
                req
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    payload_preview = %String::from_utf8_lossy(&payload[..payload.len().min(100)]),
                    "Failed to parse ${requestType} request"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Invalid ${requestType} payload: {}", e),
                    field: Some("payload".to_string()),
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

        // Call user business logic
        match self.service.handle_${pattern.request.rustName}(request, context).await {
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
            } else if (pattern.type === 'send_only') {
                const sendMessageName = getMessageTypeName(pattern.sendMessage);
                const sendType = sendMessageName ? toRustTypeName(sendMessageName) : 'serde_json::Value';

                return `

    /// Send ${pattern.send.name} message with strongly typed payload
    #[instrument(skip(self, message), fields(
        channel = "${channel.name}",
        operation = "${pattern.send.name}"
    ))]
    pub async fn send_${pattern.send.rustName}(
        &self,
        message: ${sendType},
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        debug!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            "Sending ${sendType} message"
        );

        // Call user business logic for sending
        match self.service.send_${pattern.send.rustName}(message, context).await {
            Ok(()) => {
                info!(
                    correlation_id = %context.correlation_id,
                    channel = %context.channel,
                    operation = %context.operation,
                    "Message sent successfully"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    "Message sending failed"
                );
                Err(e)
            }
        }
    }`;
            }
            return '';
        }).join('')}

    /// Generic handler for backward compatibility (fallback to serde_json::Value)
    pub async fn handle_generic_message(
        &self,
        operation_name: &str,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        warn!(
            correlation_id = %context.correlation_id,
            operation = operation_name,
            "Using generic handler - consider using strongly typed handlers for better type safety"
        );

        // Parse as generic JSON
        let _message: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid JSON payload: {}", e),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?;

        // Route to appropriate handler based on operation name
        match operation_name {${channel.patterns.map(pattern => {
            if (pattern.type === 'request_response' || pattern.type === 'request_only') {
                return `
            "${pattern.request.name}" => {
                // For backward compatibility, call the generic version
                // Users should migrate to strongly typed handlers
                todo!("Implement generic fallback for ${pattern.request.name}")
            }`;
            }
            return '';
        }).join('')}
            _ => {
                Err(Box::new(AsyncApiError::Handler {
                    message: format!("Unknown operation: {}", operation_name),
                    handler_name: "${channel.rustName}".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::BusinessLogic,
                        false,
                    ),
                    source: None,
                }))
            }
        }
    }
}`).join('')}

/// Example implementation showing how users should implement the traits
/// This would typically be in user code, not generated code
pub struct ExampleService;

${channelData.map(channel => `
#[async_trait]
impl ${channel.traitName} for ExampleService {${channel.patterns.map(pattern => {
            if (pattern.type === 'request_response') {
                const requestMessageName = getMessageTypeName(pattern.requestMessage);
                const responseMessageName = getMessageTypeName(pattern.responseMessage);
                const requestType = requestMessageName ? toRustTypeName(requestMessageName) : 'serde_json::Value';
                const responseType = responseMessageName ? toRustTypeName(responseMessageName) : 'serde_json::Value';

                return `
    async fn handle_${pattern.request.rustName}(
        &self,
        request: ${requestType},
        context: &MessageContext,
    ) -> AsyncApiResult<${responseType}> {
        // TODO: Replace this with your actual business logic
        info!(
            correlation_id = %context.correlation_id,
            "Processing ${pattern.request.name} request for ${channel.name} channel"
        );

        // Your business logic goes here
        // For example:
        // - Validate request fields
        // - Perform business operations
        // - Query databases or external services
        // - Build and return response

        // Example response (replace with actual logic)
        ${responseType === 'serde_json::Value' ?
            'Ok(serde_json::json!({"status": "success", "message": "Request processed"}))' :
            `// Create and return a proper ${responseType} instance
        todo!("Implement ${responseType} response creation")`}
    }`;
            } else if (pattern.type === 'request_only') {
                const requestMessageName = getMessageTypeName(pattern.requestMessage);
                const requestType = requestMessageName ? toRustTypeName(requestMessageName) : 'serde_json::Value';

                return `
    async fn handle_${pattern.request.rustName}(
        &self,
        request: ${requestType},
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // TODO: Replace this with your actual business logic
        info!(
            correlation_id = %context.correlation_id,
            "Processing ${pattern.request.name} request for ${channel.name} channel"
        );

        // Your business logic goes here
        // For example:
        // - Validate request fields
        // - Perform business operations
        // - Update databases or external services
        // - Send notifications

        Ok(())
    }`;
            } else if (pattern.type === 'send_only') {
                const sendMessageName = getMessageTypeName(pattern.sendMessage);
                const sendType = sendMessageName ? toRustTypeName(sendMessageName) : 'serde_json::Value';

                return `
    async fn send_${pattern.send.rustName}(
        &self,
        message: ${sendType},
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // TODO: Replace this with your actual message sending logic
        info!(
            correlation_id = %context.correlation_id,
            "Sending ${pattern.send.name} message for ${channel.name} channel"
        );

        // Your message sending logic goes here
        // For example:
        // - Validate message fields
        // - Transform message if needed
        // - Send to transport layer
        // - Handle sending errors

        Ok(())
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
`}
        </File>
    );
}

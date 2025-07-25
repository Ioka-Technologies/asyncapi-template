//! Message handlers for AsyncAPI operations with trait-based architecture
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
//! ```no-run
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
//! ```

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
    pub headers: HashMap<String, String>,
    #[cfg(feature = "auth")]
    pub claims: Option<crate::auth::Claims>,
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
            headers: HashMap::new(),
            #[cfg(feature = "auth")]
            claims: None,
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

    /// Get authentication claims if available
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
    }
}


/// Business logic trait for chatMessages channel operations
/// Users must implement this trait to provide their business logic
#[async_trait]
pub trait ChatMessagesService: Send + Sync {
    /// Handle sendChatMessage request and return response
    /// The response will be automatically sent back via the transport layer
    async fn handle_send_chat_message(
        &self,
        request: ChatMessage,
        context: &MessageContext,
    ) -> AsyncApiResult<MessageDelivered>;
}

/// Handler for chatMessages channel with enhanced error handling and transport integration
/// This is the generated infrastructure code that calls user-implemented traits
#[derive(Debug)]
pub struct ChatMessagesHandler<T: ChatMessagesService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ChatMessagesService + ?Sized> ChatMessagesHandler<T> {
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
    }

    /// Handle sendChatMessage request with strongly typed messages and automatic response
    #[instrument(skip(self, payload), fields(
        channel = "chatMessages",
        operation = "sendChatMessage",
        payload_size = payload.len()
    ))]
    pub async fn handle_send_chat_message_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<MessageDelivered> {
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
        let request: ChatMessage = match envelope.extract_payload::<ChatMessage>() {
            Ok(req) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    envelope_operation = %envelope.operation,
                    "Successfully extracted ChatMessage from envelope payload"
                );
                req
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    envelope_operation = %envelope.operation,
                    "Failed to extract ChatMessage from envelope payload"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Invalid ChatMessage in envelope payload: {}", e),
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
        match self.service.handle_send_chat_message(request, context).await {
            Ok(response) => {
                info!(
                    correlation_id = %context.correlation_id,
                    channel = %context.channel,
                    operation = %context.operation,
                    processing_time = ?(chrono::Utc::now() - context.timestamp),
                    "Request processed successfully, sending MessageDelivered response"
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
    }

    /// Send receiveChatMessage message with strongly typed payload
    #[instrument(skip(self, message), fields(
        channel = "chatMessages",
        operation = "receiveChatMessage"
    ))]
    pub async fn send_receive_chat_message(
        &self,
        message: ChatMessage,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        debug!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            retry_count = context.retry_count,
            "Starting message sending with strongly typed message"
        );

        // Serialize message to JSON
        let payload = match serde_json::to_vec(&message) {
            Ok(payload) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    payload_size = payload.len(),
                    "Successfully serialized ChatMessage message"
                );
                payload
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    "Failed to serialize ChatMessage message"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Failed to serialize ChatMessage message: {}", e),
                    field: Some("message".to_string()),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Validation,
                        false,
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", &context.channel)
                    .with_context("operation", &context.operation)
                    .with_context("serialize_error", &e.to_string()),
                    source: Some(Box::new(e)),
                }));
            }
        };

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
    }

}
/// Business logic trait for profileUpdate channel operations
/// Users must implement this trait to provide their business logic
#[async_trait]
pub trait ProfileUpdateService: Send + Sync {
    /// Handle updateUserProfile request and return response
    /// The response will be automatically sent back via the transport layer
    async fn handle_update_user_profile(
        &self,
        request: ProfileUpdateRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ProfileUpdateResponse>;
}

/// Handler for profileUpdate channel with enhanced error handling and transport integration
/// This is the generated infrastructure code that calls user-implemented traits
#[derive(Debug)]
pub struct ProfileUpdateHandler<T: ProfileUpdateService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ProfileUpdateService + ?Sized> ProfileUpdateHandler<T> {
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
    }

    /// Handle updateUserProfile request with strongly typed messages and automatic response
    #[instrument(skip(self, payload), fields(
        channel = "profileUpdate",
        operation = "updateUserProfile",
        payload_size = payload.len()
    ))]
    pub async fn handle_update_user_profile_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<ProfileUpdateResponse> {
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
        let request: ProfileUpdateRequest = match envelope.extract_payload::<ProfileUpdateRequest>() {
            Ok(req) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    envelope_operation = %envelope.operation,
                    "Successfully extracted ProfileUpdateRequest from envelope payload"
                );
                req
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    envelope_operation = %envelope.operation,
                    "Failed to extract ProfileUpdateRequest from envelope payload"
                );
                return Err(Box::new(AsyncApiError::Validation {
                    message: format!("Invalid ProfileUpdateRequest in envelope payload: {}", e),
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
        match self.service.handle_update_user_profile(request, context).await {
            Ok(response) => {
                info!(
                    correlation_id = %context.correlation_id,
                    channel = %context.channel,
                    operation = %context.operation,
                    processing_time = ?(chrono::Utc::now() - context.timestamp),
                    "Request processed successfully, sending ProfileUpdateResponse response"
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
    }

}

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


/// Channel-specific message handler for chatMessages that implements MessageHandler trait
/// This connects the TransportManager directly to the generated ChatMessagesHandler
pub struct ChatMessagesMessageHandler<T: ChatMessagesService + ?Sized> {
    handler: Arc<ChatMessagesHandler<T>>,
}

impl<T: ChatMessagesService + ?Sized> ChatMessagesMessageHandler<T> {
    pub fn new(handler: Arc<ChatMessagesHandler<T>>) -> Self {
        Self { handler }
    }
}

impl<T: ChatMessagesService + ?Sized> std::fmt::Debug for ChatMessagesMessageHandler<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatMessagesMessageHandler")
            .field("handler", &"<handler>")
            .finish()
    }
}

#[async_trait]
impl<T: ChatMessagesService + ?Sized> crate::transport::MessageHandler for ChatMessagesMessageHandler<T> {
    async fn handle_message(&self, message: crate::transport::TransportMessage) -> AsyncApiResult<()> {
        let correlation_id = message.metadata.headers.get("correlation_id")
            .and_then(|id| id.parse().ok())
            .unwrap_or_else(uuid::Uuid::new_v4);

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

        let channel = envelope.channel.as_deref().unwrap_or("chatMessages");
        let operation = &envelope.operation;

        debug!(
            correlation_id = %correlation_id,
            channel = %channel,
            operation = %operation,
            payload_size = message.payload.len(),
            "ChatMessagesMessageHandler received message"
        );

        // Create message context from transport message
        let mut context = MessageContext::new(channel, operation);
        context.headers = message.metadata.headers.clone();

        // Set correlation ID if available
        if let Some(correlation_str) = message.metadata.headers.get("correlation_id") {
            if let Ok(correlation_uuid) = correlation_str.parse() {
                context.correlation_id = correlation_uuid;
            }
        }

        // Route to appropriate handler method based on operation from envelope
        match envelope.operation.as_str() {
            "sendChatMessage" => {
                debug!(
                    correlation_id = %context.correlation_id,
                    operation = "sendChatMessage",
                    "Routing to handle_send_chat_message_request handler method (request/response pattern)"
                );
                // For request/response patterns, the handler returns the response but also automatically sends it
                // We discard the returned response since it's already been sent
                self.handler.handle_send_chat_message_request(&message.payload, &context).await.map(|_| ())
            }
            _ => {
                warn!(
                    correlation_id = %context.correlation_id,
                    operation = %envelope.operation,
                    "Unknown operation for chatMessages channel"
                );
                Err(Box::new(AsyncApiError::Handler {
                    message: format!("Unknown operation '{}' for channel 'chatMessages'", envelope.operation),
                    handler_name: "ChatMessagesMessageHandler".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::BusinessLogic,
                        false,
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", "chatMessages")
                    .with_context("operation", &envelope.operation),
                    source: None,
                }))
            }
        }
    }
}
/// Channel-specific message handler for profileUpdate that implements MessageHandler trait
/// This connects the TransportManager directly to the generated ProfileUpdateHandler
pub struct ProfileUpdateMessageHandler<T: ProfileUpdateService + ?Sized> {
    handler: Arc<ProfileUpdateHandler<T>>,
}

impl<T: ProfileUpdateService + ?Sized> ProfileUpdateMessageHandler<T> {
    pub fn new(handler: Arc<ProfileUpdateHandler<T>>) -> Self {
        Self { handler }
    }
}

impl<T: ProfileUpdateService + ?Sized> std::fmt::Debug for ProfileUpdateMessageHandler<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileUpdateMessageHandler")
            .field("handler", &"<handler>")
            .finish()
    }
}

#[async_trait]
impl<T: ProfileUpdateService + ?Sized> crate::transport::MessageHandler for ProfileUpdateMessageHandler<T> {
    async fn handle_message(&self, message: crate::transport::TransportMessage) -> AsyncApiResult<()> {
        let correlation_id = message.metadata.headers.get("correlation_id")
            .and_then(|id| id.parse().ok())
            .unwrap_or_else(uuid::Uuid::new_v4);

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

        let channel = envelope.channel.as_deref().unwrap_or("profileUpdate");
        let operation = &envelope.operation;

        debug!(
            correlation_id = %correlation_id,
            channel = %channel,
            operation = %operation,
            payload_size = message.payload.len(),
            "ProfileUpdateMessageHandler received message"
        );

        // Create message context from transport message
        let mut context = MessageContext::new(channel, operation);
        context.headers = message.metadata.headers.clone();

        // Set correlation ID if available
        if let Some(correlation_str) = message.metadata.headers.get("correlation_id") {
            if let Ok(correlation_uuid) = correlation_str.parse() {
                context.correlation_id = correlation_uuid;
            }
        }

        // Route to appropriate handler method based on operation from envelope
        match envelope.operation.as_str() {
            "updateUserProfile" => {
                debug!(
                    correlation_id = %context.correlation_id,
                    operation = "updateUserProfile",
                    "Routing to handle_update_user_profile_request handler method (request/response pattern)"
                );
                // For request/response patterns, the handler returns the response but also automatically sends it
                // We discard the returned response since it's already been sent
                self.handler.handle_update_user_profile_request(&message.payload, &context).await.map(|_| ())
            }
            _ => {
                warn!(
                    correlation_id = %context.correlation_id,
                    operation = %envelope.operation,
                    "Unknown operation for profileUpdate channel"
                );
                Err(Box::new(AsyncApiError::Handler {
                    message: format!("Unknown operation '{}' for channel 'profileUpdate'", envelope.operation),
                    handler_name: "ProfileUpdateMessageHandler".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::BusinessLogic,
                        false,
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", "profileUpdate")
                    .with_context("operation", &envelope.operation),
                    source: None,
                }))
            }
        }
    }
}

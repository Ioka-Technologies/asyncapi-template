/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function HandlersRs({ asyncapi }) {
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

    // Extract channels and their operations
    const channels = asyncapi.channels();
    const channelData = [];

    if (channels) {
        Object.entries(channels).forEach(([channelName, channel]) => {
            const operations = channel.operations && channel.operations();
            const channelOps = [];

            if (operations) {
                Object.entries(operations).forEach(([opName, operation]) => {
                    const action = operation.action && operation.action();
                    const messages = operation.messages && operation.messages();

                    channelOps.push({
                        name: opName,
                        action,
                        messages: messages || [],
                        rustName: toRustFieldName(opName)
                    });
                });
            }

            channelData.push({
                name: channelName,
                rustName: toRustTypeName(channelName + '_handler'),
                fieldName: toRustFieldName(channelName + '_handler'),
                traitName: toRustTypeName(channelName + '_service'),
                address: channel.address && channel.address(),
                description: channel.description && channel.description(),
                operations: channelOps
            });
        });
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
//!
//! ## Usage
//!
//! Users implement the generated traits to provide business logic:
//!
//! \`\`\`rust
//! use async_trait::async_trait;
//!
//! #[async_trait]
//! impl UserSignupService for MyUserService {
//!     async fn handle_signup(&self, message: &serde_json::Value, context: &MessageContext) -> AsyncApiResult<()> {
//!         // Your business logic here
//!         Ok(())
//!     }
//! }
//! \`\`\`

use crate::context::RequestContext;
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use crate::models::*;
use crate::recovery::{RecoveryManager, RetryConfig};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Context for message processing with correlation tracking
#[derive(Debug, Clone)]
pub struct MessageContext {
    pub correlation_id: Uuid,
    pub channel: String,
    pub operation: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub retry_count: u32,
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
            #[cfg(feature = "auth")]
            claims: None,
        }
    }

    pub fn with_retry(&self, retry_count: u32) -> Self {
        let mut ctx = self.clone();
        ctx.retry_count = retry_count;
        ctx
    }

    /// Get authentication claims if available
    #[cfg(feature = "auth")]
    pub fn claims(&self) -> Option<&crate::auth::Claims> {
        self.claims.as_ref()
    }

    /// Set authentication claims
    #[cfg(feature = "auth")]
    pub fn set_claims(&mut self, claims: crate::auth::Claims) {
        self.claims = Some(claims);
    }

    /// Get authentication claims if available (no-op when auth feature is disabled)
    #[cfg(not(feature = "auth"))]
    pub fn claims(&self) -> Option<&()> {
        None
    }

    /// Set authentication claims (no-op when auth feature is disabled)
    #[cfg(not(feature = "auth"))]
    pub fn set_claims(&mut self, _claims: ()) {
        // No-op when auth feature is disabled
    }
}

${channelData.map(channel => `
/// Business logic trait for ${channel.name} channel operations
/// Users must implement this trait to provide their business logic
#[async_trait]
pub trait ${channel.traitName}: Send + Sync {${channel.operations.map(op => `
    /// Handle ${op.action} operation for ${channel.name}
    async fn handle_${op.rustName}(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()>;`).join('')}
}

/// Handler for ${channel.name} channel with enhanced error handling
/// This is the generated infrastructure code that calls user-implemented traits
#[derive(Debug)]
pub struct ${channel.rustName}<T: ${channel.traitName}> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
}

impl<T: ${channel.traitName}> ${channel.rustName}<T> {
    pub fn new(service: Arc<T>, recovery_manager: Arc<RecoveryManager>) -> Self {
        Self { service, recovery_manager }
    }${channel.operations.map(op => `

    /// Handle ${op.action} operation for ${channel.name} with comprehensive error handling
    #[instrument(skip(self, payload), fields(
        channel = "${channel.name}",
        operation = "${op.name}",
        payload_size = payload.len()
    ))]
    pub async fn handle_${op.rustName}(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        debug!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            retry_count = context.retry_count,
            "Starting message processing"
        );

        // Input validation with detailed error context
        if payload.is_empty() {
            return Err(AsyncApiError::Validation {
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
            });
        }

        // Parse message with error handling
        let message: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(payload) {
            Ok(msg) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    message_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "Successfully parsed message"
                );
                msg
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    payload_preview = %String::from_utf8_lossy(&payload[..payload.len().min(100)]),
                    "Failed to parse message payload"
                );
                return Err(AsyncApiError::Validation {
                    message: format!("Invalid JSON payload: {}", e),
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
                });
            }
        };

        // Call user-implemented business logic
        match self.service.handle_${op.rustName}(&message, context).await {
            Ok(()) => {
                info!(
                    correlation_id = %context.correlation_id,
                    channel = %context.channel,
                    operation = %context.operation,
                    processing_time = ?(chrono::Utc::now() - context.timestamp),
                    "Message processed successfully"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    retry_count = context.retry_count,
                    "Message processing failed"
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

    /// Handle ${op.action} operation with full recovery mechanisms
    pub async fn handle_${op.rustName}_with_recovery(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        let mut retry_strategy = self.recovery_manager.get_retry_strategy("message_handler");

        // Get circuit breaker for this handler
        let circuit_breaker = self.recovery_manager.get_circuit_breaker("${channel.rustName}");

        // Get bulkhead for message processing
        let bulkhead = self.recovery_manager.get_bulkhead("message_processing");

        // Execute with all recovery mechanisms
        let operation = || async {
            // Use bulkhead if available
            if let Some(bulkhead) = &bulkhead {
                bulkhead
                    .execute(|| async { self.handle_${op.rustName}(payload, context).await })
                    .await
            } else {
                self.handle_${op.rustName}(payload, context).await
            }
        };

        // Use circuit breaker if available
        let result = if let Some(ref circuit_breaker) = circuit_breaker {
            circuit_breaker.execute(operation).await
        } else {
            operation().await
        };

        // Apply retry strategy if the operation failed
        match result {
            Ok(()) => Ok(()),
            Err(e) if e.is_retryable() => {
                warn!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    "Operation failed, attempting retry"
                );

                // Clone necessary values to avoid borrowing issues
                let circuit_breaker_clone = circuit_breaker.clone();
                let bulkhead_clone = bulkhead.clone();

                let current_attempt = retry_strategy.current_attempt();
                retry_strategy
                    .execute(|| async {
                        let retry_context = context.with_retry(current_attempt);
                        if let Some(ref circuit_breaker) = circuit_breaker_clone {
                            circuit_breaker
                                .execute(|| async {
                                    if let Some(ref bulkhead) = bulkhead_clone {
                                        bulkhead
                                            .execute(|| async {
                                                self.handle_${op.rustName}(payload, &retry_context).await
                                            })
                                            .await
                                    } else {
                                        self.handle_${op.rustName}(payload, &retry_context).await
                                    }
                                })
                                .await
                        } else {
                            self.handle_${op.rustName}(payload, &retry_context).await
                        }
                    })
                    .await
            }
            Err(e) => Err(e),
        }
    }`).join('')}
}`).join('')}

/// Example implementation showing how users should implement the traits
/// This would typically be in user code, not generated code
pub struct ExampleService;

${channelData.map(channel => `
#[async_trait]
impl ${channel.traitName} for ExampleService {${channel.operations.map(op => `
    async fn handle_${op.rustName}(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // TODO: Replace this with your actual business logic
        info!(
            correlation_id = %context.correlation_id,
            "Processing ${op.name} operation for ${channel.name} channel"
        );

        // Example: Extract and validate message fields
        let message_type = message
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        debug!(
            correlation_id = %context.correlation_id,
            message_type = message_type,
            "Processing message of type: {}", message_type
        );

        // Your business logic goes here
        // For example:
        // - Validate message schema
        // - Extract required fields
        // - Perform business operations
        // - Update databases or external services
        // - Send responses or notifications

        Ok(())
    }`).join('')}
}`).join('')}

/// Registry for managing all handlers with trait-based architecture
/// This provides a unified interface for message routing
#[derive(Debug)]
pub struct HandlerRegistry {
    recovery_manager: Arc<RecoveryManager>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self {
            recovery_manager: Arc::new(RecoveryManager::default()),
        }
    }

    pub fn with_recovery_manager(recovery_manager: Arc<RecoveryManager>) -> Self {
        Self { recovery_manager }
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
        Err(AsyncApiError::Handler {
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
        })
    }

    /// Get recovery manager for external configuration
    pub fn recovery_manager(&self) -> Arc<RecoveryManager> {
        self.recovery_manager.clone()
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

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
                        messages: messages || []
                    });
                });
            }

            channelData.push({
                name: channelName,
                rustName: toRustTypeName(channelName + '_handler'),
                fieldName: toRustFieldName(channelName + '_handler'),
                address: channel.address && channel.address(),
                description: channel.description && channel.description(),
                operations: channelOps.map(op => ({
                    ...op,
                    rustName: toRustFieldName(op.name)
                }))
            });
        });
    }

    return (
        <File name="handlers.rs">
            {`//! Message handlers for AsyncAPI operations with enhanced error handling
//!
//! This module provides:
//! - Robust error handling with custom error types
//! - Retry mechanisms with exponential backoff
//! - Circuit breaker pattern for failure isolation
//! - Dead letter queue for unprocessable messages
//! - Comprehensive logging and monitoring

use crate::context::RequestContext;
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use crate::models::*;
use crate::recovery::{RecoveryManager, RetryConfig};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Base trait for all message handlers with enhanced error handling
#[async_trait]
pub trait MessageHandler<T> {
    /// Handle a message with basic error handling
    async fn handle(&self, message: T) -> AsyncApiResult<()>;

    /// Handle a message with full recovery mechanisms
    async fn handle_with_recovery(
        &self,
        message: T,
        recovery_manager: &RecoveryManager,
    ) -> AsyncApiResult<()>;
}

/// Context for message processing with correlation tracking
#[derive(Debug, Clone)]
pub struct MessageContext {
    pub correlation_id: Uuid,
    pub channel: String,
    pub operation: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub retry_count: u32,
}

impl MessageContext {
    pub fn new(channel: &str, operation: &str) -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            channel: channel.to_string(),
            operation: operation.to_string(),
            timestamp: chrono::Utc::now(),
            retry_count: 0,
        }
    }

    pub fn with_retry(&self, retry_count: u32) -> Self {
        let mut ctx = self.clone();
        ctx.retry_count = retry_count;
        ctx
    }
}

${channelData.map(channel => `/// Handler for ${channel.name} channel with enhanced error handling
#[derive(Debug)]
pub struct ${channel.rustName} {
    recovery_manager: Arc<RecoveryManager>,
}

impl ${channel.rustName} {
    pub fn new(recovery_manager: Arc<RecoveryManager>) -> Self {
        Self { recovery_manager }
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

        // Parse message with error handling - fix type annotation
        let message: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(payload)
        {
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

        // Business logic with error handling
        match self.process_${op.rustName}_message(&message, context).await {
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

    /// Process the actual business logic for ${op.action} operation
    async fn process_${op.rustName}_message(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // TODO: Implement your business logic here
        // This is where you would:
        // 1. Validate the message schema
        // 2. Extract required fields
        // 3. Perform business operations
        // 4. Update databases or external services
        // 5. Send responses or notifications

        // Example implementation with error handling:
        let message_type = message
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AsyncApiError::Validation {
                message: "Missing required field 'type'".to_string(),
                field: Some("type".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                )
                .with_context("correlation_id", &context.correlation_id.to_string()),
                source: None,
            })?;

        debug!(
            correlation_id = %context.correlation_id,
            message_type = message_type,
            "Processing message of type: {}", message_type
        );

        // Simulate processing with potential failure
        match message_type {
            "ping" => {
                info!(correlation_id = %context.correlation_id, "Processing ping message");
                Ok(())
            }
            "error_test" => {
                // Simulate a retryable error for testing
                Err(AsyncApiError::Handler {
                    message: "Simulated processing error for testing".to_string(),
                    handler_name: "${channel.rustName}".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::BusinessLogic,
                        true, // This error is retryable
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("message_type", message_type),
                    source: None,
                })
            }
            _ => {
                warn!(
                    correlation_id = %context.correlation_id,
                    message_type = message_type,
                    "Unknown message type, processing as generic message"
                );
                Ok(())
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
                                                self.handle_${op.rustName}(payload, &retry_context)
                                    .await
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
    }`).join('\n')}
}`).join('\n')}

/// Enhanced handler registry with recovery management
#[derive(Debug)]
pub struct HandlerRegistry {
    ${channelData.map(channel => `pub ${channel.fieldName}: ${channel.rustName},`).join('\n    ')}
    recovery_manager: Arc<RecoveryManager>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        let recovery_manager = Arc::new(RecoveryManager::default());
        Self {
            ${channelData.map(channel => `${channel.fieldName}: ${channel.rustName}::new(recovery_manager.clone()),`).join('\n            ')}
            recovery_manager,
        }
    }

    pub fn with_recovery_manager(recovery_manager: Arc<RecoveryManager>) -> Self {
        Self {
            ${channelData.map(channel => `${channel.fieldName}: ${channel.rustName}::new(recovery_manager.clone()),`).join('\n            ')}
            recovery_manager,
        }
    }

    /// Route message to appropriate handler with enhanced error handling
    #[instrument(skip(self, payload), fields(channel, operation, payload_size = payload.len()))]
    pub async fn route_message(
        &self,
        channel: &str,
        operation: &str,
        payload: &[u8],
    ) -> AsyncApiResult<()> {
        let context = MessageContext::new(channel, operation);

        debug!(
            correlation_id = %context.correlation_id,
            channel = channel,
            operation = operation,
            payload_size = payload.len(),
            "Routing message to handler"
        );

        match channel {
            ${channelData.map(channel => `"${channel.name}" => {
                match operation {
                    ${channel.operations.map(op => `"${op.name}" => {
                        self.${channel.fieldName}.handle_${op.rustName}_with_recovery(payload, &context).await
                    },`).join('\n                    ')}
                    _ => {
                        warn!(
                            correlation_id = %context.correlation_id,
                            channel = channel,
                            operation = operation,
                            "Unknown operation for channel"
                        );
                        Err(AsyncApiError::Handler {
                            message: format!("Unknown operation '{}' for channel '{}'", operation, channel),
                            handler_name: "HandlerRegistry".to_string(),
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::Medium,
                                ErrorCategory::BusinessLogic,
                                false,
                            )
                            .with_context("correlation_id", &context.correlation_id.to_string())
                            .with_context("channel", channel)
                            .with_context("operation", operation),
                            source: None,
                        })
                    }
                }
            },`).join('\n            ')}
            _ => {
                error!(
                    correlation_id = %context.correlation_id,
                    channel = channel,
                    operation = operation,
                    "Unknown channel"
                );
                Err(AsyncApiError::Handler {
                    message: format!("Unknown channel: {}", channel),
                    handler_name: "HandlerRegistry".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::BusinessLogic,
                        false,
                    )
                    .with_context("correlation_id", &context.correlation_id.to_string())
                    .with_context("channel", channel)
                    .with_context("operation", operation),
                    source: None,
                })
            }
        }
    }

    /// Get recovery manager for external configuration
    pub fn recovery_manager(&self) -> Arc<RecoveryManager> {
        self.recovery_manager.clone()
    }

    /// Get handler statistics for monitoring
    pub async fn get_statistics(&self) -> HandlerStatistics {
        HandlerStatistics {
            dead_letter_queue_size: self.recovery_manager.get_dead_letter_queue().size().await,
            // Add more statistics as needed
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

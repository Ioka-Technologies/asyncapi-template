/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function MiddlewareRs() {
    return (
        <File name="middleware.rs">
            {`//! Enhanced middleware for request/response processing with comprehensive error handling
//!
//! This module provides:
//! - Error-aware middleware pipeline
//! - Metrics collection and monitoring
//! - Request/response validation
//! - Performance tracking
//! - Security and rate limiting

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorMetadata, ErrorSeverity, ErrorCategory};
use crate::context::RequestContext;
use crate::recovery::RecoveryManager;
use async_trait::async_trait;
use tracing::{info, warn, error, debug, instrument};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

/// Enhanced middleware trait for processing messages with error handling
#[async_trait::async_trait]
pub trait Middleware: Send + Sync {
    /// Process inbound messages with error handling
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>>;

    /// Process outbound messages with error handling
    async fn process_outbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>>;

    /// Get middleware name for logging and metrics
    fn name(&self) -> &'static str;

    /// Check if middleware is enabled
    fn is_enabled(&self) -> bool {
        true
    }
}

/// Context for middleware processing with correlation tracking
#[derive(Debug, Clone)]
pub struct MiddlewareContext {
    pub correlation_id: Uuid,
    pub channel: String,
    pub operation: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub metadata: std::collections::HashMap<String, String>,
}

impl MiddlewareContext {
    pub fn new(channel: &str, operation: &str) -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            channel: channel.to_string(),
            operation: operation.to_string(),
            timestamp: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Logging middleware that logs all message traffic with enhanced context
pub struct LoggingMiddleware {
    log_payloads: bool,
    max_payload_log_size: usize,
}

impl LoggingMiddleware {
    pub fn new(log_payloads: bool, max_payload_log_size: usize) -> Self {
        Self {
            log_payloads,
            max_payload_log_size,
        }
    }
}

impl Default for LoggingMiddleware {
    fn default() -> Self {
        Self::new(false, 100) // Don't log payloads by default for security
    }
}

#[async_trait::async_trait]
impl Middleware for LoggingMiddleware {
    #[instrument(skip(self, payload), fields(
        middleware = "logging",
        correlation_id = %context.correlation_id,
        channel = %context.channel,
        operation = %context.operation,
        payload_size = payload.len()
    ))]
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let start_time = Instant::now();

        info!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            payload_size = payload.len(),
            "Processing inbound message"
        );

        if self.log_payloads && !payload.is_empty() {
            let payload_preview = if payload.len() > self.max_payload_log_size {
                format!("{}... (truncated)", String::from_utf8_lossy(&payload[..self.max_payload_log_size]))
            } else {
                String::from_utf8_lossy(payload).to_string()
            };

            debug!(
                correlation_id = %context.correlation_id,
                payload_preview = %payload_preview,
                "Inbound message payload"
            );
        }

        let processing_time = start_time.elapsed();
        debug!(
            correlation_id = %context.correlation_id,
            processing_time_ms = processing_time.as_millis(),
            "Logging middleware processing completed"
        );

        Ok(payload.to_vec())
    }

    #[instrument(skip(self, payload), fields(
        middleware = "logging",
        correlation_id = %context.correlation_id,
        channel = %context.channel,
        operation = %context.operation,
        payload_size = payload.len()
    ))]
    async fn process_outbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        info!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            payload_size = payload.len(),
            "Processing outbound message"
        );

        if self.log_payloads && !payload.is_empty() {
            let payload_preview = if payload.len() > self.max_payload_log_size {
                format!("{}... (truncated)", String::from_utf8_lossy(&payload[..self.max_payload_log_size]))
            } else {
                String::from_utf8_lossy(payload).to_string()
            };

            debug!(
                correlation_id = %context.correlation_id,
                payload_preview = %payload_preview,
                "Outbound message payload"
            );
        }

        Ok(payload.to_vec())
    }

    fn name(&self) -> &'static str {
        "logging"
    }
}

/// Metrics middleware for collecting performance data and error rates
pub struct MetricsMiddleware {
    start_time: Instant,
    message_count: Arc<RwLock<u64>>,
    error_count: Arc<RwLock<u64>>,
    processing_times: Arc<RwLock<Vec<std::time::Duration>>>,
}

impl MetricsMiddleware {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            message_count: Arc::new(RwLock::new(0)),
            error_count: Arc::new(RwLock::new(0)),
            processing_times: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn get_metrics(&self) -> MiddlewareMetrics {
        let message_count = *self.message_count.read().await;
        let error_count = *self.error_count.read().await;
        let processing_times = self.processing_times.read().await;

        let avg_processing_time = if processing_times.is_empty() {
            std::time::Duration::ZERO
        } else {
            let total: std::time::Duration = processing_times.iter().sum();
            total / processing_times.len() as u32
        };

        MiddlewareMetrics {
            uptime: self.start_time.elapsed(),
            message_count,
            error_count,
            error_rate: if message_count > 0 { error_count as f64 / message_count as f64 } else { 0.0 },
            avg_processing_time,
        }
    }
}

impl Default for MetricsMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Middleware for MetricsMiddleware {
    #[instrument(skip(self, payload), fields(
        middleware = "metrics",
        correlation_id = %context.correlation_id,
        payload_size = payload.len()
    ))]
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let start_time = Instant::now();

        // Increment message count
        {
            let mut count = self.message_count.write().await;
            *count += 1;
        }

        let processing_time = start_time.elapsed();

        // Record processing time
        {
            let mut times = self.processing_times.write().await;
            times.push(processing_time);

            // Keep only last 1000 measurements to prevent memory growth
            if times.len() > 1000 {
                times.remove(0);
            }
        }

        debug!(
            correlation_id = %context.correlation_id,
            processing_time_ms = processing_time.as_millis(),
            "Metrics collected for inbound message"
        );

        Ok(payload.to_vec())
    }

    async fn process_outbound(&self, _context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        // For outbound, we just pass through without additional metrics
        Ok(payload.to_vec())
    }

    fn name(&self) -> &'static str {
        "metrics"
    }
}

/// Validation middleware for message schema validation with detailed error reporting
pub struct ValidationMiddleware {
    strict_mode: bool,
}

impl ValidationMiddleware {
    pub fn new(strict_mode: bool) -> Self {
        Self { strict_mode }
    }
}

impl Default for ValidationMiddleware {
    fn default() -> Self {
        Self::new(true) // Strict validation by default
    }
}

#[async_trait::async_trait]
impl Middleware for ValidationMiddleware {
    #[instrument(skip(self, payload), fields(
        middleware = "validation",
        correlation_id = %context.correlation_id,
        strict_mode = self.strict_mode,
        payload_size = payload.len()
    ))]
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        debug!(
            correlation_id = %context.correlation_id,
            strict_mode = self.strict_mode,
            "Starting message validation"
        );

        // Basic payload validation
        if payload.is_empty() {
            return Err(AsyncApiError::Validation {
                message: "Empty payload received".to_string(),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                ).with_context("correlation_id", &context.correlation_id.to_string())
                 .with_context("channel", &context.channel)
                 .with_context("operation", &context.operation)
                 .with_context("middleware", "validation"),
                source: None,
            });
        }

        // JSON validation
        match serde_json::from_slice::<serde_json::Value>(payload) {
            Ok(json_value) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    message_type = json_value.get("type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "Message validation successful"
                );

                // Additional validation in strict mode
                if self.strict_mode {
                    // Check for required fields
                    if json_value.get("type").is_none() {
                        warn!(
                            correlation_id = %context.correlation_id,
                            "Missing 'type' field in strict validation mode"
                        );

                        return Err(AsyncApiError::Validation {
                            message: "Missing required field 'type' in message".to_string(),
                            field: Some("type".to_string()),
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::Medium,
                                ErrorCategory::Validation,
                                false,
                            ).with_context("correlation_id", &context.correlation_id.to_string())
                             .with_context("validation_mode", "strict"),
                            source: None,
                        });
                    }
                }

                Ok(payload.to_vec())
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    payload_preview = %String::from_utf8_lossy(&payload[..payload.len().min(100)]),
                    "JSON validation failed"
                );

                Err(AsyncApiError::Validation {
                    message: format!("Invalid JSON payload: {}", e),
                    field: Some("payload".to_string()),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Validation,
                        false,
                    ).with_context("correlation_id", &context.correlation_id.to_string())
                     .with_context("channel", &context.channel)
                     .with_context("operation", &context.operation)
                     .with_context("validation_error", &e.to_string()),
                    source: Some(Box::new(e)),
                })
            }
        }
    }

    async fn process_outbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        // Validate outbound messages as well
        if !payload.is_empty() {
            match serde_json::from_slice::<serde_json::Value>(payload) {
                Ok(_) => {
                    debug!(
                        correlation_id = %context.correlation_id,
                        "Outbound message validation successful"
                    );
                }
                Err(e) => {
                    warn!(
                        correlation_id = %context.correlation_id,
                        error = %e,
                        "Outbound message validation failed"
                    );
                    // For outbound, we might be less strict and just log the warning
                }
            }
        }

        Ok(payload.to_vec())
    }

    fn name(&self) -> &'static str {
        "validation"
    }
}

/// Rate limiting middleware to prevent abuse and overload
pub struct RateLimitMiddleware {
    max_requests_per_minute: u32,
    request_counts: Arc<RwLock<std::collections::HashMap<String, (u32, Instant)>>>,
}

impl RateLimitMiddleware {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            max_requests_per_minute,
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
}

impl Default for RateLimitMiddleware {
    fn default() -> Self {
        Self::new(1000) // 1000 requests per minute by default
    }
}

#[async_trait::async_trait]
impl Middleware for RateLimitMiddleware {
    #[instrument(skip(self, payload), fields(
        middleware = "rate_limit",
        correlation_id = %context.correlation_id,
        max_rpm = self.max_requests_per_minute
    ))]
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let key = format!("{}:{}", context.channel, context.operation);
        let now = Instant::now();

        {
            let mut counts = self.request_counts.write().await;

            // Clean up old entries (older than 1 minute)
            counts.retain(|_, (_, timestamp)| now.duration_since(*timestamp).as_secs() < 60);

            // Check current rate
            let (count, first_request_time) = counts.entry(key.clone()).or_insert((0, now));

            if now.duration_since(*first_request_time).as_secs() < 60 {
                if *count >= self.max_requests_per_minute {
                    warn!(
                        correlation_id = %context.correlation_id,
                        channel = %context.channel,
                        operation = %context.operation,
                        current_count = *count,
                        max_allowed = self.max_requests_per_minute,
                        "Rate limit exceeded"
                    );

                    return Err(AsyncApiError::Resource {
                        message: format!(
                            "Rate limit exceeded: {} requests per minute for {}",
                            self.max_requests_per_minute, key
                        ),
                        resource_type: "rate_limit".to_string(),
                        metadata: ErrorMetadata::new(
                            ErrorSeverity::Medium,
                            ErrorCategory::Resource,
                            true, // Rate limit errors are retryable after some time
                        ).with_context("correlation_id", &context.correlation_id.to_string())
                         .with_context("rate_limit_key", &key)
                         .with_context("current_count", &count.to_string())
                         .with_context("max_allowed", &self.max_requests_per_minute.to_string()),
                        source: None,
                    });
                }
                *count += 1;
            } else {
                // Reset counter for new minute window
                *count = 1;
                *first_request_time = now;
            }
        }

        debug!(
            correlation_id = %context.correlation_id,
            rate_limit_key = %key,
            "Rate limit check passed"
        );

        Ok(payload.to_vec())
    }

    async fn process_outbound(&self, _context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        // No rate limiting for outbound messages
        Ok(payload.to_vec())
    }

    fn name(&self) -> &'static str {
        "rate_limit"
    }
}

/// Middleware pipeline that processes messages through multiple middleware layers
pub struct MiddlewarePipeline {
    middlewares: Vec<Box<dyn Middleware>>,
    recovery_manager: Arc<RecoveryManager>,
}

impl MiddlewarePipeline {
    pub fn new(recovery_manager: Arc<RecoveryManager>) -> Self {
        Self {
            middlewares: Vec::new(),
            recovery_manager,
        }
    }

    /// Initialize the middleware pipeline
    pub async fn initialize(&self) -> AsyncApiResult<()> {
        debug!("Initializing middleware pipeline with {} middlewares", self.middlewares.len());
        Ok(())
    }

    /// Cleanup the middleware pipeline
    pub async fn cleanup(&self) -> AsyncApiResult<()> {
        debug!("Cleaning up middleware pipeline");
        Ok(())
    }

    /// Health check for the middleware pipeline
    pub async fn health_check(&self) -> AsyncApiResult<crate::server::ComponentHealth> {
        Ok(crate::server::ComponentHealth::Healthy)
    }

    /// Add middleware to the pipeline
    pub fn add_middleware<M: Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middlewares.push(Box::new(middleware));
        self
    }

    /// Process inbound message through all middleware
    #[instrument(skip(self, payload), fields(
        pipeline = "inbound",
        middleware_count = self.middlewares.len(),
        payload_size = payload.len()
    ))]
    pub async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let mut current_payload = payload.to_vec();

        for middleware in &self.middlewares {
            if !middleware.is_enabled() {
                debug!(
                    correlation_id = %context.correlation_id,
                    middleware = middleware.name(),
                    "Skipping disabled middleware"
                );
                continue;
            }

            debug!(
                correlation_id = %context.correlation_id,
                middleware = middleware.name(),
                "Processing through middleware"
            );

            match middleware.process_inbound(context, &current_payload).await {
                Ok(processed_payload) => {
                    current_payload = processed_payload;
                }
                Err(e) => {
                    error!(
                        correlation_id = %context.correlation_id,
                        middleware = middleware.name(),
                        error = %e,
                        "Middleware processing failed"
                    );
                    return Err(e);
                }
            }
        }

        info!(
            correlation_id = %context.correlation_id,
            middleware_count = self.middlewares.len(),
            final_payload_size = current_payload.len(),
            "Inbound middleware pipeline completed successfully"
        );

        Ok(current_payload)
    }

    /// Process outbound message through all middleware (in reverse order)
    #[instrument(skip(self, payload), fields(
        pipeline = "outbound",
        middleware_count = self.middlewares.len(),
        payload_size = payload.len()
    ))]
    pub async fn process_outbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let mut current_payload = payload.to_vec();

        // Process in reverse order for outbound
        for middleware in self.middlewares.iter().rev() {
            if !middleware.is_enabled() {
                continue;
            }

            match middleware.process_outbound(context, &current_payload).await {
                Ok(processed_payload) => {
                    current_payload = processed_payload;
                }
                Err(e) => {
                    error!(
                        correlation_id = %context.correlation_id,
                        middleware = middleware.name(),
                        error = %e,
                        "Outbound middleware processing failed"
                    );
                    return Err(e);
                }
            }
        }

        Ok(current_payload)
    }
}

impl Default for MiddlewarePipeline {
    fn default() -> Self {
        let recovery_manager = Arc::new(RecoveryManager::default());
        Self::new(recovery_manager)
            .add_middleware(LoggingMiddleware::default())
            .add_middleware(MetricsMiddleware::default())
            .add_middleware(ValidationMiddleware::default())
            .add_middleware(RateLimitMiddleware::default())
    }
}

/// Metrics collected by middleware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareMetrics {
    pub uptime: std::time::Duration,
    pub message_count: u64,
    pub error_count: u64,
    pub error_rate: f64,
    pub avg_processing_time: std::time::Duration,
}
`}
        </File>
    );
}

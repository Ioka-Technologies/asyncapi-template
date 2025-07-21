import { File } from '@asyncapi/generator-react-sdk';

export default function middlewareFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async_std' : 'tokio';

    return (
        <File name="src/middleware.rs">
            {`//! Middleware system for AsyncAPI server
//!
//! This module provides a flexible middleware system that allows for
//! cross-cutting concerns like logging, metrics, authentication, and more.

use crate::context::{MessageContext, LogLevel};
use crate::error::{HandlerResult, MiddlewareError, MiddlewareResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use chrono::Utc;
use log::{debug, error, info, warn};

/// Middleware trait for processing messages before and after handlers
#[async_trait]
pub trait Middleware: Send + Sync {
    /// Called before the message handler is executed
    ///
    /// # Arguments
    /// * \`message\` - The raw message bytes
    /// * \`context\` - Mutable message context
    ///
    /// # Returns
    /// * \`Ok(())\` to continue processing
    /// * \`Err(MiddlewareError)\` to stop processing (check should_continue)
    async fn before_handle(
        &self,
        message: &[u8],
        context: &mut MessageContext,
    ) -> MiddlewareResult<()>;

    /// Called after the message handler is executed
    ///
    /// # Arguments
    /// * \`result\` - The result from the handler
    /// * \`context\` - Mutable message context
    ///
    /// # Returns
    /// * \`Ok(())\` if middleware processing succeeded
    /// * \`Err(MiddlewareError)\` if middleware processing failed
    async fn after_handle(
        &self,
        result: &HandlerResult<Vec<u8>>,
        context: &mut MessageContext,
    ) -> MiddlewareResult<()>;

    /// Get the name of this middleware
    fn name(&self) -> &'static str;

    /// Get the priority of this middleware (lower numbers run first)
    fn priority(&self) -> u32 {
        100
    }
}

/// Middleware stack for managing multiple middleware components
#[derive(Debug)]
pub struct MiddlewareStack {
    middleware: Vec<Arc<dyn Middleware>>,
}

impl MiddlewareStack {
    /// Create a new middleware stack
    pub fn new() -> Self {
        Self {
            middleware: Vec::new(),
        }
    }

    /// Add middleware to the stack
    pub fn add(&mut self, middleware: Arc<dyn Middleware>) {
        self.middleware.push(middleware);
        // Sort by priority (lower numbers first)
        self.middleware.sort_by_key(|m| m.priority());
    }

    /// Execute all middleware before handlers
    pub async fn before_handle(
        &self,
        message: &[u8],
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        for middleware in &self.middleware {
            if let Err(err) = middleware.before_handle(message, context).await {
                error!("Middleware '{}' failed in before_handle: {}", middleware.name(), err);
                if !err.should_continue {
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    /// Execute all middleware after handlers (in reverse order)
    pub async fn after_handle(
        &self,
        result: &HandlerResult<Vec<u8>>,
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        for middleware in self.middleware.iter().rev() {
            if let Err(err) = middleware.after_handle(result, context).await {
                error!("Middleware '{}' failed in after_handle: {}", middleware.name(), err);
                // Continue processing other middleware even if one fails
            }
        }
        Ok(())
    }

    /// Get the number of middleware in the stack
    pub fn len(&self) -> usize {
        self.middleware.len()
    }

    /// Check if the stack is empty
    pub fn is_empty(&self) -> bool {
        self.middleware.is_empty()
    }
}

/// Logging middleware for structured logging
#[derive(Debug)]
pub struct LoggingMiddleware {
    log_requests: bool,
    log_responses: bool,
    log_errors: bool,
}

impl LoggingMiddleware {
    /// Create a new logging middleware
    pub fn new() -> Self {
        Self {
            log_requests: true,
            log_responses: true,
            log_errors: true,
        }
    }

    /// Create a logging middleware with custom settings
    pub fn with_settings(log_requests: bool, log_responses: bool, log_errors: bool) -> Self {
        Self {
            log_requests,
            log_responses,
            log_errors,
        }
    }
}

#[async_trait]
impl Middleware for LoggingMiddleware {
    async fn before_handle(
        &self,
        message: &[u8],
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        if self.log_requests {
            let message_size = message.len();
            info!(
                "Processing message: operation={}, topic={}, size={}, correlation_id={:?}",
                context.operation,
                context.protocol_metadata.topic,
                message_size,
                context.correlation_id
            );

            context.add_log(
                LogLevel::Info,
                "logging_middleware",
                &format!("Message received: {} bytes", message_size),
            );

            context.add_metric("message_size_bytes", message_size as f64);
        }
        Ok(())
    }

    async fn after_handle(
        &self,
        result: &HandlerResult<Vec<u8>>,
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        match result {
            Ok(response) => {
                if self.log_responses {
                    info!(
                        "Message processed successfully: operation={}, response_size={}, duration={:?}",
                        context.operation,
                        response.len(),
                        context.performance.duration
                    );

                    context.add_log(
                        LogLevel::Info,
                        "logging_middleware",
                        &format!("Message processed: {} bytes response", response.len()),
                    );
                }
            }
            Err(err) => {
                if self.log_errors {
                    error!(
                        "Message processing failed: operation={}, error={}, correlation_id={:?}",
                        context.operation,
                        err,
                        context.correlation_id
                    );

                    context.add_log(
                        LogLevel::Error,
                        "logging_middleware",
                        &format!("Message processing failed: {}", err),
                    );
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "logging"
    }

    fn priority(&self) -> u32 {
        10 // Run early
    }
}

/// Metrics middleware for collecting performance metrics
#[derive(Debug)]
pub struct MetricsMiddleware {
    collect_timing: bool,
    collect_throughput: bool,
    collect_errors: bool,
}

impl MetricsMiddleware {
    /// Create a new metrics middleware
    pub fn new() -> Self {
        Self {
            collect_timing: true,
            collect_throughput: true,
            collect_errors: true,
        }
    }

    /// Create a metrics middleware with custom settings
    pub fn with_settings(collect_timing: bool, collect_throughput: bool, collect_errors: bool) -> Self {
        Self {
            collect_timing,
            collect_throughput,
            collect_errors,
        }
    }
}

#[async_trait]
impl Middleware for MetricsMiddleware {
    async fn before_handle(
        &self,
        _message: &[u8],
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        if self.collect_timing {
            context.add_metric("processing_start_timestamp", Utc::now().timestamp_millis() as f64);
        }

        if self.collect_throughput {
            context.add_metric("messages_received_total", 1.0);
        }

        Ok(())
    }

    async fn after_handle(
        &self,
        result: &HandlerResult<Vec<u8>>,
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        if self.collect_timing {
            if let Some(duration) = context.performance.duration {
                context.add_metric("processing_duration_ms", duration.as_millis() as f64);
            }
        }

        if self.collect_errors && result.is_err() {
            context.add_metric("messages_failed_total", 1.0);
        }

        if self.collect_throughput && result.is_ok() {
            context.add_metric("messages_processed_total", 1.0);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "metrics"
    }

    fn priority(&self) -> u32 {
        20 // Run after logging
    }
}

/// Authentication middleware for validating requests
#[derive(Debug)]
pub struct AuthenticationMiddleware {
    required_headers: Vec<String>,
    token_validation: Option<Arc<dyn TokenValidator>>,
}

/// Trait for validating authentication tokens
#[async_trait]
pub trait TokenValidator: Send + Sync {
    async fn validate_token(&self, token: &str) -> Result<AuthInfo, String>;
}

/// Authentication information
#[derive(Debug, Clone)]
pub struct AuthInfo {
    pub user_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

impl AuthenticationMiddleware {
    /// Create a new authentication middleware
    pub fn new() -> Self {
        Self {
            required_headers: vec!["authorization".to_string()],
            token_validation: None,
        }
    }

    /// Set required headers
    pub fn with_required_headers(mut self, headers: Vec<String>) -> Self {
        self.required_headers = headers;
        self
    }

    /// Set token validator
    pub fn with_token_validator(mut self, validator: Arc<dyn TokenValidator>) -> Self {
        self.token_validation = Some(validator);
        self
    }
}

#[async_trait]
impl Middleware for AuthenticationMiddleware {
    async fn before_handle(
        &self,
        _message: &[u8],
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        // Check required headers
        for header in &self.required_headers {
            if context.get_header(header).is_none() {
                return Err(MiddlewareError::new(
                    "authentication",
                    &format!("Missing required header: {}", header),
                    false,
                ));
            }
        }

        // Validate token if validator is provided
        if let Some(validator) = &self.token_validation {
            if let Some(auth_header) = context.get_header("authorization") {
                let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

                match validator.validate_token(token).await {
                    Ok(auth_info) => {
                        context.set_auth_info("bearer", &auth_info.user_id, auth_info.roles);
                        context.add_log(
                            LogLevel::Debug,
                            "authentication_middleware",
                            &format!("User authenticated: {}", auth_info.user_id),
                        );
                    }
                    Err(err) => {
                        return Err(MiddlewareError::new(
                            "authentication",
                            &format!("Token validation failed: {}", err),
                            false,
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    async fn after_handle(
        &self,
        _result: &HandlerResult<Vec<u8>>,
        _context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "authentication"
    }

    fn priority(&self) -> u32 {
        5 // Run very early
    }
}

/// Rate limiting middleware
#[derive(Debug)]
pub struct RateLimitingMiddleware {
    max_requests_per_minute: u32,
    request_counts: Arc<${runtime === 'tokio' ? 'tokio::sync::RwLock' : 'async_std::sync::RwLock'}<HashMap<String, (u32, Instant)>>>,
}

impl RateLimitingMiddleware {
    /// Create a new rate limiting middleware
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            max_requests_per_minute,
            request_counts: Arc::new(${runtime === 'tokio' ? 'tokio::sync::RwLock' : 'async_std::sync::RwLock'}::new(HashMap::new())),
        }
    }

    /// Get rate limit key for a context
    fn get_rate_limit_key(&self, context: &MessageContext) -> String {
        // Use user ID if available, otherwise use client IP, otherwise use "anonymous"
        context.user_id
            .clone()
            .or_else(|| context.security.client_ip.clone())
            .unwrap_or_else(|| "anonymous".to_string())
    }
}

#[async_trait]
impl Middleware for RateLimitingMiddleware {
    async fn before_handle(
        &self,
        _message: &[u8],
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        let key = self.get_rate_limit_key(context);
        let now = Instant::now();

        let mut counts = self.request_counts.write().await;

        let (count, last_reset) = counts.get(&key).copied().unwrap_or((0, now));

        // Reset counter if more than a minute has passed
        let (current_count, reset_time) = if now.duration_since(last_reset) >= Duration::from_secs(60) {
            (1, now)
        } else {
            (count + 1, last_reset)
        };

        if current_count > self.max_requests_per_minute {
            let retry_after = 60 - now.duration_since(reset_time).as_secs();
            return Err(MiddlewareError::new(
                "rate_limiting",
                &format!("Rate limit exceeded. Retry after {} seconds", retry_after),
                false,
            ));
        }

        counts.insert(key, (current_count, reset_time));

        context.add_metric("rate_limit_current_count", current_count as f64);
        context.add_metric("rate_limit_max_count", self.max_requests_per_minute as f64);

        Ok(())
    }

    async fn after_handle(
        &self,
        _result: &HandlerResult<Vec<u8>>,
        _context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "rate_limiting"
    }

    fn priority(&self) -> u32 {
        15 // Run after authentication but before business logic
    }
}

/// Tracing middleware for distributed tracing
#[derive(Debug)]
pub struct TracingMiddleware {
    service_name: String,
}

impl TracingMiddleware {
    /// Create a new tracing middleware
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }
}

#[async_trait]
impl Middleware for TracingMiddleware {
    async fn before_handle(
        &self,
        _message: &[u8],
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        let span_id = context.start_span(&format!("{}.{}", self.service_name, context.operation));

        context.add_log(
            LogLevel::Debug,
            "tracing_middleware",
            &format!("Started trace span: {}", span_id),
        );

        Ok(())
    }

    async fn after_handle(
        &self,
        result: &HandlerResult<Vec<u8>>,
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        if let Some(span_id) = context.get_current_span_id() {
            context.finish_span(&span_id);

            let status = if result.is_ok() { "success" } else { "error" };
            context.add_log(
                LogLevel::Debug,
                "tracing_middleware",
                &format!("Finished trace span: {} (status: {})", span_id, status),
            );
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "tracing"
    }

    fn priority(&self) -> u32 {
        1 // Run first to capture the entire request
    }
}

impl Default for MiddlewareStack {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for LoggingMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for MetricsMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AuthenticationMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::MessageContext;

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_middleware_stack() {
        let mut stack = MiddlewareStack::new();
        stack.add(Arc::new(LoggingMiddleware::new()));
        stack.add(Arc::new(MetricsMiddleware::new()));

        assert_eq!(stack.len(), 2);

        let mut context = MessageContext::new("test", "topic");
        let message = b"test message";

        let result = stack.before_handle(message, &mut context).await;
        assert!(result.is_ok());

        let handler_result: HandlerResult<Vec<u8>> = Ok(b"response".to_vec());
        let result = stack.after_handle(&handler_result, &mut context).await;
        assert!(result.is_ok());
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_logging_middleware() {
        let middleware = LoggingMiddleware::new();
        let mut context = MessageContext::new("test", "topic");
        let message = b"test message";

        let result = middleware.before_handle(message, &mut context).await;
        assert!(result.is_ok());
        assert!(!context.middleware_data.logs.is_empty());

        let handler_result: HandlerResult<Vec<u8>> = Ok(b"response".to_vec());
        let result = middleware.after_handle(&handler_result, &mut context).await;
        assert!(result.is_ok());
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_metrics_middleware() {
        let middleware = MetricsMiddleware::new();
        let mut context = MessageContext::new("test", "topic");
        let message = b"test message";

        let result = middleware.before_handle(message, &mut context).await;
        assert!(result.is_ok());
        assert!(context.get_metric("messages_received_total").is_some());

        let handler_result: HandlerResult<Vec<u8>> = Ok(b"response".to_vec());
        let result = middleware.after_handle(&handler_result, &mut context).await;
        assert!(result.is_ok());
        assert!(context.get_metric("messages_processed_total").is_some());
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_rate_limiting_middleware() {
        let middleware = RateLimitingMiddleware::new(5); // 5 requests per minute
        let mut context = MessageContext::new("test", "topic");
        context.set_client_info(Some("192.168.1.1"), None);
        let message = b"test message";

        // First 5 requests should succeed
        for _ in 0..5 {
            let result = middleware.before_handle(message, &mut context).await;
            assert!(result.is_ok());
        }

        // 6th request should fail
        let result = middleware.before_handle(message, &mut context).await;
        assert!(result.is_err());
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_tracing_middleware() {
        let middleware = TracingMiddleware::new("test_service");
        let mut context = MessageContext::new("test", "topic");
        let message = b"test message";

        let result = middleware.before_handle(message, &mut context).await;
        assert!(result.is_ok());
        assert!(!context.middleware_data.traces.is_empty());

        let handler_result: HandlerResult<Vec<u8>> = Ok(b"response".to_vec());
        let result = middleware.after_handle(&handler_result, &mut context).await;
        assert!(result.is_ok());
        assert!(context.middleware_data.traces[0].end_time.is_some());
    }
}
`}
        </File>
    );
}

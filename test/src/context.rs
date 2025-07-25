//! Advanced context management system for AsyncAPI applications
//!
//! This module provides:
//! - Request-scoped context with automatic propagation
//! - Thread-safe execution context for shared state
//! - Context-aware error handling and enrichment
//! - Performance metrics and tracing integration
//! - Middleware data sharing and storage

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn, Span};
use uuid::Uuid;

/// Request-scoped context that carries data through the entire processing pipeline
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Unique correlation ID for request tracking
    pub correlation_id: Uuid,
    /// Request start time for performance tracking
    pub start_time: Instant,
    /// Request timestamp
    pub timestamp: SystemTime,
    /// Source channel/topic
    pub channel: String,
    /// Operation being performed
    pub operation: String,
    /// Request metadata and headers
    pub metadata: HashMap<String, String>,
    /// Custom data storage for middleware and handlers
    pub data: Arc<RwLock<HashMap<String, ContextValue>>>,
    /// Performance metrics
    pub metrics: Arc<RwLock<RequestMetrics>>,
    /// Tracing span for distributed tracing
    pub span: Span,
    /// Request priority (for routing and processing)
    pub priority: RequestPriority,
    /// Request tags for categorization
    pub tags: Vec<String>,
    /// Authentication claims (if authenticated)
    #[cfg(feature = "auth")]
    pub auth_claims: Option<crate::auth::Claims>,
    /// Server-level authentication context
    #[cfg(feature = "auth")]
    pub server_auth_context: Option<crate::auth::ServerAuthContext>,
}

impl RequestContext {
    /// Create a new request context
    pub fn new(channel: &str, operation: &str) -> Self {
        let correlation_id = Uuid::new_v4();
        let span = tracing::info_span!(
            "request",
            correlation_id = %correlation_id,
            channel = %channel,
            operation = %operation
        );

        Self {
            correlation_id,
            start_time: Instant::now(),
            timestamp: SystemTime::now(),
            channel: channel.to_string(),
            operation: operation.to_string(),
            metadata: HashMap::new(),
            data: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(RequestMetrics::new())),
            span,
            priority: RequestPriority::Normal,
            tags: Vec::new(),
            #[cfg(feature = "auth")]
            auth_claims: None,
            #[cfg(feature = "auth")]
            server_auth_context: None,
        }
    }

    /// Create context with custom correlation ID
    pub fn with_correlation_id(channel: &str, operation: &str, correlation_id: Uuid) -> Self {
        let mut ctx = Self::new(channel, operation);
        ctx.correlation_id = correlation_id;
        ctx
    }

    /// Add metadata to the context
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Set request priority
    pub fn with_priority(mut self, priority: RequestPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Add tags to the context
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Store data in the context
    pub async fn set_data<T: Into<ContextValue>>(&self, key: &str, value: T) -> AsyncApiResult<()> {
        let mut data = self.data.write().await;
        data.insert(key.to_string(), value.into());
        debug!(
            correlation_id = %self.correlation_id,
            key = key,
            "Stored data in request context"
        );
        Ok(())
    }

    /// Retrieve data from the context
    pub async fn get_data(&self, key: &str) -> Option<ContextValue> {
        let data = self.data.read().await;
        data.get(key).cloned()
    }

    /// Get typed data from the context
    pub async fn get_typed_data<T>(&self, key: &str) -> AsyncApiResult<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        if let Some(value) = self.get_data(key).await {
            match value {
                ContextValue::Json(json_str) => match serde_json::from_str::<T>(&json_str) {
                    Ok(typed_value) => Ok(Some(typed_value)),
                    Err(e) => Err(Box::new(AsyncApiError::Context {
                        message: format!("Failed to deserialize context data: {}", e),
                        context_key: key.to_string(),
                        metadata: ErrorMetadata::new(
                            ErrorSeverity::Medium,
                            ErrorCategory::Serialization,
                            false,
                        )
                        .with_context("correlation_id", &self.correlation_id.to_string()),
                        source: Some(Box::new(e)),
                    })),
                },
                _ => Err(Box::new(AsyncApiError::Context {
                    message: "Context value is not JSON serializable".to_string(),
                    context_key: key.to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Low,
                        ErrorCategory::Validation,
                        false,
                    )
                    .with_context("correlation_id", &self.correlation_id.to_string()),
                    source: None,
                })),
            }
        } else {
            Ok(None)
        }
    }

    /// Record a metric event
    pub async fn record_metric(&self, event: MetricEvent) {
        let mut metrics = self.metrics.write().await;
        metrics.record_event(event);
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> RequestMetrics {
        self.metrics.read().await.clone()
    }

    /// Get elapsed time since request start
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Create a child context for sub-operations
    pub fn child_context(&self, operation: &str) -> Self {
        let child_span = tracing::info_span!(
            parent: &self.span,
            "child_operation",
            operation = %operation,
            parent_correlation_id = %self.correlation_id
        );

        Self {
            correlation_id: Uuid::new_v4(),
            start_time: Instant::now(),
            timestamp: SystemTime::now(),
            channel: self.channel.clone(),
            operation: operation.to_string(),
            metadata: self.metadata.clone(),
            data: self.data.clone(), // Share data with parent
            metrics: Arc::new(RwLock::new(RequestMetrics::new())),
            span: child_span,
            priority: self.priority,
            tags: self.tags.clone(),
            #[cfg(feature = "auth")]
            auth_claims: self.auth_claims.clone(),
            #[cfg(feature = "auth")]
            server_auth_context: self.server_auth_context.clone(),
        }
    }

    /// Set authentication claims
    #[cfg(feature = "auth")]
    pub fn set_auth_claims(&mut self, claims: crate::auth::Claims) {
        self.auth_claims = Some(claims);
    }

    /// Get authentication claims
    #[cfg(feature = "auth")]
    pub fn get_auth_claims(&self) -> Option<&crate::auth::Claims> {
        self.auth_claims.as_ref()
    }

    /// Check if the request is authenticated
    #[cfg(feature = "auth")]
    pub fn is_authenticated(&self) -> bool {
        self.auth_claims.is_some()
    }

    /// Check if the request is authenticated (auth feature disabled)
    #[cfg(not(feature = "auth"))]
    pub fn is_authenticated(&self) -> bool {
        false
    }

    /// Get the authenticated user ID
    #[cfg(feature = "auth")]
    pub fn get_user_id(&self) -> Option<&str> {
        self.auth_claims.as_ref().map(|claims| claims.sub.as_str())
    }

    /// Get the authenticated user ID (auth feature disabled)
    #[cfg(not(feature = "auth"))]
    pub fn get_user_id(&self) -> Option<&str> {
        None
    }

    /// Check if the authenticated user has a specific role
    #[cfg(feature = "auth")]
    pub fn has_role(&self, role: &str) -> bool {
        self.auth_claims
            .as_ref()
            .map(|claims| claims.has_role(role))
            .unwrap_or(false)
    }

    /// Check if the authenticated user has a specific role (auth feature disabled)
    #[cfg(not(feature = "auth"))]
    pub fn has_role(&self, _role: &str) -> bool {
        false
    }

    /// Check if the authenticated user has a specific permission
    #[cfg(feature = "auth")]
    pub fn has_permission(&self, permission: &str) -> bool {
        self.auth_claims
            .as_ref()
            .map(|claims| claims.has_permission(permission))
            .unwrap_or(false)
    }

    /// Check if the authenticated user has a specific permission (auth feature disabled)
    #[cfg(not(feature = "auth"))]
    pub fn has_permission(&self, _permission: &str) -> bool {
        false
    }

    /// Set server authentication context
    #[cfg(feature = "auth")]
    pub fn set_server_auth_context(&mut self, context: crate::auth::ServerAuthContext) {
        self.server_auth_context = Some(context);
    }

    /// Get server authentication context
    #[cfg(feature = "auth")]
    pub fn get_server_auth_context(&self) -> Option<&crate::auth::ServerAuthContext> {
        self.server_auth_context.as_ref()
    }

    /// Check if the connection has server-level authentication
    #[cfg(feature = "auth")]
    pub fn has_server_auth(&self) -> bool {
        self.server_auth_context.as_ref().map(|ctx| ctx.authenticated).unwrap_or(false)
    }

    /// Check if the connection has a specific server-level scope
    #[cfg(feature = "auth")]
    pub fn has_server_scope(&self, scope: &str) -> bool {
        self.server_auth_context
            .as_ref()
            .map(|ctx| ctx.has_server_scope(scope))
            .unwrap_or(false)
    }

    /// Check if the connection has any of the specified server-level scopes
    #[cfg(feature = "auth")]
    pub fn has_any_server_scope(&self, scopes: &[&str]) -> bool {
        self.server_auth_context
            .as_ref()
            .map(|ctx| ctx.has_any_server_scope(scopes))
            .unwrap_or(false)
    }

    /// Check if the connection has all of the specified server-level scopes
    #[cfg(feature = "auth")]
    pub fn has_all_server_scopes(&self, scopes: &[&str]) -> bool {
        self.server_auth_context
            .as_ref()
            .map(|ctx| ctx.has_all_server_scopes(scopes))
            .unwrap_or(false)
    }

    /// Get the server authentication principal
    #[cfg(feature = "auth")]
    pub fn get_server_principal(&self) -> Option<&str> {
        self.server_auth_context
            .as_ref()
            .and_then(|ctx| ctx.principal())
    }

    /// Check if the request has both server and operation level authentication
    #[cfg(feature = "auth")]
    pub fn is_fully_authenticated(&self) -> bool {
        self.has_server_auth() && self.is_authenticated()
    }

    /// Check if the request has access to a specific scope (checks both server and operation level)
    #[cfg(feature = "auth")]
    pub fn has_access(&self, scope: &str) -> bool {
        // Check operation-level access first
        if let Some(claims) = &self.auth_claims {
            if claims.has_access(scope) {
                return true;
            }
        }

        // Check server-level access
        self.has_server_scope(scope)
    }

    /// Check if the request has access to any of the specified scopes
    #[cfg(feature = "auth")]
    pub fn has_any_access(&self, scopes: &[&str]) -> bool {
        scopes.iter().any(|scope| self.has_access(scope))
    }

    /// Check if the request has access to all of the specified scopes
    #[cfg(feature = "auth")]
    pub fn has_all_access(&self, scopes: &[&str]) -> bool {
        scopes.iter().all(|scope| self.has_access(scope))
    }

    /// Get client ID for rate limiting and tracking
    pub fn get_client_id(&self) -> Option<String> {
        // Try to get from auth claims first
        #[cfg(feature = "auth")]
        if let Some(claims) = &self.auth_claims {
            return Some(claims.sub.clone());
        }

        // Fall back to metadata
        if let Some(client_id) = self.metadata.get("client_id") {
            return Some(client_id.clone());
        }

        // Fall back to IP address or other identifier
        if let Some(ip) = self.metadata.get("remote_addr") {
            return Some(ip.clone());
        }

        None
    }

    /// Get header value
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.metadata
            .get(&format!("header_{}", name.to_lowercase()))
    }

    /// Set header value
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.metadata
            .insert(format!("header_{}", name.to_lowercase()), value.to_string());
    }

    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Set metadata value
    pub fn set_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Get property value (convenience method for common properties)
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.metadata.get(&format!("prop_{}", key))
    }

    /// Set property value (convenience method for common properties)
    pub fn set_property(&mut self, key: String, value: String) {
        self.metadata.insert(format!("prop_{}", key), value);
    }

    /// Enrich error with context information
    pub fn enrich_error(&self, mut error: AsyncApiError) -> AsyncApiError {
        error.add_context("correlation_id", &self.correlation_id.to_string());
        error.add_context("channel", &self.channel);
        error.add_context("operation", &self.operation);
        error.add_context("elapsed_ms", &self.elapsed().as_millis().to_string());

        // Add metadata to error context
        for (key, value) in &self.metadata {
            error.add_context(&format!("metadata_{}", key), value);
        }

        error
    }
}

/// Values that can be stored in the context
#[derive(Debug, Clone)]
pub enum ContextValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Json(String),
    Binary(Vec<u8>),
}

impl From<String> for ContextValue {
    fn from(value: String) -> Self {
        ContextValue::String(value)
    }
}

impl From<&str> for ContextValue {
    fn from(value: &str) -> Self {
        ContextValue::String(value.to_string())
    }
}

impl From<i64> for ContextValue {
    fn from(value: i64) -> Self {
        ContextValue::Integer(value)
    }
}

impl From<f64> for ContextValue {
    fn from(value: f64) -> Self {
        ContextValue::Float(value)
    }
}

impl From<bool> for ContextValue {
    fn from(value: bool) -> Self {
        ContextValue::Boolean(value)
    }
}

impl From<Vec<u8>> for ContextValue {
    fn from(value: Vec<u8>) -> Self {
        ContextValue::Binary(value)
    }
}

impl<T: Serialize> From<&T> for ContextValue {
    fn from(value: &T) -> Self {
        match serde_json::to_string(value) {
            Ok(json) => ContextValue::Json(json),
            Err(_) => ContextValue::String("serialization_failed".to_string()),
        }
    }
}

/// Request priority levels for routing and processing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RequestPriority {
    Low = 1,
    #[default]
    Normal = 2,
    High = 3,
    Critical = 4,
}

/// Performance metrics for a request
#[derive(Debug, Clone)]
pub struct RequestMetrics {
    pub events: Vec<MetricEvent>,
    pub start_time: Instant,
}

impl Default for RequestMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestMetrics {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            start_time: Instant::now(),
        }
    }

    pub fn record_event(&mut self, event: MetricEvent) {
        self.events.push(event);
    }

    pub fn total_duration(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn get_events_by_type(&self, event_type: &str) -> Vec<&MetricEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }
}

/// Individual metric event
#[derive(Debug, Clone)]
pub struct MetricEvent {
    pub event_type: String,
    pub timestamp: Instant,
    pub duration: Option<Duration>,
    pub metadata: HashMap<String, String>,
}

impl MetricEvent {
    pub fn new(event_type: &str) -> Self {
        Self {
            event_type: event_type.to_string(),
            timestamp: Instant::now(),
            duration: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Global execution context for shared state
#[derive(Debug)]
pub struct ExecutionContext {
    /// Application-wide configuration
    pub config: Arc<RwLock<HashMap<String, String>>>,
    /// Shared metrics and statistics
    pub global_metrics: Arc<RwLock<GlobalMetrics>>,
    /// Active request contexts
    pub active_requests: Arc<RwLock<HashMap<Uuid, RequestContext>>>,
    /// Context creation time
    pub created_at: SystemTime,
}

impl ExecutionContext {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(HashMap::new())),
            global_metrics: Arc::new(RwLock::new(GlobalMetrics::new())),
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            created_at: SystemTime::now(),
        }
    }

    /// Register an active request
    pub async fn register_request(&self, context: RequestContext) {
        let mut requests = self.active_requests.write().await;
        requests.insert(context.correlation_id, context);

        let mut metrics = self.global_metrics.write().await;
        metrics.active_requests += 1;
        metrics.total_requests += 1;
    }

    /// Unregister a completed request
    pub async fn unregister_request(&self, correlation_id: Uuid) -> Option<RequestContext> {
        let mut requests = self.active_requests.write().await;
        let context = requests.remove(&correlation_id);

        if context.is_some() {
            let mut metrics = self.global_metrics.write().await;
            metrics.active_requests = metrics.active_requests.saturating_sub(1);
        }

        context
    }

    /// Get active request count
    pub async fn active_request_count(&self) -> usize {
        self.active_requests.read().await.len()
    }

    /// Get global metrics
    pub async fn get_global_metrics(&self) -> GlobalMetrics {
        self.global_metrics.read().await.clone()
    }

    /// Set configuration value
    pub async fn set_config(&self, key: &str, value: &str) {
        let mut config = self.config.write().await;
        config.insert(key.to_string(), value.to_string());
    }

    /// Get configuration value
    pub async fn get_config(&self, key: &str) -> Option<String> {
        let config = self.config.read().await;
        config.get(key).cloned()
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global application metrics
#[derive(Debug, Clone)]
pub struct GlobalMetrics {
    pub total_requests: u64,
    pub active_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub average_response_time: Duration,
    pub uptime: Duration,
    pub start_time: SystemTime,
}

impl Default for GlobalMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalMetrics {
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            active_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            average_response_time: Duration::ZERO,
            uptime: Duration::ZERO,
            start_time: SystemTime::now(),
        }
    }

    pub fn record_success(&mut self, duration: Duration) {
        self.successful_requests += 1;
        self.update_average_response_time(duration);
    }

    pub fn record_failure(&mut self, duration: Duration) {
        self.failed_requests += 1;
        self.update_average_response_time(duration);
    }

    fn update_average_response_time(&mut self, duration: Duration) {
        let total_completed = self.successful_requests + self.failed_requests;
        if total_completed > 0 {
            let total_time = self.average_response_time.as_nanos() * (total_completed - 1) as u128
                + duration.as_nanos();
            self.average_response_time =
                Duration::from_nanos((total_time / total_completed as u128) as u64);
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total_completed = self.successful_requests + self.failed_requests;
        if total_completed > 0 {
            self.successful_requests as f64 / total_completed as f64
        } else {
            0.0
        }
    }
}

/// Context manager for handling context lifecycle
#[derive(Debug)]
pub struct ContextManager {
    execution_context: Arc<ExecutionContext>,
}

impl ContextManager {
    pub fn new() -> Self {
        Self {
            execution_context: Arc::new(ExecutionContext::new()),
        }
    }

    pub fn with_execution_context(execution_context: Arc<ExecutionContext>) -> Self {
        Self { execution_context }
    }

    /// Create a new request context and register it
    #[instrument(skip(self), fields(channel, operation))]
    pub async fn create_request_context(&self, channel: &str, operation: &str) -> RequestContext {
        let context = RequestContext::new(channel, operation);

        debug!(
            correlation_id = %context.correlation_id,
            channel = %channel,
            operation = %operation,
            "Created new request context"
        );

        self.execution_context
            .register_request(context.clone())
            .await;
        context
    }

    /// Complete a request context and update metrics
    #[instrument(skip(self, context), fields(correlation_id = %context.correlation_id))]
    pub async fn complete_request_context(
        &self,
        context: RequestContext,
        success: bool,
    ) -> AsyncApiResult<()> {
        let duration = context.elapsed();

        // Update global metrics
        {
            let mut metrics = self.execution_context.global_metrics.write().await;
            if success {
                metrics.record_success(duration);
            } else {
                metrics.record_failure(duration);
            }
        }

        // Unregister the request
        self.execution_context
            .unregister_request(context.correlation_id)
            .await;

        info!(
            correlation_id = %context.correlation_id,
            duration_ms = duration.as_millis(),
            success = success,
            "Completed request context"
        );

        Ok(())
    }

    /// Get execution context
    pub fn execution_context(&self) -> Arc<ExecutionContext> {
        self.execution_context.clone()
    }

    /// Get context statistics
    pub async fn get_statistics(&self) -> ContextStatistics {
        let global_metrics = self.execution_context.get_global_metrics().await;
        let active_count = self.execution_context.active_request_count().await;

        ContextStatistics {
            active_requests: active_count,
            total_requests: global_metrics.total_requests,
            success_rate: global_metrics.success_rate(),
            average_response_time: global_metrics.average_response_time,
            uptime: self
                .execution_context
                .created_at
                .elapsed()
                .unwrap_or_default(),
        }
    }
}

impl Default for ContextManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about context usage
#[derive(Debug, Clone, Serialize)]
pub struct ContextStatistics {
    pub active_requests: usize,
    pub total_requests: u64,
    pub success_rate: f64,
    pub average_response_time: Duration,
    pub uptime: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_request_context_creation() {
        let ctx = RequestContext::new("test/channel", "test_operation");
        assert_eq!(ctx.channel, "test/channel");
        assert_eq!(ctx.operation, "test_operation");
        assert_eq!(ctx.priority, RequestPriority::Normal);
    }

    #[tokio::test]
    async fn test_context_data_storage() {
        let ctx = RequestContext::new("test/channel", "test_operation");

        ctx.set_data("test_key", "test_value").await.unwrap();
        let value = ctx.get_data("test_key").await;

        assert!(value.is_some());
        match value.unwrap() {
            ContextValue::String(s) => assert_eq!(s, "test_value"),
            _ => panic!("Expected string value"),
        }
    }

    #[tokio::test]
    async fn test_context_manager() {
        let manager = ContextManager::new();
        let ctx = manager
            .create_request_context("test/channel", "test_op")
            .await;

        assert_eq!(manager.execution_context.active_request_count().await, 1);

        manager.complete_request_context(ctx, true).await.unwrap();
        assert_eq!(manager.execution_context.active_request_count().await, 0);
    }

    #[test]
    fn test_request_priority_ordering() {
        assert!(RequestPriority::Critical > RequestPriority::High);
        assert!(RequestPriority::High > RequestPriority::Normal);
        assert!(RequestPriority::Normal > RequestPriority::Low);
    }
}

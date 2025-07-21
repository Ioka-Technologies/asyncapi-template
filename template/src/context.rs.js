import { File } from '@asyncapi/generator-react-sdk';

export default function contextFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async_std' : 'tokio';

    return (
        <File name="src/context.rs">
            {`//! Message context for AsyncAPI server operations
//!
//! This module provides rich context information for message processing,
//! including support for request-response patterns, tracing, and middleware data.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Context information for message processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContext {
    /// Unique message identifier
    pub message_id: String,
    /// Correlation ID for request-response patterns
    pub correlation_id: Option<String>,
    /// Reply-to address for responses
    pub reply_to: Option<String>,
    /// Custom message headers
    pub headers: HashMap<String, String>,
    /// Timestamp when message was received
    pub timestamp: DateTime<Utc>,
    /// The operation being performed
    pub operation: String,
    /// User ID if authenticated
    pub user_id: Option<String>,
    /// Request ID for tracing
    pub request_id: Option<String>,
    /// Session ID if applicable
    pub session_id: Option<String>,
    /// Request-response context
    pub request_response: RequestResponseContext,
    /// Protocol-specific metadata
    pub protocol_metadata: ProtocolMetadata,
    /// Middleware data storage
    pub middleware_data: MiddlewareData,
    /// Performance tracking
    pub performance: PerformanceContext,
    /// Security context
    pub security: SecurityContext,
}

/// Request-response pattern context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestResponseContext {
    /// Fire-and-forget message (no response expected)
    FireAndForget,
    /// Request-response pattern
    RequestResponse {
        /// Topic/channel to send response to
        response_topic: String,
        /// Timeout for response
        timeout: Duration,
        /// Whether response is required
        response_required: bool,
    },
}

/// Protocol-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMetadata {
    /// The protocol being used
    pub protocol: String,
    /// Topic/channel/queue name
    pub topic: String,
    /// Protocol-specific properties
    pub properties: HashMap<String, String>,
}

/// Middleware data storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareData {
    /// Data stored by middleware components
    pub data: HashMap<String, serde_json::Value>,
    /// Metrics collected during processing
    pub metrics: HashMap<String, f64>,
    /// Log entries from middleware
    pub logs: Vec<LogEntry>,
    /// Trace spans for observability
    pub traces: Vec<TraceSpan>,
}

/// Performance tracking context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceContext {
    /// When message processing started
    pub start_time: DateTime<Utc>,
    /// Processing duration (set when complete)
    pub duration: Option<Duration>,
    /// Memory usage at start
    pub memory_usage_start: Option<u64>,
    /// Memory usage at end
    pub memory_usage_end: Option<u64>,
    /// Custom performance metrics
    pub custom_metrics: HashMap<String, f64>,
}

/// Security context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Authentication method used
    pub auth_method: Option<String>,
    /// User roles/permissions
    pub roles: Vec<String>,
    /// Security tokens
    pub tokens: HashMap<String, String>,
    /// IP address of the client
    pub client_ip: Option<String>,
    /// User agent information
    pub user_agent: Option<String>,
}

/// Log entry for middleware logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Log level
    pub level: LogLevel,
    /// Log message
    pub message: String,
    /// Timestamp of log entry
    pub timestamp: DateTime<Utc>,
    /// Component that generated the log
    pub component: String,
    /// Additional log data
    pub data: HashMap<String, serde_json::Value>,
}

/// Log levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Trace span for distributed tracing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    /// Span ID
    pub span_id: String,
    /// Parent span ID
    pub parent_span_id: Option<String>,
    /// Trace ID
    pub trace_id: String,
    /// Operation name
    pub operation_name: String,
    /// Start time
    pub start_time: DateTime<Utc>,
    /// End time
    pub end_time: Option<DateTime<Utc>>,
    /// Span tags
    pub tags: HashMap<String, String>,
    /// Span logs
    pub logs: Vec<SpanLog>,
}

/// Span log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanLog {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Log fields
    pub fields: HashMap<String, String>,
}

impl MessageContext {
    /// Create a new message context
    pub fn new(operation: &str, topic: &str) -> Self {
        let now = Utc::now();
        let message_id = Uuid::new_v4().to_string();

        Self {
            message_id,
            correlation_id: None,
            reply_to: None,
            headers: HashMap::new(),
            timestamp: now,
            operation: operation.to_string(),
            user_id: None,
            request_id: Some(Uuid::new_v4().to_string()),
            session_id: None,
            request_response: RequestResponseContext::FireAndForget,
            protocol_metadata: ProtocolMetadata {
                protocol: "${protocol}".to_string(),
                topic: topic.to_string(),
                properties: HashMap::new(),
            },
            middleware_data: MiddlewareData::new(),
            performance: PerformanceContext::new(),
            security: SecurityContext::new(),
        }
    }

    /// Create a new context for request-response pattern
    pub fn new_request_response(
        operation: &str,
        topic: &str,
        response_topic: &str,
        timeout: Duration,
    ) -> Self {
        let mut context = Self::new(operation, topic);
        context.correlation_id = Some(Uuid::new_v4().to_string());
        context.reply_to = Some(response_topic.to_string());
        context.request_response = RequestResponseContext::RequestResponse {
            response_topic: response_topic.to_string(),
            timeout,
            response_required: true,
        };
        context
    }

    /// Set correlation ID for request-response patterns
    pub fn with_correlation_id(mut self, correlation_id: &str) -> Self {
        self.correlation_id = Some(correlation_id.to_string());
        self
    }

    /// Set reply-to address
    pub fn with_reply_to(mut self, reply_to: &str) -> Self {
        self.reply_to = Some(reply_to.to_string());
        self
    }

    /// Set user ID
    pub fn with_user_id(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    /// Set session ID
    pub fn with_session_id(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.to_string());
        self
    }

    /// Add a header
    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    /// Get a header value
    pub fn get_header(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }

    /// Add protocol-specific metadata
    pub fn add_protocol_property(&mut self, key: &str, value: &str) {
        self.protocol_metadata.properties.insert(key.to_string(), value.to_string());
    }

    /// Get protocol-specific metadata
    pub fn get_protocol_property(&self, key: &str) -> Option<&String> {
        self.protocol_metadata.properties.get(key)
    }

    /// Store middleware data
    pub fn set_middleware_data(&mut self, key: &str, value: serde_json::Value) {
        self.middleware_data.data.insert(key.to_string(), value);
    }

    /// Get middleware data
    pub fn get_middleware_data(&self, key: &str) -> Option<&serde_json::Value> {
        self.middleware_data.data.get(key)
    }

    /// Add a metric
    pub fn add_metric(&mut self, name: &str, value: f64) {
        self.middleware_data.metrics.insert(name.to_string(), value);
    }

    /// Get a metric
    pub fn get_metric(&self, name: &str) -> Option<f64> {
        self.middleware_data.metrics.get(name).copied()
    }

    /// Add a log entry
    pub fn add_log(&mut self, level: LogLevel, component: &str, message: &str) {
        self.middleware_data.logs.push(LogEntry {
            level,
            message: message.to_string(),
            timestamp: Utc::now(),
            component: component.to_string(),
            data: HashMap::new(),
        });
    }

    /// Add a log entry with data
    pub fn add_log_with_data(
        &mut self,
        level: LogLevel,
        component: &str,
        message: &str,
        data: HashMap<String, serde_json::Value>,
    ) {
        self.middleware_data.logs.push(LogEntry {
            level,
            message: message.to_string(),
            timestamp: Utc::now(),
            component: component.to_string(),
            data,
        });
    }

    /// Start a trace span
    pub fn start_span(&mut self, operation_name: &str) -> String {
        let span_id = Uuid::new_v4().to_string();
        let trace_id = self.get_trace_id();

        let span = TraceSpan {
            span_id: span_id.clone(),
            parent_span_id: self.get_current_span_id(),
            trace_id,
            operation_name: operation_name.to_string(),
            start_time: Utc::now(),
            end_time: None,
            tags: HashMap::new(),
            logs: Vec::new(),
        };

        self.middleware_data.traces.push(span);
        span_id
    }

    /// Finish a trace span
    pub fn finish_span(&mut self, span_id: &str) {
        if let Some(span) = self.middleware_data.traces.iter_mut().find(|s| s.span_id == span_id) {
            span.end_time = Some(Utc::now());
        }
    }

    /// Get the current trace ID
    pub fn get_trace_id(&self) -> String {
        self.middleware_data.traces
            .first()
            .map(|s| s.trace_id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string())
    }

    /// Get the current span ID
    pub fn get_current_span_id(&self) -> Option<String> {
        self.middleware_data.traces
            .last()
            .map(|s| s.span_id.clone())
    }

    /// Mark processing as complete and calculate duration
    pub fn complete_processing(&mut self) {
        let now = Utc::now();
        self.performance.duration = Some(
            now.signed_duration_since(self.performance.start_time)
                .to_std()
                .unwrap_or(Duration::from_secs(0))
        );
    }

    /// Add a custom performance metric
    pub fn add_performance_metric(&mut self, name: &str, value: f64) {
        self.performance.custom_metrics.insert(name.to_string(), value);
    }

    /// Set authentication information
    pub fn set_auth_info(&mut self, method: &str, user_id: &str, roles: Vec<String>) {
        self.security.auth_method = Some(method.to_string());
        self.user_id = Some(user_id.to_string());
        self.security.roles = roles;
    }

    /// Add a security token
    pub fn add_security_token(&mut self, token_type: &str, token: &str) {
        self.security.tokens.insert(token_type.to_string(), token.to_string());
    }

    /// Set client information
    pub fn set_client_info(&mut self, ip: Option<&str>, user_agent: Option<&str>) {
        self.security.client_ip = ip.map(|s| s.to_string());
        self.security.user_agent = user_agent.map(|s| s.to_string());
    }

    /// Check if this is a request-response pattern
    pub fn is_request_response(&self) -> bool {
        matches!(self.request_response, RequestResponseContext::RequestResponse { .. })
    }

    /// Get response timeout if applicable
    pub fn get_response_timeout(&self) -> Option<Duration> {
        match &self.request_response {
            RequestResponseContext::RequestResponse { timeout, .. } => Some(*timeout),
            RequestResponseContext::FireAndForget => None,
        }
    }

    /// Get response topic if applicable
    pub fn get_response_topic(&self) -> Option<&String> {
        match &self.request_response {
            RequestResponseContext::RequestResponse { response_topic, .. } => Some(response_topic),
            RequestResponseContext::FireAndForget => None,
        }
    }
}

impl MiddlewareData {
    /// Create new middleware data
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            metrics: HashMap::new(),
            logs: Vec::new(),
            traces: Vec::new(),
        }
    }
}

impl PerformanceContext {
    /// Create new performance context
    pub fn new() -> Self {
        Self {
            start_time: Utc::now(),
            duration: None,
            memory_usage_start: None,
            memory_usage_end: None,
            custom_metrics: HashMap::new(),
        }
    }
}

impl SecurityContext {
    /// Create new security context
    pub fn new() -> Self {
        Self {
            auth_method: None,
            roles: Vec::new(),
            tokens: HashMap::new(),
            client_ip: None,
            user_agent: None,
        }
    }
}

impl Default for MessageContext {
    fn default() -> Self {
        Self::new("unknown", "unknown")
    }
}

impl Default for MiddlewareData {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PerformanceContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let context = MessageContext::new("test_operation", "test/topic");
        assert_eq!(context.operation, "test_operation");
        assert_eq!(context.protocol_metadata.topic, "test/topic");
        assert!(!context.message_id.is_empty());
        assert!(context.request_id.is_some());
    }

    #[test]
    fn test_request_response_context() {
        let context = MessageContext::new_request_response(
            "test_operation",
            "request/topic",
            "response/topic",
            Duration::from_secs(30),
        );

        assert!(context.is_request_response());
        assert_eq!(context.get_response_topic(), Some(&"response/topic".to_string()));
        assert_eq!(context.get_response_timeout(), Some(Duration::from_secs(30)));
        assert!(context.correlation_id.is_some());
    }

    #[test]
    fn test_middleware_data() {
        let mut context = MessageContext::new("test", "topic");

        context.set_middleware_data("key1", serde_json::json!("value1"));
        context.add_metric("latency", 123.45);
        context.add_log(LogLevel::Info, "test_component", "Test message");

        assert_eq!(context.get_middleware_data("key1"), Some(&serde_json::json!("value1")));
        assert_eq!(context.get_metric("latency"), Some(123.45));
        assert_eq!(context.middleware_data.logs.len(), 1);
    }

    #[test]
    fn test_tracing() {
        let mut context = MessageContext::new("test", "topic");

        let span_id = context.start_span("test_operation");
        assert!(!span_id.is_empty());
        assert_eq!(context.middleware_data.traces.len(), 1);

        context.finish_span(&span_id);
        assert!(context.middleware_data.traces[0].end_time.is_some());
    }

    #[test]
    fn test_security_context() {
        let mut context = MessageContext::new("test", "topic");

        context.set_auth_info("bearer", "user123", vec!["admin".to_string()]);
        context.add_security_token("access_token", "token123");
        context.set_client_info(Some("192.168.1.1"), Some("test-agent/1.0"));

        assert_eq!(context.security.auth_method, Some("bearer".to_string()));
        assert_eq!(context.user_id, Some("user123".to_string()));
        assert_eq!(context.security.roles, vec!["admin".to_string()]);
        assert_eq!(context.security.client_ip, Some("192.168.1.1".to_string()));
    }
}
`}
        </File>
    );
}

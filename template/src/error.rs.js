import { File } from '@asyncapi/generator-react-sdk';

export default function errorFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();

    return (
        <File name="src/error.rs">
            {`//! Error types for the AsyncAPI server
//!
//! This module provides a layered error handling system with rich context
//! for debugging, observability, and proper error propagation.

use std::fmt;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// Result type alias for handler operations
pub type HandlerResult<T> = std::result::Result<T, HandlerError>;

/// Result type alias for middleware operations
pub type MiddlewareResult<T> = std::result::Result<T, MiddlewareError>;

/// Main error type for AsyncAPI server operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerError {
    /// The kind of error that occurred
    pub kind: ErrorKind,
    /// Human-readable error message
    pub message: String,
    /// Additional context about the error
    pub context: ErrorContext,
    /// Timestamp when the error occurred
    pub timestamp: DateTime<Utc>,
    /// Optional source error information
    pub source: Option<String>,
}

/// Categories of errors that can occur in handlers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    /// Input validation failed
    Validation,
    /// Business logic error
    BusinessLogic,
    /// Database operation failed
    Database,
    /// External service call failed
    ExternalService,
    /// Authentication failed
    Authentication,
    /// Authorization failed
    Authorization,
    /// Rate limit exceeded
    RateLimited,
    /// Operation timed out
    Timeout,
    /// Serialization/deserialization error
    Serialization,
    /// Configuration error
    Configuration,
    /// Network/connection error
    Network,
    /// Internal server error
    Internal,
}

/// Rich context information for errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// The operation that was being performed
    pub operation: String,
    /// Message correlation ID for tracing
    pub correlation_id: Option<String>,
    /// User ID if available
    pub user_id: Option<String>,
    /// Request ID for tracking
    pub request_id: Option<String>,
    /// Additional contextual data
    pub additional_data: HashMap<String, String>,
    /// The protocol being used
    pub protocol: String,
    /// The topic/channel where error occurred
    pub topic: Option<String>,
}

/// Middleware-specific error type
#[derive(Debug, Clone)]
pub struct MiddlewareError {
    /// The middleware that caused the error
    pub middleware_name: String,
    /// Error message
    pub message: String,
    /// Whether the request should continue processing
    pub should_continue: bool,
    /// Optional source error
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl HandlerError {
    /// Create a new validation error
    pub fn validation(field: &str, message: &str) -> Self {
        Self::new(
            ErrorKind::Validation,
            format!("Validation failed for field '{}': {}", field, message),
        )
    }

    /// Create a new business logic error
    pub fn business_logic(message: &str) -> Self {
        Self::new(ErrorKind::BusinessLogic, message.to_string())
    }

    /// Create a new database error
    pub fn database(message: &str, source: impl std::error::Error) -> Self {
        Self::new_with_source(
            ErrorKind::Database,
            format!("Database error: {}", message),
            source,
        )
    }

    /// Create a new external service error
    pub fn external_service(service: &str, message: &str) -> Self {
        Self::new(
            ErrorKind::ExternalService,
            format!("External service '{}' error: {}", service, message),
        )
    }

    /// Create a new authentication error
    pub fn authentication(message: &str) -> Self {
        Self::new(ErrorKind::Authentication, message.to_string())
    }

    /// Create a new authorization error
    pub fn authorization(message: &str) -> Self {
        Self::new(ErrorKind::Authorization, message.to_string())
    }

    /// Create a new rate limiting error
    pub fn rate_limited(retry_after: Option<u64>) -> Self {
        let message = match retry_after {
            Some(seconds) => format!("Rate limit exceeded. Retry after {} seconds", seconds),
            None => "Rate limit exceeded".to_string(),
        };
        Self::new(ErrorKind::RateLimited, message)
    }

    /// Create a new timeout error
    pub fn timeout(operation: &str, duration_ms: u64) -> Self {
        Self::new(
            ErrorKind::Timeout,
            format!("Operation '{}' timed out after {}ms", operation, duration_ms),
        )
    }

    /// Create a new serialization error
    pub fn serialization(message: &str, source: impl std::error::Error) -> Self {
        Self::new_with_source(
            ErrorKind::Serialization,
            format!("Serialization error: {}", message),
            source,
        )
    }

    /// Create a new configuration error
    pub fn configuration(message: &str) -> Self {
        Self::new(ErrorKind::Configuration, message.to_string())
    }

    /// Create a new network error
    pub fn network(message: &str, source: impl std::error::Error) -> Self {
        Self::new_with_source(
            ErrorKind::Network,
            format!("Network error: {}", message),
            source,
        )
    }

    /// Create a new internal error
    pub fn internal(message: &str) -> Self {
        Self::new(ErrorKind::Internal, message.to_string())
    }

    /// Create a new error from anyhow::Error
    pub fn from_anyhow(error: anyhow::Error, kind: ErrorKind) -> Self {
        Self::new_with_source(kind, error.to_string(), error)
    }

    /// Create a new error with basic information
    fn new(kind: ErrorKind, message: String) -> Self {
        Self {
            kind,
            message,
            context: ErrorContext::default(),
            timestamp: Utc::now(),
            source: None,
        }
    }

    /// Create a new error with source error information
    fn new_with_source(
        kind: ErrorKind,
        message: String,
        source: impl std::error::Error,
    ) -> Self {
        Self {
            kind,
            message,
            context: ErrorContext::default(),
            timestamp: Utc::now(),
            source: Some(source.to_string()),
        }
    }

    /// Add operation context to the error
    pub fn with_operation(mut self, operation: &str) -> Self {
        self.context.operation = operation.to_string();
        self
    }

    /// Add correlation ID to the error
    pub fn with_correlation_id(mut self, correlation_id: &str) -> Self {
        self.context.correlation_id = Some(correlation_id.to_string());
        self
    }

    /// Add user ID to the error
    pub fn with_user_id(mut self, user_id: &str) -> Self {
        self.context.user_id = Some(user_id.to_string());
        self
    }

    /// Add request ID to the error
    pub fn with_request_id(mut self, request_id: &str) -> Self {
        self.context.request_id = Some(request_id.to_string());
        self
    }

    /// Add topic context to the error
    pub fn with_topic(mut self, topic: &str) -> Self {
        self.context.topic = Some(topic.to_string());
        self
    }

    /// Add additional context data
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.additional_data.insert(key.to_string(), value.to_string());
        self
    }

    /// Check if this error should be retried
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::Network | ErrorKind::Timeout | ErrorKind::ExternalService | ErrorKind::Database
        )
    }

    /// Get the HTTP status code for this error
    pub fn http_status_code(&self) -> u16 {
        match self.kind {
            ErrorKind::Validation => 400,
            ErrorKind::Authentication => 401,
            ErrorKind::Authorization => 403,
            ErrorKind::RateLimited => 429,
            ErrorKind::Timeout => 408,
            ErrorKind::BusinessLogic => 422,
            ErrorKind::ExternalService | ErrorKind::Database | ErrorKind::Network => 502,
            ErrorKind::Configuration | ErrorKind::Internal => 500,
            ErrorKind::Serialization => 400,
        }
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self {
            operation: "unknown".to_string(),
            correlation_id: None,
            user_id: None,
            request_id: None,
            additional_data: HashMap::new(),
            protocol: "${protocol}".to_string(),
            topic: None,
        }
    }
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind, self.message)?;

        if let Some(correlation_id) = &self.context.correlation_id {
            write!(f, " (correlation_id: {})", correlation_id)?;
        }

        if let Some(topic) = &self.context.topic {
            write!(f, " (topic: {})", topic)?;
        }

        Ok(())
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Validation => write!(f, "VALIDATION"),
            ErrorKind::BusinessLogic => write!(f, "BUSINESS_LOGIC"),
            ErrorKind::Database => write!(f, "DATABASE"),
            ErrorKind::ExternalService => write!(f, "EXTERNAL_SERVICE"),
            ErrorKind::Authentication => write!(f, "AUTHENTICATION"),
            ErrorKind::Authorization => write!(f, "AUTHORIZATION"),
            ErrorKind::RateLimited => write!(f, "RATE_LIMITED"),
            ErrorKind::Timeout => write!(f, "TIMEOUT"),
            ErrorKind::Serialization => write!(f, "SERIALIZATION"),
            ErrorKind::Configuration => write!(f, "CONFIGURATION"),
            ErrorKind::Network => write!(f, "NETWORK"),
            ErrorKind::Internal => write!(f, "INTERNAL"),
        }
    }
}

impl std::error::Error for HandlerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None // Source is stored as string for serialization
    }
}

impl fmt::Display for MiddlewareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Middleware '{}' error: {}", self.middleware_name, self.message)
    }
}

impl std::error::Error for MiddlewareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref())
    }
}

impl MiddlewareError {
    /// Create a new middleware error
    pub fn new(middleware_name: &str, message: &str, should_continue: bool) -> Self {
        Self {
            middleware_name: middleware_name.to_string(),
            message: message.to_string(),
            should_continue,
            source: None,
        }
    }

    /// Create a new middleware error with source
    pub fn with_source(
        middleware_name: &str,
        message: &str,
        should_continue: bool,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self {
            middleware_name: middleware_name.to_string(),
            message: message.to_string(),
            should_continue,
            source: Some(source),
        }
    }
}

// Conversion implementations for common error types
impl From<serde_json::Error> for HandlerError {
    fn from(err: serde_json::Error) -> Self {
        HandlerError::serialization("JSON serialization failed", err)
    }
}

impl From<std::io::Error> for HandlerError {
    fn from(err: std::io::Error) -> Self {
        HandlerError::network("I/O operation failed", err)
    }
}

${protocol === 'mqtt' || protocol === 'mqtts' ? `impl From<rumqttc::ClientError> for HandlerError {
    fn from(err: rumqttc::ClientError) -> Self {
        HandlerError::network("MQTT client error", err)
    }
}` : ''}

${protocol === 'kafka' || protocol === 'kafka-secure' ? `impl From<rdkafka::error::KafkaError> for HandlerError {
    fn from(err: rdkafka::error::KafkaError) -> Self {
        HandlerError::network("Kafka error", err)
    }
}` : ''}

${protocol === 'amqp' || protocol === 'amqps' ? `impl From<lapin::Error> for HandlerError {
    fn from(err: lapin::Error) -> Self {
        HandlerError::network("AMQP error", err)
    }
}` : ''}

${protocol === 'ws' || protocol === 'wss' ? `impl From<tokio_tungstenite::tungstenite::Error> for HandlerError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        HandlerError::network("WebSocket error", err)
    }
}` : ''}

${protocol === 'nats' ? `impl From<async_nats::Error> for HandlerError {
    fn from(err: async_nats::Error) -> Self {
        HandlerError::network("NATS error", err)
    }
}` : ''}

${protocol === 'redis' ? `impl From<redis::RedisError> for HandlerError {
    fn from(err: redis::RedisError) -> Self {
        HandlerError::network("Redis error", err)
    }
}` : ''}

${protocol === 'http' || protocol === 'https' ? `impl From<reqwest::Error> for HandlerError {
    fn from(err: reqwest::Error) -> Self {
        HandlerError::network("HTTP client error", err)
    }
}` : ''}

impl From<anyhow::Error> for HandlerError {
    fn from(err: anyhow::Error) -> Self {
        HandlerError::internal(&err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = HandlerError::validation("email", "Invalid format");
        assert_eq!(error.kind, ErrorKind::Validation);
        assert!(error.message.contains("email"));
        assert!(error.message.contains("Invalid format"));
    }

    #[test]
    fn test_error_context() {
        let error = HandlerError::business_logic("User not found")
            .with_operation("user_lookup")
            .with_correlation_id("123-456")
            .with_user_id("user123");

        assert_eq!(error.context.operation, "user_lookup");
        assert_eq!(error.context.correlation_id, Some("123-456".to_string()));
        assert_eq!(error.context.user_id, Some("user123".to_string()));
    }

    #[test]
    fn test_error_retryable() {
        assert!(HandlerError::network("Connection failed", std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "")).is_retryable());
        assert!(!HandlerError::validation("email", "Invalid").is_retryable());
    }

    #[test]
    fn test_http_status_codes() {
        assert_eq!(HandlerError::validation("field", "error").http_status_code(), 400);
        assert_eq!(HandlerError::authentication("invalid token").http_status_code(), 401);
        assert_eq!(HandlerError::authorization("no permission").http_status_code(), 403);
        assert_eq!(HandlerError::rate_limited(None).http_status_code(), 429);
    }
}
`}
        </File>
    );
}

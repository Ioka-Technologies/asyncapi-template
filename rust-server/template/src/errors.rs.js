/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ErrorsRs({ asyncapi }) {
    // Detect protocols from servers for protocol-specific errors
    const servers = asyncapi.servers();
    const protocols = new Set();

    if (servers) {
        Object.entries(servers).forEach(([_name, server]) => {
            const protocol = server.protocol && server.protocol();
            if (protocol) {
                protocols.add(protocol.toLowerCase());
            }
        });
    }

    return (
        <File name="errors.rs">
            {`//! Comprehensive error handling system for AsyncAPI operations
//!
//! This module provides a hierarchical error system with:
//! - Custom error types for different failure scenarios
//! - Error context and correlation for debugging
//! - Protocol-specific error handling
//! - Error recovery and retry mechanisms
//! - Structured error data for monitoring

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

/// Correlation ID for tracing errors across operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(pub Uuid);

impl CorrelationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

/// Error severity levels for categorization and alerting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity {
    /// Low severity - informational, no action required
    Low,
    /// Medium severity - warning, monitoring required
    Medium,
    /// High severity - error, immediate attention needed
    High,
    /// Critical severity - system failure, urgent action required
    Critical,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Low => write!(f, "LOW"),
            ErrorSeverity::Medium => write!(f, "MEDIUM"),
            ErrorSeverity::High => write!(f, "HIGH"),
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Error category for classification and handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCategory {
    /// Configuration-related errors
    Configuration,
    /// Network and protocol errors
    Network,
    /// Message validation errors
    Validation,
    /// Business logic errors
    BusinessLogic,
    /// System resource errors
    Resource,
    /// Security-related errors
    Security,
    /// Serialization/deserialization errors
    Serialization,
    /// Routing errors
    Routing,
    /// Authorization errors
    Authorization,
    /// Unknown or unclassified errors
    Unknown,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::Configuration => write!(f, "CONFIGURATION"),
            ErrorCategory::Network => write!(f, "NETWORK"),
            ErrorCategory::Validation => write!(f, "VALIDATION"),
            ErrorCategory::BusinessLogic => write!(f, "BUSINESS_LOGIC"),
            ErrorCategory::Resource => write!(f, "RESOURCE"),
            ErrorCategory::Security => write!(f, "SECURITY"),
            ErrorCategory::Serialization => write!(f, "SERIALIZATION"),
            ErrorCategory::Routing => write!(f, "ROUTING"),
            ErrorCategory::Authorization => write!(f, "AUTHORIZATION"),
            ErrorCategory::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Error metadata for enhanced context and monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMetadata {
    pub correlation_id: CorrelationId,
    pub severity: ErrorSeverity,
    pub category: ErrorCategory,
    pub timestamp: DateTime<Utc>,
    pub retryable: bool,
    pub source_location: Option<String>,
    pub additional_context: std::collections::HashMap<String, String>,
}

impl ErrorMetadata {
    pub fn new(severity: ErrorSeverity, category: ErrorCategory, retryable: bool) -> Self {
        Self {
            correlation_id: CorrelationId::new(),
            severity,
            category,
            timestamp: Utc::now(),
            retryable,
            source_location: None,
            additional_context: std::collections::HashMap::new(),
        }
    }

    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.additional_context
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_location(mut self, location: &str) -> Self {
        self.source_location = Some(location.to_string());
        self
    }
}

/// Root error type for all AsyncAPI operations
#[derive(Error, Debug)]
pub enum AsyncApiError {
    #[error("Configuration error: {message}")]
    Configuration {
        message: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Protocol error: {message}")]
    Protocol {
        message: String,
        protocol: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Validation error: {message}")]
    Validation {
        message: String,
        field: Option<String>,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Handler error: {message}")]
    Handler {
        message: String,
        handler_name: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Middleware error: {message}")]
    Middleware {
        message: String,
        middleware_name: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Recovery error: {message}")]
    Recovery {
        message: String,
        attempts: u32,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Resource error: {message}")]
    Resource {
        message: String,
        resource_type: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Security error: {message}")]
    Security {
        message: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Authentication error: {message}")]
    Authentication {
        message: String,
        auth_method: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Authorization error: {message}")]
    Authorization {
        message: String,
        required_permissions: Vec<String>,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        message: String,
        retry_after: Option<std::time::Duration>,
    },

    #[error("Context error: {message}")]
    Context {
        message: String,
        context_key: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

}

impl AsyncApiError {
    /// Create a new error with the specified message, category, and optional source
    pub fn new(
        message: String,
        category: ErrorCategory,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        let (severity, retryable) = match category {
            ErrorCategory::Configuration => (ErrorSeverity::High, false),
            ErrorCategory::Network => (ErrorSeverity::High, true),
            ErrorCategory::Validation => (ErrorSeverity::Medium, false),
            ErrorCategory::BusinessLogic => (ErrorSeverity::High, true),
            ErrorCategory::Resource => (ErrorSeverity::High, true),
            ErrorCategory::Security => (ErrorSeverity::Critical, false),
            ErrorCategory::Serialization => (ErrorSeverity::Medium, false),
            ErrorCategory::Routing => (ErrorSeverity::Medium, true),
            ErrorCategory::Authorization => (ErrorSeverity::High, false),
            ErrorCategory::Unknown => (ErrorSeverity::Medium, false),
        };

        let metadata = ErrorMetadata::new(severity, category, retryable).with_location(&format!(
            "{}:{}",
            file!(),
            line!()
        ));

        match category {
            ErrorCategory::Configuration => AsyncApiError::Configuration {
                message,
                metadata,
                source,
            },
            ErrorCategory::Network => AsyncApiError::Protocol {
                message,
                protocol: "unknown".to_string(),
                metadata,
                source,
            },
            ErrorCategory::Validation => AsyncApiError::Validation {
                message,
                field: None,
                metadata,
                source,
            },
            ErrorCategory::BusinessLogic => AsyncApiError::Handler {
                message,
                handler_name: "unknown".to_string(),
                metadata,
                source,
            },
            ErrorCategory::Resource => AsyncApiError::Resource {
                message,
                resource_type: "unknown".to_string(),
                metadata,
                source,
            },
            ErrorCategory::Security => AsyncApiError::Security {
                message,
                metadata,
                source,
            },
            ErrorCategory::Serialization => AsyncApiError::Validation {
                message,
                field: None,
                metadata,
                source,
            },
            ErrorCategory::Routing => AsyncApiError::Handler {
                message,
                handler_name: "routing".to_string(),
                metadata,
                source,
            },
            ErrorCategory::Authorization => AsyncApiError::Security {
                message,
                metadata,
                source,
            },
            ErrorCategory::Unknown => AsyncApiError::Configuration {
                message,
                metadata,
                source,
            },
        }
    }

    /// Get error metadata for monitoring and logging
    pub fn metadata(&self) -> &ErrorMetadata {
        match self {
            AsyncApiError::Configuration { metadata, .. } => metadata,
            AsyncApiError::Protocol { metadata, .. } => metadata,
            AsyncApiError::Validation { metadata, .. } => metadata,
            AsyncApiError::Handler { metadata, .. } => metadata,
            AsyncApiError::Middleware { metadata, .. } => metadata,
            AsyncApiError::Recovery { metadata, .. } => metadata,
            AsyncApiError::Resource { metadata, .. } => metadata,
            AsyncApiError::Security { metadata, .. } => metadata,
            AsyncApiError::Authentication { metadata, .. } => metadata,
            AsyncApiError::Authorization { metadata, .. } => metadata,
            AsyncApiError::Context { metadata, .. } => metadata,
            // RateLimit doesn't have metadata
            AsyncApiError::RateLimit { .. } => panic!("RateLimit error variant doesn't have metadata"),
        }
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        self.metadata().retryable
    }

    /// Get error severity
    pub fn severity(&self) -> ErrorSeverity {
        self.metadata().severity
    }

    /// Get error category
    pub fn category(&self) -> ErrorCategory {
        self.metadata().category
    }

    /// Get correlation ID for tracing
    pub fn correlation_id(&self) -> &CorrelationId {
        &self.metadata().correlation_id
    }

    /// Add context to error metadata
    pub fn add_context(&mut self, key: &str, value: &str) {
        match self {
            AsyncApiError::Configuration { metadata, .. } => {
                metadata
                    .additional_context
                    .insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Protocol { metadata, .. } => {
                metadata
                    .additional_context
                    .insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Validation { metadata, .. } => {
                metadata
                    .additional_context
                    .insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Handler { metadata, .. } => {
                metadata
                    .additional_context
                    .insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Middleware { metadata, .. } => {
                metadata
                    .additional_context
                    .insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Recovery { metadata, .. } => {
                metadata
                    .additional_context
                    .insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Resource { metadata, .. } => {
                metadata
                    .additional_context
                    .insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Security { metadata, .. } => {
                metadata
                    .additional_context
                    .insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Context { metadata, .. } => {
                metadata
                    .additional_context
                    .insert(key.to_string(), value.to_string());
            }
            // Authentication, Authorization, and RateLimit don't have metadata
            _ => {}
        }
    }

    /// Get HTTP status code for this error type
    pub fn http_status_code(&self) -> u16 {
        match self {
            AsyncApiError::Authentication { .. } => 401,
            AsyncApiError::Authorization { .. } => 403,
            AsyncApiError::Validation { .. } => 400,
            AsyncApiError::Handler { .. } => 500,
            AsyncApiError::Protocol { .. } => 502,
            AsyncApiError::Configuration { .. } => 500,
            AsyncApiError::Middleware { .. } => 500,
            AsyncApiError::Recovery { .. } => 503,
            AsyncApiError::Resource { .. } => 503,
            AsyncApiError::Security { .. } => 403,
            AsyncApiError::RateLimit { .. } => 429,
            AsyncApiError::Context { .. } => 500,
        }
    }

    /// Check if this is an authentication or authorization error
    pub fn is_auth_error(&self) -> bool {
        matches!(self, AsyncApiError::Authentication { .. } | AsyncApiError::Authorization { .. })
    }
}

${Array.from(protocols).map(protocol => {
                const protocolTitle = protocol.charAt(0).toUpperCase() + protocol.slice(1);

                return `/// ${protocolTitle} protocol-specific errors
#[derive(Error, Debug)]
pub enum ${protocolTitle}Error {
    #[error("${protocolTitle} connection error: {message}")]
    Connection {
        message: String,
        endpoint: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("${protocolTitle} authentication error: {message}")]
    Authentication {
        message: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("${protocolTitle} message error: {message}")]
    Message {
        message: String,
        message_id: Option<String>,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
${protocol === 'mqtt' ? `
    #[error("MQTT subscription error: {message}")]
    Subscription {
        message: String,
        topic: String,
        qos: u8,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("MQTT publish error: {message}")]
    Publish {
        message: String,
        topic: String,
        qos: u8,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}${protocol === 'kafka' ? `
    #[error("Kafka producer error: {message}")]
    Producer {
        message: String,
        topic: String,
        partition: Option<i32>,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Kafka consumer error: {message}")]
    Consumer {
        message: String,
        topic: String,
        group_id: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Kafka offset error: {message}")]
    Offset {
        message: String,
        topic: String,
        partition: i32,
        offset: i64,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}${protocol === 'amqp' ? `
    #[error("AMQP channel error: {message}")]
    Channel {
        message: String,
        channel_id: u16,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("AMQP exchange error: {message}")]
    Exchange {
        message: String,
        exchange_name: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("AMQP queue error: {message}")]
    Queue {
        message: String,
        queue_name: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}${(protocol === 'ws' || protocol === 'wss') ? `
    #[error("WebSocket frame error: {message}")]
    Frame {
        message: String,
        frame_type: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("WebSocket protocol error: {message}")]
    Protocol {
        message: String,
        expected: String,
        received: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}${(protocol === 'http' || protocol === 'https') ? `
    #[error("HTTP status error: {status_code} - {message}")]
    Status {
        message: String,
        status_code: u16,
        method: String,
        url: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("HTTP timeout error: {message}")]
    Timeout {
        message: String,
        timeout_duration: std::time::Duration,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}
}

impl ${protocolTitle}Error {
    /// Get error metadata
    pub fn metadata(&self) -> &ErrorMetadata {
        match self {
            ${protocolTitle}Error::Connection { metadata, .. } => metadata,
            ${protocolTitle}Error::Authentication { metadata, .. } => metadata,
            ${protocolTitle}Error::Message { metadata, .. } => metadata,${protocol === 'mqtt' ? `
            ${protocolTitle}Error::Subscription { metadata, .. } => metadata,
            ${protocolTitle}Error::Publish { metadata, .. } => metadata,` : ''}${protocol === 'kafka' ? `
            ${protocolTitle}Error::Producer { metadata, .. } => metadata,
            ${protocolTitle}Error::Consumer { metadata, .. } => metadata,
            ${protocolTitle}Error::Offset { metadata, .. } => metadata,` : ''}${protocol === 'amqp' ? `
            ${protocolTitle}Error::Channel { metadata, .. } => metadata,
            ${protocolTitle}Error::Exchange { metadata, .. } => metadata,
            ${protocolTitle}Error::Queue { metadata, .. } => metadata,` : ''}${(protocol === 'ws' || protocol === 'wss') ? `
            ${protocolTitle}Error::Frame { metadata, .. } => metadata,
            ${protocolTitle}Error::Protocol { metadata, .. } => metadata,` : ''}${(protocol === 'http' || protocol === 'https') ? `
            ${protocolTitle}Error::Status { metadata, .. } => metadata,
            ${protocolTitle}Error::Timeout { metadata, .. } => metadata,` : ''}
        }
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        self.metadata().retryable
    }
}

impl From<${protocolTitle}Error> for AsyncApiError {
    fn from(error: ${protocolTitle}Error) -> Self {
        AsyncApiError::Protocol {
            message: error.to_string(),
            protocol: "${protocol}".to_string(),
            metadata: error.metadata().clone(),
            source: Some(Box::new(error)),
        }
    }
}`;
            }).join('\n')}

/// Result type alias for AsyncAPI operations
pub type AsyncApiResult<T> = Result<T, Box<AsyncApiError>>;

/// Helper macros for creating errors with context
#[macro_export]
macro_rules! config_error {
    ($msg:expr) => {
        Box::new(AsyncApiError::Configuration {
            message: $msg.to_string(),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Configuration, false)
                .with_location(&format!("{}:{}", file!(), line!())),
            source: None,
        })
    };
    ($msg:expr, $source:expr) => {
        Box::new(AsyncApiError::Configuration {
            message: $msg.to_string(),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Configuration, false)
                .with_location(&format!("{}:{}", file!(), line!())),
            source: Some(Box::new($source)),
        })
    };
}

#[macro_export]
macro_rules! validation_error {
    ($msg:expr) => {
        Box::new(AsyncApiError::Validation {
            message: $msg.to_string(),
            field: None,
            metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false)
                .with_location(&format!("{}:{}", file!(), line!())),
            source: None,
        })
    };
    ($msg:expr, $field:expr) => {
        Box::new(AsyncApiError::Validation {
            message: $msg.to_string(),
            field: Some($field.to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false)
                .with_location(&format!("{}:{}", file!(), line!())),
            source: None,
        })
    };
}

#[macro_export]
macro_rules! handler_error {
    ($msg:expr, $handler:expr) => {
        Box::new(AsyncApiError::Handler {
            message: $msg.to_string(),
            handler_name: $handler.to_string(),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::BusinessLogic, true)
                .with_location(&format!("{}:{}", file!(), line!())),
            source: None,
        })
    };
    ($msg:expr, $handler:expr, $source:expr) => {
        Box::new(AsyncApiError::Handler {
            message: $msg.to_string(),
            handler_name: $handler.to_string(),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::BusinessLogic, true)
                .with_location(&format!("{}:{}", file!(), line!())),
            source: Some(Box::new($source)),
        })
    };
}

/// Error conversion utilities
impl From<serde_json::Error> for AsyncApiError {
    fn from(error: serde_json::Error) -> Self {
        AsyncApiError::Validation {
            message: format!("JSON serialization/deserialization error: {error}"),
            field: None,
            metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
            source: Some(Box::new(error)),
        }
    }
}

impl From<anyhow::Error> for AsyncApiError {
    fn from(error: anyhow::Error) -> Self {
        AsyncApiError::Configuration {
            message: format!("Configuration error: {error}"),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Configuration, false),
            source: None,
        }
    }
}

impl From<std::env::VarError> for AsyncApiError {
    fn from(error: std::env::VarError) -> Self {
        AsyncApiError::Configuration {
            message: format!("Environment variable error: {error}"),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Configuration, false),
            source: Some(Box::new(error)),
        }
    }
}

impl From<std::num::ParseIntError> for AsyncApiError {
    fn from(error: std::num::ParseIntError) -> Self {
        AsyncApiError::Configuration {
            message: format!("Integer parsing error: {error}"),
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::Configuration,
                false,
            ),
            source: Some(Box::new(error)),
        }
    }
}

impl From<tokio::time::error::Elapsed> for AsyncApiError {
    fn from(error: tokio::time::error::Elapsed) -> Self {
        AsyncApiError::Resource {
            message: format!("Operation timeout: {error}"),
            resource_type: "timeout".to_string(),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Resource, true),
            source: Some(Box::new(error)),
        }
    }
}
`}
        </File>
    );
}

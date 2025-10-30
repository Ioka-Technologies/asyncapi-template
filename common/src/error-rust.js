/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

/**
 * Generate shared AsyncAPI error type for wire transmission
 * This type is serializable and can be shared between server and client
 */
export function generateAsyncApiError() {
    return `//! Shared AsyncAPI error type for wire transmission
//!
//! This module provides a serializable error type that can be transmitted
//! between server and client, preserving rich error information.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Correlation ID for tracing errors across operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(pub Uuid);

impl CorrelationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_location: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub additional_context: HashMap<String, String>,
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
            additional_context: HashMap::new(),
        }
    }
}

/// Serializable AsyncAPI error for wire transmission
///
/// This error type can be sent between server and client while preserving
/// all the rich error information needed for proper error handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "error_type", content = "details")]
pub enum AsyncApiError {
    #[serde(rename = "configuration")]
    Configuration {
        message: String,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "protocol")]
    Protocol {
        message: String,
        protocol: String,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "validation")]
    Validation {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        field: Option<String>,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "handler")]
    Handler {
        message: String,
        handler_name: String,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "middleware")]
    Middleware {
        message: String,
        middleware_name: String,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "recovery")]
    Recovery {
        message: String,
        attempts: u32,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "resource")]
    Resource {
        message: String,
        resource_type: String,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "security")]
    Security {
        message: String,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "authentication")]
    Authentication {
        message: String,
        auth_method: String,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "authorization")]
    Authorization {
        message: String,
        required_permissions: Vec<String>,
        metadata: ErrorMetadata,
    },

    #[serde(rename = "rate_limit")]
    RateLimit {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        retry_after_secs: Option<u64>,
    },

    #[serde(rename = "context")]
    Context {
        message: String,
        context_key: String,
        metadata: ErrorMetadata,
    },
}

impl AsyncApiError {
    /// Get error message
    pub fn message(&self) -> &str {
        match self {
            AsyncApiError::Configuration { message, .. } => message,
            AsyncApiError::Protocol { message, .. } => message,
            AsyncApiError::Validation { message, .. } => message,
            AsyncApiError::Handler { message, .. } => message,
            AsyncApiError::Middleware { message, .. } => message,
            AsyncApiError::Recovery { message, .. } => message,
            AsyncApiError::Resource { message, .. } => message,
            AsyncApiError::Security { message, .. } => message,
            AsyncApiError::Authentication { message, .. } => message,
            AsyncApiError::Authorization { message, .. } => message,
            AsyncApiError::RateLimit { message, .. } => message,
            AsyncApiError::Context { message, .. } => message,
        }
    }

    /// Get error metadata (if available)
    pub fn metadata(&self) -> Option<&ErrorMetadata> {
        match self {
            AsyncApiError::Configuration { metadata, .. } => Some(metadata),
            AsyncApiError::Protocol { metadata, .. } => Some(metadata),
            AsyncApiError::Validation { metadata, .. } => Some(metadata),
            AsyncApiError::Handler { metadata, .. } => Some(metadata),
            AsyncApiError::Middleware { metadata, .. } => Some(metadata),
            AsyncApiError::Recovery { metadata, .. } => Some(metadata),
            AsyncApiError::Resource { metadata, .. } => Some(metadata),
            AsyncApiError::Security { metadata, .. } => Some(metadata),
            AsyncApiError::Authentication { metadata, .. } => Some(metadata),
            AsyncApiError::Authorization { metadata, .. } => Some(metadata),
            AsyncApiError::Context { metadata, .. } => Some(metadata),
            AsyncApiError::RateLimit { .. } => None,
        }
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        self.metadata().map_or(false, |m| m.retryable)
    }

    /// Get error severity
    pub fn severity(&self) -> Option<ErrorSeverity> {
        self.metadata().map(|m| m.severity)
    }

    /// Get error category
    pub fn category(&self) -> Option<ErrorCategory> {
        self.metadata().map(|m| m.category)
    }

    /// Get correlation ID for tracing
    pub fn correlation_id(&self) -> Option<&CorrelationId> {
        self.metadata().map(|m| &m.correlation_id)
    }
}

impl std::fmt::Display for AsyncApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for AsyncApiError {}
`;
}

export default function ErrorRs() {
    return (
        <File name="error.rs">
            {generateAsyncApiError()}
        </File>
    );
}

//! Error types for the NATS client

use crate::auth::AuthError;
use thiserror::Error;

// Import the shared AsyncApiError type from the envelope/models module
pub use crate::envelope::{AsyncApiError, ErrorSeverity, ErrorCategory, ErrorMetadata, CorrelationId as ErrorCorrelationId};

/// Errors that can occur when using the NATS client
#[derive(Debug, Error)]
pub enum ClientError {
    /// NATS operation failed
    #[error("NATS operation failed: {0}")]
    Nats(Box<dyn std::error::Error + Send + Sync>),

    /// Serialization or deserialization failed
    #[error("Serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid message envelope format
    #[error("Invalid message envelope: {0}")]
    InvalidEnvelope(String),

    /// Operation timeout
    #[error("Operation timed out")]
    Timeout,

    /// No response received for request
    #[error("No response received")]
    NoResponse,

    /// Authentication error
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),

    /// Unauthorized access
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Server-side AsyncAPI error
    ///
    /// This error contains rich information from the server including:
    /// - Error severity and category
    /// - Correlation ID for tracing
    /// - Detailed error metadata
    /// - Whether the error is retryable
    #[error("Server error: {0}")]
    AsyncApi(Box<AsyncApiError>),
}

impl ClientError {
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            ClientError::Nats(_) => true,
            ClientError::Timeout => true,
            ClientError::NoResponse => true,
            ClientError::AsyncApi(err) => err.is_retryable(),
            _ => false,
        }
    }

    /// Get error severity if available
    pub fn severity(&self) -> Option<ErrorSeverity> {
        match self {
            ClientError::AsyncApi(err) => err.severity(),
            _ => None,
        }
    }

    /// Get error category if available
    pub fn category(&self) -> Option<ErrorCategory> {
        match self {
            ClientError::AsyncApi(err) => err.category(),
            _ => None,
        }
    }

    /// Get correlation ID for tracing if available
    pub fn correlation_id(&self) -> Option<&ErrorCorrelationId> {
        match self {
            ClientError::AsyncApi(err) => err.correlation_id(),
            _ => None,
        }
    }

    /// Check if this is a server-side error
    pub fn is_server_error(&self) -> bool {
        matches!(self, ClientError::AsyncApi(_))
    }
}

/// Result type alias for client operations
pub type ClientResult<T> = Result<T, ClientError>;

//! Message envelope for consistent NATS message format

use crate::auth::{AuthCredentials, generate_auth_headers};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorMetadata {
    pub correlation_id: CorrelationId,
    pub severity: ErrorSeverity,
    pub category: ErrorCategory,
    pub timestamp: DateTime<Utc>,
    pub retryable: bool,
    pub kind: u32,
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
            kind: 0,
            source_location: None,
            additional_context: HashMap::new(),
        }
    }

    pub fn with_kind(mut self, kind: u32) -> Self {
        self.kind = kind;
        self
    }
}

/// Serializable AsyncAPI error for wire transmission
///
/// This error type can be sent between server and client while preserving
/// all the rich error information needed for proper error handling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Unified message envelope for consistent AsyncAPI message format
///
/// This envelope provides a standardized structure for all messages sent through the system,
/// enabling better correlation, error handling, authentication, and observability.
///
/// ## Features
///
/// - **Request/Response Patterns**: Correlation IDs for matching requests with responses
/// - **Error Handling**: Built-in error information for failed operations
/// - **Authentication**: Integrated auth header support
/// - **Channel Routing**: Optional channel context for message routing
/// - **Serialization**: Efficient byte conversion for transport layers
/// - **Type Safety**: Strongly-typed payload extraction
///
/// ## Usage
///
/// ```no-run
/// use crate::models::*;
/// use uuid::Uuid;
/// use std::collections::HashMap;
///
/// // Create a basic message envelope
/// let envelope = MessageEnvelope::new("sendChatMessage", chat_message)?;
///
/// // Create with correlation ID for request/response
/// let request = MessageEnvelope::new_with_correlation_id(
///     "getUserProfile",
///     user_request,
///     Uuid::new_v4().to_string()
/// )?;
///
/// // Create response with same correlation ID
/// let response = request.create_response("getUserProfile_response", user_profile)?;
///
/// // Create error response
/// let error = MessageEnvelope::error_response(
///     "getUserProfile_response",
///     "USER_NOT_FOUND",
///     "User does not exist",
///     request.correlation_id().map(|s| s.to_string())
/// );
///
/// // Add authentication headers
/// let mut headers = HashMap::new();
/// headers.insert("Authorization".to_string(), "Bearer token123".to_string());
/// let auth_envelope = envelope.with_headers(headers);
///
/// // Serialize for transport
/// let bytes = envelope.to_bytes()?;
/// let deserialized = MessageEnvelope::from_bytes(&bytes)?;
/// ```

/// Standard message envelope for all AsyncAPI messages
///
/// This envelope provides a consistent structure for all messages sent through the system,
/// enabling better correlation, error handling, and observability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Unique message identifier
    pub id: String,
    /// AsyncAPI operation ID
    pub operation: String,
    /// Message payload (any serializable type)
    pub payload: serde_json::Value,
    /// ISO 8601 timestamp when message was created
    pub timestamp: String,
    /// Correlation ID for request/response patterns
    pub correlation_id: Option<String>,
    /// Optional channel context for routing
    pub channel: Option<String>,
    /// Transport-level headers (auth, routing, etc.)
    pub headers: Option<HashMap<String, String>>,
    /// Rich error information if operation failed
    /// Contains detailed error metadata including severity, category, and correlation
    pub error: Option<AsyncApiError>,
}

impl MessageEnvelope {
    /// Create a new message envelope with the given operation and payload
    pub fn new<T: Serialize>(operation: &str, payload: T) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            operation: operation.to_string(),
            payload: serde_json::to_value(payload)?,
            timestamp: chrono::Utc::now().to_rfc3339(),
            correlation_id: None,
            channel: None,
            headers: None,
            error: None,
        })
    }

    /// Create a new envelope with automatic correlation ID generation
    pub fn new_with_id<T: Serialize>(
        operation: &str,
        payload: T,
    ) -> Result<Self, serde_json::Error> {
        Self::new(operation, payload)
            .map(|envelope| envelope.with_correlation_id(Uuid::new_v4().to_string()))
    }

    /// Create a new message envelope with a specific correlation ID
    pub fn new_with_correlation_id<T: Serialize>(
        operation: &str,
        payload: T,
        correlation_id: String,
    ) -> Result<Self, serde_json::Error> {
        let mut envelope = Self::new(operation, payload)?;
        envelope.correlation_id = Some(correlation_id);
        Ok(envelope)
    }

    /// Create an error response envelope with rich AsyncApiError
    pub fn error_response(
        operation: &str,
        error: AsyncApiError,
        correlation_id: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            operation: operation.to_string(),
            payload: serde_json::Value::Null,
            timestamp: chrono::Utc::now().to_rfc3339(),
            correlation_id,
            channel: None,
            headers: None,
            error: Some(error),
        }
    }

    /// Create a simple error response envelope (for backward compatibility)
    pub fn simple_error_response(
        operation: &str,
        error_message: &str,
        correlation_id: Option<String>,
    ) -> Self {
        let error = AsyncApiError::Handler {
            message: error_message.to_string(),
            handler_name: operation.to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::BusinessLogic,
                false,
            ),
        };
        Self::error_response(operation, error, correlation_id)
    }

    /// Set the correlation ID for this envelope
    pub fn with_correlation_id(mut self, id: String) -> Self {
        self.correlation_id = Some(id);
        self
    }

    /// Set the channel for this envelope
    pub fn with_channel(mut self, channel: String) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Set headers for this envelope
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Add a single header to this envelope
    pub fn with_header(mut self, key: String, value: String) -> Self {
        if self.headers.is_none() {
            self.headers = Some(HashMap::new());
        }
        if let Some(ref mut headers) = self.headers {
            headers.insert(key, value);
        }
        self
    }

    /// Add authentication headers to the envelope
    /// This method accepts any headers map, allowing templates to integrate their own auth systems
    pub fn with_auth_headers(mut self, auth_headers: HashMap<String, String>) -> Self {
        if !auth_headers.is_empty() {
            if let Some(ref mut headers) = self.headers {
                headers.extend(auth_headers);
            } else {
                self.headers = Some(auth_headers);
            }
        }
        self
    }

    /// Set an error on this envelope
    pub fn with_error(mut self, error: AsyncApiError) -> Self {
        self.error = Some(error);
        self
    }

    /// Set a simple error on this envelope (for backward compatibility)
    pub fn with_simple_error(mut self, message: &str) -> Self {
        let error = AsyncApiError::Handler {
            message: message.to_string(),
            handler_name: self.operation.clone(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::BusinessLogic,
                false,
            ),
        };
        self.error = Some(error);
        self
    }

    /// Extract the payload as a strongly-typed message
    pub fn extract_payload<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.payload.clone())
    }

    /// Check if this envelope contains an error
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    /// Get the correlation ID if present
    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }

    /// Create a response envelope with the same correlation ID
    pub fn create_response<T: Serialize>(
        &self,
        response_operation: &str,
        payload: T,
    ) -> Result<Self, serde_json::Error> {
        let mut response = Self::new(response_operation, payload)?;
        response.correlation_id = self.correlation_id.clone();
        response.channel = self.channel.clone();
        Ok(response)
    }

    /// Convert the envelope to bytes for transport
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Parse envelope from bytes received from transport
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}



// Client-specific extensions for auth integration
impl MessageEnvelope {
    /// Create a new message envelope with authentication headers
    pub fn new_with_auth<T: Serialize>(
        operation: &str,
        payload: T,
        auth: &AuthCredentials,
    ) -> Result<Self, serde_json::Error> {
        let auth_headers = generate_auth_headers(auth);
        Self::new(operation, payload).map(|envelope| envelope.with_auth_headers(auth_headers))
    }
}

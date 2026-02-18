//! Generated data models from AsyncAPI specification

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



/// LoginPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginPayload {
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: String,
}

/// LoginResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponsePayload {
    /// Whether login was successful
    pub success: bool,
    /// JWT token for authenticated requests
    pub jwt: String,
    /// CSKA ID for which the login was performed
    #[serde(rename = "cskaId")]
    pub cska_id: u64,
}

/// LogoutPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutPayload {
    /// Session identifier to logout
    #[serde(rename = "sessionId")]
    pub session_id: String,
}

/// LogoutResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutResponsePayload {
    /// Whether logout was successful
    pub success: bool,
    /// Success or error message
    pub message: String,
}

/// BootstrapDevicePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapDevicePayload {
    /// Human-readable name for the device
    pub device_name: String,
    /// Optional email address to send bootstrap credentials to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// URL of the UI for bootstrap email link (e.g., window.location.origin). Required if email is provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_url: Option<String>,
    /// Configuration for bootstrap with optional pre-provisioning support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<BootstrapDeviceConfiguration>,
}

/// BootstrapDeviceResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapDeviceResponsePayload {
    /// Whether the bootstrap was successful
    pub success: bool,
    /// Unique seat identifier for the bootstrapped device
    #[serde(rename = "seatId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seat_id: Option<u32>,
    #[serde(rename = "bootstrapCredentials")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_credentials: Option<DeviceCredentials>,
    /// Success or error message
    pub message: String,
}

/// GetDevicePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDevicePayload {
    /// Seat ID of the device to retrieve
    #[serde(rename = "seatId")]
    pub seat_id: u32,
}

/// GetDeviceResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDeviceResponsePayload {
    /// Whether the request was successful
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceInfo>,
    /// Success or error message
    pub message: String,
}

/// ConfigureDevicePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigureDevicePayload {
    /// Seat ID of the device to configure
    #[serde(rename = "seatId")]
    pub seat_id: u32,
    pub configuration: DeviceConfiguration,
    /// Profile ID to assign to device. If null, device uses manual configuration from the configuration field.
    #[serde(rename = "profileId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
}

/// ConfigureDeviceResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigureDeviceResponsePayload {
    /// Whether the configuration was successful
    pub success: bool,
    /// Success or error message
    pub message: String,
}

/// DeleteDevicePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDevicePayload {
    /// Seat ID of the device to delete
    #[serde(rename = "seatId")]
    pub seat_id: u32,
    /// Whether to force deletion even if device is active
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
}

/// DeleteDeviceResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDeviceResponsePayload {
    /// Whether the deletion was successful
    pub success: bool,
    /// Success or error message
    pub message: String,
}

/// Logging verbosity level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LoggingLevel {
    #[serde(rename = "debug")]
    Debug,
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "error")]
    Error,
}

/// Configuration for bootstrap with optional pre-provisioning support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapDeviceConfiguration {
    /// Logging verbosity level
    #[serde(rename = "loggingLevel")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging_level: Option<LoggingLevel>,
    /// Human-readable name of the device (overrides the device_name in the request)
    #[serde(rename = "deviceName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// Human-readable name of the CSKA that manages this device
    #[serde(rename = "cskaName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cska_name: Option<String>,
    /// List of IPv4 addresses (in dotted notation) that should be blocked at the source IP level for validator devices
    #[serde(rename = "blockedAddresses")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_addresses: Option<Vec<String>>,
    /// Array of validation rules to apply (pre-provisioning support)
    #[serde(rename = "validationRules")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_rules: Option<Vec<FilterValidationRule>>,
    /// Array of signing rules to apply (pre-provisioning support)
    #[serde(rename = "signingRules")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_rules: Option<Vec<FilterSignerRule>>,
}

/// DeviceConfiguration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfiguration {
    /// Logging verbosity level
    #[serde(rename = "loggingLevel")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging_level: Option<LoggingLevel>,
    /// Human-readable name of the device
    #[serde(rename = "deviceName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// Human-readable name of the CSKA that manages this device
    #[serde(rename = "cskaName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cska_name: Option<String>,
    /// List of seat IDs of signers that are blocked
    #[serde(rename = "blockedSigners")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_signers: Option<Vec<u32>>,
    /// List of IPv4 addresses (in dotted notation) that should be blocked at the source IP level for validator devices
    #[serde(rename = "blockedAddresses")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_addresses: Option<Vec<String>>,
    /// Array of validation rules to apply
    #[serde(rename = "validationRules")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_rules: Option<Vec<FilterValidationRule>>,
    /// Array of signing rules to apply
    #[serde(rename = "signingRules")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_rules: Option<Vec<FilterSignerRule>>,
}

/// FilterValidationRule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterValidationRule {
    /// Action to take for validation
    pub action: FilterValidationAction,
    /// Network layer to apply the filter to
    pub layer: FilterLayer,
    /// Algorithm to use for the filter
    pub algo: FilterAlgo,
    /// cBPF rule string (e.g., "udp and port 8000")
    pub rule: String,
    /// Drop packets with NewSessionHeader from remote CSKA and generate CrossCSKAThreat report
    #[serde(rename = "dropIfRemoteCska")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drop_if_remote_cska: Option<bool>,
}

/// FilterSignerRule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterSignerRule {
    /// Action to take for signing
    pub action: FilterSigningAction,
    /// Network layer to apply the filter to
    pub layer: FilterLayer,
    /// Algorithm to use for the filter
    pub algo: FilterAlgo,
    /// cBPF rule string (e.g., "udp and port 8000")
    pub rule: String,
}

/// Action to take for validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FilterValidationAction {
    #[serde(rename = "accept")]
    Accept,
    #[serde(rename = "drop")]
    Drop,
    #[serde(rename = "validate")]
    Validate,
    #[serde(rename = "validate_strip")]
    ValidateStrip,
}

/// Action to take for signing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FilterSigningAction {
    #[serde(rename = "accept")]
    Accept,
    #[serde(rename = "drop")]
    Drop,
    #[serde(rename = "sign")]
    Sign,
}

/// Network layer to apply the filter to
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FilterLayer {
    #[serde(rename = "l567")]
    L567,
    #[serde(rename = "l4")]
    L4,
    #[serde(rename = "l3")]
    L3,
}

/// Algorithm to use for the filter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FilterAlgo {
    #[serde(rename = "xor")]
    Xor,
    #[serde(rename = "sha512")]
    Sha512,
}

/// NetworkSettings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// Port number for the device to listen on
    #[serde(rename = "listenPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<i32>,
    /// List of allowed peer device IDs
    #[serde(rename = "allowedPeers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_peers: Option<Vec<String>>,
    /// Whether to enable encryption for communications
    #[serde(rename = "encryptionEnabled")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_enabled: Option<bool>,
    /// Heartbeat interval in seconds
    #[serde(rename = "heartbeatInterval")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval: Option<i32>,
}

/// DeviceCredentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCredentials {
    /// Bootstrap credentials format version (currently 1)
    pub version: u32,
    /// Unique seat identifier for the device
    #[serde(rename = "seatId")]
    pub seat_id: u32,
    /// Device seed for connecting to NATS
    pub seed: String,
    /// JWT for authenticating the device
    pub jwt: String,
    /// NATS leaf node URL for device connections
    #[serde(rename = "natsUrl")]
    pub nats_url: String,
    /// CSKA ID this device belongs to
    #[serde(rename = "cskaId")]
    pub cska_id: u64,
}

/// ListDevicesPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDevicesPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<DeviceFilters>,
}

/// ListDevicesResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDevicesResponsePayload {
    /// Whether the request was successful
    pub success: bool,
    /// List of devices
    pub devices: Vec<DeviceInfo>,
    /// Success or error message
    pub message: String,
}

/// DeviceFilters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFilters {
    /// Filter by device type
    #[serde(rename = "deviceType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<DeviceFiltersDeviceTypeEnum>,
    /// Filter by device status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<DeviceFiltersStatusEnum>,
    /// Filter by profile ID (use "none" for devices without a profile)
    #[serde(rename = "profileId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<uuid::Uuid>,
    /// Filter by tag IDs (OR logic - matches devices with any of these tags)
    #[serde(rename = "tagIds")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_ids: Option<Vec<uuid::Uuid>>,
}

/// DeviceInfo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Unique device seat identifier
    #[serde(rename = "seatId")]
    pub seat_id: u32,
    /// Human-readable name for the device
    #[serde(rename = "deviceName")]
    pub device_name: String,
    /// Optional email address associated with the device
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Type/function of the device (auto-computed from rules)
    #[serde(rename = "deviceType")]
    pub device_type: DeviceInfoDeviceTypeEnum,
    /// Current status of the device
    pub status: DeviceStatus,
    /// When the device was last contacted
    #[serde(rename = "lastSeen")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    /// When the device was created
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// ID of the profile assigned to this device (if any)
    #[serde(rename = "profileId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<uuid::Uuid>,
    /// Name of the profile assigned to this device (if any)
    #[serde(rename = "profileName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    /// Tags assigned to this device
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<TagInfo>>,
    #[serde(rename = "deviceConfiguration")]
    pub device_configuration: DeviceConfiguration,
    #[serde(rename = "bootstrapCredentials")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_credentials: Option<DeviceCredentials>,
}

/// Current status of the device
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "inactive")]
    Inactive,
    #[serde(rename = "provisioning")]
    Provisioning,
    #[serde(rename = "error")]
    Error,
}

/// GetNetworkTopologyPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNetworkTopologyPayload {
    /// Unique identifier for the request
    #[serde(rename = "requestId")]
    pub request_id: uuid::Uuid,
}

/// GetNetworkTopologyResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNetworkTopologyResponsePayload {
    /// Unique identifier matching the request
    #[serde(rename = "requestId")]
    pub request_id: uuid::Uuid,
    /// Whether the request was successful
    pub success: bool,
    #[serde(rename = "networkData")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_data: Option<NetworkTopologyData>,
    /// Success or error message
    pub message: String,
}

/// NetworkTopologyData
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopologyData {
    /// List of network nodes (CSKAs and devices)
    pub nodes: Vec<NetworkNode>,
    /// List of network links (ownership and communication)
    pub links: Vec<NetworkLink>,
}

/// NetworkNode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    /// Unique identifier for the node
    pub id: String,
    /// Type of network node
    #[serde(rename = "type")]
    pub type_: NetworkNodeTypeEnum,
    /// Human-readable name for the node
    pub name: String,
    /// Function of the device (only for device nodes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<NetworkNodeFunctionEnum>,
    /// Type of CSKA (only for CSKA nodes)
    #[serde(rename = "cskaType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cska_type: Option<NetworkNodeCskaTypeEnum>,
    /// Source IP address (only for threat_actor nodes)
    #[serde(rename = "sourceIp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Total number of threats from this actor (only for threat_actor nodes)
    #[serde(rename = "threatCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_count: Option<i32>,
}

/// NetworkLink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLink {
    /// ID of the source node
    pub source: String,
    /// ID of the target node
    pub target: String,
    /// Type of network link
    #[serde(rename = "type")]
    pub type_: NetworkLinkTypeEnum,
    /// Whether this link has detected threats (for communication links)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<bool>,
    /// Description of the threat (if any)
    #[serde(rename = "threatDescription")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_description: Option<String>,
    /// Number of threats on this link (for threat type links)
    #[serde(rename = "threatCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_count: Option<i32>,
}

/// DeviceStatusUpdatePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatusUpdatePayload {
    /// Seat ID of the device whose status changed
    #[serde(rename = "seatId")]
    pub seat_id: u32,
    /// Current status of the device
    #[serde(rename = "previousStatus")]
    pub previous_status: DeviceStatus,
    /// Current status of the device
    #[serde(rename = "newStatus")]
    pub new_status: DeviceStatus,
    /// When the status change occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "deviceInfo")]
    pub device_info: DeviceInfo,
    /// Reason for status change (e.g., "device_provisioned", "manual_update")
    pub reason: String,
}

/// UpdateDeviceMetadataPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDeviceMetadataPayload {
    /// Seat ID of the device to update
    #[serde(rename = "seatId")]
    pub seat_id: u32,
    /// List of tag IDs to assign to the device (replaces existing tags)
    #[serde(rename = "tagIds")]
    pub tag_ids: Vec<uuid::Uuid>,
}

/// UpdateDeviceMetadataResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDeviceMetadataResponsePayload {
    /// Whether the update was successful
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceInfo>,
    /// Success or error message
    pub message: String,
}

/// ProvisionDeviceRefreshRequestPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionDeviceRefreshRequestPayload {
    /// The public key for the user to be created
    pub device_user_id_pub: String,
    /// The seat ID for the device
    pub seat_id: u32,
}

/// ProvisionDeviceRefreshResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionDeviceRefreshResponsePayload {
    /// The device user JWT for the new user
    pub device_user_jwt: String,
}

/// SaltedKeyRequestPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaltedKeyRequestPayload {
    /// Version of the SaltedKeyRequest data structure
    pub version: u32,
    /// ID for the signer or validator
    pub signer_id: SeatId,
    /// ID for the signer or validator
    pub validator_id: SeatId,
    /// Index to use for salting the signing key
    pub signing_salt_index: u8,
    /// ID to salt a Key for a Channel
    pub channel_id: ChannelId,
    /// IP address of the signer for threat reports
    pub signer_ip: String,
    /// Port of the signer for threat reports
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_port: Option<u16>,
    /// MAC address of the signer for threat reports
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_mac: Option<Vec<u8>>,
    /// IP address of the validator for threat reports
    pub validator_ip: String,
    /// Port of the validator for threat reports
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_port: Option<u16>,
    /// MAC address of the validator for threat reports
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_mac: Option<Vec<u8>>,
    /// Human-readable name of the validator for connection tracking
    pub validator_name: String,
    /// CSKA ID of the validator for connection tracking
    pub validator_cska_id: u64,
    /// Human-readable name of the validator's CSKA for connection tracking
    pub validator_cska_name: String,
}

/// SaltedKeyResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaltedKeyResponsePayload {
    /// Version of the SaltedKeyResponse data structure
    pub version: u32,
    /// A salted key for validation (16 bytes)
    pub salted_key: Salt,
    /// Human-readable name of the signer for connection tracking
    pub signer_name: String,
    /// Human-readable name of the signer's CSKA for connection tracking
    pub signer_cska_name: String,
}

/// ID for the signer or validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeatId(pub u64);

impl From<u64> for SeatId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<SeatId> for u64 {
    fn from(value: SeatId) -> Self {
        value.0
    }
}

impl std::fmt::Display for SeatId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// ID to salt a Key for a Channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelId(pub u64);

impl From<u64> for ChannelId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<ChannelId> for u64 {
    fn from(value: ChannelId) -> Self {
        value.0
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A full signing key before salting (32 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key(pub Vec<u8>);

impl From<Vec<u8>> for Key {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Key> for Vec<u8> {
    fn from(value: Key) -> Self {
        value.0
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{:02x}", byte))
    }
}

/// A salted key for validation (16 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Salt(pub Vec<u8>);

impl From<Vec<u8>> for Salt {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Salt> for Vec<u8> {
    fn from(value: Salt) -> Self {
        value.0
    }
}

impl std::fmt::Display for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{:02x}", byte))
    }
}

/// SignerKey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerKey {
    /// Version of the SignerKey data structure
    pub version: u32,
    /// A full signing key before salting (32 bytes)
    pub key: Key,
}

/// NewSessionHeader
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSessionHeader {
    /// Channel ID for the session
    pub channel_id: u64,
    /// CSKA ID for the session
    pub cska_id: u32,
    /// Logical seat ID for the session
    pub logical_seat_id: u32,
}

/// HashDigests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashDigests {
    /// Layer 3 hash digest
    pub l3_digest: u32,
    /// Layer 4 hash digest
    pub l4_digest: u32,
    /// Layer 5/6/7 hash digest
    pub l567_digest: u32,
}

/// ThreatReportPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReportPayload {
    /// Version of the ThreatReport data structure
    pub version: u32,
    /// Timestamp when threat was detected (milliseconds since epoch)
    pub when: u64,
    /// Type of threat detected
    pub kind: ThreatKind,
    /// CSKA ID where threat was detected
    pub cska_id: u64,
    /// IP address of the signer
    pub signer_ip: String,
    /// Port of the signer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_port: Option<u16>,
    /// MAC address of the signer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_mac: Option<Vec<u8>>,
    /// ID for the signer or validator
    pub validator_id: SeatId,
    /// IP address of the validator
    pub validator_ip: String,
    /// Port of the validator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_port: Option<u16>,
    /// MAC address of the validator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_mac: Option<Vec<u8>>,
    /// Additional information about the threat
    pub info: String,
    /// Base64-encoded raw packet data starting from IP header (up to 100 bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_session_header: Option<NewSessionHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_digests: Option<HashDigests>,
}

/// ThreatReportResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReportResponsePayload {
    /// Whether the threat report was successfully processed
    pub success: bool,
    /// Success or error message
    pub message: String,
}

/// ThreatQueryPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatQueryPayload {
    /// Start timestamp for query range (milliseconds since epoch)
    pub start_time: u64,
    /// End timestamp for query range (milliseconds since epoch)
    pub end_time: u64,
    /// Filter by threat types (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_kinds: Option<Vec<ThreatKind>>,
    /// Filter by validator IDs (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_ids: Option<Vec<SeatId>>,
    /// Maximum number of results to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,
    /// Number of results to skip for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
}

/// ThreatQueryResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatQueryResponsePayload {
    /// Whether the query was successful
    pub success: bool,
    /// Array of threat reports matching the query
    pub threats: Vec<ThreatReportPayload>,
    /// Total number of threats matching the query (for pagination)
    pub total_count: i32,
    /// Success or error message
    pub message: String,
}

/// ThreatStreamNotificationPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStreamNotificationPayload {
    pub threat_report: ThreatReportPayload,
    /// When the threat was archived (milliseconds since epoch)
    pub archived_at: u64,
}

/// Type of threat detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatKind {
    #[serde(rename = "unsigned")]
    Unsigned,
    #[serde(rename = "protocol_violation")]
    ProtocolViolation,
    #[serde(rename = "version_mismatch")]
    VersionMismatch,
    #[serde(rename = "signature_mismatch_l2")]
    SignatureMismatchL2,
    #[serde(rename = "signature_mismatch_l3")]
    SignatureMismatchL3,
    #[serde(rename = "signature_mismatch_l4")]
    SignatureMismatchL4,
    #[serde(rename = "signature_mismatch_l567")]
    SignatureMismatchL567,
    #[serde(rename = "invalid_signer_id")]
    InvalidSignerId,
    #[serde(rename = "expired_signer_id")]
    ExpiredSignerId,
    #[serde(rename = "double_key_deref")]
    DoubleKeyDeref,
    #[serde(rename = "ddos")]
    Ddos,
    #[serde(rename = "cross_cska_threat")]
    CrossCskaThreat,
}

/// ValidatorConnectionReportPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConnectionReportPayload {
    /// ID for the signer or validator
    pub validator_id: SeatId,
    /// Human-readable name of the validator
    pub validator_name: String,
    /// CSKA ID of the validator
    pub validator_cska_id: u64,
    /// Human-readable name of the validator's CSKA
    pub validator_cska_name: String,
    /// ID for the signer or validator
    pub signer_id: SeatId,
    /// Human-readable name of the signer
    pub signer_name: String,
    /// CSKA ID of the signer
    pub signer_cska_id: u64,
    /// Human-readable name of the signer's CSKA
    pub signer_cska_name: String,
    /// ID to salt a Key for a Channel
    pub channel_id: ChannelId,
    /// Timestamp when the connection was established (milliseconds since epoch)
    pub timestamp: u64,
}

/// ValidatorConnectionResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConnectionResponsePayload {
    /// Whether the connection report was successfully processed
    pub success: bool,
    /// Success or error message
    pub message: String,
}

/// ConnectionQueryPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionQueryPayload {
    /// Filter by connection type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<ConnectionQueryPayloadConnectionTypeEnum>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_range: Option<DateRange>,
    /// Filter by specific signer IDs (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_ids: Option<Vec<SeatId>>,
    /// Filter by specific validator IDs (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_ids: Option<Vec<SeatId>>,
    /// Filter by specific CSKA IDs (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cska_ids: Option<Vec<u64>>,
    /// Filter by minimum connection count (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_connection_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PaginationParams>,
}

/// ConnectionQueryResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionQueryResponsePayload {
    /// Whether the query was successful
    pub success: bool,
    /// Array of connection records matching the query
    pub connections: Vec<ConnectionRecord>,
    /// Total number of connections matching the query (for pagination)
    pub total_count: i32,
    /// Success or error message
    pub message: String,
}

/// ConnectionStreamNotificationPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStreamNotificationPayload {
    /// Type of connection event
    pub event_type: ConnectionStreamNotificationPayloadEventTypeEnum,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_record: Option<ConnectionRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topology_delta: Option<TopologyDelta>,
    /// Timestamp when the event occurred (milliseconds since epoch)
    pub timestamp: u64,
}

/// DateRange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    /// Start timestamp (milliseconds since epoch)
    pub start_time: u64,
    /// End timestamp (milliseconds since epoch)
    pub end_time: u64,
}

/// PaginationParams
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    /// Maximum number of results to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,
    /// Number of results to skip for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
}

/// ConnectionRecord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    /// Type of connection record
    pub connection_type: ConnectionRecordConnectionTypeEnum,
    /// Signer device ID
    pub signer_id: u64,
    /// Human-readable name of the signer
    pub signer_name: String,
    /// CSKA ID of the signer
    pub signer_cska_id: u64,
    /// Human-readable name of the signer's CSKA
    pub signer_cska_name: String,
    /// Validator device ID
    pub validator_id: u64,
    /// Human-readable name of the validator
    pub validator_name: String,
    /// CSKA ID of the validator
    pub validator_cska_id: u64,
    /// Human-readable name of the validator's CSKA
    pub validator_cska_name: String,
    /// Timestamp when connection was first established (milliseconds since epoch)
    pub first_seen: u64,
    /// Timestamp when connection was last active (milliseconds since epoch)
    pub last_seen: u64,
    /// Number of times this connection has been established
    pub connection_count: u64,
}

/// TopologyDelta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyDelta {
    /// Type of topology change
    pub operation: TopologyDeltaOperationEnum,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<NetworkNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<NetworkLink>,
    /// Additional metadata about the change
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// MetricsQueryPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsQueryPayload {
    /// Seat ID of the device to query metrics for
    pub seat_id: u32,
    /// Filter by specific metric names (optional, returns all if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric_names: Option<Vec<String>>,
    /// Start timestamp in milliseconds since epoch (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    /// End timestamp in milliseconds since epoch (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i64>,
}

/// MetricsQueryResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsQueryResponsePayload {
    /// Whether the query was successful
    pub success: bool,
    /// Seat ID of the device
    pub seat_id: u32,
    /// Array of metric samples matching the query
    pub samples: Vec<MetricSample>,
    /// Success or error message
    pub message: String,
}

/// MetricsStreamNotificationPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsStreamNotificationPayload {
    /// Seat ID of the device
    pub seat_id: u32,
    pub sample: MetricSample,
    /// Timestamp when the notification was sent (milliseconds since epoch)
    pub timestamp: i64,
}

/// MetricSample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    /// Timestamp in milliseconds since epoch when metrics were collected
    pub timestamp: i64,
    /// Map of metric name to metric value (e.g., signed_packets, verified_packets, dropped_packets, threats)
    pub metrics: serde_json::Value,
}

/// MetricsResetPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResetPayload {
    /// Seat ID of the device to reset metrics for
    pub seat_id: u32,
    /// Specific metric name to reset (e.g., "threats_detected")
    pub metric_name: String,
}

/// MetricsResetResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResetResponsePayload {
    /// Whether the reset was successful
    pub success: bool,
    /// Success or error message
    pub message: String,
}

/// ThreatPcapDownloadPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPcapDownloadPayload {
    /// Source IP address to filter threats (e.g., "192.168.1.100")
    pub source_ip: String,
    /// Start timestamp for query range (milliseconds since epoch)
    pub start_time: u64,
    /// End timestamp for query range (milliseconds since epoch)
    pub end_time: u64,
    /// Maximum number of packets to include in PCAP (enforced server-side)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,
}

/// ThreatPcapDownloadResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPcapDownloadResponsePayload {
    /// Whether the ZIP archive generation was successful
    pub success: bool,
    /// Base64-encoded ZIP archive containing threats.pcap and threats.json (only present if success is true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcap_data: Option<String>,
    /// Suggested filename for the download (e.g., "threats-192.168.1.100.zip")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Number of packets included in the PCAP file within the ZIP
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_count: Option<i32>,
    /// Success or error message
    pub message: String,
}

/// TagInfo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagInfo {
    /// Unique identifier for the tag
    #[serde(rename = "tagId")]
    pub tag_id: uuid::Uuid,
    /// Human-readable name for the tag (unique within CSKA)
    #[serde(rename = "tagName")]
    pub tag_name: String,
    /// Optional color for UI display (hex format, e.g., "#FF5733")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// When the tag was created
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Number of devices using this tag (computed on query)
    #[serde(rename = "deviceCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_count: Option<i32>,
}

/// CreateTagPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTagPayload {
    /// Human-readable name for the tag
    #[serde(rename = "tagName")]
    pub tag_name: String,
    /// Optional color for UI display (hex format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

/// CreateTagResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTagResponsePayload {
    /// Whether the tag was created successfully
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<TagInfo>,
    /// Success or error message
    pub message: String,
}

/// UpdateTagPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTagPayload {
    /// ID of the tag to update
    #[serde(rename = "tagId")]
    pub tag_id: uuid::Uuid,
    /// New name for the tag
    #[serde(rename = "tagName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_name: Option<String>,
    /// New color for the tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

/// UpdateTagResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTagResponsePayload {
    /// Whether the tag was updated successfully
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<TagInfo>,
    /// Success or error message
    pub message: String,
}

/// DeleteTagPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteTagPayload {
    /// ID of the tag to delete
    #[serde(rename = "tagId")]
    pub tag_id: uuid::Uuid,
}

/// DeleteTagResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteTagResponsePayload {
    /// Whether the tag was deleted successfully
    pub success: bool,
    /// Success or error message
    pub message: String,
}

/// ListTagsPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTagsPayload {
    /// Whether to include device count for each tag
    #[serde(rename = "includeDeviceCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_device_count: Option<bool>,
}

/// ListTagsResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTagsResponsePayload {
    /// Whether the request was successful
    pub success: bool,
    /// List of tags
    pub tags: Vec<TagInfo>,
    /// Success or error message
    pub message: String,
}

/// ProfileInfo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
    /// Unique identifier for the profile
    #[serde(rename = "profileId")]
    pub profile_id: uuid::Uuid,
    /// Human-readable name for the profile
    #[serde(rename = "profileName")]
    pub profile_name: String,
    /// Optional description of the profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// When the profile was created
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the profile was last updated
    #[serde(rename = "updatedAt")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Number of devices assigned to this profile (computed on query)
    #[serde(rename = "deviceCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_count: Option<i32>,
    /// Configuration settings stored in a profile (device name and logging level remain device-specific)
    pub configuration: ProfileConfiguration,
}

/// Configuration settings stored in a profile (device name and logging level remain device-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfiguration {
    /// List of IPv4 addresses that should be blocked at the source IP level for validator devices
    #[serde(rename = "blockedAddresses")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_addresses: Option<Vec<String>>,
    /// Array of validation rules to apply
    #[serde(rename = "validationRules")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_rules: Option<Vec<FilterValidationRule>>,
    /// Array of signing rules to apply
    #[serde(rename = "signingRules")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_rules: Option<Vec<FilterSignerRule>>,
}

/// CreateProfilePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProfilePayload {
    /// Human-readable name for the profile
    #[serde(rename = "profileName")]
    pub profile_name: String,
    /// Optional description of the profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Configuration settings stored in a profile (device name and logging level remain device-specific)
    pub configuration: ProfileConfiguration,
}

/// CreateProfileResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProfileResponsePayload {
    /// Whether the profile was created successfully
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileInfo>,
    /// Success or error message
    pub message: String,
}

/// GetProfilePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProfilePayload {
    /// ID of the profile to retrieve
    #[serde(rename = "profileId")]
    pub profile_id: uuid::Uuid,
}

/// GetProfileResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProfileResponsePayload {
    /// Whether the request was successful
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileInfo>,
    /// Success or error message
    pub message: String,
}

/// UpdateProfilePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProfilePayload {
    /// ID of the profile to update
    #[serde(rename = "profileId")]
    pub profile_id: uuid::Uuid,
    /// New name for the profile
    #[serde(rename = "profileName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    /// New description for the profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Configuration settings stored in a profile (device name and logging level remain device-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<ProfileConfiguration>,
}

/// UpdateProfileResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProfileResponsePayload {
    /// Whether the profile was updated successfully
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileInfo>,
    /// Number of devices that received configuration updates
    #[serde(rename = "devicesUpdated")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices_updated: Option<i32>,
    /// Success or error message
    pub message: String,
}

/// DeleteProfilePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteProfilePayload {
    /// ID of the profile to delete
    #[serde(rename = "profileId")]
    pub profile_id: uuid::Uuid,
}

/// DeleteProfileResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteProfileResponsePayload {
    /// Whether the profile was deleted successfully
    pub success: bool,
    /// Success or error message (will indicate "blocked" if devices are assigned)
    pub message: String,
}

/// ListProfilesPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProfilesPayload {
    /// Whether to include device count for each profile
    #[serde(rename = "includeDeviceCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_device_count: Option<bool>,
}

/// ListProfilesResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProfilesResponsePayload {
    /// Whether the request was successful
    pub success: bool,
    /// List of profiles
    pub profiles: Vec<ProfileInfo>,
    /// Success or error message
    pub message: String,
}

/// AssignProfilePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignProfilePayload {
    /// ID of the profile to assign devices to
    #[serde(rename = "profileId")]
    pub profile_id: uuid::Uuid,
    /// List of device seat IDs to assign to the profile
    #[serde(rename = "seatIds")]
    pub seat_ids: Vec<u32>,
}

/// AssignProfileResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignProfileResponsePayload {
    /// Whether the assignment was successful
    pub success: bool,
    /// Number of devices successfully assigned
    #[serde(rename = "assignedCount")]
    pub assigned_count: i32,
    /// List of seat IDs that failed to be assigned (if any)
    #[serde(rename = "failedSeatIds")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_seat_ids: Option<Vec<u32>>,
    /// Success or error message
    pub message: String,
}

/// UnassignProfilePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnassignProfilePayload {
    /// List of device seat IDs to remove from their profiles
    #[serde(rename = "seatIds")]
    pub seat_ids: Vec<u32>,
}

/// UnassignProfileResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnassignProfileResponsePayload {
    /// Whether the unassignment was successful
    pub success: bool,
    /// Number of devices successfully unassigned
    #[serde(rename = "unassignedCount")]
    pub unassigned_count: i32,
    /// Success or error message
    pub message: String,
}

/// Empty payload - no parameters needed to get settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSettingsPayload {

}

/// GetSettingsResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSettingsResponsePayload {
    /// Whether the request was successful
    pub success: bool,
    /// System-wide settings stored in NATS bucket
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<SystemSettings>,
    /// Success or error message
    pub message: String,
}

/// UpdateSettingsPayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettingsPayload {
    /// System-wide settings stored in NATS bucket
    pub settings: SystemSettings,
}

/// UpdateSettingsResponsePayload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettingsResponsePayload {
    /// Whether the update was successful
    pub success: bool,
    /// System-wide settings stored in NATS bucket
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<SystemSettings>,
    /// Success or error message
    pub message: String,
}

/// System-wide settings stored in NATS bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSettings {
    /// Email notification configuration
    pub email: EmailSettings,
}

/// Email notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSettings {
    /// Whether email notifications are enabled
    pub enabled: bool,
    /// Email address to send from (required when enabled)
    #[serde(rename = "fromAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_address: Option<String>,
    /// Display name for the sender
    #[serde(rename = "fromName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    /// Type of email provider
    #[serde(rename = "activeProvider")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_provider: Option<EmailProviderType>,
    /// SendGrid email provider configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sendgrid: Option<SendGridConfig>,
    /// Mailgun email provider configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailgun: Option<MailgunConfig>,
}

/// Type of email provider
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EmailProviderType {
    #[serde(rename = "sendgrid")]
    Sendgrid,
    #[serde(rename = "mailgun")]
    Mailgun,
}

/// SendGrid email provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendGridConfig {
    /// SendGrid API key
    #[serde(rename = "apiKey")]
    pub api_key: String,
}

/// Mailgun email provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailgunConfig {
    /// Mailgun API key
    #[serde(rename = "apiKey")]
    pub api_key: String,
    /// Mailgun sending domain (e.g., mail.yourcompany.com)
    pub domain: String,
    /// Mailgun API region (US or EU)
    pub region: MailgunRegion,
}

/// Mailgun API region (US or EU)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MailgunRegion {
    #[serde(rename = "us")]
    Us,
    #[serde(rename = "eu")]
    Eu,
}


/// Filter by device type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceFiltersDeviceTypeEnum {
    #[serde(rename = "signer")]
    Signer,
    #[serde(rename = "validator")]
    Validator,
    #[serde(rename = "signer_validator")]
    SignerValidator,
    #[serde(rename = "unconfigured")]
    Unconfigured,
}

/// Filter by device status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceFiltersStatusEnum {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "inactive")]
    Inactive,
    #[serde(rename = "provisioning")]
    Provisioning,
    #[serde(rename = "error")]
    Error,
}

/// Type/function of the device (auto-computed from rules)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceInfoDeviceTypeEnum {
    #[serde(rename = "signer")]
    Signer,
    #[serde(rename = "validator")]
    Validator,
    #[serde(rename = "signer_validator")]
    SignerValidator,
    #[serde(rename = "unconfigured")]
    Unconfigured,
}

/// Type of network node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkNodeTypeEnum {
    #[serde(rename = "cska")]
    Cska,
    #[serde(rename = "device")]
    Device,
    #[serde(rename = "threat_actor")]
    ThreatActor,
}

/// Function of the device (only for device nodes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkNodeFunctionEnum {
    #[serde(rename = "signer")]
    Signer,
    #[serde(rename = "validator")]
    Validator,
    #[serde(rename = "signer_validator")]
    SignerValidator,
    #[serde(rename = "unconfigured")]
    Unconfigured,
}

/// Type of CSKA (only for CSKA nodes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkNodeCskaTypeEnum {
    #[serde(rename = "local")]
    Local,
    #[serde(rename = "remote")]
    Remote,
}

/// Type of network link
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkLinkTypeEnum {
    #[serde(rename = "ownership")]
    Ownership,
    #[serde(rename = "communication")]
    Communication,
    #[serde(rename = "threat")]
    Threat,
}

/// Filter by connection type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionQueryPayloadConnectionTypeEnum {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "signer_to_validator")]
    SignerToValidator,
    #[serde(rename = "validator_to_signer")]
    ValidatorToSigner,
}

/// Type of connection event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionStreamNotificationPayloadEventTypeEnum {
    #[serde(rename = "connection_established")]
    ConnectionEstablished,
    #[serde(rename = "connection_updated")]
    ConnectionUpdated,
    #[serde(rename = "device_offline")]
    DeviceOffline,
    #[serde(rename = "topology_changed")]
    TopologyChanged,
}

/// Type of connection record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionRecordConnectionTypeEnum {
    #[serde(rename = "signer_to_validator")]
    SignerToValidator,
    #[serde(rename = "validator_to_signer")]
    ValidatorToSigner,
}

/// Type of topology change
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TopologyDeltaOperationEnum {
    #[serde(rename = "add_node")]
    AddNode,
    #[serde(rename = "remove_node")]
    RemoveNode,
    #[serde(rename = "add_link")]
    AddLink,
    #[serde(rename = "remove_link")]
    RemoveLink,
    #[serde(rename = "update_link")]
    UpdateLink,
}


/// LoginRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    #[serde(flatten)]
    pub payload: LoginPayload,
}
/// LoginResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    #[serde(flatten)]
    pub payload: LoginResponsePayload,
}
/// LogoutRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
    #[serde(flatten)]
    pub payload: LogoutPayload,
}
/// LogoutResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutResponse {
    #[serde(flatten)]
    pub payload: LogoutResponsePayload,
}
/// BootstrapDeviceRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapDeviceRequest {
    #[serde(flatten)]
    pub payload: BootstrapDevicePayload,
}
/// BootstrapDeviceResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapDeviceResponse {
    #[serde(flatten)]
    pub payload: BootstrapDeviceResponsePayload,
}
/// GetDeviceRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDeviceRequest {
    #[serde(flatten)]
    pub payload: GetDevicePayload,
}
/// GetDeviceResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDeviceResponse {
    #[serde(flatten)]
    pub payload: GetDeviceResponsePayload,
}
/// ConfigureDeviceRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigureDeviceRequest {
    #[serde(flatten)]
    pub payload: ConfigureDevicePayload,
}
/// ConfigureDeviceResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigureDeviceResponse {
    #[serde(flatten)]
    pub payload: ConfigureDeviceResponsePayload,
}
/// DeleteDeviceRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDeviceRequest {
    #[serde(flatten)]
    pub payload: DeleteDevicePayload,
}
/// DeleteDeviceResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDeviceResponse {
    #[serde(flatten)]
    pub payload: DeleteDeviceResponsePayload,
}
/// ListDevicesRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDevicesRequest {
    #[serde(flatten)]
    pub payload: ListDevicesPayload,
}
/// ListDevicesResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDevicesResponse {
    #[serde(flatten)]
    pub payload: ListDevicesResponsePayload,
}
/// DeviceStatusUpdateNotification message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatusUpdateNotification {
    #[serde(flatten)]
    pub payload: DeviceStatusUpdatePayload,
}
/// UpdateDeviceMetadataRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDeviceMetadataRequest {
    #[serde(flatten)]
    pub payload: UpdateDeviceMetadataPayload,
}
/// UpdateDeviceMetadataResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDeviceMetadataResponse {
    #[serde(flatten)]
    pub payload: UpdateDeviceMetadataResponsePayload,
}
/// GetNetworkTopologyRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNetworkTopologyRequest {
    #[serde(flatten)]
    pub payload: GetNetworkTopologyPayload,
}
/// GetNetworkTopologyResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNetworkTopologyResponse {
    #[serde(flatten)]
    pub payload: GetNetworkTopologyResponsePayload,
}
/// ProvisionDeviceRefreshRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionDeviceRefreshRequest {
    #[serde(flatten)]
    pub payload: ProvisionDeviceRefreshRequestPayload,
}
/// ProvisionDeviceRefreshResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionDeviceRefreshResponse {
    #[serde(flatten)]
    pub payload: ProvisionDeviceRefreshResponsePayload,
}
/// SaltedKeyRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaltedKeyRequest {
    #[serde(flatten)]
    pub payload: SaltedKeyRequestPayload,
}
/// SaltedKeyResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaltedKeyResponse {
    #[serde(flatten)]
    pub payload: SaltedKeyResponsePayload,
}
/// ThreatReportRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReportRequest {
    #[serde(flatten)]
    pub payload: ThreatReportPayload,
}
/// ThreatReportResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReportResponse {
    #[serde(flatten)]
    pub payload: ThreatReportResponsePayload,
}
/// ThreatQueryRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatQueryRequest {
    #[serde(flatten)]
    pub payload: ThreatQueryPayload,
}
/// ThreatQueryResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatQueryResponse {
    #[serde(flatten)]
    pub payload: ThreatQueryResponsePayload,
}
/// ThreatStreamNotification message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStreamNotification {
    #[serde(flatten)]
    pub payload: ThreatStreamNotificationPayload,
}
/// ThreatPcapDownloadRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPcapDownloadRequest {
    #[serde(flatten)]
    pub payload: ThreatPcapDownloadPayload,
}
/// ThreatPcapDownloadResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPcapDownloadResponse {
    #[serde(flatten)]
    pub payload: ThreatPcapDownloadResponsePayload,
}
/// ValidatorConnectionReport message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConnectionReport {
    #[serde(flatten)]
    pub payload: ValidatorConnectionReportPayload,
}
/// ValidatorConnectionResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConnectionResponse {
    #[serde(flatten)]
    pub payload: ValidatorConnectionResponsePayload,
}
/// ConnectionQueryRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionQueryRequest {
    #[serde(flatten)]
    pub payload: ConnectionQueryPayload,
}
/// ConnectionQueryResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionQueryResponse {
    #[serde(flatten)]
    pub payload: ConnectionQueryResponsePayload,
}
/// ConnectionStreamNotification message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStreamNotification {
    #[serde(flatten)]
    pub payload: ConnectionStreamNotificationPayload,
}
/// MetricsQueryRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsQueryRequest {
    #[serde(flatten)]
    pub payload: MetricsQueryPayload,
}
/// MetricsQueryResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsQueryResponse {
    #[serde(flatten)]
    pub payload: MetricsQueryResponsePayload,
}
/// MetricsStreamNotification message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsStreamNotification {
    #[serde(flatten)]
    pub payload: MetricsStreamNotificationPayload,
}
/// MetricsResetRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResetRequest {
    #[serde(flatten)]
    pub payload: MetricsResetPayload,
}
/// MetricsResetResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResetResponse {
    #[serde(flatten)]
    pub payload: MetricsResetResponsePayload,
}
/// CreateTagRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTagRequest {
    #[serde(flatten)]
    pub payload: CreateTagPayload,
}
/// CreateTagResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTagResponse {
    #[serde(flatten)]
    pub payload: CreateTagResponsePayload,
}
/// UpdateTagRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTagRequest {
    #[serde(flatten)]
    pub payload: UpdateTagPayload,
}
/// UpdateTagResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTagResponse {
    #[serde(flatten)]
    pub payload: UpdateTagResponsePayload,
}
/// DeleteTagRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteTagRequest {
    #[serde(flatten)]
    pub payload: DeleteTagPayload,
}
/// DeleteTagResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteTagResponse {
    #[serde(flatten)]
    pub payload: DeleteTagResponsePayload,
}
/// ListTagsRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTagsRequest {
    #[serde(flatten)]
    pub payload: ListTagsPayload,
}
/// ListTagsResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTagsResponse {
    #[serde(flatten)]
    pub payload: ListTagsResponsePayload,
}
/// CreateProfileRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProfileRequest {
    #[serde(flatten)]
    pub payload: CreateProfilePayload,
}
/// CreateProfileResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProfileResponse {
    #[serde(flatten)]
    pub payload: CreateProfileResponsePayload,
}
/// GetProfileRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProfileRequest {
    #[serde(flatten)]
    pub payload: GetProfilePayload,
}
/// GetProfileResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProfileResponse {
    #[serde(flatten)]
    pub payload: GetProfileResponsePayload,
}
/// UpdateProfileRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(flatten)]
    pub payload: UpdateProfilePayload,
}
/// UpdateProfileResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProfileResponse {
    #[serde(flatten)]
    pub payload: UpdateProfileResponsePayload,
}
/// DeleteProfileRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteProfileRequest {
    #[serde(flatten)]
    pub payload: DeleteProfilePayload,
}
/// DeleteProfileResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteProfileResponse {
    #[serde(flatten)]
    pub payload: DeleteProfileResponsePayload,
}
/// ListProfilesRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProfilesRequest {
    #[serde(flatten)]
    pub payload: ListProfilesPayload,
}
/// ListProfilesResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProfilesResponse {
    #[serde(flatten)]
    pub payload: ListProfilesResponsePayload,
}
/// AssignProfileRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignProfileRequest {
    #[serde(flatten)]
    pub payload: AssignProfilePayload,
}
/// AssignProfileResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignProfileResponse {
    #[serde(flatten)]
    pub payload: AssignProfileResponsePayload,
}
/// UnassignProfileRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnassignProfileRequest {
    #[serde(flatten)]
    pub payload: UnassignProfilePayload,
}
/// UnassignProfileResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnassignProfileResponse {
    #[serde(flatten)]
    pub payload: UnassignProfileResponsePayload,
}
/// GetSettingsRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSettingsRequest {
    #[serde(flatten)]
    pub payload: GetSettingsPayload,
}
/// GetSettingsResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSettingsResponse {
    #[serde(flatten)]
    pub payload: GetSettingsResponsePayload,
}
/// UpdateSettingsRequest message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettingsRequest {
    #[serde(flatten)]
    pub payload: UpdateSettingsPayload,
}
/// UpdateSettingsResponse message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettingsResponse {
    #[serde(flatten)]
    pub payload: UpdateSettingsResponsePayload,
}
/// collections message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collections {
    pub data: serde_json::Value,
}
/// _meta message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub data: serde_json::Value,
}



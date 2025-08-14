/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

/**
 * Generate a unified MessageEnvelope for both rust-server and rust-client templates
 * This envelope includes all features needed by both templates:
 * - Basic message structure (id, operation, payload, timestamp)
 * - Request/response patterns (correlation_id, create_response)
 * - Channel routing (channel field)
 * - Error handling (error field, error methods)
 * - Authentication (auth header methods)
 * - Serialization (to_bytes, from_bytes)
 */
export function generateMessageEnvelope() {
    return `use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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
/// \`\`\`no-run
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
/// \`\`\`

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
    /// Error information if applicable
    pub error: Option<MessageError>,
}

/// Error information for failed operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageError {
    /// Error code (e.g., "VALIDATION_ERROR", "TIMEOUT", "UNAUTHORIZED")
    pub code: String,
    /// Human-readable error message
    pub message: String,
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

    /// Create an error response envelope
    pub fn error_response(
        operation: &str,
        error_code: &str,
        error_message: &str,
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
            error: Some(MessageError {
                code: error_code.to_string(),
                message: error_message.to_string(),
            }),
        }
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
    pub fn with_error(mut self, code: &str, message: &str) -> Self {
        self.error = Some(MessageError {
            code: code.to_string(),
            message: message.to_string(),
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestPayload {
        message: String,
        count: u32,
    }

    #[test]
    fn test_envelope_creation() {
        let payload = TestPayload {
            message: "test".to_string(),
            count: 42,
        };

        let envelope = MessageEnvelope::new("test_operation", &payload).unwrap();

        assert_eq!(envelope.operation, "test_operation");
        assert!(!envelope.id.is_empty());
        assert!(!envelope.timestamp.is_empty());
        assert_eq!(envelope.correlation_id, None);
        assert_eq!(envelope.error, None);

        let extracted: TestPayload = envelope.extract_payload().unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn test_envelope_with_correlation_id() {
        let payload = TestPayload {
            message: "test".to_string(),
            count: 42,
        };

        let correlation_id = "test-correlation-id".to_string();
        let envelope = MessageEnvelope::new_with_correlation_id(
            "test_operation",
            &payload,
            correlation_id.clone(),
        ).unwrap();

        assert_eq!(envelope.correlation_id, Some(correlation_id));
    }

    #[test]
    fn test_error_response() {
        let error_envelope = MessageEnvelope::error_response(
            "test_operation_response",
            "TEST_ERROR",
            "Test error message",
            Some("correlation-123".to_string()),
        );

        assert!(error_envelope.is_error());
        assert_eq!(error_envelope.correlation_id, Some("correlation-123".to_string()));
        if let Some(error) = &error_envelope.error {
            assert_eq!(error.code, "TEST_ERROR");
            assert_eq!(error.message, "Test error message");
        }
    }

    #[test]
    fn test_envelope_serialization() {
        let payload = TestPayload {
            message: "test".to_string(),
            count: 42,
        };

        let envelope = MessageEnvelope::new("test_operation", &payload).unwrap();
        let bytes = envelope.to_bytes().unwrap();
        let deserialized = MessageEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(envelope.id, deserialized.id);
        assert_eq!(envelope.operation, deserialized.operation);
        assert_eq!(envelope.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_response_creation() {
        let request_payload = TestPayload {
            message: "request".to_string(),
            count: 1,
        };

        let response_payload = TestPayload {
            message: "response".to_string(),
            count: 2,
        };

        let request = MessageEnvelope::new_with_correlation_id(
            "test_request",
            &request_payload,
            "test-correlation".to_string(),
        ).unwrap();

        let response = request.create_response("test_response", &response_payload).unwrap();

        assert_eq!(response.operation, "test_response");
        assert_eq!(response.correlation_id, request.correlation_id);

        let extracted: TestPayload = response.extract_payload().unwrap();
        assert_eq!(extracted, response_payload);
    }

    #[test]
    fn test_headers_and_auth() {
        let payload = TestPayload {
            message: "test".to_string(),
            count: 42,
        };

        let mut auth_headers = HashMap::new();
        auth_headers.insert("Authorization".to_string(), "Bearer token123".to_string());

        let envelope = MessageEnvelope::new("test_operation", &payload)
            .unwrap()
            .with_auth_headers(auth_headers)
            .with_header("Custom-Header".to_string(), "custom-value".to_string());

        assert!(envelope.headers.is_some());
        let headers = envelope.headers.unwrap();
        assert_eq!(headers.get("Authorization"), Some(&"Bearer token123".to_string()));
        assert_eq!(headers.get("Custom-Header"), Some(&"custom-value".to_string()));
    }
}
`;
}

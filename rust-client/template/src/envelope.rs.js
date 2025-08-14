/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ({ asyncapi, params }) {
    return (
        <File name="envelope.rs">
            {`//! Message envelope for consistent NATS message format

use crate::auth::{AuthCredentials, generate_auth_headers};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// MessageEnvelope for consistent message format across NATS operations
/// This matches the format expected by the server implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Unique message identifier
    pub id: String,
    /// Operation name from AsyncAPI spec
    pub operation: String,
    /// Message payload as JSON value
    pub payload: serde_json::Value,
    /// ISO 8601 timestamp when message was created
    pub timestamp: String,
    /// Optional correlation ID for request/reply patterns
    pub correlation_id: Option<String>,
    /// Optional headers for additional metadata
    pub headers: Option<HashMap<String, String>>,
}

impl MessageEnvelope {
    /// Create a new message envelope with generated ID and current timestamp
    pub fn new<T: Serialize>(operation: &str, payload: T) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            operation: operation.to_string(),
            payload: serde_json::to_value(payload)?,
            timestamp: chrono::Utc::now().to_rfc3339(),
            correlation_id: None,
            headers: None,
        })
    }

    /// Create a new message envelope with a specific correlation ID
    pub fn new_with_correlation_id<T: Serialize>(
        operation: &str,
        payload: T,
        correlation_id: String,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            operation: operation.to_string(),
            payload: serde_json::to_value(payload)?,
            timestamp: chrono::Utc::now().to_rfc3339(),
            correlation_id: Some(correlation_id),
            headers: None,
        })
    }

    /// Add headers to the envelope
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Add a single header to the envelope
    pub fn with_header(mut self, key: String, value: String) -> Self {
        if let Some(ref mut headers) = self.headers {
            headers.insert(key, value);
        } else {
            let mut headers = HashMap::new();
            headers.insert(key, value);
            self.headers = Some(headers);
        }
        self
    }

    /// Add authentication headers to the envelope
    pub fn with_auth_headers(mut self, auth: &AuthCredentials) -> Self {
        let auth_headers = generate_auth_headers(auth);
        if !auth_headers.is_empty() {
            if let Some(ref mut headers) = self.headers {
                headers.extend(auth_headers);
            } else {
                self.headers = Some(auth_headers);
            }
        }
        self
    }

    /// Create a new message envelope with authentication headers
    pub fn new_with_auth<T: Serialize>(
        operation: &str,
        payload: T,
        auth: &AuthCredentials,
    ) -> Result<Self, serde_json::Error> {
        let envelope = Self::new(operation, payload)?;
        Ok(envelope.with_auth_headers(auth))
    }

    /// Create a new message envelope with correlation ID and authentication headers
    pub fn new_with_correlation_id_and_auth<T: Serialize>(
        operation: &str,
        payload: T,
        correlation_id: String,
        auth: &AuthCredentials,
    ) -> Result<Self, serde_json::Error> {
        let envelope = Self::new_with_correlation_id(operation, payload, correlation_id)?;
        Ok(envelope.with_auth_headers(auth))
    }

    /// Convert the envelope to bytes for NATS transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Parse envelope from bytes received from NATS
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Extract the payload as a specific type
    pub fn extract_payload<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.payload.clone())
    }

    /// Get the correlation ID if present
    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
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

        assert_eq!(envelope.correlation_id(), Some(correlation_id.as_str()));
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
}
`}
        </File>
    );
};

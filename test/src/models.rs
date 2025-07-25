//! Strongly-typed message models generated from AsyncAPI specification
//!
//! This module provides type-safe message structures that ensure:
//! - **Compile-time validation**: Invalid message structures are caught at build time
//! - **Automatic serialization**: Messages are seamlessly converted to/from JSON
//! - **Schema compliance**: All messages match the AsyncAPI specification exactly
//! - **IDE support**: Full autocomplete and type checking for message fields
//!
//! ## Design Philosophy
//!
//! These models are designed to be:
//! - **Immutable by default**: Prevents accidental modification of message data
//! - **Clone-friendly**: Efficient copying for message routing and processing
//! - **Debug-enabled**: Easy troubleshooting with automatic debug formatting
//! - **Serde-compatible**: Seamless JSON serialization for transport layers
//!
//! ## Usage Patterns
//!
//! ```no-run
//! use crate::models::*;
//! use uuid::Uuid;
//! use chrono::Utc;
//!
//! // Create a new message with type safety
//! let signup_request = UserSignup {
//!     id: Uuid::new_v4(),
//!     username: "johndoe".to_string(),
//!     email: "john@example.com".to_string(),
//!     created_at: Utc::now(),
//!     // Compiler ensures all required fields are provided
//! };
//!
//! // Automatic JSON serialization
//! let json_payload = serde_json::to_string(&signup_request)?;
//!
//! // Type-safe deserialization with validation
//! let parsed_message: UserSignup = serde_json::from_str(&json_payload)?;
//! ```

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

/// Standard message envelope for all AsyncAPI messages
///
/// This envelope provides a consistent structure for all messages sent through the system,
/// enabling better correlation, error handling, and observability.
///
/// ## Usage
///
/// ```no-run
/// use crate::models::*;
/// use uuid::Uuid;
///
/// // Create an envelope for a request
/// let envelope = MessageEnvelope::new("sendChatMessage", chat_message)
///     .with_correlation_id(Uuid::new_v4().to_string())
///     .with_channel("chatMessages");
///
/// // Create an error response
/// let error_envelope = MessageEnvelope::error_response(
///     "sendChatMessage_response",
///     "VALIDATION_ERROR",
///     "Invalid message format",
///     Some("correlation-id-123")
/// );
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// AsyncAPI operation ID
    pub operation: String,
    /// Correlation ID for request/response patterns
    pub id: Option<String>,
    /// Optional channel context
    pub channel: Option<String>,
    /// Message payload (any serializable type)
    pub payload: serde_json::Value,
    /// ISO 8601 timestamp
    pub timestamp: Option<String>,
    /// Error information if applicable
    pub error: Option<MessageError>,
}

/// Error information for failed operations
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            operation: operation.to_string(),
            id: None,
            channel: None,
            payload: serde_json::to_value(payload)?,
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
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

    /// Create an error response envelope
    pub fn error_response(
        operation: &str,
        error_code: &str,
        error_message: &str,
        correlation_id: Option<String>,
    ) -> Self {
        Self {
            operation: operation.to_string(),
            id: correlation_id,
            channel: None,
            payload: serde_json::Value::Null,
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
            error: Some(MessageError {
                code: error_code.to_string(),
                message: error_message.to_string(),
            }),
        }
    }

    /// Set the correlation ID for this envelope
    pub fn with_correlation_id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the channel for this envelope
    pub fn with_channel(mut self, channel: String) -> Self {
        self.channel = Some(channel);
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
        self.id.as_deref()
    }

    /// Create a response envelope with the same correlation ID
    pub fn create_response<T: Serialize>(
        &self,
        response_operation: &str,
        payload: T,
    ) -> Result<Self, serde_json::Error> {
        let mut response = Self::new(response_operation, payload)?;
        response.id = self.id.clone();
        response.channel = self.channel.clone();
        Ok(response)
    }
}

/// Base trait for all AsyncAPI messages providing runtime type information
///
/// This trait enables:
/// - **Dynamic message routing**: Route messages based on their type at runtime
/// - **Channel identification**: Determine which channel a message belongs to
/// - **Logging and monitoring**: Track message types for observability
/// - **Protocol abstraction**: Handle different message types uniformly
pub trait AsyncApiMessage {
    /// Returns the message type identifier as defined in the AsyncAPI specification
    ///
    /// This is used for:
    /// - Message routing and dispatch
    /// - Logging and monitoring
    /// - Protocol-level message identification
    fn message_type(&self) -> &'static str;

    /// Returns the primary channel this message is associated with
    ///
    /// Used for:
    /// - Default routing when channel is not explicitly specified
    /// - Message categorization and organization
    /// - Channel-based access control and filtering
    fn channel(&self) -> &'static str;
}

/// Chat message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Unique message identifier
    pub message_id: uuid::Uuid,
    /// Chat room identifier
    pub room_id: String,
    /// Message sender identifier
    pub user_id: uuid::Uuid,
    /// Sender's display name
    pub username: String,
    /// Message content
    pub content: String,
    /// Type of message
    pub message_type: ChatMessageMessageTypeEnum,
    /// Message timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// ID of message being replied to
    pub reply_to: Option<uuid::Uuid>,
}

/// Message delivery confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDelivered {
    /// ID of the delivered message
    pub message_id: uuid::Uuid,
    /// Chat room identifier
    pub room_id: String,
    /// Delivery timestamp
    pub delivered_at: chrono::DateTime<chrono::Utc>,
    /// Delivery status
    pub status: MessageDeliveredStatusEnum,
    /// Error message if delivery failed
    pub error: Option<String>,
}

/// Profile update request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileUpdateRequest {
    /// Unique request identifier for correlation
    pub request_id: uuid::Uuid,
    /// Fields to update
    pub updates: ProfileUpdateRequestUpdates,
    /// Request timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Profile update response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileUpdateResponse {
    /// Correlates with the request
    pub request_id: uuid::Uuid,
    /// Whether the update was successful
    pub success: bool,
    /// List of successfully updated fields
    pub updated_fields: Option<Vec<String>>,
    /// Validation or processing errors
    pub errors: Option<Vec<serde_json::Value>>,
    /// User profile information
    pub profile: Option<ProfileUpdateResponseProfile>,
    /// Response timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Type of message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatMessageMessageTypeEnum {
    Text,
    Image,
    File,
    System,
}

/// Delivery status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageDeliveredStatusEnum {
    Delivered,
    Failed,
    Pending,
}

/// Fields to update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileUpdateRequestUpdates {
    /// User's display name
    pub display_name: Option<String>,
    /// User biography
    pub bio: Option<String>,
    /// Avatar image URL
    pub avatar: Option<String>,
}

/// User profile information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileUpdateResponseProfile {
    /// User identifier
    pub user_id: uuid::Uuid,
    /// Unique username
    pub username: String,
    /// Display name
    pub display_name: String,
    /// User biography
    pub bio: Option<String>,
    /// Avatar image URL
    pub avatar: Option<String>,
    /// Account creation date
    pub joined_at: chrono::DateTime<chrono::Utc>,
    /// Last activity timestamp
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    /// Current online status
    pub is_online: bool,
}


impl AsyncApiMessage for ChatMessage {
    fn message_type(&self) -> &'static str {
        "ChatMessage"
    }

    fn channel(&self) -> &'static str {
        "0"
    }
}
impl AsyncApiMessage for MessageDelivered {
    fn message_type(&self) -> &'static str {
        "MessageDelivered"
    }

    fn channel(&self) -> &'static str {
        "0"
    }
}
impl AsyncApiMessage for ProfileUpdateRequest {
    fn message_type(&self) -> &'static str {
        "ProfileUpdateRequest"
    }

    fn channel(&self) -> &'static str {
        "1"
    }
}
impl AsyncApiMessage for ProfileUpdateResponse {
    fn message_type(&self) -> &'static str {
        "ProfileUpdateResponse"
    }

    fn channel(&self) -> &'static str {
        "1"
    }
}
/// collections message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collections {
    pub data: serde_json::Value,
}

impl AsyncApiMessage for Collections {
    fn message_type(&self) -> &'static str {
        "collections"
    }

    fn channel(&self) -> &'static str {
        "default"
    }
}
/// _meta message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub data: serde_json::Value,
}

impl AsyncApiMessage for Meta {
    fn message_type(&self) -> &'static str {
        "_meta"
    }

    fn channel(&self) -> &'static str {
        "default"
    }
}



import { File } from '@asyncapi/generator-react-sdk';

export default function transportFile({ asyncapi, params }) {
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async_std' : 'tokio';

    return (
        <File name="src/transport.rs">
            {`//! Transport layer abstractions for AsyncAPI clients
//!
//! This module defines the core traits that all protocol implementations must implement,
//! providing a clean separation between protocol-agnostic client logic and protocol-specific
//! transport implementations.

use crate::config::Config;
use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Core transport trait that all protocol implementations must implement
///
/// This trait defines the essential operations that any AsyncAPI transport must support:
/// connection management, message publishing, subscription handling, and connection status.
#[async_trait]
pub trait AsyncApiTransport: Send + Sync {
    /// Connect to the server using the provided configuration
    ///
    /// # Arguments
    /// * \`config\` - Configuration containing connection parameters
    ///
    /// # Returns
    /// * \`Ok(())\` if connection succeeds
    /// * \`Err(Error)\` if connection fails
    async fn connect(&mut self, config: &Config) -> Result<()>;

    /// Disconnect from the server and clean up resources
    ///
    /// # Returns
    /// * \`Ok(())\` if disconnection succeeds
    /// * \`Err(Error)\` if disconnection fails
    async fn disconnect(&mut self) -> Result<()>;

    /// Publish a message to the specified topic/channel
    ///
    /// # Arguments
    /// * \`topic\` - The topic or channel to publish to
    /// * \`payload\` - The message payload as bytes
    /// * \`headers\` - Optional message headers
    ///
    /// # Returns
    /// * \`Ok(())\` if message is published successfully
    /// * \`Err(Error)\` if publishing fails
    async fn publish(
        &self,
        topic: &str,
        payload: &[u8],
        headers: Option<&HashMap<String, String>>,
    ) -> Result<()>;

    /// Subscribe to messages from the specified topic/channel
    ///
    /// # Arguments
    /// * \`topic\` - The topic or channel to subscribe to
    ///
    /// # Returns
    /// * \`Ok(())\` if subscription succeeds
    /// * \`Err(Error)\` if subscription fails
    async fn subscribe(&mut self, topic: &str) -> Result<()>;

    /// Unsubscribe from the specified topic/channel
    ///
    /// # Arguments
    /// * \`topic\` - The topic or channel to unsubscribe from
    ///
    /// # Returns
    /// * \`Ok(())\` if unsubscription succeeds
    /// * \`Err(Error)\` if unsubscription fails
    async fn unsubscribe(&mut self, topic: &str) -> Result<()>;

    /// Check if the transport is currently connected
    ///
    /// # Returns
    /// * \`true\` if connected
    /// * \`false\` if not connected
    async fn is_connected(&self) -> bool;

    /// Start the message processing loop
    ///
    /// This method should start listening for incoming messages and handle them
    /// according to the transport's protocol requirements.
    ///
    /// # Returns
    /// * \`Ok(())\` if message processing starts successfully
    /// * \`Err(Error)\` if starting fails
    async fn start_message_loop(&mut self) -> Result<()>;

    /// Stop the message processing loop
    ///
    /// # Returns
    /// * \`Ok(())\` if message processing stops successfully
    /// * \`Err(Error)\` if stopping fails
    async fn stop_message_loop(&mut self) -> Result<()>;

    /// Get the protocol name for this transport
    ///
    /// # Returns
    /// * Protocol name as a string (e.g., "mqtt", "kafka", "amqp")
    fn protocol(&self) -> &'static str;
}

/// Trait for handling incoming messages
///
/// Implementations of this trait define how to process messages received
/// from the transport layer.
#[async_trait]
pub trait MessageHandler<T>: Send + Sync {
    /// Handle an incoming message
    ///
    /// # Arguments
    /// * \`message\` - The received message
    ///
    /// # Returns
    /// * \`Ok(())\` if message is handled successfully
    /// * \`Err(Error)\` if handling fails
    async fn handle_message(&self, message: T) -> Result<()>;
}

/// Trait for message serialization and deserialization
///
/// This trait abstracts the serialization format (JSON, MessagePack, etc.)
/// from the transport implementation.
pub trait MessageSerializer: Send + Sync {
    /// Serialize a message to bytes
    ///
    /// # Arguments
    /// * \`message\` - The message to serialize
    ///
    /// # Returns
    /// * \`Ok(Vec<u8>)\` containing the serialized message
    /// * \`Err(Error)\` if serialization fails
    fn serialize<T: Serialize>(&self, message: &T) -> Result<Vec<u8>>;

    /// Deserialize bytes to a message
    ///
    /// # Arguments
    /// * \`data\` - The bytes to deserialize
    ///
    /// # Returns
    /// * \`Ok(T)\` containing the deserialized message
    /// * \`Err(Error)\` if deserialization fails
    fn deserialize<T: for<'de> Deserialize<'de>>(&self, data: &[u8]) -> Result<T>;

    /// Get the content type for this serializer
    ///
    /// # Returns
    /// * Content type string (e.g., "application/json")
    fn content_type(&self) -> &'static str;
}

/// Factory trait for creating transport instances
///
/// This trait provides a way to create transport instances based on
/// protocol configuration.
pub trait TransportFactory: Send + Sync {
    /// Create a transport instance for the specified protocol
    ///
    /// # Arguments
    /// * \`protocol\` - The protocol name (e.g., "mqtt", "kafka")
    /// * \`config\` - Configuration for the transport
    ///
    /// # Returns
    /// * \`Ok(Box<dyn AsyncApiTransport>)\` containing the transport
    /// * \`Err(Error)\` if creation fails
    fn create_transport(
        &self,
        protocol: &str,
        config: &Config,
    ) -> Result<Box<dyn AsyncApiTransport>>;

    /// List supported protocols
    ///
    /// # Returns
    /// * Vector of supported protocol names
    fn supported_protocols(&self) -> Vec<&'static str>;
}

/// Message envelope containing metadata and payload
///
/// This structure wraps messages with additional metadata that may be
/// useful for routing, tracing, or other cross-cutting concerns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageEnvelope<T> {
    /// Message payload
    pub payload: T,
    /// Message metadata
    pub metadata: MessageMetadata,
}

/// Message metadata
///
/// Contains information about the message that is not part of the
/// business payload but may be useful for processing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageMetadata {
    /// Message ID
    pub id: Option<String>,
    /// Topic or channel the message was received from
    pub topic: String,
    /// Timestamp when message was received
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Content type of the message
    pub content_type: Option<String>,
    /// Correlation ID for request-response patterns
    pub correlation_id: Option<String>,
    /// Reply-to address for request-response patterns
    pub reply_to: Option<String>,
    /// Custom headers
    pub headers: HashMap<String, String>,
}

impl Default for MessageMetadata {
    fn default() -> Self {
        Self {
            id: None,
            topic: String::new(),
            timestamp: Some(chrono::Utc::now()),
            content_type: Some("application/json".to_string()),
            correlation_id: None,
            reply_to: None,
            headers: HashMap::new(),
        }
    }
}

impl<T> MessageEnvelope<T> {
    /// Create a new message envelope
    ///
    /// # Arguments
    /// * \`payload\` - The message payload
    /// * \`topic\` - The topic the message is for
    ///
    /// # Returns
    /// * New message envelope with default metadata
    pub fn new(payload: T, topic: impl Into<String>) -> Self {
        Self {
            payload,
            metadata: MessageMetadata {
                topic: topic.into(),
                ..Default::default()
            },
        }
    }

    /// Create a new message envelope with custom metadata
    ///
    /// # Arguments
    /// * \`payload\` - The message payload
    /// * \`metadata\` - The message metadata
    ///
    /// # Returns
    /// * New message envelope
    pub fn with_metadata(payload: T, metadata: MessageMetadata) -> Self {
        Self { payload, metadata }
    }
}

/// Default JSON serializer implementation
pub struct JsonSerializer;

impl MessageSerializer for JsonSerializer {
    fn serialize<T: Serialize>(&self, message: &T) -> Result<Vec<u8>> {
        serde_json::to_vec(message).map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    fn deserialize<T: for<'de> Deserialize<'de>>(&self, data: &[u8]) -> Result<T> {
        serde_json::from_slice(data).map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    fn content_type(&self) -> &'static str {
        "application/json"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_envelope_creation() {
        let payload = "test message";
        let envelope = MessageEnvelope::new(payload, "test/topic");

        assert_eq!(envelope.payload, "test message");
        assert_eq!(envelope.metadata.topic, "test/topic");
        assert!(envelope.metadata.timestamp.is_some());
    }

    #[test]
    fn test_json_serializer() {
        let serializer = JsonSerializer;
        let message = "test";

        let serialized = serializer.serialize(&message).unwrap();
        let deserialized: String = serializer.deserialize(&serialized).unwrap();

        assert_eq!(message, deserialized);
        assert_eq!(serializer.content_type(), "application/json");
    }
}
`}
        </File>
    );
}

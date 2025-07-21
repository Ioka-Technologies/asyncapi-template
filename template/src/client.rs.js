import { File } from '@asyncapi/generator-react-sdk';
import { rustFunctionName, rustStructName } from '../helpers/rust-helpers';

export default function clientFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async_std' : 'tokio';
    const generateModels = params.generateModels !== false;
    const generateSubscribers = params.generateSubscribers !== false;
    const generatePublishers = params.generatePublishers !== false;

    return (
        <File name="src/client.rs">
            {`//! Main client implementation for AsyncAPI
//!
//! This module provides a trait-based client architecture that abstracts
//! protocol-specific details behind clean interfaces. The client uses
//! dependency injection to work with any transport implementation.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::transport::{AsyncApiTransport, MessageSerializer, JsonSerializer, MessageEnvelope, MessageMetadata};
use crate::transport::factory::create_transport;
${generateModels ? 'use crate::models::*;' : ''}
use std::sync::Arc;
use ${runtime === 'tokio' ? 'tokio::sync::RwLock' : 'async_std::sync::RwLock'};
use log::{debug, error, info, warn};
use serde::Serialize;
use std::collections::HashMap;

/// Message handler type for processing incoming messages
pub type MessageHandler<T> = Box<dyn Fn(T) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> + Send + Sync>;

/// Main AsyncAPI client with trait-based architecture
///
/// This client uses dependency injection to work with any transport implementation
/// that implements the AsyncApiTransport trait. This provides clean separation
/// between protocol-agnostic client logic and protocol-specific transport details.
pub struct Client {
    /// Transport implementation for the specific protocol
    transport: Box<dyn AsyncApiTransport>,
    /// Client configuration
    config: Arc<Config>,
    /// Message serializer for converting between Rust types and bytes
    serializer: Box<dyn MessageSerializer>,
    /// Connection state tracking
    is_running: Arc<RwLock<bool>>,
${generateModels ? '    /// Message handlers for processing incoming messages\n    message_handlers: Arc<RwLock<HashMap<String, MessageHandler<Message>>>>,' : ''}
}

impl Client {
    /// Create a new client with the given configuration
    ///
    /// This method creates a transport instance based on the protocol specified
    /// in the configuration and initializes the client with default settings.
    ///
    /// # Arguments
    /// * \`config\` - Configuration containing connection and protocol settings
    ///
    /// # Returns
    /// * \`Ok(Client)\` if creation succeeds
    /// * \`Err(Error)\` if transport creation fails
    pub fn new_with_config(config: Config) -> Result<Self> {
        let protocol = "${protocol}"; // This would be determined from config in a real implementation
        let transport = create_transport(protocol, &config)?;

        Ok(Self {
            transport,
            config: Arc::new(config),
            serializer: Box::new(JsonSerializer),
            is_running: Arc::new(RwLock::new(false)),
${generateModels ? '            message_handlers: Arc::new(RwLock::new(HashMap::new())),' : ''}
        })
    }

    /// Create a new client with custom transport and serializer
    ///
    /// This method allows for dependency injection of custom transport and
    /// serializer implementations, useful for testing or custom protocols.
    ///
    /// # Arguments
    /// * \`config\` - Configuration containing connection settings
    /// * \`transport\` - Custom transport implementation
    /// * \`serializer\` - Custom message serializer
    ///
    /// # Returns
    /// * New client instance
    pub fn new_with_transport(
        config: Config,
        transport: Box<dyn AsyncApiTransport>,
        serializer: Box<dyn MessageSerializer>,
    ) -> Self {
        Self {
            transport,
            config: Arc::new(config),
            serializer,
            is_running: Arc::new(RwLock::new(false)),
${generateModels ? '            message_handlers: Arc::new(RwLock::new(HashMap::new())),' : ''}
        }
    }

    /// Create a new client with default configuration
    ///
    /// # Returns
    /// * \`Ok(Client)\` if creation succeeds
    /// * \`Err(Error)\` if configuration loading or transport creation fails
    pub async fn new() -> Result<Self> {
        let config = Config::load().map_err(|e| Error::Config(e.to_string()))?;
        Self::new_with_config(config)
    }

    /// Connect to the server using the configured transport
    ///
    /// # Returns
    /// * \`Ok(())\` if connection succeeds
    /// * \`Err(Error)\` if connection fails
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to server: {}", self.config.server.url);

        self.transport.connect(&self.config).await?;
        *self.is_running.write().await = true;

        info!("Successfully connected to server");
        Ok(())
    }

    /// Disconnect from the server
    ///
    /// # Returns
    /// * \`Ok(())\` if disconnection succeeds
    /// * \`Err(Error)\` if disconnection fails
    pub async fn disconnect(&mut self) -> Result<()> {
        info!("Disconnecting from server");

        self.transport.disconnect().await?;
        *self.is_running.write().await = false;

        info!("Disconnected from server");
        Ok(())
    }

    /// Start the client and begin processing messages
    ///
    /// This method connects to the server and starts the message processing loop.
    ///
    /// # Returns
    /// * \`Ok(())\` if startup succeeds
    /// * \`Err(Error)\` if startup fails
    pub async fn start(&mut self) -> Result<()> {
        if self.is_connected().await {
            return Err(Error::Connection("Client is already running".to_string()));
        }

        self.connect().await?;
        self.transport.start_message_loop().await?;

        info!("Client started successfully");
        Ok(())
    }

    /// Stop the client and cleanup resources
    ///
    /// # Returns
    /// * \`Ok(())\` if shutdown succeeds
    /// * \`Err(Error)\` if shutdown fails
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping client");

        self.transport.stop_message_loop().await?;
        self.disconnect().await?;

        info!("Client stopped");
        Ok(())
    }

    /// Check if the client is connected
    ///
    /// # Returns
    /// * \`true\` if connected
    /// * \`false\` if not connected
    pub async fn is_connected(&self) -> bool {
        self.transport.is_connected().await
    }

${generatePublishers ? `    /// Publish a message to a topic
    ///
    /// This method serializes the message and publishes it to the specified topic
    /// using the configured transport.
    ///
    /// # Arguments
    /// * \`topic\` - The topic to publish to
    /// * \`message\` - The message to publish
    /// * \`headers\` - Optional message headers
    ///
    /// # Returns
    /// * \`Ok(())\` if publishing succeeds
    /// * \`Err(Error)\` if publishing fails
    pub async fn publish<T>(&self, topic: &str, message: &T) -> Result<()>
    where
        T: Serialize,
    {
        self.publish_with_headers(topic, message, None).await
    }

    /// Publish a message to a topic with custom headers
    ///
    /// # Arguments
    /// * \`topic\` - The topic to publish to
    /// * \`message\` - The message to publish
    /// * \`headers\` - Optional message headers
    ///
    /// # Returns
    /// * \`Ok(())\` if publishing succeeds
    /// * \`Err(Error)\` if publishing fails
    pub async fn publish_with_headers<T>(
        &self,
        topic: &str,
        message: &T,
        headers: Option<&HashMap<String, String>>,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let payload = self.serializer.serialize(message)?;

        self.transport.publish(topic, &payload, headers).await?;

        debug!("Published message to topic: {}", topic);
        Ok(())
    }

    /// Publish a message envelope
    ///
    /// This method publishes a message wrapped in an envelope with metadata.
    ///
    /// # Arguments
    /// * \`envelope\` - The message envelope to publish
    ///
    /// # Returns
    /// * \`Ok(())\` if publishing succeeds
    /// * \`Err(Error)\` if publishing fails
    pub async fn publish_envelope<T>(&self, envelope: &MessageEnvelope<T>) -> Result<()>
    where
        T: Serialize,
    {
        let headers = if envelope.metadata.headers.is_empty() {
            None
        } else {
            Some(&envelope.metadata.headers)
        };

        self.publish_with_headers(&envelope.metadata.topic, &envelope.payload, headers).await
    }` : ''}

${generateSubscribers ? `    /// Subscribe to messages from a topic
    ///
    /// # Arguments
    /// * \`topic\` - The topic to subscribe to
    ///
    /// # Returns
    /// * \`Ok(())\` if subscription succeeds
    /// * \`Err(Error)\` if subscription fails
    pub async fn subscribe(&mut self, topic: &str) -> Result<()> {
        self.transport.subscribe(topic).await?;
        info!("Subscribed to topic: {}", topic);
        Ok(())
    }

    /// Unsubscribe from a topic
    ///
    /// # Arguments
    /// * \`topic\` - The topic to unsubscribe from
    ///
    /// # Returns
    /// * \`Ok(())\` if unsubscription succeeds
    /// * \`Err(Error)\` if unsubscription fails
    pub async fn unsubscribe(&mut self, topic: &str) -> Result<()> {
        self.transport.unsubscribe(topic).await?;
        info!("Unsubscribed from topic: {}", topic);
        Ok(())
    }` : ''}

${generateModels ? `    /// Register a message handler for processing incoming messages
    ///
    /// # Arguments
    /// * \`handler\` - The message handler function
    pub async fn on_message<F>(&self, handler: F)
    where
        F: Fn(Message) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> + Send + Sync + 'static,
    {
        let mut handlers = self.message_handlers.write().await;
        handlers.insert("default".to_string(), Box::new(handler));
    }

    /// Register a message handler for a specific topic
    ///
    /// # Arguments
    /// * \`topic\` - The topic to handle messages for
    /// * \`handler\` - The message handler function
    pub async fn on_topic_message<F>(&self, topic: &str, handler: F)
    where
        F: Fn(Message) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> + Send + Sync + 'static,
    {
        let mut handlers = self.message_handlers.write().await;
        handlers.insert(topic.to_string(), Box::new(handler));
    }` : ''}

    /// Get the protocol name for this client
    ///
    /// # Returns
    /// * Protocol name as a string
    pub fn protocol(&self) -> &'static str {
        self.transport.protocol()
    }

    /// Get the content type used by the serializer
    ///
    /// # Returns
    /// * Content type string
    pub fn content_type(&self) -> &'static str {
        self.serializer.content_type()
    }

    /// Get a reference to the client configuration
    ///
    /// # Returns
    /// * Reference to the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}

/// Drop implementation for cleanup
impl Drop for Client {
    fn drop(&mut self) {
        // Cleanup is handled by the transport implementation
        debug!("Client dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let config = Config::default();
        let result = Client::new_with_config(config);
        assert!(result.is_ok());

        if let Ok(client) = result {
            assert_eq!(client.protocol(), "${protocol}");
            assert_eq!(client.content_type(), "application/json");
        }
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_client_connection_state() {
        let config = Config::default();
        let client = Client::new_with_config(config).unwrap();

        // Initially not connected
        assert!(!client.is_connected().await);
    }

    #[test]
    fn test_client_config_access() {
        let config = Config::default();
        let client = Client::new_with_config(config.clone()).unwrap();

        assert_eq!(client.config().server.url, config.server.url);
    }
}
`}
        </File>
    );
}

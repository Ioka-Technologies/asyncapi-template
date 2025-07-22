'use strict';

require('source-map-support/register');
var jsxRuntime = require('/Users/stevegraham/.nvm/versions/node/v20.0.0/lib/node_modules/@asyncapi/cli/node_modules/@asyncapi/generator-react-sdk/node_modules/react/cjs/react-jsx-runtime.production.min.js');

function AmqpTransport({
  asyncapi
}) {
  // Check if AMQP protocol is used
  const servers = asyncapi.servers();
  let hasAmqp = false;
  if (servers) {
    Object.entries(servers).forEach(([_name, server]) => {
      const protocol = server.protocol && server.protocol();
      if (protocol && ['amqp', 'amqps'].includes(protocol.toLowerCase())) {
        hasAmqp = true;
      }
    });
  }

  // Only generate file if AMQP is used
  if (!hasAmqp) {
    return null;
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "amqp.rs",
    children: `//! AMQP transport implementation

use async_trait::async_trait;
use lapin::{
    options::*, types::FieldTable, BasicProperties, Channel, Connection, ConnectionProperties,
    Consumer, ExchangeKind,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::StreamExt;

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

/// AMQP transport implementation
pub struct AmqpTransport {
    config: TransportConfig,
    connection: Option<Connection>,
    channel: Option<Channel>,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    subscriptions: Arc<RwLock<HashMap<String, String>>>, // queue_name -> routing_key
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl AmqpTransport {
    /// Create a new AMQP transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if config.protocol != "amqp" && config.protocol != "amqps" {
            return Err(AsyncApiError::new(
                format!("Invalid protocol for AMQP transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            ));
        }

        Ok(Self {
            config,
            connection: None,
            channel: None,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            message_handler: None,
            shutdown_tx: None,
        })
    }

    /// Set message handler for incoming messages
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Create AMQP connection URI
    fn create_connection_uri(&self) -> String {
        let scheme = if self.config.tls { "amqps" } else { "amqp" };
        let auth = if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            format!("{}:{}@", username, password)
        } else {
            String::new()
        };

        let vhost = self.config.additional_config
            .get("vhost")
            .map(|v| format!("/{}", v))
            .unwrap_or_else(|| "/".to_string());

        format!("{}://{}{}:{}{}", scheme, auth, self.config.host, self.config.port, vhost)
    }

    /// Get exchange name from configuration
    fn get_exchange_name(&self) -> String {
        self.config.additional_config
            .get("exchange")
            .cloned()
            .unwrap_or_else(|| "asyncapi".to_string())
    }

    /// Get exchange type from configuration
    fn get_exchange_type(&self) -> ExchangeKind {
        match self.config.additional_config
            .get("exchange_type")
            .map(|s| s.as_str())
            .unwrap_or("topic")
        {
            "direct" => ExchangeKind::Direct,
            "fanout" => ExchangeKind::Fanout,
            "headers" => ExchangeKind::Headers,
            _ => ExchangeKind::Topic,
        }
    }

    /// Start consuming messages from a queue
    async fn start_consumer(&mut self, queue_name: &str) -> AsyncApiResult<()> {
        let channel = self.channel.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "AMQP channel not available".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let consumer = channel
            .basic_consume(
                queue_name,
                &format!("asyncapi-consumer-{}", uuid::Uuid::new_v4()),
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to create AMQP consumer: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        let connection_state = Arc::clone(&self.connection_state);
        let stats = Arc::clone(&self.stats);
        let message_handler = self.message_handler.clone();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        tokio::spawn(async move {
            let mut consumer_stream = consumer;

            loop {
                tokio::select! {
                    delivery_result = consumer_stream.next() => {
                        match delivery_result {
                            Some(Ok(delivery)) => {
                                let mut stats = stats.write().await;
                                stats.messages_received += 1;
                                stats.bytes_received += delivery.data.len() as u64;
                                drop(stats);

                                if let Some(handler) = &message_handler {
                                    let mut headers = HashMap::new();

                                    // Add AMQP-specific metadata
                                    headers.insert("exchange".to_string(), delivery.exchange.to_string());
                                    headers.insert("routing_key".to_string(), delivery.routing_key.to_string());
                                    headers.insert("delivery_tag".to_string(), delivery.delivery_tag.to_string());
                                    headers.insert("redelivered".to_string(), delivery.redelivered.to_string());

                                    // Add message properties
                                    if let Some(properties) = &delivery.properties {
                                        if let Some(content_type) = &properties.content_type() {
                                            headers.insert("content_type".to_string(), content_type.to_string());
                                        }
                                        if let Some(content_encoding) = &properties.content_encoding() {
                                            headers.insert("content_encoding".to_string(), content_encoding.to_string());
                                        }
                                        if let Some(message_id) = &properties.message_id() {
                                            headers.insert("message_id".to_string(), message_id.to_string());
                                        }
                                        if let Some(correlation_id) = &properties.correlation_id() {
                                            headers.insert("correlation_id".to_string(), correlation_id.to_string());
                                        }
                                        if let Some(reply_to) = &properties.reply_to() {
                                            headers.insert("reply_to".to_string(), reply_to.to_string());
                                        }
                                        if let Some(user_id) = &properties.user_id() {
                                            headers.insert("user_id".to_string(), user_id.to_string());
                                        }
                                        if let Some(app_id) = &properties.app_id() {
                                            headers.insert("app_id".to_string(), app_id.to_string());
                                        }

                                        // Add custom headers
                                        if let Some(amqp_headers) = properties.headers() {
                                            for (key, value) in amqp_headers.iter() {
                                                if let Ok(value_str) = std::str::from_utf8(&value.to_string().as_bytes()) {
                                                    headers.insert(key.to_string(), value_str.to_string());
                                                }
                                            }
                                        }
                                    }

                                    let metadata = MessageMetadata {
                                        channel: delivery.routing_key.to_string(),
                                        operation: "receive".to_string(),
                                        content_type: delivery.properties
                                            .as_ref()
                                            .and_then(|p| p.content_type())
                                            .map(|ct| ct.to_string())
                                            .or_else(|| Some("application/octet-stream".to_string())),
                                        headers,
                                        timestamp: chrono::Utc::now(),
                                    };

                                    let transport_message = TransportMessage {
                                        metadata,
                                        payload: delivery.data.to_vec(),
                                    };

                                    if let Err(e) = handler.handle_message(transport_message).await {
                                        tracing::error!("Failed to handle AMQP message: {}", e);
                                        let mut stats = stats.write().await;
                                        stats.last_error = Some(e.to_string());
                                    }

                                    // Acknowledge the message
                                    if let Err(e) = delivery.ack(BasicAckOptions::default()).await {
                                        tracing::error!("Failed to acknowledge AMQP message: {}", e);
                                    }
                                }
                            }
                            Some(Err(e)) => {
                                tracing::error!("AMQP consumer error: {}", e);
                                let mut stats = stats.write().await;
                                stats.last_error = Some(e.to_string());
                            }
                            None => {
                                tracing::info!("AMQP consumer stream ended");
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("AMQP consumer shutdown requested");
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

#[async_trait]
impl Transport for AmqpTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        let connection_uri = self.create_connection_uri();
        let connection_properties = ConnectionProperties::default();

        let connection = Connection::connect(&connection_uri, connection_properties)
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to connect to AMQP broker: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        let channel = connection.create_channel().await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to create AMQP channel: {}", e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        // Declare exchange if configured
        let exchange_name = self.get_exchange_name();
        let exchange_type = self.get_exchange_type();

        channel
            .exchange_declare(
                &exchange_name,
                exchange_type,
                ExchangeDeclareOptions {
                    durable: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to declare AMQP exchange: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        self.connection = Some(connection);
        self.channel = Some(channel);

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        *self.connection_state.write().await = ConnectionState::Connected;
        tracing::info!("AMQP transport connected successfully");

        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        if let Some(channel) = &self.channel {
            if let Err(e) = channel.close(200, "Normal shutdown").await {
                tracing::warn!("Error closing AMQP channel: {}", e);
            }
        }

        if let Some(connection) = &self.connection {
            if let Err(e) = connection.close(200, "Normal shutdown").await {
                tracing::warn!("Error closing AMQP connection: {}", e);
            }
        }

        self.channel = None;
        self.connection = None;
        *self.connection_state.write().await = ConnectionState::Disconnected;

        tracing::info!("AMQP transport disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection_state
            .try_read()
            .map(|state| matches!(*state, ConnectionState::Connected))
            .unwrap_or(false)
            && self.connection.as_ref().map_or(false, |c| c.status().connected())
    }

    fn connection_state(&self) -> ConnectionState {
        self.connection_state
            .try_read()
            .map(|state| *state)
            .unwrap_or(ConnectionState::Disconnected)
    }

    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()> {
        let channel = self.channel.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "AMQP channel not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let exchange_name = self.get_exchange_name();
        let routing_key = &message.metadata.channel;

        // Create basic properties
        let mut properties = BasicProperties::default();

        if let Some(content_type) = &message.metadata.content_type {
            properties = properties.with_content_type(content_type.clone().into());
        }

        // Set properties from headers
        if let Some(message_id) = message.metadata.headers.get("message_id") {
            properties = properties.with_message_id(message_id.clone().into());
        }
        if let Some(correlation_id) = message.metadata.headers.get("correlation_id") {
            properties = properties.with_correlation_id(correlation_id.clone().into());
        }
        if let Some(reply_to) = message.metadata.headers.get("reply_to") {
            properties = properties.with_reply_to(reply_to.clone().into());
        }

        // Add custom headers
        let mut field_table = FieldTable::default();
        for (key, value) in &message.metadata.headers {
            if !["message_id", "correlation_id", "reply_to", "content_type"].contains(&key.as_str()) {
                field_table.insert(key.clone().into(), value.clone().into());
            }
        }
        if !field_table.is_empty() {
            properties = properties.with_headers(field_table);
        }

        channel
            .basic_publish(
                &exchange_name,
                routing_key,
                BasicPublishOptions::default(),
                &message.payload,
                properties,
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to publish AMQP message: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += message.payload.len() as u64;

        tracing::debug!("Published AMQP message to routing key: {}", routing_key);
        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let amqp_channel = self.channel.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "AMQP channel not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let exchange_name = self.get_exchange_name();
        let queue_name = format!("asyncapi-queue-{}", uuid::Uuid::new_v4());

        // Declare queue
        let queue = amqp_channel
            .queue_declare(
                &queue_name,
                QueueDeclareOptions {
                    auto_delete: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to declare AMQP queue: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        // Bind queue to exchange
        amqp_channel
            .queue_bind(
                &queue_name,
                &exchange_name,
                channel,
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to bind AMQP queue: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        // Start consuming
        self.start_consumer(&queue_name).await?;

        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.insert(queue_name, channel.to_string());

        tracing::info!("Subscribed to AMQP routing key: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let amqp_channel = self.channel.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "AMQP channel not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let mut subscriptions = self.subscriptions.write().await;
        let queue_to_remove = subscriptions
            .iter()
            .find(|(_, routing_key)| routing_key.as_str() == channel)
            .map(|(queue_name, _)| queue_name.clone());

        if let Some(queue_name) = queue_to_remove {
            // Delete the queue
            amqp_channel
                .queue_delete(&queue_name, QueueDeleteOptions::default())
                .await
                .map_err(|e| {
                    AsyncApiError::new(
                        format!("Failed to delete AMQP queue: {}", e),
                        ErrorCategory::Network,
                        Some(Box::new(e)),
                    )
                })?;

            subscriptions.remove(&queue_name);
        }

        tracing::info!("Unsubscribed from AMQP routing key: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // AMQP listening is handled by the consumer, which is started in subscribe()
        tracing::info!("AMQP transport is listening for messages");
        Ok(())
    }

    async fn stop_listening(&mut self) -> AsyncApiResult<()> {
        // Stop listening by disconnecting
        self.disconnect().await
    }

    fn get_stats(&self) -> TransportStats {
        self.stats.try_read()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }

    async fn health_check(&self) -> AsyncApiResult<bool> {
        Ok(self.is_connected())
    }

    fn protocol(&self) -> &str {
        &self.config.protocol
    }
}

impl Drop for AmqpTransport {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.try_send(());
        }
    }
}
`
  });
}

module.exports = AmqpTransport;
//# sourceMappingURL=amqp.rs.js.map

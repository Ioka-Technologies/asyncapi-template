/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function MqttTransport({ asyncapi }) {
    // Check if MQTT protocol is used
    const servers = asyncapi.servers();
    let hasMqtt = false;

    if (servers) {
        Object.entries(servers).forEach(([_name, server]) => {
            const protocol = server.protocol && typeof server.protocol === 'function' ? server.protocol() : server.protocol;
            if (protocol && typeof protocol === 'string' && ['mqtt', 'mqtts'].includes(protocol.toLowerCase())) {
                hasMqtt = true;
            }
        });
    }

    // Only generate file if MQTT is used
    if (!hasMqtt) {
        return null;
    }

    return (
        <File name="mqtt.rs">
            {`//! MQTT transport implementation

use async_trait::async_trait;
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

/// MQTT transport implementation
pub struct MqttTransport {
    config: TransportConfig,
    client: Option<AsyncClient>,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    subscriptions: Arc<RwLock<HashMap<String, QoS>>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl MqttTransport {
    /// Create a new MQTT transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if config.protocol != "mqtt" && config.protocol != "mqtts" {
            return Err(Box::new(AsyncApiError::new(
                format!("Invalid protocol for MQTT transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            )));
        }

        Ok(Self {
            config,
            client: None,
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

    /// Create MQTT options from configuration
    fn create_mqtt_options(&self) -> AsyncApiResult<MqttOptions> {
        let client_id = self.config.additional_config
            .get("client_id")
            .cloned()
            .unwrap_or_else(|| format!("asyncapi-client-{}", uuid::Uuid::new_v4()));

        let mut mqtt_options = MqttOptions::new(client_id, &self.config.host, self.config.port);

        // Set credentials if provided
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            mqtt_options.set_credentials(username, password);
        }

        // Configure TLS if enabled
        if self.config.tls {
            let tls_config = rumqttc::TlsConfiguration::Simple {
                ca: vec![],
                alpn: None,
                client_auth: None,
            };
            mqtt_options.set_transport(rumqttc::Transport::Tls(tls_config));
        }

        // Set keep alive interval
        if let Some(keep_alive) = self.config.additional_config
            .get("keep_alive")
            .and_then(|v| v.parse::<u64>().ok())
        {
            mqtt_options.set_keep_alive(Duration::from_secs(keep_alive));
        } else {
            mqtt_options.set_keep_alive(Duration::from_secs(60));
        }

        // Set clean session
        let clean_session = self.config.additional_config
            .get("clean_session")
            .map(|v| v.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);
        mqtt_options.set_clean_session(clean_session);

        // Set max packet size
        if let Some(max_packet_size) = self.config.additional_config
            .get("max_packet_size")
            .and_then(|v| v.parse::<usize>().ok())
        {
            mqtt_options.set_max_packet_size(max_packet_size, max_packet_size);
        }

        Ok(mqtt_options)
    }

    /// Start the MQTT event loop
    async fn start_event_loop(&mut self, mut event_loop: EventLoop) -> AsyncApiResult<()> {
        let connection_state = Arc::clone(&self.connection_state);
        let stats_arc = Arc::clone(&self.stats);
        let message_handler = self.message_handler.clone();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = event_loop.poll() => {
                        match event {
                            Ok(Event::Incoming(Packet::Publish(publish))) => {
                                {
                                    let mut stats = stats_arc.write().await;
                                    stats.messages_received += 1;
                                    stats.bytes_received += publish.payload.len() as u64;
                                }

                                if let Some(handler) = &message_handler {
                                    let mut headers = HashMap::new();
                                    headers.insert("topic".to_string(), publish.topic.clone());
                                    headers.insert("qos".to_string(), format!("{:?}", publish.qos));
                                    headers.insert("retain".to_string(), publish.retain.to_string());
                                    headers.insert("dup".to_string(), publish.dup.to_string());

                                    let metadata = MessageMetadata {
                                        content_type: Some("application/octet-stream".to_string()),
                                        headers,
                                        priority: None,
                                        ttl: None,
                                        reply_to: None,
                                        operation: "mqtt_message".to_string(),
                                        correlation_id: uuid::Uuid::new_v4(),
                                        source_transport: Some(uuid::Uuid::new_v4()), // TODO: Use actual transport UUID
                                    };

                                    if let Err(e) = handler.handle_message(&publish.payload, &metadata).await {
                                        let mut error_stats = stats_arc.write().await;
                                        error_stats.last_error = Some(e.to_string());
                                    }
                                }
                            }
                            Ok(Event::Incoming(Packet::ConnAck(_))) => {
                                *connection_state.write().await = ConnectionState::Connected;
                                tracing::info!("MQTT connection established");
                            }
                            Ok(Event::Incoming(Packet::Disconnect)) => {
                                *connection_state.write().await = ConnectionState::Disconnected;
                                tracing::info!("MQTT disconnected");
                            }
                            Ok(Event::Outgoing(_)) => {
                                // Handle outgoing packets if needed
                            }
                            Err(e) => {
                                tracing::error!("MQTT event loop error: {}", e);
                                *connection_state.write().await = ConnectionState::Failed;
                                let mut stats = stats_arc.write().await;
                                stats.last_error = Some(e.to_string());
                                break;
                            }
                            _ => {
                                // Handle other packet types
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("MQTT event loop shutdown requested");
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

#[async_trait]
impl Transport for MqttTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        let mqtt_options = self.create_mqtt_options()?;
        let (client, event_loop) = AsyncClient::new(mqtt_options, 10);

        self.client = Some(client);

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        // Start event loop
        self.start_event_loop(event_loop).await?;

        tracing::info!("MQTT transport connection initiated");
        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        if let Some(client) = &self.client {
            if let Err(e) = client.disconnect().await {
                tracing::warn!("Error disconnecting MQTT client: {}", e);
            }
        }

        self.client = None;
        *self.connection_state.write().await = ConnectionState::Disconnected;

        tracing::info!("MQTT transport disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection_state
            .try_read()
            .map(|state| matches!(*state, ConnectionState::Connected))
            .unwrap_or(false)
    }

    fn connection_state(&self) -> ConnectionState {
        self.connection_state
            .try_read()
            .map(|state| *state)
            .unwrap_or(ConnectionState::Disconnected)
    }

    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()> {
        let client = self.client.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "MQTT client not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let topic = message.metadata.headers
            .get("topic")
            .ok_or_else(|| {
                AsyncApiError::new(
                    "Topic not specified in message headers".to_string(),
                    ErrorCategory::Validation,
                    None,
                )
            })?;
        let qos = message.metadata.headers
            .get("qos")
            .and_then(|q| match q.as_str() {
                "0" => Some(QoS::AtMostOnce),
                "1" => Some(QoS::AtLeastOnce),
                "2" => Some(QoS::ExactlyOnce),
                _ => None,
            })
            .unwrap_or(QoS::AtMostOnce);

        let retain = message.metadata.headers
            .get("retain")
            .map(|r| r.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let payload_len = message.payload.len();

        client
            .publish(topic, qos, retain, message.payload)
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to publish MQTT message: {e}"),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += payload_len as u64;

        tracing::debug!("Published MQTT message to topic: {}", topic);
        Ok(())
    }

    async fn respond(&mut self, response: TransportMessage, original_metadata: &MessageMetadata) -> AsyncApiResult<()> {
        // For MQTT, responses are typically published to a response topic
        // We can use the reply_to field from the original metadata or construct a response topic
        let response_topic = if let Some(reply_to) = &original_metadata.reply_to {
            reply_to.clone()
        } else {
            // Construct response topic from original topic
            let original_topic = original_metadata.headers.get("topic")
                .unwrap_or(&original_metadata.operation);
            format!("{}/response", original_topic)
        };

        let client = self.client.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "MQTT client not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        // Use QoS from original message or default to AtLeastOnce for responses
        let qos = original_metadata.headers
            .get("qos")
            .and_then(|q| match q.as_str() {
                "0" => Some(QoS::AtMostOnce),
                "1" => Some(QoS::AtLeastOnce),
                "2" => Some(QoS::ExactlyOnce),
                _ => None,
            })
            .unwrap_or(QoS::AtLeastOnce);

        let retain = false; // Responses typically shouldn't be retained

        let payload_len = response.payload.len();

        tracing::debug!(
            "Sending MQTT response to topic: {}, correlation_id: {}",
            response_topic,
            original_metadata.correlation_id
        );

        client
            .publish(&response_topic, qos, retain, response.payload)
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to publish MQTT response: {e}"),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += payload_len as u64;

        tracing::debug!(
            "Successfully sent MQTT response to topic: {}, correlation_id: {}",
            response_topic,
            original_metadata.correlation_id
        );

        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let client = self.client.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "MQTT client not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let qos = QoS::AtMostOnce; // Default QoS, could be configurable

        client.subscribe(channel, qos).await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to subscribe to MQTT topic: {e}"),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.insert(channel.to_string(), qos);

        tracing::info!("Subscribed to MQTT topic: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let client = self.client.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "MQTT client not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        client.unsubscribe(channel).await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to unsubscribe from MQTT topic: {e}"),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.remove(channel);

        tracing::info!("Unsubscribed from MQTT topic: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // MQTT listening is handled by the event loop, which is started in connect()
        tracing::info!("MQTT transport is listening for messages");
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

impl Drop for MqttTransport {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.try_send(());
        }
    }
}
`}
        </File>
    );
}

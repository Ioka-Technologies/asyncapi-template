/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function KafkaTransport({ asyncapi }) {
    // Check if Kafka protocol is used
    const servers = asyncapi.servers();
    let hasKafka = false;

    if (servers) {
        Object.entries(servers).forEach(([_name, server]) => {
            const protocol = server.protocol && server.protocol();
            if (protocol && protocol.toLowerCase() === 'kafka') {
                hasKafka = true;
            }
        });
    }

    // Only generate file if Kafka is used
    if (!hasKafka) {
        return null;
    }

    return (
        <File name="kafka.rs">
            {`//! Kafka transport implementation

use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::{Message, TopicPartitionList};
use rdkafka::message::Headers;
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

/// Kafka transport implementation
pub struct KafkaTransport {
    config: TransportConfig,
    producer: Option<FutureProducer>,
    consumer: Option<StreamConsumer>,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    subscriptions: Arc<RwLock<Vec<String>>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl KafkaTransport {
    /// Create a new Kafka transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if config.protocol != "kafka" {
            return Err(Box::new(AsyncApiError::new(
                format!("Invalid protocol for Kafka transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            )));
        }

        Ok(Self {
            config,
            producer: None,
            consumer: None,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            subscriptions: Arc::new(RwLock::new(Vec::new())),
            message_handler: None,
            shutdown_tx: None,
        })
    }

    /// Set message handler for incoming messages
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Create Kafka client configuration
    fn create_client_config(&self) -> ClientConfig {
        let mut config = ClientConfig::new();

        // Set bootstrap servers
        let bootstrap_servers = format!("{}:{}", self.config.host, self.config.port);
        config.set("bootstrap.servers", &bootstrap_servers);

        // Set security configuration
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            config.set("security.protocol", "SASL_PLAINTEXT");
            config.set("sasl.mechanism", "PLAIN");
            config.set("sasl.username", username);
            config.set("sasl.password", password);
        }

        if self.config.tls {
            if self.config.username.is_some() {
                config.set("security.protocol", "SASL_SSL");
            } else {
                config.set("security.protocol", "SSL");
            }
        }

        // Set additional configuration
        for (key, value) in &self.config.additional_config {
            config.set(key, value);
        }

        // Set default configurations if not provided
        if !self.config.additional_config.contains_key("client.id") {
            let client_id = format!("asyncapi-client-{}", uuid::Uuid::new_v4());
            config.set("client.id", &client_id);
        }

        config
    }

    /// Create producer configuration
    fn create_producer_config(&self) -> ClientConfig {
        let mut config = self.create_client_config();

        // Producer-specific settings
        config.set("message.timeout.ms", "30000");
        config.set("queue.buffering.max.messages", "100000");
        config.set("queue.buffering.max.ms", "1000");
        config.set("batch.num.messages", "1000");

        // Set compression if specified
        if let Some(compression) = self.config.additional_config.get("compression.type") {
            config.set("compression.type", compression);
        } else {
            config.set("compression.type", "snappy");
        }

        config
    }

    /// Create consumer configuration
    fn create_consumer_config(&self) -> ClientConfig {
        let mut config = self.create_client_config();

        // Consumer-specific settings
        let group_id = self.config.additional_config
            .get("group.id")
            .cloned()
            .unwrap_or_else(|| format!("asyncapi-group-{}", uuid::Uuid::new_v4()));
        config.set("group.id", &group_id);

        config.set("enable.auto.commit", "true");
        config.set("auto.commit.interval.ms", "5000");
        config.set("session.timeout.ms", "30000");
        config.set("heartbeat.interval.ms", "10000");

        // Set auto offset reset
        let auto_offset_reset = self.config.additional_config
            .get("auto.offset.reset")
            .map(|s| s.as_str())
            .unwrap_or("latest");
        config.set("auto.offset.reset", auto_offset_reset);

        config
    }

    /// Start consuming messages
    async fn start_consumer_loop(&mut self) -> AsyncApiResult<()> {
        if let Some(consumer) = self.consumer.take() {
            let _connection_state = Arc::clone(&self.connection_state);
            let stats = Arc::clone(&self.stats);
            let message_handler = self.message_handler.clone();
            let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
            self.shutdown_tx = Some(shutdown_tx);

            Self::spawn_consumer_task(consumer, stats, message_handler, shutdown_rx);
        }

        Ok(())
    }

    /// Spawn the consumer task
    fn spawn_consumer_task(
        consumer: StreamConsumer,
        stats: Arc<RwLock<TransportStats>>,
        message_handler: Option<Arc<dyn MessageHandler>>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        tokio::spawn(async move {
                let mut message_stream = consumer.stream();

                loop {
                    tokio::select! {
                        message_result = message_stream.next() => {
                            match message_result {
                                Some(Ok(message)) => {
                                    let mut stats_guard = stats.write().await;
                                    stats_guard.messages_received += 1;
                                    if let Some(payload) = message.payload() {
                                        stats_guard.bytes_received += payload.len() as u64;
                                    }
                                    drop(stats_guard);

                                    if let Some(handler) = &message_handler {
                                        let topic = message.topic().to_string();
                                        let partition = message.partition();
                                        let offset = message.offset();

                                        let mut headers = HashMap::new();
                                        headers.insert("partition".to_string(), partition.to_string());
                                        headers.insert("offset".to_string(), offset.to_string());

                                        if let Some(key) = message.key() {
                                            if let Ok(key_str) = std::str::from_utf8(key) {
                                                headers.insert("key".to_string(), key_str.to_string());
                                            }
                                        }

                                        if let Some(kafka_headers) = message.headers() {
                                            for header in kafka_headers.iter() {
                                                if let Some(value_bytes) = header.value {
                                                    if let Ok(value_str) = std::str::from_utf8(value_bytes) {
                                                        headers.insert(header.key.to_string(), value_str.to_string());
                                                    }
                                                }
                                            }
                                        }

                                        let metadata = MessageMetadata {
                                            content_type: Some("application/octet-stream".to_string()),
                                            headers,
                                            priority: None,
                                            ttl: None,
                                            reply_to: None,
                                        };

                                        let payload = message.payload().unwrap_or(&[]).to_vec();
                                        let transport_message = TransportMessage { metadata, payload };

                                        if let Err(e) = handler.handle_message(transport_message).await {
                                            tracing::error!("Failed to handle Kafka message: {}", e);
                                            if let Ok(mut error_stats) = stats.try_write() {
                                                error_stats.last_error = Some(e.to_string());
                                            }
                                        }
                                    }
                                }
                                Some(Err(e)) => {
                                    tracing::error!("Kafka consumer error: {}", e);
                                    let mut stats_guard = stats.write().await;
                                    stats_guard.last_error = Some(e.to_string());
                                }
                                None => {
                                    tracing::info!("Kafka consumer stream ended");
                                    break;
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            tracing::info!("Kafka consumer shutdown requested");
                            break;
                        }
                    }
                }
            });
    }
}

#[async_trait]
impl Transport for KafkaTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        // Create producer
        let producer_config = self.create_producer_config();
        let producer: FutureProducer = producer_config.create().map_err(|e| {
            AsyncApiError::new(
                format!("Failed to create Kafka producer: {}", e),
                ErrorCategory::Configuration,
                Some(Box::new(e)),
            )
        })?;

        // Create consumer
        let consumer_config = self.create_consumer_config();
        let consumer: StreamConsumer = consumer_config.create().map_err(|e| {
            AsyncApiError::new(
                format!("Failed to create Kafka consumer: {}", e),
                ErrorCategory::Configuration,
                Some(Box::new(e)),
            )
        })?;

        self.producer = Some(producer);
        self.consumer = Some(consumer);

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        // Start consumer loop
        self.start_consumer_loop().await?;

        *self.connection_state.write().await = ConnectionState::Connected;
        tracing::info!("Kafka transport connected successfully");

        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        self.producer = None;
        self.consumer = None;
        *self.connection_state.write().await = ConnectionState::Disconnected;

        tracing::info!("Kafka transport disconnected");
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
        let producer = self.producer.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "Kafka producer not connected".to_string(),
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

        let mut record = FutureRecord::to(topic)
            .payload(&message.payload);

        // Set key if provided
        if let Some(key) = message.metadata.headers.get("key") {
            record = record.key(key);
        }

        // Set partition if provided
        if let Some(partition_str) = message.metadata.headers.get("partition") {
            if let Ok(partition) = partition_str.parse::<i32>() {
                record = record.partition(partition);
            }
        }

        // Set headers
        let mut kafka_headers = rdkafka::message::OwnedHeaders::new();
        for (key, value) in &message.metadata.headers {
            if key != "key" && key != "partition" {
                kafka_headers = kafka_headers.insert(rdkafka::message::Header {
                    key,
                    value: Some(value),
                });
            }
        }
        record = record.headers(kafka_headers);

        // Send message with timeout
        let timeout = Duration::from_secs(30);
        producer.send(record, timeout).await.map_err(|(e, _)| {
            AsyncApiError::new(
                format!("Failed to send Kafka message: {}", e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += message.payload.len() as u64;

        tracing::debug!("Sent Kafka message to topic: {}", topic);
        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let consumer = self.consumer.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "Kafka consumer not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        consumer.subscribe(&[channel]).map_err(|e| {
            AsyncApiError::new(
                format!("Failed to subscribe to Kafka topic {}: {}", channel, e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let mut subscriptions = self.subscriptions.write().await;
        if !subscriptions.contains(&channel.to_string()) {
            subscriptions.push(channel.to_string());
        }

        tracing::info!("Subscribed to Kafka topic: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let consumer = self.consumer.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "Kafka consumer not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        // Kafka doesn't have direct unsubscribe for individual topics
        // We need to resubscribe to remaining topics
        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.retain(|topic| topic != channel);

        if subscriptions.is_empty() {
            consumer.unsubscribe();
        } else {
            let topics: Vec<&str> = subscriptions.iter().map(|s| s.as_str()).collect();
            consumer.subscribe(&topics).map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to resubscribe to Kafka topics: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;
        }

        tracing::info!("Unsubscribed from Kafka topic: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // Kafka listening is handled by the consumer loop, which is started in connect()
        tracing::info!("Kafka transport is listening for messages");
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
        // For Kafka, we can check if producer and consumer are available
        Ok(self.is_connected() && self.producer.is_some() && self.consumer.is_some())
    }

    fn protocol(&self) -> &str {
        &self.config.protocol
    }
}

impl Drop for KafkaTransport {
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

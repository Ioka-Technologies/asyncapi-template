/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function NatsTransportRs({ asyncapi, params }) {
    // Helper functions for Rust identifier generation
    function toRustIdentifier(str) {
        if (!str) return 'unknown';
        let identifier = str
            .replace(/[^a-zA-Z0-9_]/g, '_')
            .replace(/^[0-9]/, '_$&')
            .replace(/_+/g, '_')
            .replace(/^_+|_+$/g, '');
        if (/^[0-9]/.test(identifier)) {
            identifier = 'item_' + identifier;
        }
        if (!identifier) {
            identifier = 'unknown';
        }
        const rustKeywords = [
            'as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern',
            'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match',
            'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self',
            'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe',
            'use', 'where', 'while', 'async', 'await', 'dyn'
        ];
        if (rustKeywords.includes(identifier)) {
            identifier = identifier + '_';
        }
        return identifier;
    }

    function toRustFieldName(str) {
        if (!str) return 'unknown';
        const identifier = toRustIdentifier(str);
        return identifier
            .replace(/([A-Z])/g, '_$1')
            .toLowerCase()
            .replace(/^_/, '')
            .replace(/_+/g, '_');
    }

    return (
        <File name="nats.rs">
            {`//! NATS transport implementation
//!
//! This module provides a NATS transport that:
//! - Supports both request/reply and pub/sub patterns
//! - Uses MessageEnvelope format for all messages
//! - Provides JWT authentication support

use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::transport::{MessageHandler, MessageMetadata, Transport, TransportConfig, TransportMessage, TransportStats, ConnectionState};
use async_nats::{Client, Message};
use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// NATS transport configuration
#[derive(Debug, Clone)]
pub struct NatsTransportConfig {
    /// NATS server URLs
    pub servers: Vec<String>,
    /// Connection name for monitoring
    pub name: Option<String>,
    /// JWT Authentication
    pub credentials_file: Option<String>,
    /// Connection timeout
    pub connect_timeout: Option<Duration>,
}

impl Default for NatsTransportConfig {
    fn default() -> Self {
        Self {
            servers: vec!["nats://localhost:4222".to_string()],
            name: Some("asyncapi-service".to_string()),
            credentials_file: None,
            connect_timeout: Some(Duration::from_secs(5)),
        }
    }
}

/// MessageEnvelope for consistent message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub id: String,
    pub operation: String,
    pub payload: Value,
    pub timestamp: String,
    pub correlation_id: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

impl MessageEnvelope {
    pub fn new_with_id(operation: &str, payload: Value) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            operation: operation.to_string(),
            payload,
            timestamp: chrono::Utc::now().to_rfc3339(),
            correlation_id: None,
            headers: None,
        })
    }

    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = Some(headers);
        self
    }

    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }
}

/// NATS transport implementation
pub struct NatsTransport {
    config: NatsTransportConfig,
    client: Option<Client>,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
    listening: Arc<RwLock<bool>>,
    subscribers: Arc<RwLock<Vec<async_nats::Subscriber>>>,
}

impl NatsTransport {
    /// Create a new NATS transport
    pub fn new(config: NatsTransportConfig) -> AsyncApiResult<Self> {
        Ok(Self {
            config,
            client: None,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            message_handler: None,
            listening: Arc::new(RwLock::new(false)),
            subscribers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Set the message handler for this transport
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Create NATS transport from TransportConfig
    pub fn from_transport_config(transport_config: &TransportConfig) -> AsyncApiResult<Self> {
        let mut config = NatsTransportConfig::default();

        // Build server URL
        let protocol = if transport_config.tls { "nats+tls" } else { "nats" };
        let server_url = format!("{}://{}:{}", protocol, transport_config.host, transport_config.port);
        config.servers = vec![server_url];

        // Extract NATS-specific configuration from additional_config
        if let Some(creds_file) = transport_config.additional_config.get("credentials_file") {
            config.credentials_file = Some(creds_file.clone());
        }

        if let Some(name) = transport_config.additional_config.get("name") {
            config.name = Some(name.clone());
        }

        Self::new(config)
    }

    /// Create authenticated NATS client
    async fn create_authenticated_client(&self) -> AsyncApiResult<Client> {
        debug!("Creating authenticated NATS client");

        let mut connect_options = async_nats::ConnectOptions::new();

        // Set connection name if provided
        if let Some(name) = &self.config.name {
            connect_options = connect_options.name(name);
        }

        // Configure timeouts
        if let Some(timeout) = self.config.connect_timeout {
            connect_options = connect_options.connection_timeout(timeout);
        }

        // Configure JWT authentication
        if let Some(creds_file) = &self.config.credentials_file {
            debug!("Using JWT credentials file: {}", creds_file);
            connect_options = connect_options.credentials_file(creds_file).await
                .map_err(|e| Box::new(AsyncApiError::Authentication {
                    message: format!("Failed to load credentials file: {}", e),
                    auth_method: "credentials_file".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Security,
                        false,
                    ),
                    source: Some(Box::new(e)),
                }))?;
        }

        // Connect to NATS servers
        let servers: Vec<async_nats::ServerAddr> = self.config.servers.iter()
            .map(|s| s.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Invalid server address: {}", e),
                protocol: "nats".to_string(),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Configuration,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?;

        let client = connect_options.connect(servers).await
                .map_err(|e| Box::new(AsyncApiError::Protocol {
                    message: format!("Failed to connect to NATS servers: {}", e),
                    protocol: "nats".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Network,
                        true,
                    ),
                    source: Some(Box::new(e)),
                }))?;

        info!("Successfully connected to NATS servers: {:?}", self.config.servers);
        Ok(client)
    }

    /// Extract channel from message metadata
    fn extract_channel_from_message(&self, message: &TransportMessage) -> AsyncApiResult<String> {
        // Try to get channel from headers first
        if let Some(channel) = message.metadata.headers.get("channel") {
            return Ok(channel.clone());
        }

        // Try to extract from operation if it follows channel.operation pattern
        let parts: Vec<&str> = message.metadata.operation.split('.').collect();
        if parts.len() >= 2 {
            Ok(parts[0].to_string())
        } else {
            // Default to operation name as channel
            Ok(message.metadata.operation.clone())
        }
    }

    /// Ensure payload is MessageEnvelope format
    fn ensure_message_envelope(&self, message: &TransportMessage) -> AsyncApiResult<MessageEnvelope> {
        // Try to parse existing envelope
        if let Ok(mut envelope) = serde_json::from_slice::<MessageEnvelope>(&message.payload) {
            // Update envelope with transport metadata
            envelope = envelope.with_correlation_id(message.metadata.correlation_id.to_string());
            if let Some(headers) = envelope.headers.as_mut() {
                headers.extend(message.metadata.headers.clone());
            } else {
                envelope = envelope.with_headers(message.metadata.headers.clone());
            }
            Ok(envelope)
        } else {
            // Create new envelope if payload is not already wrapped
            let payload_value = serde_json::from_slice::<Value>(&message.payload)
                .map_err(|e| Box::new(AsyncApiError::Validation {
                    message: format!("Invalid JSON payload: {}", e),
                    field: Some("payload".to_string()),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Validation,
                        false,
                    ),
                    source: Some(Box::new(e)),
                }))?;

            Ok(MessageEnvelope::new_with_id(&message.metadata.operation, payload_value)
                .map_err(|e| Box::new(AsyncApiError::Validation {
                    message: format!("Failed to create MessageEnvelope: {}", e),
                    field: Some("payload".to_string()),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Validation,
                        false,
                    ),
                    source: Some(Box::new(e)),
                }))?
                .with_correlation_id(message.metadata.correlation_id.to_string())
                .with_headers(message.metadata.headers.clone()))
        }
    }

    /// Start subscription handler for a channel
    async fn start_subscription_handler(
        &self,
        mut subscriber: async_nats::Subscriber,
        channel: String,
    ) -> AsyncApiResult<()> {
        let handler = self.message_handler.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            debug!("Starting subscription handler for channel: {}", channel);

            while let Some(message) = subscriber.next().await {
                if let Some(handler) = &handler {
                    // Parse incoming NATS message as MessageEnvelope
                    let envelope = match serde_json::from_slice::<MessageEnvelope>(&message.payload) {
                        Ok(envelope) => envelope,
                        Err(e) => {
                            warn!("Received non-MessageEnvelope format on {}: {}", message.subject, e);
                            continue;
                        }
                    };

                    // Extract metadata from envelope
                    let correlation_id = envelope.correlation_id()
                        .and_then(|id| id.parse().ok())
                        .unwrap_or_else(Uuid::new_v4);

                    let mut headers = envelope.headers.clone().unwrap_or_default();
                    headers.insert("subject".to_string(), message.subject.to_string());
                    headers.insert("channel".to_string(), channel.clone());

                    let metadata = MessageMetadata {
                        operation: envelope.operation.clone(),
                        headers,
                        correlation_id,
                        content_type: Some("application/json".to_string()),
                        reply_to: message.reply.as_ref().map(|s| s.to_string()),
                        priority: None,
                        ttl: None,
                    };

                    // Create TransportMessage for handler
                    let transport_message = TransportMessage {
                        metadata,
                        payload: serde_json::to_vec(&envelope).unwrap(),
                    };

                    // Process through handler
                    match handler.handle_message(&transport_message.payload, &transport_message.metadata).await {
                        Ok(()) => {
                            // Update stats
                            let mut stats = stats.write().await;
                            stats.messages_received += 1;
                        }
                        Err(e) => {
                            warn!("Error handling message on {}: {}", message.subject, e);
                            // Update error stats
                            let mut stats = stats.write().await;
                            stats.messages_received += 1;
                            stats.last_error = Some(format!("Handler error: {}", e));
                        }
                    }
                } else {
                    warn!("No message handler configured for channel: {}", channel);
                }
            }

            debug!("Subscription handler stopped for channel: {}", channel);
        });

        Ok(())
    }
}

#[async_trait]
impl Transport for NatsTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        info!("Connecting to NATS servers: {:?}", self.config.servers);

        *self.connection_state.write().await = ConnectionState::Connecting;

        // Create authenticated NATS client
        let client = self.create_authenticated_client().await?;
        self.client = Some(client);

        *self.connection_state.write().await = ConnectionState::Connected;

        info!("Successfully connected to NATS");
        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        info!("Disconnecting from NATS");

        *self.connection_state.write().await = ConnectionState::Disconnected;
        *self.listening.write().await = false;

        // Close all subscribers
        let mut subscribers = self.subscribers.write().await;
        subscribers.clear();

        // Close client connection
        if let Some(_client) = self.client.take() {
            debug!("NATS client connection closed");
        }

        info!("Disconnected from NATS");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        if let Ok(state) = self.connection_state.try_read() {
            matches!(*state, ConnectionState::Connected)
        } else {
            false
        }
    }

    fn connection_state(&self) -> ConnectionState {
        if let Ok(state) = self.connection_state.try_read() {
            *state
        } else {
            ConnectionState::Disconnected
        }
    }

    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()> {
        let client = self.client.as_ref().ok_or_else(|| Box::new(AsyncApiError::Protocol {
            message: "NATS client not connected".to_string(),
            protocol: "nats".to_string(),
            metadata: crate::errors::ErrorMetadata::new(
                crate::errors::ErrorSeverity::High,
                crate::errors::ErrorCategory::Network,
                false,
            ),
            source: None,
        }))?;

        // Extract channel and operation from metadata
        let channel = self.extract_channel_from_message(&message)?;
        let operation = &message.metadata.operation;
        let subject = format!("{}.{}", channel, operation);

        // Ensure payload is MessageEnvelope format
        let envelope = self.ensure_message_envelope(&message)?;
        let payload = serde_json::to_vec(&envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize MessageEnvelope: {}", e),
                field: Some("payload".to_string()),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Validation,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?;

        // Determine if this is a request/reply operation
        if message.metadata.reply_to.is_some() {
            // This is a request - use NATS request/reply
            debug!("Sending request to subject: {}", subject);
            let _response = client.request(subject, payload.into()).await
                .map_err(|e| Box::new(AsyncApiError::Protocol {
                    message: format!("NATS request failed: {}", e),
                    protocol: "nats".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Network,
                        true,
                    ),
                    source: Some(Box::new(e)),
                }))?;

            // Update stats
            let mut stats = self.stats.write().await;
            stats.messages_sent += 1;
            stats.messages_received += 1;
        } else {
            // This is a publish - use NATS publish
            debug!("Publishing message to subject: {}", subject);
            client.publish(subject, payload.into()).await
                .map_err(|e| Box::new(AsyncApiError::Protocol {
                    message: format!("NATS publish failed: {}", e),
                    protocol: "nats".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Network,
                        true,
                    ),
                    source: Some(Box::new(e)),
                }))?;

            // Update stats
            let mut stats = self.stats.write().await;
            stats.messages_sent += 1;
        }

        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let client = self.client.as_ref().ok_or_else(|| Box::new(AsyncApiError::Protocol {
            message: "NATS client not connected".to_string(),
            protocol: "nats".to_string(),
            metadata: crate::errors::ErrorMetadata::new(
                crate::errors::ErrorSeverity::High,
                crate::errors::ErrorCategory::Network,
                false,
            ),
            source: None,
        }))?;

        // Subscribe to all operations for this channel using wildcard
        let subject_pattern = format!("{}.*", channel);

        debug!("Subscribing to channel pattern: {}", subject_pattern);

        let subscriber = client.subscribe(subject_pattern).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to subscribe to channel '{}': {}", channel, e),
                protocol: "nats".to_string(),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Network,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?;

        // Store subscriber (note: Subscriber doesn't implement Clone, so we can't store it)
        // self.subscribers.write().await.push(subscriber);

        // Start subscription handler for this channel
        self.start_subscription_handler(subscriber, channel.to_string()).await?;

        info!("Subscribed to channel: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        // NATS subscriptions are automatically cleaned up when dropped
        info!("Unsubscribed from channel: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        *self.listening.write().await = true;
        info!("Started listening for NATS messages");
        Ok(())
    }

    async fn stop_listening(&mut self) -> AsyncApiResult<()> {
        *self.listening.write().await = false;
        info!("Stopped listening for NATS messages");
        Ok(())
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
        "nats"
    }
}

/// Helper function to create NATS transport from config
pub fn create_nats_transport(config: &TransportConfig) -> AsyncApiResult<Box<dyn Transport>> {
    let transport = NatsTransport::from_transport_config(config)?;
    Ok(Box::new(transport))
}
`}
        </File>
    );
}

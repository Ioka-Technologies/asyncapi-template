/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function TransportMod({ asyncapi }) {
    // Detect protocols from servers
    const servers = asyncapi.servers();
    const protocols = new Set();

    if (servers) {
        Object.entries(servers).forEach(([_name, server]) => {
            const protocol = server.protocol && typeof server.protocol === 'function' ? server.protocol() : server.protocol;
            if (protocol) {
                protocols.add(protocol.toLowerCase());
            }
        });
    }

    // Generate module declarations based on detected protocols
    let moduleDeclarations = `pub mod factory;

// Protocol-specific modules with feature guards`;

    if (protocols.has('http') || protocols.has('https')) {
        moduleDeclarations += `
pub mod http;`;
    }

    if (protocols.has('mqtt') || protocols.has('mqtts')) {
        moduleDeclarations += `
#[cfg(feature = "mqtt")]
pub mod mqtt;`;
    }

    if (protocols.has('kafka')) {
        moduleDeclarations += `
#[cfg(feature = "kafka")]
pub mod kafka;`;
    }

    if (protocols.has('amqp') || protocols.has('amqps')) {
        moduleDeclarations += `
#[cfg(feature = "amqp")]
pub mod amqp;`;
    }

    if (protocols.has('ws') || protocols.has('wss') || protocols.has('websocket')) {
        moduleDeclarations += `
pub mod websocket;`;
    }

    if (protocols.has('nats') || protocols.has('nats+tls')) {
        moduleDeclarations += `
#[cfg(feature = "nats")]
pub mod nats;`;
    }

    return (
        <File name="mod.rs">
            {`//! Transport layer abstraction for AsyncAPI protocols
//!
//! This module provides a unified interface for different transport protocols
//! including MQTT, Kafka, AMQP, WebSocket, and HTTP.
#![allow(dead_code, unused_imports)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::errors::{AsyncApiResult, AsyncApiError};
use crate::models::{AsyncApiMessage, MessageEnvelope};

${moduleDeclarations}

/// Transport configuration for different protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub additional_config: HashMap<String, String>,
}

/// Connection state for transport implementations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

/// Transport statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_attempts: u64,
    pub last_error: Option<String>,
}

/// Transport-specific metadata that doesn't belong in business messages
#[derive(Debug, Clone)]
pub struct MessageMetadata {
    /// MIME type for payload serialization (e.g., "application/json", "application/protobuf")
    pub content_type: Option<String>,
    /// Transport-specific headers (routing keys, protocol headers, etc.)
    pub headers: HashMap<String, String>,
    /// Message priority for queuing systems (0-255, higher = more priority)
    pub priority: Option<u8>,
    /// Time-to-live in milliseconds for message expiration
    pub ttl: Option<u64>,
    /// Reply-to address for response routing (queue names, callback URLs)
    pub reply_to: Option<String>,
    /// Operation name for routing to appropriate handler
    pub operation: String,
    /// Correlation ID for request/response tracking
    pub correlation_id: uuid::Uuid,
}

/// Transport message wrapper
#[derive(Debug, Clone)]
pub struct TransportMessage {
    pub metadata: MessageMetadata,
    pub payload: Vec<u8>,
}

/// Trait for transport implementations
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to the transport
    async fn connect(&mut self) -> AsyncApiResult<()>;

    /// Disconnect from the transport
    async fn disconnect(&mut self) -> AsyncApiResult<()>;

    /// Check if transport is connected
    fn is_connected(&self) -> bool;

    /// Get current connection state
    fn connection_state(&self) -> ConnectionState;

    /// Send a message through the transport
    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()>;

    /// Subscribe to a channel/topic
    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()>;

    /// Unsubscribe from a channel/topic
    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()>;

    /// Start listening for messages (non-blocking)
    async fn start_listening(&mut self) -> AsyncApiResult<()>;

    /// Stop listening for messages
    async fn stop_listening(&mut self) -> AsyncApiResult<()>;

    /// Get transport statistics
    fn get_stats(&self) -> TransportStats;

    /// Health check for the transport
    async fn health_check(&self) -> AsyncApiResult<bool>;

    /// Get protocol name
    fn protocol(&self) -> &str;
}

/// Message handler trait for processing incoming messages
#[async_trait]
pub trait MessageHandler: Send + Sync {
    async fn handle_message(&self, payload: &[u8], metadata: &MessageMetadata) -> AsyncApiResult<()>;
}

/// Transport manager for coordinating multiple transports
pub struct TransportManager {
    transports: Arc<RwLock<HashMap<String, Box<dyn Transport>>>>,
    handlers: Arc<RwLock<HashMap<String, Arc<dyn MessageHandler>>>>,
    stats: Arc<RwLock<HashMap<String, TransportStats>>>,
    middleware: Arc<RwLock<crate::middleware::MiddlewarePipeline>>,
}

impl std::fmt::Debug for TransportManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportManager")
            .field("transports", &"<trait objects>")
            .field("handlers", &"<trait objects>")
            .field("stats", &"<stats>")
            .finish()
    }
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new() -> Self {
        Self {
            transports: Arc::new(RwLock::new(HashMap::new())),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
            middleware: Arc::new(RwLock::new(crate::middleware::MiddlewarePipeline::default())),
        }
    }

    /// Create a new transport manager with middleware
    pub fn new_with_middleware(middleware: Arc<RwLock<crate::middleware::MiddlewarePipeline>>) -> Self {
        Self {
            transports: Arc::new(RwLock::new(HashMap::new())),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
            middleware: middleware.clone(),
        }
    }

    /// Add a transport to the manager
    pub async fn add_transport(&self, name: String, transport: Box<dyn Transport>) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        let protocol = transport.protocol().to_string();
        transports.insert(name.clone(), transport);

        // Initialize stats
        let mut stats = self.stats.write().await;
        stats.insert(name.clone(), TransportStats::default());

        tracing::info!("Added {} transport: {}", protocol, name);
        Ok(())
    }

    /// Create a transport with the given configuration and use this TransportManager as the handler
    /// This method leverages the TransportManager's MessageHandler implementation and registered operation handlers
    pub async fn create_transport_with_config(&self, name: String, config: TransportConfig) -> AsyncApiResult<()> {
        tracing::debug!(
            name = %name,
            protocol = %config.protocol,
            host = %config.host,
            port = config.port,
            "Creating transport with TransportManager as handler"
        );

        // Validate configuration first
        crate::transport::factory::TransportFactory::validate_config(&config)?;

        // Create a self-reference for the handler
        // We need to create an Arc<Self> to pass as the MessageHandler
        let self_handler: Arc<dyn MessageHandler> = Arc::new(TransportManagerHandler {
            transport_manager: Arc::new(TransportManagerRef {
                transports: self.transports.clone(),
                handlers: self.handlers.clone(),
                stats: self.stats.clone(),
                middleware: self.middleware.clone(),
            }),
        });

        // Create transport using factory with this TransportManager as the handler
        let transport = crate::transport::factory::TransportFactory::create_transport_with_handler(
            config.clone(),
            Some(self_handler),
        )?;

        // Add the transport to our collection
        self.add_transport(name.clone(), transport).await?;

        tracing::info!(
            name = %name,
            protocol = %config.protocol,
            "Successfully created and registered transport with TransportManager as handler"
        );

        Ok(())
    }

    /// Remove a transport from the manager
    pub async fn remove_transport(&self, name: &str) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        if let Some(mut transport) = transports.remove(name) {
            transport.disconnect().await?;
        }

        let mut stats = self.stats.write().await;
        stats.remove(name);

        tracing::info!("Removed transport: {}", name);
        Ok(())
    }

    /// Register a message handler for a channel
    pub async fn register_handler(&self, channel: String, handler: Arc<dyn MessageHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.insert(channel.clone(), handler);
        tracing::info!("Registered handler for channel: {}", channel);
    }

    /// Handle incoming message by routing directly to channel handler
    /// This replaces the router/RouterIntegration layer with direct routing
    /// Now supports MessageEnvelope format for incoming messages
    /// Processes messages through middleware pipeline before routing to handlers
    pub async fn handle_message(&self, message: TransportMessage) -> AsyncApiResult<()> {
        // Process message through middleware pipeline if configured
        let middleware_guard = self.middleware.read().await;

        let processed_payload = {
            let middleware = &*middleware_guard;

            // Try to parse the incoming message as MessageEnvelope to get context
            let (correlation_id, headers, channel, operation) = match serde_json::from_slice::<MessageEnvelope>(&message.payload) {
                Ok(envelope) => {
                    let correlation_id = envelope.correlation_id()
                        .and_then(|id| id.parse().ok())
                        .unwrap_or_else(uuid::Uuid::new_v4);
                    let channel = envelope.channel.clone().unwrap_or_else(|| "default".to_string());
                    let operation = envelope.operation.clone();
                    let headers = envelope.headers.clone();
                    (correlation_id, headers, channel, operation)
                }
                Err(_) => {
                    let correlation_id = message.metadata.headers.get("correlation_id")
                        .and_then(|id| id.parse().ok())
                        .unwrap_or_else(uuid::Uuid::new_v4);
                    (correlation_id, None, "default".to_string(), "unknown".to_string())
                }
            };

            // Create middleware context
            let mut middleware_context = crate::middleware::MiddlewareContext::new(&channel, &operation)
                .with_metadata("correlation_id", &correlation_id.to_string());

            if let Some(ref headers) = headers {
                for (key, value) in headers.iter() {
                    middleware_context = middleware_context.with_metadata(&key.to_lowercase(), value);
                }
            }

            tracing::debug!(
                correlation_id = %correlation_id,
                channel = %channel,
                operation = %operation,
                payload_size = message.payload.len(),
                "Processing message through middleware pipeline"
            );

            // Process through middleware pipeline
            match middleware.process_inbound(&middleware_context, &message.payload).await {
                Ok(processed) => {
                    tracing::debug!(
                        correlation_id = %correlation_id,
                        channel = %channel,
                        operation = %operation,
                        original_size = message.payload.len(),
                        processed_size = processed.len(),
                        "Message successfully processed through middleware pipeline"
                    );
                    processed
                }
                Err(e) => {
                    return Err(e);
                }
            }
        };
        drop(middleware_guard); // Release the middleware lock

        // Try to parse the processed message as MessageEnvelope
        let (correlation_id, channel, operation) = match serde_json::from_slice::<MessageEnvelope>(&processed_payload) {
            Ok(envelope) => {
                // Successfully parsed as MessageEnvelope - extract metadata
                let correlation_id = envelope.correlation_id()
                    .and_then(|id| id.parse().ok())
                    .unwrap_or_else(uuid::Uuid::new_v4);

                let channel = envelope.channel
                    .clone()
                    .unwrap_or_else(|| "default".to_string());

                let operation = envelope.operation.clone();

                tracing::debug!(
                    correlation_id = %correlation_id,
                    channel = %channel,
                    operation = %operation,
                    payload_size = message.payload.len(),
                    "TransportManager parsed MessageEnvelope and routing to channel handler"
                );

                (correlation_id, channel, operation)
            }
            Err(_) => {
                // Fallback: if not a MessageEnvelope, we can't determine channel/operation
                // This should be rare since all messages should use MessageEnvelope format
                let correlation_id = message.metadata.headers.get("correlation_id")
                    .and_then(|id| id.parse().ok())
                    .unwrap_or_else(uuid::Uuid::new_v4);

                tracing::warn!(
                    correlation_id = %correlation_id,
                    payload_size = message.payload.len(),
                    "TransportManager received non-MessageEnvelope format - cannot determine channel/operation"
                );

                return Err(AsyncApiError::Validation {
                    message: "Message payload is not in MessageEnvelope format".to_string(),
                    field: Some("payload".to_string()),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Validation,
                        false,
                    )
                    .with_context("correlation_id", &correlation_id.to_string()),
                    source: None,
                }.into());
            }
        };

        // Look up handler by operation name
        let handlers = self.handlers.read().await;
        let handler = match handlers.get(&operation) {
            Some(handler) => {
                tracing::debug!(
                    correlation_id = %correlation_id,
                    channel = %channel,
                    "Found handler for channel"
                );
                handler.clone()
            }
            None => {
                tracing::warn!(
                    correlation_id = %correlation_id,
                    channel = %channel,
                    operation = %operation,
                    "No handler registered for channel"
                );
                return Err(AsyncApiError::Handler {
                    message: format!("No handler registered for channel: {channel}"),
                    handler_name: "TransportManager".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::Medium,
                        crate::errors::ErrorCategory::BusinessLogic,
                        false,
                    )
                    .with_context("correlation_id", &correlation_id.to_string())
                    .with_context("channel", &channel)
                    .with_context("operation", &operation),
                    source: None,
                }.into());
            }
        };
        drop(handlers); // Release the read lock

        // Create routed message with processed payload
        let mut routed_message = TransportMessage {
            metadata: message.metadata,
            payload: processed_payload,
        };

        // Ensure correlation ID is in headers
        if !routed_message.metadata.headers.contains_key("correlation_id") {
            routed_message.metadata.headers.insert("correlation_id".to_string(), correlation_id.to_string());
        }

        // Update metadata with extracted information
        routed_message.metadata.operation = operation.clone();
        routed_message.metadata.correlation_id = correlation_id;

        // Route directly to channel handler - no router layer needed!
        tracing::debug!(
            correlation_id = %correlation_id,
            channel = %channel,
            operation = %operation,
            "Routing message directly to channel handler"
        );

        match handler.handle_message(&routed_message.payload, &routed_message.metadata).await {
            Ok(()) => {
                tracing::debug!(
                    correlation_id = %correlation_id,
                    channel = %channel,
                    operation = %operation,
                    "Message successfully processed by channel handler"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    correlation_id = %correlation_id,
                    channel = %channel,
                    operation = %operation,
                    error = %e,
                    "Channel handler failed to process message"
                );
                Err(e)
            }
        }
    }

    /// Connect all transports
    pub async fn connect_all(&self) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        for (name, transport) in transports.iter_mut() {
            match transport.connect().await {
                Ok(_) => tracing::info!("Connected transport: {}", name),
                Err(e) => {
                    tracing::error!("Failed to connect transport {}: {}", name, e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Disconnect all transports
    pub async fn disconnect_all(&self) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        for (name, transport) in transports.iter_mut() {
            match transport.disconnect().await {
                Ok(_) => tracing::info!("Disconnected transport: {}", name),
                Err(e) => tracing::error!("Failed to disconnect transport {}: {}", name, e),
            }
        }
        Ok(())
    }

    /// Start listening on all transports
    pub async fn start_all(&self) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        for (name, transport) in transports.iter_mut() {
            match transport.start_listening().await {
                Ok(_) => tracing::info!("Started listening on transport: {}", name),
                Err(e) => {
                    tracing::error!("Failed to start listening on transport {}: {}", name, e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Stop listening on all transports
    pub async fn stop_all(&self) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        for (name, transport) in transports.iter_mut() {
            match transport.stop_listening().await {
                Ok(_) => tracing::info!("Stopped listening on transport: {}", name),
                Err(e) => tracing::error!("Failed to stop listening on transport {}: {}", name, e),
            }
        }
        Ok(())
    }

    /// Get aggregated statistics from all transports
    pub async fn get_all_stats(&self) -> HashMap<String, TransportStats> {
        let transports = self.transports.read().await;
        let mut all_stats = HashMap::new();

        for (name, transport) in transports.iter() {
            all_stats.insert(name.clone(), transport.get_stats());
        }

        all_stats
    }

    /// Send a MessageEnvelope through the appropriate transport
    /// This is the primary method for sending envelope-wrapped messages
    /// Uses retry logic since this is an outgoing message
    pub async fn send_envelope(&self, envelope: MessageEnvelope) -> AsyncApiResult<()> {
        tracing::debug!(
            operation = %envelope.operation,
            correlation_id = ?envelope.id,
            channel = ?envelope.channel,
            "Sending MessageEnvelope via transport with retry logic (outgoing message)"
        );

        // Serialize the envelope to JSON
        let payload = serde_json::to_vec(&envelope).map_err(|e| AsyncApiError::Validation {
            message: format!("Failed to serialize MessageEnvelope: {e}"),
            field: Some("envelope".to_string()),
            metadata: crate::errors::ErrorMetadata::new(
                crate::errors::ErrorSeverity::High,
                crate::errors::ErrorCategory::Validation,
                false,
            )
            .with_context("operation", &envelope.operation)
            .with_context("correlation_id", envelope.id.as_deref().unwrap_or("none"))
            .with_context("channel", envelope.channel.as_deref().unwrap_or("none")),
            source: Some(Box::new(e)),
        })?;

        // Create transport headers from envelope
        let mut headers = HashMap::new();
        if let Some(correlation_id) = &envelope.id {
            headers.insert("correlation_id".to_string(), correlation_id.clone());
        }
        headers.insert("content_type".to_string(), "application/json".to_string());
        if let Some(timestamp) = &envelope.timestamp {
            headers.insert("timestamp".to_string(), timestamp.clone());
        }

        // Create transport message
        let transport_message = TransportMessage {
            metadata: MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: headers.clone(),
                priority: None,
                ttl: None,
                reply_to: None,
                operation: envelope.operation.clone(),
                correlation_id: envelope.id.as_ref()
                    .and_then(|id| id.parse().ok())
                    .unwrap_or_else(uuid::Uuid::new_v4),
            },
            payload,
        };

        // Send via transport layer with retry logic for outgoing messages
        self.send_message_with_retry(transport_message).await
    }

    /// Send a strongly-typed message wrapped in MessageEnvelope
    pub async fn send_typed_message<T: serde::Serialize>(
        &self,
        operation: &str,
        payload: T,
        channel: Option<String>,
    ) -> AsyncApiResult<()> {
        // Create envelope with automatic correlation ID
        let envelope = MessageEnvelope::new_with_id(operation, payload).map_err(|e| {
            AsyncApiError::Validation {
                message: format!("Failed to create MessageEnvelope: {e}"),
                field: Some("payload".to_string()),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Validation,
                    false,
                )
                .with_context("operation", operation),
                source: Some(Box::new(e)),
            }
        })?;

        let envelope = if let Some(channel) = channel {
            envelope.with_channel(channel)
        } else {
            envelope
        };

        self.send_envelope(envelope).await
    }

    /// Send a message through the appropriate transport
    pub async fn send_message(&self, message: TransportMessage) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;

        // For now, send through the first available connected transport
        // In a real implementation, you might want to:
        // 1. Route based on channel/protocol mapping
        // 2. Load balance across multiple transports
        // 3. Use protocol-specific routing logic

        for (name, transport) in transports.iter_mut() {
            if transport.is_connected() {
                tracing::debug!(
                    transport = %name,
                    payload_size = message.payload.len(),
                    "Sending message via transport"
                );

                match transport.send_message(message).await {
                    Ok(()) => {
                        tracing::info!(
                            transport = %name,
                            "Message sent successfully"
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::error!(
                            transport = %name,
                            error = %e,
                            "Failed to send message via transport"
                        );
                        // Continue to try other transports
                        // Note: message was moved, so we can't retry with other transports
                        // In a real implementation, you'd want to clone the message for retries
                        return Err(e);
                    }
                }
            }
        }

        // No connected transport found
        Err(AsyncApiError::Protocol {
            message: "No connected transport available for sending message".to_string(),
            protocol: "any".to_string(),
            metadata: crate::errors::ErrorMetadata::new(
                crate::errors::ErrorSeverity::High,
                crate::errors::ErrorCategory::Network,
                true, // retryable
            ),
            source: None,
        }.into())
    }

    /// Send a message through the appropriate transport with retry logic
    /// This method applies retry logic since it's used for outgoing messages
    pub async fn send_message_with_retry(&self, message: TransportMessage) -> AsyncApiResult<()> {
        // We need to create a recovery manager instance to use retry logic
        // In a real implementation, this would be injected as a dependency
        let recovery_manager = crate::recovery::RecoveryManager::default();

        let correlation_id = message.metadata.correlation_id;
        let operation = message.metadata.operation.clone();

        tracing::debug!(
            correlation_id = %correlation_id,
            operation = %operation,
            "Sending message with retry logic (outgoing message)"
        );

        // Create references to self components for the retry closure
        let transports = self.transports.clone();

        // Use direction-aware retry logic for outgoing messages
        let result = recovery_manager.execute_with_direction(
            "send_message",
            crate::recovery::MessageDirection::Outgoing,
            || {
                let message = message.clone();
                let transports = transports.clone();
                async move {
                    // Replicate the send_message logic here to avoid self reference issues
                    let mut transports_guard = transports.write().await;

                    for (name, transport) in transports_guard.iter_mut() {
                        if transport.is_connected() {
                            tracing::debug!(
                                transport = %name,
                                payload_size = message.payload.len(),
                                "Sending message via transport (retry attempt)"
                            );

                            match transport.send_message(message.clone()).await {
                                Ok(()) => {
                                    tracing::debug!(
                                        transport = %name,
                                        "Message sent successfully (retry attempt)"
                                    );
                                    return Ok(());
                                }
                                Err(e) => {
                                    tracing::error!(
                                        transport = %name,
                                        error = %e,
                                        "Failed to send message via transport (retry attempt)"
                                    );
                                    // Continue to try other transports
                                    continue;
                                }
                            }
                        }
                    }

                    // No connected transport found
                    Err(AsyncApiError::Protocol {
                        message: "No connected transport available for sending message".to_string(),
                        protocol: "any".to_string(),
                        metadata: crate::errors::ErrorMetadata::new(
                            crate::errors::ErrorSeverity::High,
                            crate::errors::ErrorCategory::Network,
                            true, // retryable
                        ),
                        source: None,
                    }.into())
                }
            }
        ).await;

        // Handle retry failure and add to dead letter queue if needed
        if let Err(ref e) = result {
            let payload = message.payload.clone();
            let channel = message.metadata.headers.get("channel")
                .unwrap_or(&operation)
                .clone();

            // Add to dead letter queue for outgoing messages
            if let Err(dlq_error) = recovery_manager.add_to_dead_letter_queue(
                &channel,
                payload,
                e,
                0, // retry count would be tracked by retry strategy
                crate::recovery::MessageDirection::Outgoing,
            ).await {
                tracing::error!(
                    correlation_id = %correlation_id,
                    error = %dlq_error,
                    "Failed to add failed outgoing message to dead letter queue"
                );
            }

            tracing::error!(
                correlation_id = %correlation_id,
                operation = %operation,
                error = %e,
                "Failed to send outgoing message after retry attempts"
            );
        }

        result
    }

    /// Send a message through a specific transport
    pub async fn send_message_via_transport(&self, transport_name: &str, message: TransportMessage) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;

        if let Some(transport) = transports.get_mut(transport_name) {
            if !transport.is_connected() {
                return Err(AsyncApiError::Protocol {
                    message: format!("Transport '{transport_name}' is not connected"),
                    protocol: transport_name.to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Network,
                        true, // retryable
                    ),
                    source: None,
                }.into());
            }

            tracing::debug!(
                transport = %transport_name,
                payload_size = message.payload.len(),
                "Sending message via specific transport"
            );

            transport.send_message(message).await
        } else {
            Err(AsyncApiError::Protocol {
                message: format!("Transport '{transport_name}' not found"),
                protocol: transport_name.to_string(),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::Medium,
                    crate::errors::ErrorCategory::Network,
                    false, // not retryable
                ),
                source: None,
            }.into())
        }
    }

    /// Perform health check on all transports
    pub async fn health_check_all(&self) -> HashMap<String, bool> {
        let transports = self.transports.read().await;
        let mut health_status = HashMap::new();

        for (name, transport) in transports.iter() {
            let is_healthy = transport.health_check().await.unwrap_or(false);
            health_status.insert(name.clone(), is_healthy);
        }

        health_status
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper struct to hold references to TransportManager components
/// This allows us to create a MessageHandler that can reference the TransportManager
#[derive(Clone)]
struct TransportManagerRef {
    transports: Arc<RwLock<HashMap<String, Box<dyn Transport>>>>,
    handlers: Arc<RwLock<HashMap<String, Arc<dyn MessageHandler>>>>,
    stats: Arc<RwLock<HashMap<String, TransportStats>>>,
    middleware: Arc<RwLock<crate::middleware::MiddlewarePipeline>>,
}

/// Wrapper struct that implements MessageHandler and delegates to TransportManager
struct TransportManagerHandler {
    transport_manager: Arc<TransportManagerRef>,
}

#[async_trait]
impl MessageHandler for TransportManagerHandler {
    async fn handle_message(&self, payload: &[u8], metadata: &MessageMetadata) -> AsyncApiResult<()> {
        // Create a temporary TransportManager instance to handle the message
        let temp_manager = TransportManager {
            transports: self.transport_manager.transports.clone(),
            handlers: self.transport_manager.handlers.clone(),
            stats: self.transport_manager.stats.clone(),
            middleware: self.transport_manager.middleware.clone(),
        };

        // Create a TransportMessage from the payload and metadata
        let message = TransportMessage {
            metadata: metadata.clone(),
            payload: payload.to_vec(),
        };

        // Delegate to the main handle_message method
        temp_manager.handle_message(message).await
    }
}

/// Implement MessageHandler for TransportManager to enable it to be used as a message handler
/// This allows the TransportManager to process messages through middleware before routing
#[async_trait]
impl MessageHandler for TransportManager {
    async fn handle_message(&self, payload: &[u8], metadata: &MessageMetadata) -> AsyncApiResult<()> {
        // Create a TransportMessage from the payload and metadata
        let message = TransportMessage {
            metadata: metadata.clone(),
            payload: payload.to_vec(),
        };

        // Delegate to the main handle_message method
        self.handle_message(message).await
    }
}
`}
        </File>
    );
}

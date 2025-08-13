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
//! This module provides a hybrid NATS transport that:
//! - Uses NATS Service API for request/reply operations with native respond() method
//! - Uses basic NATS client API for pub/sub operations
//! - Supports both patterns seamlessly based on operation type
//! - Uses MessageEnvelope format for all messages
//! - Accepts a pre-configured NATS client (user handles authentication)

use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::models::MessageEnvelope;
use crate::transport::{MessageHandler, MessageMetadata, Transport, TransportMessage, TransportStats, ConnectionState};
use crate::TransportConfig;
use async_nats::{Client, Message};
use async_nats::service::{ServiceExt, Service, Request as ServiceRequest};
use async_trait::async_trait;
use futures::StreamExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// NATS transport implementation
pub struct NatsTransport {
    config: TransportConfig,
    client: Client,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
    listening: Arc<RwLock<bool>>,
    subscribers: Arc<RwLock<Vec<async_nats::Subscriber>>>,
    /// Store pending NATS messages for native respond functionality
    pending_messages: Arc<RwLock<HashMap<Uuid, Message>>>,
    /// NATS Service for request/reply operations
    service: Option<Service>,
    /// Store pending service requests for native respond functionality
    pending_service_requests: Arc<RwLock<HashMap<Uuid, ServiceRequest>>>,
}

impl NatsTransport {
    /// Create a new NATS transport with a pre-configured NATS client
    ///
    pub fn new(client: Client, config: TransportConfig) -> Self {
        Self {
            client,
            config,
            connection_state: Arc::new(RwLock::new(ConnectionState::Connected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            message_handler: None,
            listening: Arc::new(RwLock::new(false)),
            subscribers: Arc::new(RwLock::new(Vec::new())),
            pending_messages: Arc::new(RwLock::new(HashMap::new())),
            service: None,
            pending_service_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set the message handler for this transport
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
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
                    message: format!("Invalid JSON payload: {e}"),
                    field: Some("payload".to_string()),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Validation,
                        false,
                    ),
                    source: None,
                }))?;

            // Use the models version's new method and add correlation ID
            let mut envelope = MessageEnvelope::new(&message.metadata.operation, payload_value)
                .map_err(|e| Box::new(AsyncApiError::Validation {
                    message: format!("Failed to create MessageEnvelope: {e}"),
                    field: Some("payload".to_string()),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Validation,
                        false,
                    ),
                    source: Some(Box::new(e)),
                }))?;

            envelope = envelope.with_correlation_id(message.metadata.correlation_id.to_string());
            envelope = envelope.with_headers(message.metadata.headers.clone());
            Ok(envelope)
        }
    }

    /// Start subscription handler for a channel (supports dynamic channels with wildcards)
    async fn start_subscription_handler(
        &self,
        mut subscriber: async_nats::Subscriber,
        channel: String,
    ) -> AsyncApiResult<()> {
        let handler = self.message_handler.clone();
        let stats = self.stats.clone();
        let pending_messages = self.pending_messages.clone();
        let transport_id = self.config.transport_id.clone();

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

                    // Store the original NATS message for potential responses if it has a reply subject
                    if message.reply.is_some() {
                        let mut pending = pending_messages.write().await;
                        pending.insert(correlation_id, message.clone());

                        if let Some(reply_subject) = &message.reply {
                            headers.insert("nats_reply_subject".to_string(), reply_subject.to_string());
                        }
                    }

                    let metadata = MessageMetadata {
                        operation: envelope.operation.clone(),
                        headers,
                        correlation_id,
                        content_type: Some("application/json".to_string()),
                        reply_to: message.reply.as_ref().map(|s| s.to_string()),
                        priority: None,
                        ttl: None,
                        source_transport: Some(transport_id), // Generate a UUID for this transport instance
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
                            stats.last_error = Some(format!("Handler error: {e}"));
                        }
                    }
                } else {
                    warn!("No message handler configured for NATS transport on channel: {}", channel);
                }
            }

            debug!("Subscription handler stopped for channel: {}", channel);
        });

        Ok(())
    }

    /// Create NATS service for request/reply operations
    async fn create_service(&mut self) -> AsyncApiResult<()> {
        // Create NATS service for request/reply operations
        let service_name = "asyncapi-service";
        let service = self.client
            .service_builder()
            .description("AsyncAPI NATS Service for request/reply operations")
            .start(service_name, "1.0.0")
            .await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to create NATS service: {e}"),
                protocol: "nats".to_string(),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Network,
                    false,
                ),
                source: None,
            }))?;

        self.service = Some(service);
        info!("Created NATS service: {}", service_name);
        Ok(())
    }

    /// Start service endpoint handler for request/reply operations
    async fn start_service_endpoint_handler(
        &self,
        endpoint_name: String,
    ) -> AsyncApiResult<()> {
        let service = self.service.as_ref().ok_or_else(|| Box::new(AsyncApiError::Protocol {
            message: "NATS service not created".to_string(),
            protocol: "nats".to_string(),
            metadata: crate::errors::ErrorMetadata::new(
                crate::errors::ErrorSeverity::High,
                crate::errors::ErrorCategory::Network,
                false,
            ),
            source: None,
        }))?;

        let handler = self.message_handler.clone();
        let stats = self.stats.clone();
        let pending_service_requests = self.pending_service_requests.clone();

        let mut endpoint = service.endpoint(&endpoint_name).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to create service endpoint '{endpoint_name}': {e}"),
                protocol: "nats".to_string(),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Network,
                    false,
                ),
                source: None,
            }))?;

        let endpoint_name_clone = endpoint_name.clone();
        tokio::spawn(async move {
            debug!("Starting service endpoint handler for: {}", endpoint_name_clone);

            while let Some(request) = endpoint.next().await {
                if let Some(handler) = &handler {
                    // Parse incoming service request as MessageEnvelope
                    let envelope = match serde_json::from_slice::<MessageEnvelope>(&request.message.payload) {
                        Ok(envelope) => envelope,
                        Err(e) => {
                            warn!("Received non-MessageEnvelope format on service endpoint {}: {}", endpoint_name_clone, e);
                            // Skip error response for now due to API compatibility issues
                            warn!("Skipping error response due to API compatibility");
                            continue;
                        }
                    };

                    // Extract metadata from envelope
                    let correlation_id = envelope.correlation_id()
                        .and_then(|id| id.parse().ok())
                        .unwrap_or_else(Uuid::new_v4);

                    let mut headers = envelope.headers.clone().unwrap_or_default();
                    headers.insert("subject".to_string(), request.message.subject.to_string());
                    headers.insert("endpoint".to_string(), endpoint_name_clone.clone());
                    headers.insert("service_request".to_string(), "true".to_string());

                    // Store the service request for native respond functionality
                    {
                        let mut pending = pending_service_requests.write().await;
                        pending.insert(correlation_id, request);
                    }

                    let metadata = MessageMetadata {
                        operation: envelope.operation.clone(),
                        headers,
                        correlation_id,
                        content_type: Some("application/json".to_string()),
                        reply_to: Some("service_request".to_string()), // Indicate this is a service request
                        priority: None,
                        ttl: None,
                        source_transport: Some(Uuid::new_v4()), // Generate a UUID for this transport instance
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
                            warn!("Error handling service request on {}: {}", endpoint_name_clone, e);

                            // Clean up the stored request
                            let mut pending = pending_service_requests.write().await;
                            pending.remove(&correlation_id);

                            // Update error stats
                            let mut stats = stats.write().await;
                            stats.messages_received += 1;
                            stats.last_error = Some(format!("Handler error: {e}"));
                        }
                    }
                } else {
                    warn!("No message handler configured for service endpoint: {}", endpoint_name_clone);
                }
            }

            debug!("Service endpoint handler stopped for: {}", endpoint_name_clone);
        });

        info!("Started service endpoint handler for: {}", &endpoint_name);
        Ok(())
    }

    /// Determine if an operation should use service API (request/reply) or basic API (pub/sub)
    fn is_request_reply_operation(&self, operation: &str) -> bool {
        // For now, use a simple heuristic: operations containing "request", "get", "fetch", "query" are request/reply
        // In a real implementation, this could be determined from AsyncAPI spec metadata
        let request_reply_keywords = ["request", "get", "fetch", "query", "call", "invoke"];
        let operation_lower = operation.to_lowercase();
        request_reply_keywords.iter().any(|keyword| operation_lower.contains(keyword))
    }
}

#[async_trait]
impl Transport for NatsTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        // Client is already connected when passed to constructor
        *self.connection_state.write().await = ConnectionState::Connected;
        info!("NATS transport ready (using pre-configured client)");
        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        info!("Disconnecting from NATS");

        *self.connection_state.write().await = ConnectionState::Disconnected;
        *self.listening.write().await = false;

        // Close all subscribers
        let mut subscribers = self.subscribers.write().await;
        subscribers.clear();

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
        // Extract channel and operation from metadata
        let channel = self.extract_channel_from_message(&message)?;
        let operation = &message.metadata.operation;
        let subject = format!("{channel}.{operation}");

        // Ensure payload is MessageEnvelope format
        let envelope = self.ensure_message_envelope(&message)?;
        let payload = serde_json::to_vec(&envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize MessageEnvelope: {e}"),
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
            let _response = self.client.request(subject, payload.into()).await
                .map_err(|e| Box::new(AsyncApiError::Protocol {
                    message: format!("NATS request failed: {e}"),
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
            self.client.publish(subject, payload.into()).await
                .map_err(|e| Box::new(AsyncApiError::Protocol {
                    message: format!("NATS publish failed: {e}"),
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

    async fn respond(&mut self, response: TransportMessage, original_metadata: &MessageMetadata) -> AsyncApiResult<()> {
        // Check if this is a service request (from NATS Service API)
        if original_metadata.headers.get("service_request").map(|v| v == "true").unwrap_or(false) {
            // Use native NATS Service API respond method
            debug!(
                "Using NATS Service API respond for correlation_id: {}",
                original_metadata.correlation_id
            );

            // Ensure response payload is MessageEnvelope format
            let envelope = self.ensure_message_envelope(&response)?;
            let payload = serde_json::to_vec(&envelope)
                .map_err(|e| Box::new(AsyncApiError::Validation {
                    message: format!("Failed to serialize response MessageEnvelope: {e}"),
                    field: Some("payload".to_string()),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Validation,
                        false,
                    ),
                    source: Some(Box::new(e)),
                }))?;

            // Remove the service request from storage to take ownership
            let mut pending = self.pending_service_requests.write().await;
            let service_request = pending.remove(&original_metadata.correlation_id)
                .ok_or_else(|| Box::new(AsyncApiError::Protocol {
                    message: format!("Service request not found for correlation_id: {}", original_metadata.correlation_id),
                    protocol: "nats".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Network,
                        false,
                    ),
                    source: None,
                }))?;
            drop(pending);

            // Use native NATS Service API respond method
            service_request.respond(Ok(payload.into())).await
                .map_err(|e| Box::new(AsyncApiError::Protocol {
                    message: format!("NATS Service API respond failed: {e}"),
                    protocol: "nats".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Network,
                        true,
                    ),
                    source: Some(Box::new(e)),
                }))?;

            debug!(
                "Successfully sent NATS Service API response for correlation_id: {}",
                original_metadata.correlation_id
            );
        } else {
            // Use traditional NATS request/reply pattern
            // Get the reply subject from the original message metadata
            let reply_subject = original_metadata.reply_to.as_ref()
                .ok_or_else(|| Box::new(AsyncApiError::Protocol {
                    message: "No reply subject found in original message metadata".to_string(),
                    protocol: "nats".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Network,
                        false,
                    ),
                    source: None,
                }))?;

            // Ensure response payload is MessageEnvelope format
            let envelope = self.ensure_message_envelope(&response)?;
            let payload = serde_json::to_vec(&envelope)
                .map_err(|e| Box::new(AsyncApiError::Validation {
                    message: format!("Failed to serialize response MessageEnvelope: {e}"),
                    field: Some("payload".to_string()),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Validation,
                        false,
                    ),
                    source: Some(Box::new(e)),
                }))?;

            // Use NATS publish to reply subject - this is the correct NATS request/reply pattern
            debug!(
                "Sending NATS response to reply subject: {}, correlation_id: {}",
                reply_subject,
                original_metadata.correlation_id
            );

            self.client.publish(reply_subject.clone(), payload.into()).await
                .map_err(|e| Box::new(AsyncApiError::Protocol {
                    message: format!("NATS response failed: {e}"),
                    protocol: "nats".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Network,
                        true,
                    ),
                    source: Some(Box::new(e)),
                }))?;

            // Clean up the stored message since we've responded
            let mut pending = self.pending_messages.write().await;
            pending.remove(&original_metadata.correlation_id);

            debug!(
                "Successfully sent NATS response to reply subject: {}, correlation_id: {}",
                reply_subject,
                original_metadata.correlation_id
            );
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;

        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        // Create NATS service if not already created (for request/reply operations)
        if self.service.is_none() {
            self.create_service().await?;
        }

        // Check if this channel should use service API for request/reply operations
        if self.is_request_reply_operation(channel) {
            // Use NATS Service API for request/reply operations
            debug!("Setting up NATS Service endpoint for request/reply channel: {}", channel);
            self.start_service_endpoint_handler(channel.to_string()).await?;
            info!("Created NATS Service endpoint for request/reply channel: {}", channel);
        } else {
            // Use basic NATS subscription for pub/sub operations
            debug!("Setting up basic NATS subscription for pub/sub channel: {}", channel);

            // For dynamic channels, we need to subscribe with a wildcard pattern
            // The channel might be a resolved address like "device.30000", but we should
            // subscribe to a pattern that matches all possible values
            let subject_pattern = if channel.contains('.') && !channel.ends_with(".*") {
                // This looks like a resolved dynamic channel address
                // Subscribe to the exact address for this specific dynamic channel instance
                channel.to_string()
            } else {
                // This is a static channel or already a pattern
                channel.to_string()
            };

            debug!("Subscribing to channel pattern: {}", subject_pattern);

            let subscriber = self.client.subscribe(subject_pattern).await
                .map_err(|e| Box::new(AsyncApiError::Protocol {
                    message: format!("Failed to subscribe to channel '{channel}': {e}"),
                    protocol: "nats".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Network,
                        false,
                    ),
                    source: Some(Box::new(e)),
                }))?;

            // Start subscription handler for this channel
            self.start_subscription_handler(subscriber, channel.to_string()).await?;
            info!("Subscribed to pub/sub channel: {}", channel);
        }

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

/// Helper function to create NATS transport with a pre-configured client
pub fn create_nats_transport(client: Client, config: TransportConfig) -> Box<dyn Transport> {
    Box::new(NatsTransport::new(client, config))
}
`}
        </File>
    );
}

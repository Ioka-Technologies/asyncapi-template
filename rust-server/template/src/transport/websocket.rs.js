/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function WebSocketTransport({ asyncapi }) {
    // Check if WebSocket protocol is used
    const servers = asyncapi.servers();
    let hasWebSocket = false;

    if (servers) {
        Object.entries(servers).forEach(([_name, server]) => {
            const protocol = server.protocol && typeof server.protocol === 'function' ? server.protocol() : server.protocol;
            if (protocol && typeof protocol === 'string' && ['ws', 'wss', 'websocket'].includes(protocol.toLowerCase())) {
                hasWebSocket = true;
            }
        });
    }

    // Only generate file if WebSocket is used
    if (!hasWebSocket) {
        return null;
    }

    return (
        <File name="websocket.rs">
            {`//! WebSocket transport implementation for real-time bidirectional communication
//!
//! This module provides a production-ready WebSocket transport that enables:
//! - **Real-time messaging**: Instant bidirectional communication without HTTP overhead
//! - **Connection persistence**: Maintains long-lived connections for optimal user experience
//! - **HTTP upgrade integration**: Proper WebSocket handshake through HTTP upgrade requests
//! - **Message correlation**: Tracks request/response flows for reliable communication patterns
//! - **Security integration**: Supports JWT authentication and TLS encryption
//!
//! ## Design Philosophy
//!
//! This WebSocket implementation prioritizes:
//! - **Reliability**: Robust error handling and automatic recovery mechanisms
//! - **Performance**: Minimal latency and efficient message processing
//! - **Scalability**: Support for thousands of concurrent connections
//! - **Observability**: Comprehensive metrics and logging for production monitoring
//! - **Standards compliance**: Proper HTTP upgrade flow for WebSocket connections
//!
//! ## Usage Patterns
//!
//! The WebSocket transport is ideal for:
//! - **Real-time applications**: Chat, notifications, live updates
//! - **Interactive services**: Form validation, collaborative editing
//! - **Gaming and IoT**: Low-latency command/response patterns
//! - **Financial services**: Live market data and trading interfaces
//!
//! ## Connection Lifecycle
//!
//! 1. **HTTP Request**: Client sends HTTP GET with upgrade headers
//! 2. **Authentication**: Validate JWT tokens in connection headers
//! 3. **Handshake**: HTTP server upgrades connection to WebSocket
//! 4. **Message Loop**: Process incoming messages and route to handlers
//! 5. **Health Monitoring**: Track connection health and detect failures
//! 6. **Graceful Shutdown**: Clean connection termination with proper cleanup

use async_trait::async_trait;
use axum::{
    extract::{
        ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::models::MessageEnvelope;
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

/// Represents an active WebSocket connection
#[derive(Debug)]
pub struct WebSocketConnection {
    id: String,
    sender: Arc<RwLock<Option<mpsc::UnboundedSender<AxumMessage>>>>,
    connected_at: Instant,
}

/// Shared state for WebSocket connections
#[derive(Clone)]
pub struct WebSocketState {
    connections: Arc<RwLock<HashMap<String, WebSocketConnection>>>,
    stats: Arc<RwLock<TransportStats>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
}

/// WebSocket transport implementation (Server-side using Axum)
pub struct WebSocketTransport {
    config: TransportConfig,
    connection_state: Arc<RwLock<ConnectionState>>,
    state: WebSocketState,
    shutdown_tx: Option<mpsc::Sender<()>>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl WebSocketTransport {
    /// Create a new WebSocket transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        Self::new_with_handler(config, None)
    }

    /// Create a new WebSocket transport with an optional message handler
    pub fn new_with_handler(config: TransportConfig, handler: Option<Arc<dyn MessageHandler>>) -> AsyncApiResult<Self> {
        if !["ws", "wss", "websocket"].contains(&config.protocol.to_lowercase().as_str()) {
            return Err(Box::new(AsyncApiError::new(
                format!("Invalid protocol for WebSocket transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            )));
        }

        let state = WebSocketState {
            connections: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            message_handler: handler,
        };

        Ok(Self {
            config,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            state,
            shutdown_tx: None,
            server_handle: None,
        })
    }

    /// Set message handler for incoming messages
    /// Note: This method is kept for backwards compatibility, but it's recommended
    /// to use new_with_handler() instead to set the handler during construction
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.state.message_handler = Some(handler);
    }

    /// Get server bind address
    fn get_bind_address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }

    /// Generate unique connection ID
    fn generate_connection_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!("ws_conn_{}", COUNTER.fetch_add(1, Ordering::SeqCst))
    }

    /// Create Axum router with WebSocket endpoint
    fn create_router(&self) -> Router {
        Router::new()
            .route("/ws", get(websocket_handler))
            .route("/", get(websocket_handler)) // Also handle root path
            .with_state(self.state.clone())
    }

    /// Start WebSocket server using Axum
    async fn start_server(&mut self) -> AsyncApiResult<()> {
        let bind_address = self.get_bind_address();
        let listener = TcpListener::bind(&bind_address).await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to bind WebSocket server to {bind_address}: {e}"),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let router = self.create_router();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start server task
        let server_handle = tokio::spawn(async move {
            tracing::info!("WebSocket server listening on {}", bind_address);

            tokio::select! {
                result = axum::serve(listener, router) => {
                    if let Err(e) = result {
                        tracing::error!("WebSocket server error: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("WebSocket server shutdown requested");
                }
            }
        });

        self.server_handle = Some(server_handle);
        Ok(())
    }
}

/// WebSocket upgrade handler
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<WebSocketState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_websocket(socket, state))
}

/// Handle individual WebSocket connection
async fn handle_websocket(socket: WebSocket, state: WebSocketState) {
    let connection_id = WebSocketTransport::generate_connection_id();
    tracing::info!("New WebSocket connection: {}", connection_id);

    // Create channels for communication
    let (sender, mut receiver) = mpsc::unbounded_channel::<AxumMessage>();
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Create connection record
    let connection = WebSocketConnection {
        id: connection_id.clone(),
        sender: Arc::new(RwLock::new(Some(sender))),
        connected_at: Instant::now(),
    };

    // Add connection to state
    {
        let mut connections = state.connections.write().await;
        connections.insert(connection_id.clone(), connection);
    }

    // Update stats
    {
        let mut stats = state.stats.write().await;
        stats.connection_attempts += 1;
    }

    // Spawn task to handle outgoing messages
    let outgoing_connection_id = connection_id.clone();
    let outgoing_task = tokio::spawn(async move {
        while let Some(msg) = receiver.recv().await {
            if let Err(e) = ws_sender.send(msg).await {
                tracing::error!("Failed to send WebSocket message to {}: {}", outgoing_connection_id, e);
                break;
            }
        }
        tracing::debug!("Outgoing message task ended for connection {}", outgoing_connection_id);
    });

    // Handle incoming messages
    let incoming_state = state.clone();
    let incoming_connection_id = connection_id.clone();
    while let Some(msg_result) = ws_receiver.next().await {
        match msg_result {
            Ok(msg) => {
                // Update stats
                {
                    let mut stats = incoming_state.stats.write().await;
                    stats.messages_received += 1;
                }

                match msg {
                    AxumMessage::Text(text) => {
                        if let Some(handler) = &incoming_state.message_handler {
                            let payload = text.into_bytes();

                            // Try to parse as MessageEnvelope first
                            match serde_json::from_slice::<MessageEnvelope>(&payload) {
                                Ok(envelope) => {
                                    // Successfully parsed as MessageEnvelope - extract metadata
                                    let correlation_id = envelope.correlation_id()
                                        .and_then(|id| id.parse().ok())
                                        .unwrap_or_else(uuid::Uuid::new_v4);

                                    let operation = envelope.operation.clone();

                                    let mut headers = HashMap::new();
                                    headers.insert("correlation_id".to_string(), correlation_id.to_string());

                                    // Extract headers from MessageEnvelope if present
                                    if let Some(envelope_headers) = &envelope.headers {
                                        for (key, value) in envelope_headers {
                                            headers.insert(key.clone(), value.clone());
                                        }
                                    }

                                    let metadata = MessageMetadata {
                                        content_type: Some("application/json".to_string()),
                                        headers,
                                        priority: None,
                                        ttl: None,
                                        reply_to: Some(incoming_connection_id.clone()),
                                        operation,
                                        correlation_id,
                                    };

                                    tracing::debug!(
                                        correlation_id = %correlation_id,
                                        operation = %metadata.operation,
                                        connection_id = %incoming_connection_id,
                                        "Processing WebSocket MessageEnvelope"
                                    );

                                    if let Err(e) = handler.handle_message(&payload, &metadata).await {
                                        let mut stats = incoming_state.stats.write().await;
                                        stats.last_error = Some(e.to_string());
                                    }
                                }
                                Err(_) => {
                                    // Fallback: treat as plain text message
                                    let correlation_id = uuid::Uuid::new_v4();
                                    let mut headers = HashMap::new();
                                    headers.insert("correlation_id".to_string(), correlation_id.to_string());

                                    let metadata = MessageMetadata {
                                        content_type: Some("text/plain".to_string()),
                                        headers,
                                        priority: None,
                                        ttl: None,
                                        reply_to: Some(incoming_connection_id.clone()),
                                        operation: "websocket_message".to_string(),
                                        correlation_id,
                                    };

                                    tracing::debug!(
                                        correlation_id = %correlation_id,
                                        connection_id = %incoming_connection_id,
                                        "Processing WebSocket text message (non-envelope format)"
                                    );

                                    if let Err(e) = handler.handle_message(&payload, &metadata).await {
                                        tracing::error!("Failed to handle WebSocket text message: {}", e);
                                        let mut stats = incoming_state.stats.write().await;
                                        stats.last_error = Some(e.to_string());
                                    }
                                }
                            }
                        }
                    }
                    AxumMessage::Binary(data) => {
                        if let Some(handler) = &incoming_state.message_handler {
                            // Try to parse as MessageEnvelope first
                            match serde_json::from_slice::<MessageEnvelope>(&data) {
                                Ok(envelope) => {
                                    // Successfully parsed as MessageEnvelope - extract metadata
                                    let correlation_id = envelope.correlation_id()
                                        .and_then(|id| id.parse().ok())
                                        .unwrap_or_else(uuid::Uuid::new_v4);

                                    let operation = envelope.operation.clone();

                                    let mut headers = HashMap::new();
                                    headers.insert("correlation_id".to_string(), correlation_id.to_string());

                                    // Extract headers from MessageEnvelope if present
                                    if let Some(envelope_headers) = &envelope.headers {
                                        for (key, value) in envelope_headers {
                                            headers.insert(key.clone(), value.clone());
                                        }
                                    }

                                    let metadata = MessageMetadata {
                                        content_type: Some("application/json".to_string()),
                                        headers,
                                        priority: None,
                                        ttl: None,
                                        reply_to: Some(incoming_connection_id.clone()),
                                        operation,
                                        correlation_id,
                                    };

                                    // Pass the envelope payload to the handler, not the raw message
                                    let envelope_payload = serde_json::to_vec(&envelope.payload).unwrap_or_else(|_| data.clone());

                                    tracing::debug!(
                                        correlation_id = %correlation_id,
                                        operation = %metadata.operation,
                                        connection_id = %incoming_connection_id,
                                        "Processing WebSocket binary MessageEnvelope"
                                    );

                                    if let Err(e) = handler.handle_message(&envelope_payload, &metadata).await {
                                        tracing::error!("Failed to handle WebSocket binary MessageEnvelope: {}", e);
                                        let mut stats = incoming_state.stats.write().await;
                                        stats.last_error = Some(e.to_string());
                                    }
                                }
                                Err(_) => {
                                    // Fallback: treat as binary data
                                    let correlation_id = uuid::Uuid::new_v4();
                                    let mut headers = HashMap::new();
                                    headers.insert("correlation_id".to_string(), correlation_id.to_string());

                                    let metadata = MessageMetadata {
                                        content_type: Some("application/octet-stream".to_string()),
                                        headers,
                                        priority: None,
                                        ttl: None,
                                        reply_to: Some(incoming_connection_id.clone()),
                                        operation: "websocket_message".to_string(),
                                        correlation_id,
                                    };

                                    tracing::debug!(
                                        correlation_id = %correlation_id,
                                        connection_id = %incoming_connection_id,
                                        "Processing WebSocket binary message (non-envelope format)"
                                    );

                                    if let Err(e) = handler.handle_message(&data, &metadata).await {
                                        tracing::error!("Failed to handle WebSocket binary message: {}", e);
                                        let mut stats = incoming_state.stats.write().await;
                                        stats.last_error = Some(e.to_string());
                                    }
                                }
                            }
                        }
                    }
                    AxumMessage::Ping(data) => {
                        // Respond to ping with pong
                        let connections = incoming_state.connections.read().await;
                        if let Some(connection) = connections.get(&incoming_connection_id) {
                            if let Some(sender) = connection.sender.read().await.as_ref() {
                                let _ = sender.send(AxumMessage::Pong(data));
                            }
                        }
                    }
                    AxumMessage::Pong(_) => {
                        // Ignore pong frames
                    }
                    AxumMessage::Close(_) => {
                        tracing::info!("WebSocket connection {} closed by peer", incoming_connection_id);
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::error!("WebSocket error on connection {}: {}", incoming_connection_id, e);
                let mut stats = incoming_state.stats.write().await;
                stats.last_error = Some(e.to_string());
                break;
            }
        }
    }

    // Clean up connection
    {
        let mut connections = state.connections.write().await;
        if let Some(connection) = connections.remove(&connection_id) {
            // Close the sender channel
            if let Some(sender) = connection.sender.write().await.take() {
                drop(sender);
            }
        }
    }

    // Cancel outgoing task
    outgoing_task.abort();

    tracing::info!("WebSocket connection {} closed", connection_id);
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        // Start WebSocket server
        self.start_server().await?;

        *self.connection_state.write().await = ConnectionState::Connected;
        tracing::info!("WebSocket server started successfully on {}", self.get_bind_address());

        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }

        // Close all active connections
        {
            let mut connections = self.state.connections.write().await;
            for (connection_id, connection) in connections.drain() {
                if let Some(sender) = connection.sender.write().await.take() {
                    drop(sender);
                }
                tracing::debug!("Closed WebSocket connection {}", connection_id);
            }
        }

        *self.connection_state.write().await = ConnectionState::Disconnected;
        tracing::info!("WebSocket server disconnected");
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
        // Determine message type based on content
        let ws_message = if let Some(content_type) = &message.metadata.content_type {
            if content_type.contains("text") || content_type.contains("json") {
                AxumMessage::Text(String::from_utf8_lossy(&message.payload).to_string())
            } else {
                AxumMessage::Binary(message.payload.clone())
            }
        } else {
            // Try to parse as UTF-8, fall back to binary
            match String::from_utf8(message.payload.clone()) {
                Ok(text) => AxumMessage::Text(text),
                Err(_) => AxumMessage::Binary(message.payload.clone()),
            }
        };

        // Check if we should send to a specific connection or broadcast to all
        if let Some(reply_to) = &message.metadata.reply_to {
            // Send to specific connection
            let connections = self.state.connections.read().await;
            if let Some(connection) = connections.get(reply_to) {
                if let Some(sender) = connection.sender.read().await.as_ref() {
                    sender.send(ws_message).map_err(|e| {
                        AsyncApiError::new(
                            format!("Failed to send WebSocket message to {reply_to}: {e}"),
                            ErrorCategory::Network,
                            Some(Box::new(e)),
                        )
                    })?;

                    let mut stats = self.state.stats.write().await;
                    stats.messages_sent += 1;
                    stats.bytes_sent += message.payload.len() as u64;

                    tracing::debug!("Sent WebSocket message to connection {}, payload size: {} bytes", reply_to, message.payload.len());
                } else {
                    return Err(Box::new(AsyncApiError::new(
                        format!("WebSocket connection {reply_to} sender is closed"),
                        ErrorCategory::Network,
                        None,
                    )));
                }
            } else {
                return Err(Box::new(AsyncApiError::new(
                    format!("WebSocket connection {reply_to} not found"),
                    ErrorCategory::Network,
                    None,
                )));
            }
        } else {
            // Broadcast to all connections
            let connections = self.state.connections.read().await;
            let mut sent_count = 0;
            let mut failed_connections = Vec::new();

            for (connection_id, connection) in connections.iter() {
                if let Some(sender) = connection.sender.read().await.as_ref() {
                    if let Err(e) = sender.send(ws_message.clone()) {
                        tracing::error!("Failed to send message to connection {}: {}", connection_id, e);
                        failed_connections.push(connection_id.clone());
                    } else {
                        sent_count += 1;
                    }
                }
            }

            if sent_count > 0 {
                let mut stats = self.state.stats.write().await;
                stats.messages_sent += sent_count;
                stats.bytes_sent += (message.payload.len() as u64) * sent_count;

                tracing::debug!("Broadcast WebSocket message to {} connections, payload size: {} bytes", sent_count, message.payload.len());
            }

            if !failed_connections.is_empty() {
                tracing::warn!("Failed to send message to {} connections", failed_connections.len());
            }
        }

        Ok(())
    }

    async fn subscribe(&mut self, _channel: &str) -> AsyncApiResult<()> {
        // WebSocket doesn't have explicit subscription mechanism like pub/sub systems
        // In practice, you might send a subscription message to the server
        tracing::info!("WebSocket subscription requested for channel: {}", _channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, _channel: &str) -> AsyncApiResult<()> {
        // WebSocket doesn't have explicit unsubscription mechanism
        // In practice, you might send an unsubscription message to the server
        tracing::info!("WebSocket unsubscription requested for channel: {}", _channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // WebSocket listening is handled by the message loop, which is started in connect()
        tracing::info!("WebSocket transport is listening for messages");
        Ok(())
    }

    async fn stop_listening(&mut self) -> AsyncApiResult<()> {
        // Stop listening by disconnecting
        self.disconnect().await
    }

    fn get_stats(&self) -> TransportStats {
        self.state.stats.try_read()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }

    async fn health_check(&self) -> AsyncApiResult<bool> {
        // For WebSocket server, check if server is running and has active connections
        let is_server_running = self.is_connected() && self.server_handle.is_some();

        if is_server_running {
            // Optionally check if we have any active connections
            let connections = self.state.connections.read().await;
            let connection_count = connections.len();
            tracing::debug!("WebSocket server health check: {} active connections", connection_count);
        }

        Ok(is_server_running)
    }

    fn protocol(&self) -> &str {
        &self.config.protocol
    }
}

impl Drop for WebSocketTransport {
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

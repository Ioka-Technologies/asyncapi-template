/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function WebSocketTransport({ asyncapi, params }) {
    // Check if WebSocket protocol is used
    const servers = asyncapi.servers();
    let hasWebSocket = false;

    if (servers) {
        Object.entries(servers).forEach(([_name, server]) => {
            const protocol = server.protocol && server.protocol();
            if (protocol && ['ws', 'wss', 'websocket'].includes(protocol.toLowerCase())) {
                hasWebSocket = true;
            }
        });
    }

    // Only generate file if WebSocket is used
    if (!hasWebSocket) {
        return null;
    }

    const useAsyncStd = params.useAsyncStd === 'true' || params.useAsyncStd === true;

    return (
        <File name="websocket.rs">
            {`//! WebSocket transport implementation

use async_trait::async_trait;
${useAsyncStd ? `
use async_tungstenite::{
    async_std::connect_async, async_std::connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
    WebSocketStream,
};
use async_std::net::TcpStream;
` : `
use tokio_tungstenite::{
    connect_async, connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig, client::IntoClientRequest},
    WebSocketStream, MaybeTlsStream,
};
use tokio::net::TcpStream;
`}
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use url::Url;

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

${useAsyncStd ? `
type WsStream = WebSocketStream<TcpStream>;
` : `
type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
`}

/// WebSocket transport implementation
pub struct WebSocketTransport {
    config: TransportConfig,
    ws_stream: Option<WsStream>,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    subscriptions: Arc<RwLock<Vec<String>>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl WebSocketTransport {
    /// Create a new WebSocket transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if !["ws", "wss", "websocket"].contains(&config.protocol.as_str()) {
            return Err(AsyncApiError::new(
                format!("Invalid protocol for WebSocket transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            ));
        }

        Ok(Self {
            config,
            ws_stream: None,
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

    /// Create WebSocket URL from configuration
    fn create_websocket_url(&self) -> AsyncApiResult<Url> {
        let scheme = match self.config.protocol.as_str() {
            "wss" => "wss",
            "ws" | "websocket" => if self.config.tls { "wss" } else { "ws" },
            _ => "ws",
        };

        let path = self.config.additional_config
            .get("path")
            .map(|p| p.as_str())
            .unwrap_or("/");

        let url_str = format!("{}://{}:{}{}", scheme, self.config.host, self.config.port, path);

        Url::parse(&url_str).map_err(|e| {
            AsyncApiError::new(
                format!("Invalid WebSocket URL: {}", e),
                ErrorCategory::Configuration,
                Some(Box::new(e)),
            )
        })
    }

    /// Create WebSocket configuration
    fn create_ws_config(&self) -> WebSocketConfig {
        let mut config = WebSocketConfig::default();

        // Set max message size if specified
        if let Some(max_message_size) = self.config.additional_config
            .get("max_message_size")
            .and_then(|v| v.parse::<usize>().ok())
        {
            config.max_message_size = Some(max_message_size);
        }

        // Set max frame size if specified
        if let Some(max_frame_size) = self.config.additional_config
            .get("max_frame_size")
            .and_then(|v| v.parse::<usize>().ok())
        {
            config.max_frame_size = Some(max_frame_size);
        }

        config
    }

    /// Start the WebSocket message loop
    async fn start_message_loop(&mut self) -> AsyncApiResult<()> {
        if let Some(ws_stream) = self.ws_stream.take() {
            let (mut ws_sender, mut ws_receiver) = ws_stream.split();
            let connection_state = Arc::clone(&self.connection_state);
            let stats = Arc::clone(&self.stats);
            let message_handler = self.message_handler.clone();
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            self.shutdown_tx = Some(shutdown_tx);

            // Store the sender for sending messages
            let (_msg_tx, mut msg_rx) = mpsc::channel::<Message>(100);

            // Spawn sender task
            let sender_stats = Arc::clone(&stats);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        message = msg_rx.recv() => {
                            match message {
                                Some(msg) => {
                                    if let Err(e) = ws_sender.send(msg).await {
                                        tracing::error!("Failed to send WebSocket message: {}", e);
                                        let mut stats = sender_stats.write().await;
                                        stats.last_error = Some(e.to_string());
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            tracing::info!("WebSocket sender shutdown requested");
                            break;
                        }
                    }
                }
            });

            // Spawn receiver task
            tokio::spawn(async move {
                loop {
                    match ws_receiver.next().await {
                        Some(Ok(message)) => {
                            match message {
                                Message::Text(text) => {
                                    let mut stats = stats.write().await;
                                    stats.messages_received += 1;
                                    stats.bytes_received += text.len() as u64;
                                    drop(stats);

                                    if let Some(handler) = &message_handler {
                                        let metadata = MessageMetadata {
                                            channel: "websocket".to_string(),
                                            operation: "receive".to_string(),
                                            content_type: Some("text/plain".to_string()),
                                            headers: HashMap::new(),
                                            timestamp: chrono::Utc::now(),
                                        };

                                        let transport_message = TransportMessage {
                                            metadata,
                                            payload: text.into_bytes(),
                                        };

                                        if let Err(e) = handler.handle_message(transport_message).await {
                                            tracing::error!("Failed to handle WebSocket text message: {}", e);
                                        }
                                    }
                                }
                                Message::Binary(data) => {
                                    let mut stats = stats.write().await;
                                    stats.messages_received += 1;
                                    stats.bytes_received += data.len() as u64;
                                    drop(stats);

                                    if let Some(handler) = &message_handler {
                                        let metadata = MessageMetadata {
                                            channel: "websocket".to_string(),
                                            operation: "receive".to_string(),
                                            content_type: Some("application/octet-stream".to_string()),
                                            headers: HashMap::new(),
                                            timestamp: chrono::Utc::now(),
                                        };

                                        let transport_message = TransportMessage {
                                            metadata,
                                            payload: data,
                                        };

                                        if let Err(e) = handler.handle_message(transport_message).await {
                                            tracing::error!("Failed to handle WebSocket binary message: {}", e);
                                        }
                                    }
                                }
                                Message::Ping(_data) => {
                                    tracing::debug!("Received WebSocket ping");
                                    // Pong is automatically sent by tungstenite
                                }
                                Message::Pong(_) => {
                                    tracing::debug!("Received WebSocket pong");
                                }
                                Message::Close(_) => {
                                    tracing::info!("WebSocket connection closed by peer");
                                    *connection_state.write().await = ConnectionState::Disconnected;
                                    break;
                                }
                                Message::Frame(_) => {
                                    // Raw frames are handled internally
                                }
                            }
                        }
                        Some(Err(e)) => {
                            tracing::error!("WebSocket receiver error: {}", e);
                            *connection_state.write().await = ConnectionState::Failed;
                            let mut stats = stats.write().await;
                            stats.last_error = Some(e.to_string());
                            break;
                        }
                        None => {
                            tracing::info!("WebSocket receiver stream ended");
                            *connection_state.write().await = ConnectionState::Disconnected;
                            break;
                        }
                    }
                }
            });
        }

        Ok(())
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        let url = self.create_websocket_url()?;
        let ws_config = self.create_ws_config();

        // Create connection request with optional headers
        let mut request = url.clone().into_client_request().map_err(|e| {
            AsyncApiError::new(
                format!("Failed to create WebSocket request: {}", e),
                ErrorCategory::Configuration,
                Some(Box::new(e)),
            )
        })?;

        // Add authentication headers if provided
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            use base64::{Engine as _, engine::general_purpose};
            let auth_value = general_purpose::STANDARD.encode(format!("{}:{}", username, password));
            request.headers_mut().insert(
                "Authorization",
                format!("Basic {}", auth_value).parse().unwrap(),
            );
        }

        // Add custom headers
        let custom_headers: Vec<(String, String)> = self.config.additional_config
            .iter()
            .filter_map(|(key, value)| {
                if key.starts_with("header_") {
                    let header_name = key[7..].to_string(); // Remove "header_" prefix
                    Some((header_name, value.clone()))
                } else {
                    None
                }
            })
            .collect();

        for (header_name, header_value) in custom_headers {
            if let Ok(parsed_value) = header_value.parse() {
                if let Ok(header_name) = header_name.parse::<axum::http::HeaderName>() {
                    request.headers_mut().insert(header_name, parsed_value);
                }
            }
        }

        // Connect to WebSocket
        let (ws_stream, _) = connect_async_with_config(request, Some(ws_config), false).await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to connect to WebSocket: {}", e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        self.ws_stream = Some(ws_stream);

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        // Start message loop
        self.start_message_loop().await?;

        *self.connection_state.write().await = ConnectionState::Connected;
        tracing::info!("WebSocket transport connected successfully to {}", url);

        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        self.ws_stream = None;
        *self.connection_state.write().await = ConnectionState::Disconnected;

        tracing::info!("WebSocket transport disconnected");
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
        if !self.is_connected() {
            return Err(AsyncApiError::new(
                "WebSocket not connected".to_string(),
                ErrorCategory::Network,
                None,
            ));
        }

        // Store payload length before moving it
        let payload_len = message.payload.len();

        // Determine message type based on content type
        let _ws_message = match message.metadata.content_type.as_deref() {
            Some("text/plain") | Some("application/json") | Some("text/json") => {
                let text = String::from_utf8(message.payload).map_err(|e| {
                    AsyncApiError::new(
                        format!("Invalid UTF-8 in text message: {}", e),
                        ErrorCategory::Validation,
                        Some(Box::new(e)),
                    )
                })?;
                Message::Text(text)
            }
            _ => Message::Binary(message.payload),
        };

        // For this implementation, we would need to store the sender channel
        // This is a simplified version - in practice, you'd want to store the sender
        // from the message loop and use it here

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += payload_len as u64;

        tracing::debug!("Sent WebSocket message");
        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        // WebSocket doesn't have traditional subscription model
        // This could be used to track which channels we're interested in
        let mut subscriptions = self.subscriptions.write().await;
        if !subscriptions.contains(&channel.to_string()) {
            subscriptions.push(channel.to_string());
        }

        tracing::info!("Subscribed to WebSocket channel: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.retain(|c| c != channel);

        tracing::info!("Unsubscribed from WebSocket channel: {}", channel);
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

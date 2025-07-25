//! HTTP transport implementation

use async_trait::async_trait;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{Json, Response as AxumResponse},
    routing::{delete, get, post, put},
    Router,
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory};
use crate::transport::{
    ConnectionState, MessageHandler, MessageMetadata, Transport, TransportConfig, TransportMessage,
    TransportStats,
};

/// HTTP transport implementation
pub struct HttpTransport {
    config: TransportConfig,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    routes: Arc<RwLock<HashMap<String, String>>>, // path -> method
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl HttpTransport {
    /// Create a new HTTP transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if config.protocol != "http" && config.protocol != "https" {
            return Err(Box::new(AsyncApiError::new(
                format!("Invalid protocol for HTTP transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            )));
        }

        Ok(Self {
            config,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            routes: Arc::new(RwLock::new(HashMap::new())),
            message_handler: None,
            shutdown_tx: None,
            server_handle: None,
        })
    }

    /// Set message handler for incoming messages
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Get server address
    fn get_server_address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }

    /// Create Axum router
    async fn create_axum_router(&self) -> AsyncApiResult<Router> {
        let stats = Arc::clone(&self.stats);
        let message_handler = self.message_handler.clone();

        // Create shared state
        let app_state = AppState {
            stats,
            message_handler,
        };

        let router = Router::new()
            .route("/*path", get(handle_request))
            .route("/*path", post(handle_request))
            .route("/*path", put(handle_request))
            .route("/*path", delete(handle_request))
            .route("/", get(handle_request))
            .route("/", post(handle_request))
            .route("/", put(handle_request))
            .route("/", delete(handle_request))
            .with_state(app_state)
            .layer(ServiceBuilder::new().layer(axum::middleware::from_fn(logging_middleware)));

        Ok(router)
    }
}

#[derive(Clone)]
struct AppState {
    stats: Arc<RwLock<TransportStats>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
}

async fn handle_request(
    State(state): State<AppState>,
    method: Method,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<AxumResponse<String>, StatusCode> {
    let mut stats = state.stats.write().await;
    stats.messages_received += 1;
    stats.bytes_received += body.len() as u64;
    drop(stats);

    // Extract headers
    let mut header_map = HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            header_map.insert(name.to_string(), value_str.to_string());
        }
    }

    // Add query parameters to headers
    for (key, value) in query {
        header_map.insert(format!("query_{}", key), value);
    }

    if let Some(handler) = &state.message_handler {
        let metadata = MessageMetadata {
            content_type: header_map.get("content-type").cloned(),
            headers: header_map,
            priority: None,
            ttl: None,
            reply_to: None,
        };

        let transport_message = TransportMessage {
            metadata,
            payload: body.to_vec(),
        };

        match handler.handle_message(transport_message).await {
            Ok(_) => Ok(AxumResponse::new(
                "Message processed successfully".to_string(),
            )),
            Err(e) => {
                tracing::error!("Failed to handle HTTP message: {}", e);
                let mut stats = state.stats.write().await;
                stats.last_error = Some(e.to_string());
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Ok(AxumResponse::new("No handler configured".to_string()))
    }
}

async fn logging_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().clone();
    let uri = request.uri().clone();

    tracing::info!("HTTP {} {}", method, uri);

    let response = next.run(request).await;

    tracing::info!("HTTP {} {} -> {}", method, uri, response.status());

    response
}

#[async_trait]
impl Transport for HttpTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        let address = self.get_server_address();

        let router = self.create_axum_router().await?;
        let listener = TcpListener::bind(&address).await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to bind HTTP server to {}: {}", address, e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start server in background task
        let server_handle = tokio::spawn(async move {
            tokio::select! {
                result = axum::serve(listener, router) => {
                    if let Err(e) = result {
                        tracing::error!("HTTP server error: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("HTTP server shutdown requested");
                }
            }
        });

        self.server_handle = Some(server_handle);

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        *self.connection_state.write().await = ConnectionState::Connected;
        tracing::info!("HTTP transport started on {}", address);

        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }

        *self.connection_state.write().await = ConnectionState::Disconnected;
        tracing::info!("HTTP transport disconnected");
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
        // HTTP transport is primarily for receiving messages (server mode)
        // Sending would require making HTTP client requests
        tracing::warn!(
            "HTTP transport send_message not implemented - use HTTP client for outbound requests"
        );

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += message.payload.len() as u64;

        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        // HTTP doesn't have traditional subscription model
        // This could be used to register specific routes
        let mut routes = self.routes.write().await;
        routes.insert(channel.to_string(), "GET".to_string());

        tracing::info!("Registered HTTP route: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let mut routes = self.routes.write().await;
        routes.remove(channel);

        tracing::info!("Unregistered HTTP route: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // HTTP listening is handled by the server, which is started in connect()
        tracing::info!("HTTP transport is listening for requests");
        Ok(())
    }

    async fn stop_listening(&mut self) -> AsyncApiResult<()> {
        // Stop listening by disconnecting
        self.disconnect().await
    }

    fn get_stats(&self) -> TransportStats {
        self.stats
            .try_read()
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

impl Drop for HttpTransport {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.try_send(());
        }
    }
}

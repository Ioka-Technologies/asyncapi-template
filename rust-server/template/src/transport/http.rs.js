/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function HttpTransport({ asyncapi, params }) {
    // Check if HTTP protocol is used
    const servers = asyncapi.servers();
    let hasHttp = false;

    if (servers) {
        Object.entries(servers).forEach(([_name, server]) => {
            const protocol = server.protocol && typeof server.protocol === 'function' ? server.protocol() : server.protocol;
            if (protocol && typeof protocol === 'string' && ['http', 'https'].includes(protocol.toLowerCase())) {
                hasHttp = true;
            }
        });
    }

    // Only generate file if HTTP is used
    if (!hasHttp) {
        return null;
    }

    const useAsyncStd = params.useAsyncStd === 'true' || params.useAsyncStd === true;

    return (
        <File name="http.rs">
            {`//! HTTP transport implementation

use async_trait::async_trait;
${useAsyncStd ? `
use tide::{Request, Response, Server as TideServer, StatusCode};
use async_std::task;
` : `
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Method},
    response::{Json, Response as AxumResponse},
    routing::{get, post, put, delete},
    Router,
};
use tower::ServiceBuilder;
use tokio::net::TcpListener;
`}
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use serde_json::Value;

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

/// HTTP transport implementation
pub struct HttpTransport {
    config: TransportConfig,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    routes: Arc<RwLock<HashMap<String, String>>>, // path -> method
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    ${useAsyncStd ? 'server: Option<TideServer<()>>,' : 'server_handle: Option<tokio::task::JoinHandle<()>>,'}
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
            ${useAsyncStd ? 'server: None,' : 'server_handle: None,'}
        })
    }

    /// Create a new HTTP transport with a message handler
    pub fn new_with_handler(config: TransportConfig, handler: Arc<dyn MessageHandler>) -> AsyncApiResult<Self> {
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
            message_handler: Some(handler),
            shutdown_tx: None,
            ${useAsyncStd ? 'server: None,' : 'server_handle: None,'}
        })
    }

    /// Set message handler for incoming messages
    /// Note: This method is kept for backwards compatibility, but it's recommended
    /// to use new_with_handler() instead to set the handler during construction
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Get server address
    fn get_server_address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }

    ${useAsyncStd ? `
    /// Create Tide server
    async fn create_tide_server(&self) -> AsyncApiResult<TideServer<()>> {
        let mut app = tide::new();
        let stats = Arc::clone(&self.stats);
        let message_handler = self.message_handler.clone();

        // Add middleware for logging and stats
        app.with(tide::log::LogMiddleware::new());

        // Generic handler for all routes
        let handler = move |mut req: Request<()>| {
            let stats = Arc::clone(&stats);
            let message_handler = message_handler.clone();

            async move {
                let mut stats = stats.write().await;
                stats.messages_received += 1;
                drop(stats);

                let method = req.method().to_string();
                let path = req.url().path().to_string();
                let query = req.url().query().unwrap_or("").to_string();

                // Extract headers
                let mut headers = HashMap::new();
                for (name, value) in req.iter() {
                    if let Ok(value_str) = value.to_str() {
                        headers.insert(name.to_string(), value_str.to_string());
                    }
                }

                // Read body
                let body = match req.body_bytes().await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tracing::error!("Failed to read request body: {}", e);
                        return Response::builder(StatusCode::BadRequest)
                            .body("Failed to read request body")
                            .build();
                    }
                };

                let mut stats = stats.write().await;
                stats.bytes_received += body.len() as u64;
                drop(stats);

                if let Some(handler) = &message_handler {
                    // Try to parse body as MessageEnvelope first
                    let (operation, correlation_id, final_headers, payload) = match serde_json::from_slice::<crate::models::MessageEnvelope>(&body) {
                        Ok(envelope) => {
                            // Successfully parsed as MessageEnvelope - extract metadata
                            let correlation_id = envelope.correlation_id()
                                .and_then(|id| id.parse().ok())
                                .unwrap_or_else(uuid::Uuid::new_v4);

                            let operation = envelope.operation.clone();
                            let mut final_headers = headers.clone();

                            // Extract headers from MessageEnvelope if present
                            if let Some(envelope_headers) = &envelope.headers {
                                for (key, value) in envelope_headers {
                                    final_headers.insert(key.clone(), value.clone());
                                }
                            }

                            // Use the envelope payload as the message payload
                            let payload = serde_json::to_vec(&envelope.payload).unwrap_or_else(|_| body.clone());

                            (operation, correlation_id, final_headers, payload)
                        }
                        Err(_) => {
                            // Fallback: treat as plain HTTP request
                            let correlation_id = uuid::Uuid::new_v4();
                            let operation = "http_request".to_string();
                            (operation, correlation_id, headers.clone(), body.clone())
                        }
                    };

                        let metadata = MessageMetadata {
                            content_type: final_headers.get("content-type").cloned(),
                            headers: final_headers,
                            priority: None,
                            ttl: None,
                            reply_to: None,
                            operation,
                            correlation_id,
                            source_transport: Some(uuid::Uuid::new_v4()), // TODO: Use actual transport UUID
                        };

                    match handler.handle_message(&payload, &metadata).await {
                        Ok(_) => {
                            Response::builder(StatusCode::Ok)
                                .body("Message processed successfully")
                                .build()
                        }
                        Err(e) => {
                            let mut stats = stats.write().await;
                            stats.last_error = Some(e.to_string());
                            Response::builder(StatusCode::InternalServerError)
                                .body("Failed to process message")
                                .build()
                        }
                    }
                } else {
                    Response::builder(StatusCode::Ok)
                        .body("No handler configured")
                        .build()
                }
            }
        };

        // Add routes for common HTTP methods
        app.at("/*").get(handler.clone());
        app.at("/*").post(handler.clone());
        app.at("/*").put(handler.clone());
        app.at("/*").delete(handler.clone());
        app.at("/*").patch(handler);

        Ok(app)
    }
    ` : `
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
            .layer(
                ServiceBuilder::new()
                    .layer(axum::middleware::from_fn(logging_middleware))
            );

        Ok(router)
    }
    `}
}

${useAsyncStd ? '' : `
#[derive(Clone)]
struct AppState {
    stats: Arc<RwLock<TransportStats>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
}

async fn handle_request(
    State(state): State<AppState>,
    _method: Method,
    Path(_path): Path<String>,
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
        header_map.insert(format!("query_{key}"), value);
    }

    if let Some(handler) = &state.message_handler {
        // Try to parse body as MessageEnvelope first
        let (operation, correlation_id, final_headers, payload) = match serde_json::from_slice::<crate::models::MessageEnvelope>(&body) {
            Ok(envelope) => {
                // Successfully parsed as MessageEnvelope - extract metadata
                let correlation_id = envelope.correlation_id()
                    .and_then(|id| id.parse().ok())
                    .unwrap_or_else(uuid::Uuid::new_v4);

                let operation = envelope.operation.clone();
                let mut final_headers = header_map.clone();

                // Extract headers from MessageEnvelope if present
                if let Some(envelope_headers) = &envelope.headers {
                    for (key, value) in envelope_headers {
                        final_headers.insert(key.clone(), value.clone());
                    }
                }

                // Use the envelope payload as the message payload
                let payload = serde_json::to_vec(&envelope.payload).unwrap_or_else(|_| body.to_vec());

                (operation, correlation_id, final_headers, payload)
            }
            Err(_) => {
                // Fallback: treat as plain HTTP request
                let correlation_id = uuid::Uuid::new_v4();
                let operation = "http_request".to_string();
                (operation, correlation_id, header_map, body.to_vec())
            }
        };

        let metadata = MessageMetadata {
            content_type: final_headers.get("content-type").cloned(),
            headers: final_headers,
            priority: None,
            ttl: None,
            reply_to: None,
            operation,
            correlation_id,
            source_transport: Some(uuid::Uuid::new_v4()), // TODO: Use actual transport UUID
        };

        match handler.handle_message(&payload, &metadata).await {
            Ok(_) => Ok(AxumResponse::new("Message processed successfully".to_string())),
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
`}

#[async_trait]
impl Transport for HttpTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        let address = self.get_server_address();

        ${useAsyncStd ? `
        let server = self.create_tide_server().await?;
        self.server = Some(server);

        let server_clone = self.server.as_ref().unwrap().clone();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start server in background task
        task::spawn(async move {
            tokio::select! {
                result = server_clone.listen(&address) => {
                    if let Err(e) = result {
                        tracing::error!("HTTP server error: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("HTTP server shutdown requested");
                }
            }
        });
        ` : `
        let router = self.create_axum_router().await?;
        let listener = TcpListener::bind(&address).await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to bind HTTP server to {address}: {e}"),
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
        `}

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

        ${useAsyncStd ? `
        self.server = None;
        ` : `
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
        `}

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
        tracing::warn!("HTTP transport send_message not implemented - use HTTP client for outbound requests");

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += message.payload.len() as u64;

        Ok(())
    }

    async fn respond(&mut self, response: TransportMessage, original_metadata: &MessageMetadata) -> AsyncApiResult<()> {
        // For HTTP transport, responses are typically handled by the HTTP framework
        // This method is provided for compatibility but HTTP responses are usually
        // sent directly in the request handler context
        tracing::debug!(
            "HTTP transport respond called - correlation_id: {}, operation: {}",
            original_metadata.correlation_id,
            original_metadata.operation
        );

        // In a real HTTP implementation, this would store the response to be sent
        // back to the client when the HTTP request handler completes
        // For now, we'll just log and update stats
        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += response.payload.len() as u64;

        tracing::info!(
            "HTTP response prepared for correlation_id: {}, payload size: {} bytes",
            original_metadata.correlation_id,
            response.payload.len()
        );

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

impl Drop for HttpTransport {
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

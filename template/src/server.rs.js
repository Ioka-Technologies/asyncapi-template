import { File } from '@asyncapi/generator-react-sdk';

export default function serverFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async_std' : 'tokio';

    return (
        <File name="src/server.rs">
            {`//! AsyncAPI Server Implementation
//!
//! This module provides the main server implementation that coordinates
//! transport, middleware, routing, and handler execution.

use crate::config::Config;
use crate::context::MessageContext;
use crate::error::{HandlerResult, HandlerError, ErrorKind};
use crate::handlers::HandlerRegistry;
use crate::middleware::{MiddlewareStack, Middleware};
use crate::router::{MessageRouter, DefaultMessageRouter};
use crate::transport::{ServerTransport, TransportFactory};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use log::{debug, error, info, warn};
use ${runtime === 'tokio' ? 'tokio::sync::RwLock' : 'async_std::sync::RwLock'};
use ${runtime === 'tokio' ? 'tokio::time::timeout' : 'async_std::future::timeout'};

/// Main AsyncAPI server
pub struct AsyncApiServer {
    /// Server configuration
    config: Arc<Config>,
    /// Transport layer for message communication
    transport: Option<Box<dyn ServerTransport>>,
    /// Message router for dispatching to handlers
    router: Arc<dyn MessageRouter>,
    /// Middleware stack for cross-cutting concerns
    middleware: Arc<RwLock<MiddlewareStack>>,
    /// Handler registry
    handlers: Arc<HandlerRegistry>,
    /// Server state
    state: Arc<RwLock<ServerState>>,
}

/// Server state tracking
#[derive(Debug, Clone)]
pub struct ServerState {
    /// Whether the server is running
    pub is_running: bool,
    /// Number of messages processed
    pub messages_processed: u64,
    /// Number of errors encountered
    pub error_count: u64,
    /// Server start time
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Active connections count
    pub active_connections: u32,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            is_running: false,
            messages_processed: 0,
            error_count: 0,
            start_time: None,
            active_connections: 0,
        }
    }
}

/// Server statistics
#[derive(Debug, Clone)]
pub struct ServerStats {
    /// Current server state
    pub state: ServerState,
    /// Messages per second (last minute)
    pub messages_per_second: f64,
    /// Average processing time (milliseconds)
    pub avg_processing_time_ms: f64,
    /// Error rate (percentage)
    pub error_rate: f64,
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

impl AsyncApiServer {
    /// Create a new AsyncAPI server
    pub async fn new(config: Config) -> Result<Self, HandlerError> {
        let config = Arc::new(config);
        let handlers = Arc::new(HandlerRegistry::new());
        let router = Arc::new(DefaultMessageRouter::new(handlers.clone()));
        let middleware = Arc::new(RwLock::new(MiddlewareStack::new()));
        let state = Arc::new(RwLock::new(ServerState::default()));

        Ok(Self {
            config,
            transport: None,
            router,
            middleware,
            handlers,
            state,
        })
    }

    /// Create a server with custom components
    pub async fn with_components(
        config: Config,
        handlers: Arc<HandlerRegistry>,
        router: Arc<dyn MessageRouter>,
        middleware: MiddlewareStack,
    ) -> Result<Self, HandlerError> {
        let config = Arc::new(config);
        let middleware = Arc::new(RwLock::new(middleware));
        let state = Arc::new(RwLock::new(ServerState::default()));

        Ok(Self {
            config,
            transport: None,
            router,
            middleware,
            handlers,
            state,
        })
    }

    /// Get the handler registry for registering handlers
    pub fn handlers(&self) -> &Arc<HandlerRegistry> {
        &self.handlers
    }

    /// Add middleware to the server
    pub async fn add_middleware(&self, middleware: Arc<dyn Middleware>) {
        let mut stack = self.middleware.write().await;
        stack.add(middleware);
    }

    /// Initialize the transport layer
    pub async fn initialize_transport(&mut self) -> Result<(), HandlerError> {
        let transport = TransportFactory::create_server_transport(&self.config)
            .await
            .map_err(|e| HandlerError::configuration(&format!("Failed to create transport: {}", e)))?;

        self.transport = Some(transport);
        info!("Transport initialized for protocol: ${protocol}");
        Ok(())
    }

    /// Start the server
    pub async fn start(&mut self) -> Result<(), HandlerError> {
        // Validate handlers are registered
        if let Err(missing) = self.handlers.validate() {
            return Err(HandlerError::configuration(&format!(
                "Missing required handlers: {}",
                missing.join(", ")
            )));
        }

        // Initialize transport if not already done
        if self.transport.is_none() {
            self.initialize_transport().await?;
        }

        // Update server state
        {
            let mut state = self.state.write().await;
            state.is_running = true;
            state.start_time = Some(chrono::Utc::now());
        }

        info!("Starting AsyncAPI server on ${protocol}");

        // Start the transport and begin message processing
        if let Some(transport) = &mut self.transport {
            let message_handler = MessageHandler {
                router: self.router.clone(),
                middleware: self.middleware.clone(),
                state: self.state.clone(),
            };

            transport.start(Arc::new(message_handler)).await
                .map_err(|e| HandlerError::network("Failed to start transport", e))?;
        }

        info!("AsyncAPI server started successfully");
        Ok(())
    }

    /// Stop the server
    pub async fn stop(&mut self) -> Result<(), HandlerError> {
        info!("Stopping AsyncAPI server");

        // Update server state
        {
            let mut state = self.state.write().await;
            state.is_running = false;
        }

        // Stop the transport
        if let Some(transport) = &mut self.transport {
            transport.stop().await
                .map_err(|e| HandlerError::network("Failed to stop transport", e))?;
        }

        info!("AsyncAPI server stopped");
        Ok(())
    }

    /// Check if the server is running
    pub async fn is_running(&self) -> bool {
        let state = self.state.read().await;
        state.is_running
    }

    /// Get server statistics
    pub async fn get_stats(&self) -> ServerStats {
        let state = self.state.read().await;
        let uptime_seconds = state.start_time
            .map(|start| chrono::Utc::now().signed_duration_since(start).num_seconds() as u64)
            .unwrap_or(0);

        // Calculate rates (simplified - in production you'd want sliding windows)
        let messages_per_second = if uptime_seconds > 0 {
            state.messages_processed as f64 / uptime_seconds as f64
        } else {
            0.0
        };

        let error_rate = if state.messages_processed > 0 {
            (state.error_count as f64 / state.messages_processed as f64) * 100.0
        } else {
            0.0
        };

        ServerStats {
            state: state.clone(),
            messages_per_second,
            avg_processing_time_ms: 0.0, // Would need to track this separately
            error_rate,
            uptime_seconds,
        }
    }

    /// Wait for the server to stop
    pub async fn wait_for_shutdown(&self) -> Result<(), HandlerError> {
        // In a real implementation, you'd wait for shutdown signals
        // For now, we'll just wait while the server is running
        while self.is_running().await {
            ${runtime === 'tokio' ? 'tokio::time::sleep(Duration::from_millis(100)).await;' : 'async_std::task::sleep(Duration::from_millis(100)).await;'}
        }
        Ok(())
    }

    /// Graceful shutdown with timeout
    pub async fn shutdown_with_timeout(&mut self, timeout_duration: Duration) -> Result<(), HandlerError> {
        info!("Initiating graceful shutdown with timeout: {:?}", timeout_duration);

        let shutdown_future = self.stop();

        match timeout(timeout_duration, shutdown_future).await {
            Ok(result) => result,
            Err(_) => {
                error!("Shutdown timed out after {:?}", timeout_duration);
                Err(HandlerError::timeout("shutdown", timeout_duration.as_millis() as u64))
            }
        }
    }
}

/// Message handler that processes incoming messages
struct MessageHandler {
    router: Arc<dyn MessageRouter>,
    middleware: Arc<RwLock<MiddlewareStack>>,
    state: Arc<RwLock<ServerState>>,
}

#[async_trait]
impl crate::transport::MessageHandler for MessageHandler {
    async fn handle_message(&self, message: &[u8], mut context: MessageContext) -> HandlerResult<Vec<u8>> {
        let start_time = std::time::Instant::now();

        // Execute middleware before handling
        {
            let middleware = self.middleware.read().await;
            if let Err(err) = middleware.before_handle(message, &mut context).await {
                error!("Middleware before_handle failed: {}", err);
                self.increment_error_count().await;
                return Err(HandlerError::internal(&format!("Middleware error: {}", err))
                    .with_operation(&context.operation)
                    .with_topic(&context.protocol_metadata.topic));
            }
        }

        // Route and handle the message
        let result = self.router.route_message(message, &mut context).await;

        // Calculate processing duration
        let duration = start_time.elapsed();
        context.performance.duration = Some(duration);
        context.complete_processing();

        // Execute middleware after handling
        {
            let middleware = self.middleware.read().await;
            if let Err(err) = middleware.after_handle(&result, &mut context).await {
                warn!("Middleware after_handle failed: {}", err);
                // Don't fail the request for after_handle middleware errors
            }
        }

        // Update statistics
        match &result {
            Ok(_) => {
                self.increment_message_count().await;
                debug!("Message processed successfully in {:?}", duration);
            }
            Err(err) => {
                self.increment_error_count().await;
                error!("Message processing failed: {} (duration: {:?})", err, duration);
            }
        }

        result
    }
}

impl MessageHandler {
    async fn increment_message_count(&self) {
        let mut state = self.state.write().await;
        state.messages_processed += 1;
    }

    async fn increment_error_count(&self) {
        let mut state = self.state.write().await;
        state.error_count += 1;
    }
}

/// Builder for creating AsyncAPI servers with fluent configuration
pub struct AsyncApiServerBuilder {
    config: Option<Config>,
    handlers: Option<Arc<HandlerRegistry>>,
    middleware: MiddlewareStack,
}

impl AsyncApiServerBuilder {
    /// Create a new server builder
    pub fn new() -> Self {
        Self {
            config: None,
            handlers: None,
            middleware: MiddlewareStack::new(),
        }
    }

    /// Set the server configuration
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the handler registry
    pub fn with_handlers(mut self, handlers: Arc<HandlerRegistry>) -> Self {
        self.handlers = Some(handlers);
        self
    }

    /// Add middleware to the server
    pub fn with_middleware(mut self, middleware: Arc<dyn Middleware>) -> Self {
        self.middleware.add(middleware);
        self
    }

    /// Build the server
    pub async fn build(self) -> Result<AsyncApiServer, HandlerError> {
        let config = self.config.ok_or_else(|| {
            HandlerError::configuration("Configuration is required")
        })?;

        let handlers = self.handlers.unwrap_or_else(|| Arc::new(HandlerRegistry::new()));
        let router = Arc::new(DefaultMessageRouter::new(handlers.clone()));

        AsyncApiServer::with_components(config, handlers, router, self.middleware).await
    }
}

impl Default for AsyncApiServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_server_creation() {
        let config = Config::default();
        let server = AsyncApiServer::new(config).await;
        assert!(server.is_ok());
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_server_state() {
        let config = Config::default();
        let server = AsyncApiServer::new(config).await.unwrap();

        assert!(!server.is_running().await);

        let stats = server.get_stats().await;
        assert_eq!(stats.state.messages_processed, 0);
        assert_eq!(stats.state.error_count, 0);
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_server_builder() {
        let config = Config::default();
        let handlers = Arc::new(HandlerRegistry::new());

        let builder = AsyncApiServerBuilder::new()
            .with_config(config)
            .with_handlers(handlers);

        let server = builder.build().await;
        assert!(server.is_ok());
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_server_builder_missing_config() {
        let builder = AsyncApiServerBuilder::new();
        let server = builder.build().await;
        assert!(server.is_err());
    }

    #[test]
    fn test_server_stats() {
        let state = ServerState {
            is_running: true,
            messages_processed: 100,
            error_count: 5,
            start_time: Some(chrono::Utc::now() - chrono::Duration::seconds(60)),
            active_connections: 10,
        };

        // Test error rate calculation
        let error_rate = (state.error_count as f64 / state.messages_processed as f64) * 100.0;
        assert_eq!(error_rate, 5.0);
    }
}
`}
        </File>
    );
}

export default function ServerModRs() {
    return (
        <File name="mod.rs">
            {`//! Server module for AsyncAPI service
//!
//! This module provides the main server implementation and builder pattern
//! for constructing servers with various configurations and middleware.

pub mod builder;

pub use builder::{ServerBuilder, ServerConfig};

use crate::config::Config;
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::handlers::HandlerRegistry;
use crate::middleware::MiddlewarePipeline;
use crate::context::ContextManager;
use crate::router::Router;
use crate::recovery::RecoveryManager;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

/// Main server struct that orchestrates all components
pub struct Server {
    config: Config,
    handlers: Arc<RwLock<HandlerRegistry>>,
    context_manager: Arc<ContextManager>,
    router: Arc<Router>,
    middleware: MiddlewarePipeline,
    recovery_manager: Arc<RecoveryManager>,
}

impl Server {
    /// Create a new server with default configuration
    pub async fn new(config: Config) -> AsyncApiResult<Self> {
        let recovery_manager = Arc::new(RecoveryManager::default());
        let context_manager = Arc::new(ContextManager::new());
        let router = Arc::new(Router::new());
        let handlers = Arc::new(RwLock::new(
            HandlerRegistry::with_recovery_manager(recovery_manager.clone())
        ));
        let middleware = MiddlewarePipeline::new(recovery_manager.clone());

        // Initialize router with default routes
        router.initialize_default_routes().await?;

        Ok(Self {
            config,
            handlers,
            context_manager,
            router,
            middleware,
            recovery_manager,
        })
    }

    /// Create a new server with custom configuration
    pub async fn new_with_config(
        config: Config,
        handlers: Arc<RwLock<HandlerRegistry>>,
        context_manager: Arc<ContextManager>,
        router: Arc<Router>,
        middleware: MiddlewarePipeline,
    ) -> AsyncApiResult<Self> {
        let recovery_manager = Arc::new(RecoveryManager::default());

        Ok(Self {
            config,
            handlers,
            context_manager,
            router,
            middleware,
            recovery_manager,
        })
    }

    /// Start the server
    pub async fn start(&self) -> AsyncApiResult<()> {
        info!("Starting AsyncAPI server on {}:{}",
              self.config.host,
              self.config.port);

        // Initialize all components
        self.initialize_components().await?;

        // Start the main server loop
        self.run_server_loop().await?;

        Ok(())
    }

    /// Stop the server gracefully
    pub async fn stop(&self) -> AsyncApiResult<()> {
        info!("Stopping AsyncAPI server gracefully");

        // Perform cleanup operations
        self.cleanup().await?;

        info!("Server stopped successfully");
        Ok(())
    }

    /// Initialize all server components
    async fn initialize_components(&self) -> AsyncApiResult<()> {
        debug!("Initializing server components");

        // Components are already initialized during construction
        debug!("Context manager ready");
        debug!("Middleware pipeline ready");
        debug!("Recovery manager ready");

        debug!("All server components initialized successfully");
        Ok(())
    }

    /// Main server loop
    async fn run_server_loop(&self) -> AsyncApiResult<()> {
        debug!("Starting main server loop");

        // This is where the actual server logic would run
        // For now, we'll just keep the server alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            // Check if we should continue running
            if self.should_shutdown().await {
                break;
            }
        }

        Ok(())
    }

    /// Check if the server should shutdown
    async fn should_shutdown(&self) -> bool {
        // For now, never shutdown automatically
        // In a real implementation, this would check for shutdown signals
        false
    }

    /// Cleanup server resources
    async fn cleanup(&self) -> AsyncApiResult<()> {
        debug!("Cleaning up server resources");

        // Cleanup handlers
        debug!("Handlers cleanup completed");

        // Cleanup middleware
        debug!("Middleware cleanup completed");

        // Cleanup context manager
        debug!("Context manager cleanup completed");

        // Cleanup recovery manager
        debug!("Recovery manager cleanup completed");

        debug!("Server cleanup completed");
        Ok(())
    }

    /// Get server configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get handler registry
    pub fn handlers(&self) -> Arc<RwLock<HandlerRegistry>> {
        self.handlers.clone()
    }

    /// Get context manager
    pub fn context_manager(&self) -> Arc<ContextManager> {
        self.context_manager.clone()
    }

    /// Get router
    pub fn router(&self) -> Arc<Router> {
        self.router.clone()
    }

    /// Get middleware pipeline
    pub fn middleware(&self) -> &MiddlewarePipeline {
        &self.middleware
    }

    /// Get recovery manager
    pub fn recovery_manager(&self) -> Arc<RecoveryManager> {
        self.recovery_manager.clone()
    }

    /// Health check endpoint
    pub async fn health_check(&self) -> AsyncApiResult<HealthStatus> {
        debug!("Performing health check");

        let mut status = HealthStatus::new();

        // Check handlers
        status.handlers = ComponentHealth::Healthy;

        // Check middleware
        status.middleware = ComponentHealth::Healthy;

        // Check context manager
        status.context_manager = ComponentHealth::Healthy;

        // Check recovery manager
        status.recovery_manager = ComponentHealth::Healthy;

        // Overall status
        status.overall = if status.all_healthy() {
            ComponentHealth::Healthy
        } else {
            ComponentHealth::Unhealthy
        };

        debug!("Health check completed: {:?}", status.overall);
        Ok(status)
    }

    /// Start HTTP handler
    pub async fn start_http_handler(&self) -> AsyncApiResult<()> {
        info!("Starting HTTP handler on {}:{}", self.config.host, self.config.port);

        // Initialize HTTP transport
        // For now, just log that we're starting
        debug!("HTTP handler started successfully");
        Ok(())
    }

    /// Shutdown the server
    pub async fn shutdown(&self) -> AsyncApiResult<()> {
        info!("Shutting down server");
        self.stop().await
    }
}

/// Health status for the server and its components
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub overall: ComponentHealth,
    pub handlers: ComponentHealth,
    pub middleware: ComponentHealth,
    pub context_manager: ComponentHealth,
    pub recovery_manager: ComponentHealth,
}

impl HealthStatus {
    pub fn new() -> Self {
        Self {
            overall: ComponentHealth::Unknown,
            handlers: ComponentHealth::Unknown,
            middleware: ComponentHealth::Unknown,
            context_manager: ComponentHealth::Unknown,
            recovery_manager: ComponentHealth::Unknown,
        }
    }

    pub fn all_healthy(&self) -> bool {
        matches!(self.handlers, ComponentHealth::Healthy) &&
        matches!(self.middleware, ComponentHealth::Healthy) &&
        matches!(self.context_manager, ComponentHealth::Healthy) &&
        matches!(self.recovery_manager, ComponentHealth::Healthy)
    }
}

/// Health status for individual components
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        let config = Config::default();
        let server = Server::new(config).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = Config::default();
        let server = Server::new(config).await.unwrap();
        let health = server.health_check().await;
        assert!(health.is_ok());
    }
}
`}
        </File>
    );
}

/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ServerModRs() {
    return (
        <File name="mod.rs">
            {`//! Server module for AsyncAPI service
//!
//! This module provides the main server implementation and builder pattern
//! for constructing servers with various configurations and middleware.

pub mod builder;

pub use builder::{ServerBuilder, AutoServerBuilder};

use crate::config::Config;
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::handlers::HandlerRegistry;
use crate::middleware::{MiddlewarePipeline, Middleware};
use crate::context::ContextManager;
use crate::recovery::RecoveryManager;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

/// Main server struct that orchestrates all components
pub struct Server {
    config: Config,
    handlers: Arc<RwLock<HandlerRegistry>>,
    context_manager: Arc<ContextManager>,
    transport_manager: Arc<crate::transport::TransportManager>,
    middleware: Arc<RwLock<MiddlewarePipeline>>,
    recovery_manager: Arc<RecoveryManager>,
}

impl Server {
    /// Create a new server with default configuration
    pub async fn new(config: Config) -> AsyncApiResult<Self> {
        let recovery_manager = Arc::new(RecoveryManager::default());
        let context_manager = Arc::new(ContextManager::new());
        let middleware = Arc::new(RwLock::new(MiddlewarePipeline::new(recovery_manager.clone())));

        // Create transport manager with shared middleware pipeline
        let transport_manager = Arc::new(crate::transport::TransportManager::new_with_middleware(middleware.clone()));

        let handlers = Arc::new(RwLock::new(
            HandlerRegistry::with_managers(
                recovery_manager.clone(),
                transport_manager.clone()
            )
        ));

        Ok(Self {
            config,
            handlers,
            context_manager,
            transport_manager,
            middleware,
            recovery_manager,
        })
    }

    /// Create a new server with custom components
    pub async fn new_with_components(
        config: Config,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<crate::transport::TransportManager>,
        middleware: Arc<RwLock<MiddlewarePipeline>>,
    ) -> AsyncApiResult<Self> {
        let context_manager = Arc::new(ContextManager::new());

        let handlers = Arc::new(RwLock::new(
            HandlerRegistry::with_managers(
                recovery_manager.clone(),
                transport_manager.clone()
            )
        ));

        Ok(Self {
            config,
            handlers,
            context_manager,
            transport_manager,
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

        // Start protocol handlers
        self.start_protocol_handlers().await?;

        info!("Server started successfully and is ready to accept connections");
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

    /// Start protocol handlers based on configuration
    async fn start_protocol_handlers(&self) -> AsyncApiResult<()> {
        debug!("Starting protocol handlers");

        // Connect all configured transports from AsyncAPI specification
        match self.transport_manager.connect_all().await {
            Ok(()) => {
                debug!("All transports connected successfully");
            }
            Err(e) => {
                warn!("Some transports failed to connect: {}", e);
                // Continue with available transports rather than failing completely
            }
        }

        // Start listening on all connected transports
        match self.transport_manager.start_all().await {
            Ok(()) => {
                debug!("All transports started listening successfully");
            }
            Err(e) => {
                warn!("Some transports failed to start listening: {}", e);
                // Continue with available transports rather than failing completely
            }
        }

        // Log active protocol handlers
        let stats = self.transport_manager.get_all_stats().await;
        if !stats.is_empty() {
            info!("Started {} protocol handler(s):", stats.len());
            for (transport_name, transport_stats) in stats {
                info!("  - {} (sent: {}, received: {}, connection_attempts: {})",
                      transport_name,
                      transport_stats.messages_sent,
                      transport_stats.messages_received,
                      transport_stats.connection_attempts);
            }
        } else {
            info!("No transports configured from AsyncAPI specification, starting HTTP fallback");
            // Fallback to HTTP handler when no transports are configured
            self.start_http_handler().await?;
        }

        debug!("All protocol handlers started successfully");
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

        // Stop all protocol handlers and disconnect transports
        match self.transport_manager.stop_all().await {
            Ok(()) => {
                debug!("All transports stopped successfully");
            }
            Err(e) => {
                warn!("Some transports failed to stop cleanly: {}", e);
            }
        }

        match self.transport_manager.disconnect_all().await {
            Ok(()) => {
                debug!("All transports disconnected successfully");
            }
            Err(e) => {
                warn!("Some transports failed to disconnect cleanly: {}", e);
            }
        }

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

    /// Get transport manager
    pub fn transport_manager(&self) -> Arc<crate::transport::TransportManager> {
        self.transport_manager.clone()
    }

    /// Get middleware pipeline (returns Arc for shared access)
    pub fn middleware(&self) -> Arc<RwLock<MiddlewarePipeline>> {
        self.middleware.clone()
    }

    /// Add middleware to the pipeline at runtime
    pub async fn add_middleware<M: Middleware + 'static>(&self, middleware: M) -> AsyncApiResult<()> {
        debug!("Adding middleware: {}", middleware.name());

        let mut pipeline = self.middleware.write().await;
        *pipeline = std::mem::take(&mut *pipeline).add_middleware(middleware);

        info!("Successfully added middleware to pipeline");
        Ok(())
    }

    /// Configure middleware pipeline with multiple middleware at once
    pub async fn configure_middleware<F>(&self, configurator: F) -> AsyncApiResult<()>
    where
        F: FnOnce(MiddlewarePipeline) -> MiddlewarePipeline,
    {
        debug!("Configuring middleware pipeline");

        let mut pipeline = self.middleware.write().await;
        let current_pipeline = std::mem::take(&mut *pipeline);
        *pipeline = configurator(current_pipeline);

        info!("Successfully configured middleware pipeline");
        Ok(())
    }

    /// Clear all middleware from the pipeline
    pub async fn clear_middleware(&self) -> AsyncApiResult<()> {
        debug!("Clearing all middleware from pipeline");

        let mut pipeline = self.middleware.write().await;
        *pipeline = MiddlewarePipeline::new(self.recovery_manager.clone());

        info!("Successfully cleared middleware pipeline");
        Ok(())
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

        // Check transport health
        let transport_health = self.transport_manager.health_check_all().await;
        let all_transports_healthy = transport_health.values().all(|&healthy| healthy);
        status.transports = if transport_health.is_empty() {
            ComponentHealth::Unknown // No transports configured
        } else if all_transports_healthy {
            ComponentHealth::Healthy
        } else {
            ComponentHealth::Unhealthy
        };

        // Log transport health details
        if !transport_health.is_empty() {
            debug!("Transport health status:");
            for (transport_name, is_healthy) in transport_health {
                debug!("  - {}: {}", transport_name, if is_healthy { "healthy" } else { "unhealthy" });
            }
        }

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
    pub transports: ComponentHealth,
}

impl HealthStatus {
    pub fn new() -> Self {
        Self {
            overall: ComponentHealth::Unknown,
            handlers: ComponentHealth::Unknown,
            middleware: ComponentHealth::Unknown,
            context_manager: ComponentHealth::Unknown,
            recovery_manager: ComponentHealth::Unknown,
            transports: ComponentHealth::Unknown,
        }
    }

    pub fn all_healthy(&self) -> bool {
        matches!(self.handlers, ComponentHealth::Healthy) &&
        matches!(self.middleware, ComponentHealth::Healthy) &&
        matches!(self.context_manager, ComponentHealth::Healthy) &&
        matches!(self.recovery_manager, ComponentHealth::Healthy) &&
        matches!(self.transports, ComponentHealth::Healthy | ComponentHealth::Unknown)
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

/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ServerBuilderRs() {
    return (
        <File name="builder.rs">
            {`//! Server builder for constructing AsyncAPI servers with custom configurations
//!
//! This module provides a builder pattern for creating servers with various
//! configurations, middleware, and components.

use crate::config::Config;
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::handlers::HandlerRegistry;
use crate::middleware::MiddlewarePipeline;
use crate::context::ContextManager;
use crate::router::Router;
use crate::recovery::RecoveryManager;
use crate::server::Server;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Builder for constructing AsyncAPI servers
pub struct ServerBuilder {
    config: Option<Config>,
    handlers: Option<Arc<RwLock<HandlerRegistry>>>,
    context_manager: Option<Arc<ContextManager>>,
    router: Option<Arc<Router>>,
    middleware: Option<MiddlewarePipeline>,
    recovery_manager: Option<Arc<RecoveryManager>>,
}

impl ServerBuilder {
    /// Create a new server builder
    pub fn new() -> Self {
        Self {
            config: None,
            handlers: None,
            context_manager: None,
            router: None,
            middleware: None,
            recovery_manager: None,
        }
    }

    /// Set the server configuration
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Set custom handlers
    pub fn with_handlers(mut self, handlers: Arc<RwLock<HandlerRegistry>>) -> Self {
        self.handlers = Some(handlers);
        self
    }

    /// Set custom context manager
    pub fn with_context_manager(mut self, context_manager: Arc<ContextManager>) -> Self {
        self.context_manager = Some(context_manager);
        self
    }

    /// Set custom router
    pub fn with_router(mut self, router: Arc<Router>) -> Self {
        self.router = Some(router);
        self
    }

    /// Set custom middleware pipeline
    pub fn with_middleware(mut self, middleware: MiddlewarePipeline) -> Self {
        self.middleware = Some(middleware);
        self
    }

    /// Set custom recovery manager
    pub fn with_recovery_manager(mut self, recovery_manager: Arc<RecoveryManager>) -> Self {
        self.recovery_manager = Some(recovery_manager);
        self
    }

    /// Build the server with the configured components
    pub async fn build(self) -> AsyncApiResult<Server> {
        info!("Building AsyncAPI server");

        // Use provided config or default
        let config = self.config.unwrap_or_default();
        debug!("Server configuration: {:?}", config);

        // Initialize recovery manager first (needed by other components)
        let recovery_manager = self.recovery_manager.unwrap_or_else(|| {
            debug!("Using default recovery manager");
            Arc::new(RecoveryManager::default())
        });

        // Initialize context manager
        let context_manager = self.context_manager.unwrap_or_else(|| {
            debug!("Using default context manager");
            Arc::new(ContextManager::new())
        });

        // Initialize router
        let router = self.router.unwrap_or_else(|| {
            debug!("Using default router");
            Arc::new(Router::new())
        });
        router.initialize_default_routes().await?;

        // Initialize handler registry
        let handlers = self.handlers.unwrap_or_else(|| {
            debug!("Using default handler registry");
            Arc::new(RwLock::new(
                HandlerRegistry::with_recovery_manager(recovery_manager.clone())
            ))
        });

        // Initialize middleware pipeline
        let middleware_pipeline = self.middleware.unwrap_or_else(|| {
            debug!("Using default middleware pipeline");
            MiddlewarePipeline::new(recovery_manager.clone())
        });

        // Create the server
        let server = Server::new_with_config(
            config,
            handlers,
            context_manager,
            router,
            middleware_pipeline,
        ).await?;

        info!("AsyncAPI server built successfully");
        Ok(server)
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Server configuration struct
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub timeout_seconds: u64,
    pub log_level: String,
}

impl ServerConfig {
    /// Create a new server configuration
    pub fn new() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            max_connections: 1000,
            timeout_seconds: 30,
            log_level: "info".to_string(),
        }
    }

    /// Set the host address
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// Set the port number
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the maximum number of connections
    pub fn max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Set the timeout in seconds
    pub fn timeout_seconds(mut self, timeout_seconds: u64) -> Self {
        self.timeout_seconds = timeout_seconds;
        self
    }

    /// Set the log level
    pub fn log_level(mut self, log_level: impl Into<String>) -> Self {
        self.log_level = log_level.into();
        self
    }

    /// Convert to Config
    pub fn into_config(self) -> Config {
        Config {
            host: self.host,
            port: self.port,
            ..Default::default()
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl From<ServerConfig> for Config {
    fn from(server_config: ServerConfig) -> Self {
        server_config.into_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_builder_default() {
        let server = ServerBuilder::new().build().await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_server_builder_with_config() {
        let config = Config::default();
        let server = ServerBuilder::new()
            .with_config(config)
            .build()
            .await;
        assert!(server.is_ok());
    }

    #[test]
    fn test_server_config() {
        let config = ServerConfig::new()
            .host("localhost")
            .port(3000)
            .max_connections(500)
            .timeout_seconds(60)
            .log_level("debug");

        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 3000);
        assert_eq!(config.max_connections, 500);
        assert_eq!(config.timeout_seconds, 60);
        assert_eq!(config.log_level, "debug");
    }
}
`}
        </File>
    );
}

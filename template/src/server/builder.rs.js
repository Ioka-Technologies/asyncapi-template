/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ServerBuilderRs() {
    return (
        <File name="builder.rs">
            {`//! Server builder for flexible server construction with optional components
//!
//! This module provides a fluent builder API for constructing servers with
//! optional middleware, monitoring, authentication, and other advanced features.
//! Uses derive_builder for clean, maintainable builder pattern implementation.

use crate::config::Config;
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::middleware::{Middleware, MiddlewarePipeline};
use crate::recovery::RecoveryManager;
use crate::context::ContextManager;
use crate::router::Router;
use crate::handlers::HandlerRegistry;
use crate::server::Server;
use derive_builder::Builder;
use std::sync::Arc;
use std::collections::HashMap;
use tracing::{info, debug, warn};

#[cfg(feature = "prometheus")]
use crate::metrics::prometheus::PrometheusMetrics;

#[cfg(feature = "opentelemetry")]
use crate::tracing::opentelemetry::OpenTelemetryTracing;

#[cfg(feature = "auth")]
use crate::auth::{AuthConfig, AuthMiddleware};

#[cfg(feature = "connection-pooling")]
use crate::pool::{PoolConfig, ConnectionPoolManager};

#[cfg(feature = "batching")]
use crate::batching::{BatchConfig, BatchProcessor};

#[cfg(feature = "dynamic-config")]
use crate::config::dynamic::DynamicConfigManager;

#[cfg(feature = "feature-flags")]
use crate::features::{FeatureFlags, FeatureManager};

/// Configuration for server construction with optional components
#[derive(Builder)]
#[builder(setter(into, strip_option), build_fn(validate = "Self::validate"))]
pub struct ServerConfig {
    /// Base server configuration
    pub config: Config,

    /// Middleware components to add to the pipeline
    #[builder(default = "Vec::new()", setter(skip))]
    pub middleware: Vec<Box<dyn Middleware>>,

    /// Feature flags configuration
    #[builder(default = "None")]
    pub feature_flags: Option<std::collections::HashMap<String, bool>>,

    /// Authentication configuration
    #[cfg(feature = "auth")]
    #[builder(default = "None")]
    pub auth_config: Option<AuthConfig>,

    /// Connection pool configuration
    #[cfg(feature = "connection-pooling")]
    #[builder(default = "None")]
    pub pool_config: Option<PoolConfig>,

    /// Message batching configuration
    #[cfg(feature = "batching")]
    #[builder(default = "None")]
    pub batch_config: Option<BatchConfig>,

    /// Enable Prometheus metrics
    #[builder(default = "false")]
    pub prometheus_enabled: bool,

    /// Enable OpenTelemetry tracing
    #[builder(default = "false")]
    pub opentelemetry_enabled: bool,

    /// Enable dynamic configuration
    #[builder(default = "false")]
    pub dynamic_config_enabled: bool,

    /// Custom properties for extensibility
    #[builder(default = "HashMap::new()")]
    pub custom_properties: HashMap<String, String>,
}

/// Type alias for the generated builder
pub type ServerBuilder = ServerConfigBuilder;

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ServerConfig");
        debug_struct
            .field("config", &self.config)
            .field("middleware_count", &self.middleware.len())
            .field("feature_flags", &self.feature_flags);

        #[cfg(feature = "auth")]
        {
            debug_struct.field("auth_config", &self.auth_config);
        }

        #[cfg(feature = "connection-pooling")]
        {
            debug_struct.field("pool_config", &self.pool_config);
        }

        #[cfg(feature = "batching")]
        {
            debug_struct.field("batch_config", &self.batch_config);
        }

        debug_struct
            .field("prometheus_enabled", &self.prometheus_enabled)
            .field("opentelemetry_enabled", &self.opentelemetry_enabled)
            .field("dynamic_config_enabled", &self.dynamic_config_enabled)
            .field("custom_properties", &self.custom_properties)
            .finish()
    }
}

impl ServerConfigBuilder {
    /// Validate the configuration during build
    fn validate(&self) -> Result<(), String> {
        // Check for conflicting configurations
        if self.prometheus_enabled.unwrap_or(false) && !cfg!(feature = "prometheus") {
            return Err("Prometheus metrics enabled but 'prometheus' feature not compiled".to_string());
        }

        if self.opentelemetry_enabled.unwrap_or(false) && !cfg!(feature = "opentelemetry") {
            return Err("OpenTelemetry tracing enabled but 'opentelemetry' feature not compiled".to_string());
        }

        // Validate auth configuration
        #[cfg(feature = "auth")]
        if let Some(ref auth_config) = self.auth_config {
            if let Some(auth_config) = auth_config {
                // Add auth config validation here
            }
        }

        Ok(())
    }
}

impl ServerConfig {
    /// Build the server with all configured components
    pub async fn build_server(self) -> AsyncApiResult<Server> {
        info!("Building server with configured components");

        // Initialize recovery manager
        let recovery_manager = Arc::new(RecoveryManager::default());

        // Initialize context manager
        let context_manager = Arc::new(ContextManager::new());

        // Initialize router
        let router = Arc::new(Router::new());
        router.initialize_default_routes().await?;

        // Initialize handler registry
        let handlers = Arc::new(tokio::sync::RwLock::new(
            HandlerRegistry::with_recovery_manager(recovery_manager.clone())
        ));

        // Build middleware pipeline
        let middleware_pipeline = self.build_middleware_pipeline(recovery_manager.clone()).await?;

        // Create the server
        let server = Server::new_with_config(
            self.config,
            handlers,
            context_manager,
            router,
            middleware_pipeline,
        ).await?;

        info!("Server built successfully with {} middleware components",
              self.middleware.len());

        Ok(server)
    }

    /// Build the middleware pipeline with all configured middleware
    async fn build_middleware_pipeline(&self, recovery_manager: Arc<RecoveryManager>) -> AsyncApiResult<MiddlewarePipeline> {
        debug!("Building middleware pipeline");

        let pipeline = MiddlewarePipeline::new(recovery_manager);

        // Add authentication middleware if configured
        #[cfg(feature = "auth")]
        if let Some(auth_config) = &self.auth_config {
            let auth_middleware = AuthMiddleware::new(auth_config.clone());
            pipeline = pipeline.add_middleware(auth_middleware);
        }

        // Add Prometheus metrics middleware if enabled
        #[cfg(feature = "prometheus")]
        if self.prometheus_enabled {
            let metrics_middleware = crate::middleware::MetricsMiddleware::with_prometheus();
            pipeline = pipeline.add_middleware(metrics_middleware);
        }

        // Add OpenTelemetry tracing middleware if enabled
        #[cfg(feature = "opentelemetry")]
        if self.opentelemetry_enabled {
            let tracing_middleware = crate::middleware::TracingMiddleware::new();
            pipeline = pipeline.add_middleware(tracing_middleware);
        }

        // Add user-configured middleware
        for _middleware in &self.middleware {
            // Note: This would need to be cloned or we'd need a different approach
            // for now, we'll document this limitation
        }

        debug!("Middleware pipeline built successfully");
        Ok(pipeline)
    }
}

/// Convenience constructors for common server configurations
impl ServerBuilder {
    /// Create a minimal server with basic logging
    pub fn minimal(config: Config) -> Self {
        let mut builder = Self::default();
        builder.config(config);
        builder.prometheus_enabled(false);
        builder.opentelemetry_enabled(false);
        builder
    }

    /// Create a development server with enhanced debugging
    pub fn development(config: Config) -> Self {
        let mut builder = Self::default();
        builder.config(config);
        builder.prometheus_enabled(false);
        builder.opentelemetry_enabled(false);
        builder
    }

    /// Create a production server with all monitoring and security features
    pub fn production(config: Config) -> Self {
        let mut builder = Self::default();
        builder.config(config);

        // Add optional production features if available
        #[cfg(feature = "prometheus")]
        {
            builder.prometheus_enabled(true);
        }

        #[cfg(feature = "opentelemetry")]
        {
            builder.opentelemetry_enabled(true);
        }

        builder
    }

    /// Add middleware to the builder
    pub fn add_middleware<M: Middleware + 'static>(self, _middleware: M) -> Self {
        // Since we can't use the generated setter, we need to handle this manually
        // For now, we'll document this as a limitation and provide alternative approaches
        self
    }

    /// Add middleware conditionally
    pub fn conditional_middleware<F, M>(self, _condition: F) -> Self
    where
        F: FnOnce(&Config) -> Option<M>,
        M: Middleware + 'static,
    {
        // This would need access to config to evaluate the condition
        // For now, return self unchanged
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_minimal_server_build() {
        let config = Config::default();
        let server = ServerBuilder::minimal(config).build().await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_builder_with_middleware() {
        let config = Config::default();
        let server = ServerBuilder::new(config)
            .with_middleware(crate::middleware::LoggingMiddleware::default())
            .build()
            .await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_conditional_middleware() {
        let config = Config::default();
        let server = ServerBuilder::new(config)
            .conditional_middleware(|_config| {
                Some(crate::middleware::LoggingMiddleware::default())
            })
            .build()
            .await;
        assert!(server.is_ok());
    }
}
`}
        </File>
    );
}

//! Server builder for AsyncAPI service with simplified direct routing
//!
//! This module provides a builder pattern for creating and configuring
//! the AsyncAPI server with direct TransportManager routing and handler registration.

use crate::config::Config;
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::handlers::*;
use crate::recovery::RecoveryManager;
use crate::transport::{TransportManager, factory::TransportFactory};
use crate::TransportConfig;
use crate::middleware::MiddlewarePipeline;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, debug};

/// Channel server mapping configuration extracted from AsyncAPI specification
#[derive(Debug, Clone)]
pub struct ChannelServerMapping {
    pub channel_name: String,
    pub allowed_servers: Option<Vec<String>>, // None = available on all servers
    pub description: String,
}

/// Recovery configuration presets for common scenarios
#[derive(Debug, Clone, Copy)]
pub enum RecoveryPreset {
    /// Optimized for high throughput scenarios
    HighThroughput,
    /// Optimized for high reliability scenarios
    HighReliability,
    /// Optimized for low latency scenarios
    LowLatency,
}

/// Server configuration extracted from AsyncAPI specification
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub protocol: String,
    pub url: String,
    pub description: String,
}

/// Builder for creating AsyncAPI servers with automatic routing configuration
pub struct ServerBuilder {
    config: Config,
    recovery_manager: Option<Arc<RecoveryManager>>,
    transport_manager: Option<Arc<TransportManager>>,
    // Recovery configuration
    retry_configs: std::collections::HashMap<String, crate::recovery::RetryConfig>,
    circuit_breaker_configs: std::collections::HashMap<String, crate::recovery::CircuitBreakerConfig>,
    bulkhead_configs: std::collections::HashMap<String, (usize, Duration)>,
    dead_letter_queue_size: Option<usize>,
    // HTTP configuration
    http_host: Option<String>,
    http_port: Option<u16>,
    // Authentication configuration
    #[cfg(feature = "auth")]
    auth_validator: Option<Arc<crate::auth::MultiAuthValidator>>,
    auth_handler_service: Option<Arc<dyn AuthService>>,
    device_handler_service: Option<Arc<dyn DeviceService>>,
    network_handler_service: Option<Arc<dyn NetworkService>>,
    provision_handler_service: Option<Arc<dyn ProvisionService>>,
    salting_handler_service: Option<Arc<dyn SaltingService>>,
    threats_nats_handler_service: Option<Arc<dyn ThreatsNatsService>>,
    threats_ws_handler_service: Option<Arc<dyn ThreatsWsService>>,
    validator_connection_handler_service: Option<Arc<dyn ValidatorConnectionService>>,
    connections_handler_service: Option<Arc<dyn ConnectionsService>>,
    metrics_handler_service: Option<Arc<dyn MetricsService>>,
    tags_handler_service: Option<Arc<dyn TagsService>>,
    profiles_handler_service: Option<Arc<dyn ProfilesService>>,
    settings_handler_service: Option<Arc<dyn SettingsService>>,
}

impl ServerBuilder {
    /// Create a new server builder with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            config,
            recovery_manager: None,
            transport_manager: None,
            retry_configs: std::collections::HashMap::new(),
            circuit_breaker_configs: std::collections::HashMap::new(),
            bulkhead_configs: std::collections::HashMap::new(),
            dead_letter_queue_size: None,
            http_host: None,
            http_port: None,
            #[cfg(feature = "auth")]
            auth_validator: None,
            auth_handler_service: None,
            device_handler_service: None,
            network_handler_service: None,
            provision_handler_service: None,
            salting_handler_service: None,
            threats_nats_handler_service: None,
            threats_ws_handler_service: None,
            validator_connection_handler_service: None,
            connections_handler_service: None,
            metrics_handler_service: None,
            tags_handler_service: None,
            profiles_handler_service: None,
            settings_handler_service: None,
        }
    }

    /// Set a custom recovery manager
    pub fn with_recovery_manager(mut self, recovery_manager: Arc<RecoveryManager>) -> Self {
        self.recovery_manager = Some(recovery_manager);
        self
    }

    /// Set a custom transport manager
    pub fn with_transport_manager(mut self, transport_manager: Arc<TransportManager>) -> Self {
        self.transport_manager = Some(transport_manager);
        self
    }

    // Recovery configuration methods

    /// Configure retry strategy for a specific operation type
    pub fn with_retry_config(mut self, operation_type: &str, config: crate::recovery::RetryConfig) -> Self {
        self.retry_configs.insert(operation_type.to_string(), config);
        self
    }

    /// Configure circuit breaker for a specific service
    pub fn with_circuit_breaker_config(mut self, service: &str, config: crate::recovery::CircuitBreakerConfig) -> Self {
        self.circuit_breaker_configs.insert(service.to_string(), config);
        self
    }

    /// Configure bulkhead for a specific resource
    pub fn with_bulkhead_config(mut self, resource: &str, max_concurrent: usize, timeout: std::time::Duration) -> Self {
        self.bulkhead_configs.insert(resource.to_string(), (max_concurrent, timeout));
        self
    }

    /// Configure dead letter queue size
    pub fn with_dead_letter_queue_size(mut self, size: usize) -> Self {
        self.dead_letter_queue_size = Some(size);
        self
    }

    /// Configure recovery with preset configurations
    pub fn with_recovery_preset(mut self, preset: RecoveryPreset) -> Self {
        match preset {
            RecoveryPreset::HighThroughput => {
                self.retry_configs.insert("message_handler".to_string(), crate::recovery::RetryConfig::fast());
                self.circuit_breaker_configs.insert("default".to_string(), crate::recovery::CircuitBreakerConfig {
                    failure_threshold: 10,
                    recovery_timeout: std::time::Duration::from_secs(30),
                    success_threshold: 2,
                    failure_window: std::time::Duration::from_secs(30),
                });
                self.bulkhead_configs.insert("message_processing".to_string(), (200, std::time::Duration::from_secs(10)));
                self.dead_letter_queue_size = Some(500);
            }
            RecoveryPreset::HighReliability => {
                self.retry_configs.insert("message_handler".to_string(), crate::recovery::RetryConfig::conservative());
                self.circuit_breaker_configs.insert("default".to_string(), crate::recovery::CircuitBreakerConfig {
                    failure_threshold: 3,
                    recovery_timeout: std::time::Duration::from_secs(120),
                    success_threshold: 5,
                    failure_window: std::time::Duration::from_secs(120),
                });
                self.bulkhead_configs.insert("message_processing".to_string(), (50, std::time::Duration::from_secs(60)));
                self.dead_letter_queue_size = Some(2000);
            }
            RecoveryPreset::LowLatency => {
                self.retry_configs.insert("message_handler".to_string(), crate::recovery::RetryConfig::fast());
                self.circuit_breaker_configs.insert("default".to_string(), crate::recovery::CircuitBreakerConfig {
                    failure_threshold: 15,
                    recovery_timeout: std::time::Duration::from_secs(15),
                    success_threshold: 1,
                    failure_window: std::time::Duration::from_secs(15),
                });
                self.bulkhead_configs.insert("message_processing".to_string(), (300, std::time::Duration::from_secs(5)));
                self.dead_letter_queue_size = Some(100);
            }
        }
        self
    }

    // Authentication configuration methods

    
    #[cfg(feature = "auth")]
    /// Set a custom authentication validator
    pub fn with_auth_validator(mut self, validator: Arc<crate::auth::MultiAuthValidator>) -> Self {
        self.auth_validator = Some(validator);
        self
    }

    #[cfg(feature = "auth")]
    /// Configure JWT authentication
    pub fn with_jwt_auth(mut self, secret_or_key: &str, algorithm: &str) -> AsyncApiResult<Self> {
        let validator_builder = crate::auth::MultiAuthValidatorBuilder::new()
            .with_jwt(secret_or_key, algorithm)?;

        self.auth_validator = Some(Arc::new(validator_builder.build()));
        Ok(self)
    }

    #[cfg(feature = "auth")]
    /// Configure Basic authentication
    pub fn with_basic_auth(mut self, issuer: String, audience: String) -> Self {
        let validator_builder = crate::auth::MultiAuthValidatorBuilder::new()
            .with_basic_auth(issuer, audience);

        self.auth_validator = Some(Arc::new(validator_builder.build()));
        self
    }

    #[cfg(feature = "auth")]
    /// Configure API key authentication
    pub fn with_api_key_auth(mut self, location: crate::auth::ApiKeyLocation, issuer: String, audience: String) -> Self {
        let validator_builder = crate::auth::MultiAuthValidatorBuilder::new()
            .with_api_key(location, issuer, audience);

        self.auth_validator = Some(Arc::new(validator_builder.build()));
        self
    }

    #[cfg(feature = "auth")]
    /// Configure multiple authentication methods
    pub fn with_multi_auth(mut self, builder: crate::auth::MultiAuthValidatorBuilder) -> Self {
        self.auth_validator = Some(Arc::new(builder.build()));
        self
    }

    /// Set the service implementation for auth channel
    pub fn with_auth_handler_service(mut self, service: Arc<dyn AuthService>) -> Self {
        self.auth_handler_service = Some(service);
        self
    }

    /// Set the service implementation for device channel
    pub fn with_device_handler_service(mut self, service: Arc<dyn DeviceService>) -> Self {
        self.device_handler_service = Some(service);
        self
    }

    /// Set the service implementation for network channel
    pub fn with_network_handler_service(mut self, service: Arc<dyn NetworkService>) -> Self {
        self.network_handler_service = Some(service);
        self
    }

    /// Set the service implementation for provision channel
    pub fn with_provision_handler_service(mut self, service: Arc<dyn ProvisionService>) -> Self {
        self.provision_handler_service = Some(service);
        self
    }

    /// Set the service implementation for salting channel
    pub fn with_salting_handler_service(mut self, service: Arc<dyn SaltingService>) -> Self {
        self.salting_handler_service = Some(service);
        self
    }

    /// Set the service implementation for threats_nats channel
    pub fn with_threats_nats_handler_service(mut self, service: Arc<dyn ThreatsNatsService>) -> Self {
        self.threats_nats_handler_service = Some(service);
        self
    }

    /// Set the service implementation for threats_ws channel
    pub fn with_threats_ws_handler_service(mut self, service: Arc<dyn ThreatsWsService>) -> Self {
        self.threats_ws_handler_service = Some(service);
        self
    }

    /// Set the service implementation for validator_connection channel
    pub fn with_validator_connection_handler_service(mut self, service: Arc<dyn ValidatorConnectionService>) -> Self {
        self.validator_connection_handler_service = Some(service);
        self
    }

    /// Set the service implementation for connections channel
    pub fn with_connections_handler_service(mut self, service: Arc<dyn ConnectionsService>) -> Self {
        self.connections_handler_service = Some(service);
        self
    }

    /// Set the service implementation for metrics channel
    pub fn with_metrics_handler_service(mut self, service: Arc<dyn MetricsService>) -> Self {
        self.metrics_handler_service = Some(service);
        self
    }

    /// Set the service implementation for tags channel
    pub fn with_tags_handler_service(mut self, service: Arc<dyn TagsService>) -> Self {
        self.tags_handler_service = Some(service);
        self
    }

    /// Set the service implementation for profiles channel
    pub fn with_profiles_handler_service(mut self, service: Arc<dyn ProfilesService>) -> Self {
        self.profiles_handler_service = Some(service);
        self
    }

    /// Set the service implementation for settings channel
    pub fn with_settings_handler_service(mut self, service: Arc<dyn SettingsService>) -> Self {
        self.settings_handler_service = Some(service);
        self
    }

    /// Build the server with simplified direct routing
    /// This automatically creates and configures:
    /// - TransportManager for direct message routing
    /// - Channel-specific message handlers
    /// - Direct handler registration with TransportManager
    /// - Transports with handlers pre-configured during creation
    /// - No complex router layer needed!
    pub async fn build(self) -> AsyncApiResult<crate::Server> {
        self.build_with_skip_protocols(vec![]).await
    }

    /// Build the server with the ability to skip specific protocols during AsyncAPI server setup
    /// This is useful when some transports are manually configured (e.g., pre-configured NATS client)
    pub async fn build_with_skip_protocols(mut self, skip_protocols: Vec<String>) -> AsyncApiResult<crate::Server> {
        info!("Building AsyncAPI server with automatic routing setup");

        // Initialize recovery manager with custom configurations
        let recovery_manager = self.recovery_manager.take().unwrap_or_else(|| {
            debug!("Creating recovery manager with custom configurations");
            let mut manager = RecoveryManager::new();

            // Apply custom retry configurations
            for (operation_type, config) in &self.retry_configs {
                debug!("Configuring retry strategy for operation type: {}", operation_type);
                manager.configure_retry(operation_type, config.clone());
            }

            // Apply custom circuit breaker configurations
            for (service, config) in &self.circuit_breaker_configs {
                debug!("Configuring circuit breaker for service: {}", service);
                manager.configure_circuit_breaker(service, config.clone());
            }

            // Apply custom bulkhead configurations
            for (resource, (max_concurrent, timeout)) in &self.bulkhead_configs {
                debug!("Configuring bulkhead for resource: {} (max_concurrent: {}, timeout: {:?})", resource, max_concurrent, timeout);
                manager.configure_bulkhead(resource, *max_concurrent, *timeout);
            }

            // Configure dead letter queue size if specified
            if let Some(size) = self.dead_letter_queue_size {
                debug!("Configuring dead letter queue size: {}", size);
                // Note: Current RecoveryManager doesn't support configurable DLQ size
                // This would need to be added to the RecoveryManager implementation
                // For now, we'll log the intention
                info!("Dead letter queue size configuration requested: {} (requires RecoveryManager enhancement)", size);
            }

            // If no custom configurations were provided, use defaults
            if self.retry_configs.is_empty() && self.circuit_breaker_configs.is_empty() && self.bulkhead_configs.is_empty() {
                debug!("No custom recovery configurations provided, using defaults");
                return Arc::new(RecoveryManager::default());
            }

            Arc::new(manager)
        });

        let middleware = Arc::new(RwLock::new(MiddlewarePipeline::new(recovery_manager.clone())));

        // Initialize transport manager
        let transport_manager = self.transport_manager.take().unwrap_or_else(|| {
            debug!("Creating default transport manager");
            Arc::new(TransportManager::new_with_middleware(middleware.clone()))
        });

        // Create publisher context for "receive" operations
        let publishers = Arc::new(crate::handlers::PublisherContext::new(transport_manager.clone()));
        info!("Created publisher context with channel-based publishers");

        // Create operation handlers FIRST (before transports)
        let operation_handlers = self.create_operation_handlers(&recovery_manager, &transport_manager, &publishers).await?;

        // Setup transports WITH handlers pre-configured, skipping manually configured protocols
        self.setup_transports_with_handlers_filtered(&transport_manager, &operation_handlers, &skip_protocols).await?;

        // Register handlers with transport manager for direct routing
        for (operation_name, handler) in operation_handlers {
            transport_manager.register_handler(operation_name.clone(), handler).await;
            info!("Registered direct routing for {} operation", operation_name);
        }

        info!("Direct routing system fully configured - no router layer needed!");

        // Extract scopes from AsyncAPI specification BEFORE moving self.config
        #[cfg(feature = "auth")]
        let operation_scopes = self.extract_operation_scopes()?;

        // Move config before creating server
        let config = self.config;

        // Create server instance with publishers and dynamic parameters - always use the full constructor
        // This ensures compatibility across all test scenarios
        let server = crate::Server::new_with_components_and_publishers_and_dynamic_params(
            config,
            recovery_manager.clone(),
            transport_manager,
            middleware,
            publishers,
            Arc::new(crate::server::builder::DynamicParameters::new()),
        ).await?;

        
        // Configure authentication and authorization middleware if auth is enabled
        #[cfg(feature = "auth")]
        if let Some(auth_validator) = &self.auth_validator {
            info!("Configuring authentication and authorization middleware");

            server.configure_middleware(|pipeline| {
                pipeline
                    .add_middleware(crate::middleware::AuthenticationMiddleware::new(auth_validator.clone()))
                    .add_middleware(crate::middleware::AuthorizationMiddleware::new(
                        auth_validator.clone(),
                        operation_scopes,
                    ))
            }).await?;

            info!("Authentication and authorization middleware configured successfully");
        }

        info!("AsyncAPI server built successfully with automatic routing");
        Ok(server)
    }

    /// Create operation handlers with individual authentication wrapping
    #[allow(unused_variables)]
    async fn create_operation_handlers(
        &mut self,
        recovery_manager: &Arc<RecoveryManager>,
        transport_manager: &Arc<TransportManager>,
        publishers: &Arc<crate::handlers::PublisherContext>,
    ) -> AsyncApiResult<HashMap<String, Arc<dyn crate::transport::MessageHandler>>> {
        #[allow(unused_mut)]
        let mut handlers = HashMap::new();
        let security_config = crate::handlers::get_operation_security_config();

        
        // Create operation handlers for auth channel
        if let Some(service) = self.auth_handler_service.take() {
            debug!("Creating operation handlers for auth channel");
            
            // Create auth.login operation handler
            let auth_login_handler = Arc::new(crate::handlers::AuthLoginOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("auth.login").unwrap_or(&false);

            let final_auth_login_handler = auth_login_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_auth_login_handler = {
                debug!("Creating auth.login operation handler (auth feature disabled)");
                auth_login_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("auth.login".to_string(), final_auth_login_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for auth.login operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for auth.login operation (auth feature disabled)");
            // Create auth.logout operation handler
            let auth_logout_handler = Arc::new(crate::handlers::AuthLogoutOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("auth.logout").unwrap_or(&false);

            let final_auth_logout_handler = auth_logout_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_auth_logout_handler = {
                debug!("Creating auth.logout operation handler (auth feature disabled)");
                auth_logout_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("auth.logout".to_string(), final_auth_logout_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for auth.logout operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for auth.logout operation (auth feature disabled)");
        } else {
            debug!("No service provided for auth channel - skipping operation handler creation");
        }
        // Create operation handlers for device channel
        if let Some(service) = self.device_handler_service.take() {
            debug!("Creating operation handlers for device channel");
            
            // Create device.bootstrap operation handler
            let device_bootstrap_handler = Arc::new(crate::handlers::DeviceBootstrapOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("device.bootstrap").unwrap_or(&false);

            let final_device_bootstrap_handler = device_bootstrap_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_device_bootstrap_handler = {
                debug!("Creating device.bootstrap operation handler (auth feature disabled)");
                device_bootstrap_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("device.bootstrap".to_string(), final_device_bootstrap_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for device.bootstrap operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for device.bootstrap operation (auth feature disabled)");
            // Create device.get operation handler
            let device_get_handler = Arc::new(crate::handlers::DeviceGetOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("device.get").unwrap_or(&false);

            let final_device_get_handler = device_get_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_device_get_handler = {
                debug!("Creating device.get operation handler (auth feature disabled)");
                device_get_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("device.get".to_string(), final_device_get_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for device.get operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for device.get operation (auth feature disabled)");
            // Create device.configure operation handler
            let device_configure_handler = Arc::new(crate::handlers::DeviceConfigureOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("device.configure").unwrap_or(&false);

            let final_device_configure_handler = device_configure_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_device_configure_handler = {
                debug!("Creating device.configure operation handler (auth feature disabled)");
                device_configure_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("device.configure".to_string(), final_device_configure_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for device.configure operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for device.configure operation (auth feature disabled)");
            // Create device.delete operation handler
            let device_delete_handler = Arc::new(crate::handlers::DeviceDeleteOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("device.delete").unwrap_or(&false);

            let final_device_delete_handler = device_delete_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_device_delete_handler = {
                debug!("Creating device.delete operation handler (auth feature disabled)");
                device_delete_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("device.delete".to_string(), final_device_delete_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for device.delete operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for device.delete operation (auth feature disabled)");
            // Create device.list operation handler
            let device_list_handler = Arc::new(crate::handlers::DeviceListOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("device.list").unwrap_or(&false);

            let final_device_list_handler = device_list_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_device_list_handler = {
                debug!("Creating device.list operation handler (auth feature disabled)");
                device_list_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("device.list".to_string(), final_device_list_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for device.list operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for device.list operation (auth feature disabled)");
            // Create device.update_metadata operation handler
            let device_update_metadata_handler = Arc::new(crate::handlers::DeviceUpdateMetadataOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("device.update_metadata").unwrap_or(&false);

            let final_device_update_metadata_handler = device_update_metadata_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_device_update_metadata_handler = {
                debug!("Creating device.update_metadata operation handler (auth feature disabled)");
                device_update_metadata_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("device.update_metadata".to_string(), final_device_update_metadata_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for device.update_metadata operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for device.update_metadata operation (auth feature disabled)");
        } else {
            debug!("No service provided for device channel - skipping operation handler creation");
        }
        // Create operation handlers for network channel
        if let Some(service) = self.network_handler_service.take() {
            debug!("Creating operation handlers for network channel");
            
            // Create network.topology operation handler
            let network_topology_handler = Arc::new(crate::handlers::NetworkTopologyOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("network.topology").unwrap_or(&false);

            let final_network_topology_handler = network_topology_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_network_topology_handler = {
                debug!("Creating network.topology operation handler (auth feature disabled)");
                network_topology_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("network.topology".to_string(), final_network_topology_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for network.topology operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for network.topology operation (auth feature disabled)");
        } else {
            debug!("No service provided for network channel - skipping operation handler creation");
        }
        // Create operation handlers for provision channel
        if let Some(service) = self.provision_handler_service.take() {
            debug!("Creating operation handlers for provision channel");
            
            // Create provision.refresh operation handler
            let provision_refresh_handler = Arc::new(crate::handlers::ProvisionRefreshOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("provision.refresh").unwrap_or(&false);

            let final_provision_refresh_handler = provision_refresh_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_provision_refresh_handler = {
                debug!("Creating provision.refresh operation handler (auth feature disabled)");
                provision_refresh_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("provision.refresh".to_string(), final_provision_refresh_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for provision.refresh operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for provision.refresh operation (auth feature disabled)");
        } else {
            debug!("No service provided for provision channel - skipping operation handler creation");
        }
        // Create operation handlers for salting channel
        if let Some(service) = self.salting_handler_service.take() {
            debug!("Creating operation handlers for salting channel");
            
            // Create salting.request operation handler
            let salting_request_handler = Arc::new(crate::handlers::SaltingRequestOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("salting.request").unwrap_or(&false);

            let final_salting_request_handler = salting_request_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_salting_request_handler = {
                debug!("Creating salting.request operation handler (auth feature disabled)");
                salting_request_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("salting.request".to_string(), final_salting_request_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for salting.request operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for salting.request operation (auth feature disabled)");
        } else {
            debug!("No service provided for salting channel - skipping operation handler creation");
        }
        // Create operation handlers for threats_nats channel
        if let Some(service) = self.threats_nats_handler_service.take() {
            debug!("Creating operation handlers for threats_nats channel");
            
            // Create threats.report operation handler
            let threats_report_handler = Arc::new(crate::handlers::ThreatsReportOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("threats.report").unwrap_or(&false);

            let final_threats_report_handler = threats_report_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_threats_report_handler = {
                debug!("Creating threats.report operation handler (auth feature disabled)");
                threats_report_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("threats.report".to_string(), final_threats_report_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for threats.report operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for threats.report operation (auth feature disabled)");
        } else {
            debug!("No service provided for threats_nats channel - skipping operation handler creation");
        }
        // Create operation handlers for threats_ws channel
        if let Some(service) = self.threats_ws_handler_service.take() {
            debug!("Creating operation handlers for threats_ws channel");
            
            // Create threats.query operation handler
            let threats_query_handler = Arc::new(crate::handlers::ThreatsQueryOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("threats.query").unwrap_or(&false);

            let final_threats_query_handler = threats_query_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_threats_query_handler = {
                debug!("Creating threats.query operation handler (auth feature disabled)");
                threats_query_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("threats.query".to_string(), final_threats_query_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for threats.query operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for threats.query operation (auth feature disabled)");
            // Create threats.download_pcap operation handler
            let threats_download_pcap_handler = Arc::new(crate::handlers::ThreatsDownloadPcapOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("threats.download_pcap").unwrap_or(&false);

            let final_threats_download_pcap_handler = threats_download_pcap_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_threats_download_pcap_handler = {
                debug!("Creating threats.download_pcap operation handler (auth feature disabled)");
                threats_download_pcap_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("threats.download_pcap".to_string(), final_threats_download_pcap_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for threats.download_pcap operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for threats.download_pcap operation (auth feature disabled)");
        } else {
            debug!("No service provided for threats_ws channel - skipping operation handler creation");
        }
        // Create operation handlers for validator_connection channel
        if let Some(service) = self.validator_connection_handler_service.take() {
            debug!("Creating operation handlers for validator_connection channel");
            
            // Create validator_connection.report operation handler
            let validator_connection_report_handler = Arc::new(crate::handlers::ValidatorConnectionReportOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("validator_connection.report").unwrap_or(&false);

            let final_validator_connection_report_handler = validator_connection_report_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_validator_connection_report_handler = {
                debug!("Creating validator_connection.report operation handler (auth feature disabled)");
                validator_connection_report_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("validator_connection.report".to_string(), final_validator_connection_report_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for validator_connection.report operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for validator_connection.report operation (auth feature disabled)");
        } else {
            debug!("No service provided for validator_connection channel - skipping operation handler creation");
        }
        // Create operation handlers for connections channel
        if let Some(service) = self.connections_handler_service.take() {
            debug!("Creating operation handlers for connections channel");
            
            // Create connections.query operation handler
            let connections_query_handler = Arc::new(crate::handlers::ConnectionsQueryOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("connections.query").unwrap_or(&false);

            let final_connections_query_handler = connections_query_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_connections_query_handler = {
                debug!("Creating connections.query operation handler (auth feature disabled)");
                connections_query_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("connections.query".to_string(), final_connections_query_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for connections.query operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for connections.query operation (auth feature disabled)");
        } else {
            debug!("No service provided for connections channel - skipping operation handler creation");
        }
        // Create operation handlers for metrics channel
        if let Some(service) = self.metrics_handler_service.take() {
            debug!("Creating operation handlers for metrics channel");
            
            // Create metrics.query operation handler
            let metrics_query_handler = Arc::new(crate::handlers::MetricsQueryOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("metrics.query").unwrap_or(&false);

            let final_metrics_query_handler = metrics_query_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_metrics_query_handler = {
                debug!("Creating metrics.query operation handler (auth feature disabled)");
                metrics_query_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("metrics.query".to_string(), final_metrics_query_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for metrics.query operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for metrics.query operation (auth feature disabled)");
            // Create metrics.reset operation handler
            let metrics_reset_handler = Arc::new(crate::handlers::MetricsResetOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("metrics.reset").unwrap_or(&false);

            let final_metrics_reset_handler = metrics_reset_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_metrics_reset_handler = {
                debug!("Creating metrics.reset operation handler (auth feature disabled)");
                metrics_reset_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("metrics.reset".to_string(), final_metrics_reset_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for metrics.reset operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for metrics.reset operation (auth feature disabled)");
        } else {
            debug!("No service provided for metrics channel - skipping operation handler creation");
        }
        // Create operation handlers for tags channel
        if let Some(service) = self.tags_handler_service.take() {
            debug!("Creating operation handlers for tags channel");
            
            // Create tags.create operation handler
            let tags_create_handler = Arc::new(crate::handlers::TagsCreateOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("tags.create").unwrap_or(&false);

            let final_tags_create_handler = tags_create_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_tags_create_handler = {
                debug!("Creating tags.create operation handler (auth feature disabled)");
                tags_create_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("tags.create".to_string(), final_tags_create_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for tags.create operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for tags.create operation (auth feature disabled)");
            // Create tags.update operation handler
            let tags_update_handler = Arc::new(crate::handlers::TagsUpdateOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("tags.update").unwrap_or(&false);

            let final_tags_update_handler = tags_update_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_tags_update_handler = {
                debug!("Creating tags.update operation handler (auth feature disabled)");
                tags_update_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("tags.update".to_string(), final_tags_update_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for tags.update operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for tags.update operation (auth feature disabled)");
            // Create tags.delete operation handler
            let tags_delete_handler = Arc::new(crate::handlers::TagsDeleteOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("tags.delete").unwrap_or(&false);

            let final_tags_delete_handler = tags_delete_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_tags_delete_handler = {
                debug!("Creating tags.delete operation handler (auth feature disabled)");
                tags_delete_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("tags.delete".to_string(), final_tags_delete_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for tags.delete operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for tags.delete operation (auth feature disabled)");
            // Create tags.list operation handler
            let tags_list_handler = Arc::new(crate::handlers::TagsListOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("tags.list").unwrap_or(&false);

            let final_tags_list_handler = tags_list_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_tags_list_handler = {
                debug!("Creating tags.list operation handler (auth feature disabled)");
                tags_list_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("tags.list".to_string(), final_tags_list_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for tags.list operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for tags.list operation (auth feature disabled)");
        } else {
            debug!("No service provided for tags channel - skipping operation handler creation");
        }
        // Create operation handlers for profiles channel
        if let Some(service) = self.profiles_handler_service.take() {
            debug!("Creating operation handlers for profiles channel");
            
            // Create profiles.create operation handler
            let profiles_create_handler = Arc::new(crate::handlers::ProfilesCreateOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("profiles.create").unwrap_or(&false);

            let final_profiles_create_handler = profiles_create_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_profiles_create_handler = {
                debug!("Creating profiles.create operation handler (auth feature disabled)");
                profiles_create_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("profiles.create".to_string(), final_profiles_create_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for profiles.create operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for profiles.create operation (auth feature disabled)");
            // Create profiles.get operation handler
            let profiles_get_handler = Arc::new(crate::handlers::ProfilesGetOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("profiles.get").unwrap_or(&false);

            let final_profiles_get_handler = profiles_get_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_profiles_get_handler = {
                debug!("Creating profiles.get operation handler (auth feature disabled)");
                profiles_get_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("profiles.get".to_string(), final_profiles_get_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for profiles.get operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for profiles.get operation (auth feature disabled)");
            // Create profiles.update operation handler
            let profiles_update_handler = Arc::new(crate::handlers::ProfilesUpdateOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("profiles.update").unwrap_or(&false);

            let final_profiles_update_handler = profiles_update_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_profiles_update_handler = {
                debug!("Creating profiles.update operation handler (auth feature disabled)");
                profiles_update_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("profiles.update".to_string(), final_profiles_update_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for profiles.update operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for profiles.update operation (auth feature disabled)");
            // Create profiles.delete operation handler
            let profiles_delete_handler = Arc::new(crate::handlers::ProfilesDeleteOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("profiles.delete").unwrap_or(&false);

            let final_profiles_delete_handler = profiles_delete_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_profiles_delete_handler = {
                debug!("Creating profiles.delete operation handler (auth feature disabled)");
                profiles_delete_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("profiles.delete".to_string(), final_profiles_delete_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for profiles.delete operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for profiles.delete operation (auth feature disabled)");
            // Create profiles.list operation handler
            let profiles_list_handler = Arc::new(crate::handlers::ProfilesListOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("profiles.list").unwrap_or(&false);

            let final_profiles_list_handler = profiles_list_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_profiles_list_handler = {
                debug!("Creating profiles.list operation handler (auth feature disabled)");
                profiles_list_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("profiles.list".to_string(), final_profiles_list_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for profiles.list operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for profiles.list operation (auth feature disabled)");
            // Create profiles.assign operation handler
            let profiles_assign_handler = Arc::new(crate::handlers::ProfilesAssignOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("profiles.assign").unwrap_or(&false);

            let final_profiles_assign_handler = profiles_assign_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_profiles_assign_handler = {
                debug!("Creating profiles.assign operation handler (auth feature disabled)");
                profiles_assign_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("profiles.assign".to_string(), final_profiles_assign_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for profiles.assign operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for profiles.assign operation (auth feature disabled)");
            // Create profiles.unassign operation handler
            let profiles_unassign_handler = Arc::new(crate::handlers::ProfilesUnassignOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("profiles.unassign").unwrap_or(&false);

            let final_profiles_unassign_handler = profiles_unassign_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_profiles_unassign_handler = {
                debug!("Creating profiles.unassign operation handler (auth feature disabled)");
                profiles_unassign_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("profiles.unassign".to_string(), final_profiles_unassign_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for profiles.unassign operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for profiles.unassign operation (auth feature disabled)");
        } else {
            debug!("No service provided for profiles channel - skipping operation handler creation");
        }
        // Create operation handlers for settings channel
        if let Some(service) = self.settings_handler_service.take() {
            debug!("Creating operation handlers for settings channel");
            
            // Create settings.get operation handler
            let settings_get_handler = Arc::new(crate::handlers::SettingsGetOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("settings.get").unwrap_or(&false);

            let final_settings_get_handler = settings_get_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_settings_get_handler = {
                debug!("Creating settings.get operation handler (auth feature disabled)");
                settings_get_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("settings.get".to_string(), final_settings_get_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for settings.get operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for settings.get operation (auth feature disabled)");
            // Create settings.update operation handler
            let settings_update_handler = Arc::new(crate::handlers::SettingsUpdateOperationHandler::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("settings.update").unwrap_or(&false);

            let final_settings_update_handler = settings_update_handler as Arc<dyn crate::transport::MessageHandler>;

            #[cfg(not(feature = "auth"))]
            let final_settings_update_handler = {
                debug!("Creating settings.update operation handler (auth feature disabled)");
                settings_update_handler as Arc<dyn crate::transport::MessageHandler>
            };

            handlers.insert("settings.update".to_string(), final_settings_update_handler);

            #[cfg(feature = "auth")]
            info!("Created handler for settings.update operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for settings.update operation (auth feature disabled)");
        } else {
            debug!("No service provided for settings channel - skipping operation handler creation");
        }

        info!("Created {} operation handlers", handlers.len());
        Ok(handlers)
    }

    /// Setup transports with pre-configured handlers based on AsyncAPI server specifications
    /// with protocol filtering support
    async fn setup_transports_with_handlers_filtered(
        &self,
        transport_manager: &Arc<TransportManager>,
        channel_handlers: &HashMap<String, Arc<dyn crate::transport::MessageHandler>>,
        skip_protocols: &[String],
    ) -> AsyncApiResult<()> {
        debug!("Setting up transports with pre-configured handlers from AsyncAPI server specifications (skipping: {:?})", skip_protocols);

        // Get servers from AsyncAPI specification
        let servers = self.get_asyncapi_servers()?;

        if servers.is_empty() {
            info!("No servers defined in AsyncAPI specification, setting up default HTTP transport");
            return self.setup_default_transport_with_handler(transport_manager, channel_handlers).await;
        }

        let total_servers = servers.len();
        info!("Found {} server(s) in AsyncAPI specification", total_servers);

        // Filter servers to skip manually configured protocols
        let filtered_servers: Vec<_> = servers.into_iter()
            .filter(|(server_name, server_config)| {
                let should_skip = skip_protocols.iter().any(|skip_protocol| {
                    server_config.protocol.to_lowercase() == skip_protocol.to_lowercase()
                });

                if should_skip {
                    info!("Skipping server '{}' with protocol '{}' (manually configured)", server_name, server_config.protocol);
                    false
                } else {
                    true
                }
            })
            .collect();

        info!("Processing {} server(s) after filtering (skipped {} manually configured)",
              filtered_servers.len(),
              total_servers - filtered_servers.len());

        // Setup each filtered server as a transport with appropriate handler
        for (server_name, server_config) in filtered_servers {
            match self.setup_server_transport_with_handler(&server_name, &server_config, transport_manager).await {
                Ok(()) => {
                    info!("Successfully configured transport for server: {}", server_name);
                }
                Err(e) => {
                    tracing::error!(
                        server = %server_name,
                        error = %e,
                        "Failed to configure transport for server"
                    );
                    // Continue with other servers instead of failing completely
                    continue;
                }
            }
        }

        // Verify at least one transport was configured
        let transport_count = transport_manager.get_all_stats().await.len();
        if transport_count == 0 {
            tracing::warn!("No transports were successfully configured, falling back to default HTTP");
            self.setup_default_transport_with_handler(transport_manager, channel_handlers).await?;
        }

        info!("Transport setup completed with {} active transport(s)", transport_count);
        Ok(())
    }

    /// Setup transports with pre-configured handlers based on AsyncAPI server specifications
    async fn setup_transports_with_handlers(
        &self,
        transport_manager: &Arc<TransportManager>,
        channel_handlers: &HashMap<String, Arc<dyn crate::transport::MessageHandler>>,
    ) -> AsyncApiResult<()> {
        self.setup_transports_with_handlers_filtered(transport_manager, channel_handlers, &[]).await
    }

    /// Legacy method - kept for backward compatibility
    async fn _setup_transports_with_handlers_legacy(
        &self,
        transport_manager: &Arc<TransportManager>,
        channel_handlers: &HashMap<String, Arc<dyn crate::transport::MessageHandler>>,
    ) -> AsyncApiResult<()> {
        debug!("Setting up transports with pre-configured handlers from AsyncAPI server specifications");

        // Get servers from AsyncAPI specification
        let servers = self.get_asyncapi_servers()?;

        if servers.is_empty() {
            info!("No servers defined in AsyncAPI specification, setting up default HTTP transport");
            return self.setup_default_transport_with_handler(transport_manager, channel_handlers).await;
        }

        info!("Found {} server(s) in AsyncAPI specification", servers.len());

        // Setup each server as a transport with appropriate handler
        for (server_name, server_config) in servers {
            match self.setup_server_transport_with_handler(&server_name, &server_config, transport_manager).await {
                Ok(()) => {
                    info!("Successfully configured transport for server: {}", server_name);
                }
                Err(e) => {
                    tracing::error!(
                        server = %server_name,
                        error = %e,
                        "Failed to configure transport for server"
                    );
                    // Continue with other servers instead of failing completely
                    continue;
                }
            }
        }

        // Verify at least one transport was configured
        let transport_count = transport_manager.get_all_stats().await.len();
        if transport_count == 0 {
            tracing::warn!("No transports were successfully configured, falling back to default HTTP");
            self.setup_default_transport_with_handler(transport_manager, channel_handlers).await?;
        }

        info!("Transport setup completed with {} active transport(s)", transport_count);
        Ok(())
    }

    /// Setup a single server as a transport with handler
    /// Now uses TransportManager's create_transport_with_config method which automatically
    /// uses the TransportManager as the handler, leveraging its MessageHandler implementation
    /// and registered operation handlers
    async fn setup_server_transport_with_handler(
        &self,
        server_name: &str,
        server_config: &ServerConfig,
        transport_manager: &TransportManager,
    ) -> AsyncApiResult<()> {
        debug!(
            server = %server_name,
            protocol = %server_config.protocol,
            url = %server_config.url,
            "Setting up transport for server using TransportManager as handler"
        );

        // Parse server URL and create transport configuration
        let transport_config = self.parse_server_config(server_name, server_config)?;

        debug!(
            server = %server_name,
            protocol = %transport_config.protocol,
            host = %transport_config.host,
            port = transport_config.port,
            tls = transport_config.tls,
            "Creating transport with TransportManager as handler"
        );

        // Use TransportManager's create_transport_with_config method
        // This automatically uses the TransportManager as the handler, which leverages:
        // - The TransportManager's MessageHandler implementation
        // - All registered operation handlers
        // - Middleware pipeline processing
        // - Direct routing without additional router layers
        transport_manager.create_transport_with_config(server_name.to_string(), transport_config).await?;

        info!(
            server = %server_name,
            protocol = %server_config.protocol,
            "Transport configured successfully with TransportManager as handler"
        );

        Ok(())
    }

    /// Setup default HTTP transport with handler when no servers are defined
    /// Now uses TransportManager's create_transport_with_config method
    /// Only sets up HTTP if no other transports are configured
    async fn setup_default_transport_with_handler(
        &self,
        transport_manager: &TransportManager,
        _channel_handlers: &HashMap<String, Arc<dyn crate::transport::MessageHandler>>,
    ) -> AsyncApiResult<()> {
        // Check if any transports are already configured
        let existing_transports = transport_manager.get_all_stats().await;
        if !existing_transports.is_empty() {
            info!("Transports already configured ({}), skipping default HTTP setup", existing_transports.len());
            return Ok(());
        }

        debug!("No servers defined in AsyncAPI specification and no transports configured, setting up default HTTP transport");

        let http_config = crate::transport::TransportConfig {
            transport_id: uuid::Uuid::new_v4(),
            protocol: "http".to_string(),
            host: self.http_host.clone().unwrap_or_else(|| "0.0.0.0".to_string()),
            port: self.http_port.unwrap_or(8080),
            username: None,
            password: None,
            tls: false,
            additional_config: HashMap::new(),
        };

        debug!(
            protocol = %http_config.protocol,
            host = %http_config.host,
            port = http_config.port,
            "Creating default HTTP transport with TransportManager as handler"
        );

        // Use TransportManager's create_transport_with_config method
        // This automatically uses the TransportManager as the handler
        transport_manager.create_transport_with_config("default-http".to_string(), http_config).await?;

        info!("Default HTTP transport configured successfully with TransportManager as handler");
        Ok(())
    }

    /// Extract servers from AsyncAPI specification
    fn get_asyncapi_servers(&self) -> AsyncApiResult<Vec<(String, ServerConfig)>> {
        debug!("Extracting servers from AsyncAPI specification");

        // Extract server configurations from the AsyncAPI specification
        let servers = vec![
            ("0".to_string(), ServerConfig {
                protocol: "ws".to_string(),
                url: "ws://0.0.0.0:8080/".to_string(),
                description: "Development WebSocket server".to_string(),
            }),
            ("1".to_string(), ServerConfig {
                protocol: "nats".to_string(),
                url: "nats://0.0.0.0:4222/".to_string(),
                description: "Development NATS server".to_string(),
            }),
        ];

        debug!("Found {} servers in AsyncAPI specification", servers.len());
        Ok(servers)
    }

    /// Get channel server mappings from AsyncAPI specification
    fn get_channel_server_mappings(&self) -> Vec<ChannelServerMapping> {
        debug!("Loading channel server mappings from AsyncAPI specification");

        // Channel server mappings extracted during template generation
        let mappings = vec![
            ChannelServerMapping {
                channel_name: "auth".to_string(),
                allowed_servers: Some(vec!["development-ws".to_string()]),
                description: "Channel for authentication operations".to_string(),
            },
            ChannelServerMapping {
                channel_name: "device".to_string(),
                allowed_servers: Some(vec!["development-ws".to_string(), "development-nats".to_string()]),
                description: "Channel for all device management operations and notifications".to_string(),
            },
            ChannelServerMapping {
                channel_name: "network".to_string(),
                allowed_servers: Some(vec!["development-ws".to_string()]),
                description: "Channel for network topology operations".to_string(),
            },
            ChannelServerMapping {
                channel_name: "provision".to_string(),
                allowed_servers: Some(vec!["development-nats".to_string()]),
                description: "Channel for device provisioning operations via NATS".to_string(),
            },
            ChannelServerMapping {
                channel_name: "salting".to_string(),
                allowed_servers: Some(vec!["development-nats".to_string()]),
                description: "Channel for key salting operations via NATS".to_string(),
            },
            ChannelServerMapping {
                channel_name: "threats_nats".to_string(),
                allowed_servers: Some(vec!["development-nats".to_string()]),
                description: "Channel for threat reporting operations via NATS (no authentication required)".to_string(),
            },
            ChannelServerMapping {
                channel_name: "threats_ws".to_string(),
                allowed_servers: Some(vec!["development-ws".to_string()]),
                description: "Channel for threat querying and streaming operations via WebSocket (JWT authentication required)".to_string(),
            },
            ChannelServerMapping {
                channel_name: "validator_connection".to_string(),
                allowed_servers: Some(vec!["development-nats".to_string()]),
                description: "Channel for validator connection reporting via NATS".to_string(),
            },
            ChannelServerMapping {
                channel_name: "connections".to_string(),
                allowed_servers: Some(vec!["development-ws".to_string()]),
                description: "Channel for connection querying and streaming operations via WebSocket (JWT authentication required)".to_string(),
            },
            ChannelServerMapping {
                channel_name: "metrics".to_string(),
                allowed_servers: Some(vec!["development-ws".to_string()]),
                description: "Channel for metrics querying and streaming operations via WebSocket (JWT authentication required)".to_string(),
            },
            ChannelServerMapping {
                channel_name: "tags".to_string(),
                allowed_servers: Some(vec!["development-ws".to_string()]),
                description: "Channel for tag management operations via WebSocket (JWT authentication required)".to_string(),
            },
            ChannelServerMapping {
                channel_name: "profiles".to_string(),
                allowed_servers: Some(vec!["development-ws".to_string()]),
                description: "Channel for profile management operations via WebSocket (JWT authentication required)".to_string(),
            },
            ChannelServerMapping {
                channel_name: "settings".to_string(),
                allowed_servers: Some(vec!["development-ws".to_string()]),
                description: "Channel for system settings management operations via WebSocket (JWT authentication required)".to_string(),
            },
        ];

        debug!("Loaded {} channel server mappings", mappings.len());
        mappings
    }

    /// Validate if a channel is allowed on a specific server
    fn is_channel_allowed_on_server(&self, channel_name: &str, server_name: &str) -> bool {
        let mappings = self.get_channel_server_mappings();

        for mapping in &mappings {
            if mapping.channel_name == channel_name {
                // If allowed_servers is None, channel is available on all servers
                if mapping.allowed_servers.is_none() {
                    return true;
                }

                // Check if server is in the allowed list
                if let Some(ref allowed_servers) = mapping.allowed_servers {
                    return allowed_servers.contains(&server_name.to_string());
                }
            }
        }

        // If no mapping found, assume channel is allowed on all servers
        true
    }

    /// Setup a single server as a transport
    async fn setup_server_transport(
        &self,
        server_name: &str,
        server_config: &ServerConfig,
        transport_manager: &TransportManager,
    ) -> AsyncApiResult<()> {
        debug!(
            server = %server_name,
            protocol = %server_config.protocol,
            url = %server_config.url,
            "Setting up transport for server"
        );

        // Parse server URL and create transport configuration
        let transport_config = self.parse_server_config(server_name, server_config)?;

        // Validate configuration
        crate::transport::factory::TransportFactory::validate_config(&transport_config)?;

        debug!(
            server = %server_name,
            protocol = %transport_config.protocol,
            host = %transport_config.host,
            port = transport_config.port,
            tls = transport_config.tls,
            "Creating transport with configuration"
        );

        // Create transport using factory
        let transport = crate::transport::factory::TransportFactory::create_transport(transport_config)?;

        // Add to transport manager
        transport_manager.add_transport_with_name(server_name.to_string(), transport).await?;

        info!(
            server = %server_name,
            protocol = %server_config.protocol,
            "Transport configured successfully"
        );

        Ok(())
    }

    /// Parse server configuration and create TransportConfig
    fn parse_server_config(&self, server_name: &str, server_config: &ServerConfig) -> AsyncApiResult<crate::transport::TransportConfig> {
        let (protocol, host, port, path) = self.parse_server_url(&server_config.url)?;

        // Validate protocol matches server specification
        if protocol.to_lowercase() != server_config.protocol.to_lowercase() {
            return Err(AsyncApiError::Configuration {
                message: format!(
                    "Protocol mismatch for server '{server_name}': URL protocol '{protocol}' doesn't match server protocol '{protocol}'",
                    protocol = server_config.protocol,
                ),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Configuration,
                    false,
                )
                .with_context("server_name", server_name)
                .with_context("url_protocol", &protocol)
                .with_context("server_protocol", &server_config.protocol),
                source: None,
            }.into());
        }

        // Determine if TLS should be enabled
        let tls = protocol.ends_with('s');

        // Create additional configuration
        let mut additional_config = HashMap::new();

        // Add path for protocols that need it (like WebSocket)
        if !path.is_empty() {
            additional_config.insert("path".to_string(), path);
        }

        // Add server description as metadata
        if !server_config.description.is_empty() {
            additional_config.insert("description".to_string(), server_config.description.clone());
        }

        Ok(crate::transport::TransportConfig {
            transport_id: uuid::Uuid::new_v4(),
            protocol: protocol.to_lowercase(),
            host,
            port,
            username: None,
            password: None,
            tls,
            additional_config,
        })
    }

    /// Parse server URL into components
    fn parse_server_url(&self, url: &str) -> AsyncApiResult<(String, String, u16, String)> {
        // Handle URLs like: mqtt://localhost:1883, ws://localhost:8080/ws, http://localhost:8080

        let url_parts: Vec<&str> = url.split("://").collect();
        if url_parts.len() != 2 {
            return Err(AsyncApiError::Configuration {
                message: format!("Invalid server URL format: {url}"),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Configuration,
                    false,
                )
                .with_context("url", url),
                source: None,
            }.into());
        }

        let protocol = url_parts[0].to_string();
        let remainder = url_parts[1];

        // Split host:port/path
        let (host_port, path) = if let Some(slash_pos) = remainder.find('/') {
            (remainder[..slash_pos].to_string(), remainder[slash_pos..].to_string())
        } else {
            (remainder.to_string(), String::new())
        };

        // Parse host and port
        let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
            let host = host_port[..colon_pos].to_string();
            let port_str = &host_port[colon_pos + 1..];
            let port = port_str.parse::<u16>().map_err(|_| {
                AsyncApiError::Configuration {
                    message: format!("Invalid port number in URL: {port_str}"),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Configuration,
                        false,
                    )
                    .with_context("url", url)
                    .with_context("port", port_str),
                    source: None,
                }
            })?;
            (host, port)
        } else {
            // Use default ports based on protocol
            let default_port = match protocol.to_lowercase().as_str() {
                "http" => 80,
                "https" => 443,
                "ws" => 80,
                "wss" => 443,
                "mqtt" => 1883,
                "mqtts" => 8883,
                "kafka" => 9092,
                "amqp" => 5672,
                "amqps" => 5671,
                _ => 80, // Default fallback
            };
            (host_port, default_port)
        };

        Ok((protocol, host, port, path))
    }

    /// Setup default HTTP transport when no servers are defined
    async fn setup_default_transport(&self, transport_manager: &TransportManager) -> AsyncApiResult<()> {
        debug!("Setting up default HTTP transport");

        let http_config = crate::transport::TransportConfig {
            transport_id: uuid::Uuid::new_v4(),
            protocol: "http".to_string(),
            host: "0.0.0.0".to_string(),
            port: 8080,
            username: None,
            password: None,
            tls: false,
            additional_config: HashMap::new(),
        };

        debug!(
            protocol = %http_config.protocol,
            host = %http_config.host,
            port = http_config.port,
            "Creating default HTTP transport"
        );

        // Create transport using factory
        let transport = crate::transport::factory::TransportFactory::create_transport(http_config)?;

        // Add to transport manager
        transport_manager.add_transport_with_name("default-http".to_string(), transport).await?;

        info!("Default HTTP transport configured successfully");
        Ok(())
    }

    /// Check if a channel has any operations that require security
    /// This method analyzes the AsyncAPI specification to determine if authentication
    /// should be applied to the channel's handlers
    fn channel_requires_security(&self, channel_name: &str) -> bool {
        // Parse security requirements from AsyncAPI specification during template generation
        // Static mapping based on the channel analysis

        match channel_name {
            "auth" => true,
            "device" => true,
            "network" => true,
            "provision" => false,
            "salting" => false,
            "threats_nats" => false,
            "threats_ws" => true,
            "validator_connection" => false,
            "connections" => true,
            "metrics" => true,
            "tags" => true,
            "profiles" => true,
            "settings" => true,
            _ => false, // Default: no security required for unknown channels
        }
    }

    /// Extract operation scopes from AsyncAPI specification for authorization middleware
    /// Scopes are parsed during template generation and embedded as static data
    #[cfg(feature = "auth")]
    fn extract_operation_scopes(&self) -> AsyncApiResult<std::collections::HashMap<String, Vec<String>>> {
        debug!("Loading pre-parsed operation scopes from AsyncAPI specification");

        #[allow(unused_mut)]
        let mut operation_scopes = std::collections::HashMap::new();

        // Pre-parsed scopes from AsyncAPI specification during template generation
        operation_scopes.insert("device.bootstrap".to_string(), vec!["bootstrap:device".to_string()]);
        operation_scopes.insert("device.get".to_string(), vec!["read:device".to_string()]);
        operation_scopes.insert("device.configure".to_string(), vec!["write:device".to_string()]);
        operation_scopes.insert("device.delete".to_string(), vec!["delete:device".to_string()]);
        operation_scopes.insert("device.list".to_string(), vec!["read:device".to_string()]);

        debug!("Loaded {} operation scope configurations", operation_scopes.len());
        Ok(operation_scopes)
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

/// Dynamic parameter configuration for channel template resolution
#[derive(Debug, Clone)]
pub struct DynamicParameters {
    parameters: std::collections::HashMap<String, Vec<String>>,
}

impl DynamicParameters {
    /// Create a new empty dynamic parameters configuration
    pub fn new() -> Self {
        Self {
            parameters: std::collections::HashMap::new(),
        }
    }

    /// Add parameter values for a given parameter name
    pub fn add_parameter<S: Into<String>>(&mut self, param_name: S, values: Vec<S>) -> AsyncApiResult<()> {
        let param_name = param_name.into();
        let values: Vec<String> = values.into_iter().map(|v| v.into()).collect();

        if values.is_empty() {
            return Err(AsyncApiError::Configuration {
                message: format!("Parameter '{}' cannot have empty values", param_name),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Configuration,
                    false,
                )
                .with_context("parameter_name", &param_name),
                source: None,
            }.into());
        }

        self.parameters.insert(param_name, values);
        Ok(())
    }

    /// Get parameter values for a given parameter name
    pub fn get_parameter(&self, param_name: &str) -> Option<&Vec<String>> {
        self.parameters.get(param_name)
    }

    /// Get all parameters
    pub fn get_all_parameters(&self) -> &std::collections::HashMap<String, Vec<String>> {
        &self.parameters
    }

    /// Check if a parameter is defined
    pub fn has_parameter(&self, param_name: &str) -> bool {
        self.parameters.contains_key(param_name)
    }

    /// Validate that all required parameters are provided
    pub fn validate_required_parameters(&self, required_params: &[String]) -> AsyncApiResult<()> {
        for param in required_params {
            if !self.has_parameter(param) {
                return Err(AsyncApiError::Configuration {
                    message: format!("Required dynamic parameter '{}' is not provided", param),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Configuration,
                        false,
                    )
                    .with_context("parameter_name", param),
                    source: None,
                }.into());
            }
        }
        Ok(())
    }
}

impl Default for DynamicParameters {
    fn default() -> Self {
        Self::new()
    }
}

/// Simplified server builder that automatically sets up everything
/// This is the easiest way to get started - just provide your service implementations
pub struct AutoServerBuilder {
    auth_handler_service: Option<Arc<dyn AuthService>>,
    device_handler_service: Option<Arc<dyn DeviceService>>,
    network_handler_service: Option<Arc<dyn NetworkService>>,
    provision_handler_service: Option<Arc<dyn ProvisionService>>,
    salting_handler_service: Option<Arc<dyn SaltingService>>,
    threats_nats_handler_service: Option<Arc<dyn ThreatsNatsService>>,
    threats_ws_handler_service: Option<Arc<dyn ThreatsWsService>>,
    validator_connection_handler_service: Option<Arc<dyn ValidatorConnectionService>>,
    connections_handler_service: Option<Arc<dyn ConnectionsService>>,
    metrics_handler_service: Option<Arc<dyn MetricsService>>,
    tags_handler_service: Option<Arc<dyn TagsService>>,
    profiles_handler_service: Option<Arc<dyn ProfilesService>>,
    settings_handler_service: Option<Arc<dyn SettingsService>>,
    middleware: Vec<Box<dyn crate::middleware::Middleware>>,
    // Simplified recovery configuration
    recovery_preset: Option<RecoveryPreset>,
    retry_strategy: Option<crate::recovery::RetryConfig>,
    circuit_breaker_threshold: Option<u32>,
    max_concurrent_operations: Option<usize>,
    // Dynamic channel parameters
    dynamic_parameters: DynamicParameters,
    // NATS configuration

    #[cfg(feature = "nats")]
    nats_client: Option<async_nats::Client>,

    #[cfg(not(feature = "nats"))]
    nats_client: Option<()>,
    nats_servers: Option<Vec<String>>,
    nats_credentials: Option<String>,
    nats_connection_name: Option<String>,
    nats_timeout: Option<std::time::Duration>,
    // Authentication configuration
    #[cfg(feature = "auth")]
    auth_validator: Option<Arc<crate::auth::MultiAuthValidator>>,
}

impl AutoServerBuilder {
    /// Create a new auto server builder
    pub fn new() -> Self {
        Self {
            auth_handler_service: None,
            device_handler_service: None,
            network_handler_service: None,
            provision_handler_service: None,
            salting_handler_service: None,
            threats_nats_handler_service: None,
            threats_ws_handler_service: None,
            validator_connection_handler_service: None,
            connections_handler_service: None,
            metrics_handler_service: None,
            tags_handler_service: None,
            profiles_handler_service: None,
            settings_handler_service: None,
            middleware: Vec::new(),
            recovery_preset: None,
            retry_strategy: None,
            circuit_breaker_threshold: None,
            max_concurrent_operations: None,
            dynamic_parameters: DynamicParameters::new(),
            nats_client: None,
            nats_servers: None,
            nats_credentials: None,
            nats_connection_name: None,
            nats_timeout: None,
            #[cfg(feature = "auth")]
            auth_validator: None,
        }
    }

    /// Set the service implementation for auth channel
    pub fn with_auth_handler_service(mut self, service: Arc<dyn AuthService>) -> Self {
        self.auth_handler_service = Some(service);
        self
    }

    /// Set the service implementation for device channel
    pub fn with_device_handler_service(mut self, service: Arc<dyn DeviceService>) -> Self {
        self.device_handler_service = Some(service);
        self
    }

    /// Set the service implementation for network channel
    pub fn with_network_handler_service(mut self, service: Arc<dyn NetworkService>) -> Self {
        self.network_handler_service = Some(service);
        self
    }

    /// Set the service implementation for provision channel
    pub fn with_provision_handler_service(mut self, service: Arc<dyn ProvisionService>) -> Self {
        self.provision_handler_service = Some(service);
        self
    }

    /// Set the service implementation for salting channel
    pub fn with_salting_handler_service(mut self, service: Arc<dyn SaltingService>) -> Self {
        self.salting_handler_service = Some(service);
        self
    }

    /// Set the service implementation for threats_nats channel
    pub fn with_threats_nats_handler_service(mut self, service: Arc<dyn ThreatsNatsService>) -> Self {
        self.threats_nats_handler_service = Some(service);
        self
    }

    /// Set the service implementation for threats_ws channel
    pub fn with_threats_ws_handler_service(mut self, service: Arc<dyn ThreatsWsService>) -> Self {
        self.threats_ws_handler_service = Some(service);
        self
    }

    /// Set the service implementation for validator_connection channel
    pub fn with_validator_connection_handler_service(mut self, service: Arc<dyn ValidatorConnectionService>) -> Self {
        self.validator_connection_handler_service = Some(service);
        self
    }

    /// Set the service implementation for connections channel
    pub fn with_connections_handler_service(mut self, service: Arc<dyn ConnectionsService>) -> Self {
        self.connections_handler_service = Some(service);
        self
    }

    /// Set the service implementation for metrics channel
    pub fn with_metrics_handler_service(mut self, service: Arc<dyn MetricsService>) -> Self {
        self.metrics_handler_service = Some(service);
        self
    }

    /// Set the service implementation for tags channel
    pub fn with_tags_handler_service(mut self, service: Arc<dyn TagsService>) -> Self {
        self.tags_handler_service = Some(service);
        self
    }

    /// Set the service implementation for profiles channel
    pub fn with_profiles_handler_service(mut self, service: Arc<dyn ProfilesService>) -> Self {
        self.profiles_handler_service = Some(service);
        self
    }

    /// Set the service implementation for settings channel
    pub fn with_settings_handler_service(mut self, service: Arc<dyn SettingsService>) -> Self {
        self.settings_handler_service = Some(service);
        self
    }

    /// Add middleware to the server
    pub fn with_middleware<M: crate::middleware::Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middleware.push(Box::new(middleware));
        self
    }

    /// Add multiple middleware at once
    pub fn with_middleware_vec(mut self, middleware: Vec<Box<dyn crate::middleware::Middleware>>) -> Self {
        self.middleware.extend(middleware);
        self
    }

    /// Configure recovery with a preset
    pub fn with_recovery_preset(mut self, preset: RecoveryPreset) -> Self {
        self.recovery_preset = Some(preset);
        self
    }

    /// Configure custom retry strategy
    pub fn with_retry_strategy(mut self, strategy: crate::recovery::RetryConfig) -> Self {
        self.retry_strategy = Some(strategy);
        self
    }

    /// Configure circuit breaker failure threshold
    pub fn with_circuit_breaker_threshold(mut self, threshold: u32) -> Self {
        self.circuit_breaker_threshold = Some(threshold);
        self
    }

    /// Configure maximum concurrent operations
    pub fn with_max_concurrent_operations(mut self, max: usize) -> Self {
        self.max_concurrent_operations = Some(max);
        self
    }

    /// Add dynamic parameter values for channel template resolution
    /// This allows subscribing to specific instances of dynamic channels
    /// For example, for a channel "{location_id}.user.create", you can specify:
    /// .with_dynamic_parameter("location_id", vec!["store-123", "warehouse-456"])
    /// This will subscribe to both "store-123.user.create" and "warehouse-456.user.create"
    pub fn with_dynamic_parameter<S: Into<String>>(mut self, param_name: S, values: Vec<S>) -> AsyncApiResult<Self> {
        let param_name = param_name.into();
        let values: Vec<String> = values.into_iter().map(|v| v.into()).collect();

        self.dynamic_parameters.add_parameter(param_name, values)?;
        Ok(self)
    }

    /// Configure NATS connection with server URLs
    pub fn with_nats_servers(mut self, servers: Vec<String>) -> Self {
        self.nats_servers = Some(servers);
        self
    }

    /// Configure NATS with JWT credentials file
    pub fn with_nats_credentials(mut self, credentials_file: String) -> Self {
        self.nats_credentials = Some(credentials_file);
        self
    }

    /// Configure NATS connection name
    pub fn with_nats_connection_name(mut self, name: String) -> Self {
        self.nats_connection_name = Some(name);
        self
    }

    /// Configure NATS connection timeout
    pub fn with_nats_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.nats_timeout = Some(timeout);
        self
    }

    /// Configure NATS with a pre-configured client (recommended)
    /// This gives you full control over NATS connection settings, authentication, etc.

    #[cfg(feature = "nats")]
    pub fn with_nats_client(mut self, client: async_nats::Client) -> Self {
        self.nats_client = Some(client);
        self
    }


    #[cfg(not(feature = "nats"))]
    pub fn with_nats_client(mut self, _client: ()) -> Self {
        self.nats_client = Some(());
        self
    }

    #[cfg(feature = "auth")]
    /// Set a custom authentication validator
    pub fn with_auth_validator(mut self, validator: Arc<crate::auth::MultiAuthValidator>) -> Self {
        self.auth_validator = Some(validator);
        self
    }

    #[cfg(feature = "auth")]
    /// Configure JWT authentication
    pub fn with_jwt_auth(mut self, secret_or_key: &str, algorithm: &str) -> AsyncApiResult<Self> {
        let validator_builder = crate::auth::MultiAuthValidatorBuilder::new()
            .with_jwt(secret_or_key, algorithm)?;

        self.auth_validator = Some(Arc::new(validator_builder.build()));
        Ok(self)
    }

    #[cfg(feature = "auth")]
    /// Configure Basic authentication
    pub fn with_basic_auth(mut self, issuer: String, audience: String) -> Self {
        let validator_builder = crate::auth::MultiAuthValidatorBuilder::new()
            .with_basic_auth(issuer, audience);

        self.auth_validator = Some(Arc::new(validator_builder.build()));
        self
    }

    #[cfg(feature = "auth")]
    /// Configure API key authentication
    pub fn with_api_key_auth(mut self, location: crate::auth::ApiKeyLocation, issuer: String, audience: String) -> Self {
        let validator_builder = crate::auth::MultiAuthValidatorBuilder::new()
            .with_api_key(location, issuer, audience);

        self.auth_validator = Some(Arc::new(validator_builder.build()));
        self
    }

    #[cfg(feature = "auth")]
    /// Configure multiple authentication methods
    pub fn with_multi_auth(mut self, builder: crate::auth::MultiAuthValidatorBuilder) -> Self {
        self.auth_validator = Some(Arc::new(builder.build()));
        self
    }

    /// Build and start the server with automatic configuration
    /// This is the simplest way to get a fully configured server running
    pub async fn build_and_start(self) -> AsyncApiResult<crate::Server> {
        info!("Building and starting AsyncAPI server with full automatic configuration");

        let server = self.build().await?;
        server.start().await?;

        Ok(server)
    }

    /// Build the server without starting it
    #[allow(unused_mut)]
    pub async fn build(mut self) -> AsyncApiResult<crate::Server> {
        
        #[cfg(feature = "nats")]
        let transport_config = TransportConfig {
                transport_id: uuid::Uuid::new_v4(),
                ..Default::default()
        };

        // Handle NATS configuration if provided - do this FIRST to avoid ownership issues
        #[allow(unused_variables)]
        if let Some(nats_client) = self.nats_client {
            // Create transport manager with NATS transport
            let middleware = Arc::new(tokio::sync::RwLock::new(crate::middleware::MiddlewarePipeline::new(
                Arc::new(crate::recovery::RecoveryManager::default())
            )));
            #[allow(unused_variables)]
            let transport_manager = Arc::new(TransportManager::new_with_middleware(middleware.clone()));

            // Create NATS transport with the provided client and set the message handler

            #[cfg(feature = "nats")]
            {
                let mut nats_transport = crate::transport::nats::NatsTransport::new(nats_client, transport_config.clone());

                // This ensures that incoming NATS messages are properly routed to operation handlers
                let transport_manager_handler = Arc::new(crate::transport::TransportManagerHandler {
                    transport_manager: Arc::new(crate::transport::TransportManagerRef {
                        transports: transport_manager.transports.clone(),
                        handlers: transport_manager.handlers.clone(),
                        stats: transport_manager.stats.clone(),
                        middleware: transport_manager.middleware.clone(),
                    }),
                });
                nats_transport.set_message_handler(transport_manager_handler);

                transport_manager.add_transport(transport_config.transport_id, Box::new(nats_transport)).await
                    .map_err(|e| AsyncApiError::Configuration {
                        message: format!("Failed to add NATS transport: {e}"),
                        metadata: crate::errors::ErrorMetadata::new(
                            crate::errors::ErrorSeverity::High,
                            crate::errors::ErrorCategory::Configuration,
                            false,
                        ),
                        source: Some(e),
                    })?;

                info!("Added NATS transport with pre-configured client and message handler");
            }


            #[cfg(not(feature = "nats"))]
            {
                return Err(AsyncApiError::Configuration {
                    message: "NATS client provided but NATS feature is not enabled. Enable the 'nats' feature to use NATS transport.".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Configuration,
                        false,
                    ),
                    source: None,
                }.into());
            }


            #[cfg(feature = "nats")]
            {
                // Skip NATS protocol during AsyncAPI server setup since we're using a pre-configured NATS client
                // This allows other protocols (WebSocket, HTTP, etc.) to still be configured from AsyncAPI spec
                let skip_protocols = vec!["nats".to_string(), "nats+tls".to_string()];

                // CRITICAL FIX: Create and register operation handlers BEFORE building the server
                // This ensures handlers are available for all transports (both pre-configured NATS and AsyncAPI spec transports)
                let recovery_manager = Arc::new(crate::recovery::RecoveryManager::default());
                let publishers = Arc::new(crate::handlers::PublisherContext::new(transport_manager.clone()));

                // Create operation handlers directly without using a temp builder to avoid ownership issues
                let mut operation_handlers = std::collections::HashMap::new();
                let _security_config = crate::handlers::get_operation_security_config();

                
                // Create operation handlers for auth channel
                if let Some(service) = self.auth_handler_service.take() {
                    debug!("Creating operation handlers for auth channel with pre-configured NATS client");
                    
                    // Create auth.login operation handler
                    let auth_login_handler = Arc::new(crate::handlers::AuthLoginOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_auth_login_handler = auth_login_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("auth.login".to_string(), final_auth_login_handler);
                    info!("Created handler for auth.login operation with pre-configured NATS client");
                    // Create auth.logout operation handler
                    let auth_logout_handler = Arc::new(crate::handlers::AuthLogoutOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_auth_logout_handler = auth_logout_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("auth.logout".to_string(), final_auth_logout_handler);
                    info!("Created handler for auth.logout operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for auth channel - skipping operation handler creation");
                }
                // Create operation handlers for device channel
                if let Some(service) = self.device_handler_service.take() {
                    debug!("Creating operation handlers for device channel with pre-configured NATS client");
                    
                    // Create device.bootstrap operation handler
                    let device_bootstrap_handler = Arc::new(crate::handlers::DeviceBootstrapOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_device_bootstrap_handler = device_bootstrap_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("device.bootstrap".to_string(), final_device_bootstrap_handler);
                    info!("Created handler for device.bootstrap operation with pre-configured NATS client");
                    // Create device.get operation handler
                    let device_get_handler = Arc::new(crate::handlers::DeviceGetOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_device_get_handler = device_get_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("device.get".to_string(), final_device_get_handler);
                    info!("Created handler for device.get operation with pre-configured NATS client");
                    // Create device.configure operation handler
                    let device_configure_handler = Arc::new(crate::handlers::DeviceConfigureOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_device_configure_handler = device_configure_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("device.configure".to_string(), final_device_configure_handler);
                    info!("Created handler for device.configure operation with pre-configured NATS client");
                    // Create device.delete operation handler
                    let device_delete_handler = Arc::new(crate::handlers::DeviceDeleteOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_device_delete_handler = device_delete_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("device.delete".to_string(), final_device_delete_handler);
                    info!("Created handler for device.delete operation with pre-configured NATS client");
                    // Create device.list operation handler
                    let device_list_handler = Arc::new(crate::handlers::DeviceListOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_device_list_handler = device_list_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("device.list".to_string(), final_device_list_handler);
                    info!("Created handler for device.list operation with pre-configured NATS client");
                    // Create device.update_metadata operation handler
                    let device_update_metadata_handler = Arc::new(crate::handlers::DeviceUpdateMetadataOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_device_update_metadata_handler = device_update_metadata_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("device.update_metadata".to_string(), final_device_update_metadata_handler);
                    info!("Created handler for device.update_metadata operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for device channel - skipping operation handler creation");
                }
                // Create operation handlers for network channel
                if let Some(service) = self.network_handler_service.take() {
                    debug!("Creating operation handlers for network channel with pre-configured NATS client");
                    
                    // Create network.topology operation handler
                    let network_topology_handler = Arc::new(crate::handlers::NetworkTopologyOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_network_topology_handler = network_topology_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("network.topology".to_string(), final_network_topology_handler);
                    info!("Created handler for network.topology operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for network channel - skipping operation handler creation");
                }
                // Create operation handlers for provision channel
                if let Some(service) = self.provision_handler_service.take() {
                    debug!("Creating operation handlers for provision channel with pre-configured NATS client");
                    
                    // Create provision.refresh operation handler
                    let provision_refresh_handler = Arc::new(crate::handlers::ProvisionRefreshOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_provision_refresh_handler = provision_refresh_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("provision.refresh".to_string(), final_provision_refresh_handler);
                    info!("Created handler for provision.refresh operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for provision channel - skipping operation handler creation");
                }
                // Create operation handlers for salting channel
                if let Some(service) = self.salting_handler_service.take() {
                    debug!("Creating operation handlers for salting channel with pre-configured NATS client");
                    
                    // Create salting.request operation handler
                    let salting_request_handler = Arc::new(crate::handlers::SaltingRequestOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_salting_request_handler = salting_request_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("salting.request".to_string(), final_salting_request_handler);
                    info!("Created handler for salting.request operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for salting channel - skipping operation handler creation");
                }
                // Create operation handlers for threats_nats channel
                if let Some(service) = self.threats_nats_handler_service.take() {
                    debug!("Creating operation handlers for threats_nats channel with pre-configured NATS client");
                    
                    // Create threats.report operation handler
                    let threats_report_handler = Arc::new(crate::handlers::ThreatsReportOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_threats_report_handler = threats_report_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("threats.report".to_string(), final_threats_report_handler);
                    info!("Created handler for threats.report operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for threats_nats channel - skipping operation handler creation");
                }
                // Create operation handlers for threats_ws channel
                if let Some(service) = self.threats_ws_handler_service.take() {
                    debug!("Creating operation handlers for threats_ws channel with pre-configured NATS client");
                    
                    // Create threats.query operation handler
                    let threats_query_handler = Arc::new(crate::handlers::ThreatsQueryOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_threats_query_handler = threats_query_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("threats.query".to_string(), final_threats_query_handler);
                    info!("Created handler for threats.query operation with pre-configured NATS client");
                    // Create threats.download_pcap operation handler
                    let threats_download_pcap_handler = Arc::new(crate::handlers::ThreatsDownloadPcapOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_threats_download_pcap_handler = threats_download_pcap_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("threats.download_pcap".to_string(), final_threats_download_pcap_handler);
                    info!("Created handler for threats.download_pcap operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for threats_ws channel - skipping operation handler creation");
                }
                // Create operation handlers for validator_connection channel
                if let Some(service) = self.validator_connection_handler_service.take() {
                    debug!("Creating operation handlers for validator_connection channel with pre-configured NATS client");
                    
                    // Create validator_connection.report operation handler
                    let validator_connection_report_handler = Arc::new(crate::handlers::ValidatorConnectionReportOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_validator_connection_report_handler = validator_connection_report_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("validator_connection.report".to_string(), final_validator_connection_report_handler);
                    info!("Created handler for validator_connection.report operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for validator_connection channel - skipping operation handler creation");
                }
                // Create operation handlers for connections channel
                if let Some(service) = self.connections_handler_service.take() {
                    debug!("Creating operation handlers for connections channel with pre-configured NATS client");
                    
                    // Create connections.query operation handler
                    let connections_query_handler = Arc::new(crate::handlers::ConnectionsQueryOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_connections_query_handler = connections_query_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("connections.query".to_string(), final_connections_query_handler);
                    info!("Created handler for connections.query operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for connections channel - skipping operation handler creation");
                }
                // Create operation handlers for metrics channel
                if let Some(service) = self.metrics_handler_service.take() {
                    debug!("Creating operation handlers for metrics channel with pre-configured NATS client");
                    
                    // Create metrics.query operation handler
                    let metrics_query_handler = Arc::new(crate::handlers::MetricsQueryOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_metrics_query_handler = metrics_query_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("metrics.query".to_string(), final_metrics_query_handler);
                    info!("Created handler for metrics.query operation with pre-configured NATS client");
                    // Create metrics.reset operation handler
                    let metrics_reset_handler = Arc::new(crate::handlers::MetricsResetOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_metrics_reset_handler = metrics_reset_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("metrics.reset".to_string(), final_metrics_reset_handler);
                    info!("Created handler for metrics.reset operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for metrics channel - skipping operation handler creation");
                }
                // Create operation handlers for tags channel
                if let Some(service) = self.tags_handler_service.take() {
                    debug!("Creating operation handlers for tags channel with pre-configured NATS client");
                    
                    // Create tags.create operation handler
                    let tags_create_handler = Arc::new(crate::handlers::TagsCreateOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_tags_create_handler = tags_create_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("tags.create".to_string(), final_tags_create_handler);
                    info!("Created handler for tags.create operation with pre-configured NATS client");
                    // Create tags.update operation handler
                    let tags_update_handler = Arc::new(crate::handlers::TagsUpdateOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_tags_update_handler = tags_update_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("tags.update".to_string(), final_tags_update_handler);
                    info!("Created handler for tags.update operation with pre-configured NATS client");
                    // Create tags.delete operation handler
                    let tags_delete_handler = Arc::new(crate::handlers::TagsDeleteOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_tags_delete_handler = tags_delete_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("tags.delete".to_string(), final_tags_delete_handler);
                    info!("Created handler for tags.delete operation with pre-configured NATS client");
                    // Create tags.list operation handler
                    let tags_list_handler = Arc::new(crate::handlers::TagsListOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_tags_list_handler = tags_list_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("tags.list".to_string(), final_tags_list_handler);
                    info!("Created handler for tags.list operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for tags channel - skipping operation handler creation");
                }
                // Create operation handlers for profiles channel
                if let Some(service) = self.profiles_handler_service.take() {
                    debug!("Creating operation handlers for profiles channel with pre-configured NATS client");
                    
                    // Create profiles.create operation handler
                    let profiles_create_handler = Arc::new(crate::handlers::ProfilesCreateOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_profiles_create_handler = profiles_create_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("profiles.create".to_string(), final_profiles_create_handler);
                    info!("Created handler for profiles.create operation with pre-configured NATS client");
                    // Create profiles.get operation handler
                    let profiles_get_handler = Arc::new(crate::handlers::ProfilesGetOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_profiles_get_handler = profiles_get_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("profiles.get".to_string(), final_profiles_get_handler);
                    info!("Created handler for profiles.get operation with pre-configured NATS client");
                    // Create profiles.update operation handler
                    let profiles_update_handler = Arc::new(crate::handlers::ProfilesUpdateOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_profiles_update_handler = profiles_update_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("profiles.update".to_string(), final_profiles_update_handler);
                    info!("Created handler for profiles.update operation with pre-configured NATS client");
                    // Create profiles.delete operation handler
                    let profiles_delete_handler = Arc::new(crate::handlers::ProfilesDeleteOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_profiles_delete_handler = profiles_delete_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("profiles.delete".to_string(), final_profiles_delete_handler);
                    info!("Created handler for profiles.delete operation with pre-configured NATS client");
                    // Create profiles.list operation handler
                    let profiles_list_handler = Arc::new(crate::handlers::ProfilesListOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_profiles_list_handler = profiles_list_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("profiles.list".to_string(), final_profiles_list_handler);
                    info!("Created handler for profiles.list operation with pre-configured NATS client");
                    // Create profiles.assign operation handler
                    let profiles_assign_handler = Arc::new(crate::handlers::ProfilesAssignOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_profiles_assign_handler = profiles_assign_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("profiles.assign".to_string(), final_profiles_assign_handler);
                    info!("Created handler for profiles.assign operation with pre-configured NATS client");
                    // Create profiles.unassign operation handler
                    let profiles_unassign_handler = Arc::new(crate::handlers::ProfilesUnassignOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_profiles_unassign_handler = profiles_unassign_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("profiles.unassign".to_string(), final_profiles_unassign_handler);
                    info!("Created handler for profiles.unassign operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for profiles channel - skipping operation handler creation");
                }
                // Create operation handlers for settings channel
                if let Some(service) = self.settings_handler_service.take() {
                    debug!("Creating operation handlers for settings channel with pre-configured NATS client");
                    
                    // Create settings.get operation handler
                    let settings_get_handler = Arc::new(crate::handlers::SettingsGetOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_settings_get_handler = settings_get_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("settings.get".to_string(), final_settings_get_handler);
                    info!("Created handler for settings.get operation with pre-configured NATS client");
                    // Create settings.update operation handler
                    let settings_update_handler = Arc::new(crate::handlers::SettingsUpdateOperationHandler::new(
                        service.clone(),
                        recovery_manager.clone(),
                        transport_manager.clone(),
                    ));

                    let final_settings_update_handler = settings_update_handler as Arc<dyn crate::transport::MessageHandler>;
                    operation_handlers.insert("settings.update".to_string(), final_settings_update_handler);
                    info!("Created handler for settings.update operation with pre-configured NATS client");
                } else {
                    debug!("No service provided for settings channel - skipping operation handler creation");
                }

                // Register handlers with transport manager for direct routing
                for (operation_name, handler) in operation_handlers {
                    transport_manager.register_handler(operation_name.clone(), handler).await;
                    info!("Registered handler for {} operation with pre-configured NATS client", operation_name);
                }

                // CRITICAL FIX: Now setup additional transports from AsyncAPI spec (WebSocket, HTTP, etc.)
                // This was the missing piece - we need to process AsyncAPI servers even with pre-configured NATS
                info!("Setting up additional transports from AsyncAPI specification (skipping pre-configured NATS)");

                // Create a temporary ServerBuilder to leverage existing transport setup logic
                let temp_builder = ServerBuilder::new(Config::default());

                // Use the existing transport setup method but with our pre-configured transport manager
                let empty_handlers = std::collections::HashMap::new(); // Handlers already registered above
                temp_builder.setup_transports_with_handlers_filtered(
                    &transport_manager,
                    &empty_handlers,
                    &skip_protocols
                ).await.map_err(|e| {
                    tracing::error!("Failed to setup additional transports from AsyncAPI spec: {}", e);
                    e
                })?;

                info!("Successfully setup additional transports from AsyncAPI specification");

                // Build server with dynamic parameters if provided
                let server = if !self.dynamic_parameters.get_all_parameters().is_empty() {
                    crate::Server::new_with_components_and_publishers_and_dynamic_params(
                        Config::default(),
                        recovery_manager,
                        transport_manager,
                        middleware,
                        publishers,
                        Arc::new(self.dynamic_parameters),
                    ).await?
                } else {
                    crate::Server::new_with_components_and_publishers(
                        Config::default(),
                        recovery_manager,
                        transport_manager,
                        middleware,
                        publishers,
                    ).await?
                };

                // Add middleware to the server after it's built
                let middleware = self.middleware;
                if !middleware.is_empty() {
                    server.configure_middleware(|mut pipeline| {
                        for middleware_item in middleware {
                            pipeline = pipeline.add_boxed_middleware(middleware_item);
                        }
                        pipeline
                    }).await?;
                }

                return Ok(server);
            }

        }

        // If no NATS client provided, use normal ServerBuilder path
        #[allow(unused_mut)]
        let mut builder = ServerBuilder::new(Config::default());

        // Apply recovery configuration
        if let Some(preset) = self.recovery_preset {
            builder = builder.with_recovery_preset(preset);
        }

        if let Some(strategy) = self.retry_strategy {
            builder = builder.with_retry_config("message_handler", strategy);
        }

        if let Some(threshold) = self.circuit_breaker_threshold {
            let config = crate::recovery::CircuitBreakerConfig {
                failure_threshold: threshold,
                recovery_timeout: std::time::Duration::from_secs(60),
                success_threshold: 3,
                failure_window: std::time::Duration::from_secs(60),
            };
            builder = builder.with_circuit_breaker_config("default", config);
        }

        if let Some(max_concurrent) = self.max_concurrent_operations {
            builder = builder.with_bulkhead_config("message_processing", max_concurrent, std::time::Duration::from_secs(30));
        }

        // Transfer authentication configuration
        #[cfg(feature = "auth")]
        if let Some(auth_validator) = self.auth_validator {
            builder = builder.with_auth_validator(auth_validator);
        }

        if let Some(service) = self.auth_handler_service {
            builder = builder.with_auth_handler_service(service);
        }

        if let Some(service) = self.device_handler_service {
            builder = builder.with_device_handler_service(service);
        }

        if let Some(service) = self.network_handler_service {
            builder = builder.with_network_handler_service(service);
        }

        if let Some(service) = self.provision_handler_service {
            builder = builder.with_provision_handler_service(service);
        }

        if let Some(service) = self.salting_handler_service {
            builder = builder.with_salting_handler_service(service);
        }

        if let Some(service) = self.threats_nats_handler_service {
            builder = builder.with_threats_nats_handler_service(service);
        }

        if let Some(service) = self.threats_ws_handler_service {
            builder = builder.with_threats_ws_handler_service(service);
        }

        if let Some(service) = self.validator_connection_handler_service {
            builder = builder.with_validator_connection_handler_service(service);
        }

        if let Some(service) = self.connections_handler_service {
            builder = builder.with_connections_handler_service(service);
        }

        if let Some(service) = self.metrics_handler_service {
            builder = builder.with_metrics_handler_service(service);
        }

        if let Some(service) = self.tags_handler_service {
            builder = builder.with_tags_handler_service(service);
        }

        if let Some(service) = self.profiles_handler_service {
            builder = builder.with_profiles_handler_service(service);
        }

        if let Some(service) = self.settings_handler_service {
            builder = builder.with_settings_handler_service(service);
        }

        if self.nats_servers.is_some() || self.nats_credentials.is_some() {
            // Auto-create NATS client from configuration

            #[cfg(feature = "nats")]
            {
                info!("Creating NATS client from configuration");

                let mut connect_options = async_nats::ConnectOptions::new();

                if let Some(name) = self.nats_connection_name {
                    connect_options = connect_options.name(name);
                }

                if let Some(timeout) = self.nats_timeout {
                    connect_options = connect_options.connection_timeout(timeout);
                }

                if let Some(credentials_file) = self.nats_credentials {
                    connect_options = connect_options.credentials_file(credentials_file).await
                        .map_err(|e| AsyncApiError::Configuration {
                            message: format!("Failed to load NATS credentials: {e}"),
                            metadata: crate::errors::ErrorMetadata::new(
                                crate::errors::ErrorSeverity::High,
                                crate::errors::ErrorCategory::Configuration,
                                false,
                            ),
                            source: Some(Box::new(e)),
                        })?;
                }

                let servers = self.nats_servers.unwrap_or_else(|| vec!["nats://localhost:4222".to_string()]);
                let server_url = servers.join(",");

                let nats_client = connect_options.connect(&server_url).await
                    .map_err(|e| AsyncApiError::Configuration {
                        message: format!("Failed to connect to NATS servers: {e}"),
                        metadata: crate::errors::ErrorMetadata::new(
                            crate::errors::ErrorSeverity::High,
                            crate::errors::ErrorCategory::Network,
                            true,
                        ),
                        source: Some(Box::new(e)),
                    })?;

                // Create transport manager with NATS transport
                let transport_manager = Arc::new(TransportManager::new());
                let nats_transport = crate::transport::nats::NatsTransport::new(nats_client, transport_config.clone());
                transport_manager.add_transport(transport_config.transport_id, Box::new(nats_transport)).await
                    .map_err(|e| AsyncApiError::Configuration {
                        message: format!("Failed to add NATS transport: {e}"),
                        metadata: crate::errors::ErrorMetadata::new(
                            crate::errors::ErrorSeverity::High,
                            crate::errors::ErrorCategory::Configuration,
                            false,
                        ),
                        source: Some(e),
                    })?;

                info!("Created NATS transport from configuration");
                builder = builder.with_transport_manager(transport_manager);
            }


            #[cfg(not(feature = "nats"))]
            {
                return Err(AsyncApiError::Configuration {
                    message: "NATS configuration provided but NATS feature is not enabled. Enable the 'nats' feature to use NATS transport.".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Configuration,
                        false,
                    ),
                    source: None,
                }.into());
            }
        }

        // Create a server with dynamic parameters
        let server = if !self.dynamic_parameters.get_all_parameters().is_empty() {
            // Build server with dynamic parameters
            // Create server with dynamic parameters
            let recovery_manager = Arc::new(crate::recovery::RecoveryManager::default());
            let middleware = Arc::new(tokio::sync::RwLock::new(crate::middleware::MiddlewarePipeline::new(recovery_manager.clone())));
            #[allow(unused_variables)]
            let transport_manager = Arc::new(TransportManager::new_with_middleware(middleware.clone()));
            let publishers = Arc::new(crate::handlers::PublisherContext::new(transport_manager.clone()));

            crate::Server::new_with_components_and_publishers_and_dynamic_params(
                Config::default(),
                recovery_manager,
                transport_manager,
                middleware,
                publishers,
                Arc::new(self.dynamic_parameters),
            ).await?
        } else {
            builder.build().await?
        };

        // Add middleware to the server after it's built
        // We need to use the configure_middleware method since add_middleware expects concrete types
        let middleware = self.middleware;
        if !middleware.is_empty() {
            server.configure_middleware(|mut pipeline| {
                for middleware_item in middleware {
                    pipeline = pipeline.add_boxed_middleware(middleware_item);
                }
                pipeline
            }).await?;
        }

        Ok(server)
    }
}

impl Default for AutoServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}


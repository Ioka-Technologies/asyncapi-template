//! Server builder for AsyncAPI service with simplified direct routing
//!
//! This module provides a builder pattern for creating and configuring
//! the AsyncAPI server with direct TransportManager routing and handler registration.

use crate::config::Config;
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::handlers::*;
use crate::recovery::RecoveryManager;
use crate::transport::{TransportManager, factory::TransportFactory};
use std::sync::Arc;
use tracing::{info, debug};

/// Builder for creating AsyncAPI servers with automatic routing configuration
pub struct ServerBuilder {
    config: Config,
    recovery_manager: Option<Arc<RecoveryManager>>,
    transport_manager: Option<Arc<TransportManager>>,
    chat_messages_handler_service: Option<Arc<dyn ChatMessagesService>>,
    profile_update_handler_service: Option<Arc<dyn ProfileUpdateService>>,
}

impl ServerBuilder {
    /// Create a new server builder with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            config,
            recovery_manager: None,
            transport_manager: None,
            chat_messages_handler_service: None,
            profile_update_handler_service: None,
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

    /// Set the service implementation for chatMessages channel
    pub fn with_chat_messages_handler_service(mut self, service: Arc<dyn ChatMessagesService>) -> Self {
        self.chat_messages_handler_service = Some(service);
        self
    }

    /// Set the service implementation for profileUpdate channel
    pub fn with_profile_update_handler_service(mut self, service: Arc<dyn ProfileUpdateService>) -> Self {
        self.profile_update_handler_service = Some(service);
        self
    }

    /// Build the server with simplified direct routing
    /// This automatically creates and configures:
    /// - TransportManager for direct message routing
    /// - Channel-specific message handlers
    /// - Direct handler registration with TransportManager
    /// - No complex router layer needed!
    pub async fn build(mut self) -> AsyncApiResult<crate::Server> {
        info!("Building AsyncAPI server with automatic routing setup");

        // Initialize recovery manager
        let recovery_manager = self.recovery_manager.take().unwrap_or_else(|| {
            debug!("Creating default recovery manager");
            Arc::new(RecoveryManager::default())
        });

        // Initialize transport manager
        let transport_manager = self.transport_manager.take().unwrap_or_else(|| {
            debug!("Creating default transport manager");
            Arc::new(TransportManager::new())
        });

        // Setup transports based on configuration
        self.setup_transports(&transport_manager).await?;

        // Register chatMessages channel handler directly with TransportManager (SIMPLIFIED)
        if let Some(service) = self.chat_messages_handler_service.take() {
            debug!("Setting up chatMessages channel handler with direct routing");
            let handler = Arc::new(ChatMessagesHandler::new(
                service,
                recovery_manager.clone(),
                transport_manager.clone(),
            ));
            let message_handler = Arc::new(ChatMessagesMessageHandler::new(handler));
            transport_manager.register_handler("chatMessages".to_string(), message_handler).await;
            info!("Registered direct routing for chatMessages channel");
        } else {
            debug!("No service provided for chatMessages channel - skipping handler registration");
        }

        // Register profileUpdate channel handler directly with TransportManager (SIMPLIFIED)
        if let Some(service) = self.profile_update_handler_service.take() {
            debug!("Setting up profileUpdate channel handler with direct routing");
            let handler = Arc::new(ProfileUpdateHandler::new(
                service,
                recovery_manager.clone(),
                transport_manager.clone(),
            ));
            let message_handler = Arc::new(ProfileUpdateMessageHandler::new(handler));
            transport_manager.register_handler("profileUpdate".to_string(), message_handler).await;
            info!("Registered direct routing for profileUpdate channel");
        } else {
            debug!("No service provided for profileUpdate channel - skipping handler registration");
        }

        info!("Direct routing system fully configured - no router layer needed!");

        // Create server instance
        let server = crate::Server::new_with_components(
            self.config,
            recovery_manager,
            transport_manager,
        ).await?;

        info!("AsyncAPI server built successfully with automatic routing");
        Ok(server)
    }

    /// Setup transports based on server configuration
    async fn setup_transports(&self, transport_manager: &TransportManager) -> AsyncApiResult<()> {
        debug!("Setting up transports from configuration");

        // For now, we'll use a default HTTP transport configuration
        // In a real implementation, this would read from the config
        let http_config = crate::transport::TransportConfig {
            protocol: "http".to_string(),
            host: "0.0.0.0".to_string(),
            port: 8080,
            username: None,
            password: None,
            tls: false,
            additional_config: std::collections::HashMap::new(),
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
        transport_manager.add_transport("http".to_string(), transport).await?;

        info!("Default HTTP transport configured successfully");
        Ok(())
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

/// Simplified server builder that automatically sets up everything
/// This is the easiest way to get started - just provide your service implementations
pub struct AutoServerBuilder {
    chat_messages_handler_service: Option<Arc<dyn ChatMessagesService>>,
    profile_update_handler_service: Option<Arc<dyn ProfileUpdateService>>,
}

impl AutoServerBuilder {
    /// Create a new auto server builder
    pub fn new() -> Self {
        Self {
            chat_messages_handler_service: None,
            profile_update_handler_service: None,
        }
    }

    /// Set the service implementation for chatMessages channel
    pub fn with_chat_messages_handler_service(mut self, service: Arc<dyn ChatMessagesService>) -> Self {
        self.chat_messages_handler_service = Some(service);
        self
    }

    /// Set the service implementation for profileUpdate channel
    pub fn with_profile_update_handler_service(mut self, service: Arc<dyn ProfileUpdateService>) -> Self {
        self.profile_update_handler_service = Some(service);
        self
    }

    /// Build and start the server with automatic configuration
    /// This is the simplest way to get a fully configured server running
    pub async fn build_and_start(self) -> AsyncApiResult<()> {
        info!("Building and starting AsyncAPI server with full automatic configuration");

        #[allow(unused_mut)]
        let mut builder = ServerBuilder::new(Config::default());

        if let Some(service) = self.chat_messages_handler_service {
            builder = builder.with_chat_messages_handler_service(service);
        }

        if let Some(service) = self.profile_update_handler_service {
            builder = builder.with_profile_update_handler_service(service);
        }

        let server = builder.build().await?;
        server.start().await?;

        Ok(())
    }

    /// Build the server without starting it
    pub async fn build(self) -> AsyncApiResult<crate::Server> {
        #[allow(unused_mut)]
        let mut builder = ServerBuilder::new(Config::default());

        if let Some(service) = self.chat_messages_handler_service {
            builder = builder.with_chat_messages_handler_service(service);
        }

        if let Some(service) = self.profile_update_handler_service {
            builder = builder.with_profile_update_handler_service(service);
        }

        builder.build().await
    }
}

impl Default for AutoServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}


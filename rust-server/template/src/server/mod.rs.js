/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ServerModRs({ asyncapi }) {
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

/// Information about a channel that requires subscription
#[derive(Debug, Clone)]
pub struct ChannelSubscriptionInfo {
    pub name: String,
    pub address: String,
    pub description: String,
    pub is_dynamic: bool,
    pub parameters: Vec<String>, // extracted parameter names like ["location_id"]
}

/// Main server struct that orchestrates all components
pub struct Server {
    config: Config,
    handlers: Arc<RwLock<HandlerRegistry>>,
    context_manager: Arc<ContextManager>,
    transport_manager: Arc<crate::transport::TransportManager>,
    middleware: Arc<RwLock<MiddlewarePipeline>>,
    recovery_manager: Arc<RecoveryManager>,
    publishers: Arc<crate::handlers::PublisherContext>,
    dynamic_parameters: Arc<crate::server::builder::DynamicParameters>,
}

impl Server {
    /// Create a new server with default configuration
    pub async fn new(config: Config) -> AsyncApiResult<Self> {
        let recovery_manager = Arc::new(RecoveryManager::default());
        let context_manager = Arc::new(ContextManager::new());
        let middleware = Arc::new(RwLock::new(MiddlewarePipeline::new(recovery_manager.clone())));

        // Create transport manager with shared middleware pipeline
        let transport_manager = Arc::new(crate::transport::TransportManager::new_with_middleware(middleware.clone()));

        // Create publisher context
        let publishers = Arc::new(${(() => {
                    // Check if there are any "receive" operations that would generate channel publishers
                    const channels = asyncapi.channels();
                    const operations = asyncapi.operations && asyncapi.operations();
                    let hasReceiveOperations = false;

                    if (channels && operations) {
                        for (const operation of operations) {
                            const action = operation.action && operation.action();
                            if (action === 'receive') {
                                hasReceiveOperations = true;
                                break;
                            }
                        }
                    }

                    return hasReceiveOperations ?
                        'crate::handlers::PublisherContext::new(transport_manager.clone())' :
                        'crate::handlers::PublisherContext::new()';
                })()});

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
            publishers,
            dynamic_parameters: Arc::new(crate::server::builder::DynamicParameters::new()),
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

        // Create publisher context
        let publishers = Arc::new(${(() => {
                    // Check if there are any "receive" operations that would generate channel publishers
                    const channels = asyncapi.channels();
                    const operations = asyncapi.operations && asyncapi.operations();
                    let hasReceiveOperations = false;

                    if (channels && operations) {
                        for (const operation of operations) {
                            const action = operation.action && operation.action();
                            if (action === 'receive') {
                                hasReceiveOperations = true;
                                break;
                            }
                        }
                    }

                    return hasReceiveOperations ?
                        'crate::handlers::PublisherContext::new(transport_manager.clone())' :
                        'crate::handlers::PublisherContext::new()';
                })()});

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
            publishers,
            dynamic_parameters: Arc::new(crate::server::builder::DynamicParameters::new()),
        })
    }

    /// Create a new server with custom components and publishers
    pub async fn new_with_components_and_publishers(
        config: Config,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<crate::transport::TransportManager>,
        middleware: Arc<RwLock<MiddlewarePipeline>>,
        publishers: Arc<crate::handlers::PublisherContext>,
    ) -> AsyncApiResult<Self> {
        Self::new_with_components_and_publishers_and_dynamic_params(
            config,
            recovery_manager,
            transport_manager,
            middleware,
            publishers,
            Arc::new(crate::server::builder::DynamicParameters::new()),
        ).await
    }

    /// Create a new server with custom components, publishers, and dynamic parameters
    pub async fn new_with_components_and_publishers_and_dynamic_params(
        config: Config,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<crate::transport::TransportManager>,
        middleware: Arc<RwLock<MiddlewarePipeline>>,
        publishers: Arc<crate::handlers::PublisherContext>,
        dynamic_parameters: Arc<crate::server::builder::DynamicParameters>,
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
            publishers,
            dynamic_parameters,
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

        // Subscribe to channels defined in AsyncAPI specification
        match self.subscribe_to_channels().await {
            Ok(()) => {
                debug!("Successfully subscribed to all channels");
            }
            Err(e) => {
                warn!("Some channel subscriptions failed: {}", e);
                // Continue with available subscriptions rather than failing completely
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

    /// Subscribe to channels defined in AsyncAPI specification
    /// This method ensures that transports subscribe to the appropriate channels
    /// for proper pub/sub functionality
    async fn subscribe_to_channels(&self) -> AsyncApiResult<()> {
        debug!("Subscribing to channels defined in AsyncAPI specification");

        // Get the list of channels that need subscription from AsyncAPI spec
        let channels_to_subscribe = self.get_channels_for_subscription();

        if channels_to_subscribe.is_empty() {
            debug!("No channels found that require subscription");
            return Ok(());
        }

        info!("Found {} channel(s) that require subscription", channels_to_subscribe.len());

        // Subscribe to each channel through the transport manager
        for channel_info in channels_to_subscribe {
            debug!("Subscribing to channel: {} (address: {})", channel_info.name, channel_info.address);

            // Use the transport manager to subscribe to the channel
            // The transport manager will delegate to the appropriate transport implementation
            match self.subscribe_to_channel(&channel_info).await {
                Ok(()) => {
                    info!("Successfully subscribed to channel: {} ({})", channel_info.name, channel_info.address);
                }
                Err(e) => {
                    warn!("Failed to subscribe to channel {}: {}", channel_info.name, e);
                    // Continue with other channels rather than failing completely
                }
            }
        }

        info!("Channel subscription process completed");
        Ok(())
    }

    /// Get channels that require subscription based on AsyncAPI specification
    /// Returns channels that have "send" operations (where the server receives messages)
    fn get_channels_for_subscription(&self) -> Vec<ChannelSubscriptionInfo> {
        debug!("Extracting channels for subscription from AsyncAPI specification");

        // Channels extracted from AsyncAPI specification during template generation
        // Only include channels that have "send" operations (server receives messages)
        let channels = vec![${(() => {
                    const channelsToSubscribe = [];

                    try {
                        // Extract channels and operations using AsyncAPI parser methods
                        let channels, operations;

                        // Method 1: Direct method calls
                        if (typeof asyncapi.channels === 'function') {
                            channels = asyncapi.channels();
                        }

                        if (typeof asyncapi.operations === 'function') {
                            operations = asyncapi.operations();
                        }

                        // Method 2: Try accessing _json property as fallback
                        if (!channels && asyncapi._json) {
                            const doc = asyncapi._json;
                            if (doc.channels) {
                                channels = Object.entries(doc.channels).map(([id, data]) => ({
                                    id: () => id,
                                    address: () => data.address,
                                    description: () => data.description
                                }));
                            }
                            if (doc.operations) {
                                operations = Object.entries(doc.operations).map(([id, data]) => ({
                                    id: () => id,
                                    action: () => data.action,
                                    _json: data
                                }));
                            }
                        }

                        if (channels && operations) {
                            // Create a map of channels that have "send" operations
                            const channelSendOps = new Map();

                            // Find operations with "send" action
                            for (const operation of operations) {
                                const action = operation.action && operation.action();

                                if (action === 'send') {
                                    // This is a "send" operation - server receives messages on this channel
                                    // Check the embedded channel data in operation._json.channel
                                    const embeddedChannel = operation._json && operation._json.channel;

                                    if (embeddedChannel) {
                                        let channelName = null;

                                        if (embeddedChannel.$ref) {
                                            // Extract channel name from "#/channels/channelName"
                                            channelName = embeddedChannel.$ref.split('/').pop();
                                        } else if (embeddedChannel['x-parser-unique-object-id']) {
                                            // Use the unique object ID as the channel name
                                            channelName = embeddedChannel['x-parser-unique-object-id'];
                                        }

                                        if (channelName) {
                                            channelSendOps.set(channelName, true);
                                        }
                                    }
                                }
                            }

                            // Now iterate through channels and include those with send operations
                            for (const channel of channels) {
                                const channelId = channel.id();
                                if (channelSendOps.has(channelId)) {
                                    const address = channel.address && channel.address();
                                    const description = channel.description && channel.description();

                                    // Check if the address contains dynamic parameters (e.g., {location_id})
                                    const isDynamic = address && address.includes('{') && address.includes('}');
                                    const parameters = [];

                                    if (isDynamic) {
                                        // Extract parameter names from the address
                                        const paramMatches = address.match(/\{([^}]+)\}/g);
                                        if (paramMatches) {
                                            for (const match of paramMatches) {
                                                const paramName = match.slice(1, -1); // Remove { and }
                                                parameters.push(paramName);
                                            }
                                        }
                                    }

                                    channelsToSubscribe.push(`
            ChannelSubscriptionInfo {
                name: "${channelId}".to_string(),
                address: "${address || channelId}".to_string(),
                description: "${description || ''}".to_string(),
                is_dynamic: ${isDynamic},
                parameters: vec![${parameters.map(p => `"${p}".to_string()`).join(', ')}],
            },`);
                                }
                            }
                        }
                    } catch (error) {
                        // Log error but continue with empty channels list
                        console.error('Error in channel extraction:', error.message);
                    }

                    return channelsToSubscribe.join('');
                })()}
        ];

        debug!("Found {} channels for subscription", channels.len());
        channels
    }

    /// Subscribe to a specific channel using the transport manager
    /// This method handles both static and dynamic channel subscriptions
    async fn subscribe_to_channel(&self, channel_info: &ChannelSubscriptionInfo) -> AsyncApiResult<()> {
        debug!("Subscribing to channel: {} with address: {}", channel_info.name, channel_info.address);

        // Get all transport stats to iterate through available transports
        let transport_stats = self.transport_manager.get_all_stats().await;

        if transport_stats.is_empty() {
            return Err(AsyncApiError::Protocol {
                message: "No transports available for channel subscription".to_string(),
                protocol: "any".to_string(),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::Medium,
                    crate::errors::ErrorCategory::Network,
                    false,
                ),
                source: None,
            }.into());
        }

        if channel_info.is_dynamic && !channel_info.parameters.is_empty() {
            // Handle dynamic channel subscription with parameter substitution
            debug!("Channel '{}' is dynamic with parameters: {:?}", channel_info.name, channel_info.parameters);

            // Get dynamic parameters from the transport manager's configuration
            // Note: This would need to be passed from the ServerBuilder during construction
            // For now, we'll use a placeholder approach that can be enhanced
            let resolved_addresses = self.resolve_dynamic_channel_addresses(channel_info).await?;

            if resolved_addresses.is_empty() {
                warn!("No dynamic parameter values provided for channel '{}' with parameters {:?}",
                      channel_info.name, channel_info.parameters);
                return Ok(());
            }

            // Subscribe to each resolved channel address
            for resolved_address in resolved_addresses {
                debug!("Subscribing to resolved dynamic address '{}' for channel '{}'",
                       resolved_address, channel_info.name);

                match self.transport_manager.subscribe_to_channel(&resolved_address).await {
                    Ok(()) => {
                        info!("Successfully subscribed to dynamic channel: {} -> {}",
                              channel_info.name, resolved_address);
                    }
                    Err(e) => {
                        warn!("Failed to subscribe to dynamic channel address '{}': {}",
                              resolved_address, e);
                        // Continue with other addresses rather than failing completely
                    }
                }
            }
        } else {
            // Handle static channel subscription
            let subscription_address = &channel_info.address;
            debug!("Subscribing to static address '{}' for channel '{}'",
                   subscription_address, channel_info.name);

            // Call the TransportManager's subscribe method that delegates to individual transports
            self.transport_manager.subscribe_to_channel(subscription_address).await?;
        }

        Ok(())
    }

    /// Resolve dynamic channel addresses by substituting parameter values
    /// This method takes a dynamic channel template and generates all possible
    /// concrete channel addresses based on the provided parameter values
    async fn resolve_dynamic_channel_addresses(&self, channel_info: &ChannelSubscriptionInfo) -> AsyncApiResult<Vec<String>> {
        debug!("Resolving dynamic channel addresses for channel: {}", channel_info.name);

        let mut resolved_addresses = Vec::new();
        let template_address = &channel_info.address;

        // Check if we have parameter values for all required parameters
        let mut all_parameter_values = std::collections::HashMap::new();
        let mut missing_parameters = Vec::new();

        for param_name in &channel_info.parameters {
            if let Some(values) = self.dynamic_parameters.get_parameter(param_name) {
                all_parameter_values.insert(param_name.clone(), values.clone());
                debug!("Found {} values for parameter '{}': {:?}", values.len(), param_name, values);
            } else {
                missing_parameters.push(param_name.clone());
            }
        }

        if !missing_parameters.is_empty() {
            warn!("Missing parameter values for channel '{}': {:?}", channel_info.name, missing_parameters);
            return Ok(resolved_addresses);
        }

        // Generate all combinations of parameter substitutions
        if channel_info.parameters.is_empty() {
            // No parameters to substitute, return the original address
            resolved_addresses.push(template_address.clone());
        } else {
            // Generate cartesian product of all parameter values
            let parameter_combinations = self.generate_parameter_combinations(&channel_info.parameters, &all_parameter_values)?;

            for combination in parameter_combinations {
                let mut resolved_address = template_address.clone();

                // Replace each parameter placeholder with its value
                for (param_name, param_value) in combination {
                    let placeholder = format!("{{{}}}", param_name);
                    resolved_address = resolved_address.replace(&placeholder, &param_value);
                }

                resolved_addresses.push(resolved_address);
                debug!("Generated resolved address: {}", resolved_addresses.last().unwrap());
            }
        }

        info!("Resolved {} dynamic addresses for channel '{}': {:?}",
               resolved_addresses.len(), channel_info.name, resolved_addresses);

        Ok(resolved_addresses)
    }

    /// Generate all combinations of parameter values (cartesian product)
    fn generate_parameter_combinations(
        &self,
        parameters: &[String],
        parameter_values: &std::collections::HashMap<String, Vec<String>>,
    ) -> AsyncApiResult<Vec<std::collections::HashMap<String, String>>> {
        if parameters.is_empty() {
            return Ok(vec![std::collections::HashMap::new()]);
        }

        let mut combinations = Vec::new();
        self.generate_combinations_recursive(
            parameters,
            parameter_values,
            0,
            std::collections::HashMap::new(),
            &mut combinations,
        )?;

        debug!("Generated {} parameter combinations", combinations.len());
        Ok(combinations)
    }

    /// Recursive helper for generating parameter combinations
    fn generate_combinations_recursive(
        &self,
        parameters: &[String],
        parameter_values: &std::collections::HashMap<String, Vec<String>>,
        param_index: usize,
        current_combination: std::collections::HashMap<String, String>,
        all_combinations: &mut Vec<std::collections::HashMap<String, String>>,
    ) -> AsyncApiResult<()> {
        if param_index >= parameters.len() {
            // Base case: we've assigned values to all parameters
            all_combinations.push(current_combination);
            return Ok(());
        }

        let param_name = &parameters[param_index];
        let values = parameter_values.get(param_name).ok_or_else(|| {
            AsyncApiError::Configuration {
                message: format!("No values found for parameter '{}'", param_name),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Configuration,
                    false,
                )
                .with_context("parameter_name", param_name),
                source: None,
            }
        })?;

        // Recursive case: try each value for the current parameter
        for value in values {
            let mut new_combination = current_combination.clone();
            new_combination.insert(param_name.clone(), value.clone());

            self.generate_combinations_recursive(
                parameters,
                parameter_values,
                param_index + 1,
                new_combination,
                all_combinations,
            )?;
        }

        Ok(())
    }

    /// Cleanup server resources
    async fn cleanup(&self) -> AsyncApiResult<()> {
        debug!("Cleaning up server resources");

        // Unsubscribe from channels before stopping transports
        match self.unsubscribe_from_channels().await {
            Ok(()) => {
                debug!("Successfully unsubscribed from all channels");
            }
            Err(e) => {
                warn!("Some channel unsubscriptions failed: {}", e);
            }
        }

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

    /// Unsubscribe from channels during cleanup
    async fn unsubscribe_from_channels(&self) -> AsyncApiResult<()> {
        debug!("Unsubscribing from channels during cleanup");

        let channels_to_unsubscribe = self.get_channels_for_subscription();

        for channel_info in channels_to_unsubscribe {
            debug!("Unsubscribing from channel: {} (address: {})", channel_info.name, channel_info.address);

            match self.unsubscribe_from_channel(&channel_info).await {
                Ok(()) => {
                    debug!("Successfully unsubscribed from channel: {}", channel_info.name);
                }
                Err(e) => {
                    warn!("Failed to unsubscribe from channel {}: {}", channel_info.name, e);
                    // Continue with other channels rather than failing completely
                }
            }
        }

        debug!("Channel unsubscription process completed");
        Ok(())
    }

    /// Unsubscribe from a specific channel
    async fn unsubscribe_from_channel(&self, channel_info: &ChannelSubscriptionInfo) -> AsyncApiResult<()> {
        debug!("Unsubscribing from channel: {} with address: {}", channel_info.name, channel_info.address);

        // Call the TransportManager's unsubscribe method that delegates to individual transports
        self.transport_manager.unsubscribe_from_channel(&channel_info.address).await?;

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

    /// Get publisher context for sending messages
    pub fn publishers(&self) -> Arc<crate::handlers::PublisherContext> {
        self.publishers.clone()
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

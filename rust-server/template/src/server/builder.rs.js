/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ServerBuilderRs({ asyncapi, params }) {
    // Check if auth feature is enabled
    const enableAuth = params.enableAuth === 'true' || params.enableAuth === true;

    // Helper functions for Rust identifier generation
    function toRustIdentifier(str) {
        if (!str) return 'unknown';
        let identifier = str
            .replace(/[^a-zA-Z0-9_]/g, '_')
            .replace(/^[0-9]/, '_$&')
            .replace(/_+/g, '_')
            .replace(/^_+|_+$/g, '');
        if (/^[0-9]/.test(identifier)) {
            identifier = 'item_' + identifier;
        }
        if (!identifier) {
            identifier = 'unknown';
        }
        const rustKeywords = [
            'as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern',
            'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match',
            'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self',
            'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe',
            'use', 'where', 'while', 'async', 'await', 'dyn'
        ];
        if (rustKeywords.includes(identifier)) {
            identifier = identifier + '_';
        }
        return identifier;
    }

    function toRustTypeName(str) {
        if (!str) return 'Unknown';
        const identifier = toRustIdentifier(str);

        // Handle camelCase and PascalCase inputs by splitting on capital letters too
        const parts = identifier
            .replace(/([a-z])([A-Z])/g, '$1_$2') // Insert underscore before capital letters
            .split(/[_\s-]+/) // Split on underscores, spaces, and hyphens
            .filter(part => part.length > 0);

        return parts
            .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
            .join('');
    }

    function toRustFieldName(str) {
        if (!str) return 'unknown';
        const identifier = toRustIdentifier(str);
        return identifier
            .replace(/([A-Z])/g, '_$1')
            .toLowerCase()
            .replace(/^_/, '')
            .replace(/_+/g, '_');
    }

    // Helper function to detect request/response patterns
    function analyzeOperationPattern(channelOps, channelName) {
        const sendOps = channelOps.filter(op => op.action === 'send');
        const receiveOps = channelOps.filter(op => op.action === 'receive');

        // Look for request/response patterns
        const patterns = [];

        // Process send operations (server handles incoming requests)
        for (const sendOp of sendOps) {
            // Check if this send operation has a reply message defined
            let hasReply = false;
            let replyMessage = null;

            // Check if the send operation has a reply field (AsyncAPI 3.x)
            if (sendOp.reply) {
                hasReply = true;
                replyMessage = sendOp.reply;
            }

            if (hasReply) {
                // Request/Response pattern: server receives request and sends response
                patterns.push({
                    type: 'request_response',
                    operation: sendOp,
                    requestMessage: sendOp.messages[0],
                    responseMessage: replyMessage
                });
            } else {
                // Request-only pattern: server receives and processes request
                patterns.push({
                    type: 'request_only',
                    operation: sendOp,
                    requestMessage: sendOp.messages[0]
                });
            }
        }

        // Process receive operations (server sends outgoing messages)
        for (const receiveOp of receiveOps) {
            patterns.push({
                type: 'send_message',
                operation: receiveOp,
                message: receiveOp.messages[0]
            });
        }

        return patterns;
    }

    // Extract servers from AsyncAPI specification
    const servers = asyncapi.servers();
    const serverData = [];

    if (servers) {
        for (const [serverName, server] of Object.entries(servers)) {
            const protocol = server.protocol && typeof server.protocol === 'function' ? server.protocol() : server.protocol;
            const url = server.url && typeof server.url === 'function' ? server.url() : server.url;
            const description = server.description && typeof server.description === 'function' ? server.description() : server.description;

            if (protocol && url) {
                serverData.push({
                    name: serverName,
                    protocol: protocol.toLowerCase(),
                    url: url,
                    description: description || ''
                });
            }
        }
    }

    // Extract channels and their operations
    const channels = asyncapi.channels();
    const operations = asyncapi.operations && asyncapi.operations();
    const channelData = [];

    if (channels) {
        // Process each channel using the proper AsyncAPI collection iteration
        for (const channel of channels) {
            const channelName = channel.id();
            const channelOps = [];

            // For AsyncAPI 3.x: Find operations that reference this channel
            if (operations) {
                for (const operation of operations) {
                    const operationId = operation.id();
                    try {
                        const operationChannel = operation.channel && operation.channel();

                        // Check if this operation belongs to the current channel
                        // The channel data is embedded in the operation's _json.channel
                        let belongsToChannel = false;

                        // Check the embedded channel data in operation._json.channel
                        const embeddedChannel = operation._json && operation._json.channel;
                        if (embeddedChannel) {
                            // Check if the embedded channel's unique object ID matches our channel name
                            const embeddedChannelId = embeddedChannel['x-parser-unique-object-id'];
                            if (embeddedChannelId === channelName) {
                                belongsToChannel = true;
                            }
                        }

                        if (belongsToChannel) {
                            const action = operation.action && operation.action();
                            const messages = operation.messages && operation.messages();

                            // Check for reply information
                            const reply = operation.reply && operation.reply();
                            let replyMessage = null;
                            if (reply) {
                                // Get the reply message
                                const replyMessages = reply.messages && reply.messages();
                                if (replyMessages && replyMessages.length > 0) {
                                    replyMessage = replyMessages[0];
                                } else {
                                    // Try to get single message from reply
                                    replyMessage = reply.message && reply.message();
                                }
                            }

                            channelOps.push({
                                name: operationId,
                                action,
                                messages: messages || [],
                                reply: replyMessage,
                                rustName: toRustFieldName(operationId)
                            });
                        }
                    } catch (e) {
                        // Skip operations that cause errors
                        console.warn(`Skipping operation ${operationId} due to error:`, e.message);
                    }
                }
            }

            // For AsyncAPI 2.x: Check for operations directly on the channel
            // Only add these if no operations were found in the operations collection
            if (channelOps.length === 0) {
                const subscribe = channel.subscribe && channel.subscribe();
                const publish = channel.publish && channel.publish();

                if (subscribe) {
                    const operationId = subscribe.operationId && subscribe.operationId();
                    const summary = subscribe.summary && subscribe.summary();
                    const message = subscribe.message && subscribe.message();

                    channelOps.push({
                        name: operationId || `subscribe_${channelName}`,
                        action: 'receive',
                        messages: message ? [message] : [],
                        rustName: toRustFieldName(operationId || `subscribe_${channelName}`)
                    });
                }

                if (publish) {
                    const operationId = publish.operationId && publish.operationId();
                    const summary = publish.summary && publish.summary();
                    const message = publish.message && publish.message();

                    channelOps.push({
                        name: operationId || `publish_${channelName}`,
                        action: 'send',
                        messages: message ? [message] : [],
                        rustName: toRustFieldName(operationId || `publish_${channelName}`)
                    });
                }
            }

            // Analyze operation patterns for this channel
            const patterns = analyzeOperationPattern(channelOps, channelName);

            // Clean channel name for code generation (remove path parameters)
            const cleanChannelName = channelName.replace(/\{[^}]+\}/g, '');

            channelData.push({
                name: channelName,
                cleanName: cleanChannelName,
                rustName: toRustTypeName(cleanChannelName + '_handler'),
                fieldName: toRustFieldName(cleanChannelName + '_handler'),
                traitName: toRustTypeName(cleanChannelName + '_service'),
                typeName: toRustTypeName(cleanChannelName),
                address: channel.address && channel.address(),
                description: channel.description && channel.description(),
                operations: channelOps,
                patterns: patterns
            });
        }
    }

    return (
        <File name="builder.rs">
            {`//! Server builder for AsyncAPI service with simplified direct routing
//!
//! This module provides a builder pattern for creating and configuring
//! the AsyncAPI server with direct TransportManager routing and handler registration.

use crate::config::Config;
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::handlers::*;
use crate::recovery::RecoveryManager;
use crate::transport::{TransportManager, factory::TransportFactory};
use crate::middleware::MiddlewarePipeline;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, debug};

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
    // Authentication configuration
    ${enableAuth ? `#[cfg(feature = "auth")]
    auth_validator: Option<Arc<crate::auth::MultiAuthValidator>>,`: ''}${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
    ${channel.fieldName}_service: Option<Arc<dyn ${channel.traitName}>>,`).join('')}
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
            ${enableAuth ? `#[cfg(feature = "auth")]
            auth_validator: None,`: ''}${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
            ${channel.fieldName}_service: None,`).join('')}
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

    ${enableAuth ? `
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
    }`: ''}${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `

    /// Set the service implementation for ${channel.name} channel
    pub fn with_${channel.fieldName}_service(mut self, service: Arc<dyn ${channel.traitName}>) -> Self {
        self.${channel.fieldName}_service = Some(service);
        self
    }`).join('')}

    /// Build the server with simplified direct routing
    /// This automatically creates and configures:
    /// - TransportManager for direct message routing
    /// - Channel-specific message handlers
    /// - Direct handler registration with TransportManager
    /// - Transports with handlers pre-configured during creation
    /// - No complex router layer needed!
    pub async fn build(mut self) -> AsyncApiResult<crate::Server> {
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

        // Setup transports WITH handlers pre-configured
        self.setup_transports_with_handlers(&transport_manager, &operation_handlers).await?;

        // Register handlers with transport manager for direct routing
        for (operation_name, handler) in operation_handlers {
            transport_manager.register_handler(operation_name.clone(), handler).await;
            info!("Registered direct routing for {} operation", operation_name);
        }

        info!("Direct routing system fully configured - no router layer needed!");

        // Extract scopes from AsyncAPI specification BEFORE moving self.config
        ${enableAuth ? `#[cfg(feature = "auth")]
        let operation_scopes = self.extract_operation_scopes()?;` : ''}

        // Move config before creating server
        let config = self.config;

        // Create server instance with publishers
        let server = crate::Server::new_with_components_and_publishers(
            config,
            recovery_manager.clone(),
            transport_manager,
            middleware,
            publishers,
        ).await?;

        ${enableAuth ? `
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
        }`: ''}

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

        ${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
        // Create operation handlers for ${channel.name} channel
        if let Some(service) = self.${channel.fieldName}_service.take() {
            debug!("Creating operation handlers for ${channel.name} channel");
            ${channel.patterns.filter(p => p.type === 'request_response' || p.type === 'request_only').map(pattern => {
                const operationHandlerName = toRustTypeName(pattern.operation.name + '_operation_handler');
                return `
            // Create ${pattern.operation.name} operation handler
            let ${pattern.operation.rustName}_handler = Arc::new(crate::handlers::${operationHandlerName}::new(
                service.clone(),
                recovery_manager.clone(),
                transport_manager.clone(),
            ));

            let operation_requires_security = security_config.get("${pattern.operation.name}").unwrap_or(&false);

            let final_${pattern.operation.rustName}_handler = ${pattern.operation.rustName}_handler as Arc<dyn crate::transport::MessageHandler>;

            ${enableAuth ? `#[cfg(not(feature = "auth"))]
            let final_${pattern.operation.rustName}_handler = {
                debug!("Creating ${pattern.operation.name} operation handler (auth feature disabled)");
                ${pattern.operation.rustName}_handler as Arc<dyn crate::transport::MessageHandler>
            };`: ''}

            handlers.insert("${pattern.operation.name}".to_string(), final_${pattern.operation.rustName}_handler);

            ${enableAuth ? `#[cfg(feature = "auth")]
            info!("Created handler for ${pattern.operation.name} operation with auth support: {} (requires security: {})",
                  self.auth_validator.is_some(), *operation_requires_security);
            #[cfg(not(feature = "auth"))]
            info!("Created handler for ${pattern.operation.name} operation (auth feature disabled)");` : ''}`;
            }).join('')}
        } else {
            debug!("No service provided for ${channel.name} channel - skipping operation handler creation");
        }`).join('')}

        info!("Created {} operation handlers", handlers.len());
        Ok(handlers)
    }

    /// Setup transports with pre-configured handlers based on AsyncAPI server specifications
    async fn setup_transports_with_handlers(
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
    async fn setup_default_transport_with_handler(
        &self,
        transport_manager: &TransportManager,
        _channel_handlers: &HashMap<String, Arc<dyn crate::transport::MessageHandler>>,
    ) -> AsyncApiResult<()> {
        debug!("Setting up default HTTP transport using TransportManager as handler");

        let http_config = crate::transport::TransportConfig {
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
        let servers = vec![${serverData.map(server => `
            ("${server.name}".to_string(), ServerConfig {
                protocol: "${server.protocol}".to_string(),
                url: "${server.url}".to_string(),
                description: "${server.description}".to_string(),
            }),`).join('')}
        ];

        debug!("Found {} servers in AsyncAPI specification", servers.len());
        Ok(servers)
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
        transport_manager.add_transport(server_name.to_string(), transport).await?;

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
        transport_manager.add_transport("default-http".to_string(), transport).await?;

        info!("Default HTTP transport configured successfully");
        Ok(())
    }

    /// Check if a channel has any operations that require security
    /// This method analyzes the AsyncAPI specification to determine if authentication
    /// should be applied to the channel's handlers
    fn channel_requires_security(&self, channel_name: &str) -> bool {
        // Parse security requirements from AsyncAPI specification during template generation
        // Static mapping based on the channel analysis

        match channel_name {${(() => {
                    // Generate security requirement mappings during template generation
                    const channelSecurityMap = new Map();

                    // Helper function to check if an operation has security requirements
                    function operationHasSecurity(operation) {
                        // Check if operation has security defined in AsyncAPI spec
                        const operations = asyncapi.operations && asyncapi.operations();
                        if (!operations) return false;

                        for (const op of operations) {
                            const opId = op.id();
                            if (opId === operation.name) {
                                // Check if operation has security requirements
                                const security = op.security && op.security();
                                if (security && security.length > 0) {
                                    return true;
                                }

                                // Also check if operation is defined with security in the operation object
                                const opSecurity = op._json && op._json.security;
                                if (opSecurity && opSecurity.length > 0) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    }

                    // Analyze each channel to see if any operations require security
                    for (const channel of channelData) {
                        let channelHasSecurity = false;

                        for (const operation of channel.operations) {
                            if (operationHasSecurity(operation)) {
                                channelHasSecurity = true;
                                break;
                            }
                        }

                        channelSecurityMap.set(channel.name, channelHasSecurity);
                    }

                    // Generate Rust match statements for channel security requirements
                    const securityChecks = [];
                    for (const [channelName, hasSecurity] of channelSecurityMap) {
                        securityChecks.push(`\n            "${channelName}" => ${hasSecurity},`);
                    }

                    return securityChecks.join('');
                })()}
            _ => false, // Default: no security required for unknown channels
        }
    }

    ${enableAuth ? `/// Extract operation scopes from AsyncAPI specification for authorization middleware
    /// Scopes are parsed during template generation and embedded as static data
    #[cfg(feature = "auth")]
    fn extract_operation_scopes(&self) -> AsyncApiResult<std::collections::HashMap<String, Vec<String>>> {
        debug!("Loading pre-parsed operation scopes from AsyncAPI specification");

        #[allow(unused_mut)]
        let mut operation_scopes = std::collections::HashMap::new();

        // Pre-parsed scopes from AsyncAPI specification during template generation
${(() => {
                        // Parse scopes from all operations during template generation
                        const operationScopeMap = new Map();

                        // Helper function to parse scopes from description
                        function parseScopesFromDescription(description) {
                            if (!description) return [];
                            const scopes = [];
                            // Parse description for scope patterns like "- device:provision: Description"
                            const scopeMatches = description.match(/^[\s]*-[\s]*([a-zA-Z0-9_]+:[a-zA-Z0-9_]+)[\s]*:/gm);
                            if (scopeMatches) {
                                for (const match of scopeMatches) {
                                    const scopeMatch = match.match(/^[\s]*-[\s]*([a-zA-Z0-9_]+:[a-zA-Z0-9_]+)[\s]*:/);
                                    if (scopeMatch && scopeMatch[1]) {
                                        scopes.push(scopeMatch[1]);
                                    }
                                }
                            }
                            return scopes;
                        }

                        // Helper function to get operation description from AsyncAPI spec
                        function getOperationDescription(operationName) {
                            const operations = asyncapi.operations && asyncapi.operations();
                            if (!operations) return null;

                            for (const operation of operations) {
                                const opId = operation.id();
                                if (opId === operationName) {
                                    const description = operation.description && operation.description();
                                    return description;
                                }
                            }
                            return null;
                        }

                        // Helper function to parse scopes from security schemes
                        function parseScopesFromSecuritySchemes() {
                            const securitySchemes = asyncapi.components() && asyncapi.components().securitySchemes();
                            if (!securitySchemes) return [];

                            const scopes = [];
                            for (const [schemeName, scheme] of Object.entries(securitySchemes)) {
                                const description = scheme.description && typeof scheme.description === 'function'
                                    ? scheme.description()
                                    : scheme.description;

                                if (description) {
                                    // Parse operation-level permissions from security scheme descriptions
                                    const operationPermissionsMatch = description.match(/Operation-level permissions?:\s*([\s\S]*?)(?:\n\n|\n\s*[A-Z]|$)/i);
                                    if (operationPermissionsMatch) {
                                        const permissionsText = operationPermissionsMatch[1];
                                        const permissionMatches = permissionsText.match(/^[\s]*-[\s]*([a-zA-Z0-9_]+:[a-zA-Z0-9_]+)[\s]*:/gm);
                                        if (permissionMatches) {
                                            for (const match of permissionMatches) {
                                                const scopeMatch = match.match(/^[\s]*-[\s]*([a-zA-Z0-9_]+:[a-zA-Z0-9_]+)[\s]*:/);
                                                if (scopeMatch && scopeMatch[1]) {
                                                    scopes.push(scopeMatch[1]);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            return scopes;
                        }

                        // Helper function to get operation-specific scopes based on patterns
                        function getOperationSpecificScopes(operation, availableScopes) {
                            const scopes = [];
                            const opName = operation.name.toLowerCase();

                            // Chat operations
                            if (opName.includes('chat') || opName.includes('message')) {
                                if (operation.action === 'send') {
                                    if (availableScopes.includes('chat:write')) scopes.push('chat:write');
                                } else if (operation.action === 'receive') {
                                    if (availableScopes.includes('chat:read')) scopes.push('chat:read');
                                }
                            }

                            // Profile operations
                            if (opName.includes('profile') || opName.includes('user')) {
                                if (operation.action === 'send') {
                                    if (availableScopes.includes('profile:write')) scopes.push('profile:write');
                                    if (availableScopes.includes('user:self')) scopes.push('user:self');
                                }
                            }

                            // Device operations (for the user's example)
                            if (opName.includes('device') || opName.includes('provision')) {
                                if (availableScopes.includes('device:provision')) scopes.push('device:provision');
                            }

                            return scopes;
                        }

                        // Helper function to get basic scopes from security requirements
                        function getBasicScopesFromSecurity(operation) {
                            const security = operation.security;
                            if (!security || security.length === 0) return [];

                            const basicScopes = [];
                            const opName = operation.name.toLowerCase();

                            // Determine basic scopes based on operation action and name
                            if (operation.action === 'send') {
                                if (opName.includes('chat') || opName.includes('message')) {
                                    basicScopes.push('chat:write');
                                } else if (opName.includes('profile') || opName.includes('user')) {
                                    basicScopes.push('profile:write');
                                } else {
                                    // Generic write permission
                                    basicScopes.push('write:' + opName);
                                }
                            } else if (operation.action === 'receive') {
                                if (opName.includes('chat') || opName.includes('message')) {
                                    basicScopes.push('chat:read');
                                } else {
                                    // Generic read permission
                                    basicScopes.push('read:' + opName);
                                }
                            }

                            return basicScopes;
                        }

                        // Parse available scopes from security schemes
                        const availableScopes = parseScopesFromSecuritySchemes();

                        // Process each operation and extract scopes
                        for (const channel of channelData) {
                            for (const operation of channel.operations) {
                                const allScopes = new Set();

                                // Strategy 1: Parse from operation description
                                const operationDescription = getOperationDescription(operation.name);
                                const descriptionScopes = parseScopesFromDescription(operationDescription);
                                descriptionScopes.forEach(scope => allScopes.add(scope));

                                // Strategy 2: Map to security scheme scopes
                                const securityScopes = getOperationSpecificScopes(operation, availableScopes);
                                securityScopes.forEach(scope => allScopes.add(scope));

                                // Strategy 3: Basic scopes from security requirements
                                const basicScopes = getBasicScopesFromSecurity(operation);
                                basicScopes.forEach(scope => allScopes.add(scope));

                                // Store the scopes for this operation
                                if (allScopes.size > 0) {
                                    operationScopeMap.set(operation.name, Array.from(allScopes).sort());
                                }
                            }
                        }

                        // Generate Rust code for the scope mappings
                        const scopeEntries = [];
                        for (const [operationName, scopes] of operationScopeMap) {
                            scopeEntries.push(`        operation_scopes.insert("${operationName}".to_string(), vec![${scopes.map(scope => `"${scope}".to_string()`).join(', ')}]);`);
                        }

                        return scopeEntries.join('\n');
                    })()}

        debug!("Loaded {} operation scope configurations", operation_scopes.len());
        Ok(operation_scopes)
    }`: ''}
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

/// Simplified server builder that automatically sets up everything
/// This is the easiest way to get started - just provide your service implementations
pub struct AutoServerBuilder {${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
    ${channel.fieldName}_service: Option<Arc<dyn ${channel.traitName}>>,`).join('')}
    middleware: Vec<Box<dyn crate::middleware::Middleware>>,
    // Simplified recovery configuration
    recovery_preset: Option<RecoveryPreset>,
    retry_strategy: Option<crate::recovery::RetryConfig>,
    circuit_breaker_threshold: Option<u32>,
    max_concurrent_operations: Option<usize>,
    ${enableAuth ? `// Authentication configuration
    #[cfg(feature = "auth")]
    auth_validator: Option<Arc<crate::auth::MultiAuthValidator>>,` : ''}
}

impl AutoServerBuilder {
    /// Create a new auto server builder
    pub fn new() -> Self {
        Self {${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
            ${channel.fieldName}_service: None,`).join('')}
            middleware: Vec::new(),
            recovery_preset: None,
            retry_strategy: None,
            circuit_breaker_threshold: None,
            max_concurrent_operations: None,
            ${enableAuth ? `#[cfg(feature = "auth")]
            auth_validator: None,`: ''}
        }
    }${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `

    /// Set the service implementation for ${channel.name} channel
    pub fn with_${channel.fieldName}_service(mut self, service: Arc<dyn ${channel.traitName}>) -> Self {
        self.${channel.fieldName}_service = Some(service);
        self
    }`).join('')}

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

    ${enableAuth ? `#[cfg(feature = "auth")]
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
    }` : ''}

    /// Build and start the server with automatic configuration
    /// This is the simplest way to get a fully configured server running
    pub async fn build_and_start(self) -> AsyncApiResult<crate::Server> {
        info!("Building and starting AsyncAPI server with full automatic configuration");

        let server = self.build().await?;
        server.start().await?;

        Ok(server)
    }

    /// Build the server without starting it
    pub async fn build(self) -> AsyncApiResult<crate::Server> {
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

        ${enableAuth ? `// Transfer authentication configuration
        #[cfg(feature = "auth")]
        if let Some(auth_validator) = self.auth_validator {
            builder = builder.with_auth_validator(auth_validator);
        }`: ''}${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `

        if let Some(service) = self.${channel.fieldName}_service {
            builder = builder.with_${channel.fieldName}_service(service);
        }`).join('')}

        let server = builder.build().await?;

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

`}
        </File>
    );
}

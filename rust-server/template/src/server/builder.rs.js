/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ServerBuilderRs({ asyncapi, params }) {
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
use std::sync::Arc;
use std::collections::HashMap;
use tracing::{info, debug};

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
    transport_manager: Option<Arc<TransportManager>>,${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
    ${channel.fieldName}_service: Option<Arc<dyn ${channel.traitName}>>,`).join('')}
}

impl ServerBuilder {
    /// Create a new server builder with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            config,
            recovery_manager: None,
            transport_manager: None,${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
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
    }${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `

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

        // Create channel handlers FIRST (before transports)
        let channel_handlers = self.create_channel_handlers(&recovery_manager, &transport_manager).await?;

        // Setup transports WITH handlers pre-configured
        self.setup_transports_with_handlers(&transport_manager, &channel_handlers).await?;

        // Register handlers with transport manager for direct routing
        for (channel_name, handler) in channel_handlers {
            transport_manager.register_handler(channel_name.clone(), handler).await;
            info!("Registered direct routing for {} channel", channel_name);
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

    /// Create channel handlers before transport setup
    #[allow(unused_variables)]
    async fn create_channel_handlers(
        &mut self,
        recovery_manager: &Arc<RecoveryManager>,
        transport_manager: &Arc<TransportManager>,
    ) -> AsyncApiResult<HashMap<String, Arc<dyn crate::transport::MessageHandler>>> {
        #[allow(unused_mut)]
        let mut handlers = HashMap::new();${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `

        // Create ${channel.name} channel handler
        if let Some(service) = self.${channel.fieldName}_service.take() {
            debug!("Creating ${channel.name} channel handler");
            let handler = Arc::new(${channel.rustName}::new(
                service,
                recovery_manager.clone(),
                transport_manager.clone(),
            ));
            let message_handler = Arc::new(${channel.typeName}MessageHandler::new(handler));
            handlers.insert("${channel.name}".to_string(), message_handler as Arc<dyn crate::transport::MessageHandler>);
            info!("Created handler for ${channel.name} channel");
        } else {
            debug!("No service provided for ${channel.name} channel - skipping handler creation");
        }`).join('')}

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
            // Find the appropriate handler for this transport
            let handler = self.find_handler_for_transport(&server_name, &server_config, channel_handlers);

            match self.setup_server_transport_with_handler(&server_name, &server_config, transport_manager, handler).await {
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

    /// Find the appropriate handler for a transport based on channel mapping
    fn find_handler_for_transport(
        &self,
        _server_name: &str,
        _server_config: &ServerConfig,
        channel_handlers: &HashMap<String, Arc<dyn crate::transport::MessageHandler>>,
    ) -> Option<Arc<dyn crate::transport::MessageHandler>> {
        // For now, use the first available handler
        // In a more sophisticated implementation, you might:
        // 1. Map specific channels to specific transports
        // 2. Use server names to determine handler routing
        // 3. Support multiple handlers per transport
        channel_handlers.values().next().cloned()
    }

    /// Setup a single server as a transport with handler
    async fn setup_server_transport_with_handler(
        &self,
        server_name: &str,
        server_config: &ServerConfig,
        transport_manager: &TransportManager,
        handler: Option<Arc<dyn crate::transport::MessageHandler>>,
    ) -> AsyncApiResult<()> {
        debug!(
            server = %server_name,
            protocol = %server_config.protocol,
            url = %server_config.url,
            has_handler = handler.is_some(),
            "Setting up transport for server with handler"
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
            "Creating transport with configuration and handler"
        );

        // Create transport using factory WITH handler
        let transport = crate::transport::factory::TransportFactory::create_transport_with_handler(transport_config, handler)?;

        // Add to transport manager
        transport_manager.add_transport(server_name.to_string(), transport).await?;

        info!(
            server = %server_name,
            protocol = %server_config.protocol,
            "Transport configured successfully with handler"
        );

        Ok(())
    }

    /// Setup default HTTP transport with handler when no servers are defined
    async fn setup_default_transport_with_handler(
        &self,
        transport_manager: &TransportManager,
        channel_handlers: &HashMap<String, Arc<dyn crate::transport::MessageHandler>>,
    ) -> AsyncApiResult<()> {
        debug!("Setting up default HTTP transport with handler");

        let http_config = crate::transport::TransportConfig {
            protocol: "http".to_string(),
            host: "0.0.0.0".to_string(),
            port: 8080,
            username: None,
            password: None,
            tls: false,
            additional_config: HashMap::new(),
        };

        // Find an appropriate handler
        let handler = channel_handlers.values().next().cloned();

        debug!(
            protocol = %http_config.protocol,
            host = %http_config.host,
            port = http_config.port,
            has_handler = handler.is_some(),
            "Creating default HTTP transport with handler"
        );

        // Create transport using factory WITH handler
        let transport = crate::transport::factory::TransportFactory::create_transport_with_handler(http_config, handler)?;

        // Add to transport manager
        transport_manager.add_transport("default-http".to_string(), transport).await?;

        info!("Default HTTP transport configured successfully with handler");
        Ok(())
    }

    /// Setup transports based on AsyncAPI server specifications (legacy method)
    async fn setup_transports(&self, transport_manager: &TransportManager) -> AsyncApiResult<()> {
        debug!("Setting up transports from AsyncAPI server specifications");

        // Get servers from AsyncAPI specification
        let servers = self.get_asyncapi_servers()?;

        if servers.is_empty() {
            info!("No servers defined in AsyncAPI specification, setting up default HTTP transport");
            return self.setup_default_transport(transport_manager).await;
        }

        info!("Found {} server(s) in AsyncAPI specification", servers.len());

        // Setup each server as a transport
        for (server_name, server_config) in servers {
            match self.setup_server_transport(&server_name, &server_config, transport_manager).await {
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
            self.setup_default_transport(transport_manager).await?;
        }

        info!("Transport setup completed with {} active transport(s)", transport_count);
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
                    "Protocol mismatch for server '{}': URL protocol '{}' doesn't match server protocol '{}'",
                    server_name, protocol, server_config.protocol
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
}

impl AutoServerBuilder {
    /// Create a new auto server builder
    pub fn new() -> Self {
        Self {${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
            ${channel.fieldName}_service: None,`).join('')}
            middleware: Vec::new(),
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

    /// Build and start the server with automatic configuration
    /// This is the simplest way to get a fully configured server running
    pub async fn build_and_start(self) -> AsyncApiResult<()> {
        info!("Building and starting AsyncAPI server with full automatic configuration");

        let server = self.build().await?;
        server.start().await?;

        Ok(())
    }

    /// Build the server without starting it
    pub async fn build(self) -> AsyncApiResult<crate::Server> {
        #[allow(unused_mut)]
        let mut builder = ServerBuilder::new(Config::default());${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `

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

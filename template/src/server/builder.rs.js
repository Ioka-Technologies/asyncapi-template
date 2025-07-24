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
use tracing::{info, debug};

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
        self.setup_transports(&transport_manager).await?;${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `

        // Register ${channel.name} channel handler directly with TransportManager (SIMPLIFIED)
        if let Some(service) = self.${channel.fieldName}_service.take() {
            debug!("Setting up ${channel.name} channel handler with direct routing");
            let handler = Arc::new(${channel.rustName}::new(
                service,
                recovery_manager.clone(),
                transport_manager.clone(),
            ));
            let message_handler = Arc::new(${channel.typeName}MessageHandler::new(handler));
            transport_manager.register_handler("${channel.name}".to_string(), message_handler).await;
            info!("Registered direct routing for ${channel.name} channel");
        } else {
            debug!("No service provided for ${channel.name} channel - skipping handler registration");
        }`).join('')}

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
pub struct AutoServerBuilder {${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
    ${channel.fieldName}_service: Option<Arc<dyn ${channel.traitName}>>,`).join('')}
}

impl AutoServerBuilder {
    /// Create a new auto server builder
    pub fn new() -> Self {
        Self {${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `
            ${channel.fieldName}_service: None,`).join('')}
        }
    }${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `

    /// Set the service implementation for ${channel.name} channel
    pub fn with_${channel.fieldName}_service(mut self, service: Arc<dyn ${channel.traitName}>) -> Self {
        self.${channel.fieldName}_service = Some(service);
        self
    }`).join('')}

    /// Build and start the server with automatic configuration
    /// This is the simplest way to get a fully configured server running
    pub async fn build_and_start(self) -> AsyncApiResult<()> {
        info!("Building and starting AsyncAPI server with full automatic configuration");

        #[allow(unused_mut)]
        let mut builder = ServerBuilder::new(Config::default());${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).map(channel => `

        if let Some(service) = self.${channel.fieldName}_service {
            builder = builder.with_${channel.fieldName}_service(service);
        }`).join('')}

        let server = builder.build().await?;
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

        builder.build().await
    }
}

impl Default for AutoServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_builder_default() {
        let server = ServerBuilder::default().build().await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_auto_server_builder() {
        let server = AutoServerBuilder::new().build().await;
        assert!(server.is_ok());
    }
}
`}
        </File>
    );
}

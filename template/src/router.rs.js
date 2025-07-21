import { File } from '@asyncapi/generator-react-sdk';
import { rustFunctionName, rustStructName } from '../helpers/rust-helpers';

export default function routerFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async_std' : 'tokio';
    const generateModels = params.generateModels !== false;

    // Get all operations from the AsyncAPI spec
    const operations = [];

    // Process channels and their operations
    for (const [channelName, channel] of asyncapi.channels()) {
        const channelOperations = channel.operations();
        for (const [operationId, operation] of channelOperations) {
            const action = operation.action();
            const messages = operation.messages();

            operations.push({
                id: operationId,
                action,
                channel: channelName,
                operation,
                messages: Array.from(messages.values())
            });
        }
    }

    // Filter to only receive operations (messages we handle)
    const receiveOperations = operations.filter(op => op.action === 'receive');

    return (
        <File name="src/router.rs">
            {`//! Message routing for AsyncAPI server
//!
//! This module provides message routing functionality that dispatches
//! incoming messages to the appropriate handlers based on the operation
//! and message type.

use crate::context::MessageContext;
use crate::error::{HandlerResult, HandlerError, ErrorKind};
use crate::handlers::{HandlerRegistry, JsonCodec, MessageCodec};
${generateModels ? 'use crate::models::*;' : ''}
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use log::{debug, error, info, warn};

/// Trait for routing messages to handlers
#[async_trait]
pub trait MessageRouter: Send + Sync {
    /// Route a message to the appropriate handler
    ///
    /// # Arguments
    /// * \`message\` - The raw message bytes
    /// * \`context\` - Message context with routing information
    ///
    /// # Returns
    /// * \`Ok(Vec<u8>)\` - Response bytes (empty for fire-and-forget)
    /// * \`Err(HandlerError)\` - Routing or handler error
    async fn route_message(&self, message: &[u8], context: &mut MessageContext) -> HandlerResult<Vec<u8>>;

    /// Check if a route exists for the given operation and topic
    fn has_route(&self, operation: &str, topic: &str) -> bool;

    /// Get all available routes
    fn get_routes(&self) -> Vec<RouteInfo>;
}

/// Information about a route
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Operation ID
    pub operation: String,
    /// Topic/channel pattern
    pub topic: String,
    /// Message types handled by this route
    pub message_types: Vec<String>,
    /// Whether this is a request-response route
    pub is_request_response: bool,
}

/// Default message router implementation
pub struct DefaultMessageRouter {
    /// Handler registry
    handlers: Arc<HandlerRegistry>,
    /// Message codec for serialization
    codec: Arc<dyn MessageCodec<serde_json::Value> + Send + Sync>,
    /// Route mapping from (operation, topic) to handler info
    routes: HashMap<(String, String), RouteHandler>,
}

/// Handler information for routing
#[derive(Debug, Clone)]
struct RouteHandler {
    operation: String,
    message_types: Vec<String>,
    is_request_response: bool,
}

impl DefaultMessageRouter {
    /// Create a new message router
    pub fn new(handlers: Arc<HandlerRegistry>) -> Self {
        let mut router = Self {
            handlers,
            codec: Arc::new(JsonCodec),
            routes: HashMap::new(),
        };

        router.initialize_routes();
        router
    }

    /// Create a router with custom codec
    pub fn with_codec(
        handlers: Arc<HandlerRegistry>,
        codec: Arc<dyn MessageCodec<serde_json::Value> + Send + Sync>,
    ) -> Self {
        let mut router = Self {
            handlers,
            codec,
            routes: HashMap::new(),
        };

        router.initialize_routes();
        router
    }

    /// Initialize route mappings from AsyncAPI specification
    fn initialize_routes(&mut self) {
${receiveOperations.map(op => {
                const messages = op.messages.map(msg => `"${msg.uid()}"`).join(', ');
                const hasResponse = op.messages.some(msg => msg.correlationId());

                return `        // Route for ${op.id} operation
        self.routes.insert(
            ("${op.id}".to_string(), "${op.channel}".to_string()),
            RouteHandler {
                operation: "${op.id}".to_string(),
                message_types: vec![${messages}],
                is_request_response: ${hasResponse},
            },
        );`;
            }).join('\n')}
    }

    /// Route message based on operation and topic
    async fn route_by_operation(&self, operation: &str, topic: &str, message: &[u8], context: &mut MessageContext) -> HandlerResult<Vec<u8>> {
        let route_key = (operation.to_string(), topic.to_string());

        if let Some(route_handler) = self.routes.get(&route_key) {
            debug!("Routing message to operation: {} on topic: {}", operation, topic);

            match operation {
${receiveOperations.map(op => {
                const handlerName = rustStructName(op.id) + 'Handler';
                const functionName = rustFunctionName(op.id);
                const isRequestResponse = op.messages.some(msg => msg.correlationId());

                if (isRequestResponse) {
                    // Find request and response message types
                    const requestMessage = op.messages.find(msg => !msg.correlationId() ||
                        op.messages.filter(m => m.correlationId() === msg.correlationId()).length === 1);
                    const responseMessage = op.messages.find(msg => msg.correlationId() && msg !== requestMessage);

                    if (requestMessage && responseMessage) {
                        const requestName = rustStructName(requestMessage.uid());
                        const responseName = rustStructName(responseMessage.uid());

                        return `                "${op.id}" => {
                    if let Some(handler) = self.handlers.get_${functionName}_handler() {
                        // Deserialize request
                        let request: ${requestName} = serde_json::from_slice(message)
                            .map_err(|e| HandlerError::serialization("Failed to deserialize ${requestName}", e)
                                .with_operation("${op.id}")
                                .with_topic("${op.channel}"))?;

                        // Call handler
                        let response = handler.${functionName}(request, context).await?;

                        // Serialize response
                        let response_bytes = serde_json::to_vec(&response)
                            .map_err(|e| HandlerError::serialization("Failed to serialize ${responseName}", e)
                                .with_operation("${op.id}")
                                .with_topic("${op.channel}"))?;

                        Ok(response_bytes)
                    } else {
                        Err(HandlerError::configuration("No handler registered for ${op.id}")
                            .with_operation("${op.id}")
                            .with_topic("${op.channel}"))
                    }
                }`;
                    }
                } else {
                    // Fire-and-forget pattern
                    const messageName = rustStructName(op.messages[0].uid());

                    return `                "${op.id}" => {
                    if let Some(handler) = self.handlers.get_${functionName}_handler() {
                        // Deserialize message
                        let msg: ${messageName} = serde_json::from_slice(message)
                            .map_err(|e| HandlerError::serialization("Failed to deserialize ${messageName}", e)
                                .with_operation("${op.id}")
                                .with_topic("${op.channel}"))?;

                        // Call handler
                        handler.${functionName}(msg, context).await?;

                        // Fire-and-forget returns empty response
                        Ok(Vec::new())
                    } else {
                        Err(HandlerError::configuration("No handler registered for ${op.id}")
                            .with_operation("${op.id}")
                            .with_topic("${op.channel}"))
                    }
                }`;
                }
            }).join('\n')}
                _ => {
                    Err(HandlerError::configuration(&format!("Unknown operation: {}", operation))
                        .with_operation(operation)
                        .with_topic(topic))
                }
            }
        } else {
            Err(HandlerError::configuration(&format!("No route found for operation: {} on topic: {}", operation, topic))
                .with_operation(operation)
                .with_topic(topic))
        }
    }

    /// Attempt to infer operation from topic pattern
    fn infer_operation_from_topic(&self, topic: &str) -> Option<String> {
        // Try to match topic patterns to known operations
${receiveOperations.map(op => {
                return `        if topic.starts_with("${op.channel}") || topic == "${op.channel}" {
            return Some("${op.id}".to_string());
        }`;
            }).join('\n')}

        None
    }

    /// Attempt to infer operation from message content
    async fn infer_operation_from_message(&self, message: &[u8]) -> Option<String> {
        // Try to parse as JSON and look for operation indicators
        if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(message) {
            // Look for common operation indicators
            if let Some(obj) = json_value.as_object() {
                // Check for explicit operation field
                if let Some(op) = obj.get("operation").and_then(|v| v.as_str()) {
                    return Some(op.to_string());
                }

                // Check for message type field
                if let Some(msg_type) = obj.get("type").and_then(|v| v.as_str()) {
                    // Map message types to operations
${receiveOperations.map(op => {
                return op.messages.map(msg => {
                    return `                    if msg_type == "${msg.uid()}" {
                        return Some("${op.id}".to_string());
                    }`;
                }).join('\n');
            }).join('\n')}
                }
            }
        }

        None
    }
}

#[async_trait]
impl MessageRouter for DefaultMessageRouter {
    async fn route_message(&self, message: &[u8], context: &mut MessageContext) -> HandlerResult<Vec<u8>> {
        let operation = &context.operation;
        let topic = &context.protocol_metadata.topic;

        debug!("Routing message: operation={}, topic={}, size={}", operation, topic, message.len());

        // First try explicit operation routing
        if operation != "unknown" {
            return self.route_by_operation(operation, topic, message, context).await;
        }

        // Try to infer operation from topic
        if let Some(inferred_op) = self.infer_operation_from_topic(topic) {
            context.operation = inferred_op.clone();
            info!("Inferred operation '{}' from topic '{}'", inferred_op, topic);
            return self.route_by_operation(&inferred_op, topic, message, context).await;
        }

        // Try to infer operation from message content
        if let Some(inferred_op) = self.infer_operation_from_message(message).await {
            context.operation = inferred_op.clone();
            info!("Inferred operation '{}' from message content", inferred_op);
            return self.route_by_operation(&inferred_op, topic, message, context).await;
        }

        // No route found
        Err(HandlerError::configuration(&format!("Unable to route message: no operation specified and could not infer from topic '{}' or message content", topic))
            .with_topic(topic))
    }

    fn has_route(&self, operation: &str, topic: &str) -> bool {
        self.routes.contains_key(&(operation.to_string(), topic.to_string()))
    }

    fn get_routes(&self) -> Vec<RouteInfo> {
        self.routes.iter().map(|((operation, topic), handler)| {
            RouteInfo {
                operation: operation.clone(),
                topic: topic.clone(),
                message_types: handler.message_types.clone(),
                is_request_response: handler.is_request_response,
            }
        }).collect()
    }
}

/// Builder for creating message routers with custom configuration
pub struct MessageRouterBuilder {
    handlers: Option<Arc<HandlerRegistry>>,
    codec: Option<Arc<dyn MessageCodec<serde_json::Value> + Send + Sync>>,
}

impl MessageRouterBuilder {
    /// Create a new router builder
    pub fn new() -> Self {
        Self {
            handlers: None,
            codec: None,
        }
    }

    /// Set the handler registry
    pub fn with_handlers(mut self, handlers: Arc<HandlerRegistry>) -> Self {
        self.handlers = Some(handlers);
        self
    }

    /// Set the message codec
    pub fn with_codec(mut self, codec: Arc<dyn MessageCodec<serde_json::Value> + Send + Sync>) -> Self {
        self.codec = Some(codec);
        self
    }

    /// Build the message router
    pub fn build(self) -> Result<DefaultMessageRouter, String> {
        let handlers = self.handlers.ok_or("Handler registry is required")?;

        let router = if let Some(codec) = self.codec {
            DefaultMessageRouter::with_codec(handlers, codec)
        } else {
            DefaultMessageRouter::new(handlers)
        };

        Ok(router)
    }
}

impl Default for MessageRouterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::MessageContext;

    #[test]
    fn test_route_info() {
        let route = RouteInfo {
            operation: "test_operation".to_string(),
            topic: "test/topic".to_string(),
            message_types: vec!["TestMessage".to_string()],
            is_request_response: false,
        };

        assert_eq!(route.operation, "test_operation");
        assert_eq!(route.topic, "test/topic");
        assert!(!route.is_request_response);
    }

    #[test]
    fn test_router_builder() {
        let handlers = Arc::new(HandlerRegistry::new());
        let codec = Arc::new(JsonCodec);

        let builder = MessageRouterBuilder::new()
            .with_handlers(handlers)
            .with_codec(codec);

        let router = builder.build();
        assert!(router.is_ok());
    }

    #[test]
    fn test_router_builder_missing_handlers() {
        let builder = MessageRouterBuilder::new();
        let router = builder.build();
        assert!(router.is_err());
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_route_inference() {
        let handlers = Arc::new(HandlerRegistry::new());
        let router = DefaultMessageRouter::new(handlers);

        // Test topic inference
${receiveOperations.slice(0, 1).map(op => {
                return `        let inferred = router.infer_operation_from_topic("${op.channel}");
        assert_eq!(inferred, Some("${op.id}".to_string()));`;
            }).join('\n')}

        // Test message inference
        let message_with_type = serde_json::json!({
            "type": "${receiveOperations[0]?.messages[0]?.uid() || 'TestMessage'}",
            "data": "test"
        });
        let message_bytes = serde_json::to_vec(&message_with_type).unwrap();
        let inferred = router.infer_operation_from_message(&message_bytes).await;
        assert!(inferred.is_some());
    }

    #[test]
    fn test_route_registry() {
        let handlers = Arc::new(HandlerRegistry::new());
        let router = DefaultMessageRouter::new(handlers);

        let routes = router.get_routes();
        assert!(!routes.is_empty());

${receiveOperations.slice(0, 1).map(op => {
                return `        assert!(router.has_route("${op.id}", "${op.channel}"));`;
            }).join('\n')}
    }
}
`}
        </File>
    );
}

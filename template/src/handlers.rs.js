import { File } from '@asyncapi/generator-react-sdk';
import { rustFunctionName, rustStructName } from '../helpers/rust-helpers';

export default function handlersFile({ asyncapi, params }) {
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

    return (
        <File name="src/handlers.rs">
            {`//! Generated handler traits for AsyncAPI operations
//!
//! This module contains trait definitions for each operation defined in the AsyncAPI specification.
//! Implement these traits to provide business logic for your server.

use crate::context::MessageContext;
use crate::error::{HandlerResult, HandlerError};
${generateModels ? 'use crate::models::*;' : ''}
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Base trait for all message handlers
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Handle a raw message
    async fn handle_raw(&self, message: &[u8], context: &MessageContext) -> HandlerResult<Vec<u8>>;
}

/// Trait for handlers that support request-response patterns
#[async_trait]
pub trait RequestResponseHandler<TRequest, TResponse>: Send + Sync
where
    TRequest: for<'de> Deserialize<'de> + Send,
    TResponse: Serialize + Send,
{
    /// Handle a request and return a response
    async fn handle_request(&self, request: TRequest, context: &MessageContext) -> HandlerResult<TResponse>;
}

/// Trait for handlers that process fire-and-forget messages
#[async_trait]
pub trait FireAndForgetHandler<TMessage>: Send + Sync
where
    TMessage: for<'de> Deserialize<'de> + Send,
{
    /// Handle a fire-and-forget message
    async fn handle_message(&self, message: TMessage, context: &MessageContext) -> HandlerResult<()>;
}

${operations.map(op => {
                const handlerName = rustStructName(op.id) + 'Handler';
                const functionName = rustFunctionName(op.id);
                const isSubscribe = op.action === 'receive';
                const isPublish = op.action === 'send';

                // For subscribe operations, we handle incoming messages
                // For publish operations, we might validate outgoing messages

                let traitDefinition = '';

                if (isSubscribe) {
                    // This is a message we receive and need to handle
                    op.messages.forEach((message, index) => {
                        const messageName = rustStructName(message.uid());
                        const responseMessage = message.correlationId() ?
                            op.messages.find(m => m.correlationId() === message.correlationId() && m !== message) : null;

                        if (responseMessage) {
                            // Request-response pattern
                            const responseName = rustStructName(responseMessage.uid());
                            traitDefinition += `
/// Handler trait for ${op.id} operation (request-response pattern)
///
/// Channel: ${op.channel}
/// Action: ${op.action}
/// Message: ${message.uid()}
/// Response: ${responseMessage.uid()}
#[async_trait]
pub trait ${handlerName}: Send + Sync {
    /// Handle ${op.id} request
    ///
    /// # Arguments
    /// * \`request\` - The incoming ${messageName} request
    /// * \`context\` - Message context with correlation ID and metadata
    ///
    /// # Returns
    /// * \`Ok(${responseName})\` - The response to send back
    /// * \`Err(HandlerError)\` - Error that occurred during processing
    async fn ${functionName}(
        &self,
        request: ${messageName},
        context: &MessageContext,
    ) -> HandlerResult<${responseName}>;
}

/// Convenience trait for simpler error handling in ${op.id}
#[async_trait]
pub trait Simple${handlerName}: Send + Sync {
    /// Handle ${op.id} request with anyhow error handling
    async fn ${functionName}(
        &self,
        request: ${messageName},
        context: &MessageContext,
    ) -> anyhow::Result<${responseName}>;
}

/// Auto-implement the main trait for simple handlers
#[async_trait]
impl<T: Simple${handlerName}> ${handlerName} for T {
    async fn ${functionName}(
        &self,
        request: ${messageName},
        context: &MessageContext,
    ) -> HandlerResult<${responseName}> {
        self.${functionName}(request, context)
            .await
            .map_err(|e| HandlerError::from_anyhow(e, crate::error::ErrorKind::BusinessLogic)
                .with_operation("${op.id}")
                .with_correlation_id(context.correlation_id.as_deref().unwrap_or("unknown"))
                .with_topic("${op.channel}"))
    }
}`;
                        } else {
                            // Fire-and-forget pattern
                            traitDefinition += `
/// Handler trait for ${op.id} operation (fire-and-forget pattern)
///
/// Channel: ${op.channel}
/// Action: ${op.action}
/// Message: ${message.uid()}
#[async_trait]
pub trait ${handlerName}: Send + Sync {
    /// Handle ${op.id} message
    ///
    /// # Arguments
    /// * \`message\` - The incoming ${messageName} message
    /// * \`context\` - Message context with metadata
    ///
    /// # Returns
    /// * \`Ok(())\` - Message processed successfully
    /// * \`Err(HandlerError)\` - Error that occurred during processing
    async fn ${functionName}(
        &self,
        message: ${messageName},
        context: &MessageContext,
    ) -> HandlerResult<()>;
}

/// Convenience trait for simpler error handling in ${op.id}
#[async_trait]
pub trait Simple${handlerName}: Send + Sync {
    /// Handle ${op.id} message with anyhow error handling
    async fn ${functionName}(
        &self,
        message: ${messageName},
        context: &MessageContext,
    ) -> anyhow::Result<()>;
}

/// Auto-implement the main trait for simple handlers
#[async_trait]
impl<T: Simple${handlerName}> ${handlerName} for T {
    async fn ${functionName}(
        &self,
        message: ${messageName},
        context: &MessageContext,
    ) -> HandlerResult<()> {
        self.${functionName}(message, context)
            .await
            .map_err(|e| HandlerError::from_anyhow(e, crate::error::ErrorKind::BusinessLogic)
                .with_operation("${op.id}")
                .with_correlation_id(context.correlation_id.as_deref().unwrap_or("unknown"))
                .with_topic("${op.channel}"))
    }
}`;
                        }
                    });
                } else if (isPublish) {
                    // This is a message we send - we might want validation handlers
                    op.messages.forEach((message, index) => {
                        const messageName = rustStructName(message.uid());

                        traitDefinition += `
/// Validator trait for ${op.id} operation (outgoing message validation)
///
/// Channel: ${op.channel}
/// Action: ${op.action}
/// Message: ${message.uid()}
#[async_trait]
pub trait ${handlerName}: Send + Sync {
    /// Validate ${op.id} message before sending
    ///
    /// # Arguments
    /// * \`message\` - The outgoing ${messageName} message
    /// * \`context\` - Message context with metadata
    ///
    /// # Returns
    /// * \`Ok(())\` - Message is valid and can be sent
    /// * \`Err(HandlerError)\` - Validation failed
    async fn ${functionName}(
        &self,
        message: &${messageName},
        context: &MessageContext,
    ) -> HandlerResult<()>;
}

/// Convenience trait for simpler error handling in ${op.id}
#[async_trait]
pub trait Simple${handlerName}: Send + Sync {
    /// Validate ${op.id} message with anyhow error handling
    async fn ${functionName}(
        &self,
        message: &${messageName},
        context: &MessageContext,
    ) -> anyhow::Result<()>;
}

/// Auto-implement the main trait for simple handlers
#[async_trait]
impl<T: Simple${handlerName}> ${handlerName} for T {
    async fn ${functionName}(
        &self,
        message: &${messageName},
        context: &MessageContext,
    ) -> HandlerResult<()> {
        self.${functionName}(message, context)
            .await
            .map_err(|e| HandlerError::from_anyhow(e, crate::error::ErrorKind::Validation)
                .with_operation("${op.id}")
                .with_correlation_id(context.correlation_id.as_deref().unwrap_or("unknown"))
                .with_topic("${op.channel}"))
    }
}`;
                    });
                }

                return traitDefinition;
            }).join('\n')}

/// Registry for storing handler implementations
#[derive(Default)]
pub struct HandlerRegistry {
${operations.map(op => {
                const handlerName = rustStructName(op.id) + 'Handler';
                return `    /// Handler for ${op.id} operation
    pub ${rustFunctionName(op.id)}_handler: Option<Box<dyn ${handlerName}>>,`;
            }).join('\n')}
}

impl HandlerRegistry {
    /// Create a new handler registry
    pub fn new() -> Self {
        Self::default()
    }

${operations.map(op => {
                const handlerName = rustStructName(op.id) + 'Handler';
                const functionName = rustFunctionName(op.id);

                return `    /// Register a handler for ${op.id} operation
    pub fn register_${functionName}_handler(&mut self, handler: Box<dyn ${handlerName}>) {
        self.${functionName}_handler = Some(handler);
    }

    /// Get the handler for ${op.id} operation
    pub fn get_${functionName}_handler(&self) -> Option<&dyn ${handlerName}> {
        self.${functionName}_handler.as_ref().map(|h| h.as_ref())
    }`;
            }).join('\n')}

    /// Check if all required handlers are registered
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut missing = Vec::new();

${operations.filter(op => op.action === 'receive').map(op => {
                const functionName = rustFunctionName(op.id);
                return `        if self.${functionName}_handler.is_none() {
            missing.push("${op.id}".to_string());
        }`;
            }).join('\n')}

        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }

    /// Get the number of registered handlers
    pub fn handler_count(&self) -> usize {
        let mut count = 0;
${operations.map(op => {
                const functionName = rustFunctionName(op.id);
                return `        if self.${functionName}_handler.is_some() { count += 1; }`;
            }).join('\n')}
        count
    }
}

/// Helper trait for converting between message types and raw bytes
pub trait MessageCodec<T>: Send + Sync {
    /// Serialize a message to bytes
    fn encode(&self, message: &T) -> HandlerResult<Vec<u8>>;

    /// Deserialize bytes to a message
    fn decode(&self, bytes: &[u8]) -> HandlerResult<T>;
}

/// JSON codec implementation
pub struct JsonCodec;

impl<T> MessageCodec<T> for JsonCodec
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    fn encode(&self, message: &T) -> HandlerResult<Vec<u8>> {
        serde_json::to_vec(message)
            .map_err(|e| HandlerError::serialization("Failed to encode message to JSON", e))
    }

    fn decode(&self, bytes: &[u8]) -> HandlerResult<T> {
        serde_json::from_slice(bytes)
            .map_err(|e| HandlerError::serialization("Failed to decode message from JSON", e))
    }
}

/// Handler wrapper that provides automatic serialization/deserialization
pub struct CodecHandler<T, H, C> {
    handler: H,
    codec: C,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, H, C> CodecHandler<T, H, C> {
    /// Create a new codec handler
    pub fn new(handler: H, codec: C) -> Self {
        Self {
            handler,
            codec,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<T, H, C> MessageHandler for CodecHandler<T, H, C>
where
    T: for<'de> Deserialize<'de> + Send + 'static,
    H: FireAndForgetHandler<T> + Send + Sync,
    C: MessageCodec<T> + Send + Sync,
{
    async fn handle_raw(&self, message: &[u8], context: &MessageContext) -> HandlerResult<Vec<u8>> {
        let decoded_message = self.codec.decode(message)?;
        self.handler.handle_message(decoded_message, context).await?;
        Ok(Vec::new()) // Fire-and-forget returns empty response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::MessageContext;

    #[test]
    fn test_handler_registry() {
        let registry = HandlerRegistry::new();
        assert_eq!(registry.handler_count(), 0);
    }

    #[test]
    fn test_json_codec() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestMessage {
            id: u32,
            content: String,
        }

        let codec = JsonCodec;
        let message = TestMessage {
            id: 123,
            content: "test".to_string(),
        };

        let encoded = codec.encode(&message).unwrap();
        let decoded: TestMessage = codec.decode(&encoded).unwrap();

        assert_eq!(message, decoded);
    }

    struct TestHandler;

    #[async_trait]
    impl FireAndForgetHandler<String> for TestHandler {
        async fn handle_message(&self, _message: String, _context: &MessageContext) -> HandlerResult<()> {
            Ok(())
        }
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_codec_handler() {
        let handler = TestHandler;
        let codec = JsonCodec;
        let codec_handler = CodecHandler::new(handler, codec);

        let context = MessageContext::new("test", "topic");
        let message = serde_json::to_vec(&"test message").unwrap();

        let result = codec_handler.handle_raw(&message, &context).await;
        assert!(result.is_ok());
    }
}
`}
        </File>
    );
}

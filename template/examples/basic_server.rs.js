import { File } from '@asyncapi/generator-react-sdk';
import { rustFunctionName, rustStructName } from '../helpers/rust-helpers';

export default function basicServerExampleFile({ asyncapi, params }) {
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
        <File name="examples/basic_server.rs">
            {`//! Basic AsyncAPI Server Example
//!
//! This example demonstrates how to create and run a basic AsyncAPI server
//! with handlers for all defined operations.

use ${asyncapi.info().title().toLowerCase().replace(/[^a-z0-9]/g, '_')}::prelude::*;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use log::{info, error};
use anyhow::Result;

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

                        return `/// Example handler for ${op.id} operation (request-response)
#[derive(Debug)]
pub struct Example${handlerName};

#[async_trait]
impl Simple${handlerName} for Example${handlerName} {
    async fn ${functionName}(
        &self,
        request: ${requestName},
        context: &MessageContext,
    ) -> Result<${responseName}> {
        info!("Handling ${op.id} request: {:?}", request);
        info!("Request context - correlation_id: {:?}, user_id: {:?}",
              context.correlation_id, context.user_id);

        // TODO: Implement your business logic here
        // This is just an example response
        let response = ${responseName} {
            // TODO: Fill in response fields based on your schema
            ..Default::default()
        };

        info!("Sending ${op.id} response: {:?}", response);
        Ok(response)
    }
}`;
                    }
                } else {
                    // Fire-and-forget pattern
                    const messageName = rustStructName(op.messages[0].uid());

                    return `/// Example handler for ${op.id} operation (fire-and-forget)
#[derive(Debug)]
pub struct Example${handlerName};

#[async_trait]
impl Simple${handlerName} for Example${handlerName} {
    async fn ${functionName}(
        &self,
        message: ${messageName},
        context: &MessageContext,
    ) -> Result<()> {
        info!("Handling ${op.id} message: {:?}", message);
        info!("Message context - user_id: {:?}, session_id: {:?}",
              context.user_id, context.session_id);

        // TODO: Implement your business logic here
        // For example, you might:
        // - Store the message in a database
        // - Process the data
        // - Trigger other operations
        // - Send notifications

        info!("Successfully processed ${op.id} message");
        Ok(())
    }
}`;
                }
            }).join('\n\n')}

#[${runtime === 'tokio' ? 'tokio::main' : 'async_std::main'}]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    info!("Starting ${asyncapi.info().title()} server");

    // Create server configuration
    let config = Config::default();

    // Create handler registry and register handlers
    let mut handlers = HandlerRegistry::new();

${receiveOperations.map(op => {
                const handlerName = rustStructName(op.id) + 'Handler';
                const functionName = rustFunctionName(op.id);

                return `    // Register ${op.id} handler
    handlers.register_${functionName}_handler(Box::new(Example${handlerName}));`;
            }).join('\n')}

    let handlers = Arc::new(handlers);

    // Create and configure the server
    let mut server = AsyncApiServerBuilder::new()
        .with_config(config)
        .with_handlers(handlers)
        .with_middleware(Arc::new(LoggingMiddleware::new()))
        .with_middleware(Arc::new(MetricsMiddleware::new()))
        .with_middleware(Arc::new(TracingMiddleware::new("${asyncapi.info().title().toLowerCase()}")))
        .build()
        .await?;

    // Set up graceful shutdown
    let server_handle = Arc::new(std::sync::Mutex::new(server));
    let shutdown_handle = server_handle.clone();

    // Handle shutdown signals
    ${runtime === 'tokio' ? 'tokio::spawn' : 'async_std::task::spawn'}(async move {
        ${runtime === 'tokio' ? `
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();

        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = sigint.recv() => info!("Received SIGINT"),
        }
        ` : `
        // For async-std, we'll use a simple approach
        // In production, you'd want proper signal handling
        async_std::task::sleep(Duration::from_secs(3600)).await;
        `}

        info!("Initiating graceful shutdown...");
        if let Ok(mut server) = shutdown_handle.lock() {
            if let Err(e) = server.shutdown_with_timeout(Duration::from_secs(30)).await {
                error!("Error during shutdown: {}", e);
            }
        }
    });

    // Start the server
    {
        let mut server = server_handle.lock().unwrap();
        server.start().await?;
    }

    info!("Server started successfully on ${protocol}");
    info!("Press Ctrl+C to stop the server");

    // Wait for shutdown
    {
        let server = server_handle.lock().unwrap();
        server.wait_for_shutdown().await?;
    }

    info!("Server stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ${asyncapi.info().title().toLowerCase().replace(/[^a-z0-9]/g, '_')}::context::MessageContext;

${receiveOperations.slice(0, 2).map(op => {
                const handlerName = rustStructName(op.id) + 'Handler';
                const functionName = rustFunctionName(op.id);
                const isRequestResponse = op.messages.some(msg => msg.correlationId());

                if (isRequestResponse) {
                    const requestMessage = op.messages.find(msg => !msg.correlationId() ||
                        op.messages.filter(m => m.correlationId() === msg.correlationId()).length === 1);
                    const responseName = rustStructName(op.messages.find(msg => msg.correlationId() && msg !== requestMessage)?.uid() || 'Response');
                    const requestName = rustStructName(requestMessage?.uid() || 'Request');

                    return `    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_${functionName}_handler() {
        let handler = Example${handlerName};
        let context = MessageContext::new("${op.id}", "${op.channel}");

        // Create a test request
        let request = ${requestName} {
            // TODO: Fill in test data based on your schema
            ..Default::default()
        };

        let result = handler.${functionName}(request, &context).await;
        assert!(result.is_ok());
    }`;
                } else {
                    const messageName = rustStructName(op.messages[0].uid());

                    return `    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_${functionName}_handler() {
        let handler = Example${handlerName};
        let context = MessageContext::new("${op.id}", "${op.channel}");

        // Create a test message
        let message = ${messageName} {
            // TODO: Fill in test data based on your schema
            ..Default::default()
        };

        let result = handler.${functionName}(message, &context).await;
        assert!(result.is_ok());
    }`;
                }
            }).join('\n\n')}
}
`}
        </File>
    );
}

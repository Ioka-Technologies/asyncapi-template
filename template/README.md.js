import { File } from '@asyncapi/generator-react-sdk';
import { kebabCase } from '../helpers/index';

export default function readmeFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();
    const packageName = params.packageName || kebabCase(asyncapi.info().title()) || 'asyncapi_server';
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async-std' : 'tokio';

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
        <File name="README.md">
            {`# ${asyncapi.info().title()} Server

${asyncapi.info().description() || 'AsyncAPI generated Rust server'}

This is a production-ready Rust server library generated from an AsyncAPI specification. It provides a complete server implementation with middleware, routing, error handling, and observability for the **${protocol.toUpperCase()}** protocol using the **${runtime}** async runtime.

## 🚀 Features

- 🦀 **Type-safe**: All message types and handlers are generated as Rust structs with proper serialization/deserialization
- ⚡ **High Performance**: Built on ${runtime} for high-performance async I/O with minimal overhead
- 🔒 **Protocol Support**: Native ${protocol.toUpperCase()} protocol implementation with trait-based architecture
- 🏗️ **Modular Design**: Clean separation between transport, middleware, routing, and business logic
- 🛡️ **Comprehensive Error Handling**: Rich error types with context and structured error responses
- 🔌 **Middleware System**: Extensible middleware for logging, metrics, authentication, rate limiting, and tracing
- 📊 **Built-in Observability**: Structured logging, metrics collection, and distributed tracing support
- 🎯 **Request-Response & Fire-and-Forget**: Support for both synchronous and asynchronous message patterns
- 📝 **Auto-generated Documentation**: Complete API documentation generated from AsyncAPI schemas
- 🧪 **Testing Support**: Built-in test utilities and example implementations

## 📦 Installation

Add this to your \`Cargo.toml\`:

\`\`\`toml
[dependencies]
${packageName} = "0.1.0"
${runtime} = { version = "1.0", features = ["full"] }
async-trait = "0.1"
serde = { version = "1.0", features = ["derive"] }
anyhow = "1.0"
log = "0.4"
env_logger = "0.10"
\`\`\`

## 🏃 Quick Start

### Basic Server

\`\`\`rust
use ${packageName.replace(/-/g, '_')}::prelude::*;
use async_trait::async_trait;
use anyhow::Result;

${receiveOperations.slice(0, 1).map(op => {
                const handlerName = `Example${op.id.charAt(0).toUpperCase() + op.id.slice(1)}Handler`;
                const messageName = op.messages[0]?.uid() || 'Message';
                const isRequestResponse = op.messages.some(msg => msg.correlationId());

                if (isRequestResponse) {
                    const responseName = op.messages.find(msg => msg.correlationId())?.uid() || 'Response';
                    return `// Implement your business logic
#[derive(Debug)]
struct ${handlerName};

#[async_trait]
impl Simple${op.id.charAt(0).toUpperCase() + op.id.slice(1)}Handler for ${handlerName} {
    async fn ${op.id}(
        &self,
        request: ${messageName},
        context: &MessageContext,
    ) -> Result<${responseName}> {
        // Your business logic here
        Ok(${responseName}::default())
    }
}`;
                } else {
                    return `// Implement your business logic
#[derive(Debug)]
struct ${handlerName};

#[async_trait]
impl Simple${op.id.charAt(0).toUpperCase() + op.id.slice(1)}Handler for ${handlerName} {
    async fn ${op.id}(
        &self,
        message: ${messageName},
        context: &MessageContext,
    ) -> Result<()> {
        println!("Received message: {:?}", message);
        Ok(())
    }
}`;
                }
            }).join('\n\n')}

#[${runtime === 'tokio' ? 'tokio::main' : 'async_std::main'}]
async fn main() -> Result<()> {
    env_logger::init();

    // Create configuration
    let config = Config::default();

    // Register handlers
    let mut handlers = HandlerRegistry::new();
${receiveOperations.slice(0, 1).map(op => {
                const handlerName = `Example${op.id.charAt(0).toUpperCase() + op.id.slice(1)}Handler`;
                return `    handlers.register_${op.id}_handler(Box::new(${handlerName}));`;
            }).join('\n')}

    // Build and start server
    let mut server = AsyncApiServerBuilder::new()
        .with_config(config)
        .with_handlers(Arc::new(handlers))
        .with_middleware(Arc::new(LoggingMiddleware::new()))
        .with_middleware(Arc::new(MetricsMiddleware::new()))
        .build()
        .await?;

    server.start().await?;
    server.wait_for_shutdown().await?;

    Ok(())
}
\`\`\`

## 🏗️ Architecture

The server is built with a layered architecture:

\`\`\`
┌─────────────────────────────────────────────────────────────┐
│                    Business Logic                           │
│                   (Your Handlers)                          │
├─────────────────────────────────────────────────────────────┤
│                      Routing                               │
│              (Message → Handler)                           │
├─────────────────────────────────────────────────────────────┤
│                    Middleware                              │
│         (Logging, Auth, Metrics, etc.)                    │
├─────────────────────────────────────────────────────────────┤
│                    Transport                               │
│                 (${protocol.toUpperCase()} Protocol)                              │
└─────────────────────────────────────────────────────────────┘
\`\`\`

## 📋 Generated Operations

This server handles the following operations:

${receiveOperations.map(op => {
                const pattern = op.messages.some(msg => msg.correlationId()) ? 'Request-Response' : 'Fire-and-Forget';
                return `### \`${op.id}\` (${pattern})
- **Channel**: \`${op.channel}\`
- **Pattern**: ${pattern}
- **Messages**: ${op.messages.map(m => `\`${m.uid()}\``).join(', ')}`;
            }).join('\n\n')}

## 🔧 Configuration

### Environment Variables

\`\`\`bash
# Server configuration
export SERVER_HOST="0.0.0.0"
export SERVER_PORT="8080"
export RUST_LOG="info"

${protocol === 'mqtt' || protocol === 'mqtts' ? `# MQTT specific
export MQTT_BROKER_URL="${server.url()}"
export MQTT_CLIENT_ID="server-\${HOSTNAME}"
export MQTT_KEEP_ALIVE="60"` : ''}

${protocol === 'kafka' || protocol === 'kafka-secure' ? `# Kafka specific
export KAFKA_BROKERS="${server.url()}"
export KAFKA_GROUP_ID="server-group"
export KAFKA_AUTO_OFFSET_RESET="earliest"` : ''}

${protocol === 'amqp' || protocol === 'amqps' ? `# AMQP specific
export AMQP_URL="${server.url()}"
export AMQP_EXCHANGE="asyncapi"
export AMQP_QUEUE_PREFIX="server"` : ''}
\`\`\`

### Configuration File

Create a \`config.toml\` file:

\`\`\`toml
[server]
host = "0.0.0.0"
port = 8080
max_connections = 1000

${protocol === 'mqtt' || protocol === 'mqtts' ? `[mqtt]
broker_url = "${server.url()}"
client_id = "server"
keep_alive = 60
clean_session = true
qos = 1` : ''}

${protocol === 'kafka' || protocol === 'kafka-secure' ? `[kafka]
brokers = ["${server.url()}"]
group_id = "server-group"
auto_offset_reset = "earliest"
enable_auto_commit = true
session_timeout_ms = 30000` : ''}

${protocol === 'amqp' || protocol === 'amqps' ? `[amqp]
url = "${server.url()}"
exchange = "asyncapi"
queue_prefix = "server"
durable = true` : ''}

[middleware]
enable_logging = true
enable_metrics = true
enable_tracing = true
enable_auth = false
enable_rate_limiting = false

[middleware.rate_limiting]
max_requests_per_minute = 1000

[middleware.auth]
required_headers = ["authorization"]
\`\`\`

## 🔌 Middleware

The server includes several built-in middleware components:

### Logging Middleware
Provides structured logging for all requests and responses:

\`\`\`rust
server.add_middleware(Arc::new(LoggingMiddleware::new())).await;
\`\`\`

### Metrics Middleware
Collects performance metrics:

\`\`\`rust
server.add_middleware(Arc::new(MetricsMiddleware::new())).await;
\`\`\`

### Authentication Middleware
Validates authentication tokens:

\`\`\`rust
let auth_middleware = AuthenticationMiddleware::new()
    .with_required_headers(vec!["authorization".to_string()]);
server.add_middleware(Arc::new(auth_middleware)).await;
\`\`\`

### Rate Limiting Middleware
Prevents abuse with configurable rate limits:

\`\`\`rust
let rate_limiter = RateLimitingMiddleware::new(100); // 100 requests per minute
server.add_middleware(Arc::new(rate_limiter)).await;
\`\`\`

### Tracing Middleware
Provides distributed tracing support:

\`\`\`rust
let tracing = TracingMiddleware::new("my-service");
server.add_middleware(Arc::new(tracing)).await;
\`\`\`

### Custom Middleware

Implement the \`Middleware\` trait to create custom middleware:

\`\`\`rust
use async_trait::async_trait;

#[derive(Debug)]
struct CustomMiddleware;

#[async_trait]
impl Middleware for CustomMiddleware {
    async fn before_handle(
        &self,
        message: &[u8],
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        // Pre-processing logic
        Ok(())
    }

    async fn after_handle(
        &self,
        result: &HandlerResult<Vec<u8>>,
        context: &mut MessageContext,
    ) -> MiddlewareResult<()> {
        // Post-processing logic
        Ok(())
    }

    fn name(&self) -> &'static str {
        "custom"
    }

    fn priority(&self) -> u32 {
        50 // Lower numbers run first
    }
}
\`\`\`

## 📊 Monitoring & Observability

### Health Checks

The server provides built-in health check endpoints:

\`\`\`rust
let stats = server.get_stats().await;
println!("Messages processed: {}", stats.state.messages_processed);
println!("Error rate: {:.2}%", stats.error_rate);
println!("Uptime: {}s", stats.uptime_seconds);
\`\`\`

### Metrics

Key metrics are automatically collected:

- **Messages processed**: Total number of messages handled
- **Error rate**: Percentage of failed message processing
- **Processing time**: Average time to process messages
- **Active connections**: Current number of active connections
- **Throughput**: Messages per second

### Logging

Structured logging with configurable levels:

\`\`\`bash
RUST_LOG=debug cargo run  # Debug level
RUST_LOG=info cargo run   # Info level (default)
RUST_LOG=warn cargo run   # Warning level
RUST_LOG=error cargo run  # Error level only
\`\`\`

## 🧪 Testing

### Unit Tests

Test your handlers in isolation:

\`\`\`rust
#[cfg(test)]
mod tests {
    use super::*;

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_handler() {
        let handler = MyHandler;
        let context = MessageContext::new("test_op", "test/topic");
        let message = TestMessage::default();

        let result = handler.handle_message(message, &context).await;
        assert!(result.is_ok());
    }
}
\`\`\`

### Integration Tests

Test the complete server:

\`\`\`rust
#[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
async fn test_server_integration() {
    let config = Config::default();
    let mut server = AsyncApiServer::new(config).await.unwrap();

    // Register test handlers
    // Start server
    // Send test messages
    // Verify responses
}
\`\`\`

## 📚 Examples

Check the \`examples/\` directory for complete examples:

- \`examples/basic_server.rs\` - Basic server with all handlers
- \`examples/middleware_server.rs\` - Server with custom middleware
- \`examples/auth_server.rs\` - Server with authentication
- \`examples/metrics_server.rs\` - Server with metrics collection

## 🚀 Deployment

### Docker

\`\`\`dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/server /usr/local/bin/server
EXPOSE 8080
CMD ["server"]
\`\`\`

### Kubernetes

\`\`\`yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: asyncapi-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: asyncapi-server
  template:
    metadata:
      labels:
        app: asyncapi-server
    spec:
      containers:
      - name: server
        image: your-registry/asyncapi-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: RUST_LOG
          value: "info"
        - name: SERVER_PORT
          value: "8080"
\`\`\`

## 🔧 Development

### Building

\`\`\`bash
cargo build
\`\`\`

### Testing

\`\`\`bash
cargo test
\`\`\`

### Running Examples

\`\`\`bash
cargo run --example basic_server
\`\`\`

### Generating Documentation

\`\`\`bash
cargo doc --open
\`\`\`

## 📄 License

This project is licensed under the MIT OR Apache-2.0 license.

## 🤖 Generated Code

This code was generated from an AsyncAPI specification. Do not edit manually.

- **AsyncAPI Version**: ${asyncapi.version()}
- **Generated**: ${new Date().toISOString()}
- **Protocol**: ${protocol.toUpperCase()}
- **Server**: ${params.server}
- **Runtime**: ${runtime}

For more information about AsyncAPI, visit [asyncapi.org](https://www.asyncapi.org/).
`}
        </File>
    );
}

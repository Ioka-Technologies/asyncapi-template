# AsyncAPI Rust Server Generator

A production-ready AsyncAPI code generator for creating Rust server implementations. This generator creates complete, type-safe server libraries with middleware, routing, error handling, and observability features.

## 🚀 Features

- **🦀 Type-Safe**: Generates Rust structs for all AsyncAPI message schemas with proper serialization/deserialization
- **⚡ High Performance**: Built on Tokio or async-std for high-performance async I/O
- **🏗️ Modular Architecture**: Clean separation between transport, middleware, routing, and business logic
- **🔌 Middleware System**: Extensible middleware for logging, metrics, authentication, rate limiting, and tracing
- **📊 Built-in Observability**: Structured logging, metrics collection, and distributed tracing support
- **🎯 Multiple Message Patterns**: Support for request-response and fire-and-forget patterns
- **🛡️ Comprehensive Error Handling**: Rich error types with context and structured error responses
- **🧪 Testing Support**: Built-in test utilities and example implementations
- **📝 Auto-generated Documentation**: Complete API documentation generated from AsyncAPI schemas
- **🚀 Production Ready**: Docker and Kubernetes deployment examples included

## 📋 Supported Protocols

- **MQTT/MQTTS**: Full MQTT 3.1.1 and 5.0 support with QoS levels
- **Kafka**: Apache Kafka with consumer groups and producer support
- **AMQP/AMQPS**: RabbitMQ and other AMQP 0.9.1 brokers
- **WebSocket**: Real-time bidirectional communication
- **HTTP**: RESTful APIs with async request handling

## 📦 Installation

### Using AsyncAPI CLI

```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Generate Rust server from AsyncAPI spec
asyncapi generate fromTemplate asyncapi.yaml @asyncapi/rust-template --output ./generated-server
```

### Using AsyncAPI Generator

```bash
# Install AsyncAPI Generator
npm install -g @asyncapi/generator

# Generate Rust server
ag asyncapi.yaml @asyncapi/rust-template --output ./generated-server
```

## 🏃 Quick Start

### 1. Create an AsyncAPI Specification

Create an `asyncapi.yaml` file:

```yaml
asyncapi: 3.0.0
info:
  title: User Service
  version: 1.0.0
  description: A simple user management service

servers:
  production:
    host: localhost:1883
    protocol: mqtt
    description: Production MQTT broker

channels:
  user/created:
    address: user/created
    messages:
      UserCreated:
        $ref: '#/components/messages/UserCreated'
  user/updated:
    address: user/updated
    messages:
      UserUpdated:
        $ref: '#/components/messages/UserUpdated'

operations:
  onUserCreated:
    action: receive
    channel:
      $ref: '#/channels/user~1created'
  onUserUpdated:
    action: receive
    channel:
      $ref: '#/channels/user~1updated'

components:
  messages:
    UserCreated:
      payload:
        type: object
        properties:
          id:
            type: string
            format: uuid
          name:
            type: string
          email:
            type: string
            format: email
          created_at:
            type: string
            format: date-time
        required:
          - id
          - name
          - email
          - created_at
    UserUpdated:
      payload:
        type: object
        properties:
          id:
            type: string
            format: uuid
          name:
            type: string
          email:
            type: string
            format: email
          updated_at:
            type: string
            format: date-time
        required:
          - id
          - updated_at
```

### 2. Generate the Server

```bash
asyncapi generate fromTemplate asyncapi.yaml @asyncapi/rust-template --output ./user-service
```

### 3. Implement Your Business Logic

```rust
use user_service::prelude::*;
use async_trait::async_trait;
use anyhow::Result;

#[derive(Debug)]
struct UserCreatedHandler;

#[async_trait]
impl SimpleOnUserCreatedHandler for UserCreatedHandler {
    async fn on_user_created(
        &self,
        message: UserCreated,
        context: &MessageContext,
    ) -> Result<()> {
        println!("New user created: {} ({})", message.name, message.email);

        // Your business logic here:
        // - Save to database
        // - Send welcome email
        // - Update analytics
        // - Trigger other services

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let config = Config::default();
    let mut handlers = HandlerRegistry::new();

    handlers.register_on_user_created_handler(Box::new(UserCreatedHandler));

    let mut server = AsyncApiServerBuilder::new()
        .with_config(config)
        .with_handlers(Arc::new(handlers))
        .with_middleware(Arc::new(LoggingMiddleware::new()))
        .build()
        .await?;

    server.start().await?;
    server.wait_for_shutdown().await?;

    Ok(())
}
```

### 4. Run Your Server

```bash
cd user-service
cargo run
```

## ⚙️ Generator Parameters

Configure the generator with these parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `packageName` | string | `asyncapi-server` | Name of the generated Rust package |
| `server` | string | First server | Which server from the AsyncAPI spec to use |
| `useAsyncStd` | boolean | `false` | Use async-std instead of Tokio |
| `generateModels` | boolean | `true` | Generate message model structs |
| `generateSubscribers` | boolean | `true` | Generate subscriber handlers |
| `generatePublishers` | boolean | `true` | Generate publisher methods |
| `enableMiddleware` | boolean | `true` | Include middleware system |
| `enableMetrics` | boolean | `true` | Include metrics collection |
| `enableTracing` | boolean | `true` | Include distributed tracing |

### Example with Parameters

```bash
asyncapi generate fromTemplate asyncapi.yaml @asyncapi/rust-template \
  --output ./my-server \
  --param packageName=my-awesome-server \
  --param server=production \
  --param useAsyncStd=true
```

## 🏗️ Generated Project Structure

```
generated-server/
├── Cargo.toml                 # Rust package configuration
├── README.md                  # Generated documentation
├── src/
│   ├── lib.rs                 # Main library entry point
│   ├── config.rs              # Configuration management
│   ├── context.rs             # Message context and metadata
│   ├── error.rs               # Error types and handling
│   ├── handlers.rs            # Handler traits and registry
│   ├── middleware.rs          # Middleware system
│   ├── models.rs              # Generated message types
│   ├── router.rs              # Message routing
│   ├── server.rs              # Main server implementation
│   └── transport.rs           # Protocol transport layer
├── examples/
│   ├── basic_server.rs        # Complete working example
│   ├── middleware_server.rs   # Custom middleware example
│   └── auth_server.rs         # Authentication example
├── tests/
│   ├── integration_tests.rs   # Integration test suite
│   └── handler_tests.rs       # Handler unit tests
└── docs/
    ├── architecture.md        # Architecture documentation
    ├── deployment.md          # Deployment guide
    └── api.md                 # API reference
```

## 🔧 Configuration

### Environment Variables

The generated server supports configuration via environment variables:

```bash
# Server configuration
export SERVER_HOST="0.0.0.0"
export SERVER_PORT="8080"
export RUST_LOG="info"

# Protocol-specific configuration
export MQTT_BROKER_URL="mqtt://localhost:1883"
export KAFKA_BROKERS="localhost:9092"
export AMQP_URL="amqp://localhost:5672"

# Middleware configuration
export ENABLE_METRICS="true"
export ENABLE_TRACING="true"
export ENABLE_AUTH="false"
```

### Configuration File

Create a `config.toml` file for more complex configuration:

```toml
[server]
host = "0.0.0.0"
port = 8080
max_connections = 1000

[middleware]
enable_logging = true
enable_metrics = true
enable_tracing = true
enable_auth = false

[middleware.rate_limiting]
max_requests_per_minute = 1000

[mqtt]
broker_url = "mqtt://localhost:1883"
client_id = "server"
keep_alive = 60
```

## 🔌 Middleware System

The generated server includes a powerful middleware system:

### Built-in Middleware

- **LoggingMiddleware**: Structured logging for all requests
- **MetricsMiddleware**: Performance metrics collection
- **TracingMiddleware**: Distributed tracing support
- **AuthenticationMiddleware**: Token-based authentication
- **RateLimitingMiddleware**: Request rate limiting
- **ValidationMiddleware**: Message validation

### Custom Middleware

Create custom middleware by implementing the `Middleware` trait:

```rust
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
```

## 📊 Observability

### Metrics

The server automatically collects key metrics:

- Message processing rate
- Error rates
- Processing latency
- Active connections
- Memory usage

### Logging

Structured logging with configurable levels:

```bash
RUST_LOG=debug cargo run    # Debug level
RUST_LOG=info cargo run     # Info level (default)
RUST_LOG=warn cargo run     # Warning level
RUST_LOG=error cargo run    # Error level only
```

### Tracing

Distributed tracing support with OpenTelemetry:

```rust
let tracing = TracingMiddleware::new("my-service")
    .with_service_version("1.0.0")
    .with_environment("production");
server.add_middleware(Arc::new(tracing)).await;
```

## 🧪 Testing

### Unit Tests

Test individual handlers:

```rust
#[tokio::test]
async fn test_user_created_handler() {
    let handler = UserCreatedHandler;
    let context = MessageContext::new("onUserCreated", "user/created");
    let message = UserCreated {
        id: "123".to_string(),
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
        created_at: "2023-01-01T00:00:00Z".to_string(),
    };

    let result = handler.on_user_created(message, &context).await;
    assert!(result.is_ok());
}
```

### Integration Tests

Test the complete server:

```rust
#[tokio::test]
async fn test_server_integration() {
    let config = Config::default();
    let mut server = AsyncApiServer::new(config).await.unwrap();

    // Register test handlers
    // Start server
    // Send test messages
    // Verify responses
}
```

## 🚀 Deployment

### Docker

The generator includes a production-ready Dockerfile:

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/server /usr/local/bin/server
EXPOSE 8080
CMD ["server"]
```

Build and run:

```bash
docker build -t my-server .
docker run -p 8080:8080 my-server
```

### Kubernetes

Example Kubernetes deployment:

```yaml
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
        image: my-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: RUST_LOG
          value: "info"
        - name: SERVER_PORT
          value: "8080"
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Clone the repository:
```bash
git clone https://github.com/asyncapi/rust-template.git
cd rust-template
```

2. Install dependencies:
```bash
npm install
```

3. Run tests:
```bash
npm test
```

4. Test with a sample AsyncAPI spec:
```bash
npm run test:generate
```

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [AsyncAPI Specification](https://www.asyncapi.com/docs/reference/specification/v3.0.0)
- [AsyncAPI Generator](https://www.asyncapi.com/docs/tools/generator)
- [Rust Documentation](https://doc.rust-lang.org/)
- [Tokio Documentation](https://tokio.rs/)
- [Community Templates](https://github.com/asyncapi/generator/blob/master/docs/authoring.md)

## 🆘 Support

- [GitHub Issues](https://github.com/asyncapi/rust-template/issues)
- [AsyncAPI Slack](https://asyncapi.com/slack-invite)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/asyncapi)

---

**Generated with ❤️ by the AsyncAPI Community**

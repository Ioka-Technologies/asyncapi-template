# AsyncAPI Rust Template

A production-ready AsyncAPI code generator template for the Rust programming language. This template generates idiomatic Rust code from AsyncAPI specifications, including message handlers, data structures, and server implementations.

## Features

- 🦀 **Idiomatic Rust Code**: Generates clean, safe, and performant Rust code
- 📡 **Multiple Protocols**: Support for HTTP, MQTT, WebSocket, and more
- 🔧 **Configurable**: Extensive configuration options for customization
- 📦 **Production Ready**: Includes error handling, logging, and best practices
- 🧪 **Well Tested**: Comprehensive test coverage and examples
- 📚 **Rich Documentation**: Generated code includes comprehensive documentation

## Quick Start

### Prerequisites

- [AsyncAPI CLI](https://github.com/asyncapi/cli) installed
- [Rust](https://rustup.rs/) 1.70+ installed
- [Node.js](https://nodejs.org/) 16+ (for the generator)

### Installation

```bash
# Install AsyncAPI CLI if you haven't already
npm install -g @asyncapi/cli

# Generate Rust code from your AsyncAPI specification
asyncapi generate fromTemplate asyncapi.yaml https://github.com/asyncapi/rust-template
```

### Basic Usage

1. **Create an AsyncAPI specification** (see [examples/](./examples/) for samples):

```yaml
asyncapi: 3.0.0
info:
  title: My Service
  version: 1.0.0
servers:
  local:
    host: localhost:8080
    protocol: http
channels:
  userEvents:
    address: user/events
    messages:
      userCreated:
        payload:
          type: object
          properties:
            id:
              type: string
            name:
              type: string
```

2. **Generate Rust code**:

```bash
asyncapi generate fromTemplate asyncapi.yaml https://github.com/asyncapi/rust-template -o ./generated-rust-service
```

3. **Build and run**:

```bash
cd generated-rust-service
cargo build
cargo run
```

## Configuration Options

The template supports extensive configuration through parameters:

### Basic Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `packageName` | string | `"asyncapi-service"` | Name of the generated Rust package |
| `packageVersion` | string | `"0.1.0"` | Version of the generated package |
| `author` | string | `"AsyncAPI Generator"` | Package author |
| `license` | string | `"Apache-2.0"` | Package license |
| `edition` | string | `"2021"` | Rust edition to use |

### Server Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `serverPort` | integer | `8080` | Default server port |
| `serverHost` | string | `"localhost"` | Default server host |
| `enableCors` | boolean | `true` | Enable CORS middleware |
| `enableLogging` | boolean | `true` | Enable structured logging |

### Code Generation Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `generateServer` | boolean | `true` | Generate server implementation |
| `generateClient` | boolean | `false` | Generate client implementation |
| `generateTests` | boolean | `true` | Generate unit tests |
| `generateDocs` | boolean | `true` | Generate documentation |
| `asyncRuntime` | string | `"tokio"` | Async runtime (`tokio` or `async-std`) |

### Protocol-Specific Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `httpFramework` | string | `"axum"` | HTTP framework (`axum`, `warp`, `actix-web`) |
| `mqttClient` | string | `"rumqttc"` | MQTT client library |
| `websocketLib` | string | `"tokio-tungstenite"` | WebSocket library |

### Example Configuration

```bash
asyncapi generate fromTemplate asyncapi.yaml https://github.com/asyncapi/rust-template \
  -o ./my-service \
  -p packageName=my-awesome-service \
  -p packageVersion=1.0.0 \
  -p author="Your Name" \
  -p httpFramework=axum \
  -p enableCors=true \
  -p generateTests=true
```

## Generated Project Structure

```
generated-rust-service/
├── Cargo.toml                 # Package manifest
├── README.md                  # Generated documentation
├── src/
│   ├── main.rs               # Application entry point
│   ├── lib.rs                # Library root
│   ├── config.rs             # Configuration management
│   ├── error.rs              # Error types and handling
│   ├── models/               # Generated data models
│   │   ├── mod.rs
│   │   ├── user_signup.rs
│   │   └── ...
│   ├── handlers/             # Message handlers
│   │   ├── mod.rs
│   │   ├── user_events.rs
│   │   └── ...
│   ├── server/               # Server implementation
│   │   ├── mod.rs
│   │   ├── builder.rs
│   │   ├── routes.rs
│   │   └── middleware.rs
│   └── client/               # Client implementation (if enabled)
│       ├── mod.rs
│       └── ...
├── tests/                    # Integration tests
│   ├── integration_test.rs
│   └── ...
├── examples/                 # Usage examples
│   ├── basic_usage.rs
│   └── ...
└── docs/                     # Generated documentation
    ├── api.md
    └── ...
```

## Examples

This repository includes several examples demonstrating different use cases:

### Simple HTTP Service

See [examples/simple/](./examples/simple/) for a basic HTTP service example.

```bash
# Generate from the simple example
asyncapi generate fromTemplate examples/simple/asyncapi.yaml https://github.com/asyncapi/rust-template -o ./simple-service

# Run the generated service
cd simple-service
cargo run
```

### MQTT IoT Service

See [examples/mqtt/](./examples/mqtt/) for an MQTT-based IoT device management system.

```bash
# Generate from the MQTT example
asyncapi generate fromTemplate examples/mqtt/asyncapi.yaml https://github.com/asyncapi/rust-template -o ./iot-service

# Run the generated service
cd iot-service
cargo run
```

## Generated Code Features

### Type-Safe Message Handling

The generator creates strongly-typed Rust structs for all message payloads:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSignupPayload {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
```

### Async Message Handlers

Generated handlers use async/await for non-blocking operation:

```rust
#[async_trait]
pub trait UserEventsHandler {
    async fn handle_user_signup(&self, payload: UserSignupPayload) -> Result<(), HandlerError>;
    async fn handle_user_welcome(&self, payload: UserWelcomePayload) -> Result<(), HandlerError>;
}
```

### Server Builder Pattern

The generated server uses a builder pattern for easy configuration:

```rust
let server = ServerBuilder::new()
    .with_host("0.0.0.0")
    .with_port(8080)
    .with_cors(true)
    .with_handler(Box::new(MyUserEventsHandler))
    .build()
    .await?;

server.run().await?;
```

### Error Handling

Comprehensive error handling with custom error types:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Handler error: {0}")]
    Handler(#[from] HandlerError),
    #[error("Server error: {0}")]
    Server(String),
}
```

## Protocol Support

### HTTP/REST

- **Framework**: Axum (default), Warp, or Actix-web
- **Features**: JSON serialization, CORS, middleware support
- **Operations**: GET, POST, PUT, DELETE with proper routing

### MQTT

- **Client**: rumqttc (default) or paho-mqtt
- **Features**: QoS levels, retained messages, last will
- **Operations**: Publish/Subscribe with topic patterns

### WebSocket

- **Library**: tokio-tungstenite (default) or async-tungstenite
- **Features**: Binary/text messages, connection management
- **Operations**: Bidirectional real-time communication

## Development

### Building the Template

```bash
# Clone the repository
git clone https://github.com/asyncapi/rust-template.git
cd rust-template

# Install dependencies
npm install

# Run tests
npm test

# Lint code
npm run lint
```

### Testing with Examples

```bash
# Test with the simple example
npm run test:simple

# Test with the MQTT example
npm run test:mqtt

# Test all examples
npm run test:examples
```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests
4. Run the test suite: `npm test`
5. Commit your changes: `git commit -am 'Add my feature'`
6. Push to the branch: `git push origin feature/my-feature`
7. Submit a pull request

## Advanced Usage

### Custom Templates

You can extend the template by creating custom partials:

```javascript
// In your custom template
const customPartial = `
{{#each channels}}
// Custom code for channel: {{@key}}
{{/each}}
`;
```

### Middleware Integration

The generated server supports custom middleware:

```rust
let server = ServerBuilder::new()
    .with_middleware(cors_middleware())
    .with_middleware(logging_middleware())
    .with_middleware(auth_middleware())
    .build()
    .await?;
```

### Custom Handlers

Implement custom business logic by implementing the generated traits:

```rust
pub struct MyCustomHandler {
    database: Arc<Database>,
    cache: Arc<Cache>,
}

#[async_trait]
impl UserEventsHandler for MyCustomHandler {
    async fn handle_user_signup(&self, payload: UserSignupPayload) -> Result<(), HandlerError> {
        // Custom business logic
        self.database.create_user(&payload).await?;
        self.cache.invalidate_user_cache().await?;
        Ok(())
    }
}
```

## Troubleshooting

### Common Issues

1. **Compilation Errors**: Ensure you're using Rust 1.70+ and all dependencies are up to date
2. **Missing Dependencies**: Run `cargo update` to update dependencies
3. **Port Conflicts**: Change the server port using the `serverPort` parameter
4. **MQTT Connection Issues**: Verify your MQTT broker is running and accessible

### Debug Mode

Enable debug logging for troubleshooting:

```bash
RUST_LOG=debug cargo run
```

### Performance Tuning

For production deployments:

```bash
cargo build --release
RUST_LOG=info ./target/release/your-service
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Community

- [AsyncAPI Community](https://asyncapi.com/community)
- [GitHub Discussions](https://github.com/asyncapi/rust-template/discussions)
- [Slack Channel](https://asyncapi.com/slack-invite)

## Related Projects

- [AsyncAPI Generator](https://github.com/asyncapi/generator)
- [AsyncAPI CLI](https://github.com/asyncapi/cli)
- [AsyncAPI Specification](https://github.com/asyncapi/spec)
- [Other AsyncAPI Templates](https://github.com/search?q=topic%3Aasyncapi+topic%3Atemplate)

# AsyncAPI Rust Template

This template generates a Rust server implementation from AsyncAPI specifications with support for multiple messaging protocols.

## Features

- **Protocol Support**: MQTT, Kafka, AMQP, WebSocket, HTTP/HTTPS
- **Async/Await**: Built on Tokio for high-performance async I/O
- **Type Safety**: Generates type-safe message structs from AsyncAPI schemas
- **Structured Logging**: Built-in tracing and logging support
- **Configuration**: Environment variable based configuration
- **Production Ready**: Includes error handling, graceful shutdown, and best practices

## Supported Protocols

| Protocol | Dependency | Features |
|----------|------------|----------|
| MQTT/MQTTS | `rumqttc` | Publish/Subscribe messaging |
| Kafka | `rdkafka` | High-throughput streaming |
| AMQP/AMQPS | `lapin` | Advanced message queuing |
| WebSocket | `tokio-tungstenite` | Real-time communication |
| HTTP/HTTPS | Built-in | RESTful APIs |

## Usage

### Generate a Rust server from AsyncAPI spec

```bash
# Using AsyncAPI CLI
npx @asyncapi/cli generate fromTemplate asyncapi.yaml @asyncapi/rust-template --output ./my-rust-server

# With custom package name
npx @asyncapi/cli generate fromTemplate asyncapi.yaml @asyncapi/rust-template --output ./my-rust-server --param packageName=my-awesome-server
```

### Generated Project Structure

```
my-rust-server/
├── Cargo.toml              # Rust project configuration with protocol dependencies
├── README.md               # Generated documentation
├── src/
│   ├── main.rs            # Server entry point
│   ├── lib.rs             # Library exports
│   ├── models.rs          # Message type definitions
│   └── handlers.rs        # Message handlers
```

### Running the Generated Server

```bash
cd my-rust-server

# Build the project
cargo build

# Run the server
cargo run

# Run with custom configuration
LOG_LEVEL=debug SERVER_HOST=localhost SERVER_PORT=3000 cargo run
```

## Template Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `packageName` | Name of the generated Rust package | `asyncapi-server` |

## Configuration

The generated server supports configuration through environment variables:

- `LOG_LEVEL`: Logging level (trace, debug, info, warn, error) - default: `info`
- `SERVER_HOST`: Server host - default: `0.0.0.0`
- `SERVER_PORT`: Server port - default: `8080`

## Generated Code Features

### Automatic Protocol Detection

The template automatically detects protocols from your AsyncAPI specification and includes the appropriate dependencies:

```toml
# For MQTT specs
rumqttc = "0.24"

# For Kafka specs
rdkafka = "0.36"

# For AMQP specs
lapin = "2.3"

# For WebSocket specs
tokio-tungstenite = "0.21"
```

### Type-Safe Message Handling

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCreatedMessage {
    pub user_id: String,
    pub email: String,
    pub created_at: i64,
}

impl AsyncApiMessage for UserCreatedMessage {
    fn message_type(&self) -> &'static str {
        "user.created"
    }
}
```

### Handler Pattern

```rust
impl MessageHandler<UserCreatedMessage> for UserCreatedHandler {
    async fn handle(&self, message: UserCreatedMessage) -> Result<()> {
        info!("New user created: {}", message.email);
        // Your business logic here
        Ok(())
    }
}
```

## Development

### Prerequisites

- Node.js 18+ (for AsyncAPI CLI)
- Rust 1.70+ (for generated code)

### Testing the Template

```bash
# Clone this repository
git clone https://github.com/asyncapi/rust-template
cd rust-template

# Install dependencies
npm install

# Test with sample specs
npm run test:generate
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Examples

### MQTT User Service

```yaml
asyncapi: 3.0.0
info:
  title: User Service
  version: 1.0.0
  description: A user management service using MQTT

servers:
  production:
    host: mqtt.example.com
    protocol: mqtt
    description: Production MQTT broker

channels:
  user/created:
    messages:
      UserCreated:
        payload:
          type: object
          properties:
            userId:
              type: string
            email:
              type: string
            createdAt:
              type: string
              format: date-time
```

Generates a complete Rust MQTT server with:
- MQTT client setup with `rumqttc`
- Type-safe `UserCreated` message struct
- Handler for processing user creation events
- Configuration and logging

## License

Apache 2.0

## Support

- [AsyncAPI Documentation](https://www.asyncapi.com/docs)
- [Rust AsyncAPI Template Issues](https://github.com/asyncapi/rust-template/issues)
- [AsyncAPI Community Slack](https://asyncapi.com/slack-invite)

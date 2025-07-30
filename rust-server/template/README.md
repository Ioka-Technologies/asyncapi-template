# {{info.title}}

Generate a production-ready Rust server from your AsyncAPI specification with support for multiple messaging protocols.

## Overview

This template generates a Rust library that provides a clean separation between generated infrastructure code and your business logic. The generated code handles protocol-specific concerns while you focus on implementing your domain logic through simple trait interfaces.

## Technical Requirements

- Rust 1.70+
- AsyncAPI CLI 1.0+

## Supported Protocols

- WebSocket
- HTTP/HTTPS
- MQTT/MQTTS
- Kafka
- AMQP/AMQPS

## Quick Start

### Generate Server

```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Generate your Rust server
asyncapi generate fromTemplate asyncapi.yaml @ioka-technologies/asyncapi-rust-server-template -o my-server

cd my-server
cargo build
```

### Implement Business Logic

The generated code provides traits that you implement with your business logic:

```rust
use async_trait::async_trait;
use my_server::*;

pub struct MyService;

#[async_trait]
impl UserService for MyService {
    async fn handle_user_signup(&self, request: SignupRequest, ctx: &MessageContext) -> Result<User> {
        // Your business logic here
        Ok(User {
            id: generate_id(),
            email: request.email,
            created_at: chrono::Utc::now(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let service = Arc::new(MyService);

    Server::builder()
        .with_user_service(service)
        .build()
        .start()
        .await
}
```

## Generated Project Structure

```
my-server/
├── Cargo.toml              # Rust project configuration
├── README.md               # This file
├── src/
│   ├── lib.rs             # Library exports
│   ├── models.rs          # Message type definitions
│   ├── handlers.rs        # Generated trait definitions
│   ├── server/            # Server implementation
│   ├── transport/         # Protocol implementations
│   └── auth/              # Authentication support
└── examples/              # Usage examples
```

## Configuration

Configure the server through environment variables:

- `LOG_LEVEL`: Logging level (trace, debug, info, warn, error) - default: `info`
- `SERVER_HOST`: Server host - default: `0.0.0.0`
- `SERVER_PORT`: Server port - default: `8080`

## Development

```bash
# Build the library
cargo build --lib

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

## Features

- **Type Safety**: Generated message structs with full Rust type safety
- **Protocol Agnostic**: Same business logic works across all supported protocols
- **Async/Await**: Built on Tokio for high-performance async I/O
- **Authentication**: Built-in support for JWT, API keys, and basic auth
- **Error Handling**: Comprehensive error types and recovery mechanisms
- **Observability**: Structured logging and metrics support

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run the test suite: `cargo test`
5. Submit a pull request

## License

Apache-2.0

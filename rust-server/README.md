# AsyncAPI Rust Server Template

⚠️ **Experimental**: This template is still a work in progress and until we reach a 0.1.0 version, assume this is experimental and is not production ready.

Generate production-ready Rust servers from your AsyncAPI specifications using a trait-based library architecture that separates infrastructure concerns from business logic.

## Overview

This template generates Rust libraries (not applications) that provide a clean separation between generated infrastructure code and your business logic. When you regenerate from an updated AsyncAPI spec, your business implementations remain untouched while the infrastructure evolves.

**Key Benefits:**

- **Regeneration Safe**: Your business logic is never overwritten
- **Protocol Agnostic**: Same business logic works across WebSocket, HTTP, MQTT, Kafka
- **Production Ready**: Built-in authentication, error handling, monitoring
- **Type Safe**: Full Rust type safety with generated message structs

## Technical Requirements

- Rust 1.70+
- AsyncAPI CLI 1.0+

## Supported Protocols

- WebSocket
- HTTP
- MQTT
- Kafka
- AMQP

## Quick Start

### Installation

```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Generate your Rust server library
asyncapi generate fromTemplate asyncapi.yaml @ioka-technologies/asyncapi-rust-server-template -o my-server

cd my-server
```

### Basic Usage

The generated code provides traits that you implement with your business logic:

```rust
// Your business logic (never touched by regeneration)
use async_trait::async_trait;
use my_server::*;

pub struct MyService {
    database: Database,
}

#[async_trait]
impl UserService for MyService {
    async fn handle_user_signup(&self, request: SignupRequest, ctx: &MessageContext) -> Result<User> {
        // Your business logic here
        let user = self.database.create_user(&request).await?;
        Ok(user)
    }
}

// Start the server
#[tokio::main]
async fn main() -> Result<()> {
    let service = Arc::new(MyService::new());

    Server::builder()
        .with_user_service(service)
        .build()
        .start()
        .await
}
```

### Code Regeneration

Update your AsyncAPI spec and regenerate safely:

```bash
# Your business logic remains untouched
asyncapi generate fromTemplate updated-asyncapi.yaml @ioka-technologies/asyncapi-rust-server-template -o my-server --force-write
```

## Template Configuration

Configure the template with parameters:

```bash
asyncapi generate fromTemplate asyncapi.yaml @ioka-technologies/asyncapi-rust-server-template \
  -o my-server \
  -p packageName=my-awesome-service \
  -p packageVersion=1.0.0 \
  -p author="Your Name"
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `packageName` | `"asyncapi-service"` | Name of the generated Rust package |
| `packageVersion` | `"0.1.0"` | Version of the generated package |
| `author` | `"AsyncAPI Generator"` | Package author |
| `license` | `"Apache-2.0"` | Package license |

## Architecture

The template generates a library with clear separation of concerns:

- **Generated Infrastructure** (`src/`): Protocol handling, routing, authentication
- **Your Business Logic** (`services/`): Trait implementations you create
- **Generated Traits** (`src/handlers.rs`): Interfaces you implement

## Examples

See the [examples directory](../examples/) for sample AsyncAPI specifications and generated code.

## Development

```bash
# Clone and test locally
git clone https://github.com/Ioka-Technologies/asyncapi-template.git
cd asyncapi-template/rust-server

# Run tests
npm test
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run the test suite: `npm test`
5. Submit a pull request

## License

Apache-2.0

## Related Projects

- [AsyncAPI Generator](https://github.com/asyncapi/generator)
- [AsyncAPI CLI](https://github.com/asyncapi/cli)
- [TypeScript Client Template](../ts-client/)

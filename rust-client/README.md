# AsyncAPI Rust NATS Client Template

This template generates a Rust client library for NATS messaging based on AsyncAPI specifications. It creates type-safe, idiomatic Rust code that integrates seamlessly with the `async-nats` ecosystem.

## Features

- **Type-Safe Client Generation**: Generates Rust structs and client methods from AsyncAPI schemas
- **NATS Integration**: Uses the official `async-nats` client library
- **Request/Reply Support**: Automatically detects and implements NATS request/reply patterns
- **Pub/Sub Support**: Supports NATS publish/subscribe patterns for asynchronous messaging
- **Message Envelope**: Consistent message format with metadata and correlation IDs
- **Flexible Authentication**: Accepts pre-configured NATS clients with any authentication method
- **Comprehensive Error Handling**: Specific error types for different failure scenarios
- **Documentation**: Generates comprehensive documentation and usage examples

## Usage

### Prerequisites

- AsyncAPI Generator CLI
- AsyncAPI specification with NATS protocol
- Rust 1.70+ (for generated code)

### Generate a Client

```bash
# Install AsyncAPI Generator if not already installed
npm install -g @asyncapi/generator

# Generate Rust NATS client
ag path/to/your/asyncapi.yaml @asyncapi/rust-client-template -o ./generated-client
```

### Template Parameters

The template supports several parameters to customize the generated code:

- `clientName`: Name of the generated client struct (default: `{Title}Client`)
- `packageName`: Name of the generated Rust crate (default: `{title}-client`)
- `packageVersion`: Version of the generated crate (default: from AsyncAPI spec)
- `author`: Author of the generated crate (default: "AsyncAPI Generator")
- `license`: License of the generated crate (default: "Apache-2.0")

Example with parameters:

```bash
ag asyncapi.yaml @asyncapi/rust-client-template \
  -o ./my-client \
  -p clientName=MyServiceClient \
  -p packageName=my-service-client \
  -p author="Your Name"
```

## Generated Code Structure

The template generates a complete Rust crate with the following structure:

```
generated-client/
├── Cargo.toml              # Rust package manifest
├── README.md               # Usage documentation
└── src/
    ├── lib.rs              # Main library file with re-exports
    ├── client.rs           # Generated client implementation
    ├── models.rs           # Generated data models from schemas
    ├── envelope.rs         # Message envelope for consistent format
    └── errors.rs           # Error types and handling
```

## AsyncAPI Requirements

### Supported Protocols

- `nats` - NATS messaging protocol

### Operation Patterns

The template supports the following AsyncAPI operation patterns:

#### Request/Reply Operations

Operations with `action: send` and a `reply` section generate request/reply methods:

```yaml
operations:
  createUser:
    action: send
    channel:
      $ref: '#/channels/user.create'
    messages:
      - $ref: '#/components/messages/CreateUserRequest'
    reply:
      channel:
        $ref: '#/channels/user.create.reply'
      messages:
        - $ref: '#/components/messages/CreateUserResponse'
```

Generates:
```rust
pub async fn create_user(&self, payload: CreateUserRequest) -> ClientResult<CreateUserResponse>
```

#### Publish Operations

Operations with `action: send` and no `reply` section generate publish methods:

```yaml
operations:
  publishUserEvent:
    action: send
    channel:
      $ref: '#/channels/user.events'
    messages:
      - $ref: '#/components/messages/UserEvent'
```

Generates:
```rust
pub async fn publish_user_event(&self, payload: UserEvent) -> ClientResult<()>
```

#### Subscribe Operations

Operations with `action: receive` generate subscription methods:

```yaml
operations:
  subscribeUserEvents:
    action: receive
    channel:
      $ref: '#/channels/user.events'
    messages:
      - $ref: '#/components/messages/UserEvent'
```

Generates:
```rust
pub async fn subscribe_user_events(&self) -> ClientResult<async_nats::Subscriber>
```

### Schema Support

The template generates Rust structs from AsyncAPI schemas with:

- **Type Mapping**: JSON Schema types mapped to appropriate Rust types
- **Serde Integration**: Automatic serialization/deserialization
- **Optional Fields**: Proper handling of optional vs required fields
- **Documentation**: Generated from schema descriptions
- **Constructors**: Convenience methods for creating instances

## Generated Client Usage

### Basic Usage

```rust
use async_nats;
use my_service_client::MyServiceClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up NATS client
    let nats_client = async_nats::connect("nats://localhost:4222").await?;

    // Create service client
    let client = MyServiceClient::with(nats_client);

    // Use generated methods
    let response = client.create_user(CreateUserRequest {
        email: "user@example.com".to_string(),
        name: "John Doe".to_string(),
    }).await?;

    println!("Created user: {:?}", response);

    Ok(())
}
```

### With Authentication

```rust
use async_nats;
use my_service_client::MyServiceClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up NATS client with JWT authentication
    let nats_client = async_nats::ConnectOptions::new()
        .credentials_file("./service.creds").await?
        .name("my-service-client")
        .connect("nats://production.example.com:4222").await?;

    let client = MyServiceClient::with(nats_client);

    // Client operations work the same way
    let response = client.create_user(request).await?;

    Ok(())
}
```

### Subscription Handling

```rust
use async_nats;
use my_service_client::{MyServiceClient, MessageEnvelope};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nats_client = async_nats::connect("nats://localhost:4222").await?;
    let client = MyServiceClient::with(nats_client);

    // Subscribe to events
    let mut subscriber = client.subscribe_user_events().await?;

    // Handle incoming messages
    while let Some(message) = subscriber.next().await {
        let envelope = MessageEnvelope::from_bytes(&message.payload)?;
        let event: UserEvent = envelope.extract_payload()?;

        println!("Received event: {:?}", event);

        // Acknowledge message if needed
        message.ack().await?;
    }

    Ok(())
}
```

## Dependencies

The generated client depends on:

- `async-nats` - Official async NATS client
- `serde` - Serialization framework
- `serde_json` - JSON serialization
- `uuid` - UUID generation for message IDs
- `chrono` - Date/time handling
- `thiserror` - Error handling

## Compatibility

- **AsyncAPI**: 2.x and 3.x
- **Rust**: 1.70+
- **NATS**: Compatible with NATS 2.x servers
- **async-nats**: 0.33+

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

Apache-2.0

# AsyncAPI Rust Template Usage Guide

This guide provides detailed instructions for using the AsyncAPI Rust template to generate production-ready Rust servers.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Template Parameters](#template-parameters)
- [Generated Code Structure](#generated-code-structure)
- [Customization](#customization)
- [Protocol-Specific Configuration](#protocol-specific-configuration)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

1. **AsyncAPI CLI**: Install the AsyncAPI CLI tool
   ```bash
   npm install -g @asyncapi/cli
   ```

2. **Rust**: Install Rust 1.70 or later
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

### Template Installation

The template is available through the AsyncAPI CLI and doesn't require separate installation.

## Basic Usage

### Generate from Local File

```bash
asyncapi generate fromTemplate ./asyncapi.yaml @asyncapi/rust-template
```

### Generate from URL

```bash
asyncapi generate fromTemplate https://raw.githubusercontent.com/asyncapi/spec/master/examples/simple.yml @asyncapi/rust-template
```

### Generate with Custom Output Directory

```bash
asyncapi generate fromTemplate ./asyncapi.yaml @asyncapi/rust-template --output ./my-rust-server
```

### Force Overwrite Existing Files

```bash
asyncapi generate fromTemplate ./asyncapi.yaml @asyncapi/rust-template --force-write
```

## Template Parameters

| Parameter | Type | Description | Default | Example |
|-----------|------|-------------|---------|---------|
| `packageName` | string | Name of the generated Rust package | `asyncapi-server` | `my-mqtt-server` |

### Using Parameters

```bash
asyncapi generate fromTemplate ./asyncapi.yaml @asyncapi/rust-template --param packageName=my-awesome-server
```

## Generated Code Structure

```
generated-server/
├── Cargo.toml              # Rust project manifest
├── README.md               # Project documentation
├── src/
│   ├── main.rs            # Application entry point
│   ├── config.rs          # Configuration management
│   ├── server.rs          # Main server implementation
│   ├── handlers.rs        # Message handlers for each channel
│   ├── models.rs          # Generated message models
│   └── middleware.rs      # Middleware components
└── helpers/               # Template helper functions (development only)
```

### Key Files Explained

#### `main.rs`
- Application entry point
- Initializes logging and configuration
- Starts protocol handlers
- Handles graceful shutdown

#### `config.rs`
- Environment-based configuration
- Protocol-specific settings
- Default values for all configuration options

#### `server.rs`
- Main server struct
- Protocol handler coordination
- Connection management
- Graceful shutdown logic

#### `handlers.rs`
- Message handlers for each channel
- Operation-specific handler methods
- Message routing logic
- Handler registry for centralized management

#### `models.rs`
- Strongly-typed message structs
- Generated from AsyncAPI schemas
- Serde serialization/deserialization
- AsyncAPI message trait implementation

#### `middleware.rs`
- Middleware trait definition
- Example middleware implementations
- Metrics and logging middleware

## Customization

### 1. Implementing Message Handlers

Edit the generated handler methods in `src/handlers.rs`:

```rust
impl UserChannelHandler {
    pub async fn handle_user_signup(&self, payload: &[u8]) -> Result<()> {
        // Parse the incoming message
        let user_signup: UserSignupMessage = serde_json::from_slice(payload)?;

        // Add your business logic here
        println!("Processing user signup: {:?}", user_signup);

        // Example: Save to database
        // self.database.save_user(user_signup).await?;

        // Example: Send confirmation email
        // self.email_service.send_confirmation(&user_signup.email).await?;

        Ok(())
    }
}
```

### 2. Adding Protocol Connections

Update the protocol handlers in `src/server.rs`:

```rust
pub async fn start_mqtt_handler(&self) -> Result<()> {
    info!("Starting MQTT handler");

    // Configure MQTT client
    let mut mqttoptions = rumqttc::MqttOptions::new(
        "rust-asyncapi-client",
        &self.config.mqtt_config.host,
        self.config.mqtt_config.port
    );

    // Set up client and event loop
    let (client, mut eventloop) = rumqttc::AsyncClient::new(mqttoptions, 10);

    // Subscribe to topics
    client.subscribe("user/+/signup", rumqttc::QoS::AtMostOnce).await?;

    // Handle incoming messages
    let handlers = self.handlers.clone();
    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish))) => {
                    let topic = &publish.topic;
                    let payload = &publish.payload;

                    // Route message to appropriate handler
                    if let Err(e) = handlers.read().await.route_message(topic, "signup", payload).await {
                        error!("Failed to handle message: {}", e);
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    error!("MQTT connection error: {}", e);
                    break;
                }
            }
        }
    });

    Ok(())
}
```

### 3. Adding Custom Middleware

Implement custom middleware in `src/middleware.rs`:

```rust
pub struct AuthMiddleware {
    secret_key: String,
}

impl AuthMiddleware {
    pub fn new(secret_key: String) -> Self {
        Self { secret_key }
    }
}

impl Middleware for AuthMiddleware {
    fn process_inbound(&self, channel: &str, payload: &[u8]) -> Result<Vec<u8>> {
        // Add authentication logic
        info!("Authenticating message on channel: {}", channel);

        // Example: Verify JWT token in message headers
        // let token = extract_token(payload)?;
        // verify_token(&token, &self.secret_key)?;

        Ok(payload.to_vec())
    }

    fn process_outbound(&self, channel: &str, payload: &[u8]) -> Result<Vec<u8>> {
        // Add outbound processing
        Ok(payload.to_vec())
    }
}
```

### 4. Environment Configuration

Create a `.env` file for local development:

```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
LOG_LEVEL=info

# MQTT Configuration (if using MQTT)
MQTT_HOST=localhost
MQTT_PORT=1883
MQTT_USERNAME=
MQTT_PASSWORD=

# Kafka Configuration (if using Kafka)
KAFKA_BROKERS=localhost:9092
KAFKA_GROUP_ID=rust-asyncapi-consumer

# Database Configuration (custom)
DATABASE_URL=postgresql://user:password@localhost/mydb
```

## Protocol-Specific Configuration

### MQTT

```rust
// In your AsyncAPI spec
servers:
  mqtt:
    url: mqtt://localhost:1883
    protocol: mqtt
    description: MQTT broker
```

Generated configuration:
```rust
pub struct MqttConfig {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}
```

### Kafka

```rust
// In your AsyncAPI spec
servers:
  kafka:
    url: kafka://localhost:9092
    protocol: kafka
    description: Kafka cluster
```

### WebSocket

```rust
// In your AsyncAPI spec
servers:
  websocket:
    url: ws://localhost:8080/ws
    protocol: ws
    description: WebSocket server
```

### HTTP

```rust
// In your AsyncAPI spec
servers:
  api:
    url: https://api.example.com
    protocol: https
    description: REST API
```

## Examples

### Simple Message Processing

```yaml
# asyncapi.yaml
asyncapi: 2.6.0
info:
  title: User Service
  version: 1.0.0

channels:
  user/signup:
    subscribe:
      operationId: userSignup
      message:
        $ref: '#/components/messages/UserSignup'

components:
  messages:
    UserSignup:
      payload:
        type: object
        properties:
          id:
            type: string
            format: uuid
          username:
            type: string
          email:
            type: string
            format: email
        required:
          - id
          - username
          - email
```

Generated handler:
```rust
impl UserSignupHandler {
    pub async fn handle_user_signup(&self, payload: &[u8]) -> Result<()> {
        let user_signup: UserSignup = serde_json::from_slice(payload)?;
        info!("Processing user signup: {:?}", user_signup);
        // Add your business logic here
        Ok(())
    }
}
```

### Multi-Protocol Server

```yaml
asyncapi: 2.6.0
info:
  title: Multi-Protocol Service
  version: 1.0.0

servers:
  mqtt:
    url: mqtt://localhost:1883
    protocol: mqtt
  kafka:
    url: kafka://localhost:9092
    protocol: kafka
  websocket:
    url: ws://localhost:8080/ws
    protocol: ws

channels:
  notifications:
    subscribe:
      operationId: receiveNotification
      message:
        $ref: '#/components/messages/Notification'
```

## Best Practices

### 1. Error Handling

Always use proper error handling in your handlers:

```rust
impl NotificationHandler {
    pub async fn handle_receive_notification(&self, payload: &[u8]) -> Result<()> {
        let notification = match serde_json::from_slice::<Notification>(payload) {
            Ok(n) => n,
            Err(e) => {
                error!("Failed to parse notification: {}", e);
                return Err(anyhow::anyhow!("Invalid notification format"));
            }
        };

        // Process notification
        self.process_notification(notification).await
    }

    async fn process_notification(&self, notification: Notification) -> Result<()> {
        // Your business logic with proper error handling
        Ok(())
    }
}
```

### 2. Logging

Use structured logging throughout your application:

```rust
use tracing::{info, warn, error, debug};

impl UserHandler {
    pub async fn handle_user_signup(&self, payload: &[u8]) -> Result<()> {
        debug!("Received user signup payload: {} bytes", payload.len());

        let user: UserSignup = serde_json::from_slice(payload)?;
        info!(user_id = %user.id, username = %user.username, "Processing user signup");

        match self.create_user(user).await {
            Ok(_) => {
                info!("User signup completed successfully");
                Ok(())
            }
            Err(e) => {
                error!(error = %e, "Failed to create user");
                Err(e)
            }
        }
    }
}
```

### 3. Configuration Management

Use environment variables for all configuration:

```rust
impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .context("Invalid SERVER_PORT")?,
            database_url: env::var("DATABASE_URL")
                .context("DATABASE_URL must be set")?,
        })
    }
}
```

### 4. Testing

Add tests for your handlers:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_user_signup_handler() {
        let handler = UserSignupHandler::new();
        let payload = r#"{"id":"123e4567-e89b-12d3-a456-426614174000","username":"testuser","email":"test@example.com"}"#;

        let result = handler.handle_user_signup(payload.as_bytes()).await;
        assert!(result.is_ok());
    }
}
```

## Troubleshooting

### Common Issues

#### 1. Compilation Errors

**Problem**: Generated code doesn't compile
**Solution**:
- Check your AsyncAPI spec is valid
- Ensure all required dependencies are in Cargo.toml
- Verify schema types are supported

#### 2. Runtime Errors

**Problem**: Server fails to start
**Solution**:
- Check environment variables are set correctly
- Verify protocol servers are accessible
- Review log output for specific errors

#### 3. Message Parsing Errors

**Problem**: Messages fail to deserialize
**Solution**:
- Ensure message format matches AsyncAPI schema
- Check for required fields
- Validate JSON structure

### Debug Mode

Run with debug logging to troubleshoot issues:

```bash
RUST_LOG=debug cargo run
```

### Validation

Validate your AsyncAPI specification before generating:

```bash
asyncapi validate asyncapi.yaml
```

## Advanced Usage

### Custom Dependencies

Add custom dependencies to the generated `Cargo.toml`:

```toml
[dependencies]
# Generated dependencies
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }

# Your custom dependencies
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls"] }
redis = "0.23"
```

### Custom Modules

Add custom modules to your generated project:

```rust
// src/database.rs
use sqlx::PgPool;

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self { pool })
    }
}
```

Then import in your handlers:

```rust
// src/handlers.rs
use crate::database::Database;

impl UserSignupHandler {
    pub fn new(database: Database) -> Self {
        Self { database }
    }
}
```

This completes the comprehensive usage guide for the AsyncAPI Rust template.

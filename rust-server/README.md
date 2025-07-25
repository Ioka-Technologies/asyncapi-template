# AsyncAPI Rust Template

A production-ready AsyncAPI code generator template for the Rust programming language. This template generates idiomatic Rust code from AsyncAPI specifications using a **trait-based architecture** that separates infrastructure code from business logic.

## 🎯 Key Features

- 🦀 **Trait-Based Architecture**: Business logic separated from generated infrastructure
- 🔄 **Regeneration Safe**: Your business logic is never overwritten
- 📡 **Multiple Protocols**: HTTP, MQTT, WebSocket, Kafka, AMQP support
- 🔧 **Production Ready**: Error handling, retries, circuit breakers, dead letter queues
- 🧪 **Well Tested**: Comprehensive test coverage and examples
- 📚 **Rich Documentation**: Generated code includes comprehensive documentation

## 🚀 Quick Start

### Prerequisites

- [AsyncAPI CLI](https://github.com/asyncapi/cli) installed
- [Rust](https://rustup.rs/) 1.70+ installed
- [Node.js](https://nodejs.org/) 16+ (for the generator)

### Generate Your Service

```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Generate Rust library from your AsyncAPI specification
asyncapi generate fromTemplate asyncapi.yaml https://github.com/asyncapi/rust-template -o ./my-service

# Build the library
cd my-service
cargo build --lib

# See the generated USAGE.md for how to create your application
```

## 🏗️ Trait-Based Architecture

This template uses a **trait-based architecture** that completely separates generated infrastructure code from your business logic. This means:

- ✅ **Your business logic is never overwritten** when regenerating code
- ✅ **Clean separation of concerns** between infrastructure and business logic
- ✅ **Type-safe interfaces** with comprehensive error handling
- ✅ **Production-ready infrastructure** with retries, circuit breakers, and monitoring

### How It Works

#### 1. Generated Traits (Your Interface)

For each channel in your AsyncAPI spec, the generator creates a trait that you implement:

```rust
#[async_trait]
pub trait UserEventsService: Send + Sync {
    async fn handle_user_signup(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()>;

    async fn handle_user_welcome(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()>;
}
```

#### 2. Generated Infrastructure (Handles Everything Else)

The generator creates handler structs that manage all the infrastructure concerns:

```rust
pub struct UserEventsHandler<T: UserEventsService> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
}

impl<T: UserEventsService> UserEventsHandler<T> {
    // Generated methods handle:
    // - Message parsing and validation
    // - Error handling and recovery
    // - Retries and circuit breakers
    // - Dead letter queues
    // - Logging and monitoring
    // - Then calls your business logic
}
```

#### 3. Your Implementation (Never Overwritten)

You implement the traits with your business logic in separate files:

```rust
// src/services/user_service.rs (your file, never touched by generator)
pub struct MyUserService {
    database: Arc<Database>,
    email_service: Arc<EmailService>,
}

#[async_trait]
impl UserEventsService for MyUserService {
    async fn handle_user_signup(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // Your business logic here
        let user_data = serde_json::from_value(message.clone())?;
        self.database.create_user(user_data).await?;
        self.email_service.send_welcome_email(&user_data.email).await?;
        Ok(())
    }
}
```

#### 4. Wire Everything Together

```rust
// In your main.rs
let user_service = Arc::new(MyUserService::new(database, email_service));
let recovery_manager = Arc::new(RecoveryManager::default());
let user_handler = UserEventsHandler::new(user_service, recovery_manager);

// Use the handler in your server setup
```

## 📁 Generated Project Structure

```
my-service/
├── Cargo.toml                 # Library package manifest
├── README.md                  # Generated documentation
├── USAGE.md                   # Detailed usage instructions
├── src/
│   ├── lib.rs                # Library root
│   ├── config.rs             # Configuration management
│   ├── errors.rs             # Error types and handling
│   ├── handlers.rs           # Generated traits and handlers
│   ├── models.rs             # Generated data models
│   ├── recovery.rs           # Recovery mechanisms
│   ├── router.rs             # Message routing
│   ├── middleware.rs         # Middleware support
│   ├── context.rs            # Request context
│   ├── server/               # Server implementation
│   │   ├── mod.rs
│   │   └── builder.rs
│   ├── transport/            # Protocol implementations
│   │   ├── mod.rs
│   │   ├── http.rs
│   │   ├── mqtt.rs
│   │   ├── websocket.rs
│   │   ├── kafka.rs
│   │   └── amqp.rs
│   └── auth/                 # Authentication (if enabled)
│       ├── mod.rs
│       ├── jwt.rs
│       └── rbac.rs
└── services/                 # Your business logic (create this)
    ├── mod.rs
    ├── user_service.rs       # Your trait implementations
    └── ...
```

## 🔧 Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `packageName` | string | `"asyncapi-service"` | Name of the generated Rust package |
| `packageVersion` | string | `"0.1.0"` | Version of the generated package |
| `author` | string | `"AsyncAPI Generator"` | Package author |
| `license` | string | `"Apache-2.0"` | Package license |
| `edition` | string | `"2021"` | Rust edition to use |
| `generateTests` | boolean | `true` | Generate unit tests |
| `asyncRuntime` | string | `"tokio"` | Async runtime (`tokio` or `async-std`) |

### Example with Configuration

```bash
asyncapi generate fromTemplate asyncapi.yaml https://github.com/asyncapi/rust-template \
  -o ./my-service \
  -p packageName=my-awesome-service \
  -p packageVersion=1.0.0 \
  -p author="Your Name" \
```

## 📚 Examples

This repository includes several examples demonstrating different use cases:

- **[Simple HTTP Service](./examples/simple/)** - Basic HTTP service example
- **[MQTT IoT Service](./examples/mqtt/)** - MQTT-based IoT device management
- **[Multi-Protocol Service](./examples/multi-protocol/)** - Service supporting multiple protocols

```bash
# Generate from an example
asyncapi generate fromTemplate examples/simple/asyncapi.yaml https://github.com/asyncapi/rust-template -o ./simple-service

# Build the generated library
cd simple-service
cargo build --lib

# See USAGE.md for how to create your own application using this library
```

## 🛡️ Production Features

### Error Handling & Recovery

- **Comprehensive Error Types**: Structured error handling with context
- **Retry Mechanisms**: Exponential backoff with configurable limits
- **Circuit Breakers**: Prevent cascade failures
- **Dead Letter Queues**: Handle unprocessable messages
- **Graceful Degradation**: Continue operating during partial failures

### Monitoring & Observability

- **Structured Logging**: JSON logging with correlation IDs
- **Metrics**: Built-in metrics for monitoring
- **Health Checks**: Readiness and liveness endpoints
- **Distributed Tracing**: OpenTelemetry integration ready

### Security

- **JWT Authentication**: Built-in JWT support
- **RBAC**: Role-based access control
- **Input Validation**: Comprehensive payload validation

## 🔄 Development Workflow

### 1. Initial Generation

```bash
asyncapi generate fromTemplate asyncapi.yaml https://github.com/asyncapi/rust-template -o ./my-service
cd my-service
```

### 2. Implement Your Business Logic

Create your service implementations:

```rust
// src/services/my_service.rs
use crate::handlers::*;
use async_trait::async_trait;

pub struct MyService;

#[async_trait]
impl UserEventsService for MyService {
    async fn handle_user_signup(&self, message: &serde_json::Value, context: &MessageContext) -> AsyncApiResult<()> {
        // Your business logic here
        Ok(())
    }
}
```

### 3. Update AsyncAPI & Regenerate

When you update your AsyncAPI specification:

```bash
# Regenerate - your business logic in src/services/ is safe
asyncapi generate fromTemplate asyncapi.yaml https://github.com/asyncapi/rust-template -o ./my-service --force-write
```

Your trait implementations are never overwritten!

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run specific test
cargo test test_user_signup
```

## 📖 Documentation

For detailed usage instructions, see [USAGE.md](./USAGE.md).

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests
4. Run the test suite: `npm test`
5. Commit your changes: `git commit -am 'Add my feature'`
6. Push to the branch: `git push origin feature/my-feature`
7. Submit a pull request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🌟 Why Trait-Based Architecture?

Traditional code generators often embed business logic directly in generated code, leading to:
- ❌ Business logic gets overwritten on regeneration
- ❌ Mixing of infrastructure and business concerns
- ❌ Difficult to test and maintain

Our trait-based approach solves these problems:
- ✅ **Separation of Concerns**: Infrastructure and business logic are completely separate
- ✅ **Regeneration Safe**: Your business logic is never touched
- ✅ **Testable**: Easy to unit test your business logic
- ✅ **Maintainable**: Clean, idiomatic Rust code
- ✅ **Production Ready**: Built-in error handling, retries, monitoring

## 🔗 Related Projects

- [AsyncAPI Generator](https://github.com/asyncapi/generator)
- [AsyncAPI CLI](https://github.com/asyncapi/cli)
- [AsyncAPI Specification](https://github.com/asyncapi/spec)

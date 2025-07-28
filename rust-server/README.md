# AsyncAPI Rust Template

**The paradigm shift from code generation to architecture generation**

This template doesn't just generate code—it generates a **sustainable software architecture** that evolves with your business needs. We've solved the fundamental tension between powerful code generation and maintainable software by creating a **trait-based library architecture** that completely separates infrastructure concerns from business logic.

## 🎯 The Architecture Philosophy

**The Problem**: Traditional code generators force you to choose between powerful infrastructure and maintainable business logic. You either get generated code that's overwritten (losing your work) or you avoid regeneration (missing improvements).

**Our Solution**: **Architectural Separation of Concerns**

```rust
// Generated Infrastructure (Evolves with AsyncAPI spec)
// - Protocol handling (WebSocket, HTTP, MQTT, Kafka)
// - Message routing and validation
// - Authentication and authorization
// - Error handling and recovery
// - Monitoring and observability

// Your Business Logic (Protected from regeneration)
impl UserService for MyUserService {
    async fn handle_signup(&self, request: SignupRequest) -> Result<User> {
        // Pure domain logic - no infrastructure concerns
        // This code NEVER changes when you regenerate
    }
}
```

**Why This Matters**:
- 🔄 **Evolutionary Architecture**: Your AsyncAPI spec can evolve without breaking existing business logic
- 🎯 **Protocol Agnostic**: Same business logic works over any transport protocol
- 🏗️ **Library-First**: Generate reusable libraries, not throwaway applications
- 🛡️ **Future-Proof**: Infrastructure improvements don't require business logic rewrites

## 🚀 The 3-Minute Production Service

**Goal**: Understand why this architecture matters by building a real service.

### The Business Scenario
You're building a user notification system that needs to:
- Handle user signups via WebSocket (real-time)
- Send welcome emails via HTTP API (reliable)
- Process analytics via Kafka (scalable)
- **Evolve** as business requirements change

### Step 1: Generate the Architecture (30 seconds)
```bash
# Install tools
npm install -g @asyncapi/cli
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Generate your service architecture
asyncapi generate fromTemplate your-notification-api.yaml ./rust-server -o notification-service
cd notification-service
```

### Step 2: Implement Business Logic (2 minutes)
```rust
// src/services/notification_service.rs
// This is YOUR code - never touched by regeneration
use async_trait::async_trait;

pub struct NotificationService {
    email_client: EmailClient,
    analytics: AnalyticsClient,
}

#[async_trait]
impl UserSignupService for NotificationService {
    async fn handle_user_signup(&self, signup: UserSignup, ctx: &MessageContext) -> Result<WelcomeMessage> {
        // Pure business logic - no protocol concerns

        // 1. Validate business rules
        if !self.is_valid_email(&signup.email) {
            return Err(NotificationError::InvalidEmail);
        }

        // 2. Send welcome email
        self.email_client.send_welcome(&signup.email, &signup.name).await?;

        // 3. Track analytics
        self.analytics.track_signup(&signup).await?;

        // 4. Return response (automatically sent via any protocol)
        Ok(WelcomeMessage {
            user_id: signup.id,
            message: format!("Welcome {}! Check your email.", signup.name),
            onboarding_url: self.generate_onboarding_url(&signup.id),
        })
    }
}
```

### Step 3: Run Production Service (30 seconds)
```bash
cargo run
# ✅ Handles WebSocket connections for real-time signups
# ✅ Processes HTTP requests for API integrations
# ✅ Connects to Kafka for analytics pipeline
# ✅ Includes authentication, monitoring, error handling
# ✅ Scales to thousands of concurrent connections
```

### The Magic: Evolution Without Rewrites

**Month 1**: WebSocket-only signups
**Month 3**: Add HTTP API - update AsyncAPI spec, regenerate, **business logic unchanged**
**Month 6**: Add Kafka analytics - update AsyncAPI spec, regenerate, **business logic unchanged**
**Month 12**: Add MQTT for IoT devices - update AsyncAPI spec, regenerate, **business logic unchanged**

**Your business logic never changes. Only the infrastructure evolves.**

## 🏗️ The Trait-Based Architecture Revolution

**The Insight**: Most async messaging systems fail because they mix infrastructure concerns with business logic. When protocols change or specs evolve, everything breaks.

**Our Innovation**: **Complete Architectural Separation**

### The Three-Layer Architecture

#### Layer 1: Generated Infrastructure (Protocol & Transport)
```rust
// Generated automatically from your AsyncAPI spec
// Handles ALL infrastructure concerns:

pub struct UserSignupHandler<T: UserSignupService> {
    service: Arc<T>,           // Your business logic
    transport: TransportLayer, // WebSocket, HTTP, MQTT, Kafka
    auth: AuthLayer,          // JWT, OAuth, API keys
    recovery: RecoveryLayer,   // Retries, circuit breakers
    monitoring: MetricsLayer,  // Tracing, health checks
}

// This layer evolves with your AsyncAPI spec
// Your business logic is completely isolated
```

#### Layer 2: Business Logic Interface (Your Contract)
```rust
// Generated trait that YOU implement
// This is your stable contract with the infrastructure

#[async_trait]
pub trait UserSignupService: Send + Sync {
    async fn handle_signup(&self, request: SignupRequest, context: &MessageContext) -> Result<WelcomeResponse>;
    //                     ↑ Strongly typed    ↑ Rich context    ↑ Type-safe response
}

// This interface is protocol-agnostic
// Same trait works for WebSocket, HTTP, MQTT, Kafka
```

#### Layer 3: Your Business Logic (Protected Domain Code)
```rust
// src/services/user_service.rs - YOUR code, never touched by generator
pub struct UserService {
    database: Database,
    email_service: EmailService,
    analytics: Analytics,
}

#[async_trait]
impl UserSignupService for UserService {
    async fn handle_signup(&self, request: SignupRequest, ctx: &MessageContext) -> Result<WelcomeResponse> {
        // Pure business logic - no infrastructure concerns
        // This code survives ANY AsyncAPI spec changes

        let user = self.database.create_user(&request).await?;
        self.email_service.send_welcome(&user.email).await?;
        self.analytics.track_signup(&user).await?;

        Ok(WelcomeResponse {
            user_id: user.id,
            message: "Welcome aboard!".to_string(),
        })
    }
}
```

### Why This Architecture Wins

**🔄 Protocol Evolution**: Start with WebSocket, add HTTP, then MQTT - same business logic
**📈 Scaling**: Infrastructure handles connection pooling, load balancing, failover
**🛡️ Reliability**: Built-in retries, circuit breakers, dead letter queues
**🧪 Testability**: Mock the trait interface, test business logic in isolation
**📊 Observability**: Automatic metrics, tracing, health checks
**🔐 Security**: Authentication and authorization handled at infrastructure layer

### The Competitive Advantage

**Traditional Approach**:
```rust
// Tightly coupled - protocol changes break everything
async fn handle_websocket_signup(ws: WebSocket, msg: String) -> Result<()> {
    let signup: SignupRequest = serde_json::from_str(&msg)?; // Parsing
    let user = database.create_user(signup).await?;          // Business logic
    ws.send(serde_json::to_string(&user)?).await?;          // Protocol
    // Change from WebSocket to HTTP? Rewrite everything!
}
```

**Our Approach**:
```rust
// Completely decoupled - protocols are interchangeable
impl UserSignupService for UserService {
    async fn handle_signup(&self, request: SignupRequest, ctx: &MessageContext) -> Result<WelcomeResponse> {
        let user = self.database.create_user(request).await?;  // Pure business logic
        Ok(WelcomeResponse { user_id: user.id })               // Infrastructure handles the rest
    }
}
// Same code works over WebSocket, HTTP, MQTT, Kafka, or any future protocol
```

## 📁 Generated Architecture: What You Get

**The Strategic Design**: Every file has a purpose in the separation of concerns.

```
notification-service/          # Your generated service library
├── Cargo.toml                # Dependencies automatically detected from AsyncAPI
├── README.md                 # Service-specific documentation
├── USAGE.md                  # Integration guide for your team
├── src/
│   ├── lib.rs               # Public API - what other services import
│   ├── config.rs            # Environment-based configuration
│   ├── errors.rs            # Domain-specific error types
│   ├── handlers.rs          # Generated traits YOU implement
│   ├── models.rs            # Type-safe message structs
│   ├── context.rs           # Rich request context (user, correlation IDs)
│   ├── recovery.rs          # Enterprise-grade error recovery
│   ├── middleware.rs        # Extensible middleware pipeline
│   ├── server/              # Infrastructure layer
│   │   ├── mod.rs          # Server orchestration
│   │   └── builder.rs      # Fluent configuration API
│   ├── transport/           # Protocol implementations
│   │   ├── mod.rs          # Transport abstraction
│   │   ├── websocket.rs    # Real-time connections
│   │   ├── http.rs         # REST API support
│   │   ├── mqtt.rs         # IoT device communication
│   │   ├── kafka.rs        # Event streaming
│   │   └── amqp.rs         # Message queuing
│   └── auth/                # Security layer (if enabled)
│       ├── mod.rs          # Authentication orchestration
│       ├── jwt.rs          # JWT token validation
│       ├── rbac.rs         # Role-based access control
│       └── middleware.rs   # Auth middleware integration
└── services/                # YOUR BUSINESS LOGIC (you create this)
    ├── mod.rs               # Service registry
    ├── notification_service.rs  # Your trait implementations
    ├── user_service.rs      # Domain logic
    └── analytics_service.rs # Business intelligence
```

### The File Strategy

**Generated Files** (src/*): Infrastructure that evolves with your AsyncAPI spec
- **Regenerate safely**: These files change when your spec changes
- **Don't modify**: Your changes will be overwritten
- **Trust the architecture**: These handle all the complex infrastructure

**Your Files** (services/*): Business logic that you own forever
- **Never touched**: Regeneration never modifies these files
- **Your domain**: Pure business logic with no infrastructure concerns
- **Stable interfaces**: Traits provide stable contracts

### Integration Patterns

**Library Integration** (Recommended):
```rust
// In your main application
use notification_service::{NotificationService, AutoServerBuilder};

#[tokio::main]
async fn main() -> Result<()> {
    let service = Arc::new(MyNotificationService::new());

    AutoServerBuilder::new()
        .with_notification_service(service)
        .build_and_start()
        .await
}
```

**Microservice Deployment**:
```rust
// Generated main.rs for standalone deployment
use notification_service::*;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    let service = create_service_from_config(&config).await?;

    Server::new(config)
        .with_service(service)
        .start()
        .await
}
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

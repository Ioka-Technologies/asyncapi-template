# AsyncAPI Rust Template Usage Guide

This guide provides detailed instructions for using the AsyncAPI Rust template to generate production-ready Rust servers with **trait-based architecture**.

## Table of Contents

- [Quick Start](#quick-start)
- [Trait-Based Architecture](#trait-based-architecture)
- [Template Parameters](#template-parameters)
- [Generated Code Structure](#generated-code-structure)
- [Implementation Guide](#implementation-guide)
- [Protocol-Specific Configuration](#protocol-specific-configuration)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites

1. **AsyncAPI CLI**: Install the AsyncAPI CLI tool
   ```bash
   npm install -g @asyncapi/cli
   ```

2. **Rust**: Install Rust 1.70 or later
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

### Generate Your Service

```bash
# Generate from local AsyncAPI specification
asyncapi generate fromTemplate ./asyncapi.yaml https://github.com/asyncapi/rust-template -o ./my-service

# Navigate to generated project
cd my-service

# Build the project
cargo build

# Run the service
cargo run
```

### Generate with Parameters

```bash
asyncapi generate fromTemplate ./asyncapi.yaml https://github.com/asyncapi/rust-template \
  -o ./my-service \
  -p packageName=my-awesome-service \
  -p packageVersion=1.0.0 \
  -p author="Your Name" \
  -p serverPort=3000
```

## Trait-Based Architecture

This template uses a **trait-based architecture** that completely separates generated infrastructure code from your business logic.

### Key Concepts

1. **Generated Traits**: Define the interface for your business logic
2. **Generated Handlers**: Manage infrastructure concerns (parsing, validation, error handling)
3. **Your Implementations**: Contain business logic in separate files
4. **Regeneration Safety**: Your business logic is never overwritten

### Architecture Flow

```
AsyncAPI Spec → Generated Traits → Your Implementation → Generated Infrastructure → Runtime
```

## Template Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `packageName` | string | `"asyncapi-service"` | Name of the generated Rust package |
| `packageVersion` | string | `"0.1.0"` | Version of the generated package |
| `author` | string | `"AsyncAPI Generator"` | Package author |
| `license` | string | `"Apache-2.0"` | Package license |
| `edition` | string | `"2021"` | Rust edition to use |
| `serverPort` | integer | `8080` | Default server port |
| `enableCors` | boolean | `true` | Enable CORS middleware |
| `enableLogging` | boolean | `true` | Enable structured logging |
| `generateTests` | boolean | `true` | Generate unit tests |
| `asyncRuntime` | string | `"tokio"` | Async runtime (`tokio` or `async-std`) |

### Using Parameters

```bash
asyncapi generate fromTemplate ./asyncapi.yaml https://github.com/asyncapi/rust-template \
  --param packageName=user-service \
  --param packageVersion=2.0.0 \
  --param author="John Doe" \
  --param serverPort=9000 \
  --param enableCors=false
```

## Generated Code Structure

```
my-service/
├── Cargo.toml                 # Package manifest
├── README.md                  # Generated documentation
├── src/
│   ├── main.rs               # Application entry point
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

### Key Files Explained

#### Generated Files (Infrastructure)

- **`handlers.rs`**: Contains generated traits and handler structs
- **`models.rs`**: Generated data models from AsyncAPI schemas
- **`transport/`**: Protocol-specific implementations
- **`server/`**: Server builder and configuration
- **`errors.rs`**: Comprehensive error handling
- **`recovery.rs`**: Retry mechanisms and circuit breakers

#### Your Files (Business Logic)

- **`services/`**: Directory for your trait implementations
- **Custom modules**: Any additional business logic modules

## Implementation Guide

### Step 1: Understand Generated Traits

After generation, examine `src/handlers.rs` to see the traits you need to implement:

```rust
// Generated in src/handlers.rs
#[async_trait]
pub trait UserEventsService: Send + Sync {
    async fn handle_user_signup(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()>;

    async fn handle_user_profile_update(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()>;
}
```

### Step 2: Create Your Service Directory

```bash
mkdir -p src/services
```

### Step 3: Implement the Traits

Create `src/services/mod.rs`:

```rust
pub mod user_service;

pub use user_service::*;
```

Create `src/services/user_service.rs`:

```rust
use crate::handlers::{UserEventsService, MessageContext, AsyncApiResult};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tracing::{info, error};

pub struct UserService {
    // Your dependencies
    database: Arc<dyn Database>,
    email_service: Arc<dyn EmailService>,
}

impl UserService {
    pub fn new(
        database: Arc<dyn Database>,
        email_service: Arc<dyn EmailService>,
    ) -> Self {
        Self {
            database,
            email_service,
        }
    }
}

#[async_trait]
impl UserEventsService for UserService {
    async fn handle_user_signup(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        info!(
            correlation_id = %context.correlation_id(),
            "Processing user signup"
        );

        // Parse the message
        let signup_data: UserSignupData = serde_json::from_value(message.clone())?;

        // Validate the data
        self.validate_signup_data(&signup_data)?;

        // Create user in database
        let user_id = self.database.create_user(&signup_data).await?;

        // Send welcome email
        self.email_service
            .send_welcome_email(&signup_data.email, &user_id)
            .await?;

        info!(
            user_id = %user_id,
            email = %signup_data.email,
            "User signup completed successfully"
        );

        Ok(())
    }

    async fn handle_user_profile_update(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        info!(
            correlation_id = %context.correlation_id(),
            "Processing user profile update"
        );

        // Parse the message
        let update_data: UserProfileUpdateData = serde_json::from_value(message.clone())?;

        // Update user profile
        self.database.update_user_profile(&update_data).await?;

        info!(
            user_id = %update_data.user_id,
            "User profile updated successfully"
        );

        Ok(())
    }
}

impl UserService {
    fn validate_signup_data(&self, data: &UserSignupData) -> AsyncApiResult<()> {
        if data.email.is_empty() {
            return Err(crate::errors::AsyncApiError::ValidationError(
                "Email cannot be empty".to_string(),
            ));
        }

        if data.username.len() < 3 {
            return Err(crate::errors::AsyncApiError::ValidationError(
                "Username must be at least 3 characters".to_string(),
            ));
        }

        Ok(())
    }
}

// Your data structures
#[derive(serde::Deserialize)]
struct UserSignupData {
    username: String,
    email: String,
    full_name: Option<String>,
}

#[derive(serde::Deserialize)]
struct UserProfileUpdateData {
    user_id: String,
    full_name: Option<String>,
    bio: Option<String>,
}

// Your trait definitions for dependencies
#[async_trait]
pub trait Database: Send + Sync {
    async fn create_user(&self, data: &UserSignupData) -> AsyncApiResult<String>;
    async fn update_user_profile(&self, data: &UserProfileUpdateData) -> AsyncApiResult<()>;
}

#[async_trait]
pub trait EmailService: Send + Sync {
    async fn send_welcome_email(&self, email: &str, user_id: &str) -> AsyncApiResult<()>;
}
```

### Step 4: Wire Everything Together

Update `src/main.rs` to use your service:

```rust
mod services;

use services::{UserService, Database, EmailService};
use crate::handlers::UserEventsHandler;
use std::sync::Arc;

// Your concrete implementations
struct PostgresDatabase {
    pool: sqlx::PgPool,
}

struct SmtpEmailService {
    client: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
}

#[async_trait]
impl Database for PostgresDatabase {
    async fn create_user(&self, data: &UserSignupData) -> AsyncApiResult<String> {
        // Database implementation
        todo!()
    }

    async fn update_user_profile(&self, data: &UserProfileUpdateData) -> AsyncApiResult<()> {
        // Database implementation
        todo!()
    }
}

#[async_trait]
impl EmailService for SmtpEmailService {
    async fn send_welcome_email(&self, email: &str, user_id: &str) -> AsyncApiResult<()> {
        // Email implementation
        todo!()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize your dependencies
    let database = Arc::new(PostgresDatabase::new().await?);
    let email_service = Arc::new(SmtpEmailService::new().await?);

    // Create your service
    let user_service = Arc::new(UserService::new(database, email_service));

    // Create the handler with your service
    let recovery_manager = Arc::new(RecoveryManager::default());
    let user_handler = UserEventsHandler::new(user_service, recovery_manager);

    // Use the handler in your server setup
    let server = ServerBuilder::new()
        .with_user_events_handler(user_handler)
        .build()
        .await?;

    server.start().await?;

    Ok(())
}
```

## Protocol-Specific Configuration

### MQTT Configuration

```yaml
# In your AsyncAPI spec
servers:
  mqtt:
    url: mqtt://localhost:1883
    protocol: mqtt
    description: MQTT broker
    variables:
      port:
        default: '1883'
        description: MQTT broker port
```

Environment variables:
```bash
MQTT_HOST=localhost
MQTT_PORT=1883
MQTT_USERNAME=your_username
MQTT_PASSWORD=your_password
MQTT_CLIENT_ID=rust-service
```

### Kafka Configuration

```yaml
servers:
  kafka:
    url: kafka://localhost:9092
    protocol: kafka
    description: Kafka cluster
```

Environment variables:
```bash
KAFKA_BROKERS=localhost:9092
KAFKA_GROUP_ID=rust-service-group
KAFKA_AUTO_OFFSET_RESET=earliest
```

### WebSocket Configuration

```yaml
servers:
  websocket:
    url: ws://localhost:8080/ws
    protocol: ws
    description: WebSocket server
```

### HTTP Configuration

```yaml
servers:
  api:
    url: https://api.example.com
    protocol: https
    description: REST API
```

## Examples

### Simple User Service

**AsyncAPI Specification** (`asyncapi.yaml`):

```yaml
asyncapi: 2.6.0
info:
  title: User Service
  version: 1.0.0
  description: A simple user management service

servers:
  mqtt:
    url: mqtt://localhost:1883
    protocol: mqtt

channels:
  user/events:
    subscribe:
      operationId: userEvents
      message:
        oneOf:
          - $ref: '#/components/messages/UserSignup'
          - $ref: '#/components/messages/UserProfileUpdate'

components:
  messages:
    UserSignup:
      name: UserSignup
      title: User Signup
      payload:
        type: object
        properties:
          type:
            type: string
            const: signup
          username:
            type: string
            minLength: 3
          email:
            type: string
            format: email
          full_name:
            type: string
        required:
          - type
          - username
          - email

    UserProfileUpdate:
      name: UserProfileUpdate
      title: User Profile Update
      payload:
        type: object
        properties:
          type:
            type: string
            const: profile_update
          user_id:
            type: string
            format: uuid
          full_name:
            type: string
          bio:
            type: string
        required:
          - type
          - user_id
```

**Generated Trait** (in `src/handlers.rs`):

```rust
#[async_trait]
pub trait UserEventsService: Send + Sync {
    async fn handle_user_events(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()>;
}
```

**Your Implementation** (`src/services/user_service.rs`):

```rust
use crate::handlers::{UserEventsService, MessageContext, AsyncApiResult};
use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, warn};

pub struct UserService;

#[async_trait]
impl UserEventsService for UserService {
    async fn handle_user_events(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // Route based on message type
        let message_type = message
            .get("type")
            .and_then(|t| t.as_str())
            .ok_or_else(|| {
                crate::errors::AsyncApiError::ValidationError(
                    "Missing message type".to_string(),
                )
            })?;

        match message_type {
            "signup" => self.handle_signup(message, context).await,
            "profile_update" => self.handle_profile_update(message, context).await,
            _ => {
                warn!("Unknown message type: {}", message_type);
                Ok(())
            }
        }
    }
}

impl UserService {
    async fn handle_signup(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        info!("Processing user signup");
        // Your signup logic here
        Ok(())
    }

    async fn handle_profile_update(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        info!("Processing profile update");
        // Your profile update logic here
        Ok(())
    }
}
```

### Multi-Protocol Service

For services that support multiple protocols, the same traits work across all protocols:

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
      operationId: notifications
      message:
        $ref: '#/components/messages/Notification'

components:
  messages:
    Notification:
      payload:
        type: object
        properties:
          id:
            type: string
          message:
            type: string
          priority:
            type: string
            enum: [low, medium, high]
        required:
          - id
          - message
          - priority
```

Your implementation works the same regardless of protocol:

```rust
#[async_trait]
impl NotificationsService for NotificationService {
    async fn handle_notifications(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        let notification: Notification = serde_json::from_value(message.clone())?;

        match notification.priority.as_str() {
            "high" => self.send_urgent_notification(notification).await,
            "medium" => self.send_normal_notification(notification).await,
            "low" => self.queue_notification(notification).await,
            _ => Ok(()),
        }
    }
}
```

## Best Practices

### 1. Error Handling

Always use comprehensive error handling:

```rust
#[async_trait]
impl UserEventsService for UserService {
    async fn handle_user_signup(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // Parse with detailed error context
        let signup_data: UserSignupData = serde_json::from_value(message.clone())
            .map_err(|e| {
                crate::errors::AsyncApiError::ParseError(
                    format!("Failed to parse user signup: {}", e)
                )
            })?;

        // Validate with business rules
        self.validate_signup(&signup_data)
            .map_err(|e| {
                crate::errors::AsyncApiError::ValidationError(
                    format!("Signup validation failed: {}", e)
                )
            })?;

        // Handle business logic with proper error propagation
        self.create_user(signup_data)
            .await
            .map_err(|e| {
                crate::errors::AsyncApiError::BusinessLogicError(
                    format!("User creation failed: {}", e)
                )
            })?;

        Ok(())
    }
}
```

### 2. Structured Logging

Use structured logging with correlation IDs:

```rust
use tracing::{info, warn, error, Span};

#[async_trait]
impl UserEventsService for UserService {
    async fn handle_user_signup(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        let span = Span::current();
        span.record("correlation_id", &context.correlation_id());
        span.record("operation", "user_signup");

        info!("Starting user signup process");

        let signup_data: UserSignupData = serde_json::from_value(message.clone())?;

        span.record("username", &signup_data.username);
        span.record("email", &signup_data.email);

        match self.create_user(signup_data).await {
            Ok(user_id) => {
                info!(user_id = %user_id, "User created successfully");
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

### 3. Dependency Injection

Use dependency injection for testability:

```rust
pub struct UserService<D, E, N>
where
    D: Database,
    E: EmailService,
    N: NotificationService,
{
    database: Arc<D>,
    email_service: Arc<E>,
    notification_service: Arc<N>,
}

impl<D, E, N> UserService<D, E, N>
where
    D: Database,
    E: EmailService,
    N: NotificationService,
{
    pub fn new(
        database: Arc<D>,
        email_service: Arc<E>,
        notification_service: Arc<N>,
    ) -> Self {
        Self {
            database,
            email_service,
            notification_service,
        }
    }
}
```

### 4. Configuration Management

Use environment-based configuration:

```rust
#[derive(serde::Deserialize)]
pub struct ServiceConfig {
    pub database_url: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub notification_webhook_url: String,
}

impl ServiceConfig {
    pub fn from_env() -> Result<Self, envy::Error> {
        envy::from_env()
    }
}

// In your main.rs
let config = ServiceConfig::from_env()?;
let database = PostgresDatabase::new(&config.database_url).await?;
let email_service = SmtpEmailService::new(&config.smtp_host, config.smtp_port).await?;
```

### 5. Graceful Shutdown

Implement graceful shutdown for your services:

```rust
pub struct UserService {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl UserService {
    pub async fn shutdown(&mut self) -> AsyncApiResult<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
            info!("User service shutdown initiated");
        }
        Ok(())
    }
}
```

## Testing

### Unit Testing Your Services

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use tokio_test;

    mock! {
        TestDatabase {}

        #[async_trait]
        impl Database for TestDatabase {
            async fn create_user(&self, data: &UserSignupData) -> AsyncApiResult<String>;
            async fn update_user_profile(&self, data: &UserProfileUpdateData) -> AsyncApiResult<()>;
        }
    }

    mock! {
        TestEmailService {}

        #[async_trait]
        impl EmailService for TestEmailService {
            async fn send_welcome_email(&self, email: &str, user_id: &str) -> AsyncApiResult<()>;
        }
    }

    #[tokio::test]
    async fn test_user_signup_success() {
        let mut mock_db = MockTestDatabase::new();
        let mut mock_email = MockTestEmailService::new();

        mock_db
            .expect_create_user()
            .times(1)
            .returning(|_| Ok("user123".to_string()));

        mock_email
            .expect_send_welcome_email()
            .times(1)
            .returning(|_, _| Ok(()));

        let service = UserService::new(
            Arc::new(mock_db),
            Arc::new(mock_email),
        );

        let message = serde_json::json!({
            "username": "testuser",
            "email": "test@example.com",
            "full_name": "Test User"
        });

        let context = MessageContext::new("test-correlation-id");

        let result = service.handle_user_signup(&message, &context).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_user_signup_validation_error() {
        let mock_db = MockTestDatabase::new();
        let mock_email = MockTestEmailService::new();

        let service = UserService::new(
            Arc::new(mock_db),
            Arc::new(mock_email),
        );

        let message = serde_json::json!({
            "username": "ab", // Too short
            "email": "test@example.com"
        });

        let context = MessageContext::new("test-correlation-id");

        let result = service.handle_user_signup(&message, &context).await;
        assert!(result.is_err());
    }
}
```

### Integration Testing

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use testcontainers::*;

    #[tokio::test]
    async fn test_full_user_signup_flow() {
        // Start test containers
        let docker = clients::Cli::default();
        let postgres_container = docker.run(images::postgres::Postgres::default());
        let redis_container = docker.run(images::redis::Redis::default());

        // Set up real services with test containers
        let database_url = format!(
            "postgresql://postgres:postgres@localhost:{}/postgres",
            postgres_container.get_host_port_ipv4(5432)
        );

        let database = PostgresDatabase::new(&database_url).await.unwrap();
        let email_service = TestEmailService::new(); // Mock for integration tests

        let service = UserService::new(
            Arc::new(database),
            Arc::new(email_service),
        );

        // Test the full flow
        let message = serde_json::json!({
            "username": "integrationtest",
            "email": "integration@example.com",
            "full_name": "Integration Test"
        });

        let context = MessageContext::new("integration-test-id");
        let result = service.handle_user_signup(&message, &context).await;

        assert!(result.is_ok());

        // Verify user was created in database
        // Verify email was sent
    }
}
```

### Load Testing

```rust
#[cfg(test)]
mod load_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_concurrent_user_signups() {
        let service = Arc::new(setup_test_service().await);
        let mut handles = vec![];

        // Spawn 100 concurrent signup requests
        for i in 0..100 {
            let service_clone = service.clone();
            let handle = tokio::spawn(async move {
                let message = serde_json::json!({
                    "username": format!("user{}", i),
                    "email": format!("user{}@example.com", i),
                    "full_name": format!("User {}", i)
                });

                let context = MessageContext::new(&format!("load-test-{}", i));
                service_clone.handle_user_signup(&message, &context).await
            });
            handles.push(handle);
        }

        // Wait for all to complete within timeout
        let results = timeout(Duration::from_secs(30), futures::future::join_all(handles))
            .await
            .expect("Load test timed out");

        // Verify all succeeded
        for result in results {
            assert!(result.unwrap().is_ok());
        }
    }
}
```

## Troubleshooting

### Common Issues

#### 1. Trait Implementation Errors

**Problem**: Compiler errors about missing trait implementations

**Solution**:
```rust
// Make sure you implement all required traits
#[async_trait]
impl UserEventsService for UserService {
    // Implement ALL methods from the trait
    async fn handle_user_signup(&self, message: &Value, context: &MessageContext) -> AsyncApiResult<()> {
        // Implementation
        Ok(())
    }

    // Don't forget other methods if they exist
}
```

#### 2. Dependency Injection Issues

**Problem**: Circular dependencies or complex dependency graphs

**Solution**:
```rust
// Use dependency injection container
use std::sync::Arc;

pub struct ServiceContainer {
    pub database: Arc<dyn Database>,
    pub email_service: Arc<dyn EmailService>,
    pub user_service: Arc<UserService>,
}

impl ServiceContainer {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let database = Arc::new(PostgresDatabase::new().await?);
        let email_service = Arc::new(SmtpEmailService::new().await?);
        let user_service = Arc::new(UserService::new(
            database.clone(),
            email_service.clone(),
        ));

        Ok(Self {
            database,
            email_service,
            user_service,
        })
    }
}
```

#### 3. Message Parsing Errors

**Problem**: Messages fail to deserialize

**Solution**:
```rust
// Add detailed error handling and logging
async fn handle_user_signup(&self, message: &Value, context: &MessageContext) -> AsyncApiResult<()> {
    tracing::debug!("Raw message: {}", serde_json::to_string_pretty(message)?);

    let signup_data: UserSignupData = serde_json::from_value(message.clone())
        .map_err(|e| {
            tracing::error!("Failed to parse message: {}", e);
            tracing::error!("Message content: {}", message);
            crate::errors::AsyncApiError::ParseError(format!("Invalid message format: {}", e))
        })?;

    // Continue processing...
    Ok(())
}
```

#### 4. Performance Issues

**Problem**: Slow message processing

**Solution**:
```rust
// Use connection pooling and async processing
pub struct UserService {
    database_pool: Arc<sqlx::PgPool>,
    email_queue: Arc<tokio::sync::mpsc::Sender<EmailMessage>>,
}

impl UserService {
    async fn handle_user_signup(&self, message: &Value, context: &MessageContext) -> AsyncApiResult<()> {
        // Process database operations with connection pool
        let mut tx = self.database_pool.begin().await?;

        // Queue email for background processing
        let email_msg = EmailMessage::new(signup_data.email.clone());
        self.email_queue.send(email_msg).await?;

        tx.commit().await?;
        Ok(())
    }
}
```

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
RUST_LOG=debug cargo run
```

For specific modules:
```bash
RUST_LOG=my_service::services::user_service=debug cargo run
```

### Validation

Validate your AsyncAPI specification:

```bash
asyncapi validate asyncapi.yaml
```

### Performance Monitoring

Add metrics to your services:

```rust
use prometheus::{Counter, Histogram, register_counter, register_histogram};

lazy_static! {
    static ref SIGNUP_COUNTER: Counter = register_counter!(
        "user_signups_total",
        "Total number of user signups"
    ).unwrap();

    static ref SIGNUP_DURATION: Histogram = register_histogram!(
        "user_signup_duration_seconds",
        "Time spent processing user signups"
    ).unwrap();
}

#[async_trait]
impl UserEventsService for UserService {
    async fn handle_user_signup(&self, message: &Value, context: &MessageContext) -> AsyncApiResult<()> {
        let _timer = SIGNUP_DURATION.start_timer();
        SIGNUP_COUNTER.inc();

        // Your business logic here
        let result = self.process_signup(message, context).await;

        match &result {
            Ok(_) => info!("User signup completed successfully"),
            Err(e) => error!("User signup failed: {}", e),
        }

        result
    }
}
```

## Advanced Topics

### Custom Error Types

Define custom error types for your business logic:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserServiceError {
    #[error("User already exists: {username}")]
    UserAlreadyExists { username: String },

    #[error("Invalid email format: {email}")]
    InvalidEmail { email: String },

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Email service error: {0}")]
    EmailService(String),
}

// Convert to AsyncApiError
impl From<UserServiceError> for crate::errors::AsyncApiError {
    fn from(err: UserServiceError) -> Self {
        match err {
            UserServiceError::UserAlreadyExists { .. } => {
                crate::errors::AsyncApiError::BusinessLogicError(err.to_string())
            }
            UserServiceError::InvalidEmail { .. } => {
                crate::errors::AsyncApiError::ValidationError(err.to_string())
            }
            _ => crate::errors::AsyncApiError::InternalError(err.to_string()),
        }
    }
}
```

### Background Processing

Implement background processing for heavy operations:

```rust
use tokio::sync::mpsc;

pub struct UserService {
    background_tx: mpsc::Sender<BackgroundTask>,
}

#[derive(Debug)]
enum BackgroundTask {
    SendWelcomeEmail { email: String, user_id: String },
    GenerateUserReport { user_id: String },
}

impl UserService {
    pub fn new() -> Self {
        let (tx, mut rx) = mpsc::channel::<BackgroundTask>(100);

        // Spawn background worker
        tokio::spawn(async move {
            while let Some(task) = rx.recv().await {
                match task {
                    BackgroundTask::SendWelcomeEmail { email, user_id } => {
                        // Process email sending
                        if let Err(e) = send_email(&email, &user_id).await {
                            error!("Failed to send welcome email: {}", e);
                        }
                    }
                    BackgroundTask::GenerateUserReport { user_id } => {
                        // Generate report
                        if let Err(e) = generate_report(&user_id).await {
                            error!("Failed to generate user report: {}", e);
                        }
                    }
                }
            }
        });

        Self { background_tx: tx }
    }

    async fn handle_user_signup(&self, message: &Value, context: &MessageContext) -> AsyncApiResult<()> {
        // Process immediate signup
        let user_id = self.create_user_immediately(message).await?;

        // Queue background tasks
        let _ = self.background_tx.send(BackgroundTask::SendWelcomeEmail {
            email: signup_data.email.clone(),
            user_id: user_id.clone(),
        }).await;

        let _ = self.background_tx.send(BackgroundTask::GenerateUserReport {
            user_id,
        }).await;

        Ok(())
    }
}
```

### Health Checks

Implement health checks for your services:

```rust
#[async_trait]
pub trait HealthCheck: Send + Sync {
    async fn health_check(&self) -> Result<(), String>;
}

#[async_trait]
impl HealthCheck for UserService {
    async fn health_check(&self) -> Result<(), String> {
        // Check database connectivity
        self.database.ping().await
            .map_err(|e| format!("Database health check failed: {}", e))?;

        // Check email service
        self.email_service.ping().await
            .map_err(|e| format!("Email service health check failed: {}", e))?;

        Ok(())
    }
}

// In your main.rs, expose health endpoint
async fn health_handler(services: Arc<UserService>) -> impl warp::Reply {
    match services.health_check().await {
        Ok(_) => warp::reply::with_status("OK", warp::http::StatusCode::OK),
        Err(e) => warp::reply::with_status(
            format!("Health check failed: {}", e),
            warp::http::StatusCode::SERVICE_UNAVAILABLE,
        ),
    }
}
```

This completes the comprehensive usage guide for the AsyncAPI Rust template with trait-based architecture.

# Simple User Service Example

This example demonstrates the basic usage of the AsyncAPI Rust template with a simple user service that handles user signups and profile updates.

## Overview

This example shows:
- Basic message handling with strongly-typed structs
- Multiple channels with different operations
- Complex schema definitions with nested objects
- HTTP protocol configuration

## AsyncAPI Specification

The `asyncapi.yaml` file defines:
- **Channels**: `user/signup` and `user/profile`
- **Messages**: UserSignup, UserWelcome, and ProfileUpdate
- **Schemas**: Complex user data structures with validation

## Generated Code

When you run the template against this specification, it generates:

### Message Models (`src/models.rs`)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSignupPayload {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub preferences: Option<UserPreferences>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    pub newsletter: Option<bool>,
    pub notifications: Option<bool>,
    pub theme: Option<String>,
    pub language: Option<String>,
}
```

### Message Handlers (`src/handlers.rs`)
```rust
impl UserSignupHandler {
    pub async fn handle_user_signup(&self, payload: &[u8]) -> Result<()> {
        let user_signup: UserSignupPayload = serde_json::from_slice(payload)?;
        info!("Processing user signup: {:?}", user_signup);

        // Add your business logic here
        // Example: Save to database, send welcome email, etc.

        Ok(())
    }
}

impl UserProfileHandler {
    pub async fn handle_profile_update(&self, payload: &[u8]) -> Result<()> {
        let profile_update: ProfileUpdatePayload = serde_json::from_slice(payload)?;
        info!("Processing profile update: {:?}", profile_update);

        // Add your business logic here
        // Example: Update database, notify other services, etc.

        Ok(())
    }
}
```

## Usage

### 1. Generate the Rust Server

```bash
# From the root of the rust-template repository
asyncapi generate fromTemplate examples/simple/asyncapi.yaml . --output examples/simple/generated --force-write
```

### 2. Run the Generated Server

```bash
cd examples/simple/generated
cargo run
```

### 3. Customize the Handlers

Edit the generated handler methods in `src/handlers.rs` to add your business logic:

```rust
impl UserSignupHandler {
    pub async fn handle_user_signup(&self, payload: &[u8]) -> Result<()> {
        let user_signup: UserSignupPayload = serde_json::from_slice(payload)?;

        // Validate the user data
        if user_signup.username.len() < 3 {
            return Err(anyhow::anyhow!("Username too short"));
        }

        // Save to database (example)
        // let user_id = self.database.create_user(user_signup).await?;

        // Send welcome email (example)
        // self.email_service.send_welcome_email(&user_signup.email).await?;

        info!("Successfully processed user signup for: {}", user_signup.username);
        Ok(())
    }
}
```

### 4. Add Environment Configuration

Create a `.env` file:

```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
LOG_LEVEL=info

# Add your custom configuration
DATABASE_URL=postgresql://user:password@localhost/userdb
EMAIL_SERVICE_API_KEY=your-api-key
```

## Key Features Demonstrated

### 1. **Type Safety**
- All message payloads are strongly typed
- Compile-time validation of message structure
- Automatic serialization/deserialization

### 2. **Schema Validation**
- Required fields are enforced at compile time
- Optional fields are properly handled with `Option<T>`
- Format validation (UUID, email, date-time)

### 3. **Extensible Architecture**
- Clean separation between message handling and business logic
- Easy to add custom middleware
- Configuration management through environment variables

### 4. **Error Handling**
- Comprehensive error handling with `anyhow`
- Proper error propagation through `Result<T>`
- Structured logging for debugging

## Next Steps

1. **Add Database Integration**: Implement actual database operations
2. **Add Authentication**: Implement user authentication and authorization
3. **Add Validation**: Add custom validation logic for business rules
4. **Add Testing**: Write unit and integration tests for your handlers
5. **Add Monitoring**: Implement metrics and health checks

## Related Examples

- [MQTT Example](../mqtt/README.md) - Shows MQTT protocol integration
- [Multi-Protocol Example](../multi-protocol/README.md) - Demonstrates multiple protocols in one service

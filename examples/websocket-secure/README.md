# WebSocket Secure Chat Service

This example demonstrates a comprehensive WebSocket-based chat service with robust security features, including server-level authentication and operation-level security requirements.

## Overview

The WebSocket Secure Chat Service showcases:

- **Server Authentication**: JWT-based authentication required for WebSocket connections
- **Operation Security**: Individual operations require specific permissions
- **Multi-Channel Architecture**: Separate channels for chat messages and profile updates
- **Request/Reply Pattern**: Synchronous operations with response handling
- **Comprehensive Security Testing**: Full test suite validating security mechanisms

## Architecture

### Security Model

The service implements a two-tier security model:

1. **Server-Level Security**: All WebSocket connections must authenticate with a valid JWT token
2. **Operation-Level Security**: Individual operations require specific permissions within the JWT token

### Channels and Operations

#### Chat Messages Channel (`chatMessages`)
- **Operation**: `sendChatMessage`
- **Security**: Requires `chat:send` permission
- **Pattern**: Request/Reply
- **Description**: Send chat messages to rooms and receive delivery confirmations

#### Profile Update Channel (`profileUpdate`)
- **Operation**: `updateUserProfile`
- **Security**: Requires `profile:update` permission
- **Pattern**: Request/Reply
- **Description**: Update user profile information with validation

## Message Schemas

### ChatMessage
```json
{
  "message_id": "uuid",
  "room_id": "string",
  "user_id": "uuid",
  "username": "string",
  "content": "string",
  "message_type": "Text|Image|File|System",
  "timestamp": "datetime",
  "reply_to": "uuid?"
}
```

### MessageDelivered
```json
{
  "message_id": "uuid",
  "room_id": "string",
  "delivered_at": "datetime",
  "status": "Delivered|Failed|Pending",
  "error": "string?"
}
```

### ProfileUpdateRequest
```json
{
  "request_id": "uuid",
  "updates": {
    "display_name": "string?",
    "bio": "string?",
    "avatar": "string?"
  },
  "timestamp": "datetime"
}
```

### ProfileUpdateResponse
```json
{
  "request_id": "uuid",
  "success": "boolean",
  "updated_fields": ["string"]?,
  "errors": ["object"]?,
  "profile": "object?",
  "timestamp": "datetime"
}
```

## Security Configuration

### JWT Token Requirements

JWT tokens must include:
- **Subject (`sub`)**: User identifier
- **Permissions**: Array of permission strings
- **Roles**: Array of role strings (optional)
- **Standard Claims**: `iss`, `aud`, `exp`, `iat`

Example JWT payload:
```json
{
  "sub": "user123",
  "iss": "chat-service",
  "aud": "chat-clients",
  "exp": 1640995200,
  "iat": 1640991600,
  "roles": ["user"],
  "permissions": ["chat:send", "profile:update"],
  "scopes": []
}
```

### Required Permissions

- **Server Connection**: Valid JWT token in `Authorization` header or `token` query parameter
- **Chat Operations**: `chat:send` permission
- **Profile Operations**: `profile:update` permission

## Generated Code Features

The generated Rust code includes:

### Authentication Components
- **JWT Validator**: Token validation with HMAC and RSA support
- **Server Auth Handler**: Connection-level authentication
- **Claims Management**: Role and permission checking
- **Auth Configuration**: Flexible security configuration

### Service Handlers
- **Type-Safe Message Handling**: Strongly-typed request/response processing
- **Error Management**: Comprehensive error handling and recovery
- **Transport Abstraction**: Protocol-agnostic message routing
- **Security Integration**: Automatic security enforcement

### Testing Infrastructure
- **Security Test Suite**: Comprehensive security validation
- **Mock Services**: Test doubles for service implementations
- **Integration Tests**: End-to-end security flow validation
- **Unit Tests**: Individual component testing

## Running the Example

### Prerequisites
- Rust 1.70+
- Cargo

### Generate and Test
```bash
# Generate the service code
npm run generate examples/websocket-secure/asyncapi.yaml

# Navigate to generated code
cd test-output-websocket-secure

# Run all tests including security tests
cargo test

# Run only security tests
cargo test --test security_tests

# Build the service
cargo build
```

### Security Test Results

The security test suite validates:

✅ **JWT Token Validation**
- Valid token acceptance
- Invalid token rejection
- Token expiration handling

✅ **Server Authentication**
- Connection-level security enforcement
- Multiple authentication strategies
- Missing credential rejection

✅ **Operation Security**
- Permission-based access control
- Service-level security integration
- End-to-end security flow

✅ **Configuration Management**
- Security configuration validation
- Transport configuration
- Authentication setup

## Key Security Features Demonstrated

### 1. Server-Level Authentication
```rust
// JWT-based server authentication
let server_auth_handler = JwtServerAuthHandler::new(jwt_validator);
let auth_result = server_auth_handler
    .authenticate_connection(&auth_request)
    .await?;
```

### 2. Operation-Level Security
```rust
// Service methods automatically enforce security
async fn handle_send_chat_message(
    &self,
    request: ChatMessage,
    context: &MessageContext, // Contains auth context
) -> AsyncApiResult<MessageDelivered>
```

### 3. Permission Checking
```rust
// JWT claims include permissions
let claims = jwt_validator.validate_token(&token)?;
assert!(claims.has_permission("chat:send"));
```

### 4. Transport Security
```yaml
# WebSocket server requires authentication
servers:
  production:
    url: wss://api.example.com/chat
    protocol: ws
    security:
      - jwtAuth: []
```

## Best Practices Demonstrated

1. **Defense in Depth**: Multiple security layers (server + operation)
2. **Principle of Least Privilege**: Granular permission requirements
3. **Secure by Default**: All operations require explicit security
4. **Comprehensive Testing**: Security validation at all levels
5. **Type Safety**: Compile-time security enforcement
6. **Error Handling**: Graceful security failure management

## Integration Examples

### Client Authentication
```javascript
// WebSocket connection with JWT
const ws = new WebSocket('wss://api.example.com/chat', {
  headers: {
    'Authorization': 'Bearer ' + jwtToken
  }
});
```

### Service Implementation
```rust
// Implement secure service
#[async_trait]
impl ChatMessagesService for MyChatService {
    async fn handle_send_chat_message(
        &self,
        request: ChatMessage,
        context: &MessageContext,
    ) -> AsyncApiResult<MessageDelivered> {
        // Security context automatically available
        let user_id = context.authenticated_user()?;

        // Business logic with security enforcement
        self.send_message(request, user_id).await
    }
}
```

This example provides a complete foundation for building secure, real-time messaging services with comprehensive authentication and authorization.

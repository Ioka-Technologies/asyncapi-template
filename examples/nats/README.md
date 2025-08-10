# NATS User Service Example

This example demonstrates a complete NATS-based user service using the AsyncAPI Rust server template with NATS transport support.

## Features

- **NATS Transport**: Full NATS integration with service discovery
- **Request/Reply Patterns**: Synchronous operations using NATS request/reply
- **Pub/Sub Patterns**: Asynchronous notifications using NATS pub/sub
- **JWT Authentication**: Secure NATS connections using JWT tokens
- **Service Discovery**: Automatic service registration via NATS Services API
- **MessageEnvelope Format**: Consistent message wrapping for all operations
- **Queue Groups**: Load balancing across service instances

## Architecture

The service implements the following operations:

### Request/Reply Operations
- `user.create` - Create a new user
- `user.update` - Update an existing user
- `user.delete` - Delete a user
- `user.get` - Get user by ID

### Pub/Sub Operations
- `user.notifications` - Publish user event notifications

## NATS Configuration

### Basic Configuration
```yaml
servers:
  development:
    url: nats://localhost:4222
    protocol: nats
    description: Development NATS server
```

### Production Configuration with JWT
```yaml
servers:
  production:
    url: nats://nats.example.com:4222
    protocol: nats
    description: Production NATS server with JWT auth
    bindings:
      nats:
        clientId: user-service-prod
        queue: user-service-queue
```

## Generated Code Structure

The AsyncAPI template generates the following NATS-specific components:

### Transport Layer
- `NatsTransport` - Main NATS transport implementation
- `NatsTransportConfig` - Configuration for NATS connections
- `MessageEnvelope` - Consistent message format wrapper

### Service Registration
Each AsyncAPI channel becomes a NATS service with:
- Service name: `{channel}-service`
- Version: Configurable (default: "1.0.0")
- Description: Auto-generated from channel description
- Queue groups: For load balancing

### Authentication
Supports multiple NATS authentication methods:
- **JWT with credentials file**: `credentials_file` parameter
- **JWT with token/nkey**: `jwt_token` and `nkey_seed` parameters
- **Anonymous**: No authentication (development only)

## Usage

### 1. Generate the Rust Server
```bash
asyncapi generate fromTemplate examples/nats/asyncapi.yaml @asyncapi/rust-server-template
```

### 2. Configure NATS Connection
Set environment variables or configuration:
```bash
export NATS_URL="nats://localhost:4222"
export NATS_CREDENTIALS_FILE="/path/to/nats.creds"
# OR
export NATS_JWT_TOKEN="your-jwt-token"
export NATS_NKEY_SEED="your-nkey-seed"
```

### 3. Build and Run
```bash
cd generated-project
cargo build --features nats
cargo run
```

## Message Flow

### Request/Reply Example
```
Client -> NATS -> Service
  user.create request
    {
      "id": "uuid",
      "operation": "createUser",
      "payload": {"name": "John", "email": "john@example.com"},
      "timestamp": "2023-01-01T00:00:00Z"
    }

Service -> NATS -> Client
  user.create response
    {
      "id": "uuid",
      "operation": "createUser",
      "payload": {"id": "user-uuid", "name": "John", "email": "john@example.com"},
      "timestamp": "2023-01-01T00:00:00Z"
    }
```

### Pub/Sub Example
```
Service -> NATS -> Subscribers
  user.notifications
    {
      "id": "uuid",
      "operation": "publishUserNotification",
      "payload": {
        "type": "created",
        "userId": "user-uuid",
        "message": "User John Doe was created"
      },
      "timestamp": "2023-01-01T00:00:00Z"
    }
```

## NATS Features Used

### Service Discovery
- Each channel registers as a NATS service
- Automatic endpoint registration
- Health checks and monitoring
- Service metadata and versioning

### Queue Groups
- Load balancing across service instances
- Configurable per channel or globally
- Automatic failover

### Subject Patterns
- Hierarchical subject naming: `{channel}.{operation}`
- Wildcard subscriptions for channel-level routing
- Configurable subject prefixes

## Configuration Options

### Transport Configuration
```rust
NatsTransportConfig {
    servers: vec!["nats://localhost:4222".to_string()],
    name: Some("user-service".to_string()),

    // Authentication
    credentials_file: Some("/path/to/nats.creds".to_string()),
    // OR
    jwt_token: Some("jwt-token".to_string()),
    nkey_seed: Some("nkey-seed".to_string()),

    // Service Registration
    service_version: "1.0.0".to_string(),
    service_description_template: Some("Service for {channel} channel".to_string()),

    // Queue Groups
    global_queue_group: Some("user-service".to_string()),
    per_channel_queue_groups: HashMap::new(),

    // Subject Configuration
    subject_prefix: Some("api.v1".to_string()),
    channel_operation_separator: ".".to_string(),

    // Connection Options
    connect_timeout: Some(Duration::from_secs(5)),
    reconnect_attempts: Some(10),
    max_reconnect_delay: Some(Duration::from_secs(30)),
}
```

## Testing

### Start NATS Server
```bash
# Basic NATS server
nats-server

# With JetStream (optional)
nats-server -js

# With authentication
nats-server --auth token.txt
```

### Test with NATS CLI
```bash
# Subscribe to notifications
nats sub "user.notifications"

# Send a create user request
nats req "user.create" '{"name":"John","email":"john@example.com"}'

# Publish a notification
nats pub "user.notifications" '{"type":"created","userId":"123","message":"User created"}'
```

## Monitoring

The NATS transport provides comprehensive monitoring:

### Service Discovery
- View registered services: `nats micro list`
- Service info: `nats micro info user-service`
- Service stats: `nats micro stats user-service`

### Connection Health
- Connection status monitoring
- Automatic reconnection with backoff
- Circuit breaker patterns

### Message Statistics
- Messages sent/received counters
- Processing time metrics
- Error rates and types

## Production Considerations

### Security
- Always use JWT authentication in production
- Rotate credentials regularly
- Use TLS for encrypted connections (`nats+tls://`)

### Scalability
- Use queue groups for horizontal scaling
- Configure appropriate connection pools
- Monitor service discovery overhead

### Reliability
- Configure reconnection strategies
- Implement circuit breakers
- Use dead letter queues for failed messages

### Monitoring
- Enable NATS monitoring endpoints
- Collect service discovery metrics
- Monitor queue group distribution

## Related Documentation

- [NATS Documentation](https://docs.nats.io/)
- [NATS Services API](https://docs.nats.io/using-nats/developer/services)
- [NATS Security](https://docs.nats.io/running-a-nats-service/configuration/securing_nats)
- [AsyncAPI Specification](https://www.asyncapi.com/docs/specifications/v2.0.0)

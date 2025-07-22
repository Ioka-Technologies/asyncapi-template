# AsyncAPI Rust Template Examples

This directory contains comprehensive examples demonstrating the capabilities of the AsyncAPI Rust template across different use cases and protocols.

## 📁 Available Examples

### [Simple Example](./simple/)
**Perfect for beginners** - Demonstrates basic AsyncAPI concepts with a user service.

- **Protocol**: HTTP
- **Complexity**: Beginner
- **Features**: Basic message handling, type-safe structs, simple validation
- **Use Case**: User signup and profile management
- **Generated Code**: ~200 lines

### [MQTT Example](./mqtt/)
**IoT and real-time messaging** - Comprehensive MQTT-based IoT device management system.

- **Protocol**: MQTT
- **Complexity**: Intermediate
- **Features**: Topic patterns, device telemetry, command handling, alerts
- **Use Case**: IoT device monitoring and control
- **Generated Code**: ~500 lines

### [Multi-Protocol Example](./multi-protocol/)
**Enterprise-grade architecture** - Demonstrates multiple protocols in a single service.

- **Protocols**: MQTT, Kafka, WebSocket, HTTP
- **Complexity**: Advanced
- **Features**: Cross-protocol routing, real-time updates, event streaming
- **Use Case**: Event processing hub for microservices
- **Generated Code**: ~800 lines

## 🚀 Quick Start

### Prerequisites

1. **AsyncAPI CLI** (required for code generation):
   ```bash
   npm install -g @asyncapi/cli
   ```

2. **Rust** (required for running generated code):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

3. **Protocol Infrastructure** (optional, for testing):
   - **MQTT**: `docker run -p 1883:1883 eclipse-mosquitto`
   - **Kafka**: See [multi-protocol example](./multi-protocol/README.md#kafka-cluster)

### Generate and Run Any Example

```bash
# 1. Choose an example
cd examples/simple  # or mqtt, multi-protocol

# 2. Generate Rust code from AsyncAPI spec
asyncapi generate fromTemplate asyncapi.yaml ../.. --output generated --force-write

# 3. Run the generated server
cd generated
cargo run
```

## 📊 Example Comparison

| Feature | Simple | MQTT | Multi-Protocol |
|---------|--------|------|----------------|
| **Protocols** | HTTP | MQTT | MQTT + Kafka + WebSocket + HTTP |
| **Message Types** | 3 | 5 | 8 |
| **Channels** | 2 | 5 | 8 |
| **Complexity** | ⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Learning Curve** | Easy | Moderate | Advanced |
| **Production Ready** | Basic | Yes | Enterprise |
| **Real-time Features** | No | Yes | Yes |
| **Event Streaming** | No | No | Yes |
| **Cross-Protocol** | No | No | Yes |

## 🎯 Choose Your Example

### I'm new to AsyncAPI
👉 **Start with [Simple Example](./simple/)**
- Learn basic concepts
- Understand code generation
- See type-safe message handling

### I'm building IoT applications
👉 **Use [MQTT Example](./mqtt/)**
- Device communication patterns
- Topic-based routing
- Real-world IoT scenarios

### I need enterprise architecture
👉 **Use [Multi-Protocol Example](./multi-protocol/)**
- Multiple protocol integration
- Event-driven architecture
- Scalable microservices patterns

## 🧪 Testing Examples

Each example includes comprehensive testing instructions:

### Automated Testing
```bash
# Test all examples
./scripts/test-examples.sh

# Test specific example
./scripts/test-examples.sh simple
```

### Manual Testing
Each example's README includes:
- Step-by-step setup instructions
- Sample messages for testing
- Expected outputs and behaviors
- Troubleshooting guides

## 📚 Learning Path

### 1. **Fundamentals** (Simple Example)
- AsyncAPI specification structure
- Message schema definition
- Code generation process
- Basic Rust server patterns

### 2. **Protocol Integration** (MQTT Example)
- Protocol-specific configuration
- Topic patterns and parameters
- Message routing and handling
- Error handling and resilience

### 3. **Advanced Architecture** (Multi-Protocol Example)
- Multi-protocol coordination
- Event correlation and routing
- Real-time communication
- Production considerations

## 🔧 Customization Guide

### Adding New Message Types
1. **Update AsyncAPI spec**:
   ```yaml
   components:
     messages:
       NewMessage:
         payload:
           $ref: '#/components/schemas/NewMessagePayload'
   ```

2. **Regenerate code**:
   ```bash
   asyncapi generate fromTemplate asyncapi.yaml ../.. --output generated --force-write
   ```

3. **Implement business logic**:
   ```rust
   impl NewMessageHandler {
       pub async fn handle_new_message(&self, payload: &[u8]) -> Result<()> {
           // Your business logic here
           Ok(())
       }
   }
   ```

### Adding New Protocols
1. **Add server configuration**:
   ```yaml
   servers:
     new-protocol:
       url: protocol://localhost:port
       protocol: new-protocol
   ```

2. **Update template dependencies** (if needed)
3. **Implement protocol handler** in generated code

### Environment Configuration
All examples support environment-based configuration:

```bash
# Create .env file
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
LOG_LEVEL=info

# Protocol-specific settings
MQTT_HOST=localhost
KAFKA_BROKERS=localhost:9092
DATABASE_URL=postgresql://...
```

## 🏗️ Generated Code Structure

All examples generate similar project structures:

```
generated/
├── Cargo.toml          # Dependencies and metadata
├── README.md           # Project-specific documentation
├── src/
│   ├── main.rs        # Application entry point
│   ├── config.rs      # Configuration management
│   ├── server.rs      # Protocol handlers
│   ├── handlers.rs    # Message handlers
│   ├── models.rs      # Generated message types
│   └── middleware.rs  # Extensible middleware
└── .env.example       # Environment configuration template
```

## 🔍 Code Quality

### Generated Code Features
- **Type Safety**: All messages are strongly typed
- **Error Handling**: Comprehensive error handling with `anyhow`
- **Async/Await**: Modern async Rust patterns
- **Logging**: Structured logging with `tracing`
- **Configuration**: Environment-based configuration
- **Documentation**: Inline documentation and comments

### Best Practices Demonstrated
- Clean architecture with separation of concerns
- Proper error propagation and handling
- Extensible middleware system
- Configuration management
- Graceful shutdown handling

## 🚀 Production Deployment

### Docker Support
Each example can be containerized:

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/app /usr/local/bin/app
CMD ["app"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: asyncapi-rust-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: asyncapi-rust-service
  template:
    metadata:
      labels:
        app: asyncapi-rust-service
    spec:
      containers:
      - name: service
        image: your-registry/asyncapi-rust-service:latest
        ports:
        - containerPort: 8080
        env:
        - name: LOG_LEVEL
          value: "info"
```

## 🤝 Contributing

### Adding New Examples
1. Create new directory under `examples/`
2. Add `asyncapi.yaml` specification
3. Create comprehensive `README.md`
4. Test code generation and functionality
5. Update this main examples README

### Improving Existing Examples
1. Enhance AsyncAPI specifications
2. Add more realistic business logic
3. Improve documentation
4. Add additional test scenarios

## 📖 Additional Resources

- [AsyncAPI Documentation](https://www.asyncapi.com/docs)
- [AsyncAPI Generator](https://www.asyncapi.com/docs/tools/generator)
- [Rust AsyncAPI Template](../../README.md)
- [Template Usage Guide](../../USAGE.md)
- [Contributing Guidelines](../../CONTRIBUTING.md)

## 🆘 Getting Help

### Common Issues
1. **Code generation fails**: Check AsyncAPI spec validity
2. **Compilation errors**: Ensure Rust toolchain is up to date
3. **Runtime errors**: Check protocol infrastructure setup
4. **Connection issues**: Verify network configuration

### Support Channels
- [GitHub Issues](https://github.com/asyncapi/rust-template/issues)
- [AsyncAPI Slack](https://asyncapi.com/slack-invite)
- [AsyncAPI Community](https://github.com/asyncapi/community)

---

**Happy coding with AsyncAPI and Rust! 🦀**

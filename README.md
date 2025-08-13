# AsyncAPI Templates Monorepo

Generate production-ready async messaging systems from your AsyncAPI specifications. This monorepo contains three complementary templates that work together to provide a complete full-stack development experience.

## Templates

### 🦀 Rust Server Template

Generate trait-based Rust server libraries with automatic protocol detection and enterprise-grade infrastructure.

- **Package**: [`@ioka-technologies/asyncapi-rust-server-template`](https://www.npmjs.com/package/@ioka-technologies/asyncapi-rust-server-template)
- **Documentation**: [rust-server/README.md](./rust-server/README.md)
- **Protocols**: WebSocket, HTTP, MQTT, Kafka, AMQP, NATS

### 📱 TypeScript Websocket Client Template

Generate type-safe TypeScript clients with automatic transport selection and built-in error handling.

- **Package**: [`@ioka-technologies/asyncapi-ts-client-template`](https://www.npmjs.com/package/@ioka-technologies/asyncapi-ts-client-template)
- **Documentation**: [ts-client/README.md](./ts-client/README.md)
- **Transports**: WebSocket, HTTP

### 🚀 Rust NATS Client Template

Generate type-safe Rust NATS clients with request/reply and pub/sub patterns using the NATS Services API.

- **Package**: [`nats-asyncapi-client-template`](https://www.npmjs.com/package/nats-asyncapi-client-template)
- **Documentation**: [rust-client/README.md](./rust-client/README.md)
- **Transport**: NATS (request/reply, pub/sub)

## Quick Start

### Prerequisites

```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli
```

### Generate Full-Stack Application

```bash
# Generate Rust server
asyncapi generate fromTemplate asyncapi.yaml @ioka-technologies/asyncapi-rust-server-template -o my-server

# Generate TypeScript client
asyncapi generate fromTemplate asyncapi.yaml @ioka-technologies/asyncapi-ts-client-template -o my-client

# Generate NATS client
asyncapi generate fromTemplate asyncapi.yaml nats-asyncapi-client-template -o my-rust-client

# Build and run
cd my-server && cargo build
cd ../my-client && npm install && npm run build
cd ../my-rust-client && cargo build
```

## Key Features

### Code Regeneration Safety

All templates are designed for safe regeneration. Update your AsyncAPI spec and regenerate without losing your business logic:

```bash
# Your implementations remain untouched
asyncapi generate fromTemplate updated-asyncapi.yaml @ioka-technologies/asyncapi-rust-server-template -o my-server --force-write
asyncapi generate fromTemplate updated-asyncapi.yaml @ioka-technologies/asyncapi-ts-client-template -o my-client --force-write
asyncapi generate fromTemplate updated-asyncapi.yaml nats-asyncapi-client-template -o my-rust-client --force-write
```

### Cross-Language Compatibility

The templates share compatible message formats and architectural patterns, enabling seamless full-stack development across different protocols and languages.

### Production Ready

- **Rust Server**: Built-in authentication, monitoring, error handling, and recovery
- **TypeScript Client**: Automatic reconnection, retry logic, and comprehensive error handling
- **NATS Client**: NATS Services API integration, message envelopes, and robust error handling

## Examples

The `examples/` directory contains sample AsyncAPI specifications demonstrating various features:

- **[Simple](./examples/simple/)**: Basic WebSocket API
- **[MQTT](./examples/mqtt/)**: IoT sensor data collection
- **[NATS](./examples/nats/)**: NATS user service with request/reply patterns
- **[Multi-protocol](./examples/multi-protocol/)**: HTTP + WebSocket + Kafka
- **[WebSocket Secure](./examples/websocket-secure/)**: Authenticated WebSocket chat

## Development

### Testing

```bash
# Test all templates
npm test

# Test individual templates
npm run rust-server:test
npm run ts-client:test
npm run rust-client:test
```

### Project Structure

```
asyncapi-templates/
├── rust-server/           # Rust server template
├── ts-client/             # TypeScript client template
├── rust-client/           # NATS client template
├── examples/              # Example AsyncAPI specifications
└── package.json           # Monorepo configuration
```

## Publishing

This monorepo uses GitHub Actions to automatically publish all templates to npm when a GitHub release is created.

**Published Packages:**

- [`@ioka-technologies/asyncapi-rust-server-template`](https://www.npmjs.com/package/@ioka-technologies/asyncapi-rust-server-template)
- [`@ioka-technologies/asyncapi-ts-client-template`](https://www.npmjs.com/package/@ioka-technologies/asyncapi-ts-client-template)
- [`nats-asyncapi-client-template`](https://www.npmjs.com/package/nats-asyncapi-client-template)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run the test suite: `npm test`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [AsyncAPI Generator](https://github.com/asyncapi/generator) - The AsyncAPI code generator
- [AsyncAPI CLI](https://github.com/asyncapi/cli) - AsyncAPI command line interface
- [AsyncAPI Specification](https://github.com/asyncapi/spec) - The AsyncAPI specification

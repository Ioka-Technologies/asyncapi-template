# AsyncAPI Templates Monorepo

A comprehensive monorepo containing AsyncAPI generator templates for building production-ready applications in multiple languages and architectures.

## Overview

This monorepo provides AsyncAPI templates for generating both server and client code, enabling you to build complete async messaging systems from a single AsyncAPI specification.

### Templates Included

- **🦀 Rust Server** (`rust-server/`) - Production-ready Rust server template with support for multiple protocols
- **📱 TypeScript Client** (`ts-client/`) - TypeScript client generator for connecting to AsyncAPI services

## Quick Start

### Prerequisites

- Node.js 16+ and npm
- [AsyncAPI CLI](https://github.com/asyncapi/cli) installed globally:
  ```bash
  npm install -g @asyncapi/cli
  ```
- Rust toolchain (for rust-server template)

### Installation

```bash
# Clone the repository
git clone https://github.com/ioka-technologies/asyncapi-template.git
cd asyncapi-template

# Install dependencies
npm install
```

### Running Tests

```bash
# Test all templates
npm test

# Test individual templates
npm run rust-server:test
npm run ts-client:test

# Clean all generated test files
npm run clean
```

## Templates

### Rust Server Template

The Rust server template generates production-ready async servers with:

- **Multi-protocol support**: HTTP, WebSocket, MQTT, Kafka, AMQP
- **Authentication & Authorization**: JWT-based auth with RBAC
- **Type-safe message handling**: Generated Rust structs from AsyncAPI schemas
- **Middleware support**: Custom middleware for logging, metrics, etc.
- **Error handling**: Comprehensive error types and recovery mechanisms

#### Usage

```bash
# Generate a Rust server from your AsyncAPI spec
asyncapi generate fromTemplate your-api.yaml ./rust-server -o my-rust-server

# With authentication enabled
asyncapi generate fromTemplate your-api.yaml ./rust-server -o my-rust-server -p enableAuth=true
```

#### Parameters

- `packageName` - Name of the generated Rust package (default: "asyncapi-server")
- `packageVersion` - Version of the generated package (default: "0.1.0")
- `enableAuth` - Enable authentication middleware (default: false)

### TypeScript Client Template

The TypeScript client template generates type-safe clients for:

- **Protocol support**: HTTP, WebSocket
- **Type safety**: Generated TypeScript interfaces from AsyncAPI schemas
- **Authentication**: Built-in auth handling
- **Transport abstraction**: Pluggable transport layer
- **Error handling**: Typed error responses

#### Usage

```bash
# Generate a TypeScript client from your AsyncAPI spec
asyncapi generate fromTemplate your-api.yaml ./ts-client -o my-ts-client

# With custom configuration
asyncapi generate fromTemplate your-api.yaml ./ts-client -o my-ts-client \
  -p clientName=MyApiClient \
  -p packageName=my-api-client \
  -p enableAuth=true
```

#### Parameters

- `clientName` - Name of the generated client class
- `packageName` - Name of the generated npm package
- `packageVersion` - Version of the generated package
- `author` - Package author (default: "AsyncAPI Generator")
- `license` - Package license (default: "Apache-2.0")
- `enableAuth` - Enable authentication middleware (default: true)
- `transports` - Comma-separated list of transports (default: "websocket,http")
- `generateTests` - Generate unit tests (default: true)
- `includeExamples` - Include usage examples (default: true)

## Complete Workflow Example

Here's how to use both templates together to build a complete async messaging system:

### 1. Define Your AsyncAPI Specification

```yaml
# my-chat-api.yaml
asyncapi: 3.0.0
info:
  title: Chat Service API
  version: 1.0.0
  description: Real-time chat service

servers:
  websocket:
    host: localhost:8080
    protocol: ws

channels:
  chat/messages:
    messages:
      sendMessage:
        payload:
          type: object
          properties:
            content:
              type: string
            userId:
              type: string
      messageReceived:
        payload:
          type: object
          properties:
            content:
              type: string
            userId:
              type: string
            timestamp:
              type: string
              format: date-time
```

### 2. Generate the Rust Server

```bash
# Generate the server
asyncapi generate fromTemplate my-chat-api.yaml ./rust-server -o chat-server -p enableAuth=true

# Build and run the server
cd chat-server
cargo build --release
cargo run
```

### 3. Generate the TypeScript Client

```bash
# Generate the client
asyncapi generate fromTemplate my-chat-api.yaml ./ts-client -o chat-client \
  -p clientName=ChatClient \
  -p packageName=chat-client

# Use the client in your app
cd chat-client
npm install
npm run build
```

### 4. Use the Generated Client

```typescript
import { ChatClient } from 'chat-client';

const client = new ChatClient('ws://localhost:8080');

// Send a message
await client.sendMessage({
  content: 'Hello, world!',
  userId: 'user123'
});

// Listen for messages
client.onMessageReceived((message) => {
  console.log(`${message.userId}: ${message.content}`);
});
```

## Examples

The `examples/` directory contains sample AsyncAPI specifications demonstrating various features:

- **Simple**: Basic WebSocket API
- **MQTT**: IoT sensor data collection
- **Multi-protocol**: HTTP + WebSocket + Kafka
- **WebSocket Secure**: Authenticated WebSocket chat

## Release Process

This monorepo uses GitHub Actions to automatically publish both templates to npm when a GitHub release is created.

### Setting up NPM Publishing

To enable automatic publishing to npm, you need to configure an NPM access token:

1. **Create an NPM Access Token:**
   - Log in to [npmjs.com](https://www.npmjs.com/)
   - Go to your profile → Access Tokens
   - Click "Generate New Token"
   - Choose "Automation" type for CI/CD usage
   - Copy the generated token

2. **Configure GitHub Repository Secret:**
   - Go to your GitHub repository
   - Navigate to Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `NPM_TOKEN`
   - Value: Paste your NPM access token
   - Click "Add secret"

3. **Create a Release:**
   - Create and push a git tag: `git tag v1.0.0 && git push origin v1.0.0`
   - Or create a release through GitHub's web interface
   - The workflow will automatically:
     - Run all tests
     - Update package versions
     - Publish both templates to npm
     - Create GitHub release with example archives

### Published Packages

When released, the templates are published as:
- **Rust Server**: `@ioka-technologies/asyncapi-rust-server-template`
- **TypeScript Client**: `ts-asyncapi-generator-template`

## Development

### Project Structure

```
asyncapi-templates/
├── rust-server/           # Rust server template
│   ├── template/          # Template files
│   ├── test/              # Template tests
│   └── package.json       # Template configuration
├── ts-client/             # TypeScript client template
│   ├── template/          # Template files
│   ├── examples/          # Example specs
│   └── package.json       # Template configuration
├── examples/              # Shared example specs
├── package.json           # Monorepo configuration
└── README.md             # This file
```

### Available Scripts

```bash
# Test all templates
npm test

# Test specific templates
npm run rust-server:test
npm run ts-client:test

# Run specific test suites
npm run rust-server:test:simple
npm run rust-server:test:mqtt
npm run ts-client:test:generate

# Linting
npm run lint
npm run lint:fix

# Cleanup
npm run clean
npm run rust-server:clean
npm run ts-client:clean
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `npm test`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [AsyncAPI Documentation](https://www.asyncapi.com/docs)
- 🐛 [Report Issues](https://github.com/ioka-technologies/asyncapi-template/issues)
- 💬 [AsyncAPI Slack](https://asyncapi.com/slack-invite)

## Related Projects

- [AsyncAPI Generator](https://github.com/asyncapi/generator) - The AsyncAPI code generator
- [AsyncAPI CLI](https://github.com/asyncapi/cli) - AsyncAPI command line interface
- [AsyncAPI Studio](https://studio.asyncapi.com/) - Visual AsyncAPI editor

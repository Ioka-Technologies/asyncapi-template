# AsyncAPI TypeScript Client Template

⚠️ **Experimental**: This template is still a work in progress and until we reach a 0.1.0 version, assume this is experimental and is not production ready.

Generate type-safe TypeScript clients from your AsyncAPI specifications with automatic transport selection and built-in error handling.

## Overview

This template generates TypeScript clients that provide full type safety across the network boundary. The generated clients work seamlessly with AsyncAPI servers and automatically handle transport protocols, reconnection logic, and error recovery.

**Key Benefits:**

- **Type Safety**: Full TypeScript types generated from your AsyncAPI spec
- **Transport Agnostic**: Same API works over WebSocket or HTTP
- **Auto Reconnection**: Built-in resilience for production environments
- **Zero Configuration**: Works out of the box with sensible defaults

## Technical Requirements

- Node.js 16+
- TypeScript 4.5+
- AsyncAPI CLI 1.0+

## Supported Transports

- WebSocket (with auto-reconnection)
- HTTP (with retry logic)

## Quick Start

### Installation

```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Generate your TypeScript client
asyncapi generate fromTemplate asyncapi.yaml @ioka-technologies/asyncapi-ts-client-template -o my-client

cd my-client
npm install
npm run build
```

### Basic Usage

```typescript
import { MyApiClient } from './my-client';

// WebSocket client with auto-reconnection
const client = new MyApiClient({
    transport: 'websocket',
    websocket: {
        url: 'wss://api.example.com',
        reconnect: true
    }
});

// Type-safe API calls
await client.connect();

// All methods are fully typed
const user = await client.createUser({
    name: "John Doe",     // TypeScript knows this is required
    email: "john@example.com",
    age: 30               // TypeScript knows this is optional
});

// Response is fully typed
console.log(user.id);        // TypeScript provides autocomplete
console.log(user.createdAt); // TypeScript knows this is a Date

// Real-time subscriptions
client.onUserCreated((user) => {
    console.log('New user:', user);
});
```

### HTTP Transport

```typescript
// HTTP client with retry logic
const client = new MyApiClient({
    transport: 'http',
    http: {
        baseUrl: 'https://api.example.com',
        retry: {
            attempts: 3,
            backoff: 'exponential'
        }
    }
});

const response = await client.getUser({ userId: '123' });
```

### Authentication

```typescript
// JWT Authentication
const client = new MyApiClient({
    transport: 'websocket',
    websocket: { url: 'wss://api.example.com' },
    auth: {
        jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    }
});

// API Key Authentication
const client = new MyApiClient({
    transport: 'http',
    http: { baseUrl: 'https://api.example.com' },
    auth: {
        apiKey: {
            key: 'my-api-key-123',
            location: 'header',
            name: 'X-API-Key'
        }
    }
});
```

## Template Configuration

Configure the template with parameters:

```bash
asyncapi generate fromTemplate asyncapi.yaml @ioka-technologies/asyncapi-ts-client-template \
  -o my-client \
  -p clientName=MyApiClient \
  -p packageName=my-api-client \
  -p packageVersion=1.0.0
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `clientName` | `"{{info.title}}Client"` | Main client class name |
| `packageName` | `"{{info.title | kebabCase}}-client"` | NPM package name |
| `packageVersion` | `"{{info.version}}"` | Package version |
| `author` | `"AsyncAPI Generator"` | Package author |
| `transports` | `"websocket,http"` | Supported transport protocols |

## Error Handling

```typescript
import { ConnectionError, MessageTimeoutError, HttpError } from './my-client';

try {
    await client.createUser(userData);
} catch (error) {
    if (error instanceof ConnectionError) {
        console.error('Connection failed:', error.message);
    } else if (error instanceof MessageTimeoutError) {
        console.error('Request timed out');
    } else if (error instanceof HttpError) {
        console.error(`HTTP ${error.status}: ${error.message}`);
    }
}
```

## Generated Project Structure

```
my-client/
├── package.json              # NPM package configuration
├── tsconfig.json             # TypeScript configuration
├── src/
│   ├── index.ts              # Main exports
│   ├── client.ts             # Generated client class
│   ├── models.ts             # TypeScript interfaces
│   └── runtime/              # Transport implementations
└── examples/                 # Usage examples
```

## Examples

See the [examples directory](../examples/) for sample AsyncAPI specifications and generated clients.

## Development

```bash
# Clone and test locally
git clone https://github.com/Ioka-Technologies/asyncapi-template.git
cd asyncapi-template/ts-client

# Run tests
npm test
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run the test suite: `npm test`
5. Submit a pull request

## License

Apache-2.0

## Related Projects

- [AsyncAPI Generator](https://github.com/asyncapi/generator)
- [AsyncAPI CLI](https://github.com/asyncapi/cli)
- [Rust Server Template](../rust-server/)

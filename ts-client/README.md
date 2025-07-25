# TypeScript AsyncAPI Client Generator Template

A production-ready AsyncAPI code generator template for TypeScript clients. This template generates fully-typed TypeScript clients from AsyncAPI specifications with support for WebSocket and HTTP transports, compatible with the rust-asyncapi patterns.

## 🎯 Key Features

- 🦀 **Rust-AsyncAPI Compatible**: Generated clients are type-compatible with rust-asyncapi servers
- 🔄 **Multiple Transports**: WebSocket and HTTP support with automatic transport selection
- 🛡️ **Type Safe**: Full TypeScript support with generated interfaces from AsyncAPI schemas
- 🔧 **Smart Method Names**: Automatic sanitization of operation names to valid JavaScript identifiers
- 🔌 **Auto Reconnection**: WebSocket reconnection with configurable retry logic
- 🔐 **Authentication**: JWT, API Key, and custom authentication support
- ⚡ **Promise Based**: Modern async/await API
- 📦 **Zero Config**: Works out of the box with sensible defaults
- 🧪 **Well Tested**: Comprehensive examples and documentation

## 🚀 Quick Start

### Prerequisites

- [AsyncAPI CLI](https://github.com/asyncapi/cli) installed
- [Node.js](https://nodejs.org/) 16+ installed

### Generate Your Client

```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Generate TypeScript client from your AsyncAPI specification
asyncapi generate fromTemplate asyncapi.yaml ./template -o ./my-client

# Install dependencies and build
cd my-client
npm install
npm run build
```

## 📁 Project Structure

```
ts-asyncapi/
├── README.md                           # This file
├── USAGE.md                           # Comprehensive usage guide
├── PROJECT_SUMMARY.md                 # Project summary and achievements
├── example-api.yaml                   # Example AsyncAPI specification
├── package.json                       # Project dependencies
└── template/                         # AsyncAPI Generator Template
    ├── package.json                  # Template dependencies
    ├── index.jsx                     # Template entry point
    ├── README.md                     # Template documentation
    ├── test.js                       # Template testing script
    └── components/                   # Template components
        ├── PackageJson.js            # Package.json generator
        ├── IndexFile.js              # Main index.ts generator
        ├── ClientFile.js             # Client class generator
        ├── ModelsFile.js             # Type definitions generator
        ├── TransportsFile.js         # Transport exports
        ├── TsConfigFile.js           # TypeScript config generator
        ├── ReadmeFile.js             # Generated README
        ├── UsageFile.js              # Generated usage docs
        ├── examples/                 # Example generators
        │   ├── WebSocketExample.js   # WebSocket example generator
        │   └── HttpExample.js        # HTTP example generator
        └── runtime/                  # Runtime implementation generators
            ├── RuntimeTypes.js       # Core type definitions
            ├── RuntimeErrors.js      # Error classes
            ├── TransportFactory.js   # Transport factory
            ├── WebSocketTransport.js # WebSocket implementation
            └── HttpTransport.js      # HTTP implementation
```

## 🔧 Template Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `clientName` | string | `"{{info.title}}Client"` | Name of the generated client class |
| `packageName` | string | `"{{info.title | kebabCase}}-client"` | Name of the generated npm package |
| `packageVersion` | string | `"{{info.version}}"` | Version of the generated package |
| `author` | string | `"AsyncAPI Generator"` | Package author |
| `license` | string | `"Apache-2.0"` | Package license |
| `generateTests` | boolean | `true` | Generate unit tests |
| `includeExamples` | boolean | `true` | Include usage examples |
| `transports` | string | `"websocket,http"` | Comma-separated list of transports |

### Example with Parameters

```bash
asyncapi generate fromTemplate asyncapi.yaml ./template \
  -o ./my-client \
  -p clientName=MyAwesomeClient \
  -p packageName=my-awesome-client \
  -p packageVersion=1.0.0 \
  -p author="Your Name" \
  -p transports=websocket
```

## 📨 Message Envelope Standard

This template implements a standardized message envelope format for all AsyncAPI communications, enabling operation-based routing and consistent message handling across transports.

### Message Envelope Structure

```typescript
interface MessageEnvelope {
    operation: string;           // AsyncAPI operation ID
    id?: string;                // Correlation ID for request/response
    channel?: string;           // Optional channel context
    payload: any;               // Message payload
    timestamp?: number;         // Message timestamp
    error?: {                   // Error information
        code: string;
        message: string;
    };
}
```

### Message Flow Examples

#### Request/Response Pattern
```typescript
// Client sends:
{
    "operation": "getUserProfile",
    "id": "uuid-1234",
    "channel": "user/profile",
    "payload": { "userId": "123" },
    "timestamp": 1234567890
}

// Server responds:
{
    "operation": "getUserProfile",
    "id": "uuid-1234",
    "payload": { "id": "123", "name": "John" },
    "timestamp": 1234567891
}
```

#### Subscription Pattern
```typescript
// Server publishes:
{
    "operation": "onMessageReceived",
    "channel": "chat/receive",
    "payload": { "text": "Hello", "from": "Alice" },
    "timestamp": 1234567892
}
```

#### Error Response
```typescript
{
    "operation": "getUserProfile",
    "id": "uuid-1234",
    "error": {
        "code": "USER_NOT_FOUND",
        "message": "User with ID 123 not found"
    },
    "timestamp": 1234567893
}
```

### Transport-Specific Handling

#### WebSocket Transport
- **Sending**: All messages wrapped in MessageEnvelope
- **Receiving**: Automatic envelope parsing and operation-based routing
- **Subscriptions**: Client-side filtering by operation field
- **Correlation**: Built-in request/response correlation via `id` field

#### HTTP Transport
- **Sending**: Complete envelope in POST body
- **Headers**: Operation and correlation ID in HTTP headers
- **Error Handling**: Envelope-level errors parsed from response body
- **Subscriptions**: Warning logged (HTTP doesn't support real-time subscriptions)

### Server Implementation Guide

To implement a compatible server, ensure your server:

1. **Parses MessageEnvelope**: All incoming messages should be parsed as MessageEnvelope
2. **Routes by Operation**: Use the `operation` field to route messages to appropriate handlers
3. **Preserves Correlation**: Include the same `id` in response messages for request/response patterns
4. **Uses Error Format**: Return errors in the envelope `error` field with `code` and `message`
5. **Includes Timestamps**: Add `timestamp` field for message timing information

## 🔄 Rust-AsyncAPI Compatibility

This template generates clients that work with AsyncAPI-compliant servers. The message envelope format provides a standard way to handle operation routing and correlation across different server implementations.

### Key Compatibility Features

- **Operation-Based Routing**: Servers can route messages based on the `operation` field
- **Request/Response Correlation**: Built-in correlation ID support for async request/response patterns
- **Standardized Error Format**: Consistent error structure across all operations
- **Transport Agnostic**: Same envelope format works across WebSocket and HTTP transports
- **Channel Context**: Optional channel information for debugging and routing

## 📚 Usage Examples

### WebSocket Client

```typescript
import { MyServiceClient } from './my-client';

const client = new MyServiceClient({
    transport: 'websocket',
    websocket: {
        url: 'ws://localhost:8080',
        reconnect: true,
        auth: {
            token: 'your-jwt-token'
        }
    }
});

await client.connect();
const response = await client.getUserProfile({ userId: '123' });
console.log(response);
```

### HTTP Client

```typescript
import { MyServiceClient } from './my-client';

const client = new MyServiceClient({
    transport: 'http',
    http: {
        baseUrl: 'http://localhost:8080',
        retry: {
            attempts: 3,
            delay: 1000,
            backoff: 'exponential'
        }
    }
});

await client.connect();
const response = await client.createUser({ name: 'John', email: 'john@example.com' });
console.log(response);
```

## 🛡️ Type Safety

The generated client provides full TypeScript type safety:

```typescript
// All request/response types are generated from your AsyncAPI spec
const response = await client.getUserProfile({
    userId: '123' // TypeScript knows this is required
});

// Response is fully typed
console.log(response.user.name); // TypeScript provides autocomplete
```

## 🔐 Authentication Support

### JWT Tokens

```typescript
{
    auth: {
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    }
}
```

### API Keys

```typescript
{
    auth: {
        apiKey: 'your-api-key'
    }
}
```

### Custom Headers

```typescript
{
    auth: {
        headers: {
            'X-Custom-Auth': 'custom-value'
        }
    }
}
```

## 🔄 Error Handling

Comprehensive error types for robust error handling:

```typescript
import { ConnectionError, MessageTimeoutError, HttpError } from './my-client';

try {
    await client.someOperation(data);
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

## 🧪 Testing the Template

```bash
# Test the template with the example API
cd template
npm install
node test.js
```

## 🏗️ Generated Project Structure

When you generate a client, you'll get a complete TypeScript project:

```
my-client/
├── package.json              # NPM package configuration
├── tsconfig.json             # TypeScript configuration
├── README.md                 # Generated documentation
├── USAGE.md                  # Detailed usage instructions
├── src/
│   ├── index.ts              # Main exports
│   ├── client.ts             # Generated client class
│   ├── models.ts             # Generated TypeScript interfaces
│   ├── transports.ts         # Transport exports
│   └── runtime/              # Runtime implementation
│       ├── types.ts          # Core type definitions
│       ├── errors.ts         # Error classes
│       └── transports/       # Transport implementations
│           ├── factory.ts    # Transport factory
│           ├── websocket.ts  # WebSocket transport
│           └── http.ts       # HTTP transport
└── examples/                 # Usage examples
    ├── websocket-example.ts  # WebSocket example
    └── http-example.ts       # HTTP example
```

## 📖 Documentation

- **[USAGE.md](./USAGE.md)** - Comprehensive usage guide with examples
- **[PROJECT_SUMMARY.md](./PROJECT_SUMMARY.md)** - Complete project summary
- **[template/README.md](./template/README.md)** - Template-specific documentation

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Submit a pull request

## 📋 Requirements

- **Node.js**: >= 16.0.0
- **TypeScript**: >= 4.5.0
- **AsyncAPI CLI**: Latest version

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [AsyncAPI Generator](https://github.com/asyncapi/generator)
- [AsyncAPI CLI](https://github.com/asyncapi/cli)
- [Rust AsyncAPI Template](https://github.com/asyncapi/rust-template)
- [AsyncAPI Specification](https://github.com/asyncapi/spec)

---

Generated with ❤️ by [AsyncAPI Generator](https://github.com/asyncapi/generator)

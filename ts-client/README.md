# TypeScript AsyncAPI Client Generator

**Type safety across the network boundary - the missing piece of full-stack AsyncAPI development**

This template solves the fundamental challenge of maintaining type safety and API consistency between async servers and their clients. Instead of hand-writing clients that drift out of sync, we generate **production-ready TypeScript clients** that automatically stay in perfect alignment with your AsyncAPI servers.

## 🎯 The Full-Stack Vision

**The Problem**: Traditional async API development breaks down at the client boundary. You have a perfectly typed server, but clients are hand-written, error-prone, and constantly fall out of sync with server changes.

**Our Solution**: **Automatic Type-Safe Client Generation**

```typescript
// Generated client with perfect server compatibility
const client = new ChatClient({
    transport: 'websocket',  // or 'http' - same interface
    websocket: { url: 'wss://api.example.com', reconnect: true }
});

// Type-safe method calls with IntelliSense
const user = await client.createUser({
    name: "John",     // ✅ TypeScript knows this is required
    email: "john@...", // ✅ TypeScript validates email format
    age: 25           // ✅ TypeScript knows this is optional
});

// Response is fully typed - no runtime surprises
console.log(user.id);        // ✅ TypeScript provides autocomplete
console.log(user.createdAt); // ✅ TypeScript knows this is a Date
```

**Why This Changes Everything**:
- 🔄 **Perfect Sync**: Client and server types are generated from the same AsyncAPI spec
- 🛡️ **Compile-Time Safety**: Catch API mismatches before they reach production
- 🚀 **Zero Configuration**: Works out of the box with intelligent defaults
- 🌐 **Transport Agnostic**: Same code works over WebSocket or HTTP
- 🔌 **Production Ready**: Built-in reconnection, error handling, and monitoring

## 🚀 The 2-Minute Full-Stack Experience

**Goal**: Experience the power of synchronized client-server development.

### The Business Scenario
You have a Rust AsyncAPI server handling user management. You need web and mobile clients that stay perfectly in sync as the API evolves.

### Step 1: Generate Type-Safe Client (30 seconds)
```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Generate client from the SAME spec as your Rust server
asyncapi generate fromTemplate your-user-api.yaml ./ts-client -o user-client

# Install and build
cd user-client && npm install && npm run build
```

### Step 2: Use in Your Application (1 minute)
```typescript
// React/Vue/Angular - works everywhere
import { UserApiClient } from './user-client';

const client = new UserApiClient({
    transport: 'websocket',
    websocket: {
        url: 'wss://api.yourcompany.com',
        auth: { jwt: getAuthToken() },
        reconnect: true  // Production-ready resilience
    }
});

// Type-safe API calls with IntelliSense
const App = () => {
    const [users, setUsers] = useState([]);

    useEffect(() => {
        client.connect();

        // Real-time updates
        client.onUserCreated((user) => {
            setUsers(prev => [...prev, user]);
        });

        return () => client.disconnect();
    }, []);

    const createUser = async (userData) => {
        // Fully type-safe - catches errors at compile time
        const newUser = await client.createUser({
            name: userData.name,     // Required field
            email: userData.email,   // Validated format
            preferences: {           // Nested object support
                newsletter: true,
                theme: 'dark'
            }
        });

        // Response is fully typed
        console.log(`Created user ${newUser.id} at ${newUser.createdAt}`);
    };
};
```

### Step 3: Experience the Magic (30 seconds)
```bash
# Server team updates AsyncAPI spec (adds new field)
# Regenerate client
asyncapi generate fromTemplate updated-api.yaml ./ts-client -o user-client --force-write

# TypeScript compiler immediately shows what changed
npm run build
# ✅ New fields are available with IntelliSense
# ✅ Removed fields cause compile errors (catch before production)
# ✅ Changed types are automatically updated
```

**Result**: Your client and server are always perfectly synchronized. API changes are caught at compile time, not in production.

## 📁 Generated Client Architecture

**The Strategic Design**: Every generated file serves the full-stack development experience.

```
user-client/                          # Your generated TypeScript client
├── package.json                     # NPM package ready for publishing
├── tsconfig.json                    # TypeScript configuration
├── README.md                        # Client-specific documentation
├── USAGE.md                         # Integration examples
├── src/
│   ├── index.ts                    # Public API exports
│   ├── client.ts                   # Main client class
│   ├── models.ts                   # Generated TypeScript interfaces
│   ├── transports.ts               # Transport layer exports
│   └── runtime/                    # Production-ready runtime
│       ├── types.ts               # Core type definitions
│       ├── errors.ts              # Typed error classes
│       └── transports/            # Transport implementations
│           ├── factory.ts         # Intelligent transport selection
│           ├── websocket.ts       # Real-time WebSocket transport
│           └── http.ts            # Reliable HTTP transport
├── examples/                        # Ready-to-run examples
│   ├── websocket-example.ts        # WebSocket integration
│   ├── http-example.ts             # HTTP integration
│   └── react-example.tsx           # React component example
└── dist/                           # Compiled JavaScript (after build)
    ├── index.js                    # ES modules
    ├── index.d.ts                  # TypeScript declarations
    └── ...                         # All compiled outputs
```

### The Architecture Strategy

**Generated Types** (src/models.ts): Perfect server compatibility
- **Synchronized**: Generated from the same AsyncAPI spec as your Rust server
- **Type-safe**: Catch mismatches at compile time, not runtime
- **Rich**: Support for nested objects, enums, optional fields, validation

**Transport Layer** (src/runtime/transports/): Production resilience
- **WebSocket**: Real-time communication with automatic reconnection
- **HTTP**: Reliable request/response with retry logic
- **Unified Interface**: Same API regardless of transport choice

**Client Class** (src/client.ts): Developer experience
- **IntelliSense**: Full autocomplete for all operations
- **Promise-based**: Modern async/await patterns
- **Event-driven**: Subscribe to real-time updates
- **Error handling**: Typed exceptions for robust error handling

### Integration Patterns

**React/Vue/Angular Integration**:
```typescript
// Hook-based integration
const useUserApi = () => {
    const [client] = useState(() => new UserApiClient({
        transport: 'websocket',
        websocket: { url: process.env.REACT_APP_API_URL }
    }));

    useEffect(() => {
        client.connect();
        return () => client.disconnect();
    }, []);

    return client;
};
```

**Node.js Backend Integration**:
```typescript
// Server-to-server communication
const apiClient = new UserApiClient({
    transport: 'http',
    http: {
        baseUrl: 'https://internal-api.company.com',
        auth: { apiKey: process.env.API_KEY },
        retry: { attempts: 3, backoff: 'exponential' }
    }
});
```

**Mobile App Integration**:
```typescript
// React Native / Expo
const client = new UserApiClient({
    transport: 'websocket',
    websocket: {
        url: 'wss://api.company.com',
        auth: { jwt: await getStoredToken() },
        reconnect: true,
        reconnectInterval: 5000
    }
});
```

## 🔧 Configuration: Tailored for Your Stack

**Strategic Configuration**: Every parameter serves a specific architectural purpose.

| Parameter | Type | Default | Purpose |
|-----------|------|---------|---------|
| `clientName` | string | `"{{info.title}}Client"` | **Class naming**: Controls the main client class name for your codebase |
| `packageName` | string | `"{{info.title | kebabCase}}-client"` | **NPM publishing**: Package name for internal/public npm registry |
| `packageVersion` | string | `"{{info.version}}"` | **Versioning**: Syncs client version with AsyncAPI spec version |
| `author` | string | `"AsyncAPI Generator"` | **Attribution**: Your team/company name for package metadata |
| `license` | string | `"Apache-2.0"` | **Legal**: License for your generated client package |
| `transports` | string | `"websocket,http"` | **Architecture**: Which transport layers to include |
| `generateTests` | boolean | `true` | **Quality**: Include comprehensive test suite |
| `includeExamples` | boolean | `true` | **Developer Experience**: Include integration examples |

### Real-World Configuration Examples

**Enterprise Microservice Client**:
```bash
asyncapi generate fromTemplate user-service.yaml ./ts-client \
  -o @company/user-service-client \
  -p clientName=UserServiceClient \
  -p packageName=@company/user-service-client \
  -p packageVersion=2.1.0 \
  -p author="Platform Team <platform@company.com>" \
  -p transports=http \
  -p generateTests=true
```

**Real-Time Web Application Client**:
```bash
asyncapi generate fromTemplate chat-api.yaml ./ts-client \
  -o chat-web-client \
  -p clientName=ChatClient \
  -p packageName=chat-web-client \
  -p transports=websocket \
  -p includeExamples=true
```

**Mobile App Client**:
```bash
asyncapi generate fromTemplate mobile-api.yaml ./ts-client \
  -o @myapp/api-client \
  -p clientName=MobileApiClient \
  -p packageName=@myapp/api-client \
  -p transports=websocket,http \
  -p generateTests=false \
  -p includeExamples=true
```

**IoT Dashboard Client**:
```bash
asyncapi generate fromTemplate iot-telemetry.yaml ./ts-client \
  -o iot-dashboard-client \
  -p clientName=IoTDashboardClient \
  -p transports=websocket \
  -p author="IoT Team" \
  -p license=MIT
```

## 📨 The Message Envelope: Cross-Language Compatibility

**The Innovation**: A standardized message format that enables perfect compatibility between Rust servers and TypeScript clients, regardless of transport protocol.

**Why This Matters**: Traditional async APIs suffer from protocol-specific message formats. Our envelope provides a universal standard that works across WebSocket, HTTP, MQTT, and any future transport.

### Universal Message Structure

```typescript
interface MessageEnvelope {
    operation: string;           // AsyncAPI operation ID for routing
    id?: string;                // Correlation ID for request/response tracking
    channel?: string;           // Channel context for debugging and routing
    payload: any;               // Strongly-typed message payload
    timestamp?: number;         // Message timing for analytics
    error?: {                   // Standardized error format
        code: string;           // Machine-readable error code
        message: string;        // Human-readable error message
    };
}
```

**The Architecture Benefits**:
- 🔄 **Operation Routing**: Servers route messages based on operation field
- 🎯 **Request/Response Correlation**: Built-in correlation ID support
- 🛡️ **Standardized Errors**: Consistent error handling across all operations
- 🌐 **Transport Agnostic**: Same envelope works over any protocol
- 📊 **Observability**: Built-in timing and debugging information

### Real-World Message Flows

**The Power**: These patterns work identically whether you're using WebSocket, HTTP, or any other transport.

#### Enterprise User Management Flow
```typescript
// 1. Client Request (WebSocket or HTTP - same format)
{
    "operation": "createUser",
    "id": "req_789abc",
    "channel": "user/management",
    "payload": {
        "name": "Sarah Johnson",
        "email": "sarah@company.com",
        "department": "Engineering",
        "role": "Senior Developer"
    },
    "timestamp": 1640995200000
}

// 2. Server Success Response
{
    "operation": "createUser",
    "id": "req_789abc",
    "payload": {
        "userId": "usr_456def",
        "name": "Sarah Johnson",
        "email": "sarah@company.com",
        "createdAt": "2021-12-31T12:00:00Z",
        "onboardingTasks": [
            "complete_profile",
            "setup_2fa",
            "join_team_channels"
        ]
    },
    "timestamp": 1640995201500
}

// 3. Real-Time Notification (to other users)
{
    "operation": "userJoined",
    "channel": "team/notifications",
    "payload": {
        "userId": "usr_456def",
        "name": "Sarah Johnson",
        "department": "Engineering",
        "joinedAt": "2021-12-31T12:00:00Z"
    },
    "timestamp": 1640995201600
}
```

#### Error Handling with Business Context
```typescript
// Business Logic Error
{
    "operation": "createUser",
    "id": "req_789abc",
    "error": {
        "code": "EMAIL_ALREADY_EXISTS",
        "message": "A user with email sarah@company.com already exists"
    },
    "timestamp": 1640995201000
}

// Validation Error
{
    "operation": "createUser",
    "id": "req_789abc",
    "error": {
        "code": "VALIDATION_FAILED",
        "message": "Invalid email format: not-an-email"
    },
    "timestamp": 1640995201000
}

// Infrastructure Error
{
    "operation": "createUser",
    "id": "req_789abc",
    "error": {
        "code": "SERVICE_UNAVAILABLE",
        "message": "User database is temporarily unavailable"
    },
    "timestamp": 1640995201000
}
```

#### IoT Telemetry Stream
```typescript
// Sensor Data (MQTT → WebSocket bridge)
{
    "operation": "sensorReading",
    "channel": "sensors/temperature",
    "payload": {
        "sensorId": "temp_001",
        "location": "server_room_a",
        "temperature": 23.5,
        "humidity": 45.2,
        "batteryLevel": 87
    },
    "timestamp": 1640995202000
}

// Alert Trigger
{
    "operation": "alertTriggered",
    "channel": "alerts/critical",
    "payload": {
        "alertId": "alert_456",
        "type": "TEMPERATURE_HIGH",
        "sensorId": "temp_001",
        "currentValue": 35.8,
        "threshold": 30.0,
        "severity": "CRITICAL"
    },
    "timestamp": 1640995203000
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

## 🔐 Authentication & Retry Support

The generated client includes comprehensive authentication and retry capabilities inspired by the Rust server template.

### JWT Authentication

```typescript
const client = new MyServiceClient({
    transport: 'http',
    url: 'https://api.example.com',
    auth: {
        jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    }
});

// JWT token is automatically added to Authorization header
const response = await client.getUserProfile({ userId: '123' });
```

### Basic Authentication

```typescript
const client = new MyServiceClient({
    transport: 'http',
    url: 'https://api.example.com',
    auth: {
        basic: {
            username: 'myuser',
            password: 'mypassword'
        }
    }
});
```

### API Key Authentication

```typescript
// API Key in header
const client = new MyServiceClient({
    transport: 'http',
    url: 'https://api.example.com',
    auth: {
        apikey: {
            key: 'my-api-key-123',
            location: 'header',
            name: 'X-API-Key'
        }
    }
});

// API Key in query parameter
const client2 = new MyServiceClient({
    transport: 'http',
    url: 'https://api.example.com',
    auth: {
        apikey: {
            key: 'my-api-key-123',
            location: 'query',
            name: 'apikey'
        }
    }
});
```

### Retry Configuration

```typescript
// Using retry presets
const client = new MyServiceClient({
    transport: 'http',
    url: 'https://api.example.com',
    retry: 'balanced'  // 'conservative', 'balanced', 'aggressive', or 'none'
});

// Custom retry configuration
const client2 = new MyServiceClient({
    transport: 'http',
    url: 'https://api.example.com',
    retry: {
        enabled: true,
        maxAttempts: 3,
        baseDelay: 1000,
        maxDelay: 30000,
        backoffMultiplier: 2,
        jitter: true,
        retryableStatusCodes: [429, 500, 502, 503, 504],
        retryableErrors: ['NETWORK_ERROR', 'TIMEOUT']
    }
});

// Per-request retry override
const response = await client.createUser(userData, {
    retry: 'aggressive',
    timeout: 10000
});
```

### Auth Error Handling

```typescript
const client = new MyServiceClient({
    transport: 'http',
    url: 'https://api.example.com',
    auth: { jwt: 'your-token' },
    authCallbacks: {
        onAuthError: async () => {
            // Handle 401 errors - refresh token, etc.
            console.log('Authentication failed, attempting to refresh...');
            return false; // Return true to retry with updated auth
        }
    },
    retryCallbacks: {
        onRetry: (attempt, error, delay) => {
            console.log(`Retry attempt ${attempt} after ${delay}ms`);
        }
    }
});
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

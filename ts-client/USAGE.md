# TypeScript AsyncAPI Client Generator - Usage Guide

This guide demonstrates how to use the TypeScript AsyncAPI client generator template to create fully-typed, production-ready clients that are compatible with rust-asyncapi servers.

## 🚀 Quick Start

### 1. Install AsyncAPI CLI

```bash
npm install -g @asyncapi/cli
```

### 2. Generate Your Client

```bash
# Generate from your AsyncAPI specification
asyncapi generate fromTemplate your-api.yaml ./template -o ./my-client

# Or use the published template (when available)
# asyncapi generate fromTemplate your-api.yaml @asyncapi/typescript-template -o ./my-client
```

### 3. Install and Build

```bash
cd my-client
npm install
npm run build
```

## 📋 Example AsyncAPI Specification

Here's an example AsyncAPI specification that demonstrates the features supported by this template:

```yaml
asyncapi: 3.0.0
info:
  title: Example API
  version: 1.0.0
  description: An example AsyncAPI for demonstrating the TypeScript client generator

servers:
  websocket:
    host: localhost:8080
    protocol: ws
    description: WebSocket server
  http:
    host: localhost:8080
    protocol: http
    description: HTTP server

channels:
  user/profile:
    address: user/profile
    messages:
      getUserProfile:
        $ref: '#/components/messages/GetUserProfile'
      userProfile:
        $ref: '#/components/messages/UserProfile'

  user/create:
    address: user/create
    messages:
      createUser:
        $ref: '#/components/messages/CreateUser'
      userCreated:
        $ref: '#/components/messages/UserCreated'

operations:
  getUserProfile:
    action: send
    channel:
      $ref: '#/channels/user~1profile'
    messages:
      - $ref: '#/channels/user~1profile/messages/getUserProfile'
    reply:
      channel:
        $ref: '#/channels/user~1profile'
      messages:
        - $ref: '#/channels/user~1profile/messages/userProfile'

  createUser:
    action: send
    channel:
      $ref: '#/channels/user~1create'
    messages:
      - $ref: '#/channels/user~1create/messages/createUser'
    reply:
      channel:
        $ref: '#/channels/user~1create'
      messages:
        - $ref: '#/channels/user~1create/messages/userCreated'

components:
  messages:
    GetUserProfile:
      payload:
        type: object
        properties:
          userId:
            type: string
            description: The user ID to fetch
        required:
          - userId

    UserProfile:
      payload:
        type: object
        properties:
          id:
            type: string
          name:
            type: string
          email:
            type: string
          createdAt:
            type: string
            format: date-time
        required:
          - id
          - name
          - email
          - createdAt

    CreateUser:
      payload:
        type: object
        properties:
          name:
            type: string
          email:
            type: string
        required:
          - name
          - email

    UserCreated:
      payload:
        type: object
        properties:
          id:
            type: string
          name:
            type: string
          email:
            type: string
          createdAt:
            type: string
            format: date-time
        required:
          - id
          - name
          - email
          - createdAt
```

## 🔧 Generated Client Usage

### WebSocket Client Example

```typescript
import { ExampleApiClient } from './my-client';

async function websocketExample() {
    // Create client with WebSocket transport
    const client = new ExampleApiClient({
        transport: 'websocket',
        websocket: {
            url: 'ws://localhost:8080',
            reconnect: true,
            reconnectInterval: 5000,
            maxReconnectAttempts: 5,
            timeout: 10000,
            auth: {
                token: 'your-jwt-token'
                // or apiKey: 'your-api-key'
                // or authorization: 'Bearer custom-token'
            }
        }
    });

    try {
        // Connect to the server
        await client.connect();
        console.log('✅ Connected to WebSocket server');

        // Send a request and get a typed response
        const userProfile = await client.getUserProfile({
            userId: '123'
        });

        // TypeScript provides full type safety
        console.log(`User: ${userProfile.name} (${userProfile.email})`);
        console.log(`Created: ${userProfile.createdAt}`);

        // Create a new user
        const newUser = await client.createUser({
            name: 'John Doe',
            email: 'john@example.com'
        });

        console.log(`Created user with ID: ${newUser.id}`);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        // Always disconnect when done
        await client.disconnect();
    }
}

websocketExample();
```

### HTTP Client Example

```typescript
import { ExampleApiClient } from './my-client';

async function httpExample() {
    // Create client with HTTP transport
    const client = new ExampleApiClient({
        transport: 'http',
        http: {
            baseUrl: 'http://localhost:8080',
            timeout: 30000,
            auth: {
                token: 'your-jwt-token'
            },
            retry: {
                attempts: 3,
                delay: 1000,
                backoff: 'exponential',
                maxDelay: 10000
            }
        }
    });

    try {
        // Connect (for HTTP this just validates config)
        await client.connect();
        console.log('✅ HTTP client ready');

        // Send requests with automatic retry
        const userProfile = await client.getUserProfile({
            userId: '456'
        });

        console.log(`User: ${userProfile.name} (${userProfile.email})`);

        // Create a new user
        const newUser = await client.createUser({
            name: 'Jane Smith',
            email: 'jane@example.com'
        });

        console.log(`Created user with ID: ${newUser.id}`);

    } catch (error) {
        console.error('Error:', error);
    }
}

httpExample();
```

### Event Handling

```typescript
import { ExampleApiClient } from './my-client';

async function eventHandlingExample() {
    const client = new ExampleApiClient({
        transport: 'websocket',
        websocket: {
            url: 'ws://localhost:8080',
            reconnect: true
        }
    });

    // Connection events
    client.on('connected', () => {
        console.log('🔌 Connected to server');
    });

    client.on('disconnected', (reason) => {
        console.log('🔌 Disconnected:', reason);
    });

    client.on('reconnecting', (attempt) => {
        console.log(`🔄 Reconnecting... attempt ${attempt}`);
    });

    client.on('error', (error) => {
        console.error('❌ Client error:', error);
    });

    // Raw message events (for debugging)
    client.on('message', (envelope) => {
        console.log('📨 Raw message:', envelope);
    });

    await client.connect();

    // Your application logic here...

    await client.disconnect();
}

eventHandlingExample();
```

### Error Handling

```typescript
import {
    ExampleApiClient,
    ConnectionError,
    MessageTimeoutError,
    HttpError,
    ConfigurationError
} from './my-client';

async function errorHandlingExample() {
    const client = new ExampleApiClient({
        transport: 'websocket',
        websocket: {
            url: 'ws://localhost:8080'
        }
    });

    try {
        await client.connect();

        const result = await client.getUserProfile({
            userId: 'invalid-id'
        });

    } catch (error) {
        if (error instanceof ConnectionError) {
            console.error('Connection failed:', error.message);
            // Handle connection issues

        } else if (error instanceof MessageTimeoutError) {
            console.error('Request timed out:', error.message);
            // Handle timeout

        } else if (error instanceof HttpError) {
            console.error(`HTTP error ${error.status}: ${error.message}`);
            // Handle HTTP errors

        } else if (error instanceof ConfigurationError) {
            console.error('Configuration error:', error.message);
            // Handle config issues

        } else {
            console.error('Unknown error:', error);
            // Handle unexpected errors
        }
    }
}

errorHandlingExample();
```

### Advanced Configuration

```typescript
import { ExampleApiClient } from './my-client';

// Advanced WebSocket configuration
const wsClient = new ExampleApiClient({
    transport: 'websocket',
    websocket: {
        url: 'wss://api.example.com',
        reconnect: true,
        reconnectInterval: 5000,
        maxReconnectAttempts: 10,
        timeout: 15000,
        auth: {
            headers: {
                'X-API-Key': 'your-api-key',
                'X-Client-Version': '1.0.0'
            }
        }
    }
});

// Advanced HTTP configuration
const httpClient = new ExampleApiClient({
    transport: 'http',
    http: {
        baseUrl: 'https://api.example.com',
        timeout: 60000,
        auth: {
            token: 'jwt-token'
        },
        retry: {
            attempts: 5,
            delay: 2000,
            backoff: 'exponential',
            maxDelay: 30000,
            retryCondition: (error) => {
                // Custom retry logic
                return error.status >= 500 || error.status === 429;
            }
        },
        headers: {
            'User-Agent': 'MyApp/1.0.0',
            'Accept': 'application/json'
        }
    }
});
```

## 🧪 Testing Your Client

```typescript
import { ExampleApiClient } from './my-client';

// Mock transport for testing
const mockTransport = {
    connect: jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    request: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
    getConnectionState: jest.fn().mockReturnValue({ status: 'connected' })
};

describe('ExampleApiClient', () => {
    let client: ExampleApiClient;

    beforeEach(() => {
        client = new ExampleApiClient({
            transport: 'websocket',
            websocket: { url: 'ws://test' }
        });

        // Inject mock transport
        (client as any).transport = mockTransport;
    });

    test('should get user profile', async () => {
        const mockResponse = {
            id: '123',
            name: 'John Doe',
            email: 'john@example.com',
            createdAt: '2023-01-01T00:00:00Z'
        };

        mockTransport.request.mockResolvedValue({
            payload: mockResponse
        });

        const result = await client.getUserProfile({ userId: '123' });

        expect(result).toEqual(mockResponse);
        expect(mockTransport.request).toHaveBeenCalledWith({
            operation: 'getUserProfile',
            payload: { userId: '123' }
        });
    });
});
```

## 🔄 Rust-AsyncAPI Compatibility

This template generates clients that are fully compatible with servers generated by the rust-asyncapi template:

### Message Envelope Structure

Both clients and servers use the same message envelope format:

```typescript
interface MessageEnvelope {
    correlationId: string;
    operation: string;
    payload: any;
    timestamp?: string;
    error?: {
        code: string;
        message: string;
    };
}
```

### Operation Naming

Operation names are derived consistently from the AsyncAPI specification:
- Channel addresses become method names (e.g., `user/profile` → `getUserProfile`)
- CamelCase conversion follows the same rules as rust-asyncapi
- Request/response patterns are automatically detected

### Type Compatibility

- TypeScript interfaces match Rust struct definitions
- Optional fields are handled consistently
- Enum types are converted to TypeScript union types
- Date/time fields use ISO 8601 strings

## 📚 API Reference

### Client Configuration

```typescript
interface ClientConfig {
    transport: 'websocket' | 'http';
    websocket?: WebSocketConfig;
    http?: HttpConfig;
}

interface WebSocketConfig {
    url: string;
    reconnect?: boolean;
    reconnectInterval?: number;
    maxReconnectAttempts?: number;
    timeout?: number;
    auth?: AuthConfig;
}

interface HttpConfig {
    baseUrl: string;
    timeout?: number;
    auth?: AuthConfig;
    retry?: RetryConfig;
    headers?: Record<string, string>;
}

interface AuthConfig {
    token?: string;
    apiKey?: string;
    authorization?: string;
    headers?: Record<string, string>;
}

interface RetryConfig {
    attempts: number;
    delay: number;
    backoff?: 'linear' | 'exponential';
    maxDelay?: number;
    retryCondition?: (error: any) => boolean;
}
```

### Client Methods

```typescript
class ExampleApiClient {
    constructor(config: ClientConfig);

    // Connection management
    connect(): Promise<void>;
    disconnect(): Promise<void>;
    getConnectionState(): ConnectionState;

    // Event handling
    on(event: string, handler: Function): void;
    off(event: string, handler: Function): void;

    // Generated operation methods (based on your AsyncAPI spec)
    getUserProfile(request: GetUserProfileRequest): Promise<UserProfile>;
    createUser(request: CreateUserRequest): Promise<UserCreated>;
    // ... other operations
}
```

## 🎯 Best Practices

1. **Always handle errors**: Use try-catch blocks and specific error types
2. **Clean up connections**: Always call `disconnect()` when done
3. **Use TypeScript**: Take advantage of the generated types for better development experience
4. **Configure retries**: Set appropriate retry policies for production use
5. **Monitor connections**: Listen to connection events for better observability
6. **Test thoroughly**: Use the provided testing patterns to ensure reliability

## 🔗 Related Resources

- [AsyncAPI Specification](https://www.asyncapi.com/docs/reference/specification/v3.0.0)
- [AsyncAPI Generator](https://github.com/asyncapi/generator)
- [Rust AsyncAPI Template](https://github.com/asyncapi/rust-template)
- [TypeScript Documentation](https://www.typescriptlang.org/docs/)

---

Generated with ❤️ by [AsyncAPI Generator](https://github.com/asyncapi/generator)

# TypeScript Client Auth and Retry Example

This example demonstrates how to use the authentication and retry features in the TypeScript AsyncAPI client.

## Features

- **Authentication Support**: JWT, Basic Auth, and API Key authentication
- **Retry Logic**: Exponential backoff with configurable presets
- **Type Safety**: Full TypeScript support with proper error handling
- **Clean API**: Same method signatures regardless of auth requirements

## Basic Usage

### Simple Client Setup

```typescript
import { UserServiceClient } from './generated-client';

// Basic client without auth or retry
const client = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com'
});

await client.connect();
const user = await client.userSignup({ email: 'user@example.com', password: 'secret' });
```

### Client with JWT Authentication

```typescript
const client = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  auth: {
    jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
  }
});

// Auth headers are automatically added to all requests
const user = await client.userSignup(signupData);
```

### Client with Basic Authentication

```typescript
const client = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  auth: {
    basic: {
      username: 'myuser',
      password: 'mypassword'
    }
  }
});
```

### Client with API Key Authentication

```typescript
// API Key in header
const client = new UserServiceClient({
  type: 'http',
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
const client2 = new UserServiceClient({
  type: 'http',
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

## Retry Configuration

### Using Retry Presets

```typescript
// Conservative retry (3 attempts, longer delays)
const client = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  retry: 'conservative'
});

// Balanced retry (5 attempts, moderate delays)
const client2 = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  retry: 'balanced'
});

// Aggressive retry (10 attempts, shorter delays)
const client3 = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  retry: 'aggressive'
});

// No retry
const client4 = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  retry: 'none'
});
```

### Custom Retry Configuration

```typescript
const client = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  retry: {
    enabled: true,
    maxAttempts: 3,
    baseDelay: 1000,        // 1 second initial delay
    maxDelay: 30000,        // 30 seconds max delay
    backoffMultiplier: 2,   // Double delay each attempt
    jitter: true,           // Add randomization
    retryableStatusCodes: [429, 500, 502, 503, 504],
    retryableErrors: ['NETWORK_ERROR', 'TIMEOUT', 'ECONNRESET']
  }
});
```

## Advanced Features

### Auth and Retry Combined

```typescript
const client = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  auth: {
    jwt: 'your-jwt-token'
  },
  retry: 'balanced',
  authCallbacks: {
    onAuthError: async () => {
      // Handle 401 errors - refresh token, etc.
      console.log('Authentication failed, attempting to refresh token...');
      // Return true to retry the request with updated auth
      return false;
    },
    onTokenRefresh: async (oldToken) => {
      // Refresh the JWT token
      const newToken = await refreshJwtToken(oldToken);
      return newToken;
    }
  },
  retryCallbacks: {
    onRetry: (attempt, error, delay) => {
      console.log(`Retry attempt ${attempt} after ${delay}ms due to:`, error.message);
    },
    onRetryExhausted: (operation, finalError) => {
      console.error(`All retry attempts exhausted for ${operation}:`, finalError);
    }
  }
});
```

### Per-Request Retry Override

```typescript
// Override retry config for specific requests
const user = await client.userSignup(signupData, {
  retry: 'aggressive',  // Use aggressive retry for this request only
  timeout: 10000        // 10 second timeout
});

// Disable retry for a specific request
const quickResult = await client.getUserProfile(userId, {
  retry: 'none'
});
```

### WebSocket with Auth

```typescript
const client = new UserServiceClient({
  type: 'websocket',
  url: 'wss://api.example.com/ws',
  auth: {
    jwt: 'your-jwt-token'
  }
});

await client.connect();

// Subscribe to events (auth is handled automatically)
const unsubscribe = client.userNotifications((notification) => {
  console.log('Received notification:', notification);
});

// Clean up
unsubscribe();
await client.disconnect();
```

## Error Handling

```typescript
import { AuthError, UnauthorizedError, RetryError, MaxRetriesExceededError } from './generated-client';

try {
  const user = await client.userSignup(signupData);
} catch (error) {
  if (error instanceof UnauthorizedError) {
    console.error('Authentication failed:', error.message);
    // Redirect to login page
  } else if (error instanceof MaxRetriesExceededError) {
    console.error('Request failed after all retry attempts:', error.lastError);
    // Show user-friendly error message
  } else if (error instanceof AuthError) {
    console.error('Auth configuration error:', error.message);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

## Login Flow and JWT Token Management

### Basic Login Flow

```typescript
// Step 1: Create client without auth for login
const client = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  retry: 'balanced'
});

await client.connect();

// Step 2: Login (no auth required)
const loginResponse = await client.userLogin({
  email: 'user@example.com',
  password: 'mypassword'
});

// Step 3: Update client with JWT token
client.updateAuth({
  jwt: loginResponse.token
});

// Step 4: Make authenticated requests
const userProfile = await client.getUserProfile({
  userId: loginResponse.user.id
});
```

### Advanced Login with Token Refresh

```typescript
const client = new UserServiceClient({
  type: 'http',
  url: 'https://api.example.com',
  retry: 'balanced',
  authCallbacks: {
    onAuthError: async () => {
      // Handle 401 errors by refreshing token
      if (refreshToken) {
        try {
          const refreshResponse = await refreshJwtToken(refreshToken);
          client.updateAuth({ jwt: refreshResponse.token });
          return true; // Retry the original request
        } catch (error) {
          // Redirect to login page
          return false;
        }
      }
      return false;
    }
  }
});

// Login and store tokens
const loginResponse = await client.userLogin(credentials);
client.updateAuth({ jwt: loginResponse.token });
refreshToken = loginResponse.refreshToken;
```

### WebSocket Login Flow

```typescript
// For WebSocket, you may need to reconnect after auth update
const client = new UserServiceClient({
  type: 'websocket',
  url: 'wss://api.example.com/ws'
});

await client.connect();

// Login
const loginResponse = await client.userLogin(credentials);

// Disconnect and reconnect with auth
await client.disconnect();
client.updateAuth({ jwt: loginResponse.token });
await client.connect();

// Now subscribe to authenticated events
const unsubscribe = client.userNotifications((notification) => {
  console.log('Notification:', notification);
});
```

### React Hook Example

```typescript
function useAuthenticatedClient() {
  const [client, setClient] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const login = useCallback(async (email, password) => {
    const loginResponse = await client.userLogin({ email, password });

    client.updateAuth({ jwt: loginResponse.token });
    setIsAuthenticated(true);

    return loginResponse;
  }, [client]);

  const logout = useCallback(async () => {
    client.updateAuth({});
    setIsAuthenticated(false);
  }, [client]);

  return { client, isAuthenticated, login, logout };
}
```

## Best Practices

1. **Configure Once**: Set up auth and retry at the client level rather than per-request
2. **Use Presets**: Start with retry presets (`balanced` is recommended) before customizing
3. **Handle Auth Errors**: Implement `onAuthError` callback for token refresh scenarios
4. **Monitor Retries**: Use retry callbacks to log and monitor retry behavior
5. **Graceful Degradation**: Handle `MaxRetriesExceededError` with user-friendly messages
6. **Security**: Never log auth credentials or tokens in production
7. **Login Flow**: Use `updateAuth()` to set JWT tokens after login
8. **WebSocket Auth**: Reconnect WebSocket connections after updating auth

## Environment-Specific Configuration

```typescript
// Development
const devClient = new UserServiceClient({
  type: 'http',
  url: 'http://localhost:3000',
  retry: 'aggressive',  // Fast feedback during development
  auth: { jwt: 'dev-token' }
});

// Production
const prodClient = new UserServiceClient({
  type: 'https',
  url: 'https://api.production.com',
  retry: 'balanced',    // Balanced approach for production
  auth: { jwt: process.env.JWT_TOKEN },
  retryCallbacks: {
    onRetryExhausted: (operation, error) => {
      // Log to monitoring service
      logger.error('Request failed after retries', { operation, error });
    }
  }
});

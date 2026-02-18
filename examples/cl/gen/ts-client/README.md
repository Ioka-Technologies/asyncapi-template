# Channel Lock Device Management API

AsyncAPI specification for managing a collection of Channel Lock devices.
This API allows provisioning, configuration, and deletion of devices,
as well as receiving threat notifications and communication link updates.


## Overview

This TypeScript client provides type-safe access to your AsyncAPI service with automatic transport selection and built-in error handling. Generated from your AsyncAPI specification, it offers seamless integration with both WebSocket and HTTP protocols.

## Technical Requirements

- Node.js 16+
- TypeScript 4.5+

## Supported Transports

- WebSocket (with auto-reconnection)
- HTTP (with retry logic)

## Installation

### For Node.js Projects

```bash
npm install channel-lock-device-management-api-client ws
```

### For Browser Projects

```bash
npm install channel-lock-device-management-api-client
```

## Quick Start

### WebSocket Client

```typescript
import { ChannelLockDeviceManagementAPIClient } from 'channel-lock-device-management-api-client';

const client = new ChannelLockDeviceManagementAPIClient({
    type: 'websocket',
    url: 'ws://localhost:8080',
    headers: {
        'Authorization': 'Bearer your-token'
    }
});

// Connect and send messages
await client.connect();
const response = await client.sendMessage({
    text: 'Hello, World!',
    userId: '123'
});
console.log('Response:', response);
```

### HTTP Client

```typescript
import { ChannelLockDeviceManagementAPIClient } from 'channel-lock-device-management-api-client';

const client = new ChannelLockDeviceManagementAPIClient({
    type: 'http',
    url: 'http://localhost:8080/api',
    headers: {
        'Authorization': 'Bearer your-token'
    }
});

const response = await client.sendMessage({
    text: 'Hello, World!',
    userId: '123'
});
```

## Configuration Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `type` | `'websocket' \| 'http'` | Transport protocol | Required |
| `url` | `string` | Server URL | Required |
| `headers` | `Record<string, string>` | Request headers | `{}` |
| `timeout` | `number` | Request timeout (ms) | `30000` |

## Error Handling

The client provides specific error types for different scenarios:

```typescript
import { TransportError, ConnectionError, TimeoutError } from 'channel-lock-device-management-api-client';

try {
    await client.sendMessage(payload);
} catch (error) {
    if (error instanceof ConnectionError) {
        console.error('Connection failed:', error.message);
    } else if (error instanceof TimeoutError) {
        console.error('Request timed out');
    } else if (error instanceof TransportError) {
        console.error('Transport error:', error.message);
    }
}
```

## Environment Compatibility

- **Browser**: Uses native WebSocket API (no additional dependencies)
- **Node.js**: Requires `ws` package for WebSocket support

## Development

```bash
# Build the project
npm run build

# Watch for changes
npm run dev

# Run tests
npm test

# Lint code
npm run lint
```

## Generated from AsyncAPI

- **AsyncAPI Version**: 3.0.0
- **Generated**: 2026-02-04T20:32:08.633Z
- **Title**: Channel Lock Device Management API
- **Version**: 0.0.1

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run the test suite: `npm test`
5. Submit a pull request

## License

Apache-2.0

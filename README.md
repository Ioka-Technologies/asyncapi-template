# AsyncAPI Templates Monorepo

**Build production-ready async messaging systems with confidence**

This monorepo represents a paradigm shift in AsyncAPI development: instead of generating throwaway code, we generate **maintainable, production-ready libraries** that evolve with your business needs. Our templates solve the fundamental problem of code generation - how to provide powerful infrastructure while preserving your business logic through specification changes.

## The Vision: Sustainable AsyncAPI Development

Traditional code generators create a painful choice: either accept generated code that gets overwritten (losing your work), or avoid regeneration (missing spec improvements). We've eliminated this dilemma through **architectural innovation**.

### Core Philosophy

**🏗️ Library-First Architecture**: Generate reusable libraries, not applications. Your business logic lives in separate, protected implementations that are never touched by regeneration.

**🎯 Trait-Based Separation**: Clean interfaces separate infrastructure concerns (protocols, serialization, error handling) from business logic (your domain code). Change protocols without touching business logic.

**🔄 Regeneration Safety**: Update your AsyncAPI spec and regenerate fearlessly. Your business implementations remain untouched while infrastructure code evolves.

**🌐 Cross-Language Compatibility**: Rust servers and TypeScript clients share the same message envelope format and architectural patterns, enabling seamless full-stack development.

### Templates Included

- **🦀 Rust Server** (`rust-server/`) - **The gold standard for async messaging servers**. Generates trait-based libraries with automatic protocol detection, enterprise-grade error handling, and zero-downtime regeneration. Perfect for high-performance backends, IoT gateways, and microservices.

- **📱 TypeScript Client** (`ts-client/`) - **Type-safe clients that just work**. Generates fully-typed TypeScript clients with automatic transport selection, reconnection logic, and seamless integration with Rust servers. Ideal for web apps, Node.js services, and mobile backends.

## Why Choose These Templates?

### The Traditional AsyncAPI Problem
```
AsyncAPI Spec → Generate Code → Customize → Spec Changes → 😱 Lose Customizations
```

### Our Solution
```
AsyncAPI Spec → Generate Library → Implement Traits → Spec Changes → ✅ Regenerate Safely
```

## Quick Start: From Zero to Production

### The 5-Minute AsyncAPI Experience

**Goal**: Generate a production-ready chat service that handles 1000+ concurrent connections.

#### 1. Prerequisites (30 seconds)
```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Install Rust (for server)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Node.js 16+ (for client)
```

#### 2. Clone and Setup (1 minute)
```bash
git clone https://github.com/ioka-technologies/asyncapi-template.git
cd asyncapi-template
npm install
```

#### 3. Generate Your First Service (2 minutes)
```bash
# Generate a WebSocket chat server
asyncapi generate fromTemplate examples/websocket-secure/asyncapi.yaml ./rust-server -o my-chat-server

# Generate a TypeScript client
asyncapi generate fromTemplate examples/websocket-secure/asyncapi.yaml ./ts-client -o my-chat-client
```

#### 4. Implement Business Logic (1 minute)
```rust
// In my-chat-server/src/services/chat_service.rs
impl ChatService for MyChatService {
    async fn handle_send_message(&self, msg: ChatMessage, ctx: &MessageContext) -> Result<MessageSent> {
        // Your business logic here - infrastructure is handled automatically
        println!("User {} says: {}", msg.user_id, msg.content);
        Ok(MessageSent { id: uuid::new_v4(), timestamp: Utc::now() })
    }
}
```

#### 5. Run Production-Ready Service (30 seconds)
```bash
cd my-chat-server && cargo run  # Handles 1000+ concurrent WebSocket connections
cd my-chat-client && npm start  # Type-safe client with auto-reconnection
```

**Result**: You now have a production-ready chat service with WebSocket support, automatic reconnection, type safety, error handling, and monitoring - all from a single AsyncAPI specification.

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

## Template Deep Dive

### 🦀 Rust Server Template: The Architecture That Scales

**The Problem We Solved**: Traditional async servers tightly couple business logic with infrastructure, making them brittle and hard to test. Protocol changes require rewriting business logic.

**Our Innovation**: **Trait-based library architecture** that completely separates concerns:

```rust
// Your business logic (never changes when regenerating)
impl UserService for MyUserService {
    async fn handle_signup(&self, request: SignupRequest) -> Result<User> {
        // Pure business logic - no protocol concerns
        self.create_user(request.email, request.name).await
    }
}

// Generated infrastructure (evolves with your AsyncAPI spec)
// Handles: WebSocket connections, HTTP routing, MQTT topics, Kafka streams
// Authentication, retries, circuit breakers, monitoring - all automatic
```

**Why This Matters**:
- **Protocol Agnostic**: Same business logic works over WebSocket, HTTP, MQTT, or Kafka
- **Zero-Downtime Evolution**: Update AsyncAPI spec, regenerate, deploy - business logic untouched
- **Enterprise Ready**: Built-in authentication, monitoring, error handling, and recovery
- **Performance**: Zero-copy message routing, async-first design, minimal allocations

#### Usage Patterns

```bash
# Basic service generation
asyncapi generate fromTemplate your-api.yaml ./rust-server -o my-service

# Enterprise service with authentication
asyncapi generate fromTemplate your-api.yaml ./rust-server -o my-service \
  -p enableAuth=true \
  -p packageName=my-enterprise-service
```

### 📱 TypeScript Client Template: Type Safety That Just Works

**The Problem We Solved**: JavaScript/TypeScript clients for async APIs are typically hand-written, error-prone, and fall out of sync with server changes. Type safety is lost across the network boundary.

**Our Innovation**: **Automatic type-safe client generation** with intelligent transport selection:

```typescript
// Generated client with full type safety
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

// Response is fully typed
console.log(user.id);        // ✅ TypeScript provides autocomplete
console.log(user.createdAt); // ✅ TypeScript knows this is a Date
```

**Why This Matters**:
- **Zero Configuration**: Works out of the box with sensible defaults
- **Transport Agnostic**: Same code works over WebSocket or HTTP
- **Automatic Reconnection**: Built-in resilience for production environments
- **Perfect Rust Compatibility**: Shares message envelope format with Rust servers

#### The Full-Stack Development Experience

**Before (Traditional Approach)**:
```
1. Write AsyncAPI spec
2. Generate Rust server
3. Manually write TypeScript client
4. Keep client in sync manually
5. Debug type mismatches at runtime
6. Repeat for every spec change
```

**After (Our Approach)**:
```
1. Write AsyncAPI spec
2. Generate Rust server + TypeScript client
3. Both are automatically in sync
4. Full type safety across the network
5. Update spec → regenerate → deploy
```

#### Production Features

**Enterprise Authentication**:
```typescript
const client = new ApiClient({
    auth: {
        jwt: 'eyJ...',           // JWT tokens
        apiKey: 'key_123',       // API keys
        custom: { 'X-Auth': '...' } // Custom headers
    }
});
```

**Intelligent Error Handling**:
```typescript
try {
    await client.sendMessage(data);
} catch (error) {
    if (error instanceof ConnectionError) {
        // Handle connection issues
    } else if (error instanceof ValidationError) {
        // Handle validation errors
    }
}
```

**Real-Time Features**:
```typescript
// Subscribe to real-time updates
client.onMessageReceived((message) => {
    updateUI(message);
});

// Automatic reconnection with exponential backoff
client.on('reconnected', () => {
    console.log('Back online!');
});
```

## Complete Workflow: Building a Production Chat System

**Scenario**: Build a real-time chat system that handles 10,000+ concurrent users, with web and mobile clients, message persistence, and real-time notifications.

### 1. Design Your AsyncAPI Specification

**Strategic Thinking**: Start with the business requirements, not the technology.

```yaml
# chat-system.yaml - Designed for scale and evolution
asyncapi: 3.0.0
info:
  title: Enterprise Chat System
  version: 1.0.0
  description: |
    Scalable real-time chat system supporting:
    - Multi-room conversations
    - User presence tracking
    - Message persistence
    - Push notifications
    - File sharing
    - Moderation tools

servers:
  websocket:
    host: chat.company.com
    protocol: wss  # Secure WebSocket for production
    description: Real-time messaging for web/mobile clients

  kafka:
    host: kafka.company.com:9092
    protocol: kafka
    description: Message persistence and analytics pipeline

channels:
  chat/rooms/{roomId}/messages:
    # Real-time messaging with automatic scaling
    parameters:
      roomId:
        description: Chat room identifier
        schema:
          type: string
          pattern: '^[a-zA-Z0-9_-]+$'

  user/presence:
    # User online/offline status

  notifications/push:
    # Mobile push notifications via Kafka
```

**Why This Design**:
- **WebSocket**: Real-time user experience
- **Kafka**: Reliable message persistence and analytics
- **Room-based**: Scales to millions of users across thousands of rooms
- **Presence**: Rich user experience with online indicators

### 2. Generate Production Infrastructure

```bash
# Generate enterprise-grade Rust server
asyncapi generate fromTemplate chat-system.yaml ./rust-server -o chat-server \
  -p enableAuth=true \
  -p packageName=enterprise-chat-server \
  -p packageVersion=1.0.0

# Generate TypeScript clients for web and mobile
asyncapi generate fromTemplate chat-system.yaml ./ts-client -o chat-web-client \
  -p clientName=ChatWebClient \
  -p packageName=@company/chat-web-client

asyncapi generate fromTemplate chat-system.yaml ./ts-client -o chat-mobile-client \
  -p clientName=ChatMobileClient \
  -p packageName=@company/chat-mobile-client
```

### 3. Implement Business Logic (The Part That Matters)

```rust
// chat-server/src/services/chat_service.rs
// This is YOUR code - never touched by regeneration
impl ChatService for EnterpriseChatService {
    async fn handle_send_message(&self, msg: ChatMessage, ctx: &MessageContext) -> Result<MessageSent> {
        // Business logic: validation, persistence, notifications

        // 1. Validate user permissions
        self.auth.check_room_access(&ctx.user_id, &msg.room_id).await?;

        // 2. Content moderation
        if self.moderation.is_inappropriate(&msg.content).await? {
            return Err(ChatError::ContentViolation);
        }

        // 3. Persist to database
        let saved_msg = self.db.save_message(msg).await?;

        // 4. Send push notifications (handled by infrastructure)
        self.notifications.notify_room_members(&msg.room_id, &saved_msg).await?;

        // 5. Analytics (automatic via Kafka)

        Ok(MessageSent {
            id: saved_msg.id,
            timestamp: saved_msg.created_at,
            room_id: msg.room_id,
        })
    }
}
```

### 4. Deploy and Scale

```bash
# Production deployment
cd chat-server
docker build -t company/chat-server:1.0.0 .
kubectl apply -f k8s/

# The server automatically:
# ✅ Handles 10,000+ concurrent WebSocket connections
# ✅ Persists messages to Kafka for analytics
# ✅ Manages user authentication and authorization
# ✅ Provides health checks and metrics
# ✅ Gracefully handles failures and reconnections
```

### 5. Frontend Integration

```typescript
// React web app
import { ChatWebClient } from '@company/chat-web-client';

function ChatApp() {
    const [client] = useState(() => new ChatWebClient({
        transport: 'websocket',
        websocket: {
            url: 'wss://chat.company.com',
            auth: { jwt: getAuthToken() },
            reconnect: true
        }
    }));

    useEffect(() => {
        client.connect();

        // Type-safe event handling
        client.onMessageReceived((message) => {
            setMessages(prev => [...prev, message]);
        });

        client.onUserPresenceChanged((presence) => {
            updateUserStatus(presence.userId, presence.status);
        });

        return () => client.disconnect();
    }, []);

    const sendMessage = async (content: string) => {
        // Fully type-safe with IntelliSense
        await client.sendMessage({
            roomId: currentRoom,
            content,
            timestamp: new Date().toISOString()
        });
    };
}
```

### 6. Evolution and Scaling

**Month 1**: Basic chat working
**Month 3**: Add file sharing - update AsyncAPI spec, regenerate, deploy
**Month 6**: Add video calls - same process
**Month 12**: Handle 100,000+ users - infrastructure scales automatically

**The Key**: Your business logic never changes. Only the AsyncAPI spec evolves.

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

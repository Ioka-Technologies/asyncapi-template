/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ReadmeMd({ asyncapi }) {
    const info = asyncapi.info();
    const title = info.title();

    // Detect protocols from servers
    const servers = asyncapi.servers();
    const protocols = new Set();
    const serverConfigs = [];

    if (servers) {
        Object.entries(servers).forEach(([name, server]) => {
            const protocol = server.protocol && server.protocol();
            if (protocol) {
                protocols.add(protocol.toLowerCase());
                serverConfigs.push({
                    name,
                    protocol: protocol.toLowerCase(),
                    host: server.host && server.host(),
                    description: server.description && server.description()
                });
            }
        });
    }

    // Extract channels and their operations
    const channels = asyncapi.channels();
    const channelData = [];
    const messageTypes = new Set();

    if (channels) {
        Object.entries(channels).forEach(([channelName, channel]) => {
            // Clean up channel name - remove numeric prefixes and unwanted suffixes
            let cleanChannelName = channelName;

            // Remove numeric prefixes like "0:", "1:", "2:"
            cleanChannelName = cleanChannelName.replace(/^\d+:/, '');

            // Skip unwanted channels
            if (cleanChannelName.includes('collections') || cleanChannelName.includes('_meta')) {
                return;
            }

            const operations = channel.operations && channel.operations();
            const channelOps = [];

            if (operations) {
                Object.entries(operations).forEach(([opName, operation]) => {
                    const action = operation.action && operation.action();
                    const messages = operation.messages && operation.messages();

                    if (messages) {
                        messages.forEach(message => {
                            const messageName = message.name && message.name();
                            if (messageName) {
                                messageTypes.add(messageName);
                            }
                        });
                    }

                    channelOps.push({
                        name: opName,
                        action,
                        messages: messages || []
                    });
                });
            }

            channelData.push({
                name: cleanChannelName,
                address: channel.address && channel.address(),
                description: channel.description && channel.description(),
                operations: channelOps
            });
        });
    }

    const packageName = title.toLowerCase().replace(/[^a-z0-9]/g, '-');
    const serviceName = title.replace(/[^a-zA-Z0-9]/g, '');

    return (
        <File name="README.md">
            {`# ${title}

**Your business logic, our infrastructure - the sustainable approach to AsyncAPI development**

This isn't just another generated server - it's a **paradigm shift** in how we think about async messaging architecture. Instead of generating throwaway code that locks you into specific patterns, we generate a **sustainable library architecture** that evolves with your business needs while protecting your domain logic.

## The Architectural Philosophy

**The Core Insight**: Most async messaging systems fail because they tightly couple business logic with infrastructure concerns. When protocols change, message formats evolve, or performance requirements shift, everything breaks.

**Our Innovation**: **Complete Architectural Separation**

This project implements a **trait-based library architecture** designed for evolutionary sustainability:

### 🏗️ **Library-First Design: Your Architecture, Your Rules**
- **Strategic Flexibility**: Generate reusable libraries, not rigid applications - integrate however your architecture demands
- **Zero Vendor Lock-in**: You own the main function, the deployment strategy, and the integration patterns
- **Composable by Design**: Mix with existing Rust ecosystems, frameworks, and architectural patterns without conflicts
- **Future-Proof Integration**: As your system architecture evolves, this library adapts rather than constrains

### 🎯 **Trait-Based Separation: The Protocol Independence Revolution**
- **Business Logic Sanctuary**: Your domain logic lives in a protected space, completely isolated from transport chaos
- **Protocol Agnostic by Design**: Write once, run over WebSocket, HTTP, MQTT, Kafka - or protocols that don't exist yet
- **Testing Nirvana**: Mock the trait interface, test business logic in complete isolation from infrastructure complexity
- **Maintenance Freedom**: Protocol changes, performance optimizations, and infrastructure evolution never touch your business logic

### 🔄 **Regeneration Safety: Evolution Without Fear**
- **Protected Domain Code**: Your business implementations are sacred - regeneration never touches them
- **Infrastructure Evolution**: Only the plumbing (handlers, models, transport) regenerates with your AsyncAPI spec
- **Continuous Improvement**: Benefit from template improvements, security updates, and performance enhancements automatically
- **Specification-Driven Development**: Your AsyncAPI spec becomes the single source of truth for infrastructure evolution

### 🚀 **Performance-Oriented Design: Built for Scale**
- **Zero-Copy Architecture**: Messages flow through the system without unnecessary allocations or copying
- **Async-Native**: Built on Tokio's proven async runtime for maximum concurrency and minimal resource usage
- **Compile-Time Optimization**: Type safety eliminates runtime overhead - performance is guaranteed, not hoped for
- **Memory Conscious**: Smart ownership patterns and minimal allocations ensure predictable resource usage at scale

## Why This Architecture Wins

**The Traditional Problem**:
\`\`\`rust
// Tightly coupled - protocol changes break everything
async fn handle_websocket_message(ws: WebSocket, msg: String) -> Result<()> {
    let data: UserSignup = serde_json::from_str(&msg)?;  // Parsing
    let user = create_user(data).await?;                 // Business logic
    ws.send(serde_json::to_string(&user)?).await?;      // Protocol
    // Change from WebSocket to HTTP? Rewrite everything!
}
\`\`\`

**Our Solution**:
\`\`\`rust
// Completely decoupled - protocols are interchangeable
#[async_trait]
impl UserSignupService for MyUserService {
    async fn handle_signup(&self, request: SignupRequest, ctx: &MessageContext) -> Result<User> {
        // Pure business logic - no infrastructure concerns
        // This code survives ANY protocol changes
        self.create_user(request.email, request.name).await
    }
}
// Same code works over WebSocket, HTTP, MQTT, Kafka, or any future protocol
\`\`\`

## Production-Ready Features

**Enterprise Infrastructure** (Generated automatically):
- **Multi-Protocol Support**: ${Array.from(protocols).join(', ') || 'WebSocket, HTTP, MQTT, Kafka, AMQP'}
- **Async/Await Native**: Built on Tokio for maximum concurrency and performance
- **Type-Safe Message Handling**: Strongly typed requests and responses eliminate runtime errors
- **Request/Response Patterns**: Automatic response routing with correlation ID tracking
- **Error Recovery**: Circuit breakers, retries, dead letter queues, graceful degradation
- **Observability**: Structured logging, metrics, health checks, distributed tracing
- **Security**: Input validation, authentication integration, secure error handling
- **Configuration Management**: Environment-based configuration with sensible defaults

**Developer Experience** (What you actually work with):
- **Clean Trait Interfaces**: Simple, testable contracts for your business logic
- **Rich Context**: Access to correlation IDs, user claims, request metadata
- **Type Safety**: Compile-time guarantees for message structure and flow
- **Hot Reloading**: Update AsyncAPI spec, regenerate, deploy - business logic untouched

## Integration Strategies: Your Architecture, Your Choice

**The Strategic Advantage**: This library adapts to your architectural patterns, not the other way around.

### Strategy 1: Microservice Integration
Perfect for service-oriented architectures where this service has a specific domain responsibility.

### Strategy 2: Library Integration
Ideal for monolithic applications that need async messaging capabilities without architectural disruption.

### Strategy 3: Hybrid Integration
Best for evolving architectures that need flexibility to change deployment patterns over time.

### Add as Dependency

Add this library to your project's \`Cargo.toml\`:

\`\`\`toml
[dependencies]
${packageName} = { path = "../path/to/this/library" }
tokio = { version = "1.0", features = ["full"] }
tracing = "0.1"
tracing-subscriber = "0.3"
async-trait = "0.1"
\`\`\`

### Implement Your Business Logic

**The Core Pattern**: Implement the generated traits with your domain logic. This is where your business value lives.

\`\`\`rust
use ${packageName.replace(/-/g, '_')}::*;
use async_trait::async_trait;

// Your business logic implementation - never touched by regeneration
pub struct ${serviceName}Service {
    database: Arc<Database>,
    email_service: Arc<EmailService>,
    analytics: Arc<Analytics>,
}

#[async_trait]
impl UserSignupService for ${serviceName}Service {
    async fn handle_signup(&self, request: SignupRequest, ctx: &MessageContext) -> AsyncApiResult<WelcomeResponse> {
        // Pure business logic - no infrastructure concerns
        // This code survives ANY AsyncAPI spec changes

        // 1. Validate business rules
        if !self.is_valid_email(&request.email) {
            return Err(AsyncApiError::validation("Invalid email format"));
        }

        // 2. Execute business logic
        let user = self.database.create_user(&request).await?;
        self.email_service.send_welcome(&user.email).await?;
        self.analytics.track_signup(&user).await?;

        // 3. Return typed response (infrastructure handles routing)
        Ok(WelcomeResponse {
            user_id: user.id,
            message: format!("Welcome {}!", user.name),
            onboarding_url: self.generate_onboarding_url(&user.id),
        })
    }
}

// See USAGE.md for comprehensive examples and patterns
\`\`\`

**Why This Pattern Works**:
- **Testable**: Mock the database, email service, and analytics - test business logic in isolation
- **Maintainable**: Business rules are clearly expressed without infrastructure noise
- **Evolvable**: Add new protocols, change message formats, optimize performance - business logic unchanged
- **Debuggable**: Clear separation makes issues easy to isolate and fix

### Create Your Application

Create your own \`main.rs\` that uses this library:

\`\`\`rust
use ${packageName.replace(/-/g, '_')}::{Config, Server, RecoveryManager};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt().init();

    // Load configuration
    let config = Config::from_env()?;

    // Create your service implementations
    // let my_service = Arc::new(MyServiceImpl::new());

    // Create handlers with your implementations
    // let handler = SomeHandler::new(my_service, recovery_manager);

    // Create and start server
    let server = Server::builder()
        .with_config(config)
        // .with_handlers(handler)
        .build()
        .await?;

    server.start().await?;
    Ok(())
}
\`\`\`

### Build and Test

\`\`\`bash
# Build the library
cargo build --lib

# Run library tests
cargo test --lib

# Build your application (in your project)
cargo build

# Run your application
cargo run
\`\`\`

## Generated Components

### Servers
${serverConfigs.map(server => `- **${server.name}**: ${server.protocol}://${server.host} - ${server.description || 'No description'}`).join('\n')}

### Channels
${channelData.map(channel => `- **${channel.name}**: ${channel.address || channel.name} - ${channel.description || 'No description'}`).join('\n')}

### Message Types
${Array.from(messageTypes).map(type => `- ${type}`).join('\n')}

## Quick Reference

For detailed usage instructions, see the generated \`USAGE.md\` file.

\`\`\`bash
# Build the library
cargo build --lib

# Run library tests
cargo test --lib

# Generate documentation
cargo doc --open
\`\`\`

## Configuration

The server can be configured through environment variables:

- \`LOG_LEVEL\`: Set logging level (trace, debug, info, warn, error)
- \`SERVER_HOST\`: Server host (default: 0.0.0.0)
- \`SERVER_PORT\`: Server port (default: 8080)

## Generated from AsyncAPI

This server was generated from an AsyncAPI specification. The original spec defines:

- **Title**: ${title}
- **Version**: ${info.version() || '1.0.0'}
- **Description**: ${info.description() || 'No description provided'}
- **Protocols**: ${Array.from(protocols).join(', ') || 'generic'}
`}
        </File>
    );
}

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
                name: channelName,
                address: channel.address && channel.address(),
                description: channel.description && channel.description(),
                operations: channelOps
            });
        });
    }

    return (
        <File name="README.md">
            {`# ${title}

This is a Rust AsyncAPI server generated from the AsyncAPI specification.

## Architecture

This project implements a **trait-based library architecture** designed for maximum flexibility and maintainability:

### 🏗️ **Library-First Design**
- **Reusable Components**: All functionality is packaged as a library that can be integrated into any Rust project
- **Zero Lock-in**: Your application owns the main function and can integrate this library however you need
- **Composable**: Mix and match with other libraries and frameworks without conflicts

### 🎯 **Trait-Based Separation of Concerns**
- **Business Logic Isolation**: Your domain logic is completely separated from transport and infrastructure concerns
- **Protocol Agnostic**: The same business logic works seamlessly across WebSocket, HTTP, MQTT, Kafka, and other protocols
- **Testability**: Clean interfaces make unit testing straightforward without mocking complex infrastructure
- **Maintainability**: Changes to transport layers don't affect your business logic and vice versa

### 🔄 **Regeneration-Safe Architecture**
- **Protected Implementation**: Your business logic implementations are never overwritten when regenerating from updated AsyncAPI specs
- **Generated Infrastructure**: Only the infrastructure code (handlers, models, transport) is regenerated
- **Evolutionary Design**: Your services can evolve with your AsyncAPI specification without breaking existing functionality

### 🚀 **Performance-Oriented Design**
- **Zero-Copy Message Routing**: Messages are routed without unnecessary copying or allocation
- **Async-First**: Built on Tokio for maximum concurrency and performance
- **Type-Safe**: Compile-time guarantees eliminate runtime overhead of type checking
- **Memory Efficient**: Minimal allocations and smart use of Rust's ownership system

## Features

- Async/await support with Tokio
- Structured logging with tracing
- Protocol support: ${Array.from(protocols).join(', ') || 'generic'}
- Type-safe message handling with strongly typed requests and responses
- Generated message models
- Channel-based operation handlers
- Request/response pattern support with automatic response sending
- Transport layer integration for response routing
- Configuration management
- Error handling and middleware
- Library + Binary architecture for maximum flexibility
- Correlation ID tracking for request/response flows

## Usage as a Library

This generated code is designed to be used as a library in your own Rust projects.

### Add as Dependency

Add this library to your project's \`Cargo.toml\`:

\`\`\`toml
[dependencies]
${title.toLowerCase().replace(/[^a-z0-9]/g, '-')} = { path = "../path/to/this/library" }
tokio = { version = "1.0", features = ["full"] }
tracing = "0.1"
tracing-subscriber = "0.3"
async-trait = "0.1"
\`\`\`

### Implement Service Traits

Implement the generated service traits with your business logic:

\`\`\`rust
use ${title.toLowerCase().replace(/[^a-z0-9]/g, '_')}::{/* Generated traits */, MessageContext, AsyncApiResult};
use async_trait::async_trait;

// Implement the generated service traits
// See USAGE.md for detailed examples
\`\`\`

### Create Your Application

Create your own \`main.rs\` that uses this library:

\`\`\`rust
use ${title.toLowerCase().replace(/[^a-z0-9]/g, '_')}::{Config, Server, RecoveryManager};
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

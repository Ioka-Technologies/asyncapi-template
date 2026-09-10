/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ReadmeMd({ asyncapi }) {
    const info = asyncapi.info();
    const title = info.title();
    const version = info.version() || '1.0.0';
    const description = info.description() || 'No description provided';

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

Generate a production-ready Rust server from your AsyncAPI specification with support for multiple messaging protocols.

## Overview

This template generates a Rust library that provides a clean separation between generated infrastructure code and your business logic. The generated code handles protocol-specific concerns while you focus on implementing your domain logic through simple trait interfaces.

**Generated from AsyncAPI:**
- **Title**: ${title}
- **Version**: ${version}
- **Description**: ${description}
- **Protocols**: ${Array.from(protocols).join(', ') || 'WebSocket, HTTP, MQTT, Kafka, AMQP'}

## Technical Requirements

- Rust 1.70+
- AsyncAPI CLI 1.0+

## Supported Protocols

${Array.from(protocols).map(protocol => `- ${protocol.toUpperCase()}`).join('\n') || '- WebSocket\n- HTTP/HTTPS\n- MQTT/MQTTS\n- Kafka\n- AMQP/AMQPS'}

## Quick Start

### Generate Server

\`\`\`bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Generate your Rust server
asyncapi generate fromTemplate asyncapi.yaml @ioka-technologies/asyncapi-rust-server-template -o my-server

cd my-server
cargo build
\`\`\`

### Implement Business Logic

The generated code provides traits that you implement with your business logic:

\`\`\`rust
use async_trait::async_trait;
use ${packageName.replace(/-/g, '_')}::*;

pub struct ${serviceName}Service;

#[async_trait]
impl MessageHandler for ${serviceName}Service {
    async fn handle_message(&self, message: IncomingMessage, ctx: &MessageContext) -> Result<()> {
        // Your business logic here
        match message {
${Array.from(messageTypes).slice(0, 3).map(msgType => `            IncomingMessage::${msgType}(data) => {
                // Handle ${msgType} message
                println!("Received ${msgType}: {:?}", data);
                Ok(())
            }`).join('\n')}
            _ => Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let service = Arc::new(${serviceName}Service);

    Server::builder()
        .with_message_handler(service)
        .build()
        .start()
        .await
}
\`\`\`

## Generated Project Structure

\`\`\`
${packageName}/
├── Cargo.toml              # Rust project configuration
├── README.md               # This file
├── src/
│   ├── lib.rs             # Library exports
│   ├── models.rs          # Message type definitions
│   ├── handlers.rs        # Generated trait definitions
│   ├── server/            # Server implementation
│   ├── transport/         # Protocol implementations
│   └── auth/              # Authentication support
└── examples/              # Usage examples
\`\`\`

## Configuration

Configure the server through environment variables:

- \`LOG_LEVEL\`: Logging level (trace, debug, info, warn, error) - default: \`info\`
- \`SERVER_HOST\`: Server host - default: \`0.0.0.0\`
- \`SERVER_PORT\`: Server port - default: \`8080\`

${serverConfigs.length > 0 ? `
## Servers

${serverConfigs.map(server => `- **${server.name}**: ${server.protocol}://${server.host} - ${server.description || 'No description'}`).join('\n')}
` : ''}

${channelData.length > 0 ? `
## Channels

${channelData.map(channel => `- **${channel.name}**: ${channel.address || channel.name} - ${channel.description || 'No description'}`).join('\n')}
` : ''}

${messageTypes.size > 0 ? `
## Message Types

${Array.from(messageTypes).map(type => `- ${type}`).join('\n')}
` : ''}

## Development

\`\`\`bash
# Build the library
cargo build --lib

# Run tests
cargo test

# Generate documentation
cargo doc --open
\`\`\`

## Features

- **Type Safety**: Generated message structs with full Rust type safety
- **Protocol Agnostic**: Same business logic works across all supported protocols
- **Async/Await**: Built on Tokio for high-performance async I/O
- **Authentication**: Built-in support for JWT, API keys, and basic auth
- **Error Handling**: Comprehensive error types and recovery mechanisms
- **Observability**: Structured logging and metrics support

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run the test suite: \`cargo test\`
5. Submit a pull request

## License

Apache-2.0
`}
        </File>
    );
}

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

## Features

- Async/await support with Tokio
- Structured logging with tracing
- Protocol support: ${Array.from(protocols).join(', ') || 'generic'}
- Type-safe message handling
- Generated message models
- Channel-based operation handlers
- Configuration management
- Error handling and middleware

## Generated Components

### Servers
${serverConfigs.map(server => `- **${server.name}**: ${server.protocol}://${server.host} - ${server.description || 'No description'}`).join('\n')}

### Channels
${channelData.map(channel => `- **${channel.name}**: ${channel.address || channel.name} - ${channel.description || 'No description'}`).join('\n')}

### Message Types
${Array.from(messageTypes).map(type => `- ${type}`).join('\n')}

## Usage

\`\`\`bash
# Build the project
cargo build

# Run the server
cargo run

# Run tests
cargo test

# Run with custom configuration
LOG_LEVEL=debug SERVER_HOST=localhost cargo run
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

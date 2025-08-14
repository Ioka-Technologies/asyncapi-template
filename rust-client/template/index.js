import { File } from '@asyncapi/generator-react-sdk';
import React from 'react';
import LibRs from './src/lib.rs.js';
import ClientRs from './src/client.rs.js';
import ErrorsRs from './src/errors.rs.js';
import EnvelopeRs from './src/envelope.rs.js';
import ModelsRs from './src/models.rs.js';
import AuthRs from './src/auth.rs.js';
import CargoToml from './Cargo.toml.js';

export default function ({ asyncapi, params }) {
    // Extract info from AsyncAPI spec
    let title, version, description;
    try {
        const info = asyncapi.info();
        title = info.title();
        version = info.version();
        description = info.description();
    } catch (error) {
        title = 'UnknownAPI';
        version = '1.0.0';
        description = 'Generated NATS client';
    }

    // Helper function to check if a parameter contains unresolved template variables
    function isTemplateVariable(value) {
        return typeof value === 'string' && value.includes('{{') && value.includes('}}');
    }

    // Helper function to convert title to kebab-case
    function toKebabCase(str) {
        return str.toLowerCase().replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    }

    // Helper function to convert title to PascalCase for struct names
    function toPascalCase(str) {
        return str.replace(/[^a-zA-Z0-9]/g, ' ')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
            .join('');
    }

    // Helper function to convert to snake_case for Rust identifiers
    function toSnakeCase(str) {
        return str.toLowerCase().replace(/[^a-z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '');
    }

    // Resolve parameters, falling back to extracted values if parameters contain template variables
    const clientName = (params.clientName && !isTemplateVariable(params.clientName))
        ? params.clientName
        : `${toPascalCase(title)}Client`;

    const packageName = (params.packageName && !isTemplateVariable(params.packageName))
        ? params.packageName
        : `${toKebabCase(title)}-client`;

    const packageVersion = (params.packageVersion && !isTemplateVariable(params.packageVersion))
        ? params.packageVersion
        : version;

    const license = (params.license && !isTemplateVariable(params.license))
        ? params.license
        : 'Apache-2.0';

    // Generate all files from the main index.js
    return [
        // Use the separate Cargo.toml template
        React.createElement(CargoToml, { asyncapi, params }),

        // Generate Rust source files
        React.createElement(LibRs, { asyncapi, params }),
        React.createElement(ClientRs, { asyncapi, params }),
        React.createElement(ErrorsRs, { asyncapi, params }),
        React.createElement(EnvelopeRs, { asyncapi, params }),
        React.createElement(ModelsRs, { asyncapi, params }),
        React.createElement(AuthRs, { asyncapi, params }),

        React.createElement(File, { name: 'README.md' },
            `# ${title}

${description || 'Generated Rust AsyncAPI NATS client'}

## Overview

This Rust client provides type-safe access to your AsyncAPI service using NATS messaging. Generated from your AsyncAPI specification, it offers seamless integration with NATS request/reply and pub/sub patterns.

## Technical Requirements

- Rust 1.70+
- NATS server

## Installation

Add this to your \`Cargo.toml\`:

\`\`\`toml
[dependencies]
${packageName} = "${packageVersion}"
async-nats = "0.33"
tokio = { version = "1.0", features = ["full"] }
\`\`\`

## Quick Start

### Basic Usage

\`\`\`rust
use async_nats;
use ${toSnakeCase(packageName)}::${clientName};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up your NATS client with desired configuration
    let nats_client = async_nats::connect("nats://localhost:4222").await?;

    // Create the service client
    let client = ${clientName}::with(nats_client);

    // Use the generated methods
    // (see generated documentation for specific operations)

    Ok(())
}
\`\`\`

### With Authentication Headers

\`\`\`rust
use async_nats;
use ${toSnakeCase(packageName)}::{${clientName}, AuthCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nats_client = async_nats::connect("nats://localhost:4222").await?;

    // Create client with JWT authentication
    let auth = AuthCredentials::jwt("your-jwt-token");
    let client = ${clientName}::with_auth(nats_client, auth)?;

    // Or with Basic authentication
    // let auth = AuthCredentials::basic("username", "password");
    // let client = ${clientName}::with_auth(nats_client, auth)?;

    // Or with API Key authentication
    // let auth = AuthCredentials::apikey_header("X-API-Key", "your-api-key");
    // let client = ${clientName}::with_auth(nats_client, auth)?;

    // All operations will now include authentication headers
    // let result = client.some_operation(payload).await?;

    Ok(())
}
\`\`\`

### With NATS-level Authentication

\`\`\`rust
use async_nats;
use ${toSnakeCase(packageName)}::${clientName};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up NATS client with JWT credentials
    let nats_client = async_nats::ConnectOptions::new()
        .credentials_file("./service.creds").await?
        .name("${toKebabCase(title)}-client")
        .connect("nats://server:4222").await?;

    let client = ${clientName}::with(nats_client);

    // Use the client...

    Ok(())
}
\`\`\`

### Shared Client Usage

\`\`\`rust
use async_nats;
use ${toSnakeCase(packageName)}::${clientName};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Single NATS client can be shared across multiple service clients
    let nats_client = async_nats::connect("nats://localhost:4222").await?;

    let client = ${clientName}::with(nats_client.clone());
    // You can create other service clients with the same nats_client

    Ok(())
}
\`\`\`

## Configuration

The client accepts any \`async-nats::Client\`, giving you full control over:

- **Authentication**: JWT, NKey, username/password, token
- **TLS**: Custom certificates and encryption
- **Connection**: Timeouts, retry logic, clustering
- **Monitoring**: Connection events and health checks

See the [async-nats documentation](https://docs.rs/async-nats/) for complete configuration options.

## Error Handling

The client provides specific error types for different scenarios:

\`\`\`rust
use ${toSnakeCase(packageName)}::{${clientName}, ClientError};

match client.some_operation(payload).await {
    Ok(result) => println!("Success: {:?}", result),
    Err(ClientError::Nats(e)) => eprintln!("NATS error: {}", e),
    Err(ClientError::Serialization(e)) => eprintln!("Serialization error: {}", e),
    Err(ClientError::InvalidEnvelope(e)) => eprintln!("Invalid message: {}", e),
}
\`\`\`

## Generated from AsyncAPI

- **AsyncAPI Version**: ${asyncapi.version()}
- **Generated**: ${new Date().toISOString()}
- **Title**: ${title}
- **Version**: ${packageVersion}

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run the test suite: \`cargo test\`
5. Submit a pull request

## License

${license}
`
        )
    ];
};

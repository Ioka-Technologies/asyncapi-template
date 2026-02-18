# Channel Lock Device Management API

AsyncAPI specification for managing a collection of Channel Lock devices.
This API allows provisioning, configuration, and deletion of devices,
as well as receiving threat notifications and communication link updates.


## Overview

This Rust client provides type-safe access to your AsyncAPI service using NATS messaging. Generated from your AsyncAPI specification, it offers seamless integration with NATS request/reply and pub/sub patterns.

## Technical Requirements

- Rust 1.70+
- NATS server

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
cska-client = "0.0.1"
async-nats = "0.33"
tokio = { version = "1.0", features = ["full"] }
```

## Quick Start

### Basic Usage

```rust
use async_nats;
use cska_client::CSKAClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up your NATS client with desired configuration
    let nats_client = async_nats::connect("nats://localhost:4222").await?;

    // Create the service client
    let client = CSKAClient::with(nats_client);

    // Use the generated methods
    // (see generated documentation for specific operations)

    Ok(())
}
```

### With Authentication Headers

```rust
use async_nats;
use cska_client::{CSKAClient, AuthCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nats_client = async_nats::connect("nats://localhost:4222").await?;

    // Create client with JWT authentication
    let auth = AuthCredentials::jwt("your-jwt-token");
    let client = CSKAClient::with_auth(nats_client, auth)?;

    // Or with Basic authentication
    // let auth = AuthCredentials::basic("username", "password");
    // let client = CSKAClient::with_auth(nats_client, auth)?;

    // Or with API Key authentication
    // let auth = AuthCredentials::apikey_header("X-API-Key", "your-api-key");
    // let client = CSKAClient::with_auth(nats_client, auth)?;

    // All operations will now include authentication headers
    // let result = client.some_operation(payload).await?;

    Ok(())
}
```

### With NATS-level Authentication

```rust
use async_nats;
use cska_client::CSKAClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up NATS client with JWT credentials
    let nats_client = async_nats::ConnectOptions::new()
        .credentials_file("./service.creds").await?
        .name("channel-lock-device-management-api-client")
        .connect("nats://server:4222").await?;

    let client = CSKAClient::with(nats_client);

    // Use the client...

    Ok(())
}
```

### Shared Client Usage

```rust
use async_nats;
use cska_client::CSKAClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Single NATS client can be shared across multiple service clients
    let nats_client = async_nats::connect("nats://localhost:4222").await?;

    let client = CSKAClient::with(nats_client.clone());
    // You can create other service clients with the same nats_client

    Ok(())
}
```

## Configuration

The client accepts any `async-nats::Client`, giving you full control over:

- **Authentication**: JWT, NKey, username/password, token
- **TLS**: Custom certificates and encryption
- **Connection**: Timeouts, retry logic, clustering
- **Monitoring**: Connection events and health checks

See the [async-nats documentation](https://docs.rs/async-nats/) for complete configuration options.

## Error Handling

The client provides specific error types for different scenarios:

```rust
use cska_client::{CSKAClient, ClientError};

match client.some_operation(payload).await {
    Ok(result) => println!("Success: {:?}", result),
    Err(ClientError::Nats(e)) => eprintln!("NATS error: {}", e),
    Err(ClientError::Serialization(e)) => eprintln!("Serialization error: {}", e),
    Err(ClientError::InvalidEnvelope(e)) => eprintln!("Invalid message: {}", e),
}
```

## Generated from AsyncAPI

- **AsyncAPI Version**: 3.0.0
- **Generated**: 2026-02-04T20:32:03.717Z
- **Title**: Channel Lock Device Management API
- **Version**: 0.0.1

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run the test suite: `cargo test`
5. Submit a pull request

## License

Apache-2.0

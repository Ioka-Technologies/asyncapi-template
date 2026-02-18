# Channel Lock Device Management API

Generate a production-ready Rust server from your AsyncAPI specification with support for multiple messaging protocols.

## Overview

This template generates a Rust library that provides a clean separation between generated infrastructure code and your business logic. The generated code handles protocol-specific concerns while you focus on implementing your domain logic through simple trait interfaces.

**Generated from AsyncAPI:**
- **Title**: Channel Lock Device Management API
- **Version**: 0.0.1
- **Description**: AsyncAPI specification for managing a collection of Channel Lock devices.
This API allows provisioning, configuration, and deletion of devices,
as well as receiving threat notifications and communication link updates.

- **Protocols**: ws, nats

## Technical Requirements

- Rust 1.70+
- AsyncAPI CLI 1.0+

## Supported Protocols

- WS
- NATS

## Quick Start

### Generate Server

```bash
# Install AsyncAPI CLI
npm install -g @asyncapi/cli

# Generate your Rust server
asyncapi generate fromTemplate asyncapi.yaml @ioka-technologies/asyncapi-rust-server-template -o my-server

cd my-server
cargo build
```

### Implement Business Logic

The generated code provides traits that you implement with your business logic:

```rust
use async_trait::async_trait;
use channel_lock_device_management_api::*;

pub struct ChannelLockDeviceManagementAPIService;

#[async_trait]
impl MessageHandler for ChannelLockDeviceManagementAPIService {
    async fn handle_message(&self, message: IncomingMessage, ctx: &MessageContext) -> Result<()> {
        // Your business logic here
        match message {
            IncomingMessage::LoginRequest(data) => {
                // Handle LoginRequest message
                println!("Received LoginRequest: {:?}", data);
                Ok(())
            }
            IncomingMessage::LogoutRequest(data) => {
                // Handle LogoutRequest message
                println!("Received LogoutRequest: {:?}", data);
                Ok(())
            }
            IncomingMessage::BootstrapDeviceRequest(data) => {
                // Handle BootstrapDeviceRequest message
                println!("Received BootstrapDeviceRequest: {:?}", data);
                Ok(())
            }
            _ => Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let service = Arc::new(ChannelLockDeviceManagementAPIService);

    Server::builder()
        .with_message_handler(service)
        .build()
        .start()
        .await
}
```

## Generated Project Structure

```
channel-lock-device-management-api/
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
```

## Configuration

Configure the server through environment variables:

- `LOG_LEVEL`: Logging level (trace, debug, info, warn, error) - default: `info`
- `SERVER_HOST`: Server host - default: `0.0.0.0`
- `SERVER_PORT`: Server port - default: `8080`


## Servers

- **0**: ws://0.0.0.0:8080 - Development WebSocket server
- **1**: nats://0.0.0.0:4222 - Development NATS server



## Channels

- **0**: auth - Channel for authentication operations
- **1**: device.{cska_id} - Channel for all device management operations and notifications
- **2**: network - Channel for network topology operations
- **3**: provision.{cska_id} - Channel for device provisioning operations via NATS
- **4**: salt.{cska_id} - Channel for key salting operations via NATS
- **5**: threats.{cska_id} - Channel for threat reporting operations via NATS (no authentication required)
- **6**: threats.{cska_id} - Channel for threat querying and streaming operations via WebSocket (JWT authentication required)
- **7**: validator_connection.{cska_id} - Channel for validator connection reporting via NATS
- **8**: connections.{cska_id} - Channel for connection querying and streaming operations via WebSocket (JWT authentication required)
- **9**: metrics.{cska_id} - Channel for metrics querying and streaming operations via WebSocket (JWT authentication required)
- **10**: tags.{cska_id} - Channel for tag management operations via WebSocket (JWT authentication required)
- **11**: profiles.{cska_id} - Channel for profile management operations via WebSocket (JWT authentication required)
- **12**: settings.{cska_id} - Channel for system settings management operations via WebSocket (JWT authentication required)



## Message Types

- LoginRequest
- LogoutRequest
- BootstrapDeviceRequest
- GetDeviceRequest
- ConfigureDeviceRequest
- DeleteDeviceRequest
- ListDevicesRequest
- DeviceStatusUpdateNotification
- UpdateDeviceMetadataRequest
- GetNetworkTopologyRequest
- ProvisionDeviceRefreshRequest
- SaltedKeyRequest
- ThreatReportRequest
- ThreatQueryRequest
- ThreatStreamNotification
- ThreatPcapDownloadRequest
- ValidatorConnectionReport
- ConnectionQueryRequest
- ConnectionStreamNotification
- MetricsQueryRequest
- MetricsStreamNotification
- MetricsResetRequest
- CreateTagRequest
- UpdateTagRequest
- DeleteTagRequest
- ListTagsRequest
- CreateProfileRequest
- GetProfileRequest
- UpdateProfileRequest
- DeleteProfileRequest
- ListProfilesRequest
- AssignProfileRequest
- UnassignProfileRequest
- GetSettingsRequest
- UpdateSettingsRequest


## Development

```bash
# Build the library
cargo build --lib

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

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
4. Run the test suite: `cargo test`
5. Submit a pull request

## License

Apache-2.0

/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function UsageMd({ asyncapi, params }) {
    const info = asyncapi.info();
    const title = info.title();

    // Generate package name from title if not provided
    let defaultPackageName = 'asyncapi-server';
    if (title) {
        const transformed = title
            .toLowerCase()
            .replace(/[^a-z0-9\s-]/g, '') // Remove non-alphanumeric chars except spaces and hyphens
            .replace(/\s+/g, '-')         // Replace spaces with hyphens
            .replace(/-+/g, '-')          // Replace multiple hyphens with single hyphen
            .replace(/^-+|-+$/g, '');     // Remove leading/trailing hyphens

        // Ensure it's a valid Rust package name
        if (transformed && transformed.length > 0) {
            defaultPackageName = transformed;
        }
    }

    // Use generated package name if params.packageName is the default value
    let packageName = defaultPackageName;
    if (params.packageName && params.packageName !== 'asyncapi-server') {
        packageName = params.packageName;
    }

    // Convert package name to valid Rust crate name for use statement
    const crateNameForUse = packageName.replace(/-/g, '_');

    // Helper functions for Rust identifier generation
    function toRustIdentifier(str) {
        if (!str) return 'unknown';
        let identifier = str
            .replace(/[^a-zA-Z0-9_]/g, '_')
            .replace(/^[0-9]/, '_$&')
            .replace(/_+/g, '_')
            .replace(/^_+|_+$/g, '');
        if (/^[0-9]/.test(identifier)) {
            identifier = 'item_' + identifier;
        }
        if (!identifier) {
            identifier = 'unknown';
        }
        const rustKeywords = [
            'as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern',
            'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match',
            'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self',
            'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe',
            'use', 'where', 'while', 'async', 'await', 'dyn'
        ];
        if (rustKeywords.includes(identifier)) {
            identifier = identifier + '_';
        }
        return identifier;
    }

    function toRustTypeName(str) {
        if (!str) return 'Unknown';
        const identifier = toRustIdentifier(str);
        return identifier
            .split('_')
            .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
            .join('');
    }

    function toRustFieldName(str) {
        if (!str) return 'unknown';
        const identifier = toRustIdentifier(str);
        return identifier
            .replace(/([A-Z])/g, '_$1')
            .toLowerCase()
            .replace(/^_/, '')
            .replace(/_+/g, '_');
    }

    // Detect protocols from servers
    const servers = asyncapi.servers();
    const protocols = new Set();
    const serverConfigs = [];
    const hasWebSocket = new Set(['ws', 'wss', 'websocket']);
    let hasWebSocketProtocol = false;

    if (servers) {
        Object.entries(servers).forEach(([name, server]) => {
            const protocol = server.protocol && server.protocol();
            if (protocol) {
                protocols.add(protocol.toLowerCase());
                if (hasWebSocket.has(protocol.toLowerCase())) {
                    hasWebSocketProtocol = true;
                }
                serverConfigs.push({
                    name,
                    protocol: protocol.toLowerCase(),
                    host: server.host && server.host(),
                    description: server.description && server.description()
                });
            }
        });
    }

    // Check if auth features are enabled
    const authEnabled = params.enableAuth === 'true' || params.enableAuth === true;

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
                        messages: messages || [],
                        rustName: toRustFieldName(opName)
                    });
                });
            }

            channelData.push({
                name: channelName,
                rustName: toRustTypeName(channelName + '_handler'),
                fieldName: toRustFieldName(channelName + '_handler'),
                traitName: toRustTypeName(channelName + '_service'),
                address: channel.address && channel.address(),
                description: channel.description && channel.description(),
                operations: channelOps
            });
        });
    }

    return (
        <File name="USAGE.md">
            {`# ${title} - Usage Guide

This library was generated from your AsyncAPI specification and provides a trait-based architecture for implementing ${title.toLowerCase()} services.

## Quick Start

### 1. Add as Dependency

Create a new Rust project and add this library as a dependency:

\`\`\`bash
# Create a new binary project
cargo new my-${packageName}-app
cd my-${packageName}-app
\`\`\`

Add this library to your \`Cargo.toml\`:

\`\`\`toml
[dependencies]
${packageName} = { path = "../path/to/this/library" }
tokio = { version = "1.0", features = ["full"] }
tracing = "0.1"
tracing-subscriber = "0.3"
serde_json = "1.0"
async-trait = "0.1"
\`\`\`

### 2. Implement Service Traits

Based on your AsyncAPI specification, you need to implement the following service traits:

${channelData.map(channel => `
#### ${channel.traitName}

This trait handles operations for the \`${channel.name}\` channel:

\`\`\`rust
use ${crateNameForUse}::{${channel.traitName}, MessageContext, AsyncApiResult};
use async_trait::async_trait;
use serde_json::Value;

pub struct My${channel.traitName.replace('Service', '')}Service {
    // Your service dependencies here
}

#[async_trait]
impl ${channel.traitName} for My${channel.traitName.replace('Service', '')}Service {${channel.operations.map(op => `
    async fn handle_${op.rustName}(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // TODO: Implement your business logic for ${op.name}
        tracing::info!(
            correlation_id = %context.correlation_id,
            "Processing ${op.name} operation"
        );

        // Example: Parse message based on your schema
        // let data: YourMessageType = serde_json::from_value(message.clone())?;

        // Example: Implement your business logic
        // self.process_${op.rustName}(data).await?;

        Ok(())
    }`).join('')}
}
\`\`\`
`).join('')}

### 3. Create Your Application

Create your \`src/main.rs\`:

\`\`\`rust
use ${crateNameForUse}::{
    Config, Server, RecoveryManager,${channelData.map(channel => `
    ${channel.traitName}, ${channel.rustName},`).join('')}
};
use std::sync::Arc;
use tracing::{info, Level};

// Your service implementations${channelData.map(channel => `
mod ${channel.fieldName.replace('_handler', '_service')};
use ${channel.fieldName.replace('_handler', '_service')}::My${channel.traitName.replace('Service', '')}Service;`).join('')}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("Starting ${title} server...");

    // Load configuration
    let config = Config::from_env()?;

    // Create your service implementations${channelData.map(channel => `
    let ${channel.fieldName.replace('_handler', '_service')} = Arc::new(My${channel.traitName.replace('Service', '')}Service::new());`).join('')}

    // Create recovery manager
    let recovery_manager = Arc::new(RecoveryManager::default());

    // Create handlers with your service implementations${channelData.map(channel => `
    let ${channel.fieldName} = ${channel.rustName}::new(
        ${channel.fieldName.replace('_handler', '_service')},
        recovery_manager.clone(),
    );`).join('')}

    // Create and configure server
    let server = Server::builder()
        .with_config(config)${channelData.map(channel => `
        .with_${channel.fieldName}(${channel.fieldName})`).join('')}
        .build()
        .await?;

    info!("Server configured successfully!");

    // Start the server
    server.start().await?;

    info!("Server started! Press Ctrl+C to shutdown.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping server...");

    server.stop().await?;
    info!("Server stopped successfully!");

    Ok(())
}
\`\`\`

### 4. Implement Your Service Logic

Create service implementation files for each channel:

${channelData.map(channel => `
#### \`src/${channel.fieldName.replace('_handler', '_service')}.rs\`

\`\`\`rust
use ${crateNameForUse}::{${channel.traitName}, MessageContext, AsyncApiResult};
use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, error};

pub struct My${channel.traitName.replace('Service', '')}Service {
    // Add your dependencies here, e.g.:
    // database: Arc<dyn Database>,
    // external_api: Arc<dyn ExternalApi>,
}

impl My${channel.traitName.replace('Service', '')}Service {
    pub fn new() -> Self {
        Self {
            // Initialize your dependencies
        }
    }
}

#[async_trait]
impl ${channel.traitName} for My${channel.traitName.replace('Service', '')}Service {${channel.operations.map(op => `
    async fn handle_${op.rustName}(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        info!(
            correlation_id = %context.correlation_id,
            channel = "${channel.name}",
            operation = "${op.name}",
            "Processing ${op.name} operation"
        );

        // TODO: Replace this with your actual business logic

        // Example: Parse the message
        // let message_data: YourMessageStruct = serde_json::from_value(message.clone())
        //     .map_err(|e| AsyncApiError::Validation {
        //         message: format!("Invalid message format: {}", e),
        //         field: Some("message".to_string()),
        //         metadata: ErrorMetadata::default(),
        //         source: Some(Box::new(e)),
        //     })?;

        // Example: Validate the message
        // self.validate_${op.rustName}_message(&message_data)?;

        // Example: Process the message
        // self.process_${op.rustName}(message_data, context).await?;

        info!(
            correlation_id = %context.correlation_id,
            "Successfully processed ${op.name} operation"
        );

        Ok(())
    }`).join('')}
}

// Add your helper methods here
impl My${channel.traitName.replace('Service', '')}Service {
    // Example helper methods:${channel.operations.map(op => `

    // async fn process_${op.rustName}(
    //     &self,
    //     data: YourMessageStruct,
    //     context: &MessageContext,
    // ) -> AsyncApiResult<()> {
    //     // Your business logic here
    //     Ok(())
    // }

    // fn validate_${op.rustName}_message(&self, data: &YourMessageStruct) -> AsyncApiResult<()> {
    //     // Your validation logic here
    //     Ok(())
    // }`).join('')}
}
\`\`\`
`).join('')}

## Configuration

The server can be configured through environment variables:

### Basic Configuration
- \`LOG_LEVEL\`: Set logging level (trace, debug, info, warn, error) - default: info
- \`SERVER_HOST\`: Server host - default: 0.0.0.0
- \`SERVER_PORT\`: Server port - default: 8080

${serverConfigs.length > 0 ? `### Protocol-Specific Configuration

${serverConfigs.map(server => `
#### ${server.name.toUpperCase()} (${server.protocol})
${server.protocol === 'mqtt' || server.protocol === 'mqtts' ? `- \`MQTT_HOST\`: MQTT broker host - default: ${server.host || 'localhost'}
- \`MQTT_PORT\`: MQTT broker port - default: 1883
- \`MQTT_USERNAME\`: MQTT username (optional)
- \`MQTT_PASSWORD\`: MQTT password (optional)
- \`MQTT_CLIENT_ID\`: MQTT client ID - default: rust-service` : ''}${server.protocol === 'kafka' ? `- \`KAFKA_BROKERS\`: Kafka broker addresses - default: ${server.host || 'localhost:9092'}
- \`KAFKA_GROUP_ID\`: Consumer group ID - default: rust-service-group
- \`KAFKA_AUTO_OFFSET_RESET\`: Auto offset reset - default: earliest` : ''}${server.protocol === 'ws' || server.protocol === 'wss' ? `- \`WEBSOCKET_HOST\`: WebSocket host - default: ${server.host || 'localhost'}
- \`WEBSOCKET_PORT\`: WebSocket port - default: 8080` : ''}${server.protocol === 'http' || server.protocol === 'https' ? `- \`HTTP_HOST\`: HTTP host - default: ${server.host || 'localhost'}
- \`HTTP_PORT\`: HTTP port - default: 8080` : ''}${server.protocol === 'amqp' || server.protocol === 'amqps' ? `- \`AMQP_URL\`: AMQP connection URL - default: amqp://${server.host || 'localhost:5672'}
- \`AMQP_QUEUE\`: AMQP queue name - default: rust-service` : ''}
`).join('')}` : ''}

## Running Your Application

\`\`\`bash
# Build your application
cargo build

# Run with default configuration
cargo run

# Run with custom configuration
LOG_LEVEL=debug SERVER_PORT=9000 cargo run

# Run with protocol-specific configuration${protocols.has('mqtt') ? `
MQTT_HOST=mqtt.example.com MQTT_PORT=1883 cargo run` : ''}${protocols.has('kafka') ? `
KAFKA_BROKERS=kafka1:9092,kafka2:9092 cargo run` : ''}
\`\`\`

${hasWebSocketProtocol ? `
## WebSocket Real-Time Communication

Your AsyncAPI specification includes WebSocket protocols. Here's how to implement real-time bidirectional communication:

### WebSocket Configuration

Add WebSocket-specific dependencies to your \`Cargo.toml\`:

\`\`\`toml
[dependencies]
${packageName} = { path = "../path/to/this/library", features = ["websocket"] }
tokio-tungstenite = "0.21"
futures-util = "0.3"
url = "2.5"
\`\`\`

### WebSocket Environment Variables

Configure WebSocket connections:

\`\`\`bash
# Basic WebSocket configuration
WEBSOCKET_HOST=localhost
WEBSOCKET_PORT=8080
WEBSOCKET_PATH=/ws

# WebSocket with authentication
WEBSOCKET_AUTH_HEADER_Authorization="Bearer your-jwt-token"
WEBSOCKET_AUTH_HEADER_X_API_Key="your-api-key"

# WebSocket limits
WEBSOCKET_MAX_MESSAGE_SIZE=1048576  # 1MB
WEBSOCKET_MAX_FRAME_SIZE=65536      # 64KB

# TLS configuration for WSS
WEBSOCKET_TLS_ENABLED=true
WEBSOCKET_TLS_CERT_PATH=/path/to/cert.pem
WEBSOCKET_TLS_KEY_PATH=/path/to/key.pem
\`\`\`

### WebSocket Service Implementation

Here's how to implement real-time WebSocket communication:

\`\`\`rust
use ${crateNameForUse}::{${channelData[0]?.traitName || 'WebSocketService'}, MessageContext, AsyncApiResult};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn, error};

pub struct RealTimeService {
    // Broadcast channel for real-time updates
    broadcast_tx: broadcast::Sender<String>,
    // Connected clients tracking
    connected_clients: Arc<RwLock<std::collections::HashSet<String>>>,
    // Your business logic dependencies
    database: Arc<dyn Database>,
}

impl RealTimeService {
    pub fn new(database: Arc<dyn Database>) -> Self {
        let (broadcast_tx, _) = broadcast::channel(1000);

        Self {
            broadcast_tx,
            connected_clients: Arc::new(RwLock::new(std::collections::HashSet::new())),
            database,
        }
    }

    // Method to broadcast messages to all connected clients
    pub async fn broadcast_message(&self, message: &str) -> AsyncApiResult<()> {
        match self.broadcast_tx.send(message.to_string()) {
            Ok(receiver_count) => {
                info!("Broadcasted message to {} clients", receiver_count);
                Ok(())
            }
            Err(_) => {
                warn!("No active receivers for broadcast");
                Ok(())
            }
        }
    }

    // Handle client connections
    pub async fn handle_client_connect(&self, client_id: &str) -> AsyncApiResult<()> {
        let mut clients = self.connected_clients.write().await;
        clients.insert(client_id.to_string());

        info!("Client {} connected. Total clients: {}", client_id, clients.len());

        // Send welcome message
        let welcome_msg = json!({
            "type": "welcome",
            "client_id": client_id,
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        self.broadcast_message(&welcome_msg.to_string()).await?;
        Ok(())
    }

    // Handle client disconnections
    pub async fn handle_client_disconnect(&self, client_id: &str) -> AsyncApiResult<()> {
        let mut clients = self.connected_clients.write().await;
        clients.remove(client_id);

        info!("Client {} disconnected. Total clients: {}", client_id, clients.len());
        Ok(())
    }
}

#[async_trait]
impl ${channelData[0]?.traitName || 'WebSocketService'} for RealTimeService {${channelData[0]?.operations?.map(op => `
    async fn handle_${op.rustName}(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        info!(
            correlation_id = %context.correlation_id,
            "Processing real-time ${op.name} operation"
        );

        // Parse the incoming WebSocket message
        let message_type = message.get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown");

        match message_type {
            "ping" => {
                // Handle ping messages
                let pong_response = json!({
                    "type": "pong",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });
                self.broadcast_message(&pong_response.to_string()).await?;
            }
            "subscribe" => {
                // Handle subscription requests
                let channel = message.get("channel")
                    .and_then(|c| c.as_str())
                    .unwrap_or("default");

                info!("Client subscribing to channel: {}", channel);

                // Add subscription logic here
                // self.add_subscription(context.correlation_id, channel).await?;
            }
            "message" => {
                // Handle regular messages
                let content = message.get("content")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");

                // Process the message (save to database, etc.)
                // let processed_message = self.database.save_message(content).await?;

                // Broadcast to all connected clients
                let broadcast_msg = json!({
                    "type": "broadcast",
                    "content": content,
                    "sender": context.correlation_id,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });

                self.broadcast_message(&broadcast_msg.to_string()).await?;
            }
            _ => {
                warn!("Unknown message type: {}", message_type);
            }
        }

        Ok(())
    }`).join('') || `
    async fn handle_websocket_message(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // Default WebSocket message handler
        info!("Processing WebSocket message");

        // Echo the message back to all clients
        self.broadcast_message(&message.to_string()).await?;
        Ok(())
    }`}
}
\`\`\`

### WebSocket Client Example

Here's how to create a WebSocket client to test your service:

\`\`\`rust
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "ws://localhost:8080/ws";

    // Connect to WebSocket server
    let (ws_stream, _) = connect_async(url).await?;
    println!("Connected to WebSocket server");

    let (mut write, mut read) = ws_stream.split();

    // Send a test message
    let test_message = json!({
        "type": "message",
        "content": "Hello from WebSocket client!",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    write.send(Message::Text(test_message.to_string())).await?;

    // Listen for messages
    while let Some(message) = read.next().await {
        match message? {
            Message::Text(text) => {
                println!("Received: {}", text);

                // Parse and handle different message types
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    match parsed.get("type").and_then(|t| t.as_str()) {
                        Some("welcome") => {
                            println!("Welcome message received");
                        }
                        Some("broadcast") => {
                            println!("Broadcast message: {}",
                                parsed.get("content").and_then(|c| c.as_str()).unwrap_or(""));
                        }
                        Some("pong") => {
                            println!("Pong received");
                        }
                        _ => {
                            println!("Unknown message type");
                        }
                    }
                }
            }
            Message::Binary(data) => {
                println!("Received binary data: {} bytes", data.len());
            }
            Message::Close(_) => {
                println!("Connection closed");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
\`\`\`

### WebSocket with Authentication

If authentication is enabled, here's how to handle authenticated WebSocket connections:

\`\`\`rust
use ${crateNameForUse}::auth::{JwtValidator, Claims};

impl RealTimeService {
    // Validate WebSocket connection with JWT
    pub async fn validate_websocket_auth(
        &self,
        headers: &std::collections::HashMap<String, String>,
    ) -> AsyncApiResult<Claims> {
        let auth_header = headers.get("authorization")
            .or_else(|| headers.get("Authorization"))
            .ok_or_else(|| AsyncApiError::Authentication {
                message: "Missing Authorization header".to_string(),
            })?;

        let token = auth_header.strip_prefix("Bearer ")
            .ok_or_else(|| AsyncApiError::Authentication {
                message: "Invalid Authorization header format".to_string(),
            })?;

        let jwt_validator = JwtValidator::new("your-secret-key")?;
        let claims = jwt_validator.validate_token(token).await?;

        Ok(claims)
    }

    // Handle authenticated WebSocket messages
    pub async fn handle_authenticated_message(
        &self,
        message: &Value,
        context: &MessageContext,
        claims: &Claims,
    ) -> AsyncApiResult<()> {
        // Check user permissions
        if !claims.has_permission("websocket:write") {
            return Err(AsyncApiError::Authorization {
                message: "Insufficient permissions for WebSocket write".to_string(),
                required_permissions: vec!["websocket:write".to_string()],
                user_permissions: claims.permissions.clone(),
            });
        }

        // Process the message with user context
        info!(
            user_id = %claims.sub,
            correlation_id = %context.correlation_id,
            "Processing authenticated WebSocket message"
        );

        // Your authenticated message handling logic here
        self.handle_websocket_message(message, context).await
    }
}
\`\`\`

### WebSocket Connection Management

For production use, implement proper connection management:

\`\`\`rust
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct WebSocketConnectionManager {
    connections: Arc<RwLock<HashMap<String, WebSocketConnection>>>,
}

pub struct WebSocketConnection {
    pub id: String,
    pub user_id: Option<String>,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub last_ping: chrono::DateTime<chrono::Utc>,
    pub subscriptions: Vec<String>,
}

impl WebSocketConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_connection(&self, user_id: Option<String>) -> String {
        let connection_id = Uuid::new_v4().to_string();
        let connection = WebSocketConnection {
            id: connection_id.clone(),
            user_id,
            connected_at: chrono::Utc::now(),
            last_ping: chrono::Utc::now(),
            subscriptions: Vec::new(),
        };

        let mut connections = self.connections.write().await;
        connections.insert(connection_id.clone(), connection);

        info!("Added WebSocket connection: {}", connection_id);
        connection_id
    }

    pub async fn remove_connection(&self, connection_id: &str) {
        let mut connections = self.connections.write().await;
        if connections.remove(connection_id).is_some() {
            info!("Removed WebSocket connection: {}", connection_id);
        }
    }

    pub async fn update_ping(&self, connection_id: &str) {
        let mut connections = self.connections.write().await;
        if let Some(connection) = connections.get_mut(connection_id) {
            connection.last_ping = chrono::Utc::now();
        }
    }

    pub async fn cleanup_stale_connections(&self, timeout_seconds: i64) {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(timeout_seconds);
        let mut connections = self.connections.write().await;

        let stale_connections: Vec<String> = connections
            .iter()
            .filter(|(_, conn)| conn.last_ping < cutoff)
            .map(|(id, _)| id.clone())
            .collect();

        for connection_id in stale_connections {
            connections.remove(&connection_id);
            info!("Removed stale WebSocket connection: {}", connection_id);
        }
    }
}
\`\`\`
` : ''}

${authEnabled ? `
## Authentication and Authorization

Your AsyncAPI specification has authentication enabled. This library provides comprehensive JWT-based authentication and role-based access control (RBAC).

### Enable Authentication Features

Add authentication dependencies to your \`Cargo.toml\`:

\`\`\`toml
[dependencies]
${packageName} = { path = "../path/to/this/library", features = ["auth"] }
jsonwebtoken = "9.2"
bcrypt = "0.15"
uuid = { version = "1.6", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
\`\`\`

### Authentication Configuration

Configure JWT authentication through environment variables:

\`\`\`bash
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-signing-key
JWT_EXPIRATION_HOURS=24
JWT_ISSUER=your-service-name
JWT_AUDIENCE=your-api-users

# Optional: JWT Algorithm (default: HS256)
JWT_ALGORITHM=HS256

# Optional: Refresh token settings
JWT_REFRESH_EXPIRATION_DAYS=30
JWT_ALLOW_REFRESH=true
\`\`\`

### Basic Authentication Setup

Here's how to set up JWT authentication in your application:

\`\`\`rust
use ${crateNameForUse}::auth::{
    AuthConfig, JwtValidator, Claims, AuthMiddleware,
    RoleManager, Role, Permission
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize authentication configuration
    let auth_config = AuthConfig::from_env()?;
    let jwt_validator = Arc::new(JwtValidator::new(&auth_config.jwt_secret)?);

    // Create role manager with default roles
    let role_manager = Arc::new(RoleManager::with_default_roles().await);

    // Create authentication middleware
    let auth_middleware = AuthMiddleware::new(
        jwt_validator.clone(),
        role_manager.clone(),
    );

    // Your service setup with authentication
    let server = Server::builder()
        .with_config(config)
        .with_auth_middleware(auth_middleware)${channelData.map(channel => `
        .with_${channel.fieldName}(${channel.fieldName})`).join('')}
        .build()
        .await?;

    server.start().await?;
    Ok(())
}
\`\`\`

### Role-Based Access Control (RBAC)

#### Setting Up Roles and Permissions

\`\`\`rust
use ${crateNameForUse}::auth::{RoleManager, Role, Permission};

async fn setup_rbac() -> Result<Arc<RoleManager>, Box<dyn std::error::Error>> {
    let role_manager = Arc::new(RoleManager::new());

    // Create permissions for your API operations${channelData.map(channel => channel.operations.map(op => `
    let ${op.rustName}_permission = Permission::new("${channel.name}", "${op.name}");`).join('')).join('')}

    // Create roles with specific permissions
    let admin_role = Role::new("admin", "Administrator with full access")
        .with_permission(Permission::new("*", "*")); // All permissions

    let user_role = Role::new("user", "Regular user")${channelData.map(channel => channel.operations.filter(op => op.action === 'receive' || op.action === 'subscribe').map(op => `
        .with_permission(Permission::new("${channel.name}", "${op.name}"))`).join('')).join('')};

    let moderator_role = Role::new("moderator", "Moderator with additional permissions")
        .with_parent_role("user") // Inherit user permissions${channelData.map(channel => channel.operations.filter(op => op.action === 'send' || op.action === 'publish').map(op => `
        .with_permission(Permission::new("${channel.name}", "${op.name}"))`).join('')).join('')};

    // Add roles to the manager
    role_manager.add_role(admin_role).await?;
    role_manager.add_role(user_role).await?;
    role_manager.add_role(moderator_role).await?;

    Ok(role_manager)
}
\`\`\`

#### Assigning Roles to Users

\`\`\`rust
async fn assign_user_roles(role_manager: &RoleManager) -> Result<(), Box<dyn std::error::Error>> {
    // Assign roles to users
    role_manager.assign_role_to_user("user123", "user").await?;
    role_manager.assign_role_to_user("admin456", "admin").await?;
    role_manager.assign_role_to_user("mod789", "moderator").await?;

    // Check user permissions
    let has_permission = role_manager
        .user_has_permission("user123", &Permission::new("${channelData[0]?.name || 'messages'}", "read"))
        .await;

    println!("User has permission: {}", has_permission);
    Ok(())
}
\`\`\`

### Implementing Authentication in Services

Here's how to implement authentication checks in your service handlers:

\`\`\`rust
use ${crateNameForUse}::{
    ${channelData[0]?.traitName || 'MessageService'}, MessageContext, AsyncApiResult,
    auth::{Claims, Permission}
};

pub struct Authenticated${channelData[0]?.traitName?.replace('Service', '') || 'Message'}Service {
    role_manager: Arc<RoleManager>,
    // Your other dependencies
}

impl Authenticated${channelData[0]?.traitName?.replace('Service', '') || 'Message'}Service {
    pub fn new(role_manager: Arc<RoleManager>) -> Self {
        Self {
            role_manager,
        }
    }

    // Helper method to check permissions
    async fn check_permission(
        &self,
        context: &MessageContext,
        required_permission: &Permission,
    ) -> AsyncApiResult<Claims> {
        // Extract claims from context (set by auth middleware)
        let claims = context.claims()
            .ok_or_else(|| AsyncApiError::Authentication {
                message: "No authentication claims found".to_string(),
            })?;

        // Check if user has required permission
        let has_permission = self.role_manager
            .user_has_permission(&claims.sub, required_permission)
            .await;

        if !has_permission {
            return Err(AsyncApiError::Authorization {
                message: format!("Insufficient permissions for operation"),
                required_permissions: vec![required_permission.name.clone()],
                user_permissions: claims.permissions.clone(),
            });
        }

        Ok(claims.clone())
    }
}

#[async_trait]
impl ${channelData[0]?.traitName || 'MessageService'} for Authenticated${channelData[0]?.traitName?.replace('Service', '') || 'Message'}Service {${channelData[0]?.operations?.map(op => `
    async fn handle_${op.rustName}(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // Check authentication and authorization
        let required_permission = Permission::new("${channelData[0]?.name || 'messages'}", "${op.name}");
        let claims = self.check_permission(context, &required_permission).await?;

        info!(
            user_id = %claims.sub,
            correlation_id = %context.correlation_id,
            operation = "${op.name}",
            "Processing authenticated ${op.name} operation"
        );

        // Your business logic here with user context
        self.process_${op.rustName}_for_user(message, context, &claims).await
    }

    async fn process_${op.rustName}_for_user(
        &self,
        message: &Value,
        context: &MessageContext,
        claims: &Claims,
    ) -> AsyncApiResult<()> {
        // Implement your business logic with user context
        // You can access user information through claims.sub, claims.email, etc.

        info!(
            user_id = %claims.sub,
            "Processing ${op.name} for authenticated user"
        );

        // Example: Filter data based on user permissions
        if claims.has_permission("admin") {
            // Admin users see all data
            self.process_admin_${op.rustName}(message, context).await
        } else {
            // Regular users see filtered data
            self.process_user_${op.rustName}(message, context, &claims.sub).await
        }
    }`).join('') || `
    async fn handle_authenticated_message(
        &self,
        message: &Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        let required_permission = Permission::new("messages", "read");
        let claims = self.check_permission(context, &required_permission).await?;

        // Process with user context
        Ok(())
    }`}
}
\`\`\`

### Advanced RBAC Features

#### Time-Based Access Control

\`\`\`rust
use ${crateNameForUse}::auth::{Permission, PermissionConditions, TimeRestrictions};

// Create permission with time restrictions
let business_hours_permission = Permission::new("reports", "generate")
    .with_conditions(PermissionConditions {
        time_restrictions: Some(TimeRestrictions {
            start_hour: Some(9),  // 9 AM
            end_hour: Some(17),   // 5 PM
            allowed_days: Some(vec![1, 2, 3, 4, 5]), // Monday to Friday
        }),
        ip_restrictions: None,
        custom_conditions: std::collections::HashMap::new(),
    });

// Add to role
let business_user_role = Role::new("business_user", "Business hours user")
    .with_permission(business_hours_permission);
\`\`\`

#### IP-Based Access Control

\`\`\`rust
// Create permission with IP restrictions
let internal_permission = Permission::new("admin", "access")
    .with_conditions(PermissionConditions {
        time_restrictions: None,
        ip_restrictions: Some(vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
        ]),
        custom_conditions: std::collections::HashMap::new(),
    });
\`\`\`

#### Custom Permission Conditions

\`\`\`rust
use std::collections::HashMap;

// Create permission with custom conditions
let mut custom_conditions = HashMap::new();
custom_conditions.insert("department".to_string(), "engineering".to_string());
custom_conditions.insert("clearance_level".to_string(), "secret".to_string());

let classified_permission = Permission::new("classified", "read")
    .with_conditions(PermissionConditions {
        time_restrictions: None,
        ip_restrictions: None,
        custom_conditions,
    });
\`\`\`

### JWT Token Management

#### Creating JWT Tokens

\`\`\`rust
use ${crateNameForUse}::auth::{JwtValidator, Claims};
use chrono::{Utc, Duration};

async fn create_user_token(
    jwt_validator: &JwtValidator,
    user_id: &str,
    email: &str,
    roles: Vec<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let claims = Claims {
        sub: user_id.to_string(),
        email: Some(email.to_string()),
        roles,
        permissions: vec![], // Will be populated from roles
        exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
        iat: Utc::now().timestamp() as usize,
        iss: Some("your-service".to_string()),
        aud: Some("your-api".to_string()),
    };

    let token = jwt_validator.create_token(&claims)?;
    Ok(token)
}
\`\`\`

#### Validating JWT Tokens

\`\`\`rust
async fn validate_user_token(
    jwt_validator: &JwtValidator,
    token: &str,
) -> Result<Claims, Box<dyn std::error::Error>> {
    let claims = jwt_validator.validate_token(token).await?;

    // Additional validation if needed
    if claims.is_expired() {
        return Err("Token has expired".into());
    }

    Ok(claims)
}
\`\`\`

### Authentication Middleware Integration

The authentication middleware automatically validates JWT tokens and populates the message context:

\`\`\`rust
use ${crateNameForUse}::auth::AuthMiddleware;

// The middleware automatically:
// 1. Extracts JWT token from Authorization header
// 2. Validates the token signature and expiration
// 3. Loads user roles and permissions
// 4. Populates MessageContext with Claims
// 5. Rejects requests with invalid/missing tokens

// In your service, you can access the authenticated user:
async fn handle_authenticated_operation(
    &self,
    message: &Value,
    context: &MessageContext,
) -> AsyncApiResult<()> {
    let claims = context.claims().unwrap(); // Safe because middleware validates

    info!(
        user_id = %claims.sub,
        roles = ?claims.roles,
        "Processing request for authenticated user"
    );

    // Your business logic with user context
    Ok(())
}
\`\`\`

### Testing Authentication

#### Unit Testing with Mock Authentication

\`\`\`rust
#[cfg(test)]
mod auth_tests {
    use super::*;
    use ${crateNameForUse}::auth::{Claims, RoleManager};

    #[tokio::test]
    async fn test_authenticated_operation() {
        let role_manager = Arc::new(RoleManager::new());
        let service = Authenticated${channelData[0]?.traitName?.replace('Service', '') || 'Message'}Service::new(role_manager);

        // Create mock claims
        let claims = Claims {
            sub: "test_user".to_string(),
            email: Some("test@example.com".to_string()),
            roles: vec!["user".to_string()],
            permissions: vec!["${channelData[0]?.name || 'messages'}:read".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
            iss: Some("test".to_string()),
            aud: Some("test".to_string()),
        };

        // Create context with claims
        let mut context = MessageContext::new("test-channel", "test-operation");
        context.set_claims(claims);

        let message = serde_json::json!({
            "test": "data"
        });

        let result = service.handle_${channelData[0]?.operations[0]?.rustName || 'test'}(&message, &context).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unauthorized_operation() {
        let role_manager = Arc::new(RoleManager::new());
        let service = Authenticated${channelData[0]?.traitName?.replace('Service', '') || 'Message'}Service::new(role_manager);

        // Create context without claims (unauthenticated)
        let context = MessageContext::new("test-channel", "test-operation");

        let message = serde_json::json!({
            "test": "data"
        });

        let result = service.handle_${channelData[0]?.operations[0]?.rustName || 'test'}(&message, &context).await;
        assert!(result.is_err());

        // Verify it's an authentication error
        match result.unwrap_err() {
            AsyncApiError::Authentication { .. } => {}, // Expected
            _ => panic!("Expected authentication error"),
        }
    }
}
\`\`\`

### Production Security Considerations

#### Secure JWT Secret Management

\`\`\`bash
# Use a strong, randomly generated secret
JWT_SECRET=$(openssl rand -base64 64)

# In production, use environment-specific secrets
# Development
JWT_SECRET=dev-secret-key-not-for-production

# Staging
JWT_SECRET=staging-secret-key-different-from-dev

# Production
JWT_SECRET=production-secret-key-highly-secure
\`\`\`

#### Token Rotation and Refresh

\`\`\`rust
// Implement token refresh logic
async fn refresh_token(
    jwt_validator: &JwtValidator,
    refresh_token: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Validate refresh token
    let claims = jwt_validator.validate_refresh_token(refresh_token).await?;

    // Create new access token
    let new_access_token = jwt_validator.create_token(&claims)?;

    // Create new refresh token
    let new_refresh_token = jwt_validator.create_refresh_token(&claims)?;

    Ok((new_access_token, new_refresh_token))
}
\`\`\`

#### Rate Limiting and Security Headers

\`\`\`rust
// Add rate limiting to your authentication endpoints
use ${crateNameForUse}::middleware::RateLimitMiddleware;

let rate_limiter = RateLimitMiddleware::new(
    100, // requests per minute
    Duration::from_secs(60),
);

// Add security headers
let security_headers = SecurityHeadersMiddleware::new()
    .with_content_security_policy("default-src 'self'")
    .with_x_frame_options("DENY")
    .with_x_content_type_options("nosniff");
\`\`\`
` : ''}

## Testing Your Implementation

Create tests for your service implementations:

\`\`\`rust
#[cfg(test)]
mod tests {
    use super::*;
    use ${crateNameForUse}::MessageContext;
    use serde_json::json;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_${channelData[0]?.operations[0]?.rustName || 'example'}_handler() {
        let service = My${channelData[0]?.traitName?.replace('Service', '') || 'Example'}Service::new();

        let message = json!({
            // Your test message structure
        });

        let context = MessageContext::new(
            "test-channel",
            "test-operation"
        );

        let result = service.handle_${channelData[0]?.operations[0]?.rustName || 'example'}(&message, &context).await;
        assert!(result.is_ok());
    }
}
\`\`\`

## Generated Components

This library includes the following generated components based on your AsyncAPI specification:

### Channels
${channelData.map(channel => `- **${channel.name}**: ${channel.address || channel.name} - ${channel.description || 'No description'}`).join('\n')}

### Message Types
${Array.from(messageTypes).map(type => `- ${type}`).join('\n')}

### Protocols
${Array.from(protocols).map(protocol => `- ${protocol.toUpperCase()}`).join('\n')}

## Error Handling

The library provides comprehensive error handling through the \`AsyncApiResult<T>\` type and \`AsyncApiError\` enum. Your service implementations should return appropriate errors:

\`\`\`rust
use ${crateNameForUse}::{AsyncApiError, ErrorMetadata, ErrorSeverity, ErrorCategory};

// Validation error
return Err(AsyncApiError::Validation {
    message: "Invalid input".to_string(),
    field: Some("email".to_string()),
    metadata: ErrorMetadata::new(
        ErrorSeverity::Medium,
        ErrorCategory::Validation,
        false, // not retryable
    ),
    source: None,
});

// Business logic error
return Err(AsyncApiError::BusinessLogic {
    message: "User already exists".to_string(),
    metadata: ErrorMetadata::new(
        ErrorSeverity::Low,
        ErrorCategory::BusinessLogic,
        false, // not retryable
    ),
    source: None,
});
\`\`\`

## Advanced Features

### Recovery and Resilience

The library includes built-in recovery mechanisms:

- **Retry Logic**: Automatic retries with exponential backoff
- **Circuit Breakers**: Prevent cascade failures
- **Dead Letter Queues**: Handle unprocessable messages
- **Bulkhead Pattern**: Isolate failures

### Monitoring and Observability

- **Structured Logging**: JSON logging with correlation IDs
- **Metrics**: Built-in Prometheus metrics (optional)
- **Health Checks**: Readiness and liveness endpoints
- **Distributed Tracing**: OpenTelemetry integration

### Security

- **JWT Authentication**: Built-in JWT support (optional)
- **RBAC**: Role-based access control (optional)
- **Input Validation**: Comprehensive payload validation

## Need Help?

- Check the generated \`README.md\` for more details about the library architecture
- Review the generated trait definitions in \`src/handlers.rs\`
- Look at the example implementations in the handlers file
- Refer to the AsyncAPI specification that generated this library

## Generated from AsyncAPI

This library was generated from:
- **Title**: ${title}
- **Version**: ${info.version() || '1.0.0'}
- **Description**: ${info.description() || 'No description provided'}
- **Protocols**: ${Array.from(protocols).join(', ') || 'generic'}
`}
        </File>
    );
}

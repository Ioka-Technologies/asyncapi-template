/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function CargoToml({ asyncapi, params }) {
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

    const packageVersion = params.packageVersion || '0.1.0';
    const author = params.author || 'AsyncAPI Generator';
    const license = params.license || 'Apache-2.0';
    const edition = params.edition || '2021';

    // Check which features are enabled
    const enableMetrics = params.enableMetrics === 'true' || params.enableMetrics === true;
    const enableTracing = params.enableTracing === 'true' || params.enableTracing === true;
    const enableAuth = params.enableAuth === 'true' || params.enableAuth === true;
    const enableConnectionPooling = params.enableConnectionPooling === 'true' || params.enableConnectionPooling === true;
    const enableBatching = params.enableBatching === 'true' || params.enableBatching === true;
    const enableDynamicConfig = params.enableDynamicConfig === 'true' || params.enableDynamicConfig === true;
    const enableFeatureFlags = params.enableFeatureFlags === 'true' || params.enableFeatureFlags === true;

    // Detect protocols from servers
    const servers = asyncapi.servers();
    const protocols = new Set();

    if (servers) {
        Object.entries(servers).forEach(([name, server]) => {
            const protocol = server.protocol && server.protocol();
            if (protocol) {
                protocols.add(protocol.toLowerCase());
            }
        });
    }

    return (
        <File name="Cargo.toml">
            {`[package]
name = "${packageName}"
version = "${packageVersion}"
edition = "${edition}"
authors = ["${author}"]
license = "${license}"
description = "AsyncAPI-generated Rust library for ${title || 'async message handling'}"
repository = "https://github.com/your-org/${packageName}"
keywords = ["asyncapi", "async", "messaging", "library"]
categories = ["network-programming", "asynchronous", "web-programming"]
readme = "README.md"

# This is a library crate
[lib]
name = "${packageName.replace(/-/g, '_')}"
path = "src/lib.rs"

[dependencies]
# Core async runtime
tokio = { version = "1.35", features = ["full"] }
async-trait = "0.1"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Error handling
thiserror = "1.0"
anyhow = "1.0"

# Logging and tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# HTTP and networking
reqwest = { version = "0.11", features = ["json", "stream"] }
hyper = { version = "1.0", features = ["full"] }
tower = { version = "0.4", features = ["full"] }
tower-http = { version = "0.5", features = ["cors", "trace", "compression-gzip"] }

# Utilities
uuid = { version = "1.6", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
url = "2.5"
bytes = "1.5"
futures = "0.3"
futures-util = "0.3"
regex = "1.10"
rand = "0.8"
base64 = "0.22"
axum = "0.7"
tokio-stream = "0.1"

# Configuration
config = "0.14"
dotenvy = "0.15"

# Validation
validator = { version = "0.18", features = ["derive"] }

# Circuit breaker and resilience
circuit_breaker = "0.1"${enableMetrics ? `

# Metrics
prometheus = { version = "0.13", optional = true }
metrics = { version = "0.22", optional = true }
metrics-prometheus = { version = "0.6", optional = true }` : ''}${enableAuth ? `

# Authentication and authorization
jsonwebtoken = { version = "9.2", optional = true }
bcrypt = { version = "0.15", optional = true }` : ''}${protocols.has('mqtt') || protocols.has('mqtts') ? `

# MQTT support
rumqttc = { version = "0.24", optional = true }` : ''}${protocols.has('kafka') ? `

# Kafka support
rdkafka = { version = "0.36", features = ["cmake-build"], optional = true }` : ''}${protocols.has('amqp') || protocols.has('amqps') ? `

# AMQP support
lapin = { version = "2.3", optional = true }` : ''}${protocols.has('ws') || protocols.has('wss') || protocols.has('websocket') ? `

# WebSocket support
tokio-tungstenite = { version = "0.21", features = ["native-tls"], optional = true }` : ''}${enableConnectionPooling ? `

# Connection pooling
deadpool = { version = "0.10", optional = true }
deadpool-postgres = { version = "0.12", optional = true }` : ''}${enableTracing ? `

# Tracing dependencies
tracing-opentelemetry = { version = "0.22", optional = true }
opentelemetry = { version = "0.21", optional = true }
opentelemetry_sdk = { version = "0.21", optional = true }` : ''}

[dev-dependencies]
tokio-test = "0.4"
mockall = "0.12"
wiremock = "0.6"
tempfile = "3.8"

[features]
default = ["http"]

# Protocol features
http = []${protocols.has('mqtt') || protocols.has('mqtts') ? `
mqtt = ["dep:rumqttc"]` : ''}${protocols.has('kafka') ? `
kafka = ["dep:rdkafka"]` : ''}${protocols.has('amqp') || protocols.has('amqps') ? `
amqp = ["dep:lapin"]` : ''}${protocols.has('ws') || protocols.has('wss') || protocols.has('websocket') ? `
websocket = ["dep:tokio-tungstenite"]` : ''}

# Enable all detected protocols by default for this specific AsyncAPI spec
all-protocols = [${protocols.has('mqtt') || protocols.has('mqtts') ? '"mqtt"' : ''}${protocols.has('kafka') ? (protocols.has('mqtt') || protocols.has('mqtts') ? ', "kafka"' : '"kafka"') : ''}${protocols.has('amqp') || protocols.has('amqps') ? ((protocols.has('mqtt') || protocols.has('mqtts') || protocols.has('kafka')) ? ', "amqp"' : '"amqp"') : ''}${protocols.has('ws') || protocols.has('wss') || protocols.has('websocket') ? ((protocols.has('mqtt') || protocols.has('mqtts') || protocols.has('kafka') || protocols.has('amqp') || protocols.has('amqps')) ? ', "websocket"' : '"websocket"') : ''}]

# Optional features${enableMetrics ? `
metrics = ["dep:prometheus", "dep:metrics", "dep:metrics-prometheus"]` : ''}${enableTracing ? `
tracing = ["dep:tracing-opentelemetry", "dep:opentelemetry", "dep:opentelemetry_sdk"]` : ''}
auth = [${enableAuth ? '"dep:jsonwebtoken", "dep:bcrypt"' : ''}]${enableConnectionPooling ? `
connection-pooling = ["dep:deadpool", "dep:deadpool-postgres"]` : ''}${enableBatching ? `
batching = []` : ''}${enableDynamicConfig ? `
dynamic-config = []` : ''}${enableFeatureFlags ? `
feature-flags = []` : ''}

# All features enabled
all-features = [
    "http"${protocols.has('mqtt') || protocols.has('mqtts') ? ', "mqtt"' : ''}${protocols.has('kafka') ? ', "kafka"' : ''}${protocols.has('amqp') || protocols.has('amqps') ? ', "amqp"' : ''}${protocols.has('ws') || protocols.has('wss') || protocols.has('websocket') ? ', "websocket"' : ''}${enableMetrics ? ', "metrics"' : ''}${enableTracing ? ', "tracing"' : ''}${enableAuth ? ', "auth"' : ''}${enableConnectionPooling ? ', "connection-pooling"' : ''}${enableBatching ? ', "batching"' : ''}${enableDynamicConfig ? ', "dynamic-config"' : ''}${enableFeatureFlags ? ', "feature-flags"' : ''}
]

[profile.dev]
opt-level = 0
debug = true
split-debuginfo = "unpacked"
debug-assertions = true
overflow-checks = true
lto = false
panic = "unwind"
incremental = true
codegen-units = 256
rpath = false

[profile.release]
opt-level = 3
debug = false
split-debuginfo = "packed"
debug-assertions = false
overflow-checks = false
lto = true
panic = "abort"
incremental = false
codegen-units = 1
rpath = false

[profile.test]
opt-level = 0
debug = 2
debug-assertions = true
overflow-checks = true
lto = false
codegen-units = 256
incremental = true

[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]
`}
        </File>
    );
}

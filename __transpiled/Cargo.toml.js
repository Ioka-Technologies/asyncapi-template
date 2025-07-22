'use strict';

require('source-map-support/register');
var jsxRuntime = require('/Users/stevegraham/.nvm/versions/node/v20.0.0/lib/node_modules/@asyncapi/cli/node_modules/@asyncapi/generator-react-sdk/node_modules/react/cjs/react-jsx-runtime.production.min.js');

function CargoToml({
  asyncapi,
  params
}) {
  const info = asyncapi.info();

  // Generate package name from title if not provided
  let defaultPackageName = 'asyncapi-server';
  const title = info.title();
  if (title) {
    const transformed = title.toLowerCase().replace(/[^a-z0-9\s-]/g, '') // Remove non-alphanumeric chars except spaces and hyphens
    .replace(/\s+/g, '-') // Replace spaces with hyphens
    .replace(/-+/g, '-') // Replace multiple hyphens with single hyphen
    .replace(/^-+|-+$/g, ''); // Remove leading/trailing hyphens

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
  const useAsyncStd = params.useAsyncStd === 'true' || params.useAsyncStd === true;

  // Detect protocols from servers
  const servers = asyncapi.servers();
  const protocols = new Set();
  if (servers) {
    Object.entries(servers).forEach(([_name, server]) => {
      const protocol = server.protocol && server.protocol();
      if (protocol) {
        protocols.add(protocol.toLowerCase());
      }
    });
  }

  // Generate protocol-specific dependencies
  let protocolDeps = '';
  if (protocols.has('mqtt') || protocols.has('mqtts')) {
    protocolDeps += 'rumqttc = "0.24"\n';
  }
  if (protocols.has('kafka')) {
    protocolDeps += 'rdkafka = "0.36"\ntokio-stream = "0.1"\n';
  }
  if (protocols.has('amqp') || protocols.has('amqps')) {
    protocolDeps += 'lapin = "2.3"\ntokio-stream = "0.1"\n';
  }
  if (protocols.has('ws') || protocols.has('wss')) {
    if (useAsyncStd) {
      protocolDeps += 'async-tungstenite = "0.24"\nfutures-util = "0.3"\nurl = "2.5"\n';
    } else {
      protocolDeps += 'tokio-tungstenite = "0.21"\nfutures-util = "0.3"\nurl = "2.5"\nbase64 = "0.22"\n';
    }
  }
  if (protocols.has('http') || protocols.has('https')) {
    if (useAsyncStd) {
      protocolDeps += 'tide = "0.16"\n';
    } else {
      protocolDeps += 'axum = "0.7"\ntower = "0.4"\n';
    }
  }

  // Choose async runtime
  const asyncRuntime = useAsyncStd ? 'async-std = { version = "1.12", features = ["attributes"] }' : 'tokio = { version = "1.0", features = ["full"] }';
  const devDeps = useAsyncStd ? 'async-std-test = "0.1"' : 'tokio-test = "0.4"';
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "Cargo.toml",
    children: `[package]
name = "${packageName}"
version = "0.1.0"
edition = "2021"
description = "${info.description() || 'AsyncAPI generated Rust server'}"

[dependencies]
${asyncRuntime}
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
thiserror = "1.0"
tracing = "0.1"
tracing-subscriber = "0.3"
uuid = { version = "1.0", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
async-trait = "0.1"
rand = "0.8"
derive_builder = "0.20"
regex = "1.10"

# Optional dependencies for advanced features
prometheus = { version = "0.13", optional = true }
opentelemetry = { version = "0.21", optional = true }
opentelemetry_sdk = { version = "0.21", optional = true }
opentelemetry-prometheus = { version = "0.14", optional = true }
opentelemetry-jaeger = { version = "0.20", optional = true }
jsonwebtoken = { version = "9.2", optional = true }
deadpool = { version = "0.10", optional = true }
${protocolDeps}

[features]
default = []
prometheus = ["dep:prometheus", "opentelemetry-prometheus"]
opentelemetry = ["dep:opentelemetry", "dep:opentelemetry_sdk"]
auth = ["dep:jsonwebtoken"]
connection-pooling = ["dep:deadpool"]
batching = []
dynamic-config = []
feature-flags = []

[dev-dependencies]
${devDeps}
`
  });
}

module.exports = CargoToml;
//# sourceMappingURL=Cargo.toml.js.map

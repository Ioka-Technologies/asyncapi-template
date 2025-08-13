/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    // Helper function to convert title to kebab-case
    function toKebabCase(str) {
        return str.replace(/[^a-zA-Z0-9]/g, '-')
            .toLowerCase()
            .replace(/-+/g, '-')
            .replace(/^-|-$/g, '');
    }

    // Helper function to convert title to snake_case
    function toSnakeCase(str) {
        return str.replace(/[^a-zA-Z0-9]/g, '_')
            .toLowerCase()
            .replace(/_+/g, '_')
            .replace(/^_|_$/g, '');
    }

    const info = asyncapi.info();
    const title = info.title();
    const description = (info.description() || `Generated Rust NATS client for ${title}`)
        .replace(/"/g, '\\"')
        .replace(/\n/g, ' ')
        .trim();
    const version = info.version();

    // Helper function to check if a parameter contains unresolved template variables
    function isTemplateVariable(value) {
        return typeof value === 'string' && value.includes('{{') && value.includes('}}');
    }

    // Resolve parameters with fallbacks
    const packageName = (params.packageName && !isTemplateVariable(params.packageName))
        ? params.packageName
        : toKebabCase(title) + '-client';
    const packageVersion = (params.packageVersion && !isTemplateVariable(params.packageVersion))
        ? params.packageVersion
        : version;
    const author = (params.author && !isTemplateVariable(params.author))
        ? params.author
        : 'AsyncAPI Generator';
    const license = (params.license && !isTemplateVariable(params.license))
        ? params.license
        : 'Apache-2.0';

    return (
        <File name="Cargo.toml">
            {`[package]
name = "${packageName}"
version = "${packageVersion}"
edition = "2021"
authors = ["${author}"]
license = "${license}"
description = "${description}"
repository = "https://github.com/your-org/${packageName}"
documentation = "https://docs.rs/${packageName}"
keywords = ["asyncapi", "nats", "client", "messaging"]
categories = ["network-programming", "api-bindings"]

[dependencies]
# Core async runtime
tokio = { version = "1.0", features = ["full"] }

# NATS client
async-nats = "0.38"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Utilities
uuid = { version = "1.0", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
bytes = "1.0"

# Authentication support
base64 = "0.21"

# Error handling
thiserror = "1.0"

[dev-dependencies]
tokio-test = "0.4"

[features]
default = []

# Optional features for different authentication methods
jwt = []
oauth = []

[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]
`}
        </File>
    );
};

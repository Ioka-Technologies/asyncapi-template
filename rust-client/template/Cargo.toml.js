/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import {
    toKebabCase,
    toSnakeCase,
    isTemplateVariable,
    extractAsyncApiInfo,
    resolveTemplateParameters
} from './helpers/index.js';

export default function ({ asyncapi, params }) {
    const asyncApiInfo = extractAsyncApiInfo(asyncapi);
    const { title, version, description } = asyncApiInfo;

    const resolvedParams = resolveTemplateParameters(params, asyncApiInfo);
    const { packageName, packageVersion, author, license } = resolvedParams;

    const finalDescription = (description || `Generated Rust NATS client for ${title}`)
        .replace(/"/g, '\\"')
        .replace(/\n/g, ' ')
        .trim();

    return (
        <File name="Cargo.toml">
            {`[package]
name = "${packageName}"
version = "${packageVersion}"
edition = "2021"
authors = ["${author}"]
license = "${license}"
description = "${finalDescription}"
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

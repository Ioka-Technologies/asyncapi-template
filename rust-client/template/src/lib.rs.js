/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import {
    toPascalCase,
    isTemplateVariable,
    extractAsyncApiInfo,
    resolveTemplateParameters
} from '../helpers/index.js';

export default function ({ asyncapi, params }) {
    const asyncApiInfo = extractAsyncApiInfo(asyncapi);
    const { title, version, description } = asyncApiInfo;

    const resolvedParams = resolveTemplateParameters(params, asyncApiInfo);
    const { clientName } = resolvedParams;

    // Helper function to format description for Rust doc comments
    function formatDescription(desc) {
        if (!desc) return 'Generated Rust AsyncAPI NATS client';
        return desc.split('\n').map(line => line.trim()).filter(line => line).join('\n//! ');
    }

    return (
        <File name="lib.rs">
            {`#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::empty_line_after_doc_comments)]
//! ${title}
//!
//! ${formatDescription(description)}
//!
//! This crate provides a type-safe NATS client generated from an AsyncAPI specification.
//! It supports both request/reply and pub/sub messaging patterns using the NATS protocol.
//!
//! # Features
//!
//! - **Type Safety**: All message types are generated from AsyncAPI schemas
//! - **NATS Integration**: Uses the official async-nats client library
//! - **Request/Reply**: Supports NATS request/reply patterns for synchronous operations
//! - **Pub/Sub**: Supports NATS publish/subscribe patterns for asynchronous messaging
//! - **Message Envelope**: Consistent message format with metadata and correlation IDs
//! - **Error Handling**: Comprehensive error types for different failure scenarios
//!
//! # Quick Start
//!
//! \`\`\`ignore
//! use async_nats;
//! use ${params.packageName?.replace(/-/g, '_') || 'your_crate'}::${clientName};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to NATS server
//!     let nats_client = async_nats::connect("nats://localhost:4222").await?;
//!
//!     // Create the generated client
//!     let client = ${clientName}::with(nats_client);
//!
//!     // Use the client for operations...
//!
//!     Ok(())
//! }
//! \`\`\`
//!
//! # Authentication
//!
//! The client accepts any configured \`async-nats::Client\`, allowing you to handle
//! authentication at the NATS level:
//!
//! \`\`\`ignore
//! // JWT authentication
//! let nats_client = async_nats::ConnectOptions::new()
//!     .credentials_file("./service.creds").await?
//!     .connect("nats://server:4222").await?;
//!
//! let client = ${clientName}::with(nats_client);
//! \`\`\`
//!
//! # Generated from AsyncAPI
//!
//! - **AsyncAPI Version**: ${asyncapi.version()}
//! - **Generated**: ${new Date().toISOString()}
//! - **Title**: ${title}
//! - **Version**: ${version}

pub mod auth;
pub mod client;
pub mod envelope;
pub mod errors;
pub mod models;

// Re-export main types for convenience
pub use auth::{AuthCredentials, generate_auth_headers};
pub use client::${clientName};
pub use envelope::MessageEnvelope;
pub use errors::{ClientError, ClientResult};

// Re-export all models
pub use models::*;

#[cfg(test)]
mod tests {
    #[test]
    fn test_client_creation() {
        // This test requires a NATS client, so we'll just test compilation
        // In real usage, you would create an async-nats::Client first
    }
}
`}
        </File>
    );
};

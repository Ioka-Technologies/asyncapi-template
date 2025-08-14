/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function LibRs({ asyncapi, params }) {
    // Check if auth feature is enabled
    const enableAuth = params.enableAuth === 'true' || params.enableAuth === true;
    const info = asyncapi.info();
    const title = info.title();

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

    return (
        <File name="lib.rs">
            {`#![allow(dead_code, unused_imports)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::empty_line_after_doc_comments)]
#![doc = "AsyncAPI generated Rust library for ${title}"]
//!
//! This library provides a complete AsyncAPI server implementation with support for
//! multiple protocols and transports. It can be used as a standalone library or
//! with the provided binary for quick deployment.
//!
//! # Features
//!
//! - Multiple protocol support (HTTP, WebSocket, MQTT, Kafka, AMQP)
//! - Configurable middleware pipeline
//! - Built-in authentication and authorization
//! - Error recovery and resilience
//! - Built-in metrics and tracing
//!
//! # Quick Start
//!
//! \`\`\`no-run
//! use ${title.toLowerCase().replace(/[^a-z0-9]/g, '_')}_lib::{Config, Server};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::from_env()?;
//!     let server = Server::new(config).await?;
//!     server.start().await?;
//!     Ok(())
//! }
//! \`\`\`

// Core modules${enableAuth ? `
#[cfg(feature = "auth")]
pub mod auth;` : ''}
pub mod config;
pub mod context;
pub mod errors;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod recovery;
pub mod server;
pub mod transport;

// Public re-exports for easy access
pub use config::Config;
pub use server::{Server, ServerBuilder, AutoServerBuilder, HealthStatus, ComponentHealth};
pub use errors::{AsyncApiError, AsyncApiResult};
pub use context::ContextManager;
pub use handlers::HandlerRegistry;
pub use middleware::MiddlewarePipeline;
pub use recovery::RecoveryManager;

// Re-export commonly used types
pub use models::*;

// Re-export authentication types when feature is enabled${enableAuth ? `
#[cfg(feature = "auth")]
pub use auth::AuthConfig;
#[cfg(feature = "auth")]
pub use auth::config::{JwtConfig, JwtAlgorithm, RateLimitConfig, SessionConfig};
#[cfg(feature = "auth")]
pub use auth::rbac::{Permission, Role, RoleManager};` : ''}

// Transport re-exports
pub use transport::{Transport, TransportConfig, TransportManager, MessageHandler, TransportMessage, MessageMetadata, ConnectionState, TransportStats};
pub use transport::factory::TransportFactory;

// Prelude module for convenient imports
pub mod prelude {
    //! Convenient re-exports of commonly used types and traits

    pub use crate::{
        Config,
        Server,
        ServerBuilder,
        AutoServerBuilder,
        AsyncApiError,
        AsyncApiResult,
        ContextManager,
        HandlerRegistry,
        MiddlewarePipeline,
        RecoveryManager,
        HealthStatus,
        ComponentHealth,
    };

${enableAuth ? `    #[cfg(feature = "auth")]
    pub use crate::auth::AuthConfig;
    #[cfg(feature = "auth")]
    pub use crate::auth::config::{JwtConfig, JwtAlgorithm};` : ''}

    pub use crate::transport::{Transport, TransportConfig, TransportManager};
    pub use crate::transport::factory::TransportFactory;
}

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Get library information
pub fn library_info() -> LibraryInfo {
    LibraryInfo {
        name: NAME,
        version: VERSION,
        description: env!("CARGO_PKG_DESCRIPTION"),
    }
}

/// Library information structure
#[derive(Debug, Clone)]
pub struct LibraryInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_info() {
        let info = library_info();
        assert!(!info.name.is_empty());
        assert!(!info.version.is_empty());
    }
}
`}
        </File>
    );
}

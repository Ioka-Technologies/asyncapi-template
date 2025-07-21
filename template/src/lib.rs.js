import { File } from '@asyncapi/generator-react-sdk';
import { rustModuleName } from '../helpers/rust-helpers';

export default function libFile({ asyncapi, params }) {
    const generateModels = params.generateModels !== false;
    const generateSubscribers = params.generateSubscribers !== false;
    const generatePublishers = params.generatePublishers !== false;

    return (
        <File name="src/lib.rs">
            {`//! # ${asyncapi.info().title()}
//!
//! ${asyncapi.info().description() || 'AsyncAPI generated Rust server'}
//!
//! This library provides a complete server implementation for AsyncAPI specifications.
//! It includes generated message types, handler traits, middleware, routing, and transport layers.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod config;
pub mod context;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod router;
pub mod server;
pub mod transport;
${generateModels ? 'pub mod models;' : ''}

// Re-export commonly used types for server development
pub use config::Config;
pub use context::{MessageContext, RequestResponseContext, ProtocolMetadata};
pub use error::{HandlerError, HandlerResult, MiddlewareError, MiddlewareResult, ErrorKind};
pub use handlers::{HandlerRegistry, MessageHandler, RequestResponseHandler, FireAndForgetHandler};
pub use middleware::{Middleware, MiddlewareStack, LoggingMiddleware, MetricsMiddleware, AuthenticationMiddleware, RateLimitingMiddleware, TracingMiddleware};
pub use router::{MessageRouter, DefaultMessageRouter, RouteInfo};
pub use server::{AsyncApiServer, AsyncApiServerBuilder, ServerState, ServerStats};
pub use transport::{ServerTransport, TransportFactory, MessageHandler as TransportMessageHandler};
${generateModels ? 'pub use models::*;' : ''}

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::config::Config;
    pub use crate::context::MessageContext;
    pub use crate::error::{HandlerError, HandlerResult};
    pub use crate::handlers::{HandlerRegistry, RequestResponseHandler, FireAndForgetHandler};
    pub use crate::middleware::{Middleware, MiddlewareStack};
    pub use crate::server::{AsyncApiServer, AsyncApiServerBuilder};
    ${generateModels ? 'pub use crate::models::*;' : ''}
}

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// AsyncAPI specification version this library was generated from
pub const ASYNCAPI_VERSION: &str = "${asyncapi.version()}";

/// Protocol this library supports
pub const PROTOCOL: &str = "${asyncapi.allServers().get(params.server).protocol()}";

/// Server information
pub const SERVER_INFO: &str = "${asyncapi.info().title()} v${asyncapi.info().version()}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_asyncapi_version() {
        assert!(!ASYNCAPI_VERSION.is_empty());
    }

    #[test]
    fn test_protocol() {
        assert!(!PROTOCOL.is_empty());
    }

    #[test]
    fn test_server_info() {
        assert!(!SERVER_INFO.is_empty());
    }
}
`}
        </File>
    );
}

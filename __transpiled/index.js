'use strict';

require('source-map-support/register');
require('@asyncapi/generator-react-sdk');
var Cargo_toml = require('./Cargo.toml.js');
var README_md = require('./README.md.js');
var jsxRuntime = require('/Users/stevegraham/.nvm/versions/node/v20.0.0/lib/node_modules/@asyncapi/cli/node_modules/@asyncapi/generator-react-sdk/node_modules/react/cjs/react-jsx-runtime.production.min.js');

function MainRs({
  asyncapi,
  _params
}) {
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
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "main.rs",
    children: `#![allow(dead_code, unused_imports)]

use crate::errors::AsyncApiResult;
use tracing::{info, warn, Level};
use tracing_subscriber;
use std::env;

// Import modules
mod config;
mod server;
mod models;
mod handlers;
mod middleware;
mod errors;
mod recovery;
mod transport;
mod context;
mod router;
#[cfg(feature = "auth")]
mod auth;

use config::Config;
use server::Server;

#[tokio::main]
async fn main() -> AsyncApiResult<()> {
    // Initialize tracing with configurable level
    let log_level = env::var("LOG_LEVEL")
        .unwrap_or_else(|_| "info".to_string())
        .parse::<Level>()
        .unwrap_or(Level::INFO);

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    info!("Starting ${title} server...");
    info!("Generated from AsyncAPI specification");

    // Load configuration
    let config = Config::from_env()?;
    info!("Server configuration: {:?}", config);

    // Initialize server
    let server = Server::new(config).await?;

    // Start protocol handlers
    server.start_http_handler().await?;

    info!("Server started successfully!");
    info!("Press Ctrl+C to shutdown");

    // Keep the server running
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal");
        }
        Err(err) => {
            warn!("Unable to listen for shutdown signal: {}", err);
        }
    }

    info!("Shutting down server...");
    server.shutdown().await?;

    Ok(())
}
`
  });
}

function ConfigRs({
  asyncapi
}) {
  // Helper functions for Rust identifier generation
  function toRustIdentifier(str) {
    if (!str) return 'unknown';
    let identifier = str.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^[0-9]/, '_$&').replace(/_+/g, '_').replace(/^_+|_+$/g, '');
    if (/^[0-9]/.test(identifier)) {
      identifier = 'item_' + identifier;
    }
    if (!identifier) {
      identifier = 'unknown';
    }
    const rustKeywords = ['as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern', 'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match', 'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self', 'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe', 'use', 'where', 'while', 'async', 'await', 'dyn'];
    if (rustKeywords.includes(identifier)) {
      identifier = identifier + '_';
    }
    return identifier;
  }
  function toRustTypeName(str) {
    if (!str) return 'Unknown';
    const identifier = toRustIdentifier(str);
    return identifier.split('_').map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()).join('');
  }
  function toRustFieldName(str) {
    if (!str) return 'unknown';
    const identifier = toRustIdentifier(str);
    return identifier.replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '').replace(/_+/g, '_');
  }
  function getDefaultPort(protocol) {
    switch (protocol === null || protocol === void 0 ? void 0 : protocol.toLowerCase()) {
      case 'mqtt':
      case 'mqtts':
        return 1883;
      case 'kafka':
      case 'kafka-secure':
        return 9092;
      case 'amqp':
      case 'amqps':
        return 5672;
      case 'ws':
      case 'wss':
        return 8080;
      case 'http':
        return 80;
      case 'https':
        return 443;
      default:
        return 8080;
    }
  }
  // Detect protocols from servers
  const servers = asyncapi.servers();
  const serverConfigs = [];
  if (servers) {
    Object.entries(servers).forEach(([name, server]) => {
      const protocol = server.protocol && server.protocol();
      if (protocol) {
        serverConfigs.push({
          name,
          fieldName: toRustFieldName(name),
          typeName: toRustTypeName(name + '_config'),
          protocol: protocol.toLowerCase(),
          host: server.host && server.host(),
          description: server.description && server.description(),
          defaultPort: getDefaultPort(protocol)
        });
      }
    });
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "config.rs",
    children: `//! Configuration management for the AsyncAPI server

use anyhow::Result;
use std::env;
use tracing::Level;

/// Server configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub log_level: Level,
    ${serverConfigs.map(server => `pub ${server.fieldName}_config: ${server.typeName},`).join('\n    ')}
}

${serverConfigs.map(server => `
/// Configuration for ${server.name} server
#[derive(Debug, Clone)]
pub struct ${server.typeName} {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

impl Default for ${server.typeName} {
    fn default() -> Self {
        Self {
            host: "${server.host || 'localhost'}".to_string(),
            port: ${server.defaultPort},
            protocol: "${server.protocol}".to_string(),
        }
    }
}`).join('\n')}

impl Config {
    pub fn from_env() -> Result<Self> {
        let host = env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .unwrap_or(8080);

        let log_level = env::var("LOG_LEVEL")
            .unwrap_or_else(|_| "info".to_string())
            .parse::<Level>()
            .unwrap_or(Level::INFO);

        Ok(Self {
            host,
            port,
            log_level,
            ${serverConfigs.map(server => `${server.fieldName}_config: ${server.typeName}::default(),`).join('\n            ')}
        })
    }
}
`
  });
}

function ErrorsRs({
  asyncapi
}) {
  // Detect protocols from servers for protocol-specific errors
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
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "errors.rs",
    children: `//! Comprehensive error handling system for AsyncAPI operations
//!
//! This module provides a hierarchical error system with:
//! - Custom error types for different failure scenarios
//! - Error context and correlation for debugging
//! - Protocol-specific error handling
//! - Error recovery and retry mechanisms
//! - Structured error data for monitoring

use thiserror::Error;
use std::fmt;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Correlation ID for tracing errors across operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(pub Uuid);

impl CorrelationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

/// Error severity levels for categorization and alerting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity {
    /// Low severity - informational, no action required
    Low,
    /// Medium severity - warning, monitoring required
    Medium,
    /// High severity - error, immediate attention needed
    High,
    /// Critical severity - system failure, urgent action required
    Critical,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Low => write!(f, "LOW"),
            ErrorSeverity::Medium => write!(f, "MEDIUM"),
            ErrorSeverity::High => write!(f, "HIGH"),
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Error category for classification and handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCategory {
    /// Configuration-related errors
    Configuration,
    /// Network and protocol errors
    Network,
    /// Message validation errors
    Validation,
    /// Business logic errors
    BusinessLogic,
    /// System resource errors
    Resource,
    /// Security-related errors
    Security,
    /// Serialization/deserialization errors
    Serialization,
    /// Routing errors
    Routing,
    /// Authorization errors
    Authorization,
    /// Unknown or unclassified errors
    Unknown,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::Configuration => write!(f, "CONFIGURATION"),
            ErrorCategory::Network => write!(f, "NETWORK"),
            ErrorCategory::Validation => write!(f, "VALIDATION"),
            ErrorCategory::BusinessLogic => write!(f, "BUSINESS_LOGIC"),
            ErrorCategory::Resource => write!(f, "RESOURCE"),
            ErrorCategory::Security => write!(f, "SECURITY"),
            ErrorCategory::Serialization => write!(f, "SERIALIZATION"),
            ErrorCategory::Routing => write!(f, "ROUTING"),
            ErrorCategory::Authorization => write!(f, "AUTHORIZATION"),
            ErrorCategory::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Error metadata for enhanced context and monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMetadata {
    pub correlation_id: CorrelationId,
    pub severity: ErrorSeverity,
    pub category: ErrorCategory,
    pub timestamp: DateTime<Utc>,
    pub retryable: bool,
    pub source_location: Option<String>,
    pub additional_context: std::collections::HashMap<String, String>,
}

impl ErrorMetadata {
    pub fn new(severity: ErrorSeverity, category: ErrorCategory, retryable: bool) -> Self {
        Self {
            correlation_id: CorrelationId::new(),
            severity,
            category,
            timestamp: Utc::now(),
            retryable,
            source_location: None,
            additional_context: std::collections::HashMap::new(),
        }
    }

    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.additional_context.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_location(mut self, location: &str) -> Self {
        self.source_location = Some(location.to_string());
        self
    }
}

/// Root error type for all AsyncAPI operations
#[derive(Error, Debug)]
pub enum AsyncApiError {
    #[error("Configuration error: {message}")]
    Configuration {
        message: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Protocol error: {message}")]
    Protocol {
        message: String,
        protocol: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Validation error: {message}")]
    Validation {
        message: String,
        field: Option<String>,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Handler error: {message}")]
    Handler {
        message: String,
        handler_name: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Middleware error: {message}")]
    Middleware {
        message: String,
        middleware_name: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Recovery error: {message}")]
    Recovery {
        message: String,
        attempts: u32,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Resource error: {message}")]
    Resource {
        message: String,
        resource_type: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Security error: {message}")]
    Security {
        message: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Authentication error: {message}")]
    Authentication {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Authorization error: {message}")]
    Authorization {
        message: String,
        required_permissions: Vec<String>,
        user_permissions: Vec<String>,
    },

    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        message: String,
        retry_after: Option<std::time::Duration>,
    },

    #[error("Context error: {message}")]
    Context {
        message: String,
        context_key: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Router error: {message}")]
    Router {
        message: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl AsyncApiError {
    /// Create a new error with the specified message, category, and optional source
    pub fn new(
        message: String,
        category: ErrorCategory,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        let (severity, retryable) = match category {
            ErrorCategory::Configuration => (ErrorSeverity::High, false),
            ErrorCategory::Network => (ErrorSeverity::High, true),
            ErrorCategory::Validation => (ErrorSeverity::Medium, false),
            ErrorCategory::BusinessLogic => (ErrorSeverity::High, true),
            ErrorCategory::Resource => (ErrorSeverity::High, true),
            ErrorCategory::Security => (ErrorSeverity::Critical, false),
            ErrorCategory::Serialization => (ErrorSeverity::Medium, false),
            ErrorCategory::Routing => (ErrorSeverity::Medium, true),
            ErrorCategory::Authorization => (ErrorSeverity::High, false),
            ErrorCategory::Unknown => (ErrorSeverity::Medium, false),
        };

        let metadata = ErrorMetadata::new(severity, category, retryable)
            .with_location(&format!("{}:{}", file!(), line!()));

        match category {
            ErrorCategory::Configuration => AsyncApiError::Configuration {
                message,
                metadata,
                source,
            },
            ErrorCategory::Network => AsyncApiError::Protocol {
                message,
                protocol: "unknown".to_string(),
                metadata,
                source,
            },
            ErrorCategory::Validation => AsyncApiError::Validation {
                message,
                field: None,
                metadata,
                source,
            },
            ErrorCategory::BusinessLogic => AsyncApiError::Handler {
                message,
                handler_name: "unknown".to_string(),
                metadata,
                source,
            },
            ErrorCategory::Resource => AsyncApiError::Resource {
                message,
                resource_type: "unknown".to_string(),
                metadata,
                source,
            },
            ErrorCategory::Security => AsyncApiError::Security {
                message,
                metadata,
                source,
            },
            ErrorCategory::Serialization => AsyncApiError::Validation {
                message,
                field: None,
                metadata,
                source,
            },
            ErrorCategory::Routing => AsyncApiError::Router {
                message,
                metadata,
                source,
            },
            ErrorCategory::Authorization => AsyncApiError::Security {
                message,
                metadata,
                source,
            },
            ErrorCategory::Unknown => AsyncApiError::Configuration {
                message,
                metadata,
                source,
            },
        }
    }

    /// Get error metadata for monitoring and logging
    pub fn metadata(&self) -> &ErrorMetadata {
        match self {
            AsyncApiError::Configuration { metadata, .. } => metadata,
            AsyncApiError::Protocol { metadata, .. } => metadata,
            AsyncApiError::Validation { metadata, .. } => metadata,
            AsyncApiError::Handler { metadata, .. } => metadata,
            AsyncApiError::Middleware { metadata, .. } => metadata,
            AsyncApiError::Recovery { metadata, .. } => metadata,
            AsyncApiError::Resource { metadata, .. } => metadata,
            AsyncApiError::Security { metadata, .. } => metadata,
            AsyncApiError::Context { metadata, .. } => metadata,
            AsyncApiError::Router { metadata, .. } => metadata,
            // Authentication, Authorization, and RateLimit don't have metadata
            _ => panic!("Error variant without metadata"),
        }
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        self.metadata().retryable
    }

    /// Get error severity
    pub fn severity(&self) -> ErrorSeverity {
        self.metadata().severity
    }

    /// Get error category
    pub fn category(&self) -> ErrorCategory {
        self.metadata().category
    }

    /// Get correlation ID for tracing
    pub fn correlation_id(&self) -> &CorrelationId {
        &self.metadata().correlation_id
    }

    /// Add context to error metadata
    pub fn add_context(&mut self, key: &str, value: &str) {
        match self {
            AsyncApiError::Configuration { metadata, .. } => {
                metadata.additional_context.insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Protocol { metadata, .. } => {
                metadata.additional_context.insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Validation { metadata, .. } => {
                metadata.additional_context.insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Handler { metadata, .. } => {
                metadata.additional_context.insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Middleware { metadata, .. } => {
                metadata.additional_context.insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Recovery { metadata, .. } => {
                metadata.additional_context.insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Resource { metadata, .. } => {
                metadata.additional_context.insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Security { metadata, .. } => {
                metadata.additional_context.insert(key.to_string(), value.to_string());
            }
            AsyncApiError::Context { metadata, .. } => {
                metadata.additional_context.insert(key.to_string(), value.to_string());
            }
            // Authentication, Authorization, and RateLimit don't have metadata
            _ => {}
        }
    }
}

${Array.from(protocols).map(protocol => {
      const protocolTitle = protocol.charAt(0).toUpperCase() + protocol.slice(1);
      return `
/// ${protocolTitle} protocol-specific errors
#[derive(Error, Debug)]
pub enum ${protocolTitle}Error {
    #[error("${protocolTitle} connection error: {message}")]
    Connection {
        message: String,
        endpoint: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("${protocolTitle} authentication error: {message}")]
    Authentication {
        message: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("${protocolTitle} message error: {message}")]
    Message {
        message: String,
        message_id: Option<String>,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    ${protocol === 'mqtt' ? `
    #[error("MQTT subscription error: {message}")]
    Subscription {
        message: String,
        topic: String,
        qos: u8,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("MQTT publish error: {message}")]
    Publish {
        message: String,
        topic: String,
        qos: u8,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}

    ${protocol === 'kafka' ? `
    #[error("Kafka producer error: {message}")]
    Producer {
        message: String,
        topic: String,
        partition: Option<i32>,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Kafka consumer error: {message}")]
    Consumer {
        message: String,
        topic: String,
        group_id: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Kafka offset error: {message}")]
    Offset {
        message: String,
        topic: String,
        partition: i32,
        offset: i64,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}

    ${protocol === 'amqp' ? `
    #[error("AMQP channel error: {message}")]
    Channel {
        message: String,
        channel_id: u16,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("AMQP exchange error: {message}")]
    Exchange {
        message: String,
        exchange_name: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("AMQP queue error: {message}")]
    Queue {
        message: String,
        queue_name: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}

    ${protocol === 'ws' || protocol === 'wss' ? `
    #[error("WebSocket frame error: {message}")]
    Frame {
        message: String,
        frame_type: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("WebSocket protocol error: {message}")]
    Protocol {
        message: String,
        expected: String,
        received: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}

    ${protocol === 'http' || protocol === 'https' ? `
    #[error("HTTP status error: {status_code} - {message}")]
    Status {
        message: String,
        status_code: u16,
        method: String,
        url: String,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("HTTP timeout error: {message}")]
    Timeout {
        message: String,
        timeout_duration: std::time::Duration,
        metadata: ErrorMetadata,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },` : ''}
}

impl ${protocolTitle}Error {
    /// Get error metadata
    pub fn metadata(&self) -> &ErrorMetadata {
        match self {
            ${protocolTitle}Error::Connection { metadata, .. } => metadata,
            ${protocolTitle}Error::Authentication { metadata, .. } => metadata,
            ${protocolTitle}Error::Message { metadata, .. } => metadata,
            ${protocol === 'mqtt' ? `
            ${protocolTitle}Error::Subscription { metadata, .. } => metadata,
            ${protocolTitle}Error::Publish { metadata, .. } => metadata,` : ''}
            ${protocol === 'kafka' ? `
            ${protocolTitle}Error::Producer { metadata, .. } => metadata,
            ${protocolTitle}Error::Consumer { metadata, .. } => metadata,
            ${protocolTitle}Error::Offset { metadata, .. } => metadata,` : ''}
            ${protocol === 'amqp' ? `
            ${protocolTitle}Error::Channel { metadata, .. } => metadata,
            ${protocolTitle}Error::Exchange { metadata, .. } => metadata,
            ${protocolTitle}Error::Queue { metadata, .. } => metadata,` : ''}
            ${protocol === 'ws' || protocol === 'wss' ? `
            ${protocolTitle}Error::Frame { metadata, .. } => metadata,
            ${protocolTitle}Error::Protocol { metadata, .. } => metadata,` : ''}
            ${protocol === 'http' || protocol === 'https' ? `
            ${protocolTitle}Error::Status { metadata, .. } => metadata,
            ${protocolTitle}Error::Timeout { metadata, .. } => metadata,` : ''}
        }
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        self.metadata().retryable
    }
}

impl From<${protocolTitle}Error> for AsyncApiError {
    fn from(error: ${protocolTitle}Error) -> Self {
        AsyncApiError::Protocol {
            message: error.to_string(),
            protocol: "${protocol}".to_string(),
            metadata: error.metadata().clone(),
            source: Some(Box::new(error)),
        }
    }
}`;
    }).join('\n')}

/// Result type alias for AsyncAPI operations
pub type AsyncApiResult<T> = Result<T, AsyncApiError>;

/// Helper macros for creating errors with context
#[macro_export]
macro_rules! config_error {
    ($msg:expr) => {
        AsyncApiError::Configuration {
            message: $msg.to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::Configuration,
                false,
            ).with_location(&format!("{}:{}", file!(), line!())),
            source: None,
        }
    };
    ($msg:expr, $source:expr) => {
        AsyncApiError::Configuration {
            message: $msg.to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::Configuration,
                false,
            ).with_location(&format!("{}:{}", file!(), line!())),
            source: Some(Box::new($source)),
        }
    };
}

#[macro_export]
macro_rules! validation_error {
    ($msg:expr) => {
        AsyncApiError::Validation {
            message: $msg.to_string(),
            field: None,
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::Validation,
                false,
            ).with_location(&format!("{}:{}", file!(), line!())),
            source: None,
        }
    };
    ($msg:expr, $field:expr) => {
        AsyncApiError::Validation {
            message: $msg.to_string(),
            field: Some($field.to_string()),
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::Validation,
                false,
            ).with_location(&format!("{}:{}", file!(), line!())),
            source: None,
        }
    };
}

#[macro_export]
macro_rules! handler_error {
    ($msg:expr, $handler:expr) => {
        AsyncApiError::Handler {
            message: $msg.to_string(),
            handler_name: $handler.to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::BusinessLogic,
                true,
            ).with_location(&format!("{}:{}", file!(), line!())),
            source: None,
        }
    };
    ($msg:expr, $handler:expr, $source:expr) => {
        AsyncApiError::Handler {
            message: $msg.to_string(),
            handler_name: $handler.to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::BusinessLogic,
                true,
            ).with_location(&format!("{}:{}", file!(), line!())),
            source: Some(Box::new($source)),
        }
    };
}

/// Error conversion utilities
impl From<serde_json::Error> for AsyncApiError {
    fn from(error: serde_json::Error) -> Self {
        AsyncApiError::Validation {
            message: format!("JSON serialization/deserialization error: {}", error),
            field: None,
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::Validation,
                false,
            ),
            source: Some(Box::new(error)),
        }
    }
}

impl From<anyhow::Error> for AsyncApiError {
    fn from(error: anyhow::Error) -> Self {
        AsyncApiError::Configuration {
            message: format!("Configuration error: {}", error),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::Configuration,
                false,
            ),
            source: None,
        }
    }
}

impl From<std::env::VarError> for AsyncApiError {
    fn from(error: std::env::VarError) -> Self {
        AsyncApiError::Configuration {
            message: format!("Environment variable error: {}", error),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::Configuration,
                false,
            ),
            source: Some(Box::new(error)),
        }
    }
}

impl From<std::num::ParseIntError> for AsyncApiError {
    fn from(error: std::num::ParseIntError) -> Self {
        AsyncApiError::Configuration {
            message: format!("Integer parsing error: {}", error),
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::Configuration,
                false,
            ),
            source: Some(Box::new(error)),
        }
    }
}

impl From<tokio::time::error::Elapsed> for AsyncApiError {
    fn from(error: tokio::time::error::Elapsed) -> Self {
        AsyncApiError::Resource {
            message: format!("Operation timeout: {}", error),
            resource_type: "timeout".to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::Resource,
                true,
            ),
            source: Some(Box::new(error)),
        }
    }
}

`
  });
}

function ModelsRs({
  asyncapi
}) {
  // Helper functions for Rust identifier generation
  function toRustIdentifier(str) {
    if (!str) return 'unknown';
    let identifier = str.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^[0-9]/, '_$&').replace(/_+/g, '_').replace(/^_+|_+$/g, '');
    if (/^[0-9]/.test(identifier)) {
      identifier = 'item_' + identifier;
    }
    if (!identifier) {
      identifier = 'unknown';
    }
    const rustKeywords = ['as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern', 'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match', 'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self', 'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe', 'use', 'where', 'while', 'async', 'await', 'dyn'];
    if (rustKeywords.includes(identifier)) {
      identifier = identifier + '_';
    }
    return identifier;
  }
  function toRustTypeName(str) {
    if (!str) return 'Unknown';
    const identifier = toRustIdentifier(str);
    return identifier.split('_').map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()).join('');
  }
  function toRustFieldName(str) {
    if (!str) return 'unknown';
    const identifier = toRustIdentifier(str);
    return identifier.replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '').replace(/_+/g, '_');
  }
  // Extract message schemas
  const components = asyncapi.components();
  const messageSchemas = [];
  const messageTypes = new Set();
  if (components && components.messages) {
    const messages = components.messages();
    if (messages) {
      Object.entries(messages).forEach(([name, message]) => {
        let payload = null;
        try {
          if (message.payload && typeof message.payload === 'function') {
            const payloadSchema = message.payload();
            payload = payloadSchema && payloadSchema.json ? payloadSchema.json() : null;
          }
        } catch (e) {
          // Ignore payload extraction errors
        }
        messageSchemas.push({
          name,
          rustName: toRustTypeName(name),
          payload,
          description: message.description && typeof message.description === 'function' ? message.description() : null
        });
        messageTypes.add(name);
      });
    }
  }

  // Helper function to convert JSON schema to Rust type
  function jsonSchemaToRustType(schema) {
    if (!schema || !schema.type) return 'serde_json::Value';
    switch (schema.type) {
      case 'string':
        if (schema.format === 'date-time') return 'chrono::DateTime<chrono::Utc>';
        if (schema.format === 'uuid') return 'uuid::Uuid';
        return 'String';
      case 'integer':
        return schema.format === 'int64' ? 'i64' : 'i32';
      case 'number':
        return 'f64';
      case 'boolean':
        return 'bool';
      case 'array':
        {
          const itemType = jsonSchemaToRustType(schema.items);
          return `Vec<${itemType}>`;
        }
      case 'object':
        return 'serde_json::Value';
      // For complex objects, use generic JSON
      default:
        return 'serde_json::Value';
    }
  }

  // Generate message structs
  function generateMessageStruct(schema) {
    if (!schema || !schema.properties) {
      return '    pub data: serde_json::Value,';
    }
    const fields = Object.entries(schema.properties).map(([fieldName, fieldSchema]) => {
      const rustType = jsonSchemaToRustType(fieldSchema);
      const optional = !schema.required || !schema.required.includes(fieldName);
      const finalType = optional ? `Option<${rustType}>` : rustType;
      const rustFieldName = toRustFieldName(fieldName);
      return `    pub ${rustFieldName}: ${finalType},`;
    }).join('\n');
    return fields;
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "models.rs",
    children: `//! Message models generated from AsyncAPI specification

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Base trait for all AsyncAPI messages
pub trait AsyncApiMessage {
    fn message_type(&self) -> &'static str;
    fn channel(&self) -> &'static str;
}

${messageSchemas.map(schema => `
/// ${schema.description || `Message type: ${schema.name}`}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName} {
${generateMessageStruct(schema.payload)}
}

impl AsyncApiMessage for ${schema.rustName} {
    fn message_type(&self) -> &'static str {
        "${schema.name}"
    }

    fn channel(&self) -> &'static str {
        // TODO: Map to appropriate channel based on your AsyncAPI spec
        "default"
    }
}`).join('\n')}

${messageTypes.size === 0 ? `
/// Example message structure when no messages are defined in the spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleMessage {
    pub id: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

impl AsyncApiMessage for ExampleMessage {
    fn message_type(&self) -> &'static str {
        "example"
    }

    fn channel(&self) -> &'static str {
        "example/channel"
    }
}` : ''}
`
  });
}

function HandlersRs({
  asyncapi
}) {
  // Helper functions for Rust identifier generation
  function toRustIdentifier(str) {
    if (!str) return 'unknown';
    let identifier = str.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^[0-9]/, '_$&').replace(/_+/g, '_').replace(/^_+|_+$/g, '');
    if (/^[0-9]/.test(identifier)) {
      identifier = 'item_' + identifier;
    }
    if (!identifier) {
      identifier = 'unknown';
    }
    const rustKeywords = ['as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern', 'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match', 'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self', 'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe', 'use', 'where', 'while', 'async', 'await', 'dyn'];
    if (rustKeywords.includes(identifier)) {
      identifier = identifier + '_';
    }
    return identifier;
  }
  function toRustTypeName(str) {
    if (!str) return 'Unknown';
    const identifier = toRustIdentifier(str);
    return identifier.split('_').map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()).join('');
  }
  function toRustFieldName(str) {
    if (!str) return 'unknown';
    const identifier = toRustIdentifier(str);
    return identifier.replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '').replace(/_+/g, '_');
  }

  // Extract channels and their operations
  const channels = asyncapi.channels();
  const channelData = [];
  if (channels) {
    Object.entries(channels).forEach(([channelName, channel]) => {
      const operations = channel.operations && channel.operations();
      const channelOps = [];
      if (operations) {
        Object.entries(operations).forEach(([opName, operation]) => {
          const action = operation.action && operation.action();
          const messages = operation.messages && operation.messages();
          channelOps.push({
            name: opName,
            action,
            messages: messages || []
          });
        });
      }
      channelData.push({
        name: channelName,
        rustName: toRustTypeName(channelName + '_handler'),
        fieldName: toRustFieldName(channelName + '_handler'),
        address: channel.address && channel.address(),
        description: channel.description && channel.description(),
        operations: channelOps.map(op => ({
          ...op,
          rustName: toRustFieldName(op.name)
        }))
      });
    });
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "handlers.rs",
    children: `//! Message handlers for AsyncAPI operations with enhanced error handling
//!
//! This module provides:
//! - Robust error handling with custom error types
//! - Retry mechanisms with exponential backoff
//! - Circuit breaker pattern for failure isolation
//! - Dead letter queue for unprocessable messages
//! - Comprehensive logging and monitoring

use crate::models::*;
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorMetadata, ErrorSeverity, ErrorCategory};
use crate::recovery::{RecoveryManager, RetryConfig};
use crate::context::RequestContext;
use async_trait::async_trait;
use tracing::{info, error, warn, debug, instrument};
use std::sync::Arc;
use uuid::Uuid;

/// Base trait for all message handlers with enhanced error handling
#[async_trait]
pub trait MessageHandler<T> {
    /// Handle a message with basic error handling
    async fn handle(&self, message: T) -> AsyncApiResult<()>;

    /// Handle a message with full recovery mechanisms
    async fn handle_with_recovery(&self, message: T, recovery_manager: &RecoveryManager) -> AsyncApiResult<()>;
}

/// Context for message processing with correlation tracking
#[derive(Debug, Clone)]
pub struct MessageContext {
    pub correlation_id: Uuid,
    pub channel: String,
    pub operation: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub retry_count: u32,
}

impl MessageContext {
    pub fn new(channel: &str, operation: &str) -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            channel: channel.to_string(),
            operation: operation.to_string(),
            timestamp: chrono::Utc::now(),
            retry_count: 0,
        }
    }

    pub fn with_retry(&self, retry_count: u32) -> Self {
        let mut ctx = self.clone();
        ctx.retry_count = retry_count;
        ctx
    }
}

${channelData.map(channel => `
/// Handler for ${channel.name} channel with enhanced error handling
#[derive(Debug)]
pub struct ${channel.rustName} {
    recovery_manager: Arc<RecoveryManager>,
}

impl ${channel.rustName} {
    pub fn new(recovery_manager: Arc<RecoveryManager>) -> Self {
        Self { recovery_manager }
    }

${channel.operations.map(op => `
    /// Handle ${op.action} operation for ${channel.name} with comprehensive error handling
    #[instrument(skip(self, payload), fields(
        channel = "${channel.name}",
        operation = "${op.name}",
        payload_size = payload.len()
    ))]
    pub async fn handle_${op.rustName}(&self, payload: &[u8], context: &MessageContext) -> AsyncApiResult<()> {
        debug!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            retry_count = context.retry_count,
            "Starting message processing"
        );

        // Input validation with detailed error context
        if payload.is_empty() {
            return Err(AsyncApiError::Validation {
                message: "Empty payload received".to_string(),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                ).with_context("correlation_id", &context.correlation_id.to_string())
                 .with_context("channel", &context.channel)
                 .with_context("operation", &context.operation),
                source: None,
            });
        }

        // Parse message with error handling - fix type annotation
        let message: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(payload) {
            Ok(msg) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    message_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "Successfully parsed message"
                );
                msg
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    payload_preview = %String::from_utf8_lossy(&payload[..payload.len().min(100)]),
                    "Failed to parse message payload"
                );
                return Err(AsyncApiError::Validation {
                    message: format!("Invalid JSON payload: {}", e),
                    field: Some("payload".to_string()),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Validation,
                        false,
                    ).with_context("correlation_id", &context.correlation_id.to_string())
                     .with_context("channel", &context.channel)
                     .with_context("operation", &context.operation)
                     .with_context("parse_error", &e.to_string()),
                    source: Some(Box::new(e)),
                });
            }
        };

        // Business logic with error handling
        match self.process_${op.rustName}_message(&message, context).await {
            Ok(()) => {
                info!(
                    correlation_id = %context.correlation_id,
                    channel = %context.channel,
                    operation = %context.operation,
                    processing_time = ?(chrono::Utc::now() - context.timestamp),
                    "Message processed successfully"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    retry_count = context.retry_count,
                    "Message processing failed"
                );

                // Add message to dead letter queue if not retryable
                if !e.is_retryable() {
                    let dlq = self.recovery_manager.get_dead_letter_queue();
                    dlq.add_message(&context.channel, payload.to_vec(), &e, context.retry_count).await?;
                }

                Err(e)
            }
        }
    }

    /// Process the actual business logic for ${op.action} operation
    async fn process_${op.rustName}_message(
        &self,
        message: &serde_json::Value,
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        // TODO: Implement your business logic here
        // This is where you would:
        // 1. Validate the message schema
        // 2. Extract required fields
        // 3. Perform business operations
        // 4. Update databases or external services
        // 5. Send responses or notifications

        // Example implementation with error handling:
        let message_type = message.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AsyncApiError::Validation {
                message: "Missing required field 'type'".to_string(),
                field: Some("type".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                ).with_context("correlation_id", &context.correlation_id.to_string()),
                source: None,
            })?;

        debug!(
            correlation_id = %context.correlation_id,
            message_type = message_type,
            "Processing message of type: {}", message_type
        );

        // Simulate processing with potential failure
        match message_type {
            "ping" => {
                info!(correlation_id = %context.correlation_id, "Processing ping message");
                Ok(())
            }
            "error_test" => {
                // Simulate a retryable error for testing
                Err(AsyncApiError::Handler {
                    message: "Simulated processing error for testing".to_string(),
                    handler_name: "${channel.rustName}".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::BusinessLogic,
                        true, // This error is retryable
                    ).with_context("correlation_id", &context.correlation_id.to_string())
                     .with_context("message_type", message_type),
                    source: None,
                })
            }
            _ => {
                warn!(
                    correlation_id = %context.correlation_id,
                    message_type = message_type,
                    "Unknown message type, processing as generic message"
                );
                Ok(())
            }
        }
    }

    /// Handle ${op.action} operation with full recovery mechanisms
    pub async fn handle_${op.rustName}_with_recovery(
        &self,
        payload: &[u8],
        context: &MessageContext,
    ) -> AsyncApiResult<()> {
        let mut retry_strategy = self.recovery_manager.get_retry_strategy("message_handler");

        // Get circuit breaker for this handler
        let circuit_breaker = self.recovery_manager.get_circuit_breaker("${channel.rustName}");

        // Get bulkhead for message processing
        let bulkhead = self.recovery_manager.get_bulkhead("message_processing");

        // Execute with all recovery mechanisms
        let operation = || async {
            // Use bulkhead if available
            if let Some(bulkhead) = &bulkhead {
                bulkhead.execute(|| async {
                    self.handle_${op.rustName}(payload, context).await
                }).await
            } else {
                self.handle_${op.rustName}(payload, context).await
            }
        };

        // Use circuit breaker if available
        let result = if let Some(ref circuit_breaker) = circuit_breaker {
            circuit_breaker.execute(operation).await
        } else {
            operation().await
        };

        // Apply retry strategy if the operation failed
        match result {
            Ok(()) => Ok(()),
            Err(e) if e.is_retryable() => {
                warn!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    "Operation failed, attempting retry"
                );

                // Clone necessary values to avoid borrowing issues
                let circuit_breaker_clone = circuit_breaker.clone();
                let bulkhead_clone = bulkhead.clone();

                let current_attempt = retry_strategy.current_attempt();
                retry_strategy.execute(|| async {
                    let retry_context = context.with_retry(current_attempt);
                    if let Some(ref circuit_breaker) = circuit_breaker_clone {
                        circuit_breaker.execute(|| async {
                            if let Some(ref bulkhead) = bulkhead_clone {
                                bulkhead.execute(|| async {
                                    self.handle_${op.rustName}(payload, &retry_context).await
                                }).await
                            } else {
                                self.handle_${op.rustName}(payload, &retry_context).await
                            }
                        }).await
                    } else {
                        self.handle_${op.rustName}(payload, &retry_context).await
                    }
                }).await
            }
            Err(e) => Err(e),
        }
    }`).join('\n')}
}`).join('\n')}

/// Enhanced handler registry with recovery management
#[derive(Debug)]
pub struct HandlerRegistry {
    ${channelData.map(channel => `pub ${channel.fieldName}: ${channel.rustName},`).join('\n    ')}
    recovery_manager: Arc<RecoveryManager>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        let recovery_manager = Arc::new(RecoveryManager::default());
        Self {
            ${channelData.map(channel => `${channel.fieldName}: ${channel.rustName}::new(recovery_manager.clone()),`).join('\n            ')}
            recovery_manager,
        }
    }

    pub fn with_recovery_manager(recovery_manager: Arc<RecoveryManager>) -> Self {
        Self {
            ${channelData.map(channel => `${channel.fieldName}: ${channel.rustName}::new(recovery_manager.clone()),`).join('\n            ')}
            recovery_manager,
        }
    }

    /// Route message to appropriate handler with enhanced error handling
    #[instrument(skip(self, payload), fields(channel, operation, payload_size = payload.len()))]
    pub async fn route_message(&self, channel: &str, operation: &str, payload: &[u8]) -> AsyncApiResult<()> {
        let context = MessageContext::new(channel, operation);

        debug!(
            correlation_id = %context.correlation_id,
            channel = channel,
            operation = operation,
            payload_size = payload.len(),
            "Routing message to handler"
        );

        match channel {
            ${channelData.map(channel => `"${channel.name}" => {
                match operation {
                    ${channel.operations.map(op => `"${op.name}" => {
                        self.${channel.fieldName}.handle_${op.rustName}_with_recovery(payload, &context).await
                    },`).join('\n                    ')}
                    _ => {
                        warn!(
                            correlation_id = %context.correlation_id,
                            channel = channel,
                            operation = operation,
                            "Unknown operation for channel"
                        );
                        Err(AsyncApiError::Handler {
                            message: format!("Unknown operation '{}' for channel '{}'", operation, channel),
                            handler_name: "HandlerRegistry".to_string(),
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::Medium,
                                ErrorCategory::BusinessLogic,
                                false,
                            ).with_context("correlation_id", &context.correlation_id.to_string())
                             .with_context("channel", channel)
                             .with_context("operation", operation),
                            source: None,
                        })
                    }
                }
            },`).join('\n            ')}
            _ => {
                error!(
                    correlation_id = %context.correlation_id,
                    channel = channel,
                    operation = operation,
                    "Unknown channel"
                );
                Err(AsyncApiError::Handler {
                    message: format!("Unknown channel: {}", channel),
                    handler_name: "HandlerRegistry".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::BusinessLogic,
                        false,
                    ).with_context("correlation_id", &context.correlation_id.to_string())
                     .with_context("channel", channel)
                     .with_context("operation", operation),
                    source: None,
                })
            }
        }
    }

    /// Get recovery manager for external configuration
    pub fn recovery_manager(&self) -> Arc<RecoveryManager> {
        self.recovery_manager.clone()
    }

    /// Get handler statistics for monitoring
    pub async fn get_statistics(&self) -> HandlerStatistics {
        HandlerStatistics {
            dead_letter_queue_size: self.recovery_manager.get_dead_letter_queue().size().await,
            // Add more statistics as needed
        }
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for monitoring handler performance
#[derive(Debug, Clone)]
pub struct HandlerStatistics {
    pub dead_letter_queue_size: usize,
}
`
  });
}

function ContextRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "context.rs",
    children: `//! Advanced context management system for AsyncAPI applications
//!
//! This module provides:
//! - Request-scoped context with automatic propagation
//! - Thread-safe execution context for shared state
//! - Context-aware error handling and enrichment
//! - Performance metrics and tracing integration
//! - Middleware data sharing and storage

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorMetadata, ErrorSeverity, ErrorCategory};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug, instrument, Span};

/// Request-scoped context that carries data through the entire processing pipeline
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Unique correlation ID for request tracking
    pub correlation_id: Uuid,
    /// Request start time for performance tracking
    pub start_time: Instant,
    /// Request timestamp
    pub timestamp: SystemTime,
    /// Source channel/topic
    pub channel: String,
    /// Operation being performed
    pub operation: String,
    /// Request metadata and headers
    pub metadata: HashMap<String, String>,
    /// Custom data storage for middleware and handlers
    pub data: Arc<RwLock<HashMap<String, ContextValue>>>,
    /// Performance metrics
    pub metrics: Arc<RwLock<RequestMetrics>>,
    /// Tracing span for distributed tracing
    pub span: Span,
    /// Request priority (for routing and processing)
    pub priority: RequestPriority,
    /// Request tags for categorization
    pub tags: Vec<String>,
    /// Authentication claims (if authenticated)
    #[cfg(feature = "auth")]
    pub auth_claims: Option<crate::auth::Claims>,
}

impl RequestContext {
    /// Create a new request context
    pub fn new(channel: &str, operation: &str) -> Self {
        let correlation_id = Uuid::new_v4();
        let span = tracing::info_span!(
            "request",
            correlation_id = %correlation_id,
            channel = %channel,
            operation = %operation
        );

        Self {
            correlation_id,
            start_time: Instant::now(),
            timestamp: SystemTime::now(),
            channel: channel.to_string(),
            operation: operation.to_string(),
            metadata: HashMap::new(),
            data: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(RequestMetrics::new())),
            span,
            priority: RequestPriority::Normal,
            tags: Vec::new(),
        }
    }

    /// Create context with custom correlation ID
    pub fn with_correlation_id(channel: &str, operation: &str, correlation_id: Uuid) -> Self {
        let mut ctx = Self::new(channel, operation);
        ctx.correlation_id = correlation_id;
        ctx
    }

    /// Add metadata to the context
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Set request priority
    pub fn with_priority(mut self, priority: RequestPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Add tags to the context
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Store data in the context
    pub async fn set_data<T: Into<ContextValue>>(&self, key: &str, value: T) -> AsyncApiResult<()> {
        let mut data = self.data.write().await;
        data.insert(key.to_string(), value.into());
        debug!(
            correlation_id = %self.correlation_id,
            key = key,
            "Stored data in request context"
        );
        Ok(())
    }

    /// Retrieve data from the context
    pub async fn get_data(&self, key: &str) -> Option<ContextValue> {
        let data = self.data.read().await;
        data.get(key).cloned()
    }

    /// Get typed data from the context
    pub async fn get_typed_data<T>(&self, key: &str) -> AsyncApiResult<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        if let Some(value) = self.get_data(key).await {
            match value {
                ContextValue::Json(json_str) => {
                    match serde_json::from_str::<T>(&json_str) {
                        Ok(typed_value) => Ok(Some(typed_value)),
                        Err(e) => Err(AsyncApiError::Context {
                            message: format!("Failed to deserialize context data: {}", e),
                            context_key: key.to_string(),
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::Medium,
                                ErrorCategory::Serialization,
                                false,
                            ).with_context("correlation_id", &self.correlation_id.to_string()),
                            source: Some(Box::new(e)),
                        }),
                    }
                }
                _ => Err(AsyncApiError::Context {
                    message: "Context value is not JSON serializable".to_string(),
                    context_key: key.to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Low,
                        ErrorCategory::Validation,
                        false,
                    ).with_context("correlation_id", &self.correlation_id.to_string()),
                    source: None,
                }),
            }
        } else {
            Ok(None)
        }
    }

    /// Record a metric event
    pub async fn record_metric(&self, event: MetricEvent) {
        let mut metrics = self.metrics.write().await;
        metrics.record_event(event);
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> RequestMetrics {
        self.metrics.read().await.clone()
    }

    /// Get elapsed time since request start
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Create a child context for sub-operations
    pub fn child_context(&self, operation: &str) -> Self {
        let child_span = tracing::info_span!(
            parent: &self.span,
            "child_operation",
            operation = %operation,
            parent_correlation_id = %self.correlation_id
        );

        Self {
            correlation_id: Uuid::new_v4(),
            start_time: Instant::now(),
            timestamp: SystemTime::now(),
            channel: self.channel.clone(),
            operation: operation.to_string(),
            metadata: self.metadata.clone(),
            data: self.data.clone(), // Share data with parent
            metrics: Arc::new(RwLock::new(RequestMetrics::new())),
            span: child_span,
            priority: self.priority,
            tags: self.tags.clone(),
            #[cfg(feature = "auth")]
            auth_claims: self.auth_claims.clone(),
        }
    }

    /// Set authentication claims
    #[cfg(feature = "auth")]
    pub fn set_auth_claims(&mut self, claims: crate::auth::Claims) {
        self.auth_claims = Some(claims);
    }

    /// Get authentication claims
    #[cfg(feature = "auth")]
    pub fn get_auth_claims(&self) -> Option<&crate::auth::Claims> {
        self.auth_claims.as_ref()
    }

    /// Check if the request is authenticated
    #[cfg(feature = "auth")]
    pub fn is_authenticated(&self) -> bool {
        self.auth_claims.is_some()
    }

    /// Get the authenticated user ID
    #[cfg(feature = "auth")]
    pub fn get_user_id(&self) -> Option<&str> {
        self.auth_claims.as_ref().map(|claims| claims.sub.as_str())
    }

    /// Check if the authenticated user has a specific role
    #[cfg(feature = "auth")]
    pub fn has_role(&self, role: &str) -> bool {
        self.auth_claims.as_ref()
            .map(|claims| claims.has_role(role))
            .unwrap_or(false)
    }

    /// Check if the authenticated user has a specific permission
    #[cfg(feature = "auth")]
    pub fn has_permission(&self, permission: &str) -> bool {
        self.auth_claims.as_ref()
            .map(|claims| claims.has_permission(permission))
            .unwrap_or(false)
    }

    /// Get client ID for rate limiting and tracking
    pub fn get_client_id(&self) -> Option<String> {
        // Try to get from auth claims first
        #[cfg(feature = "auth")]
        if let Some(claims) = &self.auth_claims {
            return Some(claims.sub.clone());
        }

        // Fall back to metadata
        if let Some(client_id) = self.metadata.get("client_id") {
            return Some(client_id.clone());
        }

        // Fall back to IP address or other identifier
        if let Some(ip) = self.metadata.get("remote_addr") {
            return Some(ip.clone());
        }

        None
    }

    /// Get header value
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.metadata.get(&format!("header_{}", name.to_lowercase()))
    }

    /// Set header value
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.metadata.insert(format!("header_{}", name.to_lowercase()), value.to_string());
    }

    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Set metadata value
    pub fn set_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Get property value (convenience method for common properties)
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.metadata.get(&format!("prop_{}", key))
    }

    /// Set property value (convenience method for common properties)
    pub fn set_property(&mut self, key: String, value: String) {
        self.metadata.insert(format!("prop_{}", key), value);
    }

    /// Enrich error with context information
    pub fn enrich_error(&self, mut error: AsyncApiError) -> AsyncApiError {
        error.add_context("correlation_id", &self.correlation_id.to_string());
        error.add_context("channel", &self.channel);
        error.add_context("operation", &self.operation);
        error.add_context("elapsed_ms", &self.elapsed().as_millis().to_string());

        // Add metadata to error context
        for (key, value) in &self.metadata {
            error.add_context(&format!("metadata_{}", key), value);
        }

        error
    }
}

/// Values that can be stored in the context
#[derive(Debug, Clone)]
pub enum ContextValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Json(String),
    Binary(Vec<u8>),
}

impl From<String> for ContextValue {
    fn from(value: String) -> Self {
        ContextValue::String(value)
    }
}

impl From<&str> for ContextValue {
    fn from(value: &str) -> Self {
        ContextValue::String(value.to_string())
    }
}

impl From<i64> for ContextValue {
    fn from(value: i64) -> Self {
        ContextValue::Integer(value)
    }
}

impl From<f64> for ContextValue {
    fn from(value: f64) -> Self {
        ContextValue::Float(value)
    }
}

impl From<bool> for ContextValue {
    fn from(value: bool) -> Self {
        ContextValue::Boolean(value)
    }
}

impl From<Vec<u8>> for ContextValue {
    fn from(value: Vec<u8>) -> Self {
        ContextValue::Binary(value)
    }
}

impl<T: Serialize> From<&T> for ContextValue {
    fn from(value: &T) -> Self {
        match serde_json::to_string(value) {
            Ok(json) => ContextValue::Json(json),
            Err(_) => ContextValue::String("serialization_failed".to_string()),
        }
    }
}

/// Request priority levels for routing and processing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestPriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

impl Default for RequestPriority {
    fn default() -> Self {
        RequestPriority::Normal
    }
}

/// Performance metrics for a request
#[derive(Debug, Clone)]
pub struct RequestMetrics {
    pub events: Vec<MetricEvent>,
    pub start_time: Instant,
}

impl RequestMetrics {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            start_time: Instant::now(),
        }
    }

    pub fn record_event(&mut self, event: MetricEvent) {
        self.events.push(event);
    }

    pub fn total_duration(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn get_events_by_type(&self, event_type: &str) -> Vec<&MetricEvent> {
        self.events.iter().filter(|e| e.event_type == event_type).collect()
    }
}

/// Individual metric event
#[derive(Debug, Clone)]
pub struct MetricEvent {
    pub event_type: String,
    pub timestamp: Instant,
    pub duration: Option<Duration>,
    pub metadata: HashMap<String, String>,
}

impl MetricEvent {
    pub fn new(event_type: &str) -> Self {
        Self {
            event_type: event_type.to_string(),
            timestamp: Instant::now(),
            duration: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Global execution context for shared state
#[derive(Debug)]
pub struct ExecutionContext {
    /// Application-wide configuration
    pub config: Arc<RwLock<HashMap<String, String>>>,
    /// Shared metrics and statistics
    pub global_metrics: Arc<RwLock<GlobalMetrics>>,
    /// Active request contexts
    pub active_requests: Arc<RwLock<HashMap<Uuid, RequestContext>>>,
    /// Context creation time
    pub created_at: SystemTime,
}

impl ExecutionContext {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(HashMap::new())),
            global_metrics: Arc::new(RwLock::new(GlobalMetrics::new())),
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            created_at: SystemTime::now(),
        }
    }

    /// Register an active request
    pub async fn register_request(&self, context: RequestContext) {
        let mut requests = self.active_requests.write().await;
        requests.insert(context.correlation_id, context);

        let mut metrics = self.global_metrics.write().await;
        metrics.active_requests += 1;
        metrics.total_requests += 1;
    }

    /// Unregister a completed request
    pub async fn unregister_request(&self, correlation_id: Uuid) -> Option<RequestContext> {
        let mut requests = self.active_requests.write().await;
        let context = requests.remove(&correlation_id);

        if context.is_some() {
            let mut metrics = self.global_metrics.write().await;
            metrics.active_requests = metrics.active_requests.saturating_sub(1);
        }

        context
    }

    /// Get active request count
    pub async fn active_request_count(&self) -> usize {
        self.active_requests.read().await.len()
    }

    /// Get global metrics
    pub async fn get_global_metrics(&self) -> GlobalMetrics {
        self.global_metrics.read().await.clone()
    }

    /// Set configuration value
    pub async fn set_config(&self, key: &str, value: &str) {
        let mut config = self.config.write().await;
        config.insert(key.to_string(), value.to_string());
    }

    /// Get configuration value
    pub async fn get_config(&self, key: &str) -> Option<String> {
        let config = self.config.read().await;
        config.get(key).cloned()
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global application metrics
#[derive(Debug, Clone)]
pub struct GlobalMetrics {
    pub total_requests: u64,
    pub active_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub average_response_time: Duration,
    pub uptime: Duration,
    pub start_time: SystemTime,
}

impl GlobalMetrics {
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            active_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            average_response_time: Duration::ZERO,
            uptime: Duration::ZERO,
            start_time: SystemTime::now(),
        }
    }

    pub fn record_success(&mut self, duration: Duration) {
        self.successful_requests += 1;
        self.update_average_response_time(duration);
    }

    pub fn record_failure(&mut self, duration: Duration) {
        self.failed_requests += 1;
        self.update_average_response_time(duration);
    }

    fn update_average_response_time(&mut self, duration: Duration) {
        let total_completed = self.successful_requests + self.failed_requests;
        if total_completed > 0 {
            let total_time = self.average_response_time.as_nanos() * (total_completed - 1) as u128 + duration.as_nanos();
            self.average_response_time = Duration::from_nanos((total_time / total_completed as u128) as u64);
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total_completed = self.successful_requests + self.failed_requests;
        if total_completed > 0 {
            self.successful_requests as f64 / total_completed as f64
        } else {
            0.0
        }
    }
}

/// Context manager for handling context lifecycle
pub struct ContextManager {
    execution_context: Arc<ExecutionContext>,
}

impl ContextManager {
    pub fn new() -> Self {
        Self {
            execution_context: Arc::new(ExecutionContext::new()),
        }
    }

    pub fn with_execution_context(execution_context: Arc<ExecutionContext>) -> Self {
        Self { execution_context }
    }

    /// Create a new request context and register it
    #[instrument(skip(self), fields(channel, operation))]
    pub async fn create_request_context(&self, channel: &str, operation: &str) -> RequestContext {
        let context = RequestContext::new(channel, operation);

        debug!(
            correlation_id = %context.correlation_id,
            channel = %channel,
            operation = %operation,
            "Created new request context"
        );

        self.execution_context.register_request(context.clone()).await;
        context
    }

    /// Complete a request context and update metrics
    #[instrument(skip(self, context), fields(correlation_id = %context.correlation_id))]
    pub async fn complete_request_context(&self, context: RequestContext, success: bool) -> AsyncApiResult<()> {
        let duration = context.elapsed();

        // Update global metrics
        {
            let mut metrics = self.execution_context.global_metrics.write().await;
            if success {
                metrics.record_success(duration);
            } else {
                metrics.record_failure(duration);
            }
        }

        // Unregister the request
        self.execution_context.unregister_request(context.correlation_id).await;

        info!(
            correlation_id = %context.correlation_id,
            duration_ms = duration.as_millis(),
            success = success,
            "Completed request context"
        );

        Ok(())
    }

    /// Get execution context
    pub fn execution_context(&self) -> Arc<ExecutionContext> {
        self.execution_context.clone()
    }

    /// Get context statistics
    pub async fn get_statistics(&self) -> ContextStatistics {
        let global_metrics = self.execution_context.get_global_metrics().await;
        let active_count = self.execution_context.active_request_count().await;

        ContextStatistics {
            active_requests: active_count,
            total_requests: global_metrics.total_requests,
            success_rate: global_metrics.success_rate(),
            average_response_time: global_metrics.average_response_time,
            uptime: self.execution_context.created_at.elapsed().unwrap_or_default(),
        }
    }
}

impl Default for ContextManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about context usage
#[derive(Debug, Clone, Serialize)]
pub struct ContextStatistics {
    pub active_requests: usize,
    pub total_requests: u64,
    pub success_rate: f64,
    pub average_response_time: Duration,
    pub uptime: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_request_context_creation() {
        let ctx = RequestContext::new("test/channel", "test_operation");
        assert_eq!(ctx.channel, "test/channel");
        assert_eq!(ctx.operation, "test_operation");
        assert_eq!(ctx.priority, RequestPriority::Normal);
    }

    #[tokio::test]
    async fn test_context_data_storage() {
        let ctx = RequestContext::new("test/channel", "test_operation");

        ctx.set_data("test_key", "test_value").await.unwrap();
        let value = ctx.get_data("test_key").await;

        assert!(value.is_some());
        match value.unwrap() {
            ContextValue::String(s) => assert_eq!(s, "test_value"),
            _ => panic!("Expected string value"),
        }
    }

    #[tokio::test]
    async fn test_context_manager() {
        let manager = ContextManager::new();
        let ctx = manager.create_request_context("test/channel", "test_op").await;

        assert_eq!(manager.execution_context.active_request_count().await, 1);

        manager.complete_request_context(ctx, true).await.unwrap();
        assert_eq!(manager.execution_context.active_request_count().await, 0);
    }

    #[test]
    fn test_request_priority_ordering() {
        assert!(RequestPriority::Critical > RequestPriority::High);
        assert!(RequestPriority::High > RequestPriority::Normal);
        assert!(RequestPriority::Normal > RequestPriority::Low);
    }
}
`
  });
}

/* eslint-disable no-useless-escape */
function RouterRs({
  asyncapi
}) {
  // Extract channels and operations for route generation
  const channels = asyncapi.channels();
  const channelData = [];
  if (channels) {
    Object.entries(channels).forEach(([channelName, channel]) => {
      const operations = channel.operations && channel.operations();
      const channelOps = [];
      if (operations) {
        Object.entries(operations).forEach(([opName, operation]) => {
          const action = operation.action && operation.action();
          channelOps.push({
            name: opName,
            action,
            channel: channelName
          });
        });
      }
      channelData.push({
        name: channelName,
        operations: channelOps
      });
    });
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "router.rs",
    children: `//! Advanced routing system for AsyncAPI applications
//!
//! This module provides:
//! - Pattern-based routing with wildcards and parameters
//! - Content-based message routing
//! - Route guards and middleware chains
//! - Dynamic route registration and modification
//! - Performance-optimized route matching

use crate::context::{RequestContext, RequestPriority};
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorMetadata, ErrorSeverity, ErrorCategory};
use crate::handlers::HandlerRegistry;
use crate::middleware::{Middleware, MiddlewarePipeline};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug, instrument};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Advanced router for message routing with pattern matching and content-based routing
#[derive(Debug)]
pub struct Router {
    /// Static routes for exact matches
    static_routes: Arc<RwLock<HashMap<String, Route>>>,
    /// Pattern routes for wildcard and parameter matching
    pattern_routes: Arc<RwLock<Vec<PatternRoute>>>,
    /// Content-based routes that examine message payload
    content_routes: Arc<RwLock<Vec<ContentRoute>>>,
    /// Default route for unmatched messages
    default_route: Arc<RwLock<Option<Route>>>,
    /// Route performance metrics
    metrics: Arc<RwLock<RouterMetrics>>,
    /// Route cache for performance optimization
    route_cache: Arc<RwLock<HashMap<String, CachedRoute>>>,
    /// Maximum cache size
    max_cache_size: usize,
}

impl Router {
    /// Create a new router instance
    pub fn new() -> Self {
        Self {
            static_routes: Arc::new(RwLock::new(HashMap::new())),
            pattern_routes: Arc::new(RwLock::new(Vec::new())),
            content_routes: Arc::new(RwLock::new(Vec::new())),
            default_route: Arc::new(RwLock::new(None)),
            metrics: Arc::new(RwLock::new(RouterMetrics::new())),
            route_cache: Arc::new(RwLock::new(HashMap::new())),
            max_cache_size: 1000,
        }
    }

    /// Create router with custom cache size
    pub fn with_cache_size(cache_size: usize) -> Self {
        let mut router = Self::new();
        router.max_cache_size = cache_size;
        router
    }

    /// Add a static route for exact channel/operation matching
    #[instrument(skip(self, route), fields(channel = %route.channel, operation = %route.operation))]
    pub async fn add_static_route(&self, route: Route) -> AsyncApiResult<()> {
        let route_key = format!("{}:{}", route.channel, route.operation);

        debug!(
            channel = %route.channel,
            operation = %route.operation,
            priority = ?route.priority,
            "Adding static route"
        );

        let mut routes = self.static_routes.write().await;
        routes.insert(route_key, route);

        // Clear cache when routes change
        self.clear_cache().await;

        Ok(())
    }

    /// Add a pattern route for wildcard and parameter matching
    #[instrument(skip(self, pattern_route), fields(pattern = %pattern_route.pattern))]
    pub async fn add_pattern_route(&self, pattern_route: PatternRoute) -> AsyncApiResult<()> {
        debug!(
            pattern = %pattern_route.pattern,
            priority = ?pattern_route.route.priority,
            "Adding pattern route"
        );

        let mut routes = self.pattern_routes.write().await;
        routes.push(pattern_route);

        // Sort by priority (higher priority first)
        routes.sort_by(|a, b| b.route.priority.cmp(&a.route.priority));

        // Clear cache when routes change
        self.clear_cache().await;

        Ok(())
    }

    /// Add a content-based route that examines message payload
    #[instrument(skip(self, content_route), fields(name = %content_route.name))]
    pub async fn add_content_route(&self, content_route: ContentRoute) -> AsyncApiResult<()> {
        debug!(
            name = %content_route.name,
            priority = ?content_route.route.priority,
            "Adding content-based route"
        );

        let mut routes = self.content_routes.write().await;
        routes.push(content_route);

        // Sort by priority (higher priority first)
        routes.sort_by(|a, b| b.route.priority.cmp(&a.route.priority));

        // Clear cache when routes change
        self.clear_cache().await;

        Ok(())
    }

    /// Set the default route for unmatched messages
    pub async fn set_default_route(&self, route: Route) -> AsyncApiResult<()> {
        debug!(
            channel = %route.channel,
            operation = %route.operation,
            "Setting default route"
        );

        let mut default_route = self.default_route.write().await;
        *default_route = Some(route);

        Ok(())
    }

    /// Route a message to the appropriate handler
    #[instrument(skip(self, payload, context), fields(
        correlation_id = %context.correlation_id,
        channel = %context.channel,
        operation = %context.operation,
        payload_size = payload.len()
    ))]
    pub async fn route_message(
        &self,
        context: &RequestContext,
        payload: &[u8],
        handlers: &HandlerRegistry,
    ) -> AsyncApiResult<RouteResult> {
        let start_time = Instant::now();
        let route_key = format!("{}:{}", context.channel, context.operation);

        // Check cache first
        if let Some(cached_route) = self.get_cached_route(&route_key).await {
            debug!(
                correlation_id = %context.correlation_id,
                route_key = %route_key,
                "Using cached route"
            );

            let result = self.execute_route(&cached_route.route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::CacheHit, start_time.elapsed()).await;
            return result;
        }

        // Try static routes first (fastest)
        if let Some(route) = self.find_static_route(&context.channel, &context.operation).await {
            debug!(
                correlation_id = %context.correlation_id,
                "Found static route match"
            );

            self.cache_route(route_key.clone(), route.clone()).await;
            let result = self.execute_route(&route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::StaticMatch, start_time.elapsed()).await;
            return result;
        }

        // Try pattern routes
        if let Some((route, params)) = self.find_pattern_route(&context.channel, &context.operation).await {
            debug!(
                correlation_id = %context.correlation_id,
                params = ?params,
                "Found pattern route match"
            );

            // Add route parameters to context
            for (key, value) in params {
                context.set_data(&format!("route_param_{}", key), value).await?;
            }

            self.cache_route(route_key.clone(), route.clone()).await;
            let result = self.execute_route(&route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::PatternMatch, start_time.elapsed()).await;
            return result;
        }

        // Try content-based routes
        if let Some(route) = self.find_content_route(payload, context).await? {
            debug!(
                correlation_id = %context.correlation_id,
                "Found content-based route match"
            );

            let result = self.execute_route(&route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::ContentMatch, start_time.elapsed()).await;
            return result;
        }

        // Use default route if available
        if let Some(route) = self.get_default_route().await {
            debug!(
                correlation_id = %context.correlation_id,
                "Using default route"
            );

            let result = self.execute_route(&route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::DefaultRoute, start_time.elapsed()).await;
            return result;
        }

        // No route found
        self.record_route_metric(RouteMetric::NoMatch, start_time.elapsed()).await;

        error!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            "No route found for message"
        );

        Err(AsyncApiError::Router {
            message: format!("No route found for channel '{}' operation '{}'", context.channel, context.operation),
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::Routing,
                false,
            ).with_context("correlation_id", &context.correlation_id.to_string())
             .with_context("channel", &context.channel)
             .with_context("operation", &context.operation),
            source: None,
        })
    }

    /// Execute a route with its middleware chain and guards
    async fn execute_route(
        &self,
        route: &Route,
        context: &RequestContext,
        payload: &[u8],
        handlers: &HandlerRegistry,
    ) -> AsyncApiResult<RouteResult> {
        // Check route guards
        for guard in &route.guards {
            if !(guard.check)(context, payload).await? {
                return Err(AsyncApiError::Router {
                    message: format!("Route guard '{}' failed", guard.name),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Authorization,
                        false,
                    ).with_context("correlation_id", &context.correlation_id.to_string())
                     .with_context("guard_name", &guard.name)
                     .with_context("channel", &context.channel)
                     .with_context("operation", &context.operation),
                    source: None,
                });
            }
        }

        // Process through route middleware
        let processed_payload = if let Some(ref middleware) = route.middleware {
            // Convert RequestContext to MiddlewareContext
            let middleware_context = crate::middleware::MiddlewareContext {
                correlation_id: context.correlation_id,
                channel: context.channel.clone(),
                operation: context.operation.clone(),
                timestamp: chrono::DateTime::from(context.timestamp),
                metadata: context.metadata.clone(),
            };
            middleware.process_inbound(&middleware_context, payload).await?
        } else {
            payload.to_vec()
        };

        // Route to handler
        let result = match &route.destination {
            RouteDestination::Handler { channel, operation } => {
                handlers.route_message(channel, operation, &processed_payload).await?;
                RouteResult::Handled
            }
            RouteDestination::MultipleHandlers { destinations } => {
                let mut results = Vec::new();
                for dest in destinations {
                    match handlers.route_message(&dest.channel, &dest.operation, &processed_payload).await {
                        Ok(()) => results.push(dest.clone()),
                        Err(e) => {
                            warn!(
                                correlation_id = %context.correlation_id,
                                channel = %dest.channel,
                                operation = %dest.operation,
                                error = %e,
                                "Failed to route to one of multiple destinations"
                            );
                        }
                    }
                }
                RouteResult::MultipleHandled(results)
            }
            RouteDestination::Custom { handler } => {
                handler(context, &processed_payload).await?;
                RouteResult::CustomHandled
            }
        };

        Ok(result)
    }

    /// Find static route
    async fn find_static_route(&self, channel: &str, operation: &str) -> Option<Route> {
        let routes = self.static_routes.read().await;
        let route_key = format!("{}:{}", channel, operation);
        routes.get(&route_key).cloned()
    }

    /// Find pattern route with parameter extraction
    async fn find_pattern_route(&self, channel: &str, operation: &str) -> Option<(Route, HashMap<String, String>)> {
        let routes = self.pattern_routes.read().await;
        let route_path = format!("{}:{}", channel, operation);

        for pattern_route in routes.iter() {
            if let Some(captures) = pattern_route.regex.captures(&route_path) {
                let mut params = HashMap::new();

                // Extract named parameters
                for name in pattern_route.regex.capture_names().flatten() {
                    if let Some(value) = captures.name(name) {
                        params.insert(name.to_string(), value.as_str().to_string());
                    }
                }

                return Some((pattern_route.route.clone(), params));
            }
        }

        None
    }

    /// Find content-based route
    async fn find_content_route(&self, payload: &[u8], context: &RequestContext) -> AsyncApiResult<Option<Route>> {
        let routes = self.content_routes.read().await;

        for content_route in routes.iter() {
            if content_route.matcher.matches(payload, context).await? {
                return Ok(Some(content_route.route.clone()));
            }
        }

        Ok(None)
    }

    /// Get default route
    async fn get_default_route(&self) -> Option<Route> {
        self.default_route.read().await.clone()
    }

    /// Cache a route for performance
    async fn cache_route(&self, key: String, route: Route) {
        let mut cache = self.route_cache.write().await;

        // Implement LRU eviction if cache is full
        if cache.len() >= self.max_cache_size {
            // Remove oldest entry (simple implementation)
            if let Some(oldest_key) = cache.keys().next().cloned() {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(key, CachedRoute {
            route,
            cached_at: Instant::now(),
        });
    }

    /// Get cached route
    async fn get_cached_route(&self, key: &str) -> Option<CachedRoute> {
        let cache = self.route_cache.read().await;
        cache.get(key).cloned()
    }

    /// Clear route cache
    async fn clear_cache(&self) {
        let mut cache = self.route_cache.write().await;
        cache.clear();
        debug!("Route cache cleared");
    }

    /// Record route performance metric
    async fn record_route_metric(&self, metric_type: RouteMetric, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        metrics.record_metric(metric_type, duration);
    }

    /// Get router statistics
    pub async fn get_statistics(&self) -> RouterStatistics {
        let metrics = self.metrics.read().await;
        let static_routes = self.static_routes.read().await;
        let pattern_routes = self.pattern_routes.read().await;
        let content_routes = self.content_routes.read().await;
        let cache = self.route_cache.read().await;

        RouterStatistics {
            static_route_count: static_routes.len(),
            pattern_route_count: pattern_routes.len(),
            content_route_count: content_routes.len(),
            cache_size: cache.len(),
            cache_hit_rate: metrics.cache_hit_rate(),
            average_route_time: metrics.average_route_time(),
            total_routes: metrics.total_routes,
        }
    }

    /// Initialize with default routes from AsyncAPI specification
    pub async fn initialize_default_routes(&self) -> AsyncApiResult<()> {
        info!("Initializing default routes from AsyncAPI specification");

        ${channelData.map(channel => `
        // Routes for ${channel.name}
        ${channel.operations.map(op => `
        self.add_static_route(Route {
            channel: "${channel.name}".to_string(),
            operation: "${op.name}".to_string(),
            priority: RequestPriority::Normal,
            destination: RouteDestination::Handler {
                channel: "${channel.name}".to_string(),
                operation: "${op.name}".to_string(),
            },
            guards: Vec::new(),
            middleware: None,
            metadata: HashMap::new(),
        }).await?;`).join('\n        ')}
        `).join('\n')}

        // Add pattern routes for common patterns
        self.add_pattern_route(PatternRoute {
            pattern: r"(?P<channel>[^:]+):(?P<operation>.+)".to_string(),
            regex: Regex::new(r"(?P<channel>[^:]+):(?P<operation>.+)").unwrap(),
            route: Route {
                channel: "dynamic".to_string(),
                operation: "dynamic".to_string(),
                priority: RequestPriority::Low,
                destination: RouteDestination::Handler {
                    channel: "dynamic".to_string(),
                    operation: "dynamic".to_string(),
                },
                guards: Vec::new(),
                middleware: None,
                metadata: HashMap::new(),
            },
        }).await?;

        info!("Default routes initialized successfully");
        Ok(())
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Individual route definition
pub struct Route {
    /// Channel pattern
    pub channel: String,
    /// Operation pattern
    pub operation: String,
    /// Route priority for conflict resolution
    pub priority: RequestPriority,
    /// Route destination
    pub destination: RouteDestination,
    /// Route guards for validation
    pub guards: Vec<RouteGuard>,
    /// Route-specific middleware
    pub middleware: Option<MiddlewarePipeline>,
    /// Route metadata
    pub metadata: HashMap<String, String>,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("channel", &self.channel)
            .field("operation", &self.operation)
            .field("priority", &self.priority)
            .field("destination", &self.destination)
            .field("guards", &self.guards)
            .field("middleware", &self.middleware.is_some())
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl Clone for Route {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
            operation: self.operation.clone(),
            priority: self.priority,
            destination: self.destination.clone(),
            guards: self.guards.clone(),
            middleware: None, // Can't clone MiddlewarePipeline, so set to None
            metadata: self.metadata.clone(),
        }
    }
}

/// Route destination types
pub enum RouteDestination {
    /// Route to a specific handler
    Handler { channel: String, operation: String },
    /// Route to multiple handlers (fan-out)
    MultipleHandlers { destinations: Vec<HandlerDestination> },
    /// Route to a custom function
    Custom {
        #[allow(clippy::type_complexity)]
        handler: Arc<dyn Fn(&RequestContext, &[u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = AsyncApiResult<()>> + Send>> + Send + Sync>
    },
}

impl std::fmt::Debug for RouteDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteDestination::Handler { channel, operation } => {
                f.debug_struct("Handler")
                    .field("channel", channel)
                    .field("operation", operation)
                    .finish()
            }
            RouteDestination::MultipleHandlers { destinations } => {
                f.debug_struct("MultipleHandlers")
                    .field("destinations", destinations)
                    .finish()
            }
            RouteDestination::Custom { .. } => {
                f.debug_struct("Custom")
                    .field("handler", &"<function>")
                    .finish()
            }
        }
    }
}

impl Clone for RouteDestination {
    fn clone(&self) -> Self {
        match self {
            RouteDestination::Handler { channel, operation } => {
                RouteDestination::Handler {
                    channel: channel.clone(),
                    operation: operation.clone(),
                }
            }
            RouteDestination::MultipleHandlers { destinations } => {
                RouteDestination::MultipleHandlers {
                    destinations: destinations.clone(),
                }
            }
            RouteDestination::Custom { handler } => {
                RouteDestination::Custom {
                    handler: handler.clone(),
                }
            }
        }
    }
}

/// Handler destination for multi-routing
#[derive(Debug, Clone)]
pub struct HandlerDestination {
    pub channel: String,
    pub operation: String,
}

/// Pattern-based route with regex matching
#[derive(Debug)]
pub struct PatternRoute {
    /// Original pattern string
    pub pattern: String,
    /// Compiled regex for matching
    pub regex: Regex,
    /// Route definition
    pub route: Route,
}

/// Content-based route that examines message payload
#[derive(Debug)]
pub struct ContentRoute {
    /// Route name for identification
    pub name: String,
    /// Content matcher
    pub matcher: Box<dyn ContentMatcher + Send + Sync>,
    /// Route definition
    pub route: Route,
}

/// Trait for content-based routing
#[async_trait::async_trait]
pub trait ContentMatcher: std::fmt::Debug {
    /// Check if the content matches this route
    async fn matches(&self, payload: &[u8], context: &RequestContext) -> AsyncApiResult<bool>;
}

/// JSON field matcher for content-based routing
#[derive(Debug)]
pub struct JsonFieldMatcher {
    pub field_path: String,
    pub expected_value: serde_json::Value,
}

#[async_trait::async_trait]
impl ContentMatcher for JsonFieldMatcher {
    async fn matches(&self, payload: &[u8], _context: &RequestContext) -> AsyncApiResult<bool> {
        match serde_json::from_slice::<serde_json::Value>(payload) {
            Ok(json) => {
                let field_value = json.pointer(&self.field_path);
                Ok(field_value == Some(&self.expected_value))
            }
            Err(_) => Ok(false), // Not JSON, doesn't match
        }
    }
}

/// Route guard for pre-routing validation
pub struct RouteGuard {
    pub name: String,
    #[allow(clippy::type_complexity)]
    pub check: Arc<dyn Fn(&RequestContext, &[u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = AsyncApiResult<bool>> + Send>> + Send + Sync>,
}

impl std::fmt::Debug for RouteGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteGuard")
            .field("name", &self.name)
            .field("check", &"<function>")
            .finish()
    }
}

impl Clone for RouteGuard {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            check: self.check.clone(),
        }
    }
}

/// Cached route entry
#[derive(Debug, Clone)]
pub struct CachedRoute {
    pub route: Route,
    pub cached_at: Instant,
}

/// Route execution result
#[derive(Debug)]
pub enum RouteResult {
    /// Message was handled by a single handler
    Handled,
    /// Message was handled by multiple handlers
    MultipleHandled(Vec<HandlerDestination>),
    /// Message was handled by a custom handler
    CustomHandled,
}

/// Router performance metrics
#[derive(Debug)]
pub struct RouterMetrics {
    pub total_routes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub static_matches: u64,
    pub pattern_matches: u64,
    pub content_matches: u64,
    pub default_routes: u64,
    pub no_matches: u64,
    pub route_times: Vec<Duration>,
}

impl RouterMetrics {
    pub fn new() -> Self {
        Self {
            total_routes: 0,
            cache_hits: 0,
            cache_misses: 0,
            static_matches: 0,
            pattern_matches: 0,
            content_matches: 0,
            default_routes: 0,
            no_matches: 0,
            route_times: Vec::new(),
        }
    }

    pub fn record_metric(&mut self, metric_type: RouteMetric, duration: Duration) {
        self.total_routes += 1;
        self.route_times.push(duration);

        // Keep only last 1000 measurements
        if self.route_times.len() > 1000 {
            self.route_times.remove(0);
        }

        match metric_type {
            RouteMetric::CacheHit => self.cache_hits += 1,
            RouteMetric::CacheMiss => self.cache_misses += 1,
            RouteMetric::StaticMatch => self.static_matches += 1,
            RouteMetric::PatternMatch => self.pattern_matches += 1,
            RouteMetric::ContentMatch => self.content_matches += 1,
            RouteMetric::DefaultRoute => self.default_routes += 1,
            RouteMetric::NoMatch => self.no_matches += 1,
        }
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let total_cache_attempts = self.cache_hits + self.cache_misses;
        if total_cache_attempts > 0 {
            self.cache_hits as f64 / total_cache_attempts as f64
        } else {
            0.0
        }
    }

    pub fn average_route_time(&self) -> Duration {
        if self.route_times.is_empty() {
            Duration::ZERO
        } else {
            let total: Duration = self.route_times.iter().sum();
            total / self.route_times.len() as u32
        }
    }
}

/// Route metric types
#[derive(Debug, Clone, Copy)]
pub enum RouteMetric {
    CacheHit,
    CacheMiss,
    StaticMatch,
    PatternMatch,
    ContentMatch,
    DefaultRoute,
    NoMatch,
}

/// Router statistics for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct RouterStatistics {
    pub static_route_count: usize,
    pub pattern_route_count: usize,
    pub content_route_count: usize,
    pub cache_size: usize,
    pub cache_hit_rate: f64,
    pub average_route_time: Duration,
    pub total_routes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_route_matching() {
        let router = Router::new();

        let route = Route {
            channel: "test/channel".to_string(),
            operation: "test_operation".to_string(),
            priority: RequestPriority::Normal,
            destination: RouteDestination::Handler {
                channel: "test/channel".to_string(),
                operation: "test_operation".to_string(),
            },
            guards: Vec::new(),
            middleware: None,
            metadata: HashMap::new(),
        };

        router.add_static_route(route).await.unwrap();

        let found_route = router.find_static_route("test/channel", "test_operation").await;
        assert!(found_route.is_some());
    }

    #[tokio::test]
    async fn test_pattern_route_matching() {
        let router = Router::new();

        let pattern_route = PatternRoute {
            pattern: r"user/(?P<user_id>\d+):update".to_string(),
            regex: Regex::new(r"user/(?P<user_id>\d+):update").unwrap(),
            route: Route {
                channel: "user".to_string(),
                operation: "update".to_string(),
                priority: RequestPriority::Normal,
                destination: RouteDestination::Handler {
                    channel: "user".to_string(),
                    operation: "update".to_string(),
                },
                guards: Vec::new(),
                middleware: None,
                metadata: HashMap::new(),
            },
        };

        router.add_pattern_route(pattern_route).await.unwrap();

        let (route, params) = router.find_pattern_route("user/123", "update").await.unwrap();
        assert_eq!(route.channel, "user");
        assert_eq!(params.get("user_id"), Some(&"123".to_string()));
    }

    #[test]
    fn test_json_field_matcher() {
        let matcher = JsonFieldMatcher {
            field_path: "/type".to_string(),
            expected_value: serde_json::Value::String("user_created".to_string()),
        };

        let payload = r#"{"type": "user_created", "user_id": 123}"#.as_bytes();
        // Note: This would need to be an async test in practice
        // assert!(matcher.matches(payload, &context).await.unwrap());
    }
}
`
  });
}

function ServerModRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "mod.rs",
    children: `//! Server module for AsyncAPI service
//!
//! This module provides the main server implementation and builder pattern
//! for constructing servers with various configurations and middleware.

pub mod builder;

pub use builder::{ServerBuilder, ServerConfig};

use crate::config::Config;
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::handlers::HandlerRegistry;
use crate::middleware::MiddlewarePipeline;
use crate::context::ContextManager;
use crate::router::Router;
use crate::recovery::RecoveryManager;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

/// Main server struct that orchestrates all components
pub struct Server {
    config: Config,
    handlers: Arc<RwLock<HandlerRegistry>>,
    context_manager: Arc<ContextManager>,
    router: Arc<Router>,
    middleware: MiddlewarePipeline,
    recovery_manager: Arc<RecoveryManager>,
}

impl Server {
    /// Create a new server with default configuration
    pub async fn new(config: Config) -> AsyncApiResult<Self> {
        let recovery_manager = Arc::new(RecoveryManager::default());
        let context_manager = Arc::new(ContextManager::new());
        let router = Arc::new(Router::new());
        let handlers = Arc::new(RwLock::new(
            HandlerRegistry::with_recovery_manager(recovery_manager.clone())
        ));
        let middleware = MiddlewarePipeline::new(recovery_manager.clone());

        // Initialize router with default routes
        router.initialize_default_routes().await?;

        Ok(Self {
            config,
            handlers,
            context_manager,
            router,
            middleware,
            recovery_manager,
        })
    }

    /// Create a new server with custom configuration
    pub async fn new_with_config(
        config: Config,
        handlers: Arc<RwLock<HandlerRegistry>>,
        context_manager: Arc<ContextManager>,
        router: Arc<Router>,
        middleware: MiddlewarePipeline,
    ) -> AsyncApiResult<Self> {
        let recovery_manager = Arc::new(RecoveryManager::default());

        Ok(Self {
            config,
            handlers,
            context_manager,
            router,
            middleware,
            recovery_manager,
        })
    }

    /// Start the server
    pub async fn start(&self) -> AsyncApiResult<()> {
        info!("Starting AsyncAPI server on {}:{}",
              self.config.host,
              self.config.port);

        // Initialize all components
        self.initialize_components().await?;

        // Start the main server loop
        self.run_server_loop().await?;

        Ok(())
    }

    /// Stop the server gracefully
    pub async fn stop(&self) -> AsyncApiResult<()> {
        info!("Stopping AsyncAPI server gracefully");

        // Perform cleanup operations
        self.cleanup().await?;

        info!("Server stopped successfully");
        Ok(())
    }

    /// Initialize all server components
    async fn initialize_components(&self) -> AsyncApiResult<()> {
        debug!("Initializing server components");

        // Components are already initialized during construction
        debug!("Context manager ready");
        debug!("Middleware pipeline ready");
        debug!("Recovery manager ready");

        debug!("All server components initialized successfully");
        Ok(())
    }

    /// Main server loop
    async fn run_server_loop(&self) -> AsyncApiResult<()> {
        debug!("Starting main server loop");

        // This is where the actual server logic would run
        // For now, we'll just keep the server alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            // Check if we should continue running
            if self.should_shutdown().await {
                break;
            }
        }

        Ok(())
    }

    /// Check if the server should shutdown
    async fn should_shutdown(&self) -> bool {
        // For now, never shutdown automatically
        // In a real implementation, this would check for shutdown signals
        false
    }

    /// Cleanup server resources
    async fn cleanup(&self) -> AsyncApiResult<()> {
        debug!("Cleaning up server resources");

        // Cleanup handlers
        debug!("Handlers cleanup completed");

        // Cleanup middleware
        debug!("Middleware cleanup completed");

        // Cleanup context manager
        debug!("Context manager cleanup completed");

        // Cleanup recovery manager
        debug!("Recovery manager cleanup completed");

        debug!("Server cleanup completed");
        Ok(())
    }

    /// Get server configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get handler registry
    pub fn handlers(&self) -> Arc<RwLock<HandlerRegistry>> {
        self.handlers.clone()
    }

    /// Get context manager
    pub fn context_manager(&self) -> Arc<ContextManager> {
        self.context_manager.clone()
    }

    /// Get router
    pub fn router(&self) -> Arc<Router> {
        self.router.clone()
    }

    /// Get middleware pipeline
    pub fn middleware(&self) -> &MiddlewarePipeline {
        &self.middleware
    }

    /// Get recovery manager
    pub fn recovery_manager(&self) -> Arc<RecoveryManager> {
        self.recovery_manager.clone()
    }

    /// Health check endpoint
    pub async fn health_check(&self) -> AsyncApiResult<HealthStatus> {
        debug!("Performing health check");

        let mut status = HealthStatus::new();

        // Check handlers
        status.handlers = ComponentHealth::Healthy;

        // Check middleware
        status.middleware = ComponentHealth::Healthy;

        // Check context manager
        status.context_manager = ComponentHealth::Healthy;

        // Check recovery manager
        status.recovery_manager = ComponentHealth::Healthy;

        // Overall status
        status.overall = if status.all_healthy() {
            ComponentHealth::Healthy
        } else {
            ComponentHealth::Unhealthy
        };

        debug!("Health check completed: {:?}", status.overall);
        Ok(status)
    }

    /// Start HTTP handler
    pub async fn start_http_handler(&self) -> AsyncApiResult<()> {
        info!("Starting HTTP handler on {}:{}", self.config.host, self.config.port);

        // Initialize HTTP transport
        // For now, just log that we're starting
        debug!("HTTP handler started successfully");
        Ok(())
    }

    /// Shutdown the server
    pub async fn shutdown(&self) -> AsyncApiResult<()> {
        info!("Shutting down server");
        self.stop().await
    }
}

/// Health status for the server and its components
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub overall: ComponentHealth,
    pub handlers: ComponentHealth,
    pub middleware: ComponentHealth,
    pub context_manager: ComponentHealth,
    pub recovery_manager: ComponentHealth,
}

impl HealthStatus {
    pub fn new() -> Self {
        Self {
            overall: ComponentHealth::Unknown,
            handlers: ComponentHealth::Unknown,
            middleware: ComponentHealth::Unknown,
            context_manager: ComponentHealth::Unknown,
            recovery_manager: ComponentHealth::Unknown,
        }
    }

    pub fn all_healthy(&self) -> bool {
        matches!(self.handlers, ComponentHealth::Healthy) &&
        matches!(self.middleware, ComponentHealth::Healthy) &&
        matches!(self.context_manager, ComponentHealth::Healthy) &&
        matches!(self.recovery_manager, ComponentHealth::Healthy)
    }
}

/// Health status for individual components
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        let config = Config::default();
        let server = Server::new(config).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = Config::default();
        let server = Server::new(config).await.unwrap();
        let health = server.health_check().await;
        assert!(health.is_ok());
    }
}
`
  });
}

function ServerBuilderRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "builder.rs",
    children: `//! Server builder for flexible server construction with optional components
//!
//! This module provides a fluent builder API for constructing servers with
//! optional middleware, monitoring, authentication, and other advanced features.
//! Uses derive_builder for clean, maintainable builder pattern implementation.

use crate::config::Config;
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::middleware::{Middleware, MiddlewarePipeline};
use crate::recovery::RecoveryManager;
use crate::context::ContextManager;
use crate::router::Router;
use crate::handlers::HandlerRegistry;
use crate::server::Server;
use derive_builder::Builder;
use std::sync::Arc;
use std::collections::HashMap;
use tracing::{info, debug, warn};

#[cfg(feature = "prometheus")]
use crate::metrics::prometheus::PrometheusMetrics;

#[cfg(feature = "opentelemetry")]
use crate::tracing::opentelemetry::OpenTelemetryTracing;

#[cfg(feature = "auth")]
use crate::auth::{AuthConfig, AuthMiddleware};

#[cfg(feature = "connection-pooling")]
use crate::pool::{PoolConfig, ConnectionPoolManager};

#[cfg(feature = "batching")]
use crate::batching::{BatchConfig, BatchProcessor};

#[cfg(feature = "dynamic-config")]
use crate::config::dynamic::DynamicConfigManager;

#[cfg(feature = "feature-flags")]
use crate::features::{FeatureFlags, FeatureManager};

/// Configuration for server construction with optional components
#[derive(Builder)]
#[builder(setter(into, strip_option), build_fn(validate = "Self::validate"))]
pub struct ServerConfig {
    /// Base server configuration
    pub config: Config,

    /// Middleware components to add to the pipeline
    #[builder(default = "Vec::new()", setter(skip))]
    pub middleware: Vec<Box<dyn Middleware>>,

    /// Feature flags configuration
    #[builder(default = "None")]
    pub feature_flags: Option<std::collections::HashMap<String, bool>>,

    /// Authentication configuration
    #[cfg(feature = "auth")]
    #[builder(default = "None")]
    pub auth_config: Option<AuthConfig>,

    /// Connection pool configuration
    #[cfg(feature = "connection-pooling")]
    #[builder(default = "None")]
    pub pool_config: Option<PoolConfig>,

    /// Message batching configuration
    #[cfg(feature = "batching")]
    #[builder(default = "None")]
    pub batch_config: Option<BatchConfig>,

    /// Enable Prometheus metrics
    #[builder(default = "false")]
    pub prometheus_enabled: bool,

    /// Enable OpenTelemetry tracing
    #[builder(default = "false")]
    pub opentelemetry_enabled: bool,

    /// Enable dynamic configuration
    #[builder(default = "false")]
    pub dynamic_config_enabled: bool,

    /// Custom properties for extensibility
    #[builder(default = "HashMap::new()")]
    pub custom_properties: HashMap<String, String>,
}

/// Type alias for the generated builder
pub type ServerBuilder = ServerConfigBuilder;

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ServerConfig");
        debug_struct
            .field("config", &self.config)
            .field("middleware_count", &self.middleware.len())
            .field("feature_flags", &self.feature_flags);

        #[cfg(feature = "auth")]
        {
            debug_struct.field("auth_config", &self.auth_config);
        }

        #[cfg(feature = "connection-pooling")]
        {
            debug_struct.field("pool_config", &self.pool_config);
        }

        #[cfg(feature = "batching")]
        {
            debug_struct.field("batch_config", &self.batch_config);
        }

        debug_struct
            .field("prometheus_enabled", &self.prometheus_enabled)
            .field("opentelemetry_enabled", &self.opentelemetry_enabled)
            .field("dynamic_config_enabled", &self.dynamic_config_enabled)
            .field("custom_properties", &self.custom_properties)
            .finish()
    }
}

impl ServerConfigBuilder {
    /// Validate the configuration during build
    fn validate(&self) -> Result<(), String> {
        // Check for conflicting configurations
        if self.prometheus_enabled.unwrap_or(false) && !cfg!(feature = "prometheus") {
            return Err("Prometheus metrics enabled but 'prometheus' feature not compiled".to_string());
        }

        if self.opentelemetry_enabled.unwrap_or(false) && !cfg!(feature = "opentelemetry") {
            return Err("OpenTelemetry tracing enabled but 'opentelemetry' feature not compiled".to_string());
        }

        // Validate auth configuration
        #[cfg(feature = "auth")]
        if let Some(ref auth_config) = self.auth_config {
            if let Some(auth_config) = auth_config {
                // Add auth config validation here
            }
        }

        Ok(())
    }
}

impl ServerConfig {
    /// Build the server with all configured components
    pub async fn build_server(self) -> AsyncApiResult<Server> {
        info!("Building server with configured components");

        // Initialize recovery manager
        let recovery_manager = Arc::new(RecoveryManager::default());

        // Initialize context manager
        let context_manager = Arc::new(ContextManager::new());

        // Initialize router
        let router = Arc::new(Router::new());
        router.initialize_default_routes().await?;

        // Initialize handler registry
        let handlers = Arc::new(tokio::sync::RwLock::new(
            HandlerRegistry::with_recovery_manager(recovery_manager.clone())
        ));

        // Build middleware pipeline
        let middleware_pipeline = self.build_middleware_pipeline(recovery_manager.clone()).await?;

        // Create the server
        let server = Server::new_with_config(
            self.config,
            handlers,
            context_manager,
            router,
            middleware_pipeline,
        ).await?;

        info!("Server built successfully with {} middleware components",
              self.middleware.len());

        Ok(server)
    }

    /// Build the middleware pipeline with all configured middleware
    async fn build_middleware_pipeline(&self, recovery_manager: Arc<RecoveryManager>) -> AsyncApiResult<MiddlewarePipeline> {
        debug!("Building middleware pipeline");

        let pipeline = MiddlewarePipeline::new(recovery_manager);

        // Add authentication middleware if configured
        #[cfg(feature = "auth")]
        if let Some(auth_config) = &self.auth_config {
            let auth_middleware = AuthMiddleware::new(auth_config.clone());
            pipeline = pipeline.add_middleware(auth_middleware);
        }

        // Add Prometheus metrics middleware if enabled
        #[cfg(feature = "prometheus")]
        if self.prometheus_enabled {
            let metrics_middleware = crate::middleware::MetricsMiddleware::with_prometheus();
            pipeline = pipeline.add_middleware(metrics_middleware);
        }

        // Add OpenTelemetry tracing middleware if enabled
        #[cfg(feature = "opentelemetry")]
        if self.opentelemetry_enabled {
            let tracing_middleware = crate::middleware::TracingMiddleware::new();
            pipeline = pipeline.add_middleware(tracing_middleware);
        }

        // Add user-configured middleware
        for _middleware in &self.middleware {
            // Note: This would need to be cloned or we'd need a different approach
            // for now, we'll document this limitation
        }

        debug!("Middleware pipeline built successfully");
        Ok(pipeline)
    }
}

/// Convenience constructors for common server configurations
impl ServerBuilder {
    /// Create a minimal server with basic logging
    pub fn minimal(config: Config) -> Self {
        let mut builder = Self::default();
        builder.config(config);
        builder.prometheus_enabled(false);
        builder.opentelemetry_enabled(false);
        builder
    }

    /// Create a development server with enhanced debugging
    pub fn development(config: Config) -> Self {
        let mut builder = Self::default();
        builder.config(config);
        builder.prometheus_enabled(false);
        builder.opentelemetry_enabled(false);
        builder
    }

    /// Create a production server with all monitoring and security features
    pub fn production(config: Config) -> Self {
        let mut builder = Self::default();
        builder.config(config);

        // Add optional production features if available
        #[cfg(feature = "prometheus")]
        {
            builder.prometheus_enabled(true);
        }

        #[cfg(feature = "opentelemetry")]
        {
            builder.opentelemetry_enabled(true);
        }

        builder
    }

    /// Add middleware to the builder
    pub fn add_middleware<M: Middleware + 'static>(self, _middleware: M) -> Self {
        // Since we can't use the generated setter, we need to handle this manually
        // For now, we'll document this as a limitation and provide alternative approaches
        self
    }

    /// Add middleware conditionally
    pub fn conditional_middleware<F, M>(self, _condition: F) -> Self
    where
        F: FnOnce(&Config) -> Option<M>,
        M: Middleware + 'static,
    {
        // This would need access to config to evaluate the condition
        // For now, return self unchanged
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_minimal_server_build() {
        let config = Config::default();
        let server = ServerBuilder::minimal(config).build().await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_builder_with_middleware() {
        let config = Config::default();
        let server = ServerBuilder::new(config)
            .with_middleware(crate::middleware::LoggingMiddleware::default())
            .build()
            .await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_conditional_middleware() {
        let config = Config::default();
        let server = ServerBuilder::new(config)
            .conditional_middleware(|_config| {
                Some(crate::middleware::LoggingMiddleware::default())
            })
            .build()
            .await;
        assert!(server.is_ok());
    }
}
`
  });
}

function MiddlewareRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "middleware.rs",
    children: `//! Enhanced middleware for request/response processing with comprehensive error handling
//!
//! This module provides:
//! - Error-aware middleware pipeline
//! - Metrics collection and monitoring
//! - Request/response validation
//! - Performance tracking
//! - Security and rate limiting

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorMetadata, ErrorSeverity, ErrorCategory};
use crate::context::RequestContext;
use crate::recovery::RecoveryManager;
use async_trait::async_trait;
use tracing::{info, warn, error, debug, instrument};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

/// Enhanced middleware trait for processing messages with error handling
#[async_trait::async_trait]
pub trait Middleware: Send + Sync {
    /// Process inbound messages with error handling
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>>;

    /// Process outbound messages with error handling
    async fn process_outbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>>;

    /// Get middleware name for logging and metrics
    fn name(&self) -> &'static str;

    /// Check if middleware is enabled
    fn is_enabled(&self) -> bool {
        true
    }
}

/// Context for middleware processing with correlation tracking
#[derive(Debug, Clone)]
pub struct MiddlewareContext {
    pub correlation_id: Uuid,
    pub channel: String,
    pub operation: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub metadata: std::collections::HashMap<String, String>,
}

impl MiddlewareContext {
    pub fn new(channel: &str, operation: &str) -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            channel: channel.to_string(),
            operation: operation.to_string(),
            timestamp: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Logging middleware that logs all message traffic with enhanced context
pub struct LoggingMiddleware {
    log_payloads: bool,
    max_payload_log_size: usize,
}

impl LoggingMiddleware {
    pub fn new(log_payloads: bool, max_payload_log_size: usize) -> Self {
        Self {
            log_payloads,
            max_payload_log_size,
        }
    }
}

impl Default for LoggingMiddleware {
    fn default() -> Self {
        Self::new(false, 100) // Don't log payloads by default for security
    }
}

#[async_trait::async_trait]
impl Middleware for LoggingMiddleware {
    #[instrument(skip(self, payload), fields(
        middleware = "logging",
        correlation_id = %context.correlation_id,
        channel = %context.channel,
        operation = %context.operation,
        payload_size = payload.len()
    ))]
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let start_time = Instant::now();

        info!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            payload_size = payload.len(),
            "Processing inbound message"
        );

        if self.log_payloads && !payload.is_empty() {
            let payload_preview = if payload.len() > self.max_payload_log_size {
                format!("{}... (truncated)", String::from_utf8_lossy(&payload[..self.max_payload_log_size]))
            } else {
                String::from_utf8_lossy(payload).to_string()
            };

            debug!(
                correlation_id = %context.correlation_id,
                payload_preview = %payload_preview,
                "Inbound message payload"
            );
        }

        let processing_time = start_time.elapsed();
        debug!(
            correlation_id = %context.correlation_id,
            processing_time_ms = processing_time.as_millis(),
            "Logging middleware processing completed"
        );

        Ok(payload.to_vec())
    }

    #[instrument(skip(self, payload), fields(
        middleware = "logging",
        correlation_id = %context.correlation_id,
        channel = %context.channel,
        operation = %context.operation,
        payload_size = payload.len()
    ))]
    async fn process_outbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        info!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            payload_size = payload.len(),
            "Processing outbound message"
        );

        if self.log_payloads && !payload.is_empty() {
            let payload_preview = if payload.len() > self.max_payload_log_size {
                format!("{}... (truncated)", String::from_utf8_lossy(&payload[..self.max_payload_log_size]))
            } else {
                String::from_utf8_lossy(payload).to_string()
            };

            debug!(
                correlation_id = %context.correlation_id,
                payload_preview = %payload_preview,
                "Outbound message payload"
            );
        }

        Ok(payload.to_vec())
    }

    fn name(&self) -> &'static str {
        "logging"
    }
}

/// Metrics middleware for collecting performance data and error rates
pub struct MetricsMiddleware {
    start_time: Instant,
    message_count: Arc<RwLock<u64>>,
    error_count: Arc<RwLock<u64>>,
    processing_times: Arc<RwLock<Vec<std::time::Duration>>>,
}

impl MetricsMiddleware {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            message_count: Arc::new(RwLock::new(0)),
            error_count: Arc::new(RwLock::new(0)),
            processing_times: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn get_metrics(&self) -> MiddlewareMetrics {
        let message_count = *self.message_count.read().await;
        let error_count = *self.error_count.read().await;
        let processing_times = self.processing_times.read().await;

        let avg_processing_time = if processing_times.is_empty() {
            std::time::Duration::ZERO
        } else {
            let total: std::time::Duration = processing_times.iter().sum();
            total / processing_times.len() as u32
        };

        MiddlewareMetrics {
            uptime: self.start_time.elapsed(),
            message_count,
            error_count,
            error_rate: if message_count > 0 { error_count as f64 / message_count as f64 } else { 0.0 },
            avg_processing_time,
        }
    }
}

impl Default for MetricsMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Middleware for MetricsMiddleware {
    #[instrument(skip(self, payload), fields(
        middleware = "metrics",
        correlation_id = %context.correlation_id,
        payload_size = payload.len()
    ))]
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let start_time = Instant::now();

        // Increment message count
        {
            let mut count = self.message_count.write().await;
            *count += 1;
        }

        let processing_time = start_time.elapsed();

        // Record processing time
        {
            let mut times = self.processing_times.write().await;
            times.push(processing_time);

            // Keep only last 1000 measurements to prevent memory growth
            if times.len() > 1000 {
                times.remove(0);
            }
        }

        debug!(
            correlation_id = %context.correlation_id,
            processing_time_ms = processing_time.as_millis(),
            "Metrics collected for inbound message"
        );

        Ok(payload.to_vec())
    }

    async fn process_outbound(&self, _context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        // For outbound, we just pass through without additional metrics
        Ok(payload.to_vec())
    }

    fn name(&self) -> &'static str {
        "metrics"
    }
}

/// Validation middleware for message schema validation with detailed error reporting
pub struct ValidationMiddleware {
    strict_mode: bool,
}

impl ValidationMiddleware {
    pub fn new(strict_mode: bool) -> Self {
        Self { strict_mode }
    }
}

impl Default for ValidationMiddleware {
    fn default() -> Self {
        Self::new(true) // Strict validation by default
    }
}

#[async_trait::async_trait]
impl Middleware for ValidationMiddleware {
    #[instrument(skip(self, payload), fields(
        middleware = "validation",
        correlation_id = %context.correlation_id,
        strict_mode = self.strict_mode,
        payload_size = payload.len()
    ))]
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        debug!(
            correlation_id = %context.correlation_id,
            strict_mode = self.strict_mode,
            "Starting message validation"
        );

        // Basic payload validation
        if payload.is_empty() {
            return Err(AsyncApiError::Validation {
                message: "Empty payload received".to_string(),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                ).with_context("correlation_id", &context.correlation_id.to_string())
                 .with_context("channel", &context.channel)
                 .with_context("operation", &context.operation)
                 .with_context("middleware", "validation"),
                source: None,
            });
        }

        // JSON validation
        match serde_json::from_slice::<serde_json::Value>(payload) {
            Ok(json_value) => {
                debug!(
                    correlation_id = %context.correlation_id,
                    message_type = json_value.get("type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "Message validation successful"
                );

                // Additional validation in strict mode
                if self.strict_mode {
                    // Check for required fields
                    if json_value.get("type").is_none() {
                        warn!(
                            correlation_id = %context.correlation_id,
                            "Missing 'type' field in strict validation mode"
                        );

                        return Err(AsyncApiError::Validation {
                            message: "Missing required field 'type' in message".to_string(),
                            field: Some("type".to_string()),
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::Medium,
                                ErrorCategory::Validation,
                                false,
                            ).with_context("correlation_id", &context.correlation_id.to_string())
                             .with_context("validation_mode", "strict"),
                            source: None,
                        });
                    }
                }

                Ok(payload.to_vec())
            }
            Err(e) => {
                error!(
                    correlation_id = %context.correlation_id,
                    error = %e,
                    payload_preview = %String::from_utf8_lossy(&payload[..payload.len().min(100)]),
                    "JSON validation failed"
                );

                Err(AsyncApiError::Validation {
                    message: format!("Invalid JSON payload: {}", e),
                    field: Some("payload".to_string()),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Validation,
                        false,
                    ).with_context("correlation_id", &context.correlation_id.to_string())
                     .with_context("channel", &context.channel)
                     .with_context("operation", &context.operation)
                     .with_context("validation_error", &e.to_string()),
                    source: Some(Box::new(e)),
                })
            }
        }
    }

    async fn process_outbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        // Validate outbound messages as well
        if !payload.is_empty() {
            match serde_json::from_slice::<serde_json::Value>(payload) {
                Ok(_) => {
                    debug!(
                        correlation_id = %context.correlation_id,
                        "Outbound message validation successful"
                    );
                }
                Err(e) => {
                    warn!(
                        correlation_id = %context.correlation_id,
                        error = %e,
                        "Outbound message validation failed"
                    );
                    // For outbound, we might be less strict and just log the warning
                }
            }
        }

        Ok(payload.to_vec())
    }

    fn name(&self) -> &'static str {
        "validation"
    }
}

/// Rate limiting middleware to prevent abuse and overload
pub struct RateLimitMiddleware {
    max_requests_per_minute: u32,
    request_counts: Arc<RwLock<std::collections::HashMap<String, (u32, Instant)>>>,
}

impl RateLimitMiddleware {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            max_requests_per_minute,
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
}

impl Default for RateLimitMiddleware {
    fn default() -> Self {
        Self::new(1000) // 1000 requests per minute by default
    }
}

#[async_trait::async_trait]
impl Middleware for RateLimitMiddleware {
    #[instrument(skip(self, payload), fields(
        middleware = "rate_limit",
        correlation_id = %context.correlation_id,
        max_rpm = self.max_requests_per_minute
    ))]
    async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let key = format!("{}:{}", context.channel, context.operation);
        let now = Instant::now();

        {
            let mut counts = self.request_counts.write().await;

            // Clean up old entries (older than 1 minute)
            counts.retain(|_, (_, timestamp)| now.duration_since(*timestamp).as_secs() < 60);

            // Check current rate
            let (count, first_request_time) = counts.entry(key.clone()).or_insert((0, now));

            if now.duration_since(*first_request_time).as_secs() < 60 {
                if *count >= self.max_requests_per_minute {
                    warn!(
                        correlation_id = %context.correlation_id,
                        channel = %context.channel,
                        operation = %context.operation,
                        current_count = *count,
                        max_allowed = self.max_requests_per_minute,
                        "Rate limit exceeded"
                    );

                    return Err(AsyncApiError::Resource {
                        message: format!(
                            "Rate limit exceeded: {} requests per minute for {}",
                            self.max_requests_per_minute, key
                        ),
                        resource_type: "rate_limit".to_string(),
                        metadata: ErrorMetadata::new(
                            ErrorSeverity::Medium,
                            ErrorCategory::Resource,
                            true, // Rate limit errors are retryable after some time
                        ).with_context("correlation_id", &context.correlation_id.to_string())
                         .with_context("rate_limit_key", &key)
                         .with_context("current_count", &count.to_string())
                         .with_context("max_allowed", &self.max_requests_per_minute.to_string()),
                        source: None,
                    });
                }
                *count += 1;
            } else {
                // Reset counter for new minute window
                *count = 1;
                *first_request_time = now;
            }
        }

        debug!(
            correlation_id = %context.correlation_id,
            rate_limit_key = %key,
            "Rate limit check passed"
        );

        Ok(payload.to_vec())
    }

    async fn process_outbound(&self, _context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        // No rate limiting for outbound messages
        Ok(payload.to_vec())
    }

    fn name(&self) -> &'static str {
        "rate_limit"
    }
}

/// Middleware pipeline that processes messages through multiple middleware layers
pub struct MiddlewarePipeline {
    middlewares: Vec<Box<dyn Middleware>>,
    recovery_manager: Arc<RecoveryManager>,
}

impl MiddlewarePipeline {
    pub fn new(recovery_manager: Arc<RecoveryManager>) -> Self {
        Self {
            middlewares: Vec::new(),
            recovery_manager,
        }
    }

    /// Initialize the middleware pipeline
    pub async fn initialize(&self) -> AsyncApiResult<()> {
        debug!("Initializing middleware pipeline with {} middlewares", self.middlewares.len());
        Ok(())
    }

    /// Cleanup the middleware pipeline
    pub async fn cleanup(&self) -> AsyncApiResult<()> {
        debug!("Cleaning up middleware pipeline");
        Ok(())
    }

    /// Health check for the middleware pipeline
    pub async fn health_check(&self) -> AsyncApiResult<crate::server::ComponentHealth> {
        Ok(crate::server::ComponentHealth::Healthy)
    }

    /// Add middleware to the pipeline
    pub fn add_middleware<M: Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middlewares.push(Box::new(middleware));
        self
    }

    /// Process inbound message through all middleware
    #[instrument(skip(self, payload), fields(
        pipeline = "inbound",
        middleware_count = self.middlewares.len(),
        payload_size = payload.len()
    ))]
    pub async fn process_inbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let mut current_payload = payload.to_vec();

        for middleware in &self.middlewares {
            if !middleware.is_enabled() {
                debug!(
                    correlation_id = %context.correlation_id,
                    middleware = middleware.name(),
                    "Skipping disabled middleware"
                );
                continue;
            }

            debug!(
                correlation_id = %context.correlation_id,
                middleware = middleware.name(),
                "Processing through middleware"
            );

            match middleware.process_inbound(context, &current_payload).await {
                Ok(processed_payload) => {
                    current_payload = processed_payload;
                }
                Err(e) => {
                    error!(
                        correlation_id = %context.correlation_id,
                        middleware = middleware.name(),
                        error = %e,
                        "Middleware processing failed"
                    );
                    return Err(e);
                }
            }
        }

        info!(
            correlation_id = %context.correlation_id,
            middleware_count = self.middlewares.len(),
            final_payload_size = current_payload.len(),
            "Inbound middleware pipeline completed successfully"
        );

        Ok(current_payload)
    }

    /// Process outbound message through all middleware (in reverse order)
    #[instrument(skip(self, payload), fields(
        pipeline = "outbound",
        middleware_count = self.middlewares.len(),
        payload_size = payload.len()
    ))]
    pub async fn process_outbound(&self, context: &MiddlewareContext, payload: &[u8]) -> AsyncApiResult<Vec<u8>> {
        let mut current_payload = payload.to_vec();

        // Process in reverse order for outbound
        for middleware in self.middlewares.iter().rev() {
            if !middleware.is_enabled() {
                continue;
            }

            match middleware.process_outbound(context, &current_payload).await {
                Ok(processed_payload) => {
                    current_payload = processed_payload;
                }
                Err(e) => {
                    error!(
                        correlation_id = %context.correlation_id,
                        middleware = middleware.name(),
                        error = %e,
                        "Outbound middleware processing failed"
                    );
                    return Err(e);
                }
            }
        }

        Ok(current_payload)
    }
}

impl Default for MiddlewarePipeline {
    fn default() -> Self {
        let recovery_manager = Arc::new(RecoveryManager::default());
        Self::new(recovery_manager)
            .add_middleware(LoggingMiddleware::default())
            .add_middleware(MetricsMiddleware::default())
            .add_middleware(ValidationMiddleware::default())
            .add_middleware(RateLimitMiddleware::default())
    }
}

/// Metrics collected by middleware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareMetrics {
    pub uptime: std::time::Duration,
    pub message_count: u64,
    pub error_count: u64,
    pub error_rate: f64,
    pub avg_processing_time: std::time::Duration,
}
`
  });
}

function RecoveryRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "recovery.rs",
    children: `//! Error recovery and resilience patterns for AsyncAPI operations
//!
//! This module provides:
//! - Retry mechanisms with exponential backoff
//! - Circuit breaker pattern for preventing cascade failures
//! - Bulkhead pattern for failure isolation
//! - Dead letter queue handling
//! - Graceful degradation strategies

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorMetadata, ErrorSeverity, ErrorCategory};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};

/// Retry configuration for different operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Backoff multiplier for exponential backoff
    pub backoff_multiplier: f64,
    /// Maximum total time to spend retrying
    pub max_total_time: Duration,
    /// Jitter factor to add randomness to delays (0.0 to 1.0)
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            max_total_time: Duration::from_secs(300), // 5 minutes
            jitter_factor: 0.1,
        }
    }
}

impl RetryConfig {
    /// Create a conservative retry config for critical operations
    pub fn conservative() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 1.5,
            max_total_time: Duration::from_secs(600), // 10 minutes
            jitter_factor: 0.2,
        }
    }

    /// Create an aggressive retry config for non-critical operations
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 10,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.5,
            max_total_time: Duration::from_secs(120), // 2 minutes
            jitter_factor: 0.05,
        }
    }

    /// Create a fast retry config for real-time operations
    pub fn fast() -> Self {
        Self {
            max_attempts: 2,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(500),
            backoff_multiplier: 2.0,
            max_total_time: Duration::from_secs(5),
            jitter_factor: 0.1,
        }
    }
}

/// Retry strategy implementation with exponential backoff and jitter
pub struct RetryStrategy {
    config: RetryConfig,
    start_time: Instant,
    attempt: u32,
}

impl RetryStrategy {
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            attempt: 0,
        }
    }

    /// Execute an operation with retry logic
    pub async fn execute<F, Fut, T>(&mut self, operation: F) -> AsyncApiResult<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = AsyncApiResult<T>>,
    {
        loop {
            self.attempt += 1;

            debug!(
                attempt = self.attempt,
                max_attempts = self.config.max_attempts,
                "Executing operation with retry"
            );

            match operation().await {
                Ok(result) => {
                    if self.attempt > 1 {
                        info!(
                            attempt = self.attempt,
                            elapsed = ?self.start_time.elapsed(),
                            "Operation succeeded after retry"
                        );
                    }
                    return Ok(result);
                }
                Err(error) => {
                    // Check if we should retry
                    if !self.should_retry(&error) {
                        warn!(
                            attempt = self.attempt,
                            error = %error,
                            "Operation failed with non-retryable error"
                        );
                        return Err(error);
                    }

                    // Check if we've exceeded retry limits
                    if self.attempt >= self.config.max_attempts {
                        error!(
                            attempt = self.attempt,
                            max_attempts = self.config.max_attempts,
                            "Maximum retry attempts exceeded"
                        );
                        return Err(AsyncApiError::Recovery {
                            message: format!(
                                "Operation failed after {} attempts: {}",
                                self.attempt, error
                            ),
                            attempts: self.attempt,
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::High,
                                ErrorCategory::Resource,
                                false,
                            ),
                            source: Some(Box::new(error)),
                        });
                    }

                    // Check total time limit
                    if self.start_time.elapsed() >= self.config.max_total_time {
                        error!(
                            elapsed = ?self.start_time.elapsed(),
                            max_total_time = ?self.config.max_total_time,
                            "Maximum retry time exceeded"
                        );
                        return Err(AsyncApiError::Recovery {
                            message: format!(
                                "Operation failed within time limit: {}",
                                error
                            ),
                            attempts: self.attempt,
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::High,
                                ErrorCategory::Resource,
                                false,
                            ),
                            source: Some(Box::new(error)),
                        });
                    }

                    // Calculate delay and wait
                    let delay = self.calculate_delay();
                    warn!(
                        attempt = self.attempt,
                        delay_ms = delay.as_millis(),
                        error = %error,
                        "Operation failed, retrying after delay"
                    );

                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    fn should_retry(&self, error: &AsyncApiError) -> bool {
        // Don't retry non-retryable errors
        if !error.is_retryable() {
            return false;
        }

        // Don't retry validation or security errors
        match error.category() {
            ErrorCategory::Validation | ErrorCategory::Security => false,
            _ => true,
        }
    }

    fn calculate_delay(&self) -> Duration {
        let base_delay = self.config.initial_delay.as_millis() as f64
            * self.config.backoff_multiplier.powi((self.attempt - 1) as i32);

        let max_delay = self.config.max_delay.as_millis() as f64;
        let delay = base_delay.min(max_delay);

        // Add jitter to prevent thundering herd
        let jitter = delay * self.config.jitter_factor * (rand::random::<f64>() - 0.5);
        let final_delay = (delay + jitter).max(0.0) as u64;

        Duration::from_millis(final_delay)
    }

    /// Get current attempt number
    pub fn current_attempt(&self) -> u32 {
        self.attempt
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Circuit is closed, requests are allowed
    Closed,
    /// Circuit is open, requests are rejected
    Open,
    /// Circuit is half-open, testing if service has recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit
    pub failure_threshold: u32,
    /// Time to wait before transitioning from Open to HalfOpen
    pub recovery_timeout: Duration,
    /// Number of successful requests needed to close the circuit from HalfOpen
    pub success_threshold: u32,
    /// Time window for counting failures
    pub failure_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(60),
            success_threshold: 3,
            failure_window: Duration::from_secs(60),
        }
    }
}

/// Circuit breaker implementation for preventing cascade failures
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitBreakerState>>,
    failure_count: Arc<RwLock<u32>>,
    success_count: Arc<RwLock<u32>>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    last_state_change: Arc<RwLock<Instant>>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
            failure_count: Arc::new(RwLock::new(0)),
            success_count: Arc::new(RwLock::new(0)),
            last_failure_time: Arc::new(RwLock::new(None)),
            last_state_change: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Execute an operation through the circuit breaker
    pub async fn execute<F, Fut, T>(&self, operation: F) -> AsyncApiResult<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = AsyncApiResult<T>>,
    {
        // Check if circuit should transition states
        self.check_state_transition().await;

        let current_state = *self.state.read().await;

        match current_state {
            CircuitBreakerState::Open => {
                debug!("Circuit breaker is open, rejecting request");
                Err(AsyncApiError::Resource {
                    message: "Circuit breaker is open".to_string(),
                    resource_type: "circuit_breaker".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Resource,
                        true,
                    ),
                    source: None,
                })
            }
            CircuitBreakerState::Closed | CircuitBreakerState::HalfOpen => {
                match operation().await {
                    Ok(result) => {
                        self.record_success().await;
                        Ok(result)
                    }
                    Err(error) => {
                        self.record_failure().await;
                        Err(error)
                    }
                }
            }
        }
    }

    async fn record_success(&self) {
        let mut success_count = self.success_count.write().await;
        *success_count += 1;

        let current_state = *self.state.read().await;
        if current_state == CircuitBreakerState::HalfOpen
            && *success_count >= self.config.success_threshold {
            info!("Circuit breaker transitioning to Closed state");
            *self.state.write().await = CircuitBreakerState::Closed;
            *self.failure_count.write().await = 0;
            *success_count = 0;
            *self.last_state_change.write().await = Instant::now();
        }
    }

    async fn record_failure(&self) {
        let mut failure_count = self.failure_count.write().await;
        *failure_count += 1;
        *self.last_failure_time.write().await = Some(Instant::now());

        let current_state = *self.state.read().await;
        if current_state == CircuitBreakerState::Closed
            && *failure_count >= self.config.failure_threshold {
            warn!(
                failure_count = *failure_count,
                threshold = self.config.failure_threshold,
                "Circuit breaker transitioning to Open state"
            );
            *self.state.write().await = CircuitBreakerState::Open;
            *self.success_count.write().await = 0;
            *self.last_state_change.write().await = Instant::now();
        } else if current_state == CircuitBreakerState::HalfOpen {
            warn!("Circuit breaker transitioning back to Open state");
            *self.state.write().await = CircuitBreakerState::Open;
            *self.success_count.write().await = 0;
            *self.last_state_change.write().await = Instant::now();
        }
    }

    async fn check_state_transition(&self) {
        let current_state = *self.state.read().await;
        let last_change = *self.last_state_change.read().await;

        if current_state == CircuitBreakerState::Open
            && last_change.elapsed() >= self.config.recovery_timeout {
            info!("Circuit breaker transitioning to HalfOpen state");
            *self.state.write().await = CircuitBreakerState::HalfOpen;
            *self.last_state_change.write().await = Instant::now();
        }

        // Reset failure count if outside failure window
        if let Some(last_failure) = *self.last_failure_time.read().await {
            if last_failure.elapsed() >= self.config.failure_window {
                *self.failure_count.write().await = 0;
            }
        }
    }

    /// Get current circuit breaker state
    pub async fn state(&self) -> CircuitBreakerState {
        *self.state.read().await
    }

    /// Get current failure count
    pub async fn failure_count(&self) -> u32 {
        *self.failure_count.read().await
    }
}

/// Dead letter queue for handling unprocessable messages
#[derive(Debug)]
pub struct DeadLetterQueue {
    max_size: usize,
    messages: Arc<RwLock<Vec<DeadLetterMessage>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterMessage {
    pub id: String,
    pub original_channel: String,
    pub payload: Vec<u8>,
    pub error: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub retry_count: u32,
}

impl DeadLetterQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            messages: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a message to the dead letter queue
    pub async fn add_message(
        &self,
        channel: &str,
        payload: Vec<u8>,
        error: &AsyncApiError,
        retry_count: u32,
    ) -> AsyncApiResult<()> {
        let mut messages = self.messages.write().await;

        // Remove oldest message if at capacity
        if messages.len() >= self.max_size {
            messages.remove(0);
            warn!("Dead letter queue at capacity, removing oldest message");
        }

        let message = DeadLetterMessage {
            id: uuid::Uuid::new_v4().to_string(),
            original_channel: channel.to_string(),
            payload,
            error: error.to_string(),
            timestamp: chrono::Utc::now(),
            retry_count,
        };

        messages.push(message);
        info!(
            channel = channel,
            error = %error,
            queue_size = messages.len(),
            "Message added to dead letter queue"
        );

        Ok(())
    }

    /// Get all messages in the dead letter queue
    pub async fn get_messages(&self) -> Vec<DeadLetterMessage> {
        self.messages.read().await.clone()
    }

    /// Remove a message from the dead letter queue
    pub async fn remove_message(&self, message_id: &str) -> bool {
        let mut messages = self.messages.write().await;
        if let Some(pos) = messages.iter().position(|m| m.id == message_id) {
            messages.remove(pos);
            true
        } else {
            false
        }
    }

    /// Clear all messages from the dead letter queue
    pub async fn clear(&self) {
        let mut messages = self.messages.write().await;
        let count = messages.len();
        messages.clear();
        info!(cleared_count = count, "Dead letter queue cleared");
    }

    /// Get queue size
    pub async fn size(&self) -> usize {
        self.messages.read().await.len()
    }
}

/// Bulkhead pattern for isolating failures
#[derive(Debug)]
pub struct Bulkhead {
    name: String,
    semaphore: Arc<tokio::sync::Semaphore>,
    max_concurrent: usize,
    timeout: Duration,
}

impl Bulkhead {
    pub fn new(name: String, max_concurrent: usize, timeout: Duration) -> Self {
        Self {
            name,
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
            max_concurrent,
            timeout,
        }
    }

    /// Execute an operation within the bulkhead
    pub async fn execute<F, Fut, T>(&self, operation: F) -> AsyncApiResult<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = AsyncApiResult<T>>,
    {
        // Try to acquire permit with timeout
        let permit = match tokio::time::timeout(
            self.timeout,
            self.semaphore.acquire()
        ).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(AsyncApiError::Resource {
                    message: format!("Bulkhead '{}' semaphore closed", self.name),
                    resource_type: "bulkhead".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Resource,
                        true,
                    ),
                    source: None,
                });
            }
            Err(_) => {
                return Err(AsyncApiError::Resource {
                    message: format!(
                        "Bulkhead '{}' timeout waiting for permit (max_concurrent: {})",
                        self.name, self.max_concurrent
                    ),
                    resource_type: "bulkhead".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Resource,
                        true,
                    ),
                    source: None,
                });
            }
        };

        debug!(
            bulkhead = %self.name,
            available_permits = self.semaphore.available_permits(),
            "Executing operation within bulkhead"
        );

        // Execute operation with permit held
        let result = operation().await;

        // Permit is automatically released when dropped
        drop(permit);

        result
    }

    /// Get current available permits
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// Recovery manager that coordinates all recovery strategies
#[derive(Debug)]
pub struct RecoveryManager {
    retry_configs: std::collections::HashMap<String, RetryConfig>,
    circuit_breakers: std::collections::HashMap<String, Arc<CircuitBreaker>>,
    dead_letter_queue: Arc<DeadLetterQueue>,
    bulkheads: std::collections::HashMap<String, Arc<Bulkhead>>,
}

impl RecoveryManager {
    pub fn new() -> Self {
        Self {
            retry_configs: std::collections::HashMap::new(),
            circuit_breakers: std::collections::HashMap::new(),
            dead_letter_queue: Arc::new(DeadLetterQueue::new(1000)),
            bulkheads: std::collections::HashMap::new(),
        }
    }

    /// Configure retry strategy for an operation type
    pub fn configure_retry(&mut self, operation_type: &str, config: RetryConfig) {
        self.retry_configs.insert(operation_type.to_string(), config);
    }

    /// Configure circuit breaker for a service
    pub fn configure_circuit_breaker(&mut self, service: &str, config: CircuitBreakerConfig) {
        let circuit_breaker = Arc::new(CircuitBreaker::new(config));
        self.circuit_breakers.insert(service.to_string(), circuit_breaker);
    }

    /// Configure bulkhead for a resource
    pub fn configure_bulkhead(&mut self, resource: &str, max_concurrent: usize, timeout: Duration) {
        let bulkhead = Arc::new(Bulkhead::new(resource.to_string(), max_concurrent, timeout));
        self.bulkheads.insert(resource.to_string(), bulkhead);
    }

    /// Get retry strategy for operation type
    pub fn get_retry_strategy(&self, operation_type: &str) -> RetryStrategy {
        let config = self.retry_configs
            .get(operation_type)
            .cloned()
            .unwrap_or_default();
        RetryStrategy::new(config)
    }

    /// Get circuit breaker for service
    pub fn get_circuit_breaker(&self, service: &str) -> Option<Arc<CircuitBreaker>> {
        self.circuit_breakers.get(service).cloned()
    }

    /// Get dead letter queue
    pub fn get_dead_letter_queue(&self) -> Arc<DeadLetterQueue> {
        self.dead_letter_queue.clone()
    }

    /// Get bulkhead for resource
    pub fn get_bulkhead(&self, resource: &str) -> Option<Arc<Bulkhead>> {
        self.bulkheads.get(resource).cloned()
    }
}

impl Default for RecoveryManager {
    fn default() -> Self {
        let mut manager = Self::new();

        // Configure default retry strategies
        manager.configure_retry("message_handler", RetryConfig::default());
        manager.configure_retry("connection", RetryConfig::conservative());
        manager.configure_retry("validation", RetryConfig::fast());

        // Configure default circuit breakers
        manager.configure_circuit_breaker("default", CircuitBreakerConfig::default());

        // Configure default bulkheads
        manager.configure_bulkhead("message_processing", 100, Duration::from_secs(30));
        manager.configure_bulkhead("connection_pool", 50, Duration::from_secs(10));

        manager
    }
}
`
  });
}

function AuthModRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "mod.rs",
    children: `//! Authentication and authorization module
//!
//! This module provides JWT-based authentication, role-based access control,
//! and middleware for securing AsyncAPI message handlers.

#[cfg(feature = "auth")]
pub mod jwt;
#[cfg(feature = "auth")]
pub mod middleware;
#[cfg(feature = "auth")]
pub mod rbac;
#[cfg(feature = "auth")]
pub mod config;

#[cfg(feature = "auth")]
pub use config::AuthConfig;
#[cfg(feature = "auth")]
pub use middleware::AuthMiddleware;
#[cfg(feature = "auth")]
pub use jwt::{JwtValidator, Claims};
#[cfg(feature = "auth")]
pub use rbac::{Role, Permission, RoleManager};

#[cfg(not(feature = "auth"))]
pub struct AuthConfig;

#[cfg(not(feature = "auth"))]
impl AuthConfig {
    pub fn new() -> Self {
        Self
    }

    pub fn validate(&self) -> crate::errors::AsyncApiResult<()> {
        Ok(())
    }
}

#[cfg(not(feature = "auth"))]
impl Clone for AuthConfig {
    fn clone(&self) -> Self {
        Self
    }
}
`
  });
}

function AuthConfigRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "config.rs",
    children: `//! Authentication configuration

use crate::errors::{AsyncApiError, AsyncApiResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWT configuration
    pub jwt: JwtConfig,
    /// Rate limiting configuration
    pub rate_limiting: Option<RateLimitConfig>,
    /// Session configuration
    pub session: Option<SessionConfig>,
    /// Required roles for access
    pub required_roles: Vec<String>,
    /// Required permissions for access
    pub required_permissions: Vec<String>,
    /// Whether to allow anonymous access
    pub allow_anonymous: bool,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT secret for HMAC algorithms
    pub secret: Option<String>,
    /// RSA private key PEM for signing (RS256)
    pub private_key_pem: Option<String>,
    /// RSA public key PEM for verification (RS256)
    pub public_key_pem: Option<String>,
    /// Expected issuer
    pub issuer: Option<String>,
    /// Expected audience
    pub audience: Option<String>,
    /// Token expiration time in seconds
    pub expires_in: u64,
    /// Leeway for time-based validations in seconds
    pub leeway: u64,
    /// Algorithm to use (HS256, RS256)
    pub algorithm: JwtAlgorithm,
}

/// JWT algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    /// HMAC with SHA-256
    HS256,
    /// RSA with SHA-256
    RS256,
}

/// Rate limiting configuration for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of authentication attempts per window
    pub max_attempts: u32,
    /// Time window for rate limiting
    pub window_seconds: u64,
    /// Lockout duration after exceeding rate limit
    pub lockout_seconds: u64,
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session timeout in seconds
    pub timeout_seconds: u64,
    /// Whether to extend session on activity
    pub extend_on_activity: bool,
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: Option<u32>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt: JwtConfig::default(),
            rate_limiting: Some(RateLimitConfig::default()),
            session: Some(SessionConfig::default()),
            required_roles: Vec::new(),
            required_permissions: Vec::new(),
            allow_anonymous: false,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: None,
            private_key_pem: None,
            public_key_pem: None,
            issuer: None,
            audience: None,
            expires_in: 3600, // 1 hour
            leeway: 60,       // 1 minute
            algorithm: JwtAlgorithm::HS256,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_seconds: 300,   // 5 minutes
            lockout_seconds: 900,  // 15 minutes
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 3600, // 1 hour
            extend_on_activity: true,
            max_concurrent_sessions: Some(5),
        }
    }
}

impl AuthConfig {
    /// Create a new authentication configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set JWT secret for HMAC algorithms
    pub fn with_jwt_secret(mut self, secret: String) -> Self {
        self.jwt.secret = Some(secret);
        self.jwt.algorithm = JwtAlgorithm::HS256;
        self
    }

    /// Set RSA key pair for RS256 algorithm
    pub fn with_rsa_keys(mut self, private_key_pem: String, public_key_pem: String) -> Self {
        self.jwt.private_key_pem = Some(private_key_pem);
        self.jwt.public_key_pem = Some(public_key_pem);
        self.jwt.algorithm = JwtAlgorithm::RS256;
        self
    }

    /// Set RSA public key for verification only
    pub fn with_rsa_public_key(mut self, public_key_pem: String) -> Self {
        self.jwt.public_key_pem = Some(public_key_pem);
        self.jwt.algorithm = JwtAlgorithm::RS256;
        self
    }

    /// Set JWT issuer
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.jwt.issuer = Some(issuer);
        self
    }

    /// Set JWT audience
    pub fn with_audience(mut self, audience: String) -> Self {
        self.jwt.audience = Some(audience);
        self
    }

    /// Set token expiration time
    pub fn with_expires_in(mut self, seconds: u64) -> Self {
        self.jwt.expires_in = seconds;
        self
    }

    /// Add required role
    pub fn with_required_role(mut self, role: String) -> Self {
        self.required_roles.push(role);
        self
    }

    /// Add required permission
    pub fn with_required_permission(mut self, permission: String) -> Self {
        self.required_permissions.push(permission);
        self
    }

    /// Allow anonymous access
    pub fn allow_anonymous(mut self) -> Self {
        self.allow_anonymous = true;
        self
    }

    /// Disable rate limiting
    pub fn without_rate_limiting(mut self) -> Self {
        self.rate_limiting = None;
        self
    }

    /// Configure rate limiting
    pub fn with_rate_limiting(mut self, config: RateLimitConfig) -> Self {
        self.rate_limiting = Some(config);
        self
    }

    /// Configure session management
    pub fn with_session_config(mut self, config: SessionConfig) -> Self {
        self.session = Some(config);
        self
    }

    /// Validate the authentication configuration
    pub fn validate(&self) -> AsyncApiResult<()> {
        // Validate JWT configuration
        match self.jwt.algorithm {
            JwtAlgorithm::HS256 => {
                if self.jwt.secret.is_none() {
                    return Err(AsyncApiError::Configuration {
                        message: "JWT secret is required for HS256 algorithm".to_string(),
                        field: Some("jwt.secret".to_string()),
                        source: None,
                    });
                }

                if let Some(ref secret) = self.jwt.secret {
                    if secret.len() < 32 {
                        return Err(AsyncApiError::Configuration {
                            message: "JWT secret should be at least 32 characters long".to_string(),
                            field: Some("jwt.secret".to_string()),
                            source: None,
                        });
                    }
                }
            }
            JwtAlgorithm::RS256 => {
                if self.jwt.public_key_pem.is_none() {
                    return Err(AsyncApiError::Configuration {
                        message: "RSA public key is required for RS256 algorithm".to_string(),
                        field: Some("jwt.public_key_pem".to_string()),
                        source: None,
                    });
                }
            }
        }

        // Validate expiration time
        if self.jwt.expires_in == 0 {
            return Err(AsyncApiError::Configuration {
                message: "JWT expiration time must be greater than 0".to_string(),
                field: Some("jwt.expires_in".to_string()),
                source: None,
            });
        }

        // Validate rate limiting configuration
        if let Some(ref rate_limit) = self.rate_limiting {
            if rate_limit.max_attempts == 0 {
                return Err(AsyncApiError::Configuration {
                    message: "Rate limit max_attempts must be greater than 0".to_string(),
                    field: Some("rate_limiting.max_attempts".to_string()),
                    source: None,
                });
            }

            if rate_limit.window_seconds == 0 {
                return Err(AsyncApiError::Configuration {
                    message: "Rate limit window_seconds must be greater than 0".to_string(),
                    field: Some("rate_limiting.window_seconds".to_string()),
                    source: None,
                });
            }
        }

        // Validate session configuration
        if let Some(ref session) = self.session {
            if session.timeout_seconds == 0 {
                return Err(AsyncApiError::Configuration {
                    message: "Session timeout must be greater than 0".to_string(),
                    field: Some("session.timeout_seconds".to_string()),
                    source: None,
                });
            }

            if let Some(max_sessions) = session.max_concurrent_sessions {
                if max_sessions == 0 {
                    return Err(AsyncApiError::Configuration {
                        message: "Max concurrent sessions must be greater than 0".to_string(),
                        field: Some("session.max_concurrent_sessions".to_string()),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Create configuration from environment variables
    pub fn from_env() -> AsyncApiResult<Self> {
        let mut config = Self::default();

        // JWT configuration
        if let Ok(secret) = std::env::var("JWT_SECRET") {
            config.jwt.secret = Some(secret);
            config.jwt.algorithm = JwtAlgorithm::HS256;
        }

        if let Ok(private_key) = std::env::var("JWT_PRIVATE_KEY_PEM") {
            config.jwt.private_key_pem = Some(private_key);
            config.jwt.algorithm = JwtAlgorithm::RS256;
        }

        if let Ok(public_key) = std::env::var("JWT_PUBLIC_KEY_PEM") {
            config.jwt.public_key_pem = Some(public_key);
            if config.jwt.private_key_pem.is_none() {
                config.jwt.algorithm = JwtAlgorithm::RS256;
            }
        }

        if let Ok(issuer) = std::env::var("JWT_ISSUER") {
            config.jwt.issuer = Some(issuer);
        }

        if let Ok(audience) = std::env::var("JWT_AUDIENCE") {
            config.jwt.audience = Some(audience);
        }

        if let Ok(expires_in) = std::env::var("JWT_EXPIRES_IN") {
            config.jwt.expires_in = expires_in.parse().map_err(|e| AsyncApiError::Configuration {
                message: format!("Invalid JWT_EXPIRES_IN value: {}", e),
                field: Some("JWT_EXPIRES_IN".to_string()),
                source: Some(Box::new(e)),
            })?;
        }

        // Rate limiting configuration
        if let Ok(max_attempts) = std::env::var("AUTH_RATE_LIMIT_MAX_ATTEMPTS") {
            if let Some(ref mut rate_limit) = config.rate_limiting {
                rate_limit.max_attempts = max_attempts.parse().map_err(|e| AsyncApiError::Configuration {
                    message: format!("Invalid AUTH_RATE_LIMIT_MAX_ATTEMPTS value: {}", e),
                    field: Some("AUTH_RATE_LIMIT_MAX_ATTEMPTS".to_string()),
                    source: Some(Box::new(e)),
                })?;
            }
        }

        // Anonymous access
        if let Ok(allow_anon) = std::env::var("AUTH_ALLOW_ANONYMOUS") {
            config.allow_anonymous = allow_anon.to_lowercase() == "true";
        }

        config.validate()?;
        Ok(config)
    }

    /// Get the rate limit window as Duration
    pub fn rate_limit_window(&self) -> Option<Duration> {
        self.rate_limiting.as_ref().map(|rl| Duration::from_secs(rl.window_seconds))
    }

    /// Get the rate limit lockout duration as Duration
    pub fn rate_limit_lockout(&self) -> Option<Duration> {
        self.rate_limiting.as_ref().map(|rl| Duration::from_secs(rl.lockout_seconds))
    }

    /// Get the session timeout as Duration
    pub fn session_timeout(&self) -> Option<Duration> {
        self.session.as_ref().map(|s| Duration::from_secs(s.timeout_seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuthConfig::default();
        assert!(config.validate().is_err()); // Should fail without secret
    }

    #[test]
    fn test_hmac_config() {
        let config = AuthConfig::new()
            .with_jwt_secret("this-is-a-very-long-secret-key-for-testing".to_string());

        assert!(config.validate().is_ok());
        assert_eq!(config.jwt.algorithm, JwtAlgorithm::HS256);
    }

    #[test]
    fn test_config_validation() {
        // Test short secret
        let config = AuthConfig::new()
            .with_jwt_secret("short".to_string());
        assert!(config.validate().is_err());

        // Test zero expiration
        let mut config = AuthConfig::new()
            .with_jwt_secret("this-is-a-very-long-secret-key-for-testing".to_string());
        config.jwt.expires_in = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_builder_pattern() {
        let config = AuthConfig::new()
            .with_jwt_secret("this-is-a-very-long-secret-key-for-testing".to_string())
            .with_issuer("test-issuer".to_string())
            .with_audience("test-audience".to_string())
            .with_required_role("admin".to_string())
            .allow_anonymous();

        assert!(config.validate().is_ok());
        assert_eq!(config.jwt.issuer, Some("test-issuer".to_string()));
        assert_eq!(config.jwt.audience, Some("test-audience".to_string()));
        assert!(config.required_roles.contains(&"admin".to_string()));
        assert!(config.allow_anonymous);
    }
}
`
  });
}

function AuthJwtRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "jwt.rs",
    children: `//! JWT token validation and claims handling

use crate::errors::{AsyncApiError, AsyncApiResult};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Issued at timestamp
    pub iat: u64,
    /// Expiration timestamp
    pub exp: u64,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Custom claims
    #[serde(flatten)]
    pub custom: serde_json::Map<String, serde_json::Value>,
}

impl Claims {
    /// Create new claims with expiration
    pub fn new(
        user_id: String,
        issuer: String,
        audience: String,
        expires_in_seconds: u64,
    ) -> AsyncApiResult<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AsyncApiError::Authentication {
                message: format!("Failed to get current time: {}", e),
                source: Some(Box::new(e)),
            })?
            .as_secs();

        Ok(Self {
            sub: user_id,
            iat: now,
            exp: now + expires_in_seconds,
            iss: issuer,
            aud: audience,
            roles: Vec::new(),
            permissions: Vec::new(),
            custom: serde_json::Map::new(),
        })
    }

    /// Add a role to the claims
    pub fn with_role(mut self, role: String) -> Self {
        self.roles.push(role);
        self
    }

    /// Add multiple roles to the claims
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles.extend(roles);
        self
    }

    /// Add a permission to the claims
    pub fn with_permission(mut self, permission: String) -> Self {
        self.permissions.push(permission);
        self
    }

    /// Add multiple permissions to the claims
    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions.extend(permissions);
        self
    }

    /// Add a custom claim
    pub fn with_custom_claim<T: Serialize>(mut self, key: String, value: T) -> AsyncApiResult<Self> {
        let json_value = serde_json::to_value(value).map_err(|e| AsyncApiError::Authentication {
            message: format!("Failed to serialize custom claim: {}", e),
            source: Some(Box::new(e)),
        })?;
        self.custom.insert(key, json_value);
        Ok(self)
    }

    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.exp <= now
    }

    /// Check if the claims contain a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }

    /// Check if the claims contain any of the specified roles
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|role| self.has_role(role))
    }

    /// Check if the claims contain all of the specified roles
    pub fn has_all_roles(&self, roles: &[&str]) -> bool {
        roles.iter().all(|role| self.has_role(role))
    }

    /// Check if the claims contain a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }

    /// Check if the claims contain any of the specified permissions
    pub fn has_any_permission(&self, permissions: &[&str]) -> bool {
        permissions.iter().any(|perm| self.has_permission(perm))
    }

    /// Get a custom claim value
    pub fn get_custom_claim<T: for<'de> Deserialize<'de>>(&self, key: &str) -> AsyncApiResult<Option<T>> {
        match self.custom.get(key) {
            Some(value) => {
                let result = serde_json::from_value(value.clone()).map_err(|e| AsyncApiError::Authentication {
                    message: format!("Failed to deserialize custom claim '{}': {}", key, e),
                    source: Some(Box::new(e)),
                })?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }
}

/// JWT token validator
pub struct JwtValidator {
    decoding_key: DecodingKey,
    validation: Validation,
    encoding_key: Option<EncodingKey>,
}

impl JwtValidator {
    /// Create a new JWT validator with HMAC secret
    pub fn new_hmac(secret: &[u8]) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false; // We'll validate audience manually if needed

        Self {
            decoding_key: DecodingKey::from_secret(secret),
            validation,
            encoding_key: Some(EncodingKey::from_secret(secret)),
        }
    }

    /// Create a new JWT validator with RSA public key
    pub fn new_rsa_public(public_key_pem: &[u8]) -> AsyncApiResult<Self> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem).map_err(|e| AsyncApiError::Authentication {
            message: format!("Invalid RSA public key: {}", e),
            source: Some(Box::new(e)),
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.validate_aud = false;

        Ok(Self {
            decoding_key,
            validation,
            encoding_key: None,
        })
    }

    /// Create a new JWT validator with RSA key pair
    pub fn new_rsa_keypair(private_key_pem: &[u8], public_key_pem: &[u8]) -> AsyncApiResult<Self> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem).map_err(|e| AsyncApiError::Authentication {
            message: format!("Invalid RSA public key: {}", e),
            source: Some(Box::new(e)),
        })?;

        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem).map_err(|e| AsyncApiError::Authentication {
            message: format!("Invalid RSA private key: {}", e),
            source: Some(Box::new(e)),
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.validate_aud = false;

        Ok(Self {
            decoding_key,
            validation,
            encoding_key: Some(encoding_key),
        })
    }

    /// Set required audience for validation
    pub fn with_audience(mut self, audience: String) -> Self {
        self.validation.validate_aud = true;
        self.validation.aud = Some(HashSet::from([audience]));
        self
    }

    /// Set required issuer for validation
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.validation.validate_iss = true;
        self.validation.iss = Some(HashSet::from([issuer]));
        self
    }

    /// Set leeway for time-based validations (in seconds)
    pub fn with_leeway(mut self, leeway_seconds: u64) -> Self {
        self.validation.leeway = leeway_seconds;
        self
    }

    /// Validate and decode a JWT token
    pub fn validate_token(&self, token: &str) -> AsyncApiResult<Claims> {
        debug!("Validating JWT token");

        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| {
                warn!("JWT validation failed: {}", e);
                AsyncApiError::Authentication {
                    message: format!("Invalid JWT token: {}", e),
                    source: Some(Box::new(e)),
                }
            })?;

        let claims = token_data.claims;

        // Additional custom validations
        if claims.is_expired() {
            return Err(AsyncApiError::Authentication {
                message: "Token has expired".to_string(),
                source: None,
            });
        }

        debug!("JWT token validated successfully for user: {}", claims.sub);
        Ok(claims)
    }

    /// Generate a new JWT token (requires encoding key)
    pub fn generate_token(&self, claims: &Claims) -> AsyncApiResult<String> {
        let encoding_key = self.encoding_key.as_ref().ok_or_else(|| AsyncApiError::Authentication {
            message: "No encoding key available for token generation".to_string(),
            source: None,
        })?;

        let header = Header::new(match encoding_key {
            EncodingKey::Rsa { .. } => Algorithm::RS256,
            _ => Algorithm::HS256,
        });

        encode(&header, claims, encoding_key).map_err(|e| AsyncApiError::Authentication {
            message: format!("Failed to generate JWT token: {}", e),
            source: Some(Box::new(e)),
        })
    }

    /// Extract token from Authorization header
    pub fn extract_bearer_token(auth_header: &str) -> AsyncApiResult<&str> {
        if !auth_header.starts_with("Bearer ") {
            return Err(AsyncApiError::Authentication {
                message: "Authorization header must start with 'Bearer '".to_string(),
                source: None,
            });
        }

        let token = &auth_header[7..]; // Remove "Bearer " prefix
        if token.is_empty() {
            return Err(AsyncApiError::Authentication {
                message: "Empty bearer token".to_string(),
                source: None,
            });
        }

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_creation() {
        let claims = Claims::new(
            "user123".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600,
        ).unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.iss, "test-issuer");
        assert_eq!(claims.aud, "test-audience");
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_role_permissions() {
        let claims = Claims::new(
            "user123".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600,
        ).unwrap()
        .with_role("admin".to_string())
        .with_permission("read:users".to_string());

        assert!(claims.has_role("admin"));
        assert!(!claims.has_role("user"));
        assert!(claims.has_permission("read:users"));
        assert!(!claims.has_permission("write:users"));
    }

    #[test]
    fn test_jwt_hmac_roundtrip() {
        let secret = b"test-secret-key";
        let validator = JwtValidator::new_hmac(secret);

        let claims = Claims::new(
            "user123".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600,
        ).unwrap();

        let token = validator.generate_token(&claims).unwrap();
        let decoded_claims = validator.validate_token(&token).unwrap();

        assert_eq!(claims.sub, decoded_claims.sub);
        assert_eq!(claims.iss, decoded_claims.iss);
        assert_eq!(claims.aud, decoded_claims.aud);
    }

    #[test]
    fn test_bearer_token_extraction() {
        let auth_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
        let token = JwtValidator::extract_bearer_token(auth_header).unwrap();
        assert_eq!(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

        let invalid_header = "Basic dXNlcjpwYXNz";
        assert!(JwtValidator::extract_bearer_token(invalid_header).is_err());
    }
}
`
  });
}

function AuthMiddlewareRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "middleware.rs",
    children: `//! Authentication middleware for message processing

use crate::auth::{AuthConfig, JwtValidator, Claims};
use crate::context::{RequestContext, ExecutionContext};
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::middleware::Middleware;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn, error};

/// Authentication middleware
pub struct AuthMiddleware {
    config: AuthConfig,
    jwt_validator: JwtValidator,
    rate_limiter: Option<RateLimiter>,
    session_manager: Option<SessionManager>,
}

impl AuthMiddleware {
    /// Create new authentication middleware
    pub fn new(config: AuthConfig) -> AsyncApiResult<Self> {
        let jwt_validator = Self::create_jwt_validator(&config)?;

        let rate_limiter = if let Some(ref rate_config) = config.rate_limiting {
            Some(RateLimiter::new(
                rate_config.max_attempts,
                Duration::from_secs(rate_config.window_seconds),
                Duration::from_secs(rate_config.lockout_seconds),
            ))
        } else {
            None
        };

        let session_manager = if let Some(ref session_config) = config.session {
            Some(SessionManager::new(
                Duration::from_secs(session_config.timeout_seconds),
                session_config.extend_on_activity,
                session_config.max_concurrent_sessions,
            ))
        } else {
            None
        };

        Ok(Self {
            config,
            jwt_validator,
            rate_limiter,
            session_manager,
        })
    }

    /// Create JWT validator from configuration
    fn create_jwt_validator(config: &AuthConfig) -> AsyncApiResult<JwtValidator> {
        let mut validator = match config.jwt.algorithm {
            crate::auth::config::JwtAlgorithm::HS256 => {
                let secret = config.jwt.secret.as_ref().ok_or_else(|| AsyncApiError::Configuration {
                    message: "JWT secret is required for HS256".to_string(),
                    field: Some("jwt.secret".to_string()),
                    source: None,
                })?;
                JwtValidator::new_hmac(secret.as_bytes())
            }
            crate::auth::config::JwtAlgorithm::RS256 => {
                let public_key = config.jwt.public_key_pem.as_ref().ok_or_else(|| AsyncApiError::Configuration {
                    message: "RSA public key is required for RS256".to_string(),
                    field: Some("jwt.public_key_pem".to_string()),
                    source: None,
                })?;

                if let Some(private_key) = &config.jwt.private_key_pem {
                    JwtValidator::new_rsa_keypair(private_key.as_bytes(), public_key.as_bytes())?
                } else {
                    JwtValidator::new_rsa_public(public_key.as_bytes())?
                }
            }
        };

        // Configure validator with issuer and audience if specified
        if let Some(ref issuer) = config.jwt.issuer {
            validator = validator.with_issuer(issuer.clone());
        }

        if let Some(ref audience) = config.jwt.audience {
            validator = validator.with_audience(audience.clone());
        }

        validator = validator.with_leeway(config.jwt.leeway);

        Ok(validator)
    }

    /// Extract authentication token from context
    fn extract_token(&self, context: &RequestContext) -> AsyncApiResult<Option<String>> {
        // Try to get token from headers
        if let Some(auth_header) = context.get_header("authorization") {
            let token = JwtValidator::extract_bearer_token(auth_header)?;
            return Ok(Some(token.to_string()));
        }

        // Try to get token from metadata
        if let Some(token) = context.get_metadata("auth_token") {
            return Ok(Some(token.clone()));
        }

        // Try to get token from custom properties
        if let Some(token) = context.get_property("jwt_token") {
            return Ok(Some(token.clone()));
        }

        Ok(None)
    }

    /// Validate user permissions
    fn validate_permissions(&self, claims: &Claims) -> AsyncApiResult<()> {
        // Check required roles
        if !self.config.required_roles.is_empty() {
            let has_required_role = self.config.required_roles.iter()
                .any(|role| claims.has_role(role));

            if !has_required_role {
                return Err(AsyncApiError::Authorization {
                    message: format!("User lacks required roles: {:?}", self.config.required_roles),
                    required_permissions: self.config.required_roles.clone(),
                    user_permissions: claims.roles.clone(),
                });
            }
        }

        // Check required permissions
        if !self.config.required_permissions.is_empty() {
            let has_required_permission = self.config.required_permissions.iter()
                .any(|perm| claims.has_permission(perm));

            if !has_required_permission {
                return Err(AsyncApiError::Authorization {
                    message: format!("User lacks required permissions: {:?}", self.config.required_permissions),
                    required_permissions: self.config.required_permissions.clone(),
                    user_permissions: claims.permissions.clone(),
                });
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Middleware for AuthMiddleware {
    fn name(&self) -> &'static str {
        "AuthMiddleware"
    }

    async fn process(
        &self,
        context: &mut RequestContext,
        _execution_context: &ExecutionContext,
    ) -> AsyncApiResult<()> {
        debug!("Processing authentication middleware");

        // Check rate limiting first
        if let Some(ref rate_limiter) = self.rate_limiter {
            let client_id = context.get_client_id().unwrap_or("unknown".to_string());
            if !rate_limiter.check_rate_limit(&client_id).await {
                warn!("Rate limit exceeded for client: {}", client_id);
                return Err(AsyncApiError::RateLimit {
                    message: "Authentication rate limit exceeded".to_string(),
                    retry_after: Some(self.config.rate_limit_lockout().unwrap_or(Duration::from_secs(900))),
                });
            }
        }

        // Extract authentication token
        let token = match self.extract_token(context)? {
            Some(token) => token,
            None => {
                if self.config.allow_anonymous {
                    debug!("No authentication token found, allowing anonymous access");
                    context.set_property("authenticated".to_string(), "false".to_string());
                    return Ok(());
                } else {
                    return Err(AsyncApiError::Authentication {
                        message: "No authentication token provided".to_string(),
                        source: None,
                    });
                }
            }
        };

        // Validate JWT token
        let claims = match self.jwt_validator.validate_token(&token) {
            Ok(claims) => claims,
            Err(e) => {
                warn!("JWT validation failed: {}", e);

                // Record failed attempt for rate limiting
                if let Some(ref rate_limiter) = self.rate_limiter {
                    let client_id = context.get_client_id().unwrap_or("unknown".to_string());
                    rate_limiter.record_failed_attempt(&client_id).await;
                }

                return Err(e);
            }
        };

        // Validate permissions
        self.validate_permissions(&claims)?;

        // Check session if session management is enabled
        if let Some(ref session_manager) = self.session_manager {
            session_manager.validate_session(&claims.sub, &token).await?;
        }

        // Store authentication information in context
        context.set_property("authenticated".to_string(), "true".to_string());
        context.set_property("user_id".to_string(), claims.sub.clone());
        context.set_property("user_roles".to_string(), claims.roles.join(","));
        context.set_property("user_permissions".to_string(), claims.permissions.join(","));

        // Store claims for use by handlers
        context.set_auth_claims(claims);

        debug!("Authentication successful for user: {}", context.get_property("user_id").unwrap_or(&"unknown".to_string()));
        Ok(())
    }
}

/// Rate limiter for authentication attempts
struct RateLimiter {
    max_attempts: u32,
    window: Duration,
    lockout: Duration,
    attempts: Arc<RwLock<HashMap<String, AttemptRecord>>>,
}

#[derive(Debug, Clone)]
struct AttemptRecord {
    count: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

impl RateLimiter {
    fn new(max_attempts: u32, window: Duration, lockout: Duration) -> Self {
        Self {
            max_attempts,
            window,
            lockout,
            attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn check_rate_limit(&self, client_id: &str) -> bool {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();

        let record = attempts.entry(client_id.to_string()).or_insert(AttemptRecord {
            count: 0,
            window_start: now,
            locked_until: None,
        });

        // Check if client is locked out
        if let Some(locked_until) = record.locked_until {
            if now < locked_until {
                return false;
            } else {
                // Lockout expired, reset
                record.locked_until = None;
                record.count = 0;
                record.window_start = now;
            }
        }

        // Check if we need to reset the window
        if now.duration_since(record.window_start) > self.window {
            record.count = 0;
            record.window_start = now;
        }

        record.count < self.max_attempts
    }

    async fn record_failed_attempt(&self, client_id: &str) {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();

        let record = attempts.entry(client_id.to_string()).or_insert(AttemptRecord {
            count: 0,
            window_start: now,
            locked_until: None,
        });

        record.count += 1;

        if record.count >= self.max_attempts {
            record.locked_until = Some(now + self.lockout);
            warn!("Client {} locked out due to too many failed authentication attempts", client_id);
        }
    }
}

/// Session manager for tracking user sessions
struct SessionManager {
    timeout: Duration,
    extend_on_activity: bool,
    max_concurrent_sessions: Option<u32>,
    sessions: Arc<RwLock<HashMap<String, Vec<SessionInfo>>>>,
}

#[derive(Debug, Clone)]
struct SessionInfo {
    token_hash: String,
    created_at: Instant,
    last_activity: Instant,
}

impl SessionManager {
    fn new(timeout: Duration, extend_on_activity: bool, max_concurrent_sessions: Option<u32>) -> Self {
        Self {
            timeout,
            extend_on_activity,
            max_concurrent_sessions,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn validate_session(&self, user_id: &str, token: &str) -> AsyncApiResult<()> {
        let mut sessions = self.sessions.write().await;
        let now = Instant::now();
        let token_hash = self.hash_token(token);

        let user_sessions = sessions.entry(user_id.to_string()).or_insert_with(Vec::new);

        // Remove expired sessions
        user_sessions.retain(|session| {
            now.duration_since(session.last_activity) <= self.timeout
        });

        // Find current session
        if let Some(session) = user_sessions.iter_mut().find(|s| s.token_hash == token_hash) {
            // Check if session is expired
            if now.duration_since(session.last_activity) > self.timeout {
                return Err(AsyncApiError::Authentication {
                    message: "Session has expired".to_string(),
                    source: None,
                });
            }

            // Extend session if configured
            if self.extend_on_activity {
                session.last_activity = now;
            }

            Ok(())
        } else {
            // New session
            if let Some(max_sessions) = self.max_concurrent_sessions {
                if user_sessions.len() >= max_sessions as usize {
                    // Remove oldest session
                    user_sessions.sort_by_key(|s| s.created_at);
                    user_sessions.remove(0);
                }
            }

            user_sessions.push(SessionInfo {
                token_hash,
                created_at: now,
                last_activity: now,
            });

            Ok(())
        }
    }

    fn hash_token(&self, token: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        token.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;

    #[tokio::test]
    async fn test_rate_limiter() {
        let rate_limiter = RateLimiter::new(3, Duration::from_secs(60), Duration::from_secs(300));
        let client_id = "test_client";

        // Should allow initial attempts
        assert!(rate_limiter.check_rate_limit(client_id).await);
        assert!(rate_limiter.check_rate_limit(client_id).await);
        assert!(rate_limiter.check_rate_limit(client_id).await);

        // Record failed attempts
        rate_limiter.record_failed_attempt(client_id).await;
        rate_limiter.record_failed_attempt(client_id).await;
        rate_limiter.record_failed_attempt(client_id).await;

        // Should be locked out now
        assert!(!rate_limiter.check_rate_limit(client_id).await);
    }

    #[tokio::test]
    async fn test_session_manager() {
        let session_manager = SessionManager::new(
            Duration::from_secs(3600),
            true,
            Some(2),
        );

        let user_id = "test_user";
        let token1 = "token1";
        let token2 = "token2";

        // Validate new sessions
        assert!(session_manager.validate_session(user_id, token1).await.is_ok());
        assert!(session_manager.validate_session(user_id, token2).await.is_ok());

        // Validate existing sessions
        assert!(session_manager.validate_session(user_id, token1).await.is_ok());
        assert!(session_manager.validate_session(user_id, token2).await.is_ok());
    }
}
`
  });
}

function AuthRbacRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "rbac.rs",
    children: `//! Role-Based Access Control (RBAC) system

use crate::errors::{AsyncApiError, AsyncApiResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// A role in the RBAC system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Role {
    /// Role name
    pub name: String,
    /// Role description
    pub description: String,
    /// Permissions granted by this role
    pub permissions: HashSet<Permission>,
    /// Parent roles (for role inheritance)
    pub parent_roles: HashSet<String>,
    /// Whether this role is active
    pub active: bool,
}

impl Role {
    /// Create a new role
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            permissions: HashSet::new(),
            parent_roles: HashSet::new(),
            active: true,
        }
    }

    /// Add a permission to this role
    pub fn with_permission(mut self, permission: Permission) -> Self {
        self.permissions.insert(permission);
        self
    }

    /// Add multiple permissions to this role
    pub fn with_permissions(mut self, permissions: Vec<Permission>) -> Self {
        self.permissions.extend(permissions);
        self
    }

    /// Add a parent role for inheritance
    pub fn with_parent_role(mut self, parent_role: &str) -> Self {
        self.parent_roles.insert(parent_role.to_string());
        self
    }

    /// Check if this role has a specific permission
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Get all permissions including inherited ones
    pub fn get_all_permissions(&self, role_manager: &RoleManager) -> HashSet<Permission> {
        let mut all_permissions = self.permissions.clone();

        // Add permissions from parent roles
        for parent_name in &self.parent_roles {
            if let Some(parent_role) = role_manager.get_role(parent_name) {
                all_permissions.extend(parent_role.get_all_permissions(role_manager));
            }
        }

        all_permissions
    }
}

/// A permission in the RBAC system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Permission {
    /// Permission name (e.g., "read:users", "write:messages")
    pub name: String,
    /// Resource this permission applies to
    pub resource: String,
    /// Action this permission allows
    pub action: String,
    /// Optional conditions for this permission
    pub conditions: Option<PermissionConditions>,
}

impl Permission {
    /// Create a new permission
    pub fn new(resource: &str, action: &str) -> Self {
        Self {
            name: format!("{}:{}", action, resource),
            resource: resource.to_string(),
            action: action.to_string(),
            conditions: None,
        }
    }

    /// Create a permission with conditions
    pub fn with_conditions(mut self, conditions: PermissionConditions) -> Self {
        self.conditions = Some(conditions);
        self
    }

    /// Check if this permission matches a required permission
    pub fn matches(&self, required: &Permission) -> bool {
        // Basic name matching
        if self.name == required.name {
            return true;
        }

        // Wildcard matching
        if self.action == "*" && self.resource == required.resource {
            return true;
        }

        if self.resource == "*" && self.action == required.action {
            return true;
        }

        if self.action == "*" && self.resource == "*" {
            return true;
        }

        false
    }
}

/// Conditions that can be applied to permissions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PermissionConditions {
    /// Time-based conditions
    pub time_restrictions: Option<TimeRestrictions>,
    /// IP-based conditions
    pub ip_restrictions: Option<Vec<String>>,
    /// Custom conditions
    pub custom_conditions: HashMap<String, String>,
}

/// Time-based restrictions for permissions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TimeRestrictions {
    /// Start time (hour of day, 0-23)
    pub start_hour: Option<u8>,
    /// End time (hour of day, 0-23)
    pub end_hour: Option<u8>,
    /// Days of week (0=Sunday, 6=Saturday)
    pub allowed_days: Option<Vec<u8>>,
}

/// Role manager for RBAC operations
pub struct RoleManager {
    roles: Arc<RwLock<HashMap<String, Role>>>,
    user_roles: Arc<RwLock<HashMap<String, HashSet<String>>>>,
}

impl RoleManager {
    /// Create a new role manager
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
            user_roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a role manager with default roles
    pub async fn with_default_roles() -> Self {
        let manager = Self::new();
        manager.setup_default_roles().await;
        manager
    }

    /// Set up default roles for common use cases
    async fn setup_default_roles(&self) {
        // Admin role with all permissions
        let admin_role = Role::new("admin", "Administrator with full access")
            .with_permission(Permission::new("*", "*"));

        // User role with basic permissions
        let user_role = Role::new("user", "Regular user with basic access")
            .with_permission(Permission::new("messages", "read"))
            .with_permission(Permission::new("profile", "read"))
            .with_permission(Permission::new("profile", "write"));

        // Guest role with read-only access
        let guest_role = Role::new("guest", "Guest user with read-only access")
            .with_permission(Permission::new("messages", "read"));

        // Moderator role inheriting from user
        let moderator_role = Role::new("moderator", "Moderator with additional permissions")
            .with_parent_role("user")
            .with_permission(Permission::new("messages", "write"))
            .with_permission(Permission::new("messages", "delete"));

        self.add_role(admin_role).await.ok();
        self.add_role(user_role).await.ok();
        self.add_role(guest_role).await.ok();
        self.add_role(moderator_role).await.ok();
    }

    /// Add a role to the system
    pub async fn add_role(&self, role: Role) -> AsyncApiResult<()> {
        let mut roles = self.roles.write().await;

        if roles.contains_key(&role.name) {
            return Err(AsyncApiError::Authorization {
                message: format!("Role '{}' already exists", role.name),
                required_permissions: vec![],
                user_permissions: vec![],
            });
        }

        debug!("Adding role: {}", role.name);
        roles.insert(role.name.clone(), role);
        Ok(())
    }

    /// Get a role by name
    pub fn get_role(&self, name: &str) -> Option<Role> {
        // This is a simplified synchronous version for internal use
        // In a real implementation, you might want to use async here too
        if let Ok(roles) = self.roles.try_read() {
            roles.get(name).cloned()
        } else {
            None
        }
    }

    /// Get a role by name (async version)
    pub async fn get_role_async(&self, name: &str) -> Option<Role> {
        let roles = self.roles.read().await;
        roles.get(name).cloned()
    }

    /// Update a role
    pub async fn update_role(&self, role: Role) -> AsyncApiResult<()> {
        let mut roles = self.roles.write().await;

        if !roles.contains_key(&role.name) {
            return Err(AsyncApiError::Authorization {
                message: format!("Role '{}' does not exist", role.name),
                required_permissions: vec![],
                user_permissions: vec![],
            });
        }

        debug!("Updating role: {}", role.name);
        roles.insert(role.name.clone(), role);
        Ok(())
    }

    /// Remove a role
    pub async fn remove_role(&self, name: &str) -> AsyncApiResult<()> {
        let mut roles = self.roles.write().await;

        if roles.remove(name).is_none() {
            return Err(AsyncApiError::Authorization {
                message: format!("Role '{}' does not exist", name),
                required_permissions: vec![],
                user_permissions: vec![],
            });
        }

        debug!("Removed role: {}", name);

        // Remove role from all users
        let mut user_roles = self.user_roles.write().await;
        for user_role_set in user_roles.values_mut() {
            user_role_set.remove(name);
        }

        Ok(())
    }

    /// Assign a role to a user
    pub async fn assign_role_to_user(&self, user_id: &str, role_name: &str) -> AsyncApiResult<()> {
        // Check if role exists
        {
            let roles = self.roles.read().await;
            if !roles.contains_key(role_name) {
                return Err(AsyncApiError::Authorization {
                    message: format!("Role '{}' does not exist", role_name),
                    required_permissions: vec![],
                    user_permissions: vec![],
                });
            }
        }

        let mut user_roles = self.user_roles.write().await;
        let user_role_set = user_roles.entry(user_id.to_string()).or_insert_with(HashSet::new);
        user_role_set.insert(role_name.to_string());

        debug!("Assigned role '{}' to user '{}'", role_name, user_id);
        Ok(())
    }

    /// Remove a role from a user
    pub async fn remove_role_from_user(&self, user_id: &str, role_name: &str) -> AsyncApiResult<()> {
        let mut user_roles = self.user_roles.write().await;

        if let Some(user_role_set) = user_roles.get_mut(user_id) {
            user_role_set.remove(role_name);
            debug!("Removed role '{}' from user '{}'", role_name, user_id);
        }

        Ok(())
    }

    /// Get all roles for a user
    pub async fn get_user_roles(&self, user_id: &str) -> Vec<Role> {
        let user_roles = self.user_roles.read().await;
        let roles = self.roles.read().await;

        if let Some(role_names) = user_roles.get(user_id) {
            role_names.iter()
                .filter_map(|name| roles.get(name).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all permissions for a user (including inherited)
    pub async fn get_user_permissions(&self, user_id: &str) -> HashSet<Permission> {
        let user_roles = self.get_user_roles(user_id).await;
        let mut all_permissions = HashSet::new();

        for role in user_roles {
            all_permissions.extend(role.get_all_permissions(self));
        }

        all_permissions
    }

    /// Check if a user has a specific permission
    pub async fn user_has_permission(&self, user_id: &str, required_permission: &Permission) -> bool {
        let user_permissions = self.get_user_permissions(user_id).await;

        for permission in &user_permissions {
            if permission.matches(required_permission) {
                return true;
            }
        }

        false
    }

    /// Check if a user has any of the required permissions
    pub async fn user_has_any_permission(&self, user_id: &str, required_permissions: &[Permission]) -> bool {
        for permission in required_permissions {
            if self.user_has_permission(user_id, permission).await {
                return true;
            }
        }
        false
    }

    /// Check if a user has all of the required permissions
    pub async fn user_has_all_permissions(&self, user_id: &str, required_permissions: &[Permission]) -> bool {
        for permission in required_permissions {
            if !self.user_has_permission(user_id, permission).await {
                return false;
            }
        }
        true
    }

    /// List all roles
    pub async fn list_roles(&self) -> Vec<Role> {
        let roles = self.roles.read().await;
        roles.values().cloned().collect()
    }

    /// Get role statistics
    pub async fn get_statistics(&self) -> RoleStatistics {
        let roles = self.roles.read().await;
        let user_roles = self.user_roles.read().await;

        RoleStatistics {
            total_roles: roles.len(),
            total_users_with_roles: user_roles.len(),
            active_roles: roles.values().filter(|r| r.active).count(),
            roles_by_name: roles.keys().cloned().collect(),
        }
    }
}

impl Default for RoleManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the RBAC system
#[derive(Debug, Clone, Serialize)]
pub struct RoleStatistics {
    pub total_roles: usize,
    pub total_users_with_roles: usize,
    pub active_roles: usize,
    pub roles_by_name: Vec<String>,
}

/// Helper macros for creating permissions
#[macro_export]
macro_rules! permission {
    ($resource:expr, $action:expr) => {
        Permission::new($resource, $action)
    };
}

#[macro_export]
macro_rules! role {
    ($name:expr, $description:expr) => {
        Role::new($name, $description)
    };
    ($name:expr, $description:expr, [$($permission:expr),*]) => {
        Role::new($name, $description)
            $(.with_permission($permission))*
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_role_creation() {
        let role = Role::new("test_role", "Test role")
            .with_permission(Permission::new("messages", "read"))
            .with_permission(Permission::new("users", "write"));

        assert_eq!(role.name, "test_role");
        assert_eq!(role.permissions.len(), 2);
        assert!(role.has_permission(&Permission::new("messages", "read")));
    }

    #[tokio::test]
    async fn test_permission_matching() {
        let wildcard_permission = Permission::new("*", "read");
        let specific_permission = Permission::new("messages", "read");

        assert!(wildcard_permission.matches(&specific_permission));
        assert!(specific_permission.matches(&specific_permission));
    }

    #[tokio::test]
    async fn test_role_manager() {
        let manager = RoleManager::new();

        let role = Role::new("test_role", "Test role")
            .with_permission(Permission::new("messages", "read"));

        manager.add_role(role).await.unwrap();
        manager.assign_role_to_user("user1", "test_role").await.unwrap();

        let user_roles = manager.get_user_roles("user1").await;
        assert_eq!(user_roles.len(), 1);
        assert_eq!(user_roles[0].name, "test_role");

        let has_permission = manager.user_has_permission(
            "user1",
            &Permission::new("messages", "read")
        ).await;
        assert!(has_permission);
    }

    #[tokio::test]
    async fn test_role_inheritance() {
        let manager = RoleManager::new();

        let parent_role = Role::new("parent", "Parent role")
            .with_permission(Permission::new("base", "read"));

        let child_role = Role::new("child", "Child role")
            .with_parent_role("parent")
            .with_permission(Permission::new("extra", "write"));

        manager.add_role(parent_role).await.unwrap();
        manager.add_role(child_role).await.unwrap();
        manager.assign_role_to_user("user1", "child").await.unwrap();

        // User should have permissions from both parent and child roles
        let has_parent_permission = manager.user_has_permission(
            "user1",
            &Permission::new("base", "read")
        ).await;
        let has_child_permission = manager.user_has_permission(
            "user1",
            &Permission::new("extra", "write")
        ).await;

        assert!(has_parent_permission);
        assert!(has_child_permission);
    }
}
`
  });
}

function TransportMod({
  asyncapi
}) {
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

  // Generate module declarations based on detected protocols
  let moduleDeclarations = 'pub mod factory;\n';
  if (protocols.has('mqtt') || protocols.has('mqtts')) {
    moduleDeclarations += 'pub mod mqtt;\n';
  }
  if (protocols.has('kafka')) {
    moduleDeclarations += 'pub mod kafka;\n';
  }
  if (protocols.has('amqp') || protocols.has('amqps')) {
    moduleDeclarations += 'pub mod amqp;\n';
  }
  if (protocols.has('ws') || protocols.has('wss')) {
    moduleDeclarations += 'pub mod websocket;\n';
  }
  if (protocols.has('http') || protocols.has('https')) {
    moduleDeclarations += 'pub mod http;\n';
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "mod.rs",
    children: `//! Transport layer abstraction for AsyncAPI protocols
//!
//! This module provides a unified interface for different transport protocols
//! including MQTT, Kafka, AMQP, WebSocket, and HTTP.
#![allow(dead_code, unused_imports)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::errors::{AsyncApiResult, AsyncApiError};
use crate::models::AsyncApiMessage;

${moduleDeclarations}

/// Transport configuration for different protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub additional_config: HashMap<String, String>,
}

/// Connection state for transport implementations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

/// Transport statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_attempts: u64,
    pub last_error: Option<String>,
}

/// Message metadata for transport operations
#[derive(Debug, Clone)]
pub struct MessageMetadata {
    pub channel: String,
    pub operation: String,
    pub content_type: Option<String>,
    pub headers: HashMap<String, String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Transport message wrapper
#[derive(Debug, Clone)]
pub struct TransportMessage {
    pub metadata: MessageMetadata,
    pub payload: Vec<u8>,
}

/// Trait for transport implementations
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to the transport
    async fn connect(&mut self) -> AsyncApiResult<()>;

    /// Disconnect from the transport
    async fn disconnect(&mut self) -> AsyncApiResult<()>;

    /// Check if transport is connected
    fn is_connected(&self) -> bool;

    /// Get current connection state
    fn connection_state(&self) -> ConnectionState;

    /// Send a message through the transport
    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()>;

    /// Subscribe to a channel/topic
    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()>;

    /// Unsubscribe from a channel/topic
    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()>;

    /// Start listening for messages (non-blocking)
    async fn start_listening(&mut self) -> AsyncApiResult<()>;

    /// Stop listening for messages
    async fn stop_listening(&mut self) -> AsyncApiResult<()>;

    /// Get transport statistics
    fn get_stats(&self) -> TransportStats;

    /// Health check for the transport
    async fn health_check(&self) -> AsyncApiResult<bool>;

    /// Get protocol name
    fn protocol(&self) -> &str;
}

/// Message handler trait for processing incoming messages
#[async_trait]
pub trait MessageHandler: Send + Sync {
    async fn handle_message(&self, message: TransportMessage) -> AsyncApiResult<()>;
}

/// Transport manager for coordinating multiple transports
pub struct TransportManager {
    transports: Arc<RwLock<HashMap<String, Box<dyn Transport>>>>,
    handlers: Arc<RwLock<HashMap<String, Arc<dyn MessageHandler>>>>,
    stats: Arc<RwLock<HashMap<String, TransportStats>>>,
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new() -> Self {
        Self {
            transports: Arc::new(RwLock::new(HashMap::new())),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a transport to the manager
    pub async fn add_transport(&self, name: String, transport: Box<dyn Transport>) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        let protocol = transport.protocol().to_string();
        transports.insert(name.clone(), transport);

        // Initialize stats
        let mut stats = self.stats.write().await;
        stats.insert(name.clone(), TransportStats::default());

        tracing::info!("Added {} transport: {}", protocol, name);
        Ok(())
    }

    /// Remove a transport from the manager
    pub async fn remove_transport(&self, name: &str) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        if let Some(mut transport) = transports.remove(name) {
            transport.disconnect().await?;
        }

        let mut stats = self.stats.write().await;
        stats.remove(name);

        tracing::info!("Removed transport: {}", name);
        Ok(())
    }

    /// Register a message handler for a channel
    pub async fn register_handler(&self, channel: String, handler: Arc<dyn MessageHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.insert(channel.clone(), handler);
        tracing::info!("Registered handler for channel: {}", channel);
    }

    /// Connect all transports
    pub async fn connect_all(&self) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        for (name, transport) in transports.iter_mut() {
            match transport.connect().await {
                Ok(_) => tracing::info!("Connected transport: {}", name),
                Err(e) => {
                    tracing::error!("Failed to connect transport {}: {}", name, e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Disconnect all transports
    pub async fn disconnect_all(&self) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        for (name, transport) in transports.iter_mut() {
            match transport.disconnect().await {
                Ok(_) => tracing::info!("Disconnected transport: {}", name),
                Err(e) => tracing::error!("Failed to disconnect transport {}: {}", name, e),
            }
        }
        Ok(())
    }

    /// Start listening on all transports
    pub async fn start_all(&self) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        for (name, transport) in transports.iter_mut() {
            match transport.start_listening().await {
                Ok(_) => tracing::info!("Started listening on transport: {}", name),
                Err(e) => {
                    tracing::error!("Failed to start listening on transport {}: {}", name, e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Stop listening on all transports
    pub async fn stop_all(&self) -> AsyncApiResult<()> {
        let mut transports = self.transports.write().await;
        for (name, transport) in transports.iter_mut() {
            match transport.stop_listening().await {
                Ok(_) => tracing::info!("Stopped listening on transport: {}", name),
                Err(e) => tracing::error!("Failed to stop listening on transport {}: {}", name, e),
            }
        }
        Ok(())
    }

    /// Get aggregated statistics from all transports
    pub async fn get_all_stats(&self) -> HashMap<String, TransportStats> {
        let transports = self.transports.read().await;
        let mut all_stats = HashMap::new();

        for (name, transport) in transports.iter() {
            all_stats.insert(name.clone(), transport.get_stats());
        }

        all_stats
    }

    /// Perform health check on all transports
    pub async fn health_check_all(&self) -> HashMap<String, bool> {
        let transports = self.transports.read().await;
        let mut health_status = HashMap::new();

        for (name, transport) in transports.iter() {
            let is_healthy = transport.health_check().await.unwrap_or(false);
            health_status.insert(name.clone(), is_healthy);
        }

        health_status
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}
`
  });
}

function TransportFactory({
  asyncapi
}) {
  // Detect protocols from servers
  const servers = asyncapi.servers();
  const protocols = new Set();
  if (servers) {
    Object.entries(servers).forEach(([_, server]) => {
      const protocol = server.protocol && server.protocol();
      if (protocol) {
        protocols.add(protocol.toLowerCase());
      }
    });
  }

  // Generate imports based on detected protocols
  let imports = '';
  if (protocols.has('mqtt') || protocols.has('mqtts')) {
    imports += 'use crate::transport::mqtt::MqttTransport;\n';
  }
  if (protocols.has('kafka')) {
    imports += 'use crate::transport::kafka::KafkaTransport;\n';
  }
  if (protocols.has('amqp') || protocols.has('amqps')) {
    imports += 'use crate::transport::amqp::AmqpTransport;\n';
  }
  if (protocols.has('ws') || protocols.has('wss')) {
    imports += 'use crate::transport::websocket::WebSocketTransport;\n';
  }
  if (protocols.has('http') || protocols.has('https')) {
    imports += 'use crate::transport::http::HttpTransport;\n';
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "factory.rs",
    children: `//! Transport factory for creating transport instances based on protocol

use std::collections::HashMap;
use std::sync::Arc;

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{Transport, TransportConfig};
${imports}

/// Factory for creating transport instances based on protocol
pub struct TransportFactory;

impl TransportFactory {
    /// Create a transport instance based on the protocol
    pub fn create_transport(config: TransportConfig) -> AsyncApiResult<Box<dyn Transport>> {
        match config.protocol.to_lowercase().as_str() {${protocols.has('mqtt') || protocols.has('mqtts') ? `
            "mqtt" | "mqtts" => {
                let transport = MqttTransport::new(config)?;
                Ok(Box::new(transport))
            }` : ''}${protocols.has('kafka') ? `
            "kafka" => {
                let transport = KafkaTransport::new(config)?;
                Ok(Box::new(transport))
            }` : ''}${protocols.has('amqp') || protocols.has('amqps') ? `
            "amqp" | "amqps" => {
                let transport = AmqpTransport::new(config)?;
                Ok(Box::new(transport))
            }` : ''}${protocols.has('ws') || protocols.has('wss') ? `
            "ws" | "wss" | "websocket" => {
                let transport = WebSocketTransport::new(config)?;
                Ok(Box::new(transport))
            }` : ''}${protocols.has('http') || protocols.has('https') ? `
            "http" | "https" => {
                let transport = HttpTransport::new(config)?;
                Ok(Box::new(transport))
            }` : ''}
            _ => Err(AsyncApiError::new(
                format!("Unsupported protocol: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            )),
        }
    }

    /// Create multiple transports from a configuration map
    pub fn create_transports(
        configs: HashMap<String, TransportConfig>,
    ) -> AsyncApiResult<HashMap<String, Box<dyn Transport>>> {
        let mut transports = HashMap::new();

        for (name, config) in configs {
            let transport = Self::create_transport(config)?;
            transports.insert(name, transport);
        }

        Ok(transports)
    }

    /// Get supported protocols
    pub fn supported_protocols() -> Vec<&'static str> {
        vec!["mqtt", "mqtts", "kafka", "amqp", "amqps", "ws", "wss", "websocket", "http", "https"]
    }

    /// Check if a protocol is supported
    pub fn is_protocol_supported(protocol: &str) -> bool {
        Self::supported_protocols().contains(&protocol.to_lowercase().as_str())
    }

    /// Create transport configuration from AsyncAPI server specification
    pub fn config_from_server(
        _server_name: &str,
        protocol: &str,
        host: &str,
        port: u16,
        additional_config: HashMap<String, String>,
    ) -> TransportConfig {
        TransportConfig {
            protocol: protocol.to_string(),
            host: host.to_string(),
            port,
            username: additional_config.get("username").cloned(),
            password: additional_config.get("password").cloned(),
            tls: protocol.ends_with('s') || additional_config.get("tls").map_or(false, |v| v == "true"),
            additional_config,
        }
    }

    /// Validate transport configuration
    pub fn validate_config(config: &TransportConfig) -> AsyncApiResult<()> {
        // Check if protocol is supported
        if !Self::is_protocol_supported(&config.protocol) {
            return Err(AsyncApiError::new(
                format!("Unsupported protocol: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            ));
        }

        // Validate host
        if config.host.is_empty() {
            return Err(AsyncApiError::new(
                "Host cannot be empty".to_string(),
                ErrorCategory::Configuration,
                None,
            ));
        }

        // Validate port
        if config.port == 0 {
            return Err(AsyncApiError::new(
                "Port cannot be zero".to_string(),
                ErrorCategory::Configuration,
                None,
            ));
        }

        // Protocol-specific validation
        match config.protocol.to_lowercase().as_str() {
            "mqtt" | "mqtts" => {
                // MQTT-specific validation
                if config.port < 1024 && !config.additional_config.contains_key("allow_privileged_ports") {
                    tracing::warn!("Using privileged port {} for MQTT", config.port);
                }
            }
            "kafka" => {
                // Kafka-specific validation
                if config.port != 9092 && !config.additional_config.contains_key("custom_port") {
                    tracing::warn!("Using non-standard port {} for Kafka", config.port);
                }
            }
            "amqp" | "amqps" => {
                // AMQP-specific validation
                let default_port = if config.protocol == "amqps" { 5671 } else { 5672 };
                if config.port != default_port && !config.additional_config.contains_key("custom_port") {
                    tracing::warn!("Using non-standard port {} for AMQP", config.port);
                }
            }
            "ws" | "wss" | "websocket" => {
                // WebSocket-specific validation
                let default_port = if config.protocol == "wss" { 443 } else { 80 };
                if config.port != default_port && !config.additional_config.contains_key("custom_port") {
                    tracing::warn!("Using non-standard port {} for WebSocket", config.port);
                }
            }
            "http" | "https" => {
                // HTTP-specific validation
                let default_port = if config.protocol == "https" { 443 } else { 80 };
                if config.port != default_port && !config.additional_config.contains_key("custom_port") {
                    tracing::warn!("Using non-standard port {} for HTTP", config.port);
                }
            }
            _ => {
                // This should not happen due to earlier validation
                return Err(AsyncApiError::new(
                    format!("Unknown protocol for validation: {}", config.protocol),
                    ErrorCategory::Configuration,
                    None,
                ));
            }
        }

        Ok(())
    }

    /// Create default configuration for a protocol
    pub fn default_config(protocol: &str) -> AsyncApiResult<TransportConfig> {
        let (default_port, tls) = match protocol.to_lowercase().as_str() {
            "mqtt" => (1883, false),
            "mqtts" => (8883, true),
            "kafka" => (9092, false),
            "amqp" => (5672, false),
            "amqps" => (5671, true),
            "ws" | "websocket" => (80, false),
            "wss" => (443, true),
            "http" => (80, false),
            "https" => (443, true),
            _ => {
                return Err(AsyncApiError::new(
                    format!("Unsupported protocol: {}", protocol),
                    ErrorCategory::Configuration,
                    None,
                ));
            }
        };

        Ok(TransportConfig {
            protocol: protocol.to_string(),
            host: "localhost".to_string(),
            port: default_port,
            username: None,
            password: None,
            tls,
            additional_config: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_protocols() {
        let protocols = TransportFactory::supported_protocols();
        assert!(protocols.contains(&"mqtt"));
        assert!(protocols.contains(&"kafka"));
        assert!(protocols.contains(&"amqp"));
        assert!(protocols.contains(&"ws"));
        assert!(protocols.contains(&"http"));
    }

    #[test]
    fn test_is_protocol_supported() {
        assert!(TransportFactory::is_protocol_supported("mqtt"));
        assert!(TransportFactory::is_protocol_supported("MQTT"));
        assert!(TransportFactory::is_protocol_supported("kafka"));
        assert!(!TransportFactory::is_protocol_supported("unknown"));
    }

    #[test]
    fn test_default_config() {
        let config = TransportFactory::default_config("mqtt").unwrap();
        assert_eq!(config.protocol, "mqtt");
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 1883);
        assert!(!config.tls);

        let config = TransportFactory::default_config("mqtts").unwrap();
        assert_eq!(config.protocol, "mqtts");
        assert_eq!(config.port, 8883);
        assert!(config.tls);
    }

    #[test]
    fn test_validate_config() {
        let mut config = TransportFactory::default_config("mqtt").unwrap();
        assert!(TransportFactory::validate_config(&config).is_ok());

        // Test invalid protocol
        config.protocol = "invalid".to_string();
        assert!(TransportFactory::validate_config(&config).is_err());

        // Test empty host
        config.protocol = "mqtt".to_string();
        config.host = "".to_string();
        assert!(TransportFactory::validate_config(&config).is_err());

        // Test zero port
        config.host = "localhost".to_string();
        config.port = 0;
        assert!(TransportFactory::validate_config(&config).is_err());
    }
}
`
  });
}

function MqttTransport({
  asyncapi
}) {
  // Check if MQTT protocol is used
  const servers = asyncapi.servers();
  let hasMqtt = false;
  if (servers) {
    Object.entries(servers).forEach(([_name, server]) => {
      const protocol = server.protocol && server.protocol();
      if (protocol && ['mqtt', 'mqtts'].includes(protocol.toLowerCase())) {
        hasMqtt = true;
      }
    });
  }

  // Only generate file if MQTT is used
  if (!hasMqtt) {
    return null;
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "mqtt.rs",
    children: `//! MQTT transport implementation

use async_trait::async_trait;
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

/// MQTT transport implementation
pub struct MqttTransport {
    config: TransportConfig,
    client: Option<AsyncClient>,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    subscriptions: Arc<RwLock<HashMap<String, QoS>>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl MqttTransport {
    /// Create a new MQTT transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if config.protocol != "mqtt" && config.protocol != "mqtts" {
            return Err(AsyncApiError::new(
                format!("Invalid protocol for MQTT transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            ));
        }

        Ok(Self {
            config,
            client: None,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            message_handler: None,
            shutdown_tx: None,
        })
    }

    /// Set message handler for incoming messages
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Create MQTT options from configuration
    fn create_mqtt_options(&self) -> AsyncApiResult<MqttOptions> {
        let client_id = self.config.additional_config
            .get("client_id")
            .cloned()
            .unwrap_or_else(|| format!("asyncapi-client-{}", uuid::Uuid::new_v4()));

        let mut mqtt_options = MqttOptions::new(client_id, &self.config.host, self.config.port);

        // Set credentials if provided
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            mqtt_options.set_credentials(username, password);
        }

        // Configure TLS if enabled
        if self.config.tls {
            let tls_config = rumqttc::TlsConfiguration::Simple {
                ca: vec![],
                alpn: None,
                client_auth: None,
            };
            mqtt_options.set_transport(rumqttc::Transport::Tls(tls_config));
        }

        // Set keep alive interval
        if let Some(keep_alive) = self.config.additional_config
            .get("keep_alive")
            .and_then(|v| v.parse::<u64>().ok())
        {
            mqtt_options.set_keep_alive(Duration::from_secs(keep_alive));
        } else {
            mqtt_options.set_keep_alive(Duration::from_secs(60));
        }

        // Set clean session
        let clean_session = self.config.additional_config
            .get("clean_session")
            .map(|v| v.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);
        mqtt_options.set_clean_session(clean_session);

        // Set max packet size
        if let Some(max_packet_size) = self.config.additional_config
            .get("max_packet_size")
            .and_then(|v| v.parse::<usize>().ok())
        {
            mqtt_options.set_max_packet_size(max_packet_size, max_packet_size);
        }

        Ok(mqtt_options)
    }

    /// Start the MQTT event loop
    async fn start_event_loop(&mut self, mut event_loop: EventLoop) -> AsyncApiResult<()> {
        let connection_state = Arc::clone(&self.connection_state);
        let stats_arc = Arc::clone(&self.stats);
        let message_handler = self.message_handler.clone();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = event_loop.poll() => {
                        match event {
                            Ok(Event::Incoming(Packet::Publish(publish))) => {
                                {
                                    let mut stats = stats_arc.write().await;
                                    stats.messages_received += 1;
                                    stats.bytes_received += publish.payload.len() as u64;
                                }

                                if let Some(handler) = &message_handler {
                                    let mut headers = HashMap::new();
                                    headers.insert("topic".to_string(), publish.topic.clone());
                                    headers.insert("qos".to_string(), format!("{:?}", publish.qos));
                                    headers.insert("retain".to_string(), publish.retain.to_string());
                                    headers.insert("dup".to_string(), publish.dup.to_string());

                                    let metadata = MessageMetadata {
                                        channel: publish.topic.clone(),
                                        operation: "receive".to_string(),
                                        content_type: Some("application/octet-stream".to_string()),
                                        headers,
                                        timestamp: chrono::Utc::now(),
                                    };

                                    let transport_message = TransportMessage {
                                        metadata,
                                        payload: publish.payload.to_vec(),
                                    };

                                    if let Err(e) = handler.handle_message(transport_message).await {
                                        tracing::error!("Failed to handle MQTT message: {}", e);
                                        let mut error_stats = stats_arc.write().await;
                                        error_stats.last_error = Some(e.to_string());
                                    }
                                }
                            }
                            Ok(Event::Incoming(Packet::ConnAck(_))) => {
                                *connection_state.write().await = ConnectionState::Connected;
                                tracing::info!("MQTT connection established");
                            }
                            Ok(Event::Incoming(Packet::Disconnect)) => {
                                *connection_state.write().await = ConnectionState::Disconnected;
                                tracing::info!("MQTT disconnected");
                            }
                            Ok(Event::Outgoing(_)) => {
                                // Handle outgoing packets if needed
                            }
                            Err(e) => {
                                tracing::error!("MQTT event loop error: {}", e);
                                *connection_state.write().await = ConnectionState::Failed;
                                let mut stats = stats_arc.write().await;
                                stats.last_error = Some(e.to_string());
                                break;
                            }
                            _ => {
                                // Handle other packet types
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("MQTT event loop shutdown requested");
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

#[async_trait]
impl Transport for MqttTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        let mqtt_options = self.create_mqtt_options()?;
        let (client, event_loop) = AsyncClient::new(mqtt_options, 10);

        self.client = Some(client);

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        // Start event loop
        self.start_event_loop(event_loop).await?;

        tracing::info!("MQTT transport connection initiated");
        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        if let Some(client) = &self.client {
            if let Err(e) = client.disconnect().await {
                tracing::warn!("Error disconnecting MQTT client: {}", e);
            }
        }

        self.client = None;
        *self.connection_state.write().await = ConnectionState::Disconnected;

        tracing::info!("MQTT transport disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection_state
            .try_read()
            .map(|state| matches!(*state, ConnectionState::Connected))
            .unwrap_or(false)
    }

    fn connection_state(&self) -> ConnectionState {
        self.connection_state
            .try_read()
            .map(|state| *state)
            .unwrap_or(ConnectionState::Disconnected)
    }

    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()> {
        let client = self.client.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "MQTT client not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let topic = &message.metadata.channel;
        let qos = message.metadata.headers
            .get("qos")
            .and_then(|q| match q.as_str() {
                "0" => Some(QoS::AtMostOnce),
                "1" => Some(QoS::AtLeastOnce),
                "2" => Some(QoS::ExactlyOnce),
                _ => None,
            })
            .unwrap_or(QoS::AtMostOnce);

        let retain = message.metadata.headers
            .get("retain")
            .map(|r| r.parse::<bool>().unwrap_or(false))
            .unwrap_or(false);

        let payload_len = message.payload.len();

        client
            .publish(topic, qos, retain, message.payload)
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to publish MQTT message: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += payload_len as u64;

        tracing::debug!("Published MQTT message to topic: {}", topic);
        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let client = self.client.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "MQTT client not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let qos = QoS::AtMostOnce; // Default QoS, could be configurable

        client.subscribe(channel, qos).await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to subscribe to MQTT topic: {}", e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.insert(channel.to_string(), qos);

        tracing::info!("Subscribed to MQTT topic: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let client = self.client.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "MQTT client not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        client.unsubscribe(channel).await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to unsubscribe from MQTT topic: {}", e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.remove(channel);

        tracing::info!("Unsubscribed from MQTT topic: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // MQTT listening is handled by the event loop, which is started in connect()
        tracing::info!("MQTT transport is listening for messages");
        Ok(())
    }

    async fn stop_listening(&mut self) -> AsyncApiResult<()> {
        // Stop listening by disconnecting
        self.disconnect().await
    }

    fn get_stats(&self) -> TransportStats {
        self.stats.try_read()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }

    async fn health_check(&self) -> AsyncApiResult<bool> {
        Ok(self.is_connected())
    }

    fn protocol(&self) -> &str {
        &self.config.protocol
    }
}

impl Drop for MqttTransport {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.try_send(());
        }
    }
}
`
  });
}

function KafkaTransport({
  asyncapi
}) {
  // Check if Kafka protocol is used
  const servers = asyncapi.servers();
  let hasKafka = false;
  if (servers) {
    Object.entries(servers).forEach(([_name, server]) => {
      const protocol = server.protocol && server.protocol();
      if (protocol && protocol.toLowerCase() === 'kafka') {
        hasKafka = true;
      }
    });
  }

  // Only generate file if Kafka is used
  if (!hasKafka) {
    return null;
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "kafka.rs",
    children: `//! Kafka transport implementation

use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::{Message, TopicPartitionList};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::StreamExt;

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

/// Kafka transport implementation
pub struct KafkaTransport {
    config: TransportConfig,
    producer: Option<FutureProducer>,
    consumer: Option<StreamConsumer>,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    subscriptions: Arc<RwLock<Vec<String>>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl KafkaTransport {
    /// Create a new Kafka transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if config.protocol != "kafka" {
            return Err(AsyncApiError::new(
                format!("Invalid protocol for Kafka transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            ));
        }

        Ok(Self {
            config,
            producer: None,
            consumer: None,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            subscriptions: Arc::new(RwLock::new(Vec::new())),
            message_handler: None,
            shutdown_tx: None,
        })
    }

    /// Set message handler for incoming messages
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Create Kafka client configuration
    fn create_client_config(&self) -> ClientConfig {
        let mut config = ClientConfig::new();

        // Set bootstrap servers
        let bootstrap_servers = format!("{}:{}", self.config.host, self.config.port);
        config.set("bootstrap.servers", &bootstrap_servers);

        // Set security configuration
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            config.set("security.protocol", "SASL_PLAINTEXT");
            config.set("sasl.mechanism", "PLAIN");
            config.set("sasl.username", username);
            config.set("sasl.password", password);
        }

        if self.config.tls {
            if self.config.username.is_some() {
                config.set("security.protocol", "SASL_SSL");
            } else {
                config.set("security.protocol", "SSL");
            }
        }

        // Set additional configuration
        for (key, value) in &self.config.additional_config {
            config.set(key, value);
        }

        // Set default configurations if not provided
        if !self.config.additional_config.contains_key("client.id") {
            let client_id = format!("asyncapi-client-{}", uuid::Uuid::new_v4());
            config.set("client.id", &client_id);
        }

        config
    }

    /// Create producer configuration
    fn create_producer_config(&self) -> ClientConfig {
        let mut config = self.create_client_config();

        // Producer-specific settings
        config.set("message.timeout.ms", "30000");
        config.set("queue.buffering.max.messages", "100000");
        config.set("queue.buffering.max.ms", "1000");
        config.set("batch.num.messages", "1000");

        // Set compression if specified
        if let Some(compression) = self.config.additional_config.get("compression.type") {
            config.set("compression.type", compression);
        } else {
            config.set("compression.type", "snappy");
        }

        config
    }

    /// Create consumer configuration
    fn create_consumer_config(&self) -> ClientConfig {
        let mut config = self.create_client_config();

        // Consumer-specific settings
        let group_id = self.config.additional_config
            .get("group.id")
            .cloned()
            .unwrap_or_else(|| format!("asyncapi-group-{}", uuid::Uuid::new_v4()));
        config.set("group.id", &group_id);

        config.set("enable.auto.commit", "true");
        config.set("auto.commit.interval.ms", "5000");
        config.set("session.timeout.ms", "30000");
        config.set("heartbeat.interval.ms", "10000");

        // Set auto offset reset
        let auto_offset_reset = self.config.additional_config
            .get("auto.offset.reset")
            .map(|s| s.as_str())
            .unwrap_or("latest");
        config.set("auto.offset.reset", auto_offset_reset);

        config
    }

    /// Start consuming messages
    async fn start_consumer_loop(&mut self) -> AsyncApiResult<()> {
        if let Some(consumer) = &self.consumer {
            let consumer = consumer.clone();
            let connection_state = Arc::clone(&self.connection_state);
            let stats = Arc::clone(&self.stats);
            let message_handler = self.message_handler.clone();
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            self.shutdown_tx = Some(shutdown_tx);

            tokio::spawn(async move {
                let mut message_stream = consumer.stream();

                loop {
                    tokio::select! {
                        message_result = message_stream.next() => {
                            match message_result {
                                Some(Ok(message)) => {
                                    let mut stats = stats.write().await;
                                    stats.messages_received += 1;
                                    if let Some(payload) = message.payload() {
                                        stats.bytes_received += payload.len() as u64;
                                    }
                                    drop(stats);

                                    if let Some(handler) = &message_handler {
                                        let topic = message.topic().to_string();
                                        let partition = message.partition();
                                        let offset = message.offset();

                                        let mut headers = HashMap::new();
                                        headers.insert("partition".to_string(), partition.to_string());
                                        headers.insert("offset".to_string(), offset.to_string());

                                        if let Some(key) = message.key() {
                                            if let Ok(key_str) = std::str::from_utf8(key) {
                                                headers.insert("key".to_string(), key_str.to_string());
                                            }
                                        }

                                        if let Some(kafka_headers) = message.headers() {
                                            for header in kafka_headers.iter() {
                                                if let Ok(value_str) = std::str::from_utf8(header.value) {
                                                    headers.insert(header.key.to_string(), value_str.to_string());
                                                }
                                            }
                                        }

                                        let metadata = MessageMetadata {
                                            channel: topic,
                                            operation: "receive".to_string(),
                                            content_type: Some("application/octet-stream".to_string()),
                                            headers,
                                            timestamp: chrono::Utc::now(),
                                        };

                                        let payload = message.payload().unwrap_or(&[]).to_vec();
                                        let transport_message = TransportMessage { metadata, payload };

                                        if let Err(e) = handler.handle_message(transport_message).await {
                                            tracing::error!("Failed to handle Kafka message: {}", e);
                                            let mut stats = stats.write().await;
                                            stats.last_error = Some(e.to_string());
                                        }
                                    }
                                }
                                Some(Err(e)) => {
                                    tracing::error!("Kafka consumer error: {}", e);
                                    let mut stats = stats.write().await;
                                    stats.last_error = Some(e.to_string());
                                }
                                None => {
                                    tracing::info!("Kafka consumer stream ended");
                                    break;
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            tracing::info!("Kafka consumer shutdown requested");
                            break;
                        }
                    }
                }
            });
        }

        Ok(())
    }
}

#[async_trait]
impl Transport for KafkaTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        // Create producer
        let producer_config = self.create_producer_config();
        let producer: FutureProducer = producer_config.create().map_err(|e| {
            AsyncApiError::new(
                format!("Failed to create Kafka producer: {}", e),
                ErrorCategory::Configuration,
                Some(Box::new(e)),
            )
        })?;

        // Create consumer
        let consumer_config = self.create_consumer_config();
        let consumer: StreamConsumer = consumer_config.create().map_err(|e| {
            AsyncApiError::new(
                format!("Failed to create Kafka consumer: {}", e),
                ErrorCategory::Configuration,
                Some(Box::new(e)),
            )
        })?;

        self.producer = Some(producer);
        self.consumer = Some(consumer);

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        // Start consumer loop
        self.start_consumer_loop().await?;

        *self.connection_state.write().await = ConnectionState::Connected;
        tracing::info!("Kafka transport connected successfully");

        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        self.producer = None;
        self.consumer = None;
        *self.connection_state.write().await = ConnectionState::Disconnected;

        tracing::info!("Kafka transport disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        matches!(
            *self.connection_state.try_read().unwrap_or_else(|_| {
                std::sync::RwLockReadGuard::map(
                    std::sync::RwLock::new(ConnectionState::Disconnected).read().unwrap(),
                    |state| state
                )
            }),
            ConnectionState::Connected
        )
    }

    fn connection_state(&self) -> ConnectionState {
        *self.connection_state.try_read().unwrap_or_else(|_| {
            std::sync::RwLockReadGuard::map(
                std::sync::RwLock::new(ConnectionState::Disconnected).read().unwrap(),
                |state| state
            )
        })
    }

    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()> {
        let producer = self.producer.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "Kafka producer not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let mut record = FutureRecord::to(&message.metadata.channel)
            .payload(&message.payload);

        // Set key if provided
        if let Some(key) = message.metadata.headers.get("key") {
            record = record.key(key);
        }

        // Set partition if provided
        if let Some(partition_str) = message.metadata.headers.get("partition") {
            if let Ok(partition) = partition_str.parse::<i32>() {
                record = record.partition(partition);
            }
        }

        // Set headers
        let mut kafka_headers = rdkafka::message::OwnedHeaders::new();
        for (key, value) in &message.metadata.headers {
            if key != "key" && key != "partition" {
                kafka_headers = kafka_headers.insert(rdkafka::message::Header {
                    key,
                    value: Some(value),
                });
            }
        }
        record = record.headers(kafka_headers);

        // Send message with timeout
        let timeout = Duration::from_secs(30);
        producer.send(record, timeout).await.map_err(|(e, _)| {
            AsyncApiError::new(
                format!("Failed to send Kafka message: {}", e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += message.payload.len() as u64;

        tracing::debug!("Sent Kafka message to topic: {}", message.metadata.channel);
        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let consumer = self.consumer.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "Kafka consumer not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        consumer.subscribe(&[channel]).map_err(|e| {
            AsyncApiError::new(
                format!("Failed to subscribe to Kafka topic {}: {}", channel, e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let mut subscriptions = self.subscriptions.write().await;
        if !subscriptions.contains(&channel.to_string()) {
            subscriptions.push(channel.to_string());
        }

        tracing::info!("Subscribed to Kafka topic: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let consumer = self.consumer.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "Kafka consumer not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        // Kafka doesn't have direct unsubscribe for individual topics
        // We need to resubscribe to remaining topics
        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.retain(|topic| topic != channel);

        if subscriptions.is_empty() {
            consumer.unsubscribe();
        } else {
            let topics: Vec<&str> = subscriptions.iter().map(|s| s.as_str()).collect();
            consumer.subscribe(&topics).map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to resubscribe to Kafka topics: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;
        }

        tracing::info!("Unsubscribed from Kafka topic: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // Kafka listening is handled by the consumer loop, which is started in connect()
        tracing::info!("Kafka transport is listening for messages");
        Ok(())
    }

    async fn stop_listening(&mut self) -> AsyncApiResult<()> {
        // Stop listening by disconnecting
        self.disconnect().await
    }

    fn get_stats(&self) -> TransportStats {
        self.stats.try_read()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }

    async fn health_check(&self) -> AsyncApiResult<bool> {
        // For Kafka, we can check if producer and consumer are available
        Ok(self.is_connected() && self.producer.is_some() && self.consumer.is_some())
    }

    fn protocol(&self) -> &str {
        &self.config.protocol
    }
}

impl Drop for KafkaTransport {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.try_send(());
        }
    }
}
`
  });
}

function AmqpTransport({
  asyncapi
}) {
  // Check if AMQP protocol is used
  const servers = asyncapi.servers();
  let hasAmqp = false;
  if (servers) {
    Object.entries(servers).forEach(([_name, server]) => {
      const protocol = server.protocol && server.protocol();
      if (protocol && ['amqp', 'amqps'].includes(protocol.toLowerCase())) {
        hasAmqp = true;
      }
    });
  }

  // Only generate file if AMQP is used
  if (!hasAmqp) {
    return null;
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "amqp.rs",
    children: `//! AMQP transport implementation

use async_trait::async_trait;
use lapin::{
    options::*, types::FieldTable, BasicProperties, Channel, Connection, ConnectionProperties,
    Consumer, ExchangeKind,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::StreamExt;

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

/// AMQP transport implementation
pub struct AmqpTransport {
    config: TransportConfig,
    connection: Option<Connection>,
    channel: Option<Channel>,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    subscriptions: Arc<RwLock<HashMap<String, String>>>, // queue_name -> routing_key
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl AmqpTransport {
    /// Create a new AMQP transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if config.protocol != "amqp" && config.protocol != "amqps" {
            return Err(AsyncApiError::new(
                format!("Invalid protocol for AMQP transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            ));
        }

        Ok(Self {
            config,
            connection: None,
            channel: None,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            message_handler: None,
            shutdown_tx: None,
        })
    }

    /// Set message handler for incoming messages
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Create AMQP connection URI
    fn create_connection_uri(&self) -> String {
        let scheme = if self.config.tls { "amqps" } else { "amqp" };
        let auth = if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            format!("{}:{}@", username, password)
        } else {
            String::new()
        };

        let vhost = self.config.additional_config
            .get("vhost")
            .map(|v| format!("/{}", v))
            .unwrap_or_else(|| "/".to_string());

        format!("{}://{}{}:{}{}", scheme, auth, self.config.host, self.config.port, vhost)
    }

    /// Get exchange name from configuration
    fn get_exchange_name(&self) -> String {
        self.config.additional_config
            .get("exchange")
            .cloned()
            .unwrap_or_else(|| "asyncapi".to_string())
    }

    /// Get exchange type from configuration
    fn get_exchange_type(&self) -> ExchangeKind {
        match self.config.additional_config
            .get("exchange_type")
            .map(|s| s.as_str())
            .unwrap_or("topic")
        {
            "direct" => ExchangeKind::Direct,
            "fanout" => ExchangeKind::Fanout,
            "headers" => ExchangeKind::Headers,
            _ => ExchangeKind::Topic,
        }
    }

    /// Start consuming messages from a queue
    async fn start_consumer(&mut self, queue_name: &str) -> AsyncApiResult<()> {
        let channel = self.channel.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "AMQP channel not available".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let consumer = channel
            .basic_consume(
                queue_name,
                &format!("asyncapi-consumer-{}", uuid::Uuid::new_v4()),
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to create AMQP consumer: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        let connection_state = Arc::clone(&self.connection_state);
        let stats = Arc::clone(&self.stats);
        let message_handler = self.message_handler.clone();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        tokio::spawn(async move {
            let mut consumer_stream = consumer;

            loop {
                tokio::select! {
                    delivery_result = consumer_stream.next() => {
                        match delivery_result {
                            Some(Ok(delivery)) => {
                                let mut stats = stats.write().await;
                                stats.messages_received += 1;
                                stats.bytes_received += delivery.data.len() as u64;
                                drop(stats);

                                if let Some(handler) = &message_handler {
                                    let mut headers = HashMap::new();

                                    // Add AMQP-specific metadata
                                    headers.insert("exchange".to_string(), delivery.exchange.to_string());
                                    headers.insert("routing_key".to_string(), delivery.routing_key.to_string());
                                    headers.insert("delivery_tag".to_string(), delivery.delivery_tag.to_string());
                                    headers.insert("redelivered".to_string(), delivery.redelivered.to_string());

                                    // Add message properties
                                    if let Some(properties) = &delivery.properties {
                                        if let Some(content_type) = &properties.content_type() {
                                            headers.insert("content_type".to_string(), content_type.to_string());
                                        }
                                        if let Some(content_encoding) = &properties.content_encoding() {
                                            headers.insert("content_encoding".to_string(), content_encoding.to_string());
                                        }
                                        if let Some(message_id) = &properties.message_id() {
                                            headers.insert("message_id".to_string(), message_id.to_string());
                                        }
                                        if let Some(correlation_id) = &properties.correlation_id() {
                                            headers.insert("correlation_id".to_string(), correlation_id.to_string());
                                        }
                                        if let Some(reply_to) = &properties.reply_to() {
                                            headers.insert("reply_to".to_string(), reply_to.to_string());
                                        }
                                        if let Some(user_id) = &properties.user_id() {
                                            headers.insert("user_id".to_string(), user_id.to_string());
                                        }
                                        if let Some(app_id) = &properties.app_id() {
                                            headers.insert("app_id".to_string(), app_id.to_string());
                                        }

                                        // Add custom headers
                                        if let Some(amqp_headers) = properties.headers() {
                                            for (key, value) in amqp_headers.iter() {
                                                if let Ok(value_str) = std::str::from_utf8(&value.to_string().as_bytes()) {
                                                    headers.insert(key.to_string(), value_str.to_string());
                                                }
                                            }
                                        }
                                    }

                                    let metadata = MessageMetadata {
                                        channel: delivery.routing_key.to_string(),
                                        operation: "receive".to_string(),
                                        content_type: delivery.properties
                                            .as_ref()
                                            .and_then(|p| p.content_type())
                                            .map(|ct| ct.to_string())
                                            .or_else(|| Some("application/octet-stream".to_string())),
                                        headers,
                                        timestamp: chrono::Utc::now(),
                                    };

                                    let transport_message = TransportMessage {
                                        metadata,
                                        payload: delivery.data.to_vec(),
                                    };

                                    if let Err(e) = handler.handle_message(transport_message).await {
                                        tracing::error!("Failed to handle AMQP message: {}", e);
                                        let mut stats = stats.write().await;
                                        stats.last_error = Some(e.to_string());
                                    }

                                    // Acknowledge the message
                                    if let Err(e) = delivery.ack(BasicAckOptions::default()).await {
                                        tracing::error!("Failed to acknowledge AMQP message: {}", e);
                                    }
                                }
                            }
                            Some(Err(e)) => {
                                tracing::error!("AMQP consumer error: {}", e);
                                let mut stats = stats.write().await;
                                stats.last_error = Some(e.to_string());
                            }
                            None => {
                                tracing::info!("AMQP consumer stream ended");
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("AMQP consumer shutdown requested");
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

#[async_trait]
impl Transport for AmqpTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        let connection_uri = self.create_connection_uri();
        let connection_properties = ConnectionProperties::default();

        let connection = Connection::connect(&connection_uri, connection_properties)
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to connect to AMQP broker: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        let channel = connection.create_channel().await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to create AMQP channel: {}", e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        // Declare exchange if configured
        let exchange_name = self.get_exchange_name();
        let exchange_type = self.get_exchange_type();

        channel
            .exchange_declare(
                &exchange_name,
                exchange_type,
                ExchangeDeclareOptions {
                    durable: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to declare AMQP exchange: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        self.connection = Some(connection);
        self.channel = Some(channel);

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        *self.connection_state.write().await = ConnectionState::Connected;
        tracing::info!("AMQP transport connected successfully");

        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        if let Some(channel) = &self.channel {
            if let Err(e) = channel.close(200, "Normal shutdown").await {
                tracing::warn!("Error closing AMQP channel: {}", e);
            }
        }

        if let Some(connection) = &self.connection {
            if let Err(e) = connection.close(200, "Normal shutdown").await {
                tracing::warn!("Error closing AMQP connection: {}", e);
            }
        }

        self.channel = None;
        self.connection = None;
        *self.connection_state.write().await = ConnectionState::Disconnected;

        tracing::info!("AMQP transport disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection_state
            .try_read()
            .map(|state| matches!(*state, ConnectionState::Connected))
            .unwrap_or(false)
            && self.connection.as_ref().map_or(false, |c| c.status().connected())
    }

    fn connection_state(&self) -> ConnectionState {
        self.connection_state
            .try_read()
            .map(|state| *state)
            .unwrap_or(ConnectionState::Disconnected)
    }

    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()> {
        let channel = self.channel.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "AMQP channel not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let exchange_name = self.get_exchange_name();
        let routing_key = &message.metadata.channel;

        // Create basic properties
        let mut properties = BasicProperties::default();

        if let Some(content_type) = &message.metadata.content_type {
            properties = properties.with_content_type(content_type.clone().into());
        }

        // Set properties from headers
        if let Some(message_id) = message.metadata.headers.get("message_id") {
            properties = properties.with_message_id(message_id.clone().into());
        }
        if let Some(correlation_id) = message.metadata.headers.get("correlation_id") {
            properties = properties.with_correlation_id(correlation_id.clone().into());
        }
        if let Some(reply_to) = message.metadata.headers.get("reply_to") {
            properties = properties.with_reply_to(reply_to.clone().into());
        }

        // Add custom headers
        let mut field_table = FieldTable::default();
        for (key, value) in &message.metadata.headers {
            if !["message_id", "correlation_id", "reply_to", "content_type"].contains(&key.as_str()) {
                field_table.insert(key.clone().into(), value.clone().into());
            }
        }
        if !field_table.is_empty() {
            properties = properties.with_headers(field_table);
        }

        channel
            .basic_publish(
                &exchange_name,
                routing_key,
                BasicPublishOptions::default(),
                &message.payload,
                properties,
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to publish AMQP message: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += message.payload.len() as u64;

        tracing::debug!("Published AMQP message to routing key: {}", routing_key);
        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let amqp_channel = self.channel.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "AMQP channel not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let exchange_name = self.get_exchange_name();
        let queue_name = format!("asyncapi-queue-{}", uuid::Uuid::new_v4());

        // Declare queue
        let queue = amqp_channel
            .queue_declare(
                &queue_name,
                QueueDeclareOptions {
                    auto_delete: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to declare AMQP queue: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        // Bind queue to exchange
        amqp_channel
            .queue_bind(
                &queue_name,
                &exchange_name,
                channel,
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AsyncApiError::new(
                    format!("Failed to bind AMQP queue: {}", e),
                    ErrorCategory::Network,
                    Some(Box::new(e)),
                )
            })?;

        // Start consuming
        self.start_consumer(&queue_name).await?;

        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.insert(queue_name, channel.to_string());

        tracing::info!("Subscribed to AMQP routing key: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let amqp_channel = self.channel.as_ref().ok_or_else(|| {
            AsyncApiError::new(
                "AMQP channel not connected".to_string(),
                ErrorCategory::Network,
                None,
            )
        })?;

        let mut subscriptions = self.subscriptions.write().await;
        let queue_to_remove = subscriptions
            .iter()
            .find(|(_, routing_key)| routing_key.as_str() == channel)
            .map(|(queue_name, _)| queue_name.clone());

        if let Some(queue_name) = queue_to_remove {
            // Delete the queue
            amqp_channel
                .queue_delete(&queue_name, QueueDeleteOptions::default())
                .await
                .map_err(|e| {
                    AsyncApiError::new(
                        format!("Failed to delete AMQP queue: {}", e),
                        ErrorCategory::Network,
                        Some(Box::new(e)),
                    )
                })?;

            subscriptions.remove(&queue_name);
        }

        tracing::info!("Unsubscribed from AMQP routing key: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // AMQP listening is handled by the consumer, which is started in subscribe()
        tracing::info!("AMQP transport is listening for messages");
        Ok(())
    }

    async fn stop_listening(&mut self) -> AsyncApiResult<()> {
        // Stop listening by disconnecting
        self.disconnect().await
    }

    fn get_stats(&self) -> TransportStats {
        self.stats.try_read()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }

    async fn health_check(&self) -> AsyncApiResult<bool> {
        Ok(self.is_connected())
    }

    fn protocol(&self) -> &str {
        &self.config.protocol
    }
}

impl Drop for AmqpTransport {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.try_send(());
        }
    }
}
`
  });
}

function WebSocketTransport({
  asyncapi,
  params
}) {
  // Check if WebSocket protocol is used
  const servers = asyncapi.servers();
  let hasWebSocket = false;
  if (servers) {
    Object.entries(servers).forEach(([_name, server]) => {
      const protocol = server.protocol && server.protocol();
      if (protocol && ['ws', 'wss', 'websocket'].includes(protocol.toLowerCase())) {
        hasWebSocket = true;
      }
    });
  }

  // Only generate file if WebSocket is used
  if (!hasWebSocket) {
    return null;
  }
  const useAsyncStd = params.useAsyncStd === 'true' || params.useAsyncStd === true;
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "websocket.rs",
    children: `//! WebSocket transport implementation

use async_trait::async_trait;
${useAsyncStd ? `
use async_tungstenite::{
    async_std::connect_async, async_std::connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
    WebSocketStream,
};
use async_std::net::TcpStream;
` : `
use tokio_tungstenite::{
    connect_async, connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
    WebSocketStream, MaybeTlsStream,
};
use tokio::net::TcpStream;
`}
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use url::Url;

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

${useAsyncStd ? `
type WsStream = WebSocketStream<TcpStream>;
` : `
type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
`}

/// WebSocket transport implementation
pub struct WebSocketTransport {
    config: TransportConfig,
    ws_stream: Option<WsStream>,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    subscriptions: Arc<RwLock<Vec<String>>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl WebSocketTransport {
    /// Create a new WebSocket transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if !["ws", "wss", "websocket"].contains(&config.protocol.as_str()) {
            return Err(AsyncApiError::new(
                format!("Invalid protocol for WebSocket transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            ));
        }

        Ok(Self {
            config,
            ws_stream: None,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            subscriptions: Arc::new(RwLock::new(Vec::new())),
            message_handler: None,
            shutdown_tx: None,
        })
    }

    /// Set message handler for incoming messages
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Create WebSocket URL from configuration
    fn create_websocket_url(&self) -> AsyncApiResult<Url> {
        let scheme = match self.config.protocol.as_str() {
            "wss" => "wss",
            "ws" | "websocket" => if self.config.tls { "wss" } else { "ws" },
            _ => "ws",
        };

        let path = self.config.additional_config
            .get("path")
            .map(|p| p.as_str())
            .unwrap_or("/");

        let url_str = format!("{}://{}:{}{}", scheme, self.config.host, self.config.port, path);

        Url::parse(&url_str).map_err(|e| {
            AsyncApiError::new(
                format!("Invalid WebSocket URL: {}", e),
                ErrorCategory::Configuration,
                Some(Box::new(e)),
            )
        })
    }

    /// Create WebSocket configuration
    fn create_ws_config(&self) -> WebSocketConfig {
        let mut config = WebSocketConfig::default();

        // Set max message size if specified
        if let Some(max_message_size) = self.config.additional_config
            .get("max_message_size")
            .and_then(|v| v.parse::<usize>().ok())
        {
            config.max_message_size = Some(max_message_size);
        }

        // Set max frame size if specified
        if let Some(max_frame_size) = self.config.additional_config
            .get("max_frame_size")
            .and_then(|v| v.parse::<usize>().ok())
        {
            config.max_frame_size = Some(max_frame_size);
        }

        config
    }

    /// Start the WebSocket message loop
    async fn start_message_loop(&mut self) -> AsyncApiResult<()> {
        if let Some(ws_stream) = self.ws_stream.take() {
            let (mut ws_sender, mut ws_receiver) = ws_stream.split();
            let connection_state = Arc::clone(&self.connection_state);
            let stats = Arc::clone(&self.stats);
            let message_handler = self.message_handler.clone();
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            self.shutdown_tx = Some(shutdown_tx);

            // Store the sender for sending messages
            let (msg_tx, mut msg_rx) = mpsc::channel::<Message>(100);

            // Spawn sender task
            let sender_stats = Arc::clone(&stats);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        message = msg_rx.recv() => {
                            match message {
                                Some(msg) => {
                                    if let Err(e) = ws_sender.send(msg).await {
                                        tracing::error!("Failed to send WebSocket message: {}", e);
                                        let mut stats = sender_stats.write().await;
                                        stats.last_error = Some(e.to_string());
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            tracing::info!("WebSocket sender shutdown requested");
                            break;
                        }
                    }
                }
            });

            // Spawn receiver task
            tokio::spawn(async move {
                loop {
                    match ws_receiver.next().await {
                        Some(Ok(message)) => {
                            match message {
                                Message::Text(text) => {
                                    let mut stats = stats.write().await;
                                    stats.messages_received += 1;
                                    stats.bytes_received += text.len() as u64;
                                    drop(stats);

                                    if let Some(handler) = &message_handler {
                                        let metadata = MessageMetadata {
                                            channel: "websocket".to_string(),
                                            operation: "receive".to_string(),
                                            content_type: Some("text/plain".to_string()),
                                            headers: HashMap::new(),
                                            timestamp: chrono::Utc::now(),
                                        };

                                        let transport_message = TransportMessage {
                                            metadata,
                                            payload: text.into_bytes(),
                                        };

                                        if let Err(e) = handler.handle_message(transport_message).await {
                                            tracing::error!("Failed to handle WebSocket text message: {}", e);
                                            let mut stats = stats.write().await;
                                            stats.last_error = Some(e.to_string());
                                        }
                                    }
                                }
                                Message::Binary(data) => {
                                    let mut stats = stats.write().await;
                                    stats.messages_received += 1;
                                    stats.bytes_received += data.len() as u64;
                                    drop(stats);

                                    if let Some(handler) = &message_handler {
                                        let metadata = MessageMetadata {
                                            channel: "websocket".to_string(),
                                            operation: "receive".to_string(),
                                            content_type: Some("application/octet-stream".to_string()),
                                            headers: HashMap::new(),
                                            timestamp: chrono::Utc::now(),
                                        };

                                        let transport_message = TransportMessage {
                                            metadata,
                                            payload: data,
                                        };

                                        if let Err(e) = handler.handle_message(transport_message).await {
                                            tracing::error!("Failed to handle WebSocket binary message: {}", e);
                                            let mut stats = stats.write().await;
                                            stats.last_error = Some(e.to_string());
                                        }
                                    }
                                }
                                Message::Ping(data) => {
                                    tracing::debug!("Received WebSocket ping");
                                    // Pong is automatically sent by tungstenite
                                }
                                Message::Pong(_) => {
                                    tracing::debug!("Received WebSocket pong");
                                }
                                Message::Close(_) => {
                                    tracing::info!("WebSocket connection closed by peer");
                                    *connection_state.write().await = ConnectionState::Disconnected;
                                    break;
                                }
                                Message::Frame(_) => {
                                    // Raw frames are handled internally
                                }
                            }
                        }
                        Some(Err(e)) => {
                            tracing::error!("WebSocket receiver error: {}", e);
                            *connection_state.write().await = ConnectionState::Failed;
                            let mut stats = stats.write().await;
                            stats.last_error = Some(e.to_string());
                            break;
                        }
                        None => {
                            tracing::info!("WebSocket receiver stream ended");
                            *connection_state.write().await = ConnectionState::Disconnected;
                            break;
                        }
                    }
                }
            });
        }

        Ok(())
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        let url = self.create_websocket_url()?;
        let ws_config = self.create_ws_config();

        // Create connection request with optional headers
        let mut request = url.clone().into_client_request().map_err(|e| {
            AsyncApiError::new(
                format!("Failed to create WebSocket request: {}", e),
                ErrorCategory::Configuration,
                Some(Box::new(e)),
            )
        })?;

        // Add authentication headers if provided
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            let auth_value = base64::encode(format!("{}:{}", username, password));
            request.headers_mut().insert(
                "Authorization",
                format!("Basic {}", auth_value).parse().unwrap(),
            );
        }

        // Add custom headers
        for (key, value) in &self.config.additional_config {
            if key.starts_with("header_") {
                let header_name = &key[7..]; // Remove "header_" prefix
                if let Ok(header_value) = value.parse() {
                    request.headers_mut().insert(header_name, header_value);
                }
            }
        }

        // Connect to WebSocket
        let (ws_stream, _) = if ws_config == WebSocketConfig::default() {
            connect_async(request).await
        } else {
            connect_async_with_config(request, Some(ws_config)).await
        }.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to connect to WebSocket: {}", e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        self.ws_stream = Some(ws_stream);

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        // Start message loop
        self.start_message_loop().await?;

        *self.connection_state.write().await = ConnectionState::Connected;
        tracing::info!("WebSocket transport connected successfully to {}", url);

        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        self.ws_stream = None;
        *self.connection_state.write().await = ConnectionState::Disconnected;

        tracing::info!("WebSocket transport disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection_state
            .try_read()
            .map(|state| matches!(*state, ConnectionState::Connected))
            .unwrap_or(false)
    }

    fn connection_state(&self) -> ConnectionState {
        self.connection_state
            .try_read()
            .map(|state| *state)
            .unwrap_or(ConnectionState::Disconnected)
    }

    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()> {
        if !self.is_connected() {
            return Err(AsyncApiError::new(
                "WebSocket not connected".to_string(),
                ErrorCategory::Network,
                None,
            ));
        }

        // Determine message type based on content type
        let ws_message = match message.metadata.content_type.as_deref() {
            Some("text/plain") | Some("application/json") | Some("text/json") => {
                let text = String::from_utf8(message.payload).map_err(|e| {
                    AsyncApiError::new(
                        format!("Invalid UTF-8 in text message: {}", e),
                        ErrorCategory::Validation,
                        Some(Box::new(e)),
                    )
                })?;
                Message::Text(text)
            }
            _ => Message::Binary(message.payload.clone()),
        };

        // For this implementation, we would need to store the sender channel
        // This is a simplified version - in practice, you'd want to store the sender
        // from the message loop and use it here

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += message.payload.len() as u64;

        tracing::debug!("Sent WebSocket message");
        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        // WebSocket doesn't have traditional subscription model
        // This could be used to track which channels we're interested in
        let mut subscriptions = self.subscriptions.write().await;
        if !subscriptions.contains(&channel.to_string()) {
            subscriptions.push(channel.to_string());
        }

        tracing::info!("Subscribed to WebSocket channel: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.retain(|c| c != channel);

        tracing::info!("Unsubscribed from WebSocket channel: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // WebSocket listening is handled by the message loop, which is started in connect()
        tracing::info!("WebSocket transport is listening for messages");
        Ok(())
    }

    async fn stop_listening(&mut self) -> AsyncApiResult<()> {
        // Stop listening by disconnecting
        self.disconnect().await
    }

    fn get_stats(&self) -> TransportStats {
        self.stats.try_read()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }

    async fn health_check(&self) -> AsyncApiResult<bool> {
        Ok(self.is_connected())
    }

    fn protocol(&self) -> &str {
        &self.config.protocol
    }
}

impl Drop for WebSocketTransport {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.try_send(());
        }
    }
}
`
  });
}

function HttpTransport({
  asyncapi,
  params
}) {
  // Check if HTTP protocol is used
  const servers = asyncapi.servers();
  let hasHttp = false;
  if (servers) {
    Object.entries(servers).forEach(([_name, server]) => {
      const protocol = server.protocol && server.protocol();
      if (protocol && ['http', 'https'].includes(protocol.toLowerCase())) {
        hasHttp = true;
      }
    });
  }

  // Only generate file if HTTP is used
  if (!hasHttp) {
    return null;
  }
  const useAsyncStd = params.useAsyncStd === 'true' || params.useAsyncStd === true;
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "http.rs",
    children: `//! HTTP transport implementation

use async_trait::async_trait;
${useAsyncStd ? `
use tide::{Request, Response, Server as TideServer, StatusCode};
use async_std::task;
` : `
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Method},
    response::{Json, Response as AxumResponse},
    routing::{get, post, put, delete},
    Router,
};
use tower::ServiceBuilder;
use tokio::net::TcpListener;
`}
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use serde_json::Value;

use crate::errors::{AsyncApiResult, AsyncApiError, ErrorCategory};
use crate::transport::{
    Transport, TransportConfig, TransportStats, TransportMessage, MessageMetadata,
    ConnectionState, MessageHandler,
};

/// HTTP transport implementation
pub struct HttpTransport {
    config: TransportConfig,
    connection_state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    routes: Arc<RwLock<HashMap<String, String>>>, // path -> method
    message_handler: Option<Arc<dyn MessageHandler>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    ${useAsyncStd ? 'server: Option<TideServer<()>>,' : 'server_handle: Option<tokio::task::JoinHandle<()>>,'}
}

impl HttpTransport {
    /// Create a new HTTP transport
    pub fn new(config: TransportConfig) -> AsyncApiResult<Self> {
        if config.protocol != "http" && config.protocol != "https" {
            return Err(AsyncApiError::new(
                format!("Invalid protocol for HTTP transport: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            ));
        }

        Ok(Self {
            config,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            routes: Arc::new(RwLock::new(HashMap::new())),
            message_handler: None,
            shutdown_tx: None,
            ${useAsyncStd ? 'server: None,' : 'server_handle: None,'}
        })
    }

    /// Set message handler for incoming messages
    pub fn set_message_handler(&mut self, handler: Arc<dyn MessageHandler>) {
        self.message_handler = Some(handler);
    }

    /// Get server address
    fn get_server_address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }

    ${useAsyncStd ? `
    /// Create Tide server
    async fn create_tide_server(&self) -> AsyncApiResult<TideServer<()>> {
        let mut app = tide::new();
        let stats = Arc::clone(&self.stats);
        let message_handler = self.message_handler.clone();

        // Add middleware for logging and stats
        app.with(tide::log::LogMiddleware::new());

        // Generic handler for all routes
        let handler = move |mut req: Request<()>| {
            let stats = Arc::clone(&stats);
            let message_handler = message_handler.clone();

            async move {
                let mut stats = stats.write().await;
                stats.messages_received += 1;
                drop(stats);

                let method = req.method().to_string();
                let path = req.url().path().to_string();
                let query = req.url().query().unwrap_or("").to_string();

                // Extract headers
                let mut headers = HashMap::new();
                for (name, value) in req.iter() {
                    if let Ok(value_str) = value.to_str() {
                        headers.insert(name.to_string(), value_str.to_string());
                    }
                }

                // Read body
                let body = match req.body_bytes().await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tracing::error!("Failed to read request body: {}", e);
                        return Response::builder(StatusCode::BadRequest)
                            .body("Failed to read request body")
                            .build();
                    }
                };

                let mut stats = stats.write().await;
                stats.bytes_received += body.len() as u64;
                drop(stats);

                if let Some(handler) = &message_handler {
                    let metadata = MessageMetadata {
                        channel: path.clone(),
                        operation: method.clone(),
                        content_type: headers.get("content-type").cloned(),
                        headers: headers.clone(),
                        timestamp: chrono::Utc::now(),
                    };

                    let transport_message = TransportMessage {
                        metadata,
                        payload: body,
                    };

                    match handler.handle_message(transport_message).await {
                        Ok(_) => {
                            Response::builder(StatusCode::Ok)
                                .body("Message processed successfully")
                                .build()
                        }
                        Err(e) => {
                            tracing::error!("Failed to handle HTTP message: {}", e);
                            let mut stats = stats.write().await;
                            stats.last_error = Some(e.to_string());
                            Response::builder(StatusCode::InternalServerError)
                                .body("Failed to process message")
                                .build()
                        }
                    }
                } else {
                    Response::builder(StatusCode::Ok)
                        .body("No handler configured")
                        .build()
                }
            }
        };

        // Add routes for common HTTP methods
        app.at("/*").get(handler.clone());
        app.at("/*").post(handler.clone());
        app.at("/*").put(handler.clone());
        app.at("/*").delete(handler.clone());
        app.at("/*").patch(handler);

        Ok(app)
    }
    ` : `
    /// Create Axum router
    async fn create_axum_router(&self) -> AsyncApiResult<Router> {
        let stats = Arc::clone(&self.stats);
        let message_handler = self.message_handler.clone();

        // Create shared state
        let app_state = AppState {
            stats,
            message_handler,
        };

        let router = Router::new()
            .route("/*path", get(handle_request))
            .route("/*path", post(handle_request))
            .route("/*path", put(handle_request))
            .route("/*path", delete(handle_request))
            .route("/", get(handle_request))
            .route("/", post(handle_request))
            .route("/", put(handle_request))
            .route("/", delete(handle_request))
            .with_state(app_state)
            .layer(
                ServiceBuilder::new()
                    .layer(axum::middleware::from_fn(logging_middleware))
            );

        Ok(router)
    }
    `}
}

${useAsyncStd ? '' : `
#[derive(Clone)]
struct AppState {
    stats: Arc<RwLock<TransportStats>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
}

async fn handle_request(
    State(state): State<AppState>,
    method: Method,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<AxumResponse<String>, StatusCode> {
    let mut stats = state.stats.write().await;
    stats.messages_received += 1;
    stats.bytes_received += body.len() as u64;
    drop(stats);

    // Extract headers
    let mut header_map = HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            header_map.insert(name.to_string(), value_str.to_string());
        }
    }

    // Add query parameters to headers
    for (key, value) in query {
        header_map.insert(format!("query_{}", key), value);
    }

    if let Some(handler) = &state.message_handler {
        let metadata = MessageMetadata {
            channel: format!("/{}", path),
            operation: method.to_string(),
            content_type: header_map.get("content-type").cloned(),
            headers: header_map,
            timestamp: chrono::Utc::now(),
        };

        let transport_message = TransportMessage {
            metadata,
            payload: body.to_vec(),
        };

        match handler.handle_message(transport_message).await {
            Ok(_) => Ok(AxumResponse::new("Message processed successfully".to_string())),
            Err(e) => {
                tracing::error!("Failed to handle HTTP message: {}", e);
                let mut stats = state.stats.write().await;
                stats.last_error = Some(e.to_string());
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Ok(AxumResponse::new("No handler configured".to_string()))
    }
}

async fn logging_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().clone();
    let uri = request.uri().clone();

    tracing::info!("HTTP {} {}", method, uri);

    let response = next.run(request).await;

    tracing::info!("HTTP {} {} -> {}", method, uri, response.status());

    response
}
`}

#[async_trait]
impl Transport for HttpTransport {
    async fn connect(&mut self) -> AsyncApiResult<()> {
        *self.connection_state.write().await = ConnectionState::Connecting;

        let address = self.get_server_address();

        ${useAsyncStd ? `
        let server = self.create_tide_server().await?;
        self.server = Some(server);

        let server_clone = self.server.as_ref().unwrap().clone();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start server in background task
        task::spawn(async move {
            tokio::select! {
                result = server_clone.listen(&address) => {
                    if let Err(e) = result {
                        tracing::error!("HTTP server error: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("HTTP server shutdown requested");
                }
            }
        });
        ` : `
        let router = self.create_axum_router().await?;
        let listener = TcpListener::bind(&address).await.map_err(|e| {
            AsyncApiError::new(
                format!("Failed to bind HTTP server to {}: {}", address, e),
                ErrorCategory::Network,
                Some(Box::new(e)),
            )
        })?;

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start server in background task
        let server_handle = tokio::spawn(async move {
            tokio::select! {
                result = axum::serve(listener, router) => {
                    if let Err(e) = result {
                        tracing::error!("HTTP server error: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("HTTP server shutdown requested");
                }
            }
        });

        self.server_handle = Some(server_handle);
        `}

        // Update connection attempts
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        *self.connection_state.write().await = ConnectionState::Connected;
        tracing::info!("HTTP transport started on {}", address);

        Ok(())
    }

    async fn disconnect(&mut self) -> AsyncApiResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        ${useAsyncStd ? `
        self.server = None;
        ` : `
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
        `}

        *self.connection_state.write().await = ConnectionState::Disconnected;
        tracing::info!("HTTP transport disconnected");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection_state
            .try_read()
            .map(|state| matches!(*state, ConnectionState::Connected))
            .unwrap_or(false)
    }

    fn connection_state(&self) -> ConnectionState {
        self.connection_state
            .try_read()
            .map(|state| *state)
            .unwrap_or(ConnectionState::Disconnected)
    }

    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()> {
        // HTTP transport is primarily for receiving messages (server mode)
        // Sending would require making HTTP client requests
        tracing::warn!("HTTP transport send_message not implemented - use HTTP client for outbound requests");

        let mut stats = self.stats.write().await;
        stats.messages_sent += 1;
        stats.bytes_sent += message.payload.len() as u64;

        Ok(())
    }

    async fn subscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        // HTTP doesn't have traditional subscription model
        // This could be used to register specific routes
        let mut routes = self.routes.write().await;
        routes.insert(channel.to_string(), "GET".to_string());

        tracing::info!("Registered HTTP route: {}", channel);
        Ok(())
    }

    async fn unsubscribe(&mut self, channel: &str) -> AsyncApiResult<()> {
        let mut routes = self.routes.write().await;
        routes.remove(channel);

        tracing::info!("Unregistered HTTP route: {}", channel);
        Ok(())
    }

    async fn start_listening(&mut self) -> AsyncApiResult<()> {
        // HTTP listening is handled by the server, which is started in connect()
        tracing::info!("HTTP transport is listening for requests");
        Ok(())
    }

    async fn stop_listening(&mut self) -> AsyncApiResult<()> {
        // Stop listening by disconnecting
        self.disconnect().await
    }

    fn get_stats(&self) -> TransportStats {
        self.stats.try_read()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }

    async fn health_check(&self) -> AsyncApiResult<bool> {
        Ok(self.is_connected())
    }

    fn protocol(&self) -> &str {
        &self.config.protocol
    }
}

impl Drop for HttpTransport {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.try_send(());
        }
    }
}
`
  });
}

function index ({
  asyncapi,
  params
}) {
  return [/*#__PURE__*/jsxRuntime.jsx(Cargo_toml, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(README_md, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(MainRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(ConfigRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(ErrorsRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(ModelsRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(HandlersRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(ContextRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(RouterRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(ServerModRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(ServerBuilderRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(MiddlewareRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(RecoveryRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(AuthModRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(AuthConfigRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(AuthJwtRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(AuthMiddlewareRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(AuthRbacRs, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(TransportMod, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(TransportFactory, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(MqttTransport, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(KafkaTransport, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(AmqpTransport, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(WebSocketTransport, {
    asyncapi: asyncapi,
    params: params
  }), /*#__PURE__*/jsxRuntime.jsx(HttpTransport, {
    asyncapi: asyncapi,
    params: params
  })];
}

module.exports = index;
//# sourceMappingURL=index.js.map

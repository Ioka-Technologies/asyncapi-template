//! Transport factory for creating transport instances based on protocol

use std::collections::HashMap;
use std::sync::Arc;

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory};
use crate::transport::{Transport, TransportConfig, MessageHandler};
use crate::recovery::RecoveryManager;
#[cfg(feature = "websocket")]
use crate::transport::websocket::WebSocketTransport;
#[cfg(feature = "nats")]
use crate::transport::nats::NatsTransport;


/// Factory for creating transport instances based on protocol
pub struct TransportFactory;

impl TransportFactory {
    /// Create a transport instance based on the protocol
    pub fn create_transport(config: TransportConfig) -> AsyncApiResult<Box<dyn Transport>> {
        Self::create_transport_with_handler(config, None)
    }

    /// Create a transport instance with an optional message handler
    /// This is the preferred method as it allows setting handlers during construction
    #[allow(unused_variables)]
    pub fn create_transport_with_handler(
        config: TransportConfig,
        handler: Option<Arc<dyn MessageHandler>>,
    ) -> AsyncApiResult<Box<dyn Transport>> {
        match config.protocol.to_lowercase().as_str() {
            #[cfg(feature = "websocket")]
            "ws" | "wss" | "websocket" => {
                if let Some(handler) = handler {
                    let transport = WebSocketTransport::new_with_handler(config, Some(handler))?;
                    Ok(Box::new(transport))
                } else {
                    let transport = WebSocketTransport::new(config)?;
                    Ok(Box::new(transport))
                }
            }
            #[cfg(feature = "nats")]
            "nats" | "nats+tls" => {
                // NATS transport now requires a pre-configured client
                // Users should create the NATS client themselves and use NatsTransport::new(client)
                // This factory method is deprecated for NATS
                Err(Box::new(AsyncApiError::new(
                    "NATS transport requires a pre-configured async_nats::Client. Use NatsTransport::new(client) directly instead of the factory.".to_string(),
                    ErrorCategory::Configuration,
                    None,
                )))
            }
            _ => Err(Box::new(AsyncApiError::new(
                format!("Unsupported protocol: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            ))),
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
        let mut protocols = vec![];

        protocols.extend_from_slice(&["http", "https"]);


        #[cfg(feature = "websocket")]
        {
            protocols.extend_from_slice(&["ws", "wss", "websocket"]);
        }
        #[cfg(feature = "nats")]
        {
            protocols.extend_from_slice(&["nats", "nats+tls"]);
        }

        protocols
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
            transport_id: uuid::Uuid::new_v4(),
            protocol: protocol.to_string(),
            host: host.to_string(),
            port,
            username: additional_config.get("username").cloned(),
            password: additional_config.get("password").cloned(),
            tls: protocol.ends_with('s')
                || additional_config.get("tls").is_some_and(|v| v == "true"),
            additional_config,
        }
    }

    /// Validate transport configuration
    pub fn validate_config(config: &TransportConfig) -> AsyncApiResult<()> {
        // Check if protocol is supported
        if !Self::is_protocol_supported(&config.protocol) {
            return Err(Box::new(AsyncApiError::new(
                format!("Unsupported protocol: {}", config.protocol),
                ErrorCategory::Configuration,
                None,
            )));
        }

        // Validate host
        if config.host.is_empty() {
            return Err(Box::new(AsyncApiError::new(
                "Host cannot be empty".to_string(),
                ErrorCategory::Configuration,
                None,
            )));
        }

        // Validate port
        if config.port == 0 {
            return Err(Box::new(AsyncApiError::new(
                "Port cannot be zero".to_string(),
                ErrorCategory::Configuration,
                None,
            )));
        }

        // Protocol-specific validation
        match config.protocol.to_lowercase().as_str() {
            #[cfg(feature = "websocket")]
            "ws" | "wss" | "websocket" => {
                // WebSocket-specific validation
                let default_port = if config.protocol == "wss" { 443 } else { 80 };
                if config.port != default_port
                    && !config.additional_config.contains_key("custom_port")
                {
                    tracing::warn!("Using non-standard port {} for WebSocket", config.port);
                }
            }
            #[cfg(feature = "nats")]
            "nats" | "nats+tls" => {
                // NATS-specific validation
                let default_port = if config.protocol == "nats+tls" { 4443 } else { 4222 };
                if config.port != default_port
                    && !config.additional_config.contains_key("custom_port")
                {
                    tracing::warn!("Using non-standard port {} for NATS", config.port);
                }

                // Validate NATS authentication configuration
                let has_creds = config.additional_config.contains_key("credentials_file");
                let has_jwt = config.additional_config.contains_key("jwt_token")
                    && config.additional_config.contains_key("nkey_seed");

                if !has_creds && !has_jwt {
                    tracing::warn!("No NATS authentication configured - using anonymous connection");
                }
            }
            "http" | "https" => {
                // HTTP-specific validation
                let default_port = if config.protocol == "https" { 443 } else { 80 };
                if config.port != default_port
                    && !config.additional_config.contains_key("custom_port")
                {
                    tracing::warn!("Using non-standard port {} for HTTP", config.port);
                }
            }
            _ => {
                // This should not happen due to earlier validation
                return Err(Box::new(AsyncApiError::new(
                    format!("Unknown protocol for validation: {}", config.protocol),
                    ErrorCategory::Configuration,
                    None,
                )));
            }
        }

        Ok(())
    }

    /// Create default configuration for a protocol
    pub fn default_config(protocol: &str) -> AsyncApiResult<TransportConfig> {
        let (default_port, tls) = match protocol.to_lowercase().as_str() {
            #[cfg(feature = "websocket")]
            "ws" | "websocket" => (80, false),
            #[cfg(feature = "websocket")]
            "wss" => (443, true),
            "http" => (80, false),
            "https" => (443, true),
            _ => {
                return Err(Box::new(AsyncApiError::new(
                    format!("Unsupported protocol: {protocol}"),
                    ErrorCategory::Configuration,
                    None,
                )));
            }
        };

        Ok(TransportConfig {
            transport_id: uuid::Uuid::new_v4(),
            protocol: protocol.to_string(),
            host: "localhost".to_string(),
            port: default_port,
            tls,
            username: None,
            password: None,
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
        assert!(protocols.contains(&"http"));
        assert!(protocols.contains(&"https"));

        #[cfg(feature = "websocket")]
        {
            assert!(protocols.contains(&"ws"));
            assert!(protocols.contains(&"wss"));
            assert!(protocols.contains(&"websocket"));
        }
    }

    #[test]
    fn test_is_protocol_supported() {
        assert!(TransportFactory::is_protocol_supported("http"));
        assert!(TransportFactory::is_protocol_supported("HTTP"));
        assert!(TransportFactory::is_protocol_supported("https"));
        assert!(!TransportFactory::is_protocol_supported("unknown"));
    }

    #[test]
    fn test_default_config() {
        let config = TransportFactory::default_config("http").unwrap();
        assert_eq!(config.protocol, "http");
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 80);
        assert!(!config.tls);

        let config = TransportFactory::default_config("https").unwrap();
        assert_eq!(config.protocol, "https");
        assert_eq!(config.port, 443);
        assert!(config.tls);
    }

    #[test]
    fn test_validate_config() {
        let mut config = TransportFactory::default_config("http").unwrap();
        assert!(TransportFactory::validate_config(&config).is_ok());

        // Test invalid protocol
        config.protocol = "invalid".to_string();
        assert!(TransportFactory::validate_config(&config).is_err());

        // Test empty host
        config.protocol = "http".to_string();
        config.host = "".to_string();
        assert!(TransportFactory::validate_config(&config).is_err());

        // Test zero port
        config.host = "localhost".to_string();
        config.port = 0;
        assert!(TransportFactory::validate_config(&config).is_err());
    }
}

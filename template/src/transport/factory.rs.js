/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function TransportFactory({ asyncapi }) {
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
        imports += '#[cfg(feature = "mqtt")]\nuse crate::transport::mqtt::MqttTransport;\n';
    }
    if (protocols.has('kafka')) {
        imports += '#[cfg(feature = "kafka")]\nuse crate::transport::kafka::KafkaTransport;\n';
    }
    if (protocols.has('amqp') || protocols.has('amqps')) {
        imports += '#[cfg(feature = "amqp")]\nuse crate::transport::amqp::AmqpTransport;\n';
    }
    if (protocols.has('ws') || protocols.has('wss')) {
        imports += '#[cfg(feature = "websocket")]\nuse crate::transport::websocket::WebSocketTransport;\n';
    }
    if (protocols.has('http') || protocols.has('https')) {
        imports += 'use crate::transport::http::HttpTransport;\n';
    }

    return (
        <File name="factory.rs">
            {`//! Transport factory for creating transport instances based on protocol

use std::collections::HashMap;
use std::sync::Arc;

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory};
use crate::transport::{Transport, TransportConfig};
${imports}

/// Factory for creating transport instances based on protocol
pub struct TransportFactory;

impl TransportFactory {
    /// Create a transport instance based on the protocol
    pub fn create_transport(config: TransportConfig) -> AsyncApiResult<Box<dyn Transport>> {
        match config.protocol.to_lowercase().as_str() {${protocols.has('mqtt') || protocols.has('mqtts') ? `
            #[cfg(feature = "mqtt")]
            "mqtt" | "mqtts" => {
                let transport = MqttTransport::new(config)?;
                Ok(Box::new(transport))
            }` : ''}${protocols.has('kafka') ? `
            #[cfg(feature = "kafka")]
            "kafka" => {
                let transport = KafkaTransport::new(config)?;
                Ok(Box::new(transport))
            }` : ''}${protocols.has('amqp') || protocols.has('amqps') ? `
            #[cfg(feature = "amqp")]
            "amqp" | "amqps" => {
                let transport = AmqpTransport::new(config)?;
                Ok(Box::new(transport))
            }` : ''}${protocols.has('ws') || protocols.has('wss') ? `
            #[cfg(feature = "websocket")]
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
        vec![
            "mqtt",
            "mqtts",
            "kafka",
            "amqp",
            "amqps",
            "ws",
            "wss",
            "websocket",
            "http",
            "https",
        ]
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
            tls: protocol.ends_with('s')
                || additional_config.get("tls").map_or(false, |v| v == "true"),
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
                if config.port < 1024
                    && !config
                        .additional_config
                        .contains_key("allow_privileged_ports")
                {
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
                let default_port = if config.protocol == "amqps" {
                    5671
                } else {
                    5672
                };
                if config.port != default_port
                    && !config.additional_config.contains_key("custom_port")
                {
                    tracing::warn!("Using non-standard port {} for AMQP", config.port);
                }
            }
            "ws" | "wss" | "websocket" => {
                // WebSocket-specific validation
                let default_port = if config.protocol == "wss" { 443 } else { 80 };
                if config.port != default_port
                    && !config.additional_config.contains_key("custom_port")
                {
                    tracing::warn!("Using non-standard port {} for WebSocket", config.port);
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
`}
        </File>
    );
}

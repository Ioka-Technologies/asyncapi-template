import { File } from '@asyncapi/generator-react-sdk';

export default function transportFactoryFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();

    return (
        <File name="src/transport/factory.rs">
            {`//! Transport factory for creating protocol-specific transport implementations

use crate::config::Config;
use crate::error::{Error, Result};
use crate::transport::{AsyncApiTransport, TransportFactory};

${protocol === 'mqtt' || protocol === 'mqtts' ? 'use super::mqtt::MqttTransport;' : ''}
${protocol === 'kafka' || protocol === 'kafka-secure' ? 'use super::kafka::KafkaTransport;' : ''}
${protocol === 'amqp' || protocol === 'amqps' ? 'use super::amqp::AmqpTransport;' : ''}
${protocol === 'ws' || protocol === 'wss' ? 'use super::websocket::WebSocketTransport;' : ''}
${protocol === 'nats' ? 'use super::nats::NatsTransport;' : ''}
${protocol === 'redis' ? 'use super::redis::RedisTransport;' : ''}
${protocol === 'http' || protocol === 'https' ? 'use super::http::HttpTransport;' : ''}

/// Default transport factory implementation
///
/// This factory creates transport instances based on the protocol specified
/// in the configuration. It supports all protocols that were enabled during
/// code generation.
pub struct DefaultTransportFactory;

impl TransportFactory for DefaultTransportFactory {
    fn create_transport(
        &self,
        protocol: &str,
        _config: &Config,
    ) -> Result<Box<dyn AsyncApiTransport>> {
        match protocol.to_lowercase().as_str() {
${protocol === 'mqtt' || protocol === 'mqtts' ? `            "mqtt" | "mqtts" => Ok(Box::new(MqttTransport::new())),` : ''}
${protocol === 'kafka' || protocol === 'kafka-secure' ? `            "kafka" | "kafka-secure" => Ok(Box::new(KafkaTransport::new())),` : ''}
${protocol === 'amqp' || protocol === 'amqps' ? `            "amqp" | "amqps" => Ok(Box::new(AmqpTransport::new())),` : ''}
${protocol === 'ws' || protocol === 'wss' ? `            "ws" | "wss" | "websocket" => Ok(Box::new(WebSocketTransport::new())),` : ''}
${protocol === 'nats' ? `            "nats" => Ok(Box::new(NatsTransport::new())),` : ''}
${protocol === 'redis' ? `            "redis" => Ok(Box::new(RedisTransport::new())),` : ''}
${protocol === 'http' || protocol === 'https' ? `            "http" | "https" => Ok(Box::new(HttpTransport::new())),` : ''}
            _ => Err(Error::Config(format!(
                "Unsupported protocol: {}. Supported protocols: {:?}",
                protocol,
                self.supported_protocols()
            ))),
        }
    }

    fn supported_protocols(&self) -> Vec<&'static str> {
        vec![
${protocol === 'mqtt' || protocol === 'mqtts' ? `            "mqtt",` : ''}
${protocol === 'kafka' || protocol === 'kafka-secure' ? `            "kafka",` : ''}
${protocol === 'amqp' || protocol === 'amqps' ? `            "amqp",` : ''}
${protocol === 'ws' || protocol === 'wss' ? `            "websocket",` : ''}
${protocol === 'nats' ? `            "nats",` : ''}
${protocol === 'redis' ? `            "redis",` : ''}
${protocol === 'http' || protocol === 'https' ? `            "http",` : ''}
        ]
    }
}

/// Create a transport instance for the specified protocol
///
/// This is a convenience function that uses the default transport factory
/// to create a transport instance.
///
/// # Arguments
/// * \`protocol\` - The protocol name (e.g., "mqtt", "kafka")
/// * \`config\` - Configuration for the transport
///
/// # Returns
/// * \`Ok(Box<dyn AsyncApiTransport>)\` containing the transport
/// * \`Err(Error)\` if creation fails
///
/// # Example
/// \`\`\`rust
/// use your_crate::transport::factory::create_transport;
/// use your_crate::config::Config;
///
/// let config = Config::default();
/// let transport = create_transport("${protocol}", &config)?;
/// \`\`\`
pub fn create_transport(protocol: &str, config: &Config) -> Result<Box<dyn AsyncApiTransport>> {
    let factory = DefaultTransportFactory;
    factory.create_transport(protocol, config)
}

/// Get the list of supported protocols
///
/// # Returns
/// * Vector of supported protocol names
///
/// # Example
/// \`\`\`rust
/// use your_crate::transport::factory::supported_protocols;
///
/// let protocols = supported_protocols();
/// println!("Supported protocols: {:?}", protocols);
/// \`\`\`
pub fn supported_protocols() -> Vec<&'static str> {
    let factory = DefaultTransportFactory;
    factory.supported_protocols()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_protocols() {
        let factory = DefaultTransportFactory;
        let protocols = factory.supported_protocols();

        assert!(!protocols.is_empty());
        assert!(protocols.contains(&"${protocol}"));
    }

    #[test]
    fn test_create_transport_success() {
        let factory = DefaultTransportFactory;
        let config = Config::default();

        let result = factory.create_transport("${protocol}", &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_transport_unsupported() {
        let factory = DefaultTransportFactory;
        let config = Config::default();

        let result = factory.create_transport("unsupported", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_convenience_functions() {
        let config = Config::default();

        let protocols = supported_protocols();
        assert!(!protocols.is_empty());

        let transport = create_transport("${protocol}", &config);
        assert!(transport.is_ok());
    }
}
`}
        </File>
    );
}

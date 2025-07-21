import { File } from '@asyncapi/generator-react-sdk';

export default function transportModFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();

    return (
        <File name="src/transport/mod.rs">
            {`//! Transport implementations for various protocols
//!
//! This module contains protocol-specific transport implementations that
//! implement the AsyncApiTransport trait. Each transport handles the
//! specifics of connecting to and communicating with different message
//! brokers and protocols.

// Re-export core transport traits
pub use crate::transport::{
    AsyncApiTransport, MessageHandler, MessageSerializer, TransportFactory,
    MessageEnvelope, MessageMetadata, JsonSerializer,
};

// Transport factory
pub mod factory;
pub use factory::{DefaultTransportFactory, create_transport, supported_protocols};

// Protocol-specific transport implementations
${protocol === 'mqtt' || protocol === 'mqtts' ? 'pub mod mqtt;' : ''}
${protocol === 'kafka' || protocol === 'kafka-secure' ? 'pub mod kafka;' : ''}
${protocol === 'amqp' || protocol === 'amqps' ? 'pub mod amqp;' : ''}
${protocol === 'ws' || protocol === 'wss' ? 'pub mod websocket;' : ''}
${protocol === 'nats' ? 'pub mod nats;' : ''}
${protocol === 'redis' ? 'pub mod redis;' : ''}
${protocol === 'http' || protocol === 'https' ? 'pub mod http;' : ''}

// Re-export transport implementations
${protocol === 'mqtt' || protocol === 'mqtts' ? 'pub use mqtt::MqttTransport;' : ''}
${protocol === 'kafka' || protocol === 'kafka-secure' ? 'pub use kafka::KafkaTransport;' : ''}
${protocol === 'amqp' || protocol === 'amqps' ? 'pub use amqp::AmqpTransport;' : ''}
${protocol === 'ws' || protocol === 'wss' ? 'pub use websocket::WebSocketTransport;' : ''}
${protocol === 'nats' ? 'pub use nats::NatsTransport;' : ''}
${protocol === 'redis' ? 'pub use redis::RedisTransport;' : ''}
${protocol === 'http' || protocol === 'https' ? 'pub use http::HttpTransport;' : ''}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_supported_protocols() {
        let protocols = supported_protocols();
        assert!(!protocols.is_empty());
        assert!(protocols.contains(&"${protocol}"));
    }

    #[test]
    fn test_create_transport() {
        let config = Config::default();
        let result = create_transport("${protocol}", &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transport_factory() {
        let factory = DefaultTransportFactory;
        let config = Config::default();

        let protocols = factory.supported_protocols();
        assert!(!protocols.is_empty());

        let transport = factory.create_transport("${protocol}", &config);
        assert!(transport.is_ok());

        if let Ok(transport) = transport {
            assert_eq!(transport.protocol(), "${protocol}");
        }
    }

    #[test]
    fn test_unsupported_protocol() {
        let config = Config::default();
        let result = create_transport("unsupported-protocol", &config);
        assert!(result.is_err());
    }
}
`}
        </File>
    );
}

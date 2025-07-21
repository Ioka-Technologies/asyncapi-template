import { File } from '@asyncapi/generator-react-sdk';

export default function mqttTransportFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async_std' : 'tokio';

    // Only generate if protocol is MQTT
    if (protocol !== 'mqtt' && protocol !== 'mqtts') {
        return null;
    }

    return (
        <File name="src/transport/mqtt.rs">
            {`//! MQTT transport implementation for AsyncAPI clients

use crate::config::Config;
use crate::error::{Error, Result};
use crate::transport::AsyncApiTransport;
use async_trait::async_trait;
use log::{debug, error, info, warn};
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use std::collections::HashMap;
use std::sync::Arc;
use ${runtime === 'tokio' ? 'tokio::sync::RwLock' : 'async_std::sync::RwLock'};

/// MQTT transport implementation
///
/// This transport provides MQTT/MQTTS connectivity using the rumqttc library.
/// It supports QoS levels, authentication, clean sessions, and other MQTT features.
pub struct MqttTransport {
    /// MQTT client for publishing messages
    client: Option<AsyncClient>,
    /// MQTT event loop for handling incoming messages
    event_loop: Option<EventLoop>,
    /// Connection state
    is_connected: Arc<RwLock<bool>>,
    /// Subscribed topics
    subscriptions: Arc<RwLock<HashMap<String, QoS>>>,
}

impl MqttTransport {
    /// Create a new MQTT transport instance
    ///
    /// # Returns
    /// * New MQTT transport instance
    pub fn new() -> Self {
        Self {
            client: None,
            event_loop: None,
            is_connected: Arc::new(RwLock::new(false)),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Convert QoS integer to rumqttc QoS enum
    fn qos_from_int(qos: u8) -> QoS {
        match qos {
            0 => QoS::AtMostOnce,
            1 => QoS::AtLeastOnce,
            2 => QoS::ExactlyOnce,
            _ => QoS::AtLeastOnce, // Default to QoS 1
        }
    }

    /// Extract host and port from URL
    fn parse_url(url: &str) -> Result<(String, u16)> {
        let url = url.strip_prefix("mqtt://")
            .or_else(|| url.strip_prefix("mqtts://"))
            .unwrap_or(url);

        if let Some(colon_pos) = url.find(':') {
            let host = url[..colon_pos].to_string();
            let port_str = &url[colon_pos + 1..];
            let port = port_str.parse::<u16>()
                .map_err(|_| Error::Config(format!("Invalid port in URL: {}", port_str)))?;
            Ok((host, port))
        } else {
            // Default MQTT port
            Ok((url.to_string(), 1883))
        }
    }
}

impl Default for MqttTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AsyncApiTransport for MqttTransport {
    async fn connect(&mut self, config: &Config) -> Result<()> {
        info!("Connecting to MQTT broker: {}", config.server.url);

        let (host, port) = Self::parse_url(&config.server.url)?;

        let mut mqtt_options = MqttOptions::new(
            &config.mqtt.client_id,
            host,
            port,
        );

        // Configure connection options
        mqtt_options.set_keep_alive(std::time::Duration::from_secs(config.mqtt.keep_alive as u64));
        mqtt_options.set_clean_session(config.mqtt.clean_session);

        // Set authentication if provided
        if let (Some(username), Some(password)) = (&config.mqtt.username, &config.mqtt.password) {
            mqtt_options.set_credentials(username, password);
        }

        // Create client and event loop
        let (client, event_loop) = AsyncClient::new(mqtt_options, 10);

        self.client = Some(client);
        self.event_loop = Some(event_loop);

        *self.is_connected.write().await = true;

        info!("Successfully connected to MQTT broker");
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        info!("Disconnecting from MQTT broker");

        if let Some(client) = &self.client {
            client.disconnect().await.map_err(|e| Error::Mqtt(e))?;
        }

        self.client = None;
        self.event_loop = None;
        *self.is_connected.write().await = false;

        // Clear subscriptions
        self.subscriptions.write().await.clear();

        info!("Disconnected from MQTT broker");
        Ok(())
    }

    async fn publish(
        &self,
        topic: &str,
        payload: &[u8],
        headers: Option<&HashMap<String, String>>,
    ) -> Result<()> {
        let client = self.client.as_ref()
            .ok_or_else(|| Error::Connection("MQTT client not connected".to_string()))?;

        // For MQTT, headers would typically be encoded in the payload or as user properties
        // For simplicity, we'll ignore headers in this basic implementation
        if headers.is_some() {
            warn!("MQTT transport does not support headers in this implementation");
        }

        // Use QoS from configuration (default to QoS 1)
        let qos = QoS::AtLeastOnce; // This could be made configurable

        client.publish(topic, qos, false, payload)
            .await
            .map_err(|e| Error::Mqtt(e))?;

        debug!("Published message to topic: {}", topic);
        Ok(())
    }

    async fn subscribe(&mut self, topic: &str) -> Result<()> {
        let client = self.client.as_ref()
            .ok_or_else(|| Error::Connection("MQTT client not connected".to_string()))?;

        let qos = QoS::AtLeastOnce; // This could be made configurable

        client.subscribe(topic, qos)
            .await
            .map_err(|e| Error::Mqtt(e))?;

        // Track subscription
        self.subscriptions.write().await.insert(topic.to_string(), qos);

        info!("Subscribed to topic: {}", topic);
        Ok(())
    }

    async fn unsubscribe(&mut self, topic: &str) -> Result<()> {
        let client = self.client.as_ref()
            .ok_or_else(|| Error::Connection("MQTT client not connected".to_string()))?;

        client.unsubscribe(topic)
            .await
            .map_err(|e| Error::Mqtt(e))?;

        // Remove from tracked subscriptions
        self.subscriptions.write().await.remove(topic);

        info!("Unsubscribed from topic: {}", topic);
        Ok(())
    }

    async fn is_connected(&self) -> bool {
        *self.is_connected.read().await
    }

    async fn start_message_loop(&mut self) -> Result<()> {
        if self.event_loop.is_none() {
            return Err(Error::Connection("MQTT event loop not initialized".to_string()));
        }

        info!("Starting MQTT message processing loop");

        // In a real implementation, you would spawn a task here to handle the event loop
        // and process incoming messages. For this example, we'll just mark it as started.

        // Example of how you might handle the event loop:
        /*
        let mut event_loop = self.event_loop.take().unwrap();
        let is_connected = Arc::clone(&self.is_connected);

        ${runtime === 'tokio' ? 'tokio::spawn' : 'async_std::task::spawn'}(async move {
            loop {
                match event_loop.poll().await {
                    Ok(Event::Incoming(Packet::Publish(publish))) => {
                        // Handle incoming message
                        debug!("Received message on topic: {}", publish.topic);
                        // Process the message here
                    }
                    Ok(Event::Incoming(packet)) => {
                        debug!("Received MQTT packet: {:?}", packet);
                    }
                    Ok(Event::Outgoing(_)) => {
                        // Handle outgoing events if needed
                    }
                    Err(e) => {
                        error!("MQTT event loop error: {:?}", e);
                        *is_connected.write().await = false;
                        break;
                    }
                }
            }
        });
        */

        Ok(())
    }

    async fn stop_message_loop(&mut self) -> Result<()> {
        info!("Stopping MQTT message processing loop");

        // In a real implementation, you would signal the message loop task to stop
        // For this example, we'll just mark it as stopped

        Ok(())
    }

    fn protocol(&self) -> &'static str {
        "${protocol}"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mqtt_transport_creation() {
        let transport = MqttTransport::new();
        assert_eq!(transport.protocol(), "${protocol}");
    }

    #[test]
    fn test_qos_conversion() {
        assert!(matches!(MqttTransport::qos_from_int(0), QoS::AtMostOnce));
        assert!(matches!(MqttTransport::qos_from_int(1), QoS::AtLeastOnce));
        assert!(matches!(MqttTransport::qos_from_int(2), QoS::ExactlyOnce));
        assert!(matches!(MqttTransport::qos_from_int(99), QoS::AtLeastOnce)); // Default
    }

    #[test]
    fn test_url_parsing() {
        let (host, port) = MqttTransport::parse_url("mqtt://localhost:1883").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 1883);

        let (host, port) = MqttTransport::parse_url("mqtts://broker.example.com:8883").unwrap();
        assert_eq!(host, "broker.example.com");
        assert_eq!(port, 8883);

        let (host, port) = MqttTransport::parse_url("localhost").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 1883); // Default port
    }

    #[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
    async fn test_connection_state() {
        let transport = MqttTransport::new();
        assert!(!transport.is_connected().await);
    }
}
`}
        </File>
    );
}

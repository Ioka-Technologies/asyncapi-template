import { File } from '@asyncapi/generator-react-sdk';

export default function configFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();
    const serverUrl = server.url();

    return (
        <File name="src/config.rs">
            {`//! Configuration for the AsyncAPI client

use serde::{Deserialize, Serialize};
use std::env;

/// Main configuration for the AsyncAPI client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,

    ${protocol === 'mqtt' || protocol === 'mqtts' ? `/// MQTT-specific configuration
    pub mqtt: MqttConfig,` : ''}

    ${protocol === 'kafka' || protocol === 'kafka-secure' ? `/// Kafka-specific configuration
    pub kafka: KafkaConfig,` : ''}

    ${protocol === 'amqp' || protocol === 'amqps' ? `/// AMQP-specific configuration
    pub amqp: AmqpConfig,` : ''}

    ${protocol === 'ws' || protocol === 'wss' ? `/// WebSocket-specific configuration
    pub websocket: WebSocketConfig,` : ''}

    ${protocol === 'nats' ? `/// NATS-specific configuration
    pub nats: NatsConfig,` : ''}

    ${protocol === 'redis' ? `/// Redis-specific configuration
    pub redis: RedisConfig,` : ''}

    ${protocol === 'http' || protocol === 'https' ? `/// HTTP-specific configuration
    pub http: HttpConfig,` : ''}
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server URL
    pub url: String,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Maximum number of retry attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

${protocol === 'mqtt' || protocol === 'mqtts' ? `/// MQTT-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttConfig {
    /// Client ID
    #[serde(default = "default_mqtt_client_id")]
    pub client_id: String,

    /// Keep alive interval in seconds
    #[serde(default = "default_mqtt_keep_alive")]
    pub keep_alive: u16,

    /// Clean session flag
    #[serde(default = "default_mqtt_clean_session")]
    pub clean_session: bool,

    /// QoS level
    #[serde(default = "default_mqtt_qos")]
    pub qos: u8,

    /// Username for authentication
    pub username: Option<String>,

    /// Password for authentication
    pub password: Option<String>,
}` : ''}

${protocol === 'kafka' || protocol === 'kafka-secure' ? `/// Kafka-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig {
    /// Consumer group ID
    #[serde(default = "default_kafka_group_id")]
    pub group_id: String,

    /// Auto offset reset policy
    #[serde(default = "default_kafka_auto_offset_reset")]
    pub auto_offset_reset: String,

    /// Enable auto commit
    #[serde(default = "default_kafka_enable_auto_commit")]
    pub enable_auto_commit: bool,

    /// Session timeout in milliseconds
    #[serde(default = "default_kafka_session_timeout")]
    pub session_timeout: u32,

    /// Security protocol
    pub security_protocol: Option<String>,

    /// SASL mechanism
    pub sasl_mechanism: Option<String>,

    /// SASL username
    pub sasl_username: Option<String>,

    /// SASL password
    pub sasl_password: Option<String>,
}` : ''}

${protocol === 'amqp' || protocol === 'amqps' ? `/// AMQP-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmqpConfig {
    /// Virtual host
    #[serde(default = "default_amqp_vhost")]
    pub vhost: String,

    /// Username for authentication
    pub username: Option<String>,

    /// Password for authentication
    pub password: Option<String>,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub connection_timeout: u64,

    /// Heartbeat interval in seconds
    #[serde(default = "default_amqp_heartbeat")]
    pub heartbeat: u16,
}` : ''}

${protocol === 'ws' || protocol === 'wss' ? `/// WebSocket-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    /// Maximum message size in bytes
    #[serde(default = "default_ws_max_message_size")]
    pub max_message_size: usize,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub connection_timeout: u64,

    /// Ping interval in seconds
    #[serde(default = "default_ws_ping_interval")]
    pub ping_interval: u64,
}` : ''}

${protocol === 'nats' ? `/// NATS-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    /// Connection name
    pub name: Option<String>,

    /// Username for authentication
    pub username: Option<String>,

    /// Password for authentication
    pub password: Option<String>,

    /// Token for authentication
    pub token: Option<String>,

    /// Maximum reconnect attempts
    #[serde(default = "default_nats_max_reconnects")]
    pub max_reconnects: usize,

    /// Reconnect delay in milliseconds
    #[serde(default = "default_nats_reconnect_delay")]
    pub reconnect_delay: u64,
}` : ''}

${protocol === 'redis' ? `/// Redis-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Database number
    #[serde(default = "default_redis_db")]
    pub db: i64,

    /// Username for authentication
    pub username: Option<String>,

    /// Password for authentication
    pub password: Option<String>,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub connection_timeout: u64,

    /// Response timeout in seconds
    #[serde(default = "default_timeout")]
    pub response_timeout: u64,
}` : ''}

${protocol === 'http' || protocol === 'https' ? `/// HTTP-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// User agent string
    #[serde(default = "default_http_user_agent")]
    pub user_agent: String,

    /// Maximum number of redirects to follow
    #[serde(default = "default_http_max_redirects")]
    pub max_redirects: usize,

    /// Default headers to include with requests
    pub default_headers: Option<std::collections::HashMap<String, String>>,
}` : ''}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            ${protocol === 'mqtt' || protocol === 'mqtts' ? `mqtt: MqttConfig::default(),` : ''}
            ${protocol === 'kafka' || protocol === 'kafka-secure' ? `kafka: KafkaConfig::default(),` : ''}
            ${protocol === 'amqp' || protocol === 'amqps' ? `amqp: AmqpConfig::default(),` : ''}
            ${protocol === 'ws' || protocol === 'wss' ? `websocket: WebSocketConfig::default(),` : ''}
            ${protocol === 'nats' ? `nats: NatsConfig::default(),` : ''}
            ${protocol === 'redis' ? `redis: RedisConfig::default(),` : ''}
            ${protocol === 'http' || protocol === 'https' ? `http: HttpConfig::default(),` : ''}
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: env::var("ASYNCAPI_SERVER_URL").unwrap_or_else(|_| "${serverUrl}".to_string()),
            timeout: default_timeout(),
            max_retries: default_max_retries(),
        }
    }
}

${protocol === 'mqtt' || protocol === 'mqtts' ? `impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            client_id: env::var("MQTT_CLIENT_ID").unwrap_or_else(|_| default_mqtt_client_id()),
            keep_alive: env::var("MQTT_KEEP_ALIVE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_mqtt_keep_alive),
            clean_session: env::var("MQTT_CLEAN_SESSION")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_mqtt_clean_session),
            qos: env::var("MQTT_QOS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_mqtt_qos),
            username: env::var("MQTT_USERNAME").ok(),
            password: env::var("MQTT_PASSWORD").ok(),
        }
    }
}` : ''}

${protocol === 'kafka' || protocol === 'kafka-secure' ? `impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            group_id: env::var("KAFKA_GROUP_ID").unwrap_or_else(|_| default_kafka_group_id()),
            auto_offset_reset: env::var("KAFKA_AUTO_OFFSET_RESET").unwrap_or_else(|_| default_kafka_auto_offset_reset()),
            enable_auto_commit: env::var("KAFKA_ENABLE_AUTO_COMMIT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_kafka_enable_auto_commit),
            session_timeout: env::var("KAFKA_SESSION_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_kafka_session_timeout),
            security_protocol: env::var("KAFKA_SECURITY_PROTOCOL").ok(),
            sasl_mechanism: env::var("KAFKA_SASL_MECHANISM").ok(),
            sasl_username: env::var("KAFKA_SASL_USERNAME").ok(),
            sasl_password: env::var("KAFKA_SASL_PASSWORD").ok(),
        }
    }
}` : ''}

${protocol === 'amqp' || protocol === 'amqps' ? `impl Default for AmqpConfig {
    fn default() -> Self {
        Self {
            vhost: env::var("AMQP_VHOST").unwrap_or_else(|_| default_amqp_vhost()),
            username: env::var("AMQP_USERNAME").ok(),
            password: env::var("AMQP_PASSWORD").ok(),
            connection_timeout: env::var("AMQP_CONNECTION_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_timeout),
            heartbeat: env::var("AMQP_HEARTBEAT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_amqp_heartbeat),
        }
    }
}` : ''}

${protocol === 'ws' || protocol === 'wss' ? `impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_message_size: env::var("WS_MAX_MESSAGE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_ws_max_message_size),
            connection_timeout: env::var("WS_CONNECTION_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_timeout),
            ping_interval: env::var("WS_PING_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_ws_ping_interval),
        }
    }
}` : ''}

${protocol === 'nats' ? `impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            name: env::var("NATS_NAME").ok(),
            username: env::var("NATS_USERNAME").ok(),
            password: env::var("NATS_PASSWORD").ok(),
            token: env::var("NATS_TOKEN").ok(),
            max_reconnects: env::var("NATS_MAX_RECONNECTS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_nats_max_reconnects),
            reconnect_delay: env::var("NATS_RECONNECT_DELAY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_nats_reconnect_delay),
        }
    }
}` : ''}

${protocol === 'redis' ? `impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            db: env::var("REDIS_DB")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_redis_db),
            username: env::var("REDIS_USERNAME").ok(),
            password: env::var("REDIS_PASSWORD").ok(),
            connection_timeout: env::var("REDIS_CONNECTION_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_timeout),
            response_timeout: env::var("REDIS_RESPONSE_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_timeout),
        }
    }
}` : ''}

${protocol === 'http' || protocol === 'https' ? `impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: env::var("HTTP_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_timeout),
            user_agent: env::var("HTTP_USER_AGENT").unwrap_or_else(|_| default_http_user_agent()),
            max_redirects: env::var("HTTP_MAX_REDIRECTS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_http_max_redirects),
            default_headers: None,
        }
    }
}` : ''}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        Self::default()
    }

    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration from environment variables with fallback to file
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        // Try to load from config file first
        if let Ok(config) = Self::from_file("config.toml") {
            return Ok(config);
        }

        // Fallback to environment variables
        Ok(Self::from_env())
    }
}

// Default value functions
fn default_timeout() -> u64 {
    30
}

fn default_max_retries() -> u32 {
    3
}

${protocol === 'mqtt' || protocol === 'mqtts' ? `fn default_mqtt_client_id() -> String {
    format!("asyncapi-client-{}", uuid::Uuid::new_v4())
}

fn default_mqtt_keep_alive() -> u16 {
    60
}

fn default_mqtt_clean_session() -> bool {
    true
}

fn default_mqtt_qos() -> u8 {
    1
}` : ''}

${protocol === 'kafka' || protocol === 'kafka-secure' ? `fn default_kafka_group_id() -> String {
    "asyncapi-group".to_string()
}

fn default_kafka_auto_offset_reset() -> String {
    "earliest".to_string()
}

fn default_kafka_enable_auto_commit() -> bool {
    true
}

fn default_kafka_session_timeout() -> u32 {
    30000
}` : ''}

${protocol === 'amqp' || protocol === 'amqps' ? `fn default_amqp_vhost() -> String {
    "/".to_string()
}

fn default_amqp_heartbeat() -> u16 {
    60
}` : ''}

${protocol === 'ws' || protocol === 'wss' ? `fn default_ws_max_message_size() -> usize {
    64 * 1024 * 1024 // 64MB
}

fn default_ws_ping_interval() -> u64 {
    30
}` : ''}

${protocol === 'nats' ? `fn default_nats_max_reconnects() -> usize {
    10
}

fn default_nats_reconnect_delay() -> u64 {
    2000
}` : ''}

${protocol === 'redis' ? `fn default_redis_db() -> i64 {
    0
}` : ''}

${protocol === 'http' || protocol === 'https' ? `fn default_http_user_agent() -> String {
    format!("AsyncAPI-Rust-Client/{}", env!("CARGO_PKG_VERSION"))
}

fn default_http_max_redirects() -> usize {
    10
}` : ''}
`}
        </File>
    );
}

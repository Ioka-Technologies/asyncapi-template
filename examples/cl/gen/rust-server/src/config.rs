//! Configuration management for the AsyncAPI server

use anyhow::Result;
use std::env;
use tracing::Level;

/// Server configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub log_level: Level,
    pub item_0_config: Item0Config,
    pub item_1_config: Item1Config,
}

/// Configuration for 0 server
#[derive(Debug, Clone)]
pub struct Item0Config {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

impl Default for Item0Config {
    fn default() -> Self {
        Self {
            host: "0.0.0.0:8080".to_string(),
            port: 80,
            protocol: "ws".to_string(),
        }
    }
}

/// Configuration for 1 server
#[derive(Debug, Clone)]
pub struct Item1Config {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

impl Default for Item1Config {
    fn default() -> Self {
        Self {
            host: "0.0.0.0:4222".to_string(),
            port: 8080,
            protocol: "nats".to_string(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            log_level: Level::INFO,
            item_0_config: Item0Config::default(),
            item_1_config: Item1Config::default(),
        }
    }
}

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
            item_0_config: Item0Config::default(),
            item_1_config: Item1Config::default(),
        })
    }
}

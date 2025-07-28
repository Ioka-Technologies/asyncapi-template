/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import {
    toRustIdentifier,
    toRustTypeName,
    toRustFieldName,
    getDefaultPort
} from '../helpers/index.js';

export default function ConfigRs({ asyncapi }) {
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

    return (
        <File name="config.rs">
            {`//! Configuration management for the AsyncAPI server

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

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            log_level: Level::INFO,
            ${serverConfigs.map(server => `${server.fieldName}_config: ${server.typeName}::default(),`).join('\n            ')}
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
            ${serverConfigs.map(server => `${server.fieldName}_config: ${server.typeName}::default(),`).join('\n            ')}
        })
    }
}
`}
        </File>
    );
}

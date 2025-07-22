export default function ConfigRs({ asyncapi }) {
    // Helper functions for Rust identifier generation
    function toRustIdentifier(str) {
        if (!str) return 'unknown';
        let identifier = str
            .replace(/[^a-zA-Z0-9_]/g, '_')
            .replace(/^[0-9]/, '_$&')
            .replace(/_+/g, '_')
            .replace(/^_+|_+$/g, '');
        if (/^[0-9]/.test(identifier)) {
            identifier = 'item_' + identifier;
        }
        if (!identifier) {
            identifier = 'unknown';
        }
        const rustKeywords = [
            'as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern',
            'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match',
            'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self',
            'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe',
            'use', 'where', 'while', 'async', 'await', 'dyn'
        ];
        if (rustKeywords.includes(identifier)) {
            identifier = identifier + '_';
        }
        return identifier;
    }

    function toRustTypeName(str) {
        if (!str) return 'Unknown';
        const identifier = toRustIdentifier(str);
        return identifier
            .split('_')
            .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
            .join('');
    }

    function toRustFieldName(str) {
        if (!str) return 'unknown';
        const identifier = toRustIdentifier(str);
        return identifier
            .replace(/([A-Z])/g, '_$1')
            .toLowerCase()
            .replace(/^_/, '')
            .replace(/_+/g, '_');
    }

    function getDefaultPort(protocol) {
        switch (protocol?.toLowerCase()) {
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

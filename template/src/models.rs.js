/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ModelsRs({ asyncapi }) {
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
        case 'array': {
            const itemType = jsonSchemaToRustType(schema.items);
            return `Vec<${itemType}>`;
        }
        case 'object':
            return 'serde_json::Value'; // For complex objects, use generic JSON
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

    return (
        <File name="models.rs">
            {`//! Message models generated from AsyncAPI specification

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
`}
        </File>
    );
}

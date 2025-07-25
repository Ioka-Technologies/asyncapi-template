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
        // Handle camelCase and PascalCase properly
        const identifier = str
            .replace(/[^a-zA-Z0-9]/g, '_')
            .replace(/^[0-9]/, '_$&')
            .replace(/_+/g, '_')
            .replace(/^_+|_+$/g, '');

        // Split on underscores and camelCase boundaries
        const parts = identifier.split(/[_\s]+|(?=[A-Z])/);

        return parts
            .filter(part => part.length > 0)
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

    function toRustEnumVariant(str) {
        if (!str) return 'Unknown';
        return str
            .split(/[-_\s]+/)
            .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
            .join('');
    }

    // Extract message schemas and build channel mapping
    const components = asyncapi.components();
    const messageSchemas = [];
    const messageToChannels = new Map();
    const generatedTypes = new Set();
    const nestedSchemas = new Map();

    // First, build channel to message mapping
    if (asyncapi.channels) {
        const channels = asyncapi.channels();
        if (channels) {
            Object.entries(channels).forEach(([channelName, channel]) => {
                try {
                    // Handle AsyncAPI 2.x format
                    if (channel.subscribe && channel.subscribe()) {
                        const message = channel.subscribe().message();
                        if (message) {
                            // Try to get message reference
                            let messageName = null;
                            if (message.$ref) {
                                messageName = message.$ref.split('/').pop();
                            } else if (message.name) {
                                messageName = typeof message.name === 'function' ? message.name() : message.name;
                            }

                            if (messageName) {
                                if (!messageToChannels.has(messageName)) {
                                    messageToChannels.set(messageName, []);
                                }
                                messageToChannels.get(messageName).push(channelName);
                            }
                        }
                    }
                    if (channel.publish && channel.publish()) {
                        const message = channel.publish().message();
                        if (message) {
                            // Try to get message reference
                            let messageName = null;
                            if (message.$ref) {
                                messageName = message.$ref.split('/').pop();
                            } else if (message.name) {
                                messageName = typeof message.name === 'function' ? message.name() : message.name;
                            }

                            if (messageName) {
                                if (!messageToChannels.has(messageName)) {
                                    messageToChannels.set(messageName, []);
                                }
                                messageToChannels.get(messageName).push(channelName);
                            }
                        }
                    }

                    // Handle AsyncAPI 3.x format
                    if (channel.messages) {
                        const messages = channel.messages();
                        if (messages) {
                            Object.entries(messages).forEach(([msgKey, message]) => {
                                if (message) {
                                    let messageName = null;
                                    if (message.$ref) {
                                        messageName = message.$ref.split('/').pop();
                                    } else if (message.name) {
                                        messageName = typeof message.name === 'function' ? message.name() : message.name;
                                    }

                                    if (messageName) {
                                        if (!messageToChannels.has(messageName)) {
                                            messageToChannels.set(messageName, []);
                                        }
                                        messageToChannels.get(messageName).push(channelName);
                                    }
                                }
                            });
                        }
                    }
                } catch (e) {
                    // Ignore channel processing errors
                }
            });
        }
    }

    // Extract messages from components
    if (components && components.messages) {
        const messages = components.messages();
        if (messages) {
            Object.entries(messages).forEach(([name, message]) => {
                let payload = null;
                let description = null;
                let title = null;
                let messageName = name;

                try {
                    if (message.payload && typeof message.payload === 'function') {
                        const payloadSchema = message.payload();
                        payload = payloadSchema && payloadSchema.json ? payloadSchema.json() : null;
                    }
                    description = message.description && typeof message.description === 'function' ? message.description() : null;
                    title = message.title && typeof message.title === 'function' ? message.title() : null;

                    // Try to get the actual message name
                    if (message.name && typeof message.name === 'function') {
                        messageName = message.name();
                    } else if (message.name) {
                        messageName = message.name;
                    }
                } catch (e) {
                    // Ignore payload extraction errors
                }

                const channels = messageToChannels.get(messageName) || messageToChannels.get(name) || [];
                messageSchemas.push({
                    name: messageName,
                    rustName: toRustTypeName(messageName),
                    payload,
                    description: description || title,
                    channels
                });
            });
        }
    }

    // Helper function to convert JSON schema to Rust type
    function jsonSchemaToRustType(schema, typeName = null) {
        if (!schema) return 'serde_json::Value';

        // Handle $ref
        if (schema.$ref) {
            const refName = schema.$ref.split('/').pop();
            const rustTypeName = toRustTypeName(refName);

            // Generate the referenced schema if we have access to components
            if (components && components.schemas) {
                const schemas = components.schemas();
                if (schemas && schemas[refName] && !generatedTypes.has(rustTypeName)) {
                    generatedTypes.add(rustTypeName);
                    const referencedSchema = schemas[refName];
                    const schemaJson = referencedSchema.json ? referencedSchema.json() : referencedSchema;
                    nestedSchemas.set(rustTypeName, {
                        type: 'struct',
                        schema: schemaJson,
                        description: referencedSchema.description && typeof referencedSchema.description === 'function' ? referencedSchema.description() : null
                    });
                }
            }

            return rustTypeName;
        }

        if (!schema.type) {
            // If no type specified, check for properties (object) or items (array)
            if (schema.properties) {
                schema.type = 'object';
            } else if (schema.items) {
                schema.type = 'array';
            } else {
                return 'serde_json::Value';
            }
        }

        switch (schema.type) {
        case 'string':
            if (schema.enum && schema.enum.length > 0) {
                // Generate enum type
                if (typeName) {
                    const enumName = `${typeName}Enum`;
                    if (!generatedTypes.has(enumName)) {
                        generatedTypes.add(enumName);
                        nestedSchemas.set(enumName, {
                            type: 'enum',
                            variants: schema.enum,
                            description: schema.description
                        });
                    }
                    return enumName;
                }
                return 'String'; // Fallback if no type name provided
            }
            if (schema.format === 'date-time') return 'chrono::DateTime<chrono::Utc>';
            if (schema.format === 'uuid') return 'uuid::Uuid';
            if (schema.format === 'email') return 'String';
            if (schema.format === 'uri') return 'String';
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
            if (schema.properties && Object.keys(schema.properties).length > 0) {
                // Generate nested struct
                if (typeName) {
                    const structName = toRustTypeName(typeName);
                    if (!generatedTypes.has(structName)) {
                        generatedTypes.add(structName);
                        nestedSchemas.set(structName, {
                            type: 'struct',
                            schema: schema,
                            description: schema.description
                        });
                    }
                    return structName;
                }
            }
            return 'serde_json::Value';
        default:
            return 'serde_json::Value';
        }
    }

    // Generate message structs
    function generateMessageStruct(schema, messageName) {
        if (!schema || !schema.properties) {
            return '    pub data: serde_json::Value,';
        }

        const fields = Object.entries(schema.properties).map(([fieldName, fieldSchema]) => {
            const rustFieldName = toRustFieldName(fieldName);
            const fieldTypeName = `${messageName}${toRustTypeName(fieldName)}`;
            const rustType = jsonSchemaToRustType(fieldSchema, fieldTypeName);
            const requiredFields = schema.required;
            const optional = !requiredFields || !Array.isArray(requiredFields) || requiredFields.indexOf(fieldName) === -1;
            const finalType = optional ? `Option<${rustType}>` : rustType;

            let fieldDoc = '';
            if (fieldSchema.description) {
                fieldDoc = `    /// ${fieldSchema.description}\n`;
            }

            return `${fieldDoc}    pub ${rustFieldName}: ${finalType},`;
        }).join('\n');

        return fields;
    }

    // Process all message schemas to ensure all referenced types are generated
    messageSchemas.forEach(schema => {
        if (schema.payload) {
            jsonSchemaToRustType(schema.payload, schema.rustName);
        }
    });

    // Generate nested type definitions
    function generateNestedTypes() {
        let result = '';

        for (const [typeName, typeInfo] of nestedSchemas.entries()) {
            if (typeInfo.type === 'enum') {
                const variants = typeInfo.variants.map(variant => toRustEnumVariant(variant)).join(',\n    ');
                const doc = typeInfo.description ? `/// ${typeInfo.description}\n` : '';
                result += `
${doc}#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ${typeName} {
    ${variants},
}
`;
            } else if (typeInfo.type === 'struct') {
                const fields = generateMessageStruct(typeInfo.schema, typeName);
                const doc = typeInfo.description ? `/// ${typeInfo.description}\n` : '';
                result += `
${doc}#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${typeName} {
${fields}
}
`;
            }
        }

        return result;
    }

    // Skip generating schemas from components.schemas since they are handled as message payloads
    // This prevents duplicate struct generation

    return (
        <File name="models.rs">
            {`//! Strongly-typed message models generated from AsyncAPI specification
//!
//! This module provides type-safe message structures that ensure:
//! - **Compile-time validation**: Invalid message structures are caught at build time
//! - **Automatic serialization**: Messages are seamlessly converted to/from JSON
//! - **Schema compliance**: All messages match the AsyncAPI specification exactly
//! - **IDE support**: Full autocomplete and type checking for message fields
//!
//! ## Design Philosophy
//!
//! These models are designed to be:
//! - **Immutable by default**: Prevents accidental modification of message data
//! - **Clone-friendly**: Efficient copying for message routing and processing
//! - **Debug-enabled**: Easy troubleshooting with automatic debug formatting
//! - **Serde-compatible**: Seamless JSON serialization for transport layers
//!
//! ## Usage Patterns
//!
//! \`\`\`no-run
//! use crate::models::*;
//! use uuid::Uuid;
//! use chrono::Utc;
//!
//! // Create a new message with type safety
//! let signup_request = UserSignup {
//!     id: Uuid::new_v4(),
//!     username: "johndoe".to_string(),
//!     email: "john@example.com".to_string(),
//!     created_at: Utc::now(),
//!     // Compiler ensures all required fields are provided
//! };
//!
//! // Automatic JSON serialization
//! let json_payload = serde_json::to_string(&signup_request)?;
//!
//! // Type-safe deserialization with validation
//! let parsed_message: UserSignup = serde_json::from_str(&json_payload)?;
//! \`\`\`

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

/// Standard message envelope for all AsyncAPI messages
///
/// This envelope provides a consistent structure for all messages sent through the system,
/// enabling better correlation, error handling, and observability.
///
/// ## Usage
///
/// \`\`\`no-run
/// use crate::models::*;
/// use uuid::Uuid;
///
/// // Create an envelope for a request
/// let envelope = MessageEnvelope::new("sendChatMessage", chat_message)
///     .with_correlation_id(Uuid::new_v4().to_string())
///     .with_channel("chatMessages");
///
/// // Create an error response
/// let error_envelope = MessageEnvelope::error_response(
///     "sendChatMessage_response",
///     "VALIDATION_ERROR",
///     "Invalid message format",
///     Some("correlation-id-123")
/// );
/// \`\`\`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// AsyncAPI operation ID
    pub operation: String,
    /// Correlation ID for request/response patterns
    pub id: Option<String>,
    /// Optional channel context
    pub channel: Option<String>,
    /// Message payload (any serializable type)
    pub payload: serde_json::Value,
    /// ISO 8601 timestamp
    pub timestamp: Option<String>,
    /// Error information if applicable
    pub error: Option<MessageError>,
}

/// Error information for failed operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageError {
    /// Error code (e.g., "VALIDATION_ERROR", "TIMEOUT", "UNAUTHORIZED")
    pub code: String,
    /// Human-readable error message
    pub message: String,
}

impl MessageEnvelope {
    /// Create a new message envelope with the given operation and payload
    pub fn new<T: Serialize>(operation: &str, payload: T) -> Result<Self, serde_json::Error> {
        Ok(Self {
            operation: operation.to_string(),
            id: None,
            channel: None,
            payload: serde_json::to_value(payload)?,
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
            error: None,
        })
    }

    /// Create a new envelope with automatic correlation ID generation
    pub fn new_with_id<T: Serialize>(
        operation: &str,
        payload: T,
    ) -> Result<Self, serde_json::Error> {
        Self::new(operation, payload)
            .map(|envelope| envelope.with_correlation_id(Uuid::new_v4().to_string()))
    }

    /// Create an error response envelope
    pub fn error_response(
        operation: &str,
        error_code: &str,
        error_message: &str,
        correlation_id: Option<String>,
    ) -> Self {
        Self {
            operation: operation.to_string(),
            id: correlation_id,
            channel: None,
            payload: serde_json::Value::Null,
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
            error: Some(MessageError {
                code: error_code.to_string(),
                message: error_message.to_string(),
            }),
        }
    }

    /// Set the correlation ID for this envelope
    pub fn with_correlation_id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the channel for this envelope
    pub fn with_channel(mut self, channel: String) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Set an error on this envelope
    pub fn with_error(mut self, code: &str, message: &str) -> Self {
        self.error = Some(MessageError {
            code: code.to_string(),
            message: message.to_string(),
        });
        self
    }

    /// Extract the payload as a strongly-typed message
    pub fn extract_payload<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.payload.clone())
    }

    /// Check if this envelope contains an error
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    /// Get the correlation ID if present
    pub fn correlation_id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Create a response envelope with the same correlation ID
    pub fn create_response<T: Serialize>(
        &self,
        response_operation: &str,
        payload: T,
    ) -> Result<Self, serde_json::Error> {
        let mut response = Self::new(response_operation, payload)?;
        response.id = self.id.clone();
        response.channel = self.channel.clone();
        Ok(response)
    }
}

/// Base trait for all AsyncAPI messages providing runtime type information
///
/// This trait enables:
/// - **Dynamic message routing**: Route messages based on their type at runtime
/// - **Channel identification**: Determine which channel a message belongs to
/// - **Logging and monitoring**: Track message types for observability
/// - **Protocol abstraction**: Handle different message types uniformly
pub trait AsyncApiMessage {
    /// Returns the message type identifier as defined in the AsyncAPI specification
    ///
    /// This is used for:
    /// - Message routing and dispatch
    /// - Logging and monitoring
    /// - Protocol-level message identification
    fn message_type(&self) -> &'static str;

    /// Returns the primary channel this message is associated with
    ///
    /// Used for:
    /// - Default routing when channel is not explicitly specified
    /// - Message categorization and organization
    /// - Channel-based access control and filtering
    fn channel(&self) -> &'static str;
}
${generateNestedTypes()}
${messageSchemas.map(schema => {
            const doc = schema.description ? `/// ${schema.description}` : `/// ${schema.name} message`;
            const primaryChannel = schema.channels.length > 0 ? schema.channels[0] : 'default';

            // Only generate the struct if it hasn't been generated as a nested schema
            const structDefinition = generatedTypes.has(schema.rustName) ? '' : `
${doc}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName} {
${generateMessageStruct(schema.payload, schema.rustName)}
}
`;

            return `${structDefinition}
impl AsyncApiMessage for ${schema.rustName} {
    fn message_type(&self) -> &'static str {
        "${schema.name}"
    }

    fn channel(&self) -> &'static str {
        "${primaryChannel}"
    }
}`;
        }).join('')}

${messageSchemas.length === 0 ? `
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

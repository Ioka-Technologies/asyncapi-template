import { File } from '@asyncapi/generator-react-sdk';
import { rustType, rustFieldName, rustStructName, rustDocComment, isOptional, isEnum, getEnumValues, serdeAttribute } from '../helpers/rust-helpers';

export default function modelsFile({ asyncapi, params }) {
    if (params.generateModels === false) {
        return null;
    }

    const schemas = asyncapi.allSchemas();
    const messages = asyncapi.allMessages();

    const generateStruct = (schema, name) => {
        const structName = rustStructName(name);
        const description = schema.description();
        const properties = schema.properties();
        const required = schema.required() || [];

        let structCode = '';

        // Add documentation
        if (description) {
            structCode += rustDocComment(description);
        }

        // Check if it's an enum
        if (isEnum(schema)) {
            const enumValues = getEnumValues(schema);
            structCode += `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n`;
            structCode += `pub enum ${structName} {\n`;

            enumValues.forEach(value => {
                structCode += `    ${value},\n`;
            });

            structCode += `}\n\n`;
            return structCode;
        }

        // Generate struct
        structCode += `#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]\n`;
        structCode += `pub struct ${structName} {\n`;

        if (properties) {
            Object.entries(properties).forEach(([propName, propSchema]) => {
                const fieldName = rustFieldName(propName);
                const fieldType = rustType(propSchema);
                const isOpt = isOptional(propSchema, propName, required);
                const finalType = isOpt ? `Option<${fieldType}>` : fieldType;

                // Add field documentation
                if (propSchema.description()) {
                    structCode += rustDocComment(propSchema.description(), '    ');
                }

                // Add serde rename attribute if needed
                const serdeAttr = serdeAttribute(propName, fieldName);
                if (serdeAttr) {
                    structCode += `    ${serdeAttr}\n`;
                }

                structCode += `    pub ${fieldName}: ${finalType},\n`;
            });
        }

        structCode += `}\n\n`;

        // Generate implementation block with useful methods
        structCode += `impl ${structName} {\n`;
        structCode += `    /// Create a new instance with default values\n`;
        structCode += `    pub fn new() -> Self {\n`;
        structCode += `        Self::default()\n`;
        structCode += `    }\n`;
        structCode += `}\n\n`;

        // Generate Default implementation
        structCode += `impl Default for ${structName} {\n`;
        structCode += `    fn default() -> Self {\n`;
        structCode += `        Self {\n`;

        if (properties) {
            Object.entries(properties).forEach(([propName, propSchema]) => {
                const fieldName = rustFieldName(propName);
                const isOpt = isOptional(propSchema, propName, required);

                if (isOpt) {
                    structCode += `            ${fieldName}: None,\n`;
                } else {
                    const fieldType = rustType(propSchema);
                    switch (fieldType) {
                        case 'String':
                            structCode += `            ${fieldName}: String::new(),\n`;
                            break;
                        case 'i32':
                        case 'i64':
                        case 'f32':
                        case 'f64':
                            structCode += `            ${fieldName}: 0,\n`;
                            break;
                        case 'bool':
                            structCode += `            ${fieldName}: false,\n`;
                            break;
                        default:
                            if (fieldType.startsWith('Vec<')) {
                                structCode += `            ${fieldName}: Vec::new(),\n`;
                            } else {
                                structCode += `            ${fieldName}: ${fieldType}::default(),\n`;
                            }
                    }
                }
            });
        }

        structCode += `        }\n`;
        structCode += `    }\n`;
        structCode += `}\n\n`;

        return structCode;
    };

    let fileContent = `//! Generated message models from AsyncAPI specification

use serde::{Deserialize, Serialize};

`;

    // Generate structs for all schemas
    for (const [schemaName, schema] of schemas) {
        fileContent += generateStruct(schema, schemaName);
    }

    // Generate message wrapper types
    fileContent += `/// Message envelope for all AsyncAPI messages\n`;
    fileContent += `#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]\n`;
    fileContent += `pub struct MessageEnvelope<T> {\n`;
    fileContent += `    /// Message payload\n`;
    fileContent += `    pub payload: T,\n`;
    fileContent += `    /// Message metadata\n`;
    fileContent += `    pub metadata: MessageMetadata,\n`;
    fileContent += `}\n\n`;

    fileContent += `/// Message metadata\n`;
    fileContent += `#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]\n`;
    fileContent += `pub struct MessageMetadata {\n`;
    fileContent += `    /// Message ID\n`;
    fileContent += `    pub id: Option<String>,\n`;
    fileContent += `    /// Timestamp when message was created\n`;
    fileContent += `    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,\n`;
    fileContent += `    /// Content type of the message\n`;
    fileContent += `    pub content_type: Option<String>,\n`;
    fileContent += `    /// Correlation ID for request-response patterns\n`;
    fileContent += `    pub correlation_id: Option<String>,\n`;
    fileContent += `    /// Reply-to address for request-response patterns\n`;
    fileContent += `    pub reply_to: Option<String>,\n`;
    fileContent += `    /// Custom headers\n`;
    fileContent += `    pub headers: std::collections::HashMap<String, String>,\n`;
    fileContent += `}\n\n`;

    fileContent += `impl Default for MessageMetadata {\n`;
    fileContent += `    fn default() -> Self {\n`;
    fileContent += `        Self {\n`;
    fileContent += `            id: None,\n`;
    fileContent += `            timestamp: Some(chrono::Utc::now()),\n`;
    fileContent += `            content_type: Some("application/json".to_string()),\n`;
    fileContent += `            correlation_id: None,\n`;
    fileContent += `            reply_to: None,\n`;
    fileContent += `            headers: std::collections::HashMap::new(),\n`;
    fileContent += `        }\n`;
    fileContent += `    }\n`;
    fileContent += `}\n\n`;

    // Generate message type enum
    if (messages.length > 0) {
        fileContent += `/// Enum representing all possible message types\n`;
        fileContent += `#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]\n`;
        fileContent += `#[serde(tag = "type", content = "payload")]\n`;
        fileContent += `pub enum Message {\n`;

        messages.forEach(message => {
            const messageName = rustStructName(message.uid());
            const description = message.description();

            if (description) {
                fileContent += rustDocComment(description, '    ');
            }

            fileContent += `    ${messageName}(${messageName}),\n`;
        });

        fileContent += `}\n\n`;

        // Generate message implementation
        fileContent += `impl Message {\n`;
        fileContent += `    /// Get the message type as a string\n`;
        fileContent += `    pub fn message_type(&self) -> &'static str {\n`;
        fileContent += `        match self {\n`;

        messages.forEach(message => {
            const messageName = rustStructName(message.uid());
            fileContent += `            Message::${messageName}(_) => "${message.uid()}",\n`;
        });

        fileContent += `        }\n`;
        fileContent += `    }\n\n`;

        fileContent += `    /// Serialize the message to JSON\n`;
        fileContent += `    pub fn to_json(&self) -> Result<String, serde_json::Error> {\n`;
        fileContent += `        serde_json::to_string(self)\n`;
        fileContent += `    }\n\n`;

        fileContent += `    /// Deserialize a message from JSON\n`;
        fileContent += `    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {\n`;
        fileContent += `        serde_json::from_str(json)\n`;
        fileContent += `    }\n`;
        fileContent += `}\n\n`;
    }

    // Generate validation traits
    fileContent += `/// Trait for validating message content\n`;
    fileContent += `pub trait Validate {\n`;
    fileContent += `    /// Validate the message content\n`;
    fileContent += `    fn validate(&self) -> Result<(), ValidationError>;\n`;
    fileContent += `}\n\n`;

    fileContent += `/// Validation error\n`;
    fileContent += `#[derive(Debug, Clone, PartialEq)]\n`;
    fileContent += `pub struct ValidationError {\n`;
    fileContent += `    /// Field that failed validation\n`;
    fileContent += `    pub field: String,\n`;
    fileContent += `    /// Error message\n`;
    fileContent += `    pub message: String,\n`;
    fileContent += `}\n\n`;

    fileContent += `impl std::fmt::Display for ValidationError {\n`;
    fileContent += `    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n`;
    fileContent += `        write!(f, "Validation error in field '{}': {}", self.field, self.message)\n`;
    fileContent += `    }\n`;
    fileContent += `}\n\n`;

    fileContent += `impl std::error::Error for ValidationError {}\n`;

    return (
        <File name="src/models.rs">
            {fileContent}
        </File>
    );
}

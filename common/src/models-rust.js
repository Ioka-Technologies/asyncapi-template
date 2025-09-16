/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

/**
 * Generate Rust models from AsyncAPI specification
 * This helper extracts the common schema processing logic used by both rust-server and rust-client templates
 *
 * @param {Object} asyncapi - AsyncAPI document
 * @param {Object} options - Generation options
 * @param {Function} options.toRustTypeName - Function to convert names to Rust type names
 * @param {Function} options.toRustFieldName - Function to convert names to Rust field names
 * @param {Function} options.toRustEnumVariantWithSerde - Function to convert enum variants with serde attributes
 * @param {boolean} options.includeAsyncApiTrait - Whether to include AsyncApiMessage trait implementations
 * @param {boolean} options.includeEnvelope - Whether to include MessageEnvelope (from envelope-rust.js)
 * @returns {Object} Generated models data and functions
 */
export function generateRustModels(asyncapi, options = {}) {
    const {
        toRustTypeName,
        toRustFieldName,
        toRustEnumVariantWithSerde,
        includeAsyncApiTrait = false,
        includeEnvelope = false
    } = options;

    // Extract message schemas and build channel mapping
    const components = asyncapi.components();
    const messageSchemas = [];
    const componentSchemas = [];
    const messageToChannels = new Map();
    const generatedTypes = new Set();
    const nestedSchemas = new Map();
    const schemaRegistry = new Map();

    // First, build channel to message mapping and extract inline message schemas
    if (asyncapi.channels) {
        const channels = asyncapi.channels();
        if (channels) {
            // Use proper iteration for AsyncAPI collection
            for (const channel of channels) {
                try {
                    const channelName = channel.id();

                    // Handle AsyncAPI 3.x format - extract inline messages from channels
                    if (channel.messages) {
                        const messages = channel.messages();
                        if (messages) {
                            // Check if messages is an object with message names as keys
                            if (typeof messages === 'object' && !Array.isArray(messages)) {
                                // Iterate through message entries (messageName -> messageObject)
                                Object.entries(messages).forEach(([messageName, message]) => {
                                    if (message && messageName) {
                                        let payload = null;
                                        let description = null;

                                        // Get payload schema
                                        if (message.payload && typeof message.payload === 'function') {
                                            payload = message.payload();
                                            if (payload && payload.json && typeof payload.json === 'function') {
                                                payload = payload.json();
                                            }
                                        } else if (message.payload) {
                                            payload = message.payload;
                                        }

                                        // Get description
                                        if (message.description && typeof message.description === 'function') {
                                            description = message.description();
                                        } else if (message.description) {
                                            description = message.description;
                                        }

                                        // Add to channel mapping
                                        if (!messageToChannels.has(messageName)) {
                                            messageToChannels.set(messageName, []);
                                        }
                                        messageToChannels.get(messageName).push(channelName);

                                        // Add to message schemas for inline messages
                                        messageSchemas.push({
                                            name: messageName,
                                            rustName: toRustTypeName(messageName),
                                            payload,
                                            rawPayload: payload,
                                            description,
                                            channels: [channelName]
                                        });
                                    }
                                });
                            } else {
                                // Try iterating as a collection
                                for (const message of messages) {
                                    if (message) {
                                        let messageName = null;
                                        let payload = null;
                                        let description = null;

                                        // Get message name - try multiple approaches
                                        if (message._meta && message._meta.id) {
                                            messageName = message._meta.id;
                                        } else if (message._json && message._json['x-parser-message-name']) {
                                            messageName = message._json['x-parser-message-name'];
                                        } else if (message._json && message._json['x-parser-unique-object-id']) {
                                            messageName = message._json['x-parser-unique-object-id'];
                                        } else if (message.name && typeof message.name === 'function') {
                                            messageName = message.name();
                                        } else if (message.name) {
                                            messageName = message.name;
                                        } else if (message.$ref) {
                                            messageName = message.$ref.split('/').pop();
                                        }

                                        // Get payload schema
                                        if (message.payload && typeof message.payload === 'function') {
                                            payload = message.payload();
                                            if (payload && payload.json && typeof payload.json === 'function') {
                                                payload = payload.json();
                                            }
                                        } else if (message.payload) {
                                            payload = message.payload;
                                        }

                                        // Get description
                                        if (message.description && typeof message.description === 'function') {
                                            description = message.description();
                                        } else if (message.description) {
                                            description = message.description;
                                        }

                                        if (messageName) {
                                            // Add to channel mapping
                                            if (!messageToChannels.has(messageName)) {
                                                messageToChannels.set(messageName, []);
                                            }
                                            messageToChannels.get(messageName).push(channelName);

                                            // Add to message schemas for inline messages
                                            messageSchemas.push({
                                                name: messageName,
                                                rustName: toRustTypeName(messageName),
                                                payload,
                                                rawPayload: payload,
                                                description,
                                                channels: [channelName]
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Handle AsyncAPI 2.x format
                    if (channel.subscribe && channel.subscribe()) {
                        const message = channel.subscribe().message();
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
                    }
                    if (channel.publish && channel.publish()) {
                        const message = channel.publish().message();
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
                    }
                } catch (e) {
                    // Ignore channel processing errors
                    console.warn(`Error processing channel: ${e.message}`);
                }
            }
        }
    }

    // Build schema registry from components.schemas
    // Try to access the raw AsyncAPI document
    let rawDoc = null;
    try {
        if (asyncapi.json && typeof asyncapi.json === 'function') {
            rawDoc = asyncapi.json();
        } else if (asyncapi._json) {
            rawDoc = asyncapi._json;
        }
    } catch (e) {
        // Ignore
    }

    // Extract schemas from raw document if available
    if (rawDoc && rawDoc.components && rawDoc.components.schemas) {
        Object.entries(rawDoc.components.schemas).forEach(([name, schema]) => {
            if (name && typeof name === 'string' && schema && typeof schema === 'object') {
                schemaRegistry.set(name, schema);
                componentSchemas.push({
                    name,
                    rustName: toRustTypeName(name),
                    schema: schema,
                    description: schema.description
                });
            }
        });
    }

    // Fallback: try the components.schemas() method
    if (componentSchemas.length === 0 && components && components.schemas) {
        try {
            const schemas = components.schemas();
            if (schemas) {
                // Try different ways to access schemas
                let schemaEntries = [];

                if (schemas instanceof Map) {
                    schemaEntries = Array.from(schemas.entries());
                } else if (typeof schemas === 'object') {
                    schemaEntries = Object.entries(schemas);
                } else if (schemas.all && typeof schemas.all === 'function') {
                    // AsyncAPI parser might have an all() method
                    const allSchemas = schemas.all();
                    if (Array.isArray(allSchemas)) {
                        schemaEntries = allSchemas.map(schema => {
                            const name = schema.uid ? schema.uid() : (schema.id ? schema.id() : null);
                            return [name, schema];
                        }).filter(([name]) => name);
                    }
                }

                schemaEntries.forEach(([name, schema]) => {
                    // Skip internal AsyncAPI parser objects and numeric keys
                    if (!name || name === 'collections' || name === '_meta' || name.startsWith('_') || /^\d+$/.test(name)) {
                        return;
                    }

                    let schemaData = null;
                    let description = null;

                    try {
                        // Handle different schema object types
                        if (schema && typeof schema.json === 'function') {
                            schemaData = schema.json();
                        } else if (schema && typeof schema === 'object') {
                            schemaData = schema;
                        }

                        if (schema && typeof schema.description === 'function') {
                            description = schema.description();
                        } else if (schema && schema.description) {
                            description = schema.description;
                        }
                    } catch (e) {
                        // Ignore schema extraction errors
                        console.warn(`Failed to extract schema for ${name}:`, e.message);
                    }

                    if (schemaData && typeof name === 'string' && name.length > 0) {
                        schemaRegistry.set(name, schemaData);
                        componentSchemas.push({
                            name,
                            rustName: toRustTypeName(name),
                            schema: schemaData,
                            description
                        });
                    }
                });
            }
        } catch (e) {
            console.warn('Failed to extract component schemas:', e.message);
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
                    let rawPayload = null;
                    if (message.payload && typeof message.payload === 'function') {
                        const payloadSchema = message.payload();
                        payload = payloadSchema && payloadSchema.json ? payloadSchema.json() : payloadSchema;
                        // Try to get the raw payload reference from the message
                        if (message._json && message._json.payload) {
                            rawPayload = message._json.payload;
                        }
                    }
                    description = message.description && typeof message.description === 'function' ? message.description() : null;
                    title = message.title && typeof message.title === 'function' ? message.title() : null;

                    // Try to get the actual message name
                    if (message.name && typeof message.name === 'function') {
                        messageName = message.name();
                    } else if (message.name) {
                        messageName = message.name;
                    }

                    // If we have raw document access, try to get the payload reference from there
                    if (!rawPayload && rawDoc && rawDoc.components && rawDoc.components.messages && rawDoc.components.messages[name]) {
                        rawPayload = rawDoc.components.messages[name].payload;
                    }

                    const channels = messageToChannels.get(messageName) || messageToChannels.get(name) || [];
                    messageSchemas.push({
                        name: messageName,
                        rustName: toRustTypeName(messageName),
                        payload,
                        rawPayload,
                        description: description || title,
                        channels
                    });
                } catch (e) {
                    // Ignore payload extraction errors
                    const channels = messageToChannels.get(messageName) || messageToChannels.get(name) || [];
                    messageSchemas.push({
                        name: messageName,
                        rustName: toRustTypeName(messageName),
                        payload,
                        rawPayload: null,
                        description: description || title,
                        channels
                    });
                }
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

        // Handle resolved $ref - check for x-parser-schema-id which indicates original schema name
        if (schema['x-parser-schema-id'] && typeof schema['x-parser-schema-id'] === 'string') {
            const schemaId = schema['x-parser-schema-id'];
            // Check if this matches a known component schema
            if (schemaRegistry.has(schemaId)) {
                const rustTypeName = toRustTypeName(schemaId);
                return rustTypeName;
            }
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
                switch (schema.format) {
                    case 'int32':
                        return 'i32';
                    case 'int64':
                        return 'i64';
                    case 'uint32':
                        return 'u32';
                    case 'uint64':
                        return 'u64';
                    default:
                        // Default to i32 for unspecified format (maintains backward compatibility)
                        return 'i32';
                }
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

            let serdeRename = '';
            if (rustFieldName !== fieldName) {
                serdeRename = `    #[serde(rename = "${fieldName}")]\n`;
            }

            let skipSerializing = '';
            if (optional) {
                skipSerializing = '    #[serde(skip_serializing_if = "Option::is_none")]\n';
            }

            return `${fieldDoc}${serdeRename}${skipSerializing}    pub ${rustFieldName}: ${finalType},`;
        }).join('\n');

        return fields;
    }

    // Process all component schemas first to ensure they are available for references
    componentSchemas.forEach(schema => {
        jsonSchemaToRustType(schema.schema, schema.rustName);
        generatedTypes.add(schema.rustName);
    });

    // Process all message schemas to ensure all referenced types are generated
    messageSchemas.forEach(schema => {
        if (schema.payload) {
            jsonSchemaToRustType(schema.payload, schema.rustName);
        }
    });

    // Return the processed data and generation functions
    return {
        messageSchemas,
        componentSchemas,
        messageToChannels,
        generatedTypes,
        nestedSchemas,
        schemaRegistry,

        // Generation functions
        generateMessageStruct,
        jsonSchemaToRustType,

        // Generate component schema definitions
        generateComponentSchemas() {
            let result = '';

            componentSchemas.forEach(schema => {
                const doc = schema.description ? `/// ${schema.description}\n` : `/// ${schema.name}\n`;

                // Check if this is a standalone enum schema
                if (schema.schema.type === 'string' && schema.schema.enum && Array.isArray(schema.schema.enum)) {
                    // Generate enum definition with serde rename attributes for lowercase serialization
                    const variants = schema.schema.enum.map(variant => {
                        const { rustName, serializedName } = toRustEnumVariantWithSerde(variant);
                        return `    #[serde(rename = "${serializedName}")]\n    ${rustName}`;
                    }).join(',\n');
                    result += `
${doc}#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ${schema.rustName} {
${variants},
}
`;
                } else if (schema.schema.type && !schema.schema.properties) {
                    // Handle primitive types and arrays without properties
                    // Don't use jsonSchemaToRustType here as it might return the type name itself
                    let primitiveType = 'serde_json::Value';

                    switch (schema.schema.type) {
                        case 'string':
                            if (schema.schema.format === 'date-time') primitiveType = 'chrono::DateTime<chrono::Utc>';
                            else if (schema.schema.format === 'uuid') primitiveType = 'uuid::Uuid';
                            else primitiveType = 'String';
                            break;
                        case 'integer':
                            switch (schema.schema.format) {
                                case 'int32': primitiveType = 'i32'; break;
                                case 'int64': primitiveType = 'i64'; break;
                                case 'uint32': primitiveType = 'u32'; break;
                                case 'uint64': primitiveType = 'u64'; break;
                                default: primitiveType = 'i32'; break;
                            }
                            break;
                        case 'number':
                            primitiveType = 'f64';
                            break;
                        case 'boolean':
                            primitiveType = 'bool';
                            break;
                        case 'array':
                            if (schema.schema.items) {
                                // Handle array items
                                let itemType = 'serde_json::Value';
                                if (schema.schema.items.type === 'integer') {
                                    switch (schema.schema.items.format) {
                                        case 'int32': itemType = 'i32'; break;
                                        case 'int64': itemType = 'i64'; break;
                                        case 'uint32': itemType = 'u32'; break;
                                        case 'uint64': itemType = 'u64'; break;
                                        case 'uint8': itemType = 'u8'; break;
                                        case 'int8': itemType = 'i8'; break;
                                        case 'uint16': itemType = 'u16'; break;
                                        case 'int16': itemType = 'i16'; break;
                                        default: itemType = 'i32'; break;
                                    }
                                } else if (schema.schema.items.type === 'string') {
                                    if (schema.schema.items.format === 'date-time') itemType = 'chrono::DateTime<chrono::Utc>';
                                    else if (schema.schema.items.format === 'uuid') itemType = 'uuid::Uuid';
                                    else itemType = 'String';
                                } else if (schema.schema.items.type === 'number') {
                                    itemType = 'f64';
                                } else if (schema.schema.items.type === 'boolean') {
                                    itemType = 'bool';
                                }
                                primitiveType = `Vec<${itemType}>`;
                            } else {
                                primitiveType = 'Vec<serde_json::Value>';
                            }
                            break;
                    }

                    // Generate a newtype wrapper for primitive types and arrays
                    result += `
${doc}#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName}(pub ${primitiveType});

impl From<${primitiveType}> for ${schema.rustName} {
    fn from(value: ${primitiveType}) -> Self {
        Self(value)
    }
}

impl From<${schema.rustName}> for ${primitiveType} {
    fn from(value: ${schema.rustName}) -> Self {
        value.0
    }
}

impl std::fmt::Display for ${schema.rustName} {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ${(() => {
                        // Generate appropriate Display implementation based on the primitive type
                        if (primitiveType.startsWith('Vec<u8>')) {
                            return `self.0.iter().try_for_each(|byte| write!(f, "{:02x}", byte))`;
                        } else if (primitiveType.startsWith('Vec<')) {
                            return 'write!(f, "{:?}", self.0)';
                        } else {
                            return 'write!(f, "{}", self.0)';
                        }
                    })()}
    }
}
`;
                } else {
                    // Generate struct definition
                    const fields = generateMessageStruct(schema.schema, schema.rustName);
                    result += `
${doc}#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName} {
${fields}
}
`;
                }
            });

            return result;
        },

        // Generate nested type definitions
        generateNestedTypes() {
            let result = '';

            for (const [typeName, typeInfo] of nestedSchemas.entries()) {
                // Don't skip enums - they need to be generated even if the parent type exists
                const isEnum = typeInfo.type === 'enum';
                const isComponentSchema = componentSchemas.some(cs => cs.rustName === typeName);

                // Skip if this type was already generated as a component schema (but not enums)
                if (!isEnum && isComponentSchema) {
                    continue;
                }

                if (typeInfo.type === 'enum') {
                    const variants = typeInfo.variants.map(variant => {
                        const { rustName, serializedName } = toRustEnumVariantWithSerde(variant);
                        return `    #[serde(rename = "${serializedName}")]\n    ${rustName}`;
                    }).join(',\n');
                    const doc = typeInfo.description ? `/// ${typeInfo.description}\n` : '';
                    result += `
${doc}#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
        },

        // Generate AsyncApiMessage trait implementations (optional)
        generateAsyncApiTrait() {
            if (!includeAsyncApiTrait) {
                return '';
            }

            // Track which types have already had AsyncApiMessage implementations generated
            const implementedTypes = new Set();
            const implementations = [];

            // First add the trait definition
            implementations.push(`
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
}`);

            messageSchemas.forEach(schema => {
                const doc = schema.description ? `/// ${schema.description}` : `/// ${schema.name} message`;
                const primaryChannel = schema.channels.length > 0 ? schema.channels[0] : 'default';

                // Check if the message payload references a component schema
                let payloadRustName = null;
                let isComponentMessage = false;

                if (schema.rawPayload && schema.rawPayload.$ref) {
                    const refName = schema.rawPayload.$ref.split('/').pop();
                    payloadRustName = toRustTypeName(refName);
                    isComponentMessage = true;
                } else if (schema.payload && schema.payload.$ref) {
                    const refName = schema.payload.$ref.split('/').pop();
                    payloadRustName = toRustTypeName(refName);
                    isComponentMessage = true;
                } else if (schema.payload && schema.payload['x-parser-schema-id']) {
                    // Handle resolved $ref references
                    const schemaId = schema.payload['x-parser-schema-id'];
                    if (schemaRegistry.has(schemaId)) {
                        payloadRustName = toRustTypeName(schemaId);
                        isComponentMessage = true;
                    }
                }

                // For component messages, always generate the message wrapper type
                // even if the payload schema already exists
                if (isComponentMessage && payloadRustName && !implementedTypes.has(schema.rustName)) {
                    implementedTypes.add(schema.rustName);
                    implementations.push(`
${doc}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName} {
    #[serde(flatten)]
    pub payload: ${payloadRustName},
}

impl AsyncApiMessage for ${schema.rustName} {
    fn message_type(&self) -> &'static str {
        "${schema.name}"
    }

    fn channel(&self) -> &'static str {
        "${primaryChannel}"
    }
}`);
                } else if (!generatedTypes.has(schema.rustName) && !implementedTypes.has(schema.rustName)) {
                    // Generate both struct and implementation for inline message schemas
                    implementedTypes.add(schema.rustName);
                    implementations.push(`
${doc}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName} {
${generateMessageStruct(schema.payload, schema.rustName)}
}

impl AsyncApiMessage for ${schema.rustName} {
    fn message_type(&self) -> &'static str {
        "${schema.name}"
    }

    fn channel(&self) -> &'static str {
        "${primaryChannel}"
    }
}`);
                } else if (payloadRustName && generatedTypes.has(payloadRustName) && !implementedTypes.has(payloadRustName)) {
                    // Generate AsyncApiMessage implementation for existing component schema
                    implementedTypes.add(payloadRustName);
                    implementations.push(`
impl AsyncApiMessage for ${payloadRustName} {
    fn message_type(&self) -> &'static str {
        "${schema.name}"
    }

    fn channel(&self) -> &'static str {
        "${primaryChannel}"
    }
}`);
                }
            });

            return implementations.join('');
        }
    };
}

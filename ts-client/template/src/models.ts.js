/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

function generateModels(asyncapi) {
    let content = '// Generated TypeScript models from AsyncAPI specification\n\n';

    // Helper functions for TypeScript identifier generation
    function toTypeScriptIdentifier(str) {
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
        return identifier;
    }


    function toTypeScriptTypeName(str) {
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

    // Extract message schemas and build channel mapping
    const components = asyncapi.components();
    const messageSchemas = [];
    const componentSchemas = [];
    const messageToChannels = new Map();
    const generatedTypes = new Set();
    const schemaRegistry = new Map();

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
                    typeName: toTypeScriptTypeName(name),
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
                            typeName: toTypeScriptTypeName(name),
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

    // First, build channel to message mapping
    if (asyncapi.channels) {
        const channels = asyncapi.channels();
        if (channels) {
            Object.entries(channels).forEach(([channelName, channel]) => {
                try {
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
                // Skip internal AsyncAPI parser objects
                if (name === 'collections' || name === '_meta' || name.startsWith('_')) {
                    return;
                }
                let payload = null;
                let description = null;
                let title = null;
                let messageName = name;

                try {
                    if (message.payload && typeof message.payload === 'function') {
                        const payloadSchema = message.payload();
                        payload = payloadSchema && payloadSchema.json ? payloadSchema.json() : payloadSchema;
                    }
                    description = message.description && typeof message.description === 'function' ? message.description() : message.description;
                    title = message.title && typeof message.title === 'function' ? message.title() : message.title;

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
                    typeName: toTypeScriptTypeName(messageName),
                    payload,
                    description: description || title,
                    channels
                });
            });
        }
    }

    // Helper function to convert JSON schema to TypeScript type
    function jsonSchemaToTypeScriptType(schema, fieldName = '') {
        if (!schema) return 'any';

        // Handle $ref - resolve from schema registry
        if (schema.$ref) {
            const refName = schema.$ref.split('/').pop();
            // Always return the type name for $ref, since we generate all component schemas
            const typeName = toTypeScriptTypeName(refName);
            return typeName;
        }

        // Handle resolved $ref - check for x-parser-schema-id which indicates original schema name
        if (schema['x-parser-schema-id'] && typeof schema['x-parser-schema-id'] === 'string') {
            const schemaId = schema['x-parser-schema-id'];
            // Check if this matches a known component schema
            if (schemaRegistry.has(schemaId)) {
                const typeName = toTypeScriptTypeName(schemaId);
                return typeName;
            }
        }

        if (!schema.type) {
            // If no type specified, check for properties (object) or items (array)
            if (schema.properties) {
                schema.type = 'object';
            } else if (schema.items) {
                schema.type = 'array';
            } else {
                return 'any';
            }
        }

        switch (schema.type) {
            case 'string':
                if (schema.enum && schema.enum.length > 0) {
                    return schema.enum.map(val => `'${val}'`).join(' | ');
                }
                return 'string';
            case 'integer':
            case 'number':
                return 'number';
            case 'boolean':
                return 'boolean';
            case 'array': {
                if (schema.items) {
                    const itemType = jsonSchemaToTypeScriptType(schema.items, fieldName);
                    return `${itemType}[]`;
                }
                return 'any[]';
            }
            case 'object':
                // For objects with properties, we should generate inline types or check if it's a known schema
                if (schema.properties) {
                    // This is a complex object - for now return Record<string, any>
                    // In a more sophisticated implementation, we could generate inline types
                    return 'Record<string, any>';
                }
                return 'Record<string, any>';
            default:
                return 'any';
        }
    }

    // Generate message interfaces
    function generateMessageInterface(schema, messageName) {
        if (!schema || !schema.properties) {
            return '  [key: string]: any;';
        }

        const fields = Object.entries(schema.properties).map(([fieldName, fieldSchema]) => {
            const tsType = jsonSchemaToTypeScriptType(fieldSchema, fieldName);
            const optional = !schema.required || !schema.required.includes(fieldName);
            const optionalMarker = optional ? '?' : '';

            let fieldDoc = '';
            if (fieldSchema.description) {
                fieldDoc = `  /** ${fieldSchema.description} */\n`;
            }

            return `${fieldDoc}  ${fieldName}${optionalMarker}: ${tsType};`;
        }).join('\n');

        return fields;
    }

    // Generate interfaces for component schemas first (so they can be referenced by messages)
    componentSchemas.forEach(schema => {
        const doc = schema.description ? `/** ${schema.description} */\n` : `/** ${schema.name} */\n`;

        // Check if this is a standalone enum schema
        if (schema.schema.type === 'string' && schema.schema.enum && Array.isArray(schema.schema.enum)) {
            // Generate union type for enum
            const enumValues = schema.schema.enum.map(val => `'${val}'`).join(' | ');
            content += `${doc}export type ${schema.typeName} = ${enumValues};\n\n`;
        } else {
            // Generate interface for object schema
            content += `${doc}export interface ${schema.typeName} {\n`;
            content += generateMessageInterface(schema.schema, schema.typeName);
            content += '\n}\n\n';
        }

        // Track generated types to avoid duplicates
        generatedTypes.add(schema.typeName);
    });

    // Generate interfaces for each message (only if not already generated as component schema)
    messageSchemas.forEach(schema => {
        const interfaceName = `${schema.typeName}Payload`;

        // Check if this is a duplicate of a component schema
        // For message payloads that match component schema names, skip the payload version
        if (generatedTypes.has(schema.typeName) || generatedTypes.has(interfaceName)) {
            // Skip generating the payload version if we already have the component schema
            return;
        }

        const doc = schema.description ? `/** ${schema.description} */\n` : `/** ${schema.name} message payload */\n`;

        content += `${doc}export interface ${interfaceName} {\n`;
        content += generateMessageInterface(schema.payload, schema.typeName);
        content += '\n}\n\n';

        generatedTypes.add(interfaceName);
    });

    // Generate a union type for all message payloads
    if (messageSchemas.length > 0) {
        const payloadTypes = messageSchemas.map(schema => `${schema.typeName}Payload`).join(' | ');
        content += '/** Union type for all message payloads */\n';
        content += `export type MessagePayload = ${payloadTypes};\n\n`;

        // Generate message type constants
        content += '/** Message type constants */\n';
        content += 'export const MessageTypes = {\n';
        messageSchemas.forEach(schema => {
            content += `  ${schema.typeName.toUpperCase()}: '${schema.name}',\n`;
        });
        content += '} as const;\n\n';

        content += '/** Message type union */\n';
        content += 'export type MessageType = typeof MessageTypes[keyof typeof MessageTypes];\n\n';
    }

    return content;
}

module.exports = function ({ asyncapi, params }) {
    return (
        <File name="models.ts">
            {generateModels(asyncapi)}
        </File>
    );
};

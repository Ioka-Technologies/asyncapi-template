/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import { buildSchemaRegistry as buildExternalSchemaRegistry } from './schema-utils.js';

/**
 * Generate TypeScript models from AsyncAPI specification
 * This helper extracts the common schema processing logic used by TypeScript templates
 *
 * @param {Object} asyncapi - AsyncAPI document
 * @param {Object} options - Generation options
 * @param {Function} options.toTypeScriptTypeName - Function to convert names to TypeScript type names
 * @param {Function} options.toTypeScriptIdentifier - Function to convert names to TypeScript identifiers
 * @param {boolean} options.includeMessageTypes - Whether to include message type constants
 * @returns {Object} Generated models data and functions
 */
export function generateTypeScriptModels(asyncapi, options = {}) {
    const {
        toTypeScriptTypeName,
        toTypeScriptIdentifier,
        includeMessageTypes = true
    } = options;

    // Helper functions for TypeScript identifier generation
    function defaultToTypeScriptIdentifier(str) {
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

    function defaultToTypeScriptTypeName(str) {
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

    // Use provided functions or defaults
    const toTSTypeName = toTypeScriptTypeName || defaultToTypeScriptTypeName;
    const toTSIdentifier = toTypeScriptIdentifier || defaultToTypeScriptIdentifier;

    // Extract message schemas and build channel mapping
    const components = asyncapi.components();
    const messageSchemas = [];
    const componentSchemas = [];
    const messageToChannels = new Map();
    const generatedTypes = new Set();
    const schemaRegistry = new Map();

    // Build schema registry from components.schemas
    // Try to access the raw AsyncAPI document
    // Note: asyncapi.json() returns the RESOLVED document (with $refs expanded)
    // We need to read the ORIGINAL file to get unresolved $refs
    let rawDoc = null;
    let originalDoc = null;
    try {
        if (asyncapi.json && typeof asyncapi.json === 'function') {
            rawDoc = asyncapi.json();
        } else if (asyncapi._json) {
            rawDoc = asyncapi._json;
        }
    } catch (e) {
        // Ignore
    }

    // Try to read the original file to get unresolved $refs
    const sourcePath = (() => {
        try {
            if (asyncapi._meta && asyncapi._meta.asyncapi && asyncapi._meta.asyncapi.source) {
                return asyncapi._meta.asyncapi.source;
            }
        } catch (e) {
            // Ignore
        }
        return null;
    })();

    if (sourcePath) {
        try {
            // Use require for synchronous loading (works in Node.js context)
            // eslint-disable-next-line no-undef
            const fs = require('fs');
            // eslint-disable-next-line no-undef
            const yaml = require('js-yaml');
            const content = fs.readFileSync(sourcePath, 'utf8');
            originalDoc = yaml.load(content);
        } catch (e) {
            // Ignore - will fall back to resolved doc
        }
    }

    // Build schema registry from external files using the shared buildSchemaRegistry function
    // This loads schemas from external YAML files referenced in the spec
    const externalSchemaRegistry = buildExternalSchemaRegistry(asyncapi);

    // Track schemas that are used as message payloads - these should NOT be generated as standalone types
    // Instead, they will be generated with the message name
    const payloadOnlySchemas = new Set();

    // Copy external schemas to our local registry AND to componentSchemas
    // They will be filtered out later if they are payload-only schemas
    for (const [name, schema] of externalSchemaRegistry) {
        if (!schemaRegistry.has(name)) {
            schemaRegistry.set(name, schema);
            componentSchemas.push({
                name,
                typeName: toTSTypeName(name),
                schema: schema,
                description: schema.description
            });
        }
    }

    // Extract schemas from raw document if available (these take precedence over external schemas)
    if (rawDoc && rawDoc.components && rawDoc.components.schemas) {
        Object.entries(rawDoc.components.schemas).forEach(([name, schema]) => {
            if (name && typeof name === 'string' && schema && typeof schema === 'object') {
                if (!schemaRegistry.has(name)) {
                    schemaRegistry.set(name, schema);
                    componentSchemas.push({
                        name,
                        typeName: toTSTypeName(name),
                        schema: schema,
                        description: schema.description
                    });
                }
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
                            typeName: toTSTypeName(name),
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
            Object.entries(messages).forEach(([indexOrName, message]) => {
                // Skip internal AsyncAPI parser objects
                if (indexOrName === 'collections' || indexOrName === '_meta' || (typeof indexOrName === 'string' && indexOrName.startsWith('_'))) {
                    return;
                }
                let payload = null;
                let rawPayload = null;
                let description = null;
                let title = null;
                let messageName = indexOrName;

                try {
                    if (message.payload && typeof message.payload === 'function') {
                        const payloadSchema = message.payload();
                        payload = payloadSchema && payloadSchema.json ? payloadSchema.json() : payloadSchema;
                        // Try to get the raw payload reference from the message
                        if (message._json && message._json.payload) {
                            rawPayload = message._json.payload;
                        }
                    }
                    description = message.description && typeof message.description === 'function' ? message.description() : message.description;
                    title = message.title && typeof message.title === 'function' ? message.title() : message.title;

                    // Try to get the actual message name from various sources
                    if (message.id && typeof message.id === 'function') {
                        messageName = message.id();
                    } else if (message._meta && message._meta.id) {
                        messageName = message._meta.id;
                    } else if (message.name && typeof message.name === 'function') {
                        messageName = message.name();
                    } else if (message.name) {
                        messageName = message.name;
                    } else if (message._json && message._json.name) {
                        messageName = message._json.name;
                    }

                    // If we have ORIGINAL document access (with unresolved $refs), try to get the payload reference from there
                    // This is critical for external file references like 'schemas/threats.yaml#/ThreatReportPayload'
                    // Use messageName (the actual message name) to look up in originalDoc, not the numeric index
                    if (!rawPayload || !rawPayload.$ref) {
                        if (originalDoc && originalDoc.components && originalDoc.components.messages && originalDoc.components.messages[messageName]) {
                            rawPayload = originalDoc.components.messages[messageName].payload;
                        } else if (rawDoc && rawDoc.components && rawDoc.components.messages && rawDoc.components.messages[messageName]) {
                            // Fallback to resolved doc (won't have $ref but might have x-parser-schema-id)
                            rawPayload = rawDoc.components.messages[messageName].payload;
                        }
                    }
                } catch (e) {
                    // Ignore payload extraction errors
                }

                const channels = messageToChannels.get(messageName) || messageToChannels.get(indexOrName) || [];
                messageSchemas.push({
                    name: messageName,
                    typeName: toTSTypeName(messageName),
                    payload,
                    rawPayload,
                    description: description || title,
                    channels
                });
            });
        }
    }

    // Deduplicate messageSchemas - prefer entries with rawPayload.$ref over those without
    // This handles the case where a message is referenced from both channels and components.messages
    const deduplicatedMessageSchemas = [];
    const seenMessageNames = new Map(); // Map<messageName, index in deduplicatedMessageSchemas>

    for (const schema of messageSchemas) {
        const existingIndex = seenMessageNames.get(schema.name);
        if (existingIndex !== undefined) {
            // We've seen this message before - check if the new one has rawPayload.$ref
            const existing = deduplicatedMessageSchemas[existingIndex];
            if (schema.rawPayload && schema.rawPayload.$ref && (!existing.rawPayload || !existing.rawPayload.$ref)) {
                // New entry has $ref, existing doesn't - replace
                deduplicatedMessageSchemas[existingIndex] = schema;
            }
            // Otherwise keep the existing one
        } else {
            // First time seeing this message
            seenMessageNames.set(schema.name, deduplicatedMessageSchemas.length);
            deduplicatedMessageSchemas.push(schema);
        }
    }

    // Replace messageSchemas with deduplicated version
    messageSchemas.length = 0;
    messageSchemas.push(...deduplicatedMessageSchemas);

    // Pre-populate payloadOnlySchemas by scanning all messages for payload $refs
    // This must be done BEFORE generateComponentSchemas() is called
    messageSchemas.forEach(schema => {
        let payloadSchemaName = null;

        if (schema.rawPayload && schema.rawPayload.$ref) {
            payloadSchemaName = schema.rawPayload.$ref.split('/').pop();
        } else if (schema.payload && schema.payload.$ref) {
            payloadSchemaName = schema.payload.$ref.split('/').pop();
        } else if (schema.payload && schema.payload['x-parser-schema-id']) {
            // Handle resolved $ref references
            const schemaId = schema.payload['x-parser-schema-id'];
            if (schemaRegistry.has(schemaId)) {
                payloadSchemaName = schemaId;
            }
        }

        // If we have a payload schema reference, mark it as payload-only
        if (payloadSchemaName && schemaRegistry.has(payloadSchemaName)) {
            payloadOnlySchemas.add(payloadSchemaName);
        }
    });

    // Helper function to merge allOf schemas into a single schema
    function mergeAllOfSchemas(allOfArray) {
        const merged = {
            type: 'object',
            properties: {},
            required: []
        };

        for (const subSchema of allOfArray) {
            // Recursively resolve nested allOf
            let resolvedSchema = subSchema;
            if (subSchema.allOf && Array.isArray(subSchema.allOf)) {
                resolvedSchema = mergeAllOfSchemas(subSchema.allOf);
            }

            // Handle $ref in allOf - resolve from schema registry
            if (resolvedSchema.$ref) {
                const refName = resolvedSchema.$ref.split('/').pop();
                if (schemaRegistry.has(refName)) {
                    resolvedSchema = schemaRegistry.get(refName);
                    // Recursively resolve if the referenced schema also has allOf
                    if (resolvedSchema.allOf && Array.isArray(resolvedSchema.allOf)) {
                        resolvedSchema = mergeAllOfSchemas(resolvedSchema.allOf);
                    }
                }
            }

            // Merge properties
            if (resolvedSchema.properties) {
                Object.assign(merged.properties, resolvedSchema.properties);
            }

            // Merge required arrays
            if (resolvedSchema.required && Array.isArray(resolvedSchema.required)) {
                merged.required = [...new Set([...merged.required, ...resolvedSchema.required])];
            }

            // Preserve type if specified
            if (resolvedSchema.type) {
                merged.type = resolvedSchema.type;
            }

            // Preserve description if specified
            if (resolvedSchema.description && !merged.description) {
                merged.description = resolvedSchema.description;
            }
        }

        return merged;
    }

    // Helper function to convert JSON schema to TypeScript type
    function jsonSchemaToTypeScriptType(schema, fieldName = '', isComponentSchemaDefinition = false) {
        if (!schema) return 'any';

        // Handle $ref - resolve from schema registry
        if (schema.$ref) {
            const refName = schema.$ref.split('/').pop();
            // Always return the type name for $ref, since we generate all component schemas
            const typeName = toTSTypeName(refName);
            return typeName;
        }

        // Handle resolved $ref - check for x-parser-schema-id which indicates original schema name
        // This MUST be checked BEFORE allOf handling to prevent creating duplicate types
        // when a component schema uses allOf internally
        // But skip this if we're defining the component schema itself (to avoid circular references)
        if (!isComponentSchemaDefinition && schema['x-parser-schema-id'] && typeof schema['x-parser-schema-id'] === 'string') {
            const schemaId = schema['x-parser-schema-id'];
            // Check if this matches a known component schema
            if (schemaRegistry.has(schemaId)) {
                const typeName = toTSTypeName(schemaId);
                return typeName;
            }
        }

        // Handle allOf - merge schemas and process as a single schema
        // This comes AFTER x-parser-schema-id check so that component schemas using allOf
        // are properly reused instead of creating new inline types
        if (schema.allOf && Array.isArray(schema.allOf)) {
            const mergedSchema = mergeAllOfSchemas(schema.allOf);
            return jsonSchemaToTypeScriptType(mergedSchema, fieldName, isComponentSchemaDefinition);
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
        // Handle allOf schemas by merging them first
        let processedSchema = schema;
        if (schema && schema.allOf && Array.isArray(schema.allOf)) {
            processedSchema = mergeAllOfSchemas(schema.allOf);
        }

        if (!processedSchema || !processedSchema.properties) {
            return '  [key: string]: any;';
        }

        const fields = Object.entries(processedSchema.properties).map(([fieldName, fieldSchema]) => {
            const tsType = jsonSchemaToTypeScriptType(fieldSchema, fieldName);
            const optional = !processedSchema.required || !processedSchema.required.includes(fieldName);
            const optionalMarker = optional ? '?' : '';

            let fieldDoc = '';
            if (fieldSchema.description) {
                fieldDoc = `  /** ${fieldSchema.description} */\n`;
            }

            return `${fieldDoc}  ${fieldName}${optionalMarker}: ${tsType};`;
        }).join('\n');

        return fields;
    }

    // Return the processed data and generation functions
    return {
        messageSchemas,
        componentSchemas,
        messageToChannels,
        generatedTypes,
        schemaRegistry,

        // Generation functions
        generateMessageInterface,
        jsonSchemaToTypeScriptType,

        // Generate interfaces for component schemas
        generateComponentSchemas() {
            let content = '';

            componentSchemas.forEach(schema => {
                // Skip schemas that are only used as message payloads
                // These are generated with the message name instead
                if (payloadOnlySchemas.has(schema.name)) {
                    return;
                }

                const doc = schema.description ? `/** ${schema.description} */\n` : `/** ${schema.name} */\n`;

                // Check if this is a standalone enum schema
                if (schema.schema.type === 'string' && schema.schema.enum && Array.isArray(schema.schema.enum)) {
                    // Generate union type for enum
                    const enumValues = schema.schema.enum.map(val => `'${val}'`).join(' | ');
                    content += `${doc}export type ${schema.typeName} = ${enumValues};\n\n`;
                } else if (schema.schema.type && !schema.schema.properties) {
                    // For primitive types (integer, number, string, boolean, array) without properties,
                    // generate a type alias instead of an interface
                    const tsType = jsonSchemaToTypeScriptType(schema.schema, schema.name, true);
                    content += `${doc}export type ${schema.typeName} = ${tsType};\n\n`;
                } else {
                    // Generate interface for object schema
                    content += `${doc}export interface ${schema.typeName} {\n`;
                    content += generateMessageInterface(schema.schema, schema.typeName);
                    content += '\n}\n\n';
                }

                // Track generated types to avoid duplicates
                generatedTypes.add(schema.typeName);
            });

            return content;
        },

        // Generate interfaces for each message
        generateMessageSchemas() {
            let content = '';

            messageSchemas.forEach(schema => {
                const interfaceName = schema.typeName;

                // Check if this is a duplicate of a component schema
                // For message payloads that match component schema names, skip the payload version
                if (generatedTypes.has(interfaceName)) {
                    // Skip generating if we already have this type
                    return;
                }

                const doc = schema.description ? `/** ${schema.description} */\n` : `/** ${schema.name} message */\n`;

                // Check if the message payload references a component schema
                let payloadSchemaName = null;
                let payloadSchema = null;

                if (schema.rawPayload && schema.rawPayload.$ref) {
                    payloadSchemaName = schema.rawPayload.$ref.split('/').pop();
                } else if (schema.payload && schema.payload.$ref) {
                    payloadSchemaName = schema.payload.$ref.split('/').pop();
                } else if (schema.payload && schema.payload['x-parser-schema-id']) {
                    // Handle resolved $ref references
                    const schemaId = schema.payload['x-parser-schema-id'];
                    if (schemaRegistry.has(schemaId)) {
                        payloadSchemaName = schemaId;
                    }
                }

                // If we have a payload schema reference, resolve it and flatten the fields
                // The message type should use the MESSAGE name (e.g., BootstrapDeviceRequest),
                // NOT the payload schema name (e.g., BootstrapDevicePayload)
                if (payloadSchemaName && schemaRegistry.has(payloadSchemaName)) {
                    payloadSchema = schemaRegistry.get(payloadSchemaName);
                    // Mark this schema as payload-only so it won't be generated as a standalone type
                    payloadOnlySchemas.add(payloadSchemaName);

                    // Follow $ref chains - if the schema is just a $ref, resolve it
                    // This handles cases like: ConfigureDeviceResponsePayload: { $ref: 'common.yaml#/BaseResponse' }
                    while (payloadSchema && payloadSchema.$ref && !payloadSchema.properties && !payloadSchema.allOf) {
                        const refName = payloadSchema.$ref.split('/').pop();
                        if (schemaRegistry.has(refName)) {
                            payloadSchema = schemaRegistry.get(refName);
                        } else {
                            // Can't resolve further, break
                            break;
                        }
                    }
                }

                // Generate the message interface with flattened payload fields
                content += `${doc}export interface ${interfaceName} {\n`;
                if (payloadSchema) {
                    // Use the resolved payload schema to generate fields
                    content += generateMessageInterface(payloadSchema, interfaceName);
                } else if (schema.payload) {
                    // Fallback to the parsed payload
                    content += generateMessageInterface(schema.payload, schema.typeName);
                } else {
                    // No payload - generate empty interface with index signature
                    content += '  [key: string]: any;';
                }
                content += '\n}\n\n';

                generatedTypes.add(interfaceName);
            });

            return content;
        },

        // Generate message type constants and unions
        generateMessageTypes() {
            if (!includeMessageTypes || messageSchemas.length === 0) {
                return '';
            }

            let content = '';

            // Generate a union type for all message types
            const messageTypes = messageSchemas.map(schema => schema.typeName).join(' | ');
            content += '/** Union type for all message types */\n';
            content += `export type Message = ${messageTypes};\n\n`;

            // Generate message type constants
            content += '/** Message type constants */\n';
            content += 'export const MessageTypes = {\n';
            messageSchemas.forEach(schema => {
                content += `  ${schema.typeName.toUpperCase()}: '${schema.name}',\n`;
            });
            content += '} as const;\n\n';

            content += '/** Message type union */\n';
            content += 'export type MessageType = typeof MessageTypes[keyof typeof MessageTypes];\n\n';

            return content;
        }
    };
}

/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import { buildSchemaRegistry as buildExternalSchemaRegistry } from './schema-utils.js';

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

    // Track which messages are defined in components.messages (to avoid duplicates)
    const componentMessageNames = new Set();

    // First, build channel to message mapping and extract INLINE message schemas
    // Messages that reference components.messages will be extracted later from components
    if (asyncapi.channels) {
        const channels = asyncapi.channels();
        if (channels) {
            // Use proper iteration for AsyncAPI collection
            for (const channel of channels) {
                try {
                    const channelName = channel.id();

                    // Handle AsyncAPI 3.x format - extract message names from channels
                    if (channel.messages) {
                        const messages = channel.messages();
                        if (messages) {
                            // Check if messages is an object with message names as keys
                            if (typeof messages === 'object' && !Array.isArray(messages)) {
                                // Iterate through message entries (messageName -> messageObject)
                                Object.entries(messages).forEach(([messageName, message]) => {
                                    if (message && messageName) {
                                        // Add to channel mapping
                                        if (!messageToChannels.has(messageName)) {
                                            messageToChannels.set(messageName, []);
                                        }
                                        messageToChannels.get(messageName).push(channelName);

                                        // Check if this is a reference to components.messages or an inline message
                                        // If message has _json with $ref pointing to components/messages, skip adding to messageSchemas
                                        const isComponentRef = message._json && message._json.$ref &&
                                            message._json.$ref.includes('#/components/messages/');

                                        if (!isComponentRef) {
                                            // This is an inline message - extract payload
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

                                            // Add to message schemas for inline messages
                                            messageSchemas.push({
                                                name: messageName,
                                                rustName: toRustTypeName(messageName),
                                                payload,
                                                rawPayload: payload, // For inline messages, rawPayload is the same as payload
                                                description,
                                                channels: [channelName]
                                            });
                                        }
                                    }
                                });
                            } else {
                                // Try iterating as a collection
                                for (const message of messages) {
                                    if (message) {
                                        let messageName = null;

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

                                        if (messageName) {
                                            // Add to channel mapping
                                            if (!messageToChannels.has(messageName)) {
                                                messageToChannels.set(messageName, []);
                                            }
                                            messageToChannels.get(messageName).push(channelName);

                                            // Check if this is a reference to components.messages or an inline message
                                            const isComponentRef = (message._json && message._json.$ref &&
                                                message._json.$ref.includes('#/components/messages/')) ||
                                                (message.$ref && message.$ref.includes('#/components/messages/'));

                                            if (!isComponentRef) {
                                                // This is an inline message - extract payload
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

                                                // Add to message schemas for inline messages
                                                messageSchemas.push({
                                                    name: messageName,
                                                    rustName: toRustTypeName(messageName),
                                                    payload,
                                                    rawPayload: payload, // For inline messages, rawPayload is the same as payload
                                                    description,
                                                    channels: [channelName]
                                                });
                                            }
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

    // Build schema registry from components.schemas AND external files
    // Use the shared buildSchemaRegistry function to load external schemas
    const externalSchemaRegistry = buildExternalSchemaRegistry(asyncapi);

    // Track schemas that are used as message payloads - these should NOT be generated as standalone types
    // Instead, they will be generated with the message name
    const payloadOnlySchemas = new Set();

    // Copy external schemas to our local registry (but NOT to componentSchemas yet)
    // We'll add them to componentSchemas later, after we know which ones are payload-only
    for (const [name, schema] of externalSchemaRegistry) {
        schemaRegistry.set(name, schema);
    }

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

    // Extract schemas from raw document if available (these take precedence)
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

    // Add external schemas to componentSchemas (if not already added from raw doc)
    for (const [name, schema] of externalSchemaRegistry) {
        if (!componentSchemas.some(cs => cs.name === name)) {
            componentSchemas.push({
                name,
                rustName: toRustTypeName(name),
                schema: schema,
                description: schema.description
            });
        }
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
            Object.entries(messages).forEach(([indexOrName, message]) => {
                let payload = null;
                let description = null;
                let title = null;
                let messageName = indexOrName;

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

                    const channels = messageToChannels.get(messageName) || messageToChannels.get(indexOrName) || [];
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
                    const channels = messageToChannels.get(messageName) || messageToChannels.get(indexOrName) || [];
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

    // Helper function to find a matching schema in the registry by comparing structure
    // This is needed because the parser resolves $refs and loses the original schema names
    function findMatchingSchemaInRegistry(schema) {
        if (!schema || typeof schema !== 'object') return null;

        // For enum schemas, try to match by comparing enum values
        if (schema.type === 'string' && schema.enum && Array.isArray(schema.enum)) {
            const schemaEnumValues = schema.enum.slice().sort().join(',');

            for (const [name, registrySchema] of schemaRegistry) {
                if (registrySchema.type === 'string' && registrySchema.enum && Array.isArray(registrySchema.enum)) {
                    const registryEnumValues = registrySchema.enum.slice().sort().join(',');
                    if (registryEnumValues === schemaEnumValues) {
                        return name;
                    }
                }
            }
        }

        // For allOf schemas, try to match by comparing the allOf structure
        if (schema.allOf && Array.isArray(schema.allOf)) {
            for (const [name, registrySchema] of schemaRegistry) {
                if (registrySchema.allOf && Array.isArray(registrySchema.allOf)) {
                    // Compare allOf lengths
                    if (registrySchema.allOf.length === schema.allOf.length) {
                        // Simple heuristic: if both have allOf with same length, likely a match
                        // Check if the properties match after merging
                        const mergedRegistry = mergeAllOfSchemas(registrySchema.allOf);
                        const mergedSchema = mergeAllOfSchemas(schema.allOf);

                        // Compare property names
                        const registryProps = Object.keys(mergedRegistry.properties || {}).sort().join(',');
                        const schemaProps = Object.keys(mergedSchema.properties || {}).sort().join(',');

                        if (registryProps === schemaProps && registryProps.length > 0) {
                            return name;
                        }
                    }
                }
            }
        }

        // For object schemas, try to match by comparing properties
        if (schema.properties && Object.keys(schema.properties).length > 0) {
            const schemaProps = Object.keys(schema.properties).sort().join(',');

            for (const [name, registrySchema] of schemaRegistry) {
                // Skip if registry schema has allOf (handled above)
                if (registrySchema.allOf) continue;

                if (registrySchema.properties) {
                    const registryProps = Object.keys(registrySchema.properties).sort().join(',');
                    if (registryProps === schemaProps) {
                        return name;
                    }
                }
            }
        }

        return null;
    }

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

    // Helper function to convert JSON schema to Rust type
    function jsonSchemaToRustType(schema, typeName = null, isPropertyContext = false) {
        if (!schema) return 'serde_json::Value';

        // Handle $ref - always check first and return the referenced type
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
        // This MUST be checked BEFORE allOf handling to prevent creating duplicate types
        // when a component schema uses allOf internally
        if (schema['x-parser-schema-id'] && typeof schema['x-parser-schema-id'] === 'string') {
            const schemaId = schema['x-parser-schema-id'];
            // Check if this matches a known component schema - if so, reuse it
            if (schemaRegistry.has(schemaId)) {
                const rustTypeName = toRustTypeName(schemaId);
                // Return immediately - do not create a new type with a prefixed name
                return rustTypeName;
            }
        }

        // Handle allOf - first try to match against known schemas in the registry
        // This is needed because the parser resolves $refs and loses the original schema names
        if (schema.allOf && Array.isArray(schema.allOf)) {
            // Try to find a matching schema in the registry
            const matchingSchemaName = findMatchingSchemaInRegistry(schema);
            if (matchingSchemaName) {
                const rustTypeName = toRustTypeName(matchingSchemaName);
                // Return the registry type name instead of creating a new inline type
                return rustTypeName;
            }

            // No match found, merge and process as a single schema
            const mergedSchema = mergeAllOfSchemas(schema.allOf);
            return jsonSchemaToRustType(mergedSchema, typeName, isPropertyContext);
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
                    // First, try to find a matching enum in the registry
                    const matchingEnumName = findMatchingSchemaInRegistry(schema);
                    if (matchingEnumName) {
                        const rustTypeName = toRustTypeName(matchingEnumName);
                        // Ensure the enum is generated by adding it to nestedSchemas if not already there
                        if (!generatedTypes.has(rustTypeName) && !nestedSchemas.has(rustTypeName)) {
                            const registrySchema = schemaRegistry.get(matchingEnumName);
                            if (registrySchema && registrySchema.enum) {
                                nestedSchemas.set(rustTypeName, {
                                    type: 'enum',
                                    variants: registrySchema.enum,
                                    description: registrySchema.description
                                });
                            }
                        }
                        return rustTypeName;
                    }
                    // Generate enum type only if no match found
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
                    case 'uint16':
                        return 'u16';
                    case 'uint8':
                        return 'u8';
                    case 'int16':
                        return 'i16';
                    case 'int8':
                        return 'i8';
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
                    // First, try to find a matching object schema in the registry
                    const matchingObjectName = findMatchingSchemaInRegistry(schema);
                    if (matchingObjectName) {
                        return toRustTypeName(matchingObjectName);
                    }
                    // Generate nested struct only if no match found
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
        // Handle allOf schemas by merging them first
        let processedSchema = schema;
        if (schema && schema.allOf && Array.isArray(schema.allOf)) {
            processedSchema = mergeAllOfSchemas(schema.allOf);
        }

        if (!processedSchema || !processedSchema.properties) {
            return '    pub data: serde_json::Value,';
        }

        const fields = Object.entries(processedSchema.properties).map(([fieldName, fieldSchema]) => {
            const rustFieldName = toRustFieldName(fieldName);
            const fieldTypeName = `${messageName}${toRustTypeName(fieldName)}`;
            const rustType = jsonSchemaToRustType(fieldSchema, fieldTypeName);
            const requiredFields = processedSchema.required;
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
    // We must resolve payload schemas from the registry (following $ref chains)
    // and call generateMessageStruct() to discover nested enums/structs.
    // Simply calling jsonSchemaToRustType(schema.payload) short-circuits when
    // x-parser-schema-id is present, missing inline nested types.
    messageSchemas.forEach(schema => {
        if (schema.payload) {
            jsonSchemaToRustType(schema.payload, schema.rustName);
        }

        // Also resolve the raw payload schema from the registry and generate
        // the message struct fields - this discovers nested enums and structs
        // that would otherwise only be found during generateAsyncApiTrait()
        let payloadSchemaName = null;
        let resolvedPayloadSchema = null;

        if (schema.rawPayload && schema.rawPayload.$ref) {
            payloadSchemaName = schema.rawPayload.$ref.split('/').pop();
        } else if (schema.payload && schema.payload.$ref) {
            payloadSchemaName = schema.payload.$ref.split('/').pop();
        } else if (schema.payload && schema.payload['x-parser-schema-id']) {
            const schemaId = schema.payload['x-parser-schema-id'];
            if (schemaRegistry.has(schemaId)) {
                payloadSchemaName = schemaId;
            }
        }

        if (payloadSchemaName && schemaRegistry.has(payloadSchemaName)) {
            resolvedPayloadSchema = schemaRegistry.get(payloadSchemaName);

            // Follow $ref chains
            while (resolvedPayloadSchema && resolvedPayloadSchema.$ref && !resolvedPayloadSchema.properties && !resolvedPayloadSchema.allOf) {
                const refName = resolvedPayloadSchema.$ref.split('/').pop();
                if (schemaRegistry.has(refName)) {
                    resolvedPayloadSchema = schemaRegistry.get(refName);
                } else {
                    break;
                }
            }
        }

        // Generate message struct fields from the resolved schema to discover nested types
        // Only do this for registry-resolved schemas (not inline payloads, which are already
        // handled by the jsonSchemaToRustType call above and would cause duplicate structs)
        if (resolvedPayloadSchema) {
            generateMessageStruct(resolvedPayloadSchema, schema.rustName);
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
                // Skip schemas that are only used as message payloads
                // These are generated with the message name instead
                if (payloadOnlySchemas.has(schema.name)) {
                    return;
                }

                const doc = schema.description ? `/// ${schema.description}\n` : `/// ${schema.name}\n`;

                // Check if this schema is just a $ref to another schema (type alias)
                if (schema.schema.$ref) {
                    const refName = schema.schema.$ref.split('/').pop();
                    const refRustName = toRustTypeName(refName);
                    // Generate a type alias
                    result += `
${doc}pub type ${schema.rustName} = ${refRustName};
`;
                    return;
                }

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
            const generatedInNestedTypes = new Set();

            // Build a set of message struct names that will be generated by
            // generateAsyncApiTrait() or inline message generation in templates
            const messageStructNames = new Set(messageSchemas.map(s => s.rustName));

            for (const [typeName, typeInfo] of nestedSchemas.entries()) {
                // Skip if already generated in this function
                if (generatedInNestedTypes.has(typeName)) {
                    continue;
                }

                const isComponentSchema = componentSchemas.some(cs => cs.rustName === typeName);

                // For structs, skip if already generated as a component schema
                // For enums, we need to check if the component schema actually generated it
                if (typeInfo.type === 'struct' && isComponentSchema) {
                    continue;
                }

                // For structs, skip if this will be generated as a message struct
                // (by generateAsyncApiTrait or inline message generation in templates)
                if (typeInfo.type === 'struct' && messageStructNames.has(typeName)) {
                    continue;
                }

                // For enums that are component schemas, check if they were actually generated
                // by looking at whether the component schema has the enum definition
                if (typeInfo.type === 'enum' && isComponentSchema) {
                    // The component schema should have generated this enum, so skip
                    // But we need to verify it was actually generated
                    const componentSchema = componentSchemas.find(cs => cs.rustName === typeName);
                    if (componentSchema && componentSchema.schema.type === 'string' && componentSchema.schema.enum) {
                        // Component schema will generate this enum, skip
                        continue;
                    }
                }

                generatedInNestedTypes.add(typeName);

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

                // Skip if already implemented
                if (implementedTypes.has(schema.rustName)) {
                    return;
                }

                implementedTypes.add(schema.rustName);

                // Generate the message struct with flattened payload fields
                let fields;
                if (payloadSchema) {
                    // Use the resolved payload schema to generate fields
                    fields = generateMessageStruct(payloadSchema, schema.rustName);
                } else if (schema.payload) {
                    // Fallback to the parsed payload
                    fields = generateMessageStruct(schema.payload, schema.rustName);
                } else {
                    // No payload - generate empty struct with data field
                    fields = '    pub data: serde_json::Value,';
                }

                implementations.push(`
${doc}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName} {
${fields}
}

impl AsyncApiMessage for ${schema.rustName} {
    fn message_type(&self) -> &'static str {
        "${schema.name}"
    }

    fn channel(&self) -> &'static str {
        "${primaryChannel}"
    }
}`);
            });

            return implementations.join('');
        }
    };
}

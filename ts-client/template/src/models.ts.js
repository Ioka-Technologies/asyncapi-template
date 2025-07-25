/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

function generateModels(asyncapi) {
    let content = `// Generated TypeScript models from AsyncAPI specification\n\n`;

    // Helper functions for TypeScript identifier generation
    function toTypeScriptIdentifier(str) {
        if (!str) return 'unknown';
        let identifier = str
            .replace(/[^a-zA-Z0-9_]/g, '_')
            .replace(/^[0-9]/, '_$&')
            .replace(/_+/g, '_')
            .replace(/^_+|_+$/g, '');
        if (/^[0-9]/.test(identifier)) {
            identifier = 'Item' + identifier;
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
    const messageToChannels = new Map();
    const generatedTypes = new Set();

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
    function jsonSchemaToTypeScriptType(schema) {
        if (!schema) return 'any';

        // Handle $ref
        if (schema.$ref) {
            const refName = schema.$ref.split('/').pop();
            return toTypeScriptTypeName(refName);
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
                const itemType = jsonSchemaToTypeScriptType(schema.items);
                return `${itemType}[]`;
            }
            case 'object':
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
            const tsType = jsonSchemaToTypeScriptType(fieldSchema);
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

    // Generate interfaces for each message
    messageSchemas.forEach(schema => {
        const doc = schema.description ? `/** ${schema.description} */\n` : `/** ${schema.name} message payload */\n`;

        content += `${doc}export interface ${schema.typeName}Payload {\n`;
        content += generateMessageInterface(schema.payload, schema.typeName);
        content += `\n}\n\n`;
    });

    // Generate a union type for all message payloads
    if (messageSchemas.length > 0) {
        const payloadTypes = messageSchemas.map(schema => `${schema.typeName}Payload`).join(' | ');
        content += `/** Union type for all message payloads */\n`;
        content += `export type MessagePayload = ${payloadTypes};\n\n`;

        // Generate message type constants
        content += `/** Message type constants */\n`;
        content += `export const MessageTypes = {\n`;
        messageSchemas.forEach(schema => {
            content += `  ${schema.typeName.toUpperCase()}: '${schema.name}',\n`;
        });
        content += `} as const;\n\n`;

        content += `/** Message type union */\n`;
        content += `export type MessageType = typeof MessageTypes[keyof typeof MessageTypes];\n\n`;
    }

    return content;
}

module.exports = function ({ asyncapi, params }) {
    return (
        <File name="models.ts">
            {generateModels(asyncapi)}
        </File>
    );
}

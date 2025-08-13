/**
 * Shared helper functions for Rust AsyncAPI NATS client template generation
 *
 * This module consolidates common utility functions used across multiple template files
 * to reduce code duplication and ensure consistency.
 */

/**
 * Converts a string to a valid Rust identifier
 * Handles special characters, keywords, and ensures valid Rust naming conventions
 *
 * @param {string} str - Input string to convert
 * @returns {string} Valid Rust identifier
 */
export function toRustIdentifier(str) {
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

/**
 * Converts a string to PascalCase Rust type name
 * Handles camelCase, snake_case, and kebab-case inputs
 *
 * @param {string} str - Input string to convert
 * @returns {string} PascalCase Rust type name
 */
export function toRustTypeName(str) {
    if (!str) return 'Unknown';

    // Ensure str is a string
    const strValue = String(str);
    const identifier = toRustIdentifier(strValue);

    // Handle camelCase and PascalCase inputs by splitting on capital letters too
    const parts = identifier
        .replace(/([a-z])([A-Z])/g, '$1_$2') // Insert underscore before capital letters
        .split(/[_\s-]+/) // Split on underscores, spaces, and hyphens
        .filter(part => part.length > 0);

    return parts
        .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
        .join('');
}

/**
 * Converts a string to snake_case Rust field name
 *
 * @param {string} str - Input string to convert
 * @returns {string} snake_case Rust field name
 */
export function toRustFieldName(str) {
    if (!str) return 'unknown';
    const identifier = toRustIdentifier(str);
    return identifier
        .replace(/([A-Z])/g, '_$1')
        .toLowerCase()
        .replace(/^_/, '')
        .replace(/_+/g, '_');
}

/**
 * Converts a string to Rust enum variant name (PascalCase)
 *
 * @param {string} str - Input string to convert
 * @returns {string} PascalCase enum variant name
 */
export function toRustEnumVariant(str) {
    if (!str) return 'Unknown';
    return str
        .split(/[-_\s]+/)
        .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
        .join('');
}

/**
 * Converts a string to Rust enum variant with serde rename for lowercase serialization
 *
 * @param {string} str - Input string to convert
 * @returns {object} Object with rustName (PascalCase) and serializedName (lowercase)
 */
export function toRustEnumVariantWithSerde(str) {
    if (!str) return { rustName: 'Unknown', serializedName: 'unknown' };

    const rustName = str
        .split(/[-_\s]+/)
        .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
        .join('');

    const serializedName = str.toLowerCase();

    return { rustName, serializedName };
}

/**
 * Gets the message type name from a message object
 *
 * @param {object} message - AsyncAPI message object
 * @returns {string|null} Message type name or null if not found
 */
export function getMessageTypeName(message) {
    if (!message) return null;

    try {
        // Try AsyncAPI 3.x format first - check _meta and _json properties
        if (message._meta && message._meta.id) {
            return message._meta.id;
        }
        if (message._json && message._json['x-parser-message-name']) {
            return message._json['x-parser-message-name'];
        }
        if (message._json && message._json['x-parser-unique-object-id']) {
            return message._json['x-parser-unique-object-id'];
        }

        // Try different ways to get the message name
        if (message.name && typeof message.name === 'function') {
            return message.name();
        }
        if (message.name && typeof message.name === 'string') {
            return message.name;
        }
        if (message.title && typeof message.title === 'function') {
            return message.title();
        }
        if (message.title && typeof message.title === 'string') {
            return message.title;
        }

        // Try to extract from $ref
        if (message.$ref) {
            return message.$ref.split('/').pop();
        }

        return null;
    } catch (e) {
        return null;
    }
}

/**
 * Gets the proper Rust type name from a message
 *
 * @param {object} message - AsyncAPI message object
 * @returns {string} Rust type name
 */
export function getMessageRustTypeName(message) {
    const messageName = getMessageTypeName(message);
    return messageName ? toRustTypeName(messageName) : 'UnknownMessage';
}

/**
 * Gets the payload component schema Rust type name from a message
 * This extracts the actual payload type (component schema) rather than the message wrapper
 *
 * @param {object} message - AsyncAPI message object
 * @returns {string} Rust type name for the payload component schema
 */
export function getPayloadRustTypeName(message) {
    if (!message) return 'UnknownPayload';

    try {
        // First priority: For inline message schemas, get the message name itself
        // This handles cases where the message is defined inline in channels
        const messageName = getMessageTypeName(message);
        if (messageName) {
            // Check if this is a component message reference (has payload.$ref)
            let payload = null;
            if (message.payload && typeof message.payload === 'function') {
                payload = message.payload();
            } else if (message.payload) {
                payload = message.payload;
            }

            // Check the message's _json for payload information
            const messageJson = message._json || message;
            if (!payload && messageJson.payload) {
                payload = messageJson.payload;
            }

            // If payload has a $ref, this is a component message - extract the schema name
            if (payload && payload.$ref) {
                const refParts = payload.$ref.split('/');
                const schemaName = refParts[refParts.length - 1];
                return toRustTypeName(schemaName);
            }

            // For inline message schemas, use the message name directly as the payload type
            // This is the correct approach for messages defined inline in channels
            return toRustTypeName(messageName);
        }

        // Second priority: Try to get the payload schema reference from the message
        let payload = null;

        // Try different ways to access the payload
        if (message.payload && typeof message.payload === 'function') {
            payload = message.payload();
        } else if (message.payload) {
            payload = message.payload;
        }

        if (payload) {
            // Check for $ref in the payload (direct reference to component schema)
            if (payload.$ref) {
                const refParts = payload.$ref.split('/');
                const schemaName = refParts[refParts.length - 1];
                return toRustTypeName(schemaName);
            }

            // Check for resolved $ref using x-parser-schema-id
            if (payload['x-parser-schema-id']) {
                return toRustTypeName(payload['x-parser-schema-id']);
            }

            // Check for x-parser-schema-id in _json
            if (payload._json && payload._json['x-parser-schema-id']) {
                return toRustTypeName(payload._json['x-parser-schema-id']);
            }

            // Check for title or name in the payload schema
            if (payload.title) {
                const title = typeof payload.title === 'function' ? payload.title() : payload.title;
                if (title) return toRustTypeName(title);
            }
            if (payload.name) {
                const name = typeof payload.name === 'function' ? payload.name() : payload.name;
                if (name) return toRustTypeName(name);
            }
        }

        // Check the message's _json for payload information
        const messageJson = message._json || message;
        if (messageJson.payload) {
            if (messageJson.payload.$ref) {
                const refParts = messageJson.payload.$ref.split('/');
                const schemaName = refParts[refParts.length - 1];
                return toRustTypeName(schemaName);
            }
            if (messageJson.payload['x-parser-schema-id']) {
                return toRustTypeName(messageJson.payload['x-parser-schema-id']);
            }
            if (messageJson.payload.title) {
                return toRustTypeName(messageJson.payload.title);
            }
        }

        // Final fallback: try to extract from message title or name directly
        if (message.title && typeof message.title === 'function') {
            const title = message.title();
            if (title && typeof title === 'string') {
                return toRustTypeName(title);
            }
        } else if (message.title && typeof message.title === 'string') {
            return toRustTypeName(message.title);
        }

        if (message.name && typeof message.name === 'function') {
            const name = message.name();
            if (name && typeof name === 'string') {
                return toRustTypeName(name);
            }
        } else if (message.name && typeof message.name === 'string') {
            return toRustTypeName(message.name);
        }

        // Check message._json for title/name
        if (messageJson.title && typeof messageJson.title === 'string') {
            return toRustTypeName(messageJson.title);
        }
        if (messageJson.name && typeof messageJson.name === 'string') {
            return toRustTypeName(messageJson.name);
        }

        return 'UnknownPayload';
    } catch (e) {
        console.warn('Error extracting payload type name:', e.message);
        return 'UnknownPayload';
    }
}

/**
 * Analyzes operations to determine client method patterns
 * For NATS clients, we need to distinguish between:
 * - Request/Reply operations (using NATS request/reply)
 * - Publish operations (fire-and-forget)
 * - Subscribe operations (message handlers)
 *
 * @param {Array} operations - Array of AsyncAPI operations
 * @returns {Array} Array of client method patterns
 */
export function analyzeClientOperations(operations) {
    const patterns = [];

    for (const operation of operations) {
        const operationName = operation.id();
        const action = operation.action();
        const messages = operation.messages();

        if (action === 'send') {
            // Client sends messages - this becomes a client method
            if (operation.reply && operation.reply()) {
                // Request/Reply pattern
                patterns.push({
                    type: 'request_reply',
                    operation,
                    operationName,
                    methodName: toRustFieldName(operationName),
                    requestMessage: messages[0],
                    responseMessage: operation.reply().messages()[0],
                    requestType: getPayloadRustTypeName(messages[0]),
                    responseType: getPayloadRustTypeName(operation.reply().messages()[0])
                });
            } else {
                // Publish pattern (fire-and-forget)
                patterns.push({
                    type: 'publish',
                    operation,
                    operationName,
                    methodName: toRustFieldName(operationName),
                    message: messages[0],
                    payloadType: getPayloadRustTypeName(messages[0])
                });
            }
        } else if (action === 'receive') {
            // Client receives messages - this becomes a subscription method
            patterns.push({
                type: 'subscribe',
                operation,
                operationName,
                methodName: toRustFieldName(operationName.replace(/^receive/, 'subscribe_to_')),
                message: messages[0],
                payloadType: getPayloadRustTypeName(messages[0])
            });
        }
    }

    return patterns;
}

/**
 * Gets the NATS subject from a channel address
 *
 * @param {object} channel - AsyncAPI channel object
 * @returns {string} NATS subject
 */
export function getNatsSubject(channel) {
    try {
        if (channel.address && typeof channel.address === 'function') {
            return channel.address();
        } else if (channel.address) {
            return channel.address;
        } else if (channel.id && typeof channel.id === 'function') {
            return channel.id();
        } else if (channel.id) {
            return channel.id;
        }
        return 'unknown.subject';
    } catch (e) {
        return 'unknown.subject';
    }
}

/**
 * Checks if a channel address contains variables (dynamic channel)
 *
 * @param {string} address - Channel address
 * @returns {boolean} True if the address contains variables
 */
export function isDynamicChannel(address) {
    if (!address || typeof address !== 'string') return false;
    return /\{[^}]+\}/.test(address);
}

/**
 * Extracts variable names from a channel address
 *
 * @param {string} address - Channel address with variables
 * @returns {Array<string>} Array of variable names
 */
export function extractChannelVariables(address) {
    if (!address || typeof address !== 'string') return [];
    const matches = address.match(/\{([^}]+)\}/g);
    if (!matches) return [];
    return matches.map(match => match.slice(1, -1)); // Remove { and }
}

/**
 * Gets channel parameters from a channel object
 *
 * @param {object} channel - AsyncAPI channel object
 * @returns {Array<object>} Array of parameter objects with name and description
 */
export function getChannelParameters(channel) {
    try {
        const parameters = [];

        // Try to get parameters from the channel
        let channelParams = null;
        if (channel.parameters && typeof channel.parameters === 'function') {
            channelParams = channel.parameters();
        } else if (channel.parameters) {
            channelParams = channel.parameters;
        } else if (channel._json && channel._json.parameters) {
            channelParams = channel._json.parameters;
        }

        if (channelParams) {
            // Handle different parameter formats
            if (typeof channelParams === 'object') {
                for (const [paramName, paramDef] of Object.entries(channelParams)) {
                    // Skip internal AsyncAPI parser properties
                    if (paramName.startsWith('_') || paramName === 'collections' || paramName === 'meta') {
                        continue;
                    }

                    let description = 'Channel parameter';

                    if (paramDef && typeof paramDef === 'object') {
                        if (typeof paramDef.description === 'string') {
                            description = paramDef.description;
                        } else if (typeof paramDef.description === 'function') {
                            try {
                                description = paramDef.description();
                            } catch (e) {
                                description = 'Channel parameter';
                            }
                        } else if (paramDef._json && paramDef._json.description) {
                            description = paramDef._json.description;
                        }
                    } else if (typeof paramDef === 'string') {
                        description = paramDef;
                    }

                    parameters.push({
                        name: paramName,
                        description: description,
                        rustName: toRustFieldName(paramName),
                        rustType: 'String' // For now, assume all parameters are strings
                    });
                }
            }
        }

        return parameters;
    } catch (e) {
        console.warn('Error extracting channel parameters:', e.message);
        return [];
    }
}

/**
 * Resolves a dynamic channel address with provided variable values
 *
 * @param {string} address - Channel address template with variables
 * @param {object} variables - Object mapping variable names to values
 * @returns {string} Resolved channel address
 */
export function resolveChannelAddress(address, variables) {
    if (!address || typeof address !== 'string') return address;
    if (!variables || typeof variables !== 'object') return address;

    let resolved = address;
    for (const [varName, varValue] of Object.entries(variables)) {
        const placeholder = `{${varName}}`;
        resolved = resolved.replace(new RegExp(placeholder.replace(/[{}]/g, '\\$&'), 'g'), varValue);
    }

    return resolved;
}

/**
 * Checks if a channel has dynamic parameters
 *
 * @param {object} channel - AsyncAPI channel object
 * @returns {boolean} True if the channel has parameters
 */
export function channelHasParameters(channel) {
    const address = getNatsSubject(channel);
    return isDynamicChannel(address);
}

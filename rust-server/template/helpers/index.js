/**
 * Shared helper functions for Rust AsyncAPI template generation
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
 * Checks if the AsyncAPI specification has security schemes defined
 *
 * @param {object} asyncapi - AsyncAPI specification object
 * @param {boolean} enableAuth - Whether auth feature is enabled
 * @returns {boolean} True if security schemes are present and auth is enabled
 */
export function hasSecuritySchemes(asyncapi, enableAuth) {
    if (!enableAuth) return false;

    try {
        const components = asyncapi.components();
        if (!components) return false;

        const securitySchemes = components.securitySchemes();
        return securitySchemes && Object.keys(securitySchemes).length > 0;
    } catch (e) {
        return false;
    }
}

/**
 * Analyzes operation patterns to detect request/response, request-only, and send-message patterns
 *
 * @param {Array} channelOps - Array of channel operations
 * @param {string} channelName - Name of the channel
 * @returns {Array} Array of pattern objects
 */
export function analyzeOperationPattern(channelOps, _channelName) {
    const sendOps = channelOps.filter(op => op.action === 'send');
    const receiveOps = channelOps.filter(op => op.action === 'receive');

    // Look for request/response patterns
    const patterns = [];

    // Process send operations (server handles incoming requests)
    for (const sendOp of sendOps) {
        // Check if this send operation has a reply message defined
        let hasReply = false;
        let replyMessage = null;

        // Check if the send operation has a reply field (AsyncAPI 3.x)
        if (sendOp.reply) {
            hasReply = true;
            replyMessage = sendOp.reply;
        }

        if (hasReply) {
            // Request/Response pattern: server receives request and sends response
            patterns.push({
                type: 'request_response',
                operation: sendOp,
                requestMessage: sendOp.messages[0],
                responseMessage: replyMessage
            });
        } else {
            // Request-only pattern: server receives and processes request
            patterns.push({
                type: 'request_only',
                operation: sendOp,
                requestMessage: sendOp.messages[0]
            });
        }
    }

    // Process receive operations (server sends outgoing messages)
    for (const receiveOp of receiveOps) {
        patterns.push({
            type: 'send_message',
            operation: receiveOp,
            message: receiveOp.messages[0]
        });
    }

    return patterns;
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
        // First, try to get the payload from the message
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

        // Fallback: try to derive payload name from message name
        const messageName = getMessageTypeName(message);
        if (messageName) {
            // Ensure messageName is a string
            const messageNameStr = String(messageName);

            // Convert message names to payload names using common patterns
            if (messageNameStr.endsWith('Request')) {
                return toRustTypeName(messageNameStr.replace('Request', 'Payload'));
            }
            if (messageNameStr.endsWith('Response')) {
                return toRustTypeName(messageNameStr.replace('Response', 'Payload'));
            }
            if (messageNameStr.endsWith('Message')) {
                return toRustTypeName(messageNameStr.replace('Message', 'Payload'));
            }
            // If no common suffix, append 'Payload'
            return toRustTypeName(messageNameStr + 'Payload');
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
 * Gets the default port for a given protocol
 *
 * @param {string} protocol - Protocol name
 * @returns {number} Default port number
 */
export function getDefaultPort(protocol) {
    switch (protocol?.toLowerCase()) {
        case 'http':
            return 80;
        case 'https':
            return 443;
        case 'ws':
        case 'websocket':
            return 80;
        case 'wss':
        case 'websockets':
            return 443;
        case 'mqtt':
            return 1883;
        case 'mqtts':
            return 8883;
        case 'amqp':
            return 5672;
        case 'amqps':
            return 5671;
        case 'kafka':
            return 9092;
        default:
            return 8080;
    }
}

/**
 * Analyzes operation security requirements from AsyncAPI specification
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {object} Security analysis result
 */
export function analyzeOperationSecurity(operation) {
    try {
        // Check AsyncAPI security field
        const security = operation.security && operation.security();
        if (security && Array.isArray(security) && security.length > 0) {
            return {
                hasSecurityRequirements: true,
                securitySchemes: security,
                requiresAuthentication: true
            };
        }

        // Check if operation has security defined in AsyncAPI spec
        const operationJson = operation._json || operation;
        if (operationJson.security && Array.isArray(operationJson.security) && operationJson.security.length > 0) {
            return {
                hasSecurityRequirements: true,
                securitySchemes: operationJson.security,
                requiresAuthentication: true
            };
        }

        return {
            hasSecurityRequirements: false,
            securitySchemes: [],
            requiresAuthentication: false
        };
    } catch (e) {
        return {
            hasSecurityRequirements: false,
            securitySchemes: [],
            requiresAuthentication: false
        };
    }
}

/**
 * Checks if an operation has security requirements
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {boolean} True if operation has security requirements
 */
export function operationHasSecurity(operation) {
    const analysis = analyzeOperationSecurity(operation);
    return analysis.hasSecurityRequirements;
}

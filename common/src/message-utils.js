/**
 * Message processing utilities for AsyncAPI template generation
 *
 * This module provides functions for extracting and processing message information
 * from AsyncAPI specifications, handling various AsyncAPI versions and formats.
 */

import { toRustTypeName } from './string-utils.js';

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
 * Gets the TypeScript type name from a message for TypeScript templates
 *
 * @param {object} message - AsyncAPI message object
 * @returns {string} TypeScript type name
 */
export function getMessageTypeScriptTypeName(message) {
    const messageName = getMessageTypeName(message);
    if (!messageName) return 'UnknownMessage';

    // Convert to PascalCase for TypeScript interfaces
    return messageName
        .split(/[-_\s]+/)
        .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
        .join('');
}

/**
 * Gets the payload TypeScript type name from a message
 *
 * @param {object} message - AsyncAPI message object
 * @returns {string} TypeScript type name for the payload
 */
export function getPayloadTypeScriptTypeName(message) {
    if (!message) return 'unknown';

    try {
        // Similar logic to getPayloadRustTypeName but for TypeScript naming
        const messageName = getMessageTypeName(message);
        if (messageName) {
            let payload = null;
            if (message.payload && typeof message.payload === 'function') {
                payload = message.payload();
            } else if (message.payload) {
                payload = message.payload;
            }

            const messageJson = message._json || message;
            if (!payload && messageJson.payload) {
                payload = messageJson.payload;
            }

            if (payload && payload.$ref) {
                const refParts = payload.$ref.split('/');
                const schemaName = refParts[refParts.length - 1];
                return schemaName
                    .split(/[-_\s]+/)
                    .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
                    .join('');
            }

            return messageName
                .split(/[-_\s]+/)
                .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
                .join('');
        }

        return 'unknown';
    } catch (e) {
        console.warn('Error extracting TypeScript payload type name:', e.message);
        return 'unknown';
    }
}

/**
 * Checks if a message has a payload schema defined
 *
 * @param {object} message - AsyncAPI message object
 * @returns {boolean} True if message has a payload schema
 */
export function messageHasPayload(message) {
    if (!message) return false;

    try {
        // Check for payload function
        if (message.payload && typeof message.payload === 'function') {
            const payload = message.payload();
            return payload !== null && payload !== undefined;
        }

        // Check for payload property
        if (message.payload) {
            return true;
        }

        // Check _json for payload
        const messageJson = message._json || message;
        return !!(messageJson.payload);
    } catch (e) {
        return false;
    }
}

/**
 * Gets the content type of a message
 *
 * @param {object} message - AsyncAPI message object
 * @returns {string} Content type (e.g., 'application/json')
 */
export function getMessageContentType(message) {
    if (!message) return 'application/json';

    try {
        // Check for contentType function
        if (message.contentType && typeof message.contentType === 'function') {
            return message.contentType() || 'application/json';
        }

        // Check for contentType property
        if (message.contentType) {
            return message.contentType;
        }

        // Check _json for contentType
        const messageJson = message._json || message;
        if (messageJson.contentType) {
            return messageJson.contentType;
        }

        return 'application/json';
    } catch (e) {
        return 'application/json';
    }
}

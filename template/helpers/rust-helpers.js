/**
 * Rust-specific helper functions for AsyncAPI template generation
 */

/**
 * Converts a string to a valid Rust identifier
 * @param {string} str - The string to convert
 * @returns {string} - A valid Rust identifier
 */
function toRustIdentifier(str) {
    if (!str) return 'unknown';

    // Replace invalid characters with underscores
    let identifier = str
        .replace(/[^a-zA-Z0-9_]/g, '_')
        .replace(/^[0-9]/, '_$&') // Prefix numbers with underscore
        .replace(/_+/g, '_') // Collapse multiple underscores
        .replace(/^_+|_+$/g, ''); // Remove leading/trailing underscores

    // Ensure it doesn't start with a number
    if (/^[0-9]/.test(identifier)) {
        identifier = 'item_' + identifier;
    }

    // Ensure it's not empty
    if (!identifier) {
        identifier = 'unknown';
    }

    // Avoid Rust keywords
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
 * Converts a string to a valid Rust type name (PascalCase)
 * @param {string} str - The string to convert
 * @returns {string} - A valid Rust type name
 */
function toRustTypeName(str) {
    if (!str) return 'Unknown';

    const identifier = toRustIdentifier(str);

    // Convert to PascalCase
    return identifier
        .split('_')
        .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
        .join('');
}

/**
 * Converts a string to a valid Rust field name (snake_case)
 * @param {string} str - The string to convert
 * @returns {string} - A valid Rust field name
 */
function toRustFieldName(str) {
    if (!str) return 'unknown';

    const identifier = toRustIdentifier(str);

    // Convert to snake_case
    return identifier
        .replace(/([A-Z])/g, '_$1')
        .toLowerCase()
        .replace(/^_/, '')
        .replace(/_+/g, '_');
}

/**
 * Converts a string to a valid Rust module name (snake_case)
 * @param {string} str - The string to convert
 * @returns {string} - A valid Rust module name
 */
function toRustModuleName(str) {
    return toRustFieldName(str);
}

/**
 * Gets the Rust type for a JSON Schema type
 * @param {object} schema - The JSON Schema
 * @returns {string} - The corresponding Rust type
 */
function getRustType(schema) {
    if (!schema) return 'serde_json::Value';

    const type = schema.type && schema.type();

    switch (type) {
    case 'string':
        return 'String';
    case 'integer':
        return 'i64';
    case 'number':
        return 'f64';
    case 'boolean':
        return 'bool';
    case 'array': {
        const items = schema.items && schema.items();
        if (items) {
            return `Vec<${getRustType(items)}>`;
        }
        return 'Vec<serde_json::Value>';
    }
    case 'object':
        return 'serde_json::Value'; // For now, use generic JSON value
    default:
        return 'serde_json::Value';
    }
}

/**
 * Gets the default port for a protocol
 * @param {string} protocol - The protocol name
 * @returns {number} - The default port
 */
function getDefaultPort(protocol) {
    switch (protocol?.toLowerCase()) {
    case 'mqtt':
    case 'mqtts':
        return 1883;
    case 'kafka':
    case 'kafka-secure':
        return 9092;
    case 'amqp':
    case 'amqps':
        return 5672;
    case 'ws':
    case 'wss':
        return 8080;
    case 'http':
        return 80;
    case 'https':
        return 443;
    default:
        return 8080;
    }
}

module.exports = {
    toRustIdentifier,
    toRustTypeName,
    toRustFieldName,
    toRustModuleName,
    getRustType,
    getDefaultPort
};

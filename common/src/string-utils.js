/**
 * String conversion utilities for AsyncAPI template generation
 *
 * This module provides consistent string conversion functions used across
 * multiple AsyncAPI templates to ensure naming conventions are standardized.
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
 * Converts a string to kebab-case
 * Useful for package names and file names
 *
 * @param {string} str - Input string to convert
 * @returns {string} kebab-case string
 */
export function toKebabCase(str) {
    if (!str) return '';
    return str.toLowerCase().replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
}

/**
 * Converts a string to PascalCase
 * Useful for class names and type names
 *
 * @param {string} str - Input string to convert
 * @returns {string} PascalCase string
 */
export function toPascalCase(str) {
    if (!str) return '';
    return str.replace(/[^a-zA-Z0-9]/g, ' ')
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join('');
}

/**
 * Converts a string to snake_case
 * Useful for Rust identifiers and file names
 *
 * @param {string} str - Input string to convert
 * @returns {string} snake_case string
 */
export function toSnakeCase(str) {
    if (!str) return '';
    return str.toLowerCase().replace(/[^a-z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '');
}

/**
 * Converts a string to camelCase
 * Useful for JavaScript/TypeScript identifiers
 *
 * @param {string} str - Input string to convert
 * @returns {string} camelCase string
 */
export function toCamelCase(str) {
    if (!str) return '';
    const pascalCase = toPascalCase(str);
    return pascalCase.charAt(0).toLowerCase() + pascalCase.slice(1);
}

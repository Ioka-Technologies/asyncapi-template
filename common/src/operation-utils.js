/**
 * Operation processing utilities for AsyncAPI template generation
 *
 * This module provides functions for extracting and processing operation information
 * from AsyncAPI specifications, handling different operation types and patterns.
 */

import { toRustIdentifier, toPascalCase } from './string-utils.js';

/**
 * Gets the operation name from an operation object
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {string|null} Operation name or null if not found
 */
export function getOperationName(operation) {
    if (!operation) return null;

    try {
        // Try AsyncAPI 3.x format first - check _meta and _json properties
        if (operation._meta && operation._meta.id) {
            return operation._meta.id;
        }
        if (operation._json && operation._json['x-parser-operation-id']) {
            return operation._json['x-parser-operation-id'];
        }

        // Try different ways to get the operation name
        if (operation.id && typeof operation.id === 'function') {
            return operation.id();
        }
        if (operation.id && typeof operation.id === 'string') {
            return operation.id;
        }
        if (operation.operationId && typeof operation.operationId === 'function') {
            return operation.operationId();
        }
        if (operation.operationId && typeof operation.operationId === 'string') {
            return operation.operationId;
        }

        return null;
    } catch (e) {
        return null;
    }
}

/**
 * Gets the operation action (send/receive/publish/subscribe)
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {string} Operation action
 */
export function getOperationAction(operation) {
    if (!operation) return 'unknown';

    try {
        if (operation.action && typeof operation.action === 'function') {
            return operation.action();
        }
        if (operation.action && typeof operation.action === 'string') {
            return operation.action;
        }
        if (operation._json && operation._json.action) {
            return operation._json.action;
        }

        // Fallback based on operation type
        if (operation.isSend && typeof operation.isSend === 'function' && operation.isSend()) {
            return 'send';
        }
        if (operation.isReceive && typeof operation.isReceive === 'function' && operation.isReceive()) {
            return 'receive';
        }

        return 'unknown';
    } catch (e) {
        return 'unknown';
    }
}

/**
 * Gets the channel associated with an operation
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {object|null} Channel object or null if not found
 */
export function getOperationChannel(operation) {
    if (!operation) return null;

    try {
        if (operation.channel && typeof operation.channel === 'function') {
            return operation.channel();
        }
        if (operation.channel && typeof operation.channel === 'object') {
            return operation.channel;
        }

        return null;
    } catch (e) {
        return null;
    }
}

/**
 * Gets the messages associated with an operation
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {Array} Array of message objects
 */
export function getOperationMessages(operation) {
    if (!operation) return [];

    try {
        const messages = [];

        // Try to get messages from the operation
        if (operation.messages && typeof operation.messages === 'function') {
            const operationMessages = operation.messages();
            if (operationMessages && Array.isArray(operationMessages)) {
                messages.push(...operationMessages);
            } else if (operationMessages && typeof operationMessages === 'object') {
                // Handle collection object
                if (operationMessages.all && typeof operationMessages.all === 'function') {
                    messages.push(...operationMessages.all());
                } else {
                    messages.push(...Object.values(operationMessages));
                }
            }
        } else if (operation.messages && Array.isArray(operation.messages)) {
            messages.push(...operation.messages);
        }

        // Try to get message from _json
        if (messages.length === 0 && operation._json && operation._json.message) {
            if (Array.isArray(operation._json.message)) {
                messages.push(...operation._json.message);
            } else {
                messages.push(operation._json.message);
            }
        }

        return messages;
    } catch (e) {
        return [];
    }
}

/**
 * Checks if an operation is a send operation
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {boolean} True if operation is a send operation
 */
export function isOperationSend(operation) {
    const action = getOperationAction(operation);
    return action === 'send' || action === 'publish';
}

/**
 * Checks if an operation is a receive operation
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {boolean} True if operation is a receive operation
 */
export function isOperationReceive(operation) {
    const action = getOperationAction(operation);
    return action === 'receive' || action === 'subscribe';
}

/**
 * Gets the Rust function name for an operation
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {string} Rust function name
 */
export function getOperationRustFunctionName(operation) {
    const operationName = getOperationName(operation);
    if (!operationName) return 'unknown_operation';

    return toRustIdentifier(operationName);
}

/**
 * Gets the TypeScript method name for an operation
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {string} TypeScript method name
 */
export function getOperationTypeScriptMethodName(operation) {
    const operationName = getOperationName(operation);
    if (!operationName) return 'unknownOperation';

    // Convert to camelCase for TypeScript
    return operationName
        .split(/[-_\s]+/)
        .map((part, index) => {
            if (index === 0) {
                return part.toLowerCase();
            }
            return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase();
        })
        .join('');
}

/**
 * Gets the operation description
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {string} Operation description
 */
export function getOperationDescription(operation) {
    if (!operation) return '';

    try {
        if (operation.description && typeof operation.description === 'function') {
            return operation.description() || '';
        }
        if (operation.description && typeof operation.description === 'string') {
            return operation.description;
        }
        if (operation._json && operation._json.description) {
            return operation._json.description;
        }

        return '';
    } catch (e) {
        return '';
    }
}

/**
 * Gets the operation summary
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {string} Operation summary
 */
export function getOperationSummary(operation) {
    if (!operation) return '';

    try {
        if (operation.summary && typeof operation.summary === 'function') {
            return operation.summary() || '';
        }
        if (operation.summary && typeof operation.summary === 'string') {
            return operation.summary;
        }
        if (operation._json && operation._json.summary) {
            return operation._json.summary;
        }

        return '';
    } catch (e) {
        return '';
    }
}

/**
 * Extracts all operations from an AsyncAPI specification
 *
 * @param {object} asyncapi - AsyncAPI specification object
 * @returns {Array} Array of operation objects with metadata
 */
export function extractAllOperations(asyncapi) {
    const operations = [];

    try {
        const asyncApiOperations = asyncapi.operations && asyncapi.operations();
        if (asyncApiOperations) {
            // Handle AsyncAPI parser collection - use .all() method to get array
            const operationArray = asyncApiOperations.all ? asyncApiOperations.all() : Object.values(asyncApiOperations);

            operationArray.forEach((operation) => {
                const operationName = getOperationName(operation);
                if (operationName) {
                    const channel = getOperationChannel(operation);
                    const messages = getOperationMessages(operation);

                    operations.push({
                        name: operationName,
                        operation: operation,
                        action: getOperationAction(operation),
                        channel: channel,
                        messages: messages,
                        description: getOperationDescription(operation),
                        summary: getOperationSummary(operation),
                        rustFunctionName: getOperationRustFunctionName(operation),
                        typeScriptMethodName: getOperationTypeScriptMethodName(operation),
                        isSend: isOperationSend(operation),
                        isReceive: isOperationReceive(operation)
                    });
                }
            });
        }
    } catch (e) {
        console.warn('Error extracting operations:', e.message);
    }

    return operations;
}

/**
 * Groups operations by their action type
 *
 * @param {Array} operations - Array of operation objects
 * @returns {object} Object with send and receive operation arrays
 */
export function groupOperationsByAction(operations) {
    const grouped = {
        send: [],
        receive: [],
        publish: [],
        subscribe: [],
        unknown: []
    };

    operations.forEach(operation => {
        const action = operation.action || 'unknown';
        if (grouped[action]) {
            grouped[action].push(operation);
        } else {
            grouped.unknown.push(operation);
        }
    });

    return grouped;
}

/**
 * Gets the operation trait information
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {Array} Array of trait objects
 */
export function getOperationTraits(operation) {
    if (!operation) return [];

    try {
        const traits = [];

        if (operation.traits && typeof operation.traits === 'function') {
            const operationTraits = operation.traits();
            if (operationTraits && Array.isArray(operationTraits)) {
                traits.push(...operationTraits);
            }
        } else if (operation.traits && Array.isArray(operation.traits)) {
            traits.push(...operation.traits);
        }

        // Try to get traits from _json
        if (traits.length === 0 && operation._json && operation._json.traits) {
            if (Array.isArray(operation._json.traits)) {
                traits.push(...operation._json.traits);
            }
        }

        return traits;
    } catch (e) {
        return [];
    }
}

/**
 * Checks if an operation has any traits defined
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {boolean} True if operation has traits
 */
export function operationHasTraits(operation) {
    const traits = getOperationTraits(operation);
    return traits.length > 0;
}

/**
 * Gets the operation tags
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {Array} Array of tag objects
 */
export function getOperationTags(operation) {
    if (!operation) return [];

    try {
        const tags = [];

        if (operation.tags && typeof operation.tags === 'function') {
            const operationTags = operation.tags();
            if (operationTags && Array.isArray(operationTags)) {
                tags.push(...operationTags);
            }
        } else if (operation.tags && Array.isArray(operation.tags)) {
            tags.push(...operation.tags);
        }

        // Try to get tags from _json
        if (tags.length === 0 && operation._json && operation._json.tags) {
            if (Array.isArray(operation._json.tags)) {
                tags.push(...operation._json.tags);
            }
        }

        return tags;
    } catch (e) {
        return [];
    }
}

/**
 * Generates operation handler name for server templates
 *
 * @param {object} operation - AsyncAPI operation object
 * @param {string} suffix - Optional suffix to add to handler name
 * @returns {string} Handler function name
 */
export function generateOperationHandlerName(operation, suffix = 'Handler') {
    const operationName = getOperationName(operation);
    if (!operationName) return `unknown${suffix}`;

    const pascalCaseName = toPascalCase(operationName);
    return `${pascalCaseName}${suffix}`;
}

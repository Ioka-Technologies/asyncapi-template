/**
 * Template-specific helper functions for Rust client template
 *
 * Most common utilities have been moved to the shared @common package.
 * This file now only contains template-specific functions that are unique
 * to the rust-client template.
 */

// Import common utilities for use in local functions
import {
    toRustIdentifier,
    toRustTypeName,
    toRustFieldName,
    toRustEnumVariant,
    toRustEnumVariantWithSerde,
    getMessageTypeName,
    getMessageRustTypeName,
    getPayloadRustTypeName,
    getNatsSubject,
    isDynamicChannel,
    extractChannelVariables,
    getChannelParameters,
    resolveChannelAddress,
    channelHasParameters,
    toPascalCase,
    toKebabCase,
    toSnakeCase,
    isTemplateVariable,
    extractAsyncApiInfo,
    resolveTemplateParameters
} from '../../../common/src/index.js';

// Re-export common utilities for backward compatibility
export {
    toRustIdentifier,
    toRustTypeName,
    toRustFieldName,
    toRustEnumVariant,
    toRustEnumVariantWithSerde,
    getMessageTypeName,
    getMessageRustTypeName,
    getPayloadRustTypeName,
    getNatsSubject,
    isDynamicChannel,
    extractChannelVariables,
    getChannelParameters,
    resolveChannelAddress,
    channelHasParameters,
    toPascalCase,
    toKebabCase,
    toSnakeCase,
    isTemplateVariable,
    extractAsyncApiInfo,
    resolveTemplateParameters
};

/**
 * Analyzes operations to determine client method patterns
 * For NATS clients, we need to distinguish between:
 * - Request/Reply operations (using NATS request/reply)
 * - Publish operations (fire-and-forget)
 * - Subscribe operations (message handlers)
 *
 * This function is specific to the rust-client template's operation analysis needs.
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

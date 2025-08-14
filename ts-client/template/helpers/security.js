/**
 * Security analysis helper functions for TypeScript client template
 * Most common security utilities have been moved to the shared @common package.
 */

import {
    analyzeOperationSecurity,
    operationHasSecurity,
    hasSecuritySchemes
} from '../../../common/src/index.js';

/**
 * Get security scheme type from AsyncAPI security scheme definition
 *
 * @param {object} securityScheme - AsyncAPI security scheme object
 * @returns {string} Security scheme type ('jwt', 'basic', 'apikey', etc.)
 */
function getSecuritySchemeType(securityScheme) {
    try {
        if (securityScheme.type && typeof securityScheme.type === 'function') {
            return securityScheme.type();
        }
        if (securityScheme.type) {
            return securityScheme.type;
        }
        if (securityScheme._json && securityScheme._json.type) {
            return securityScheme._json.type;
        }
        return 'unknown';
    } catch (e) {
        return 'unknown';
    }
}

/**
 * Extract security requirements for all operations in the AsyncAPI spec
 *
 * @param {object} asyncapi - AsyncAPI specification object
 * @returns {object} Map of operation names to their security requirements
 */
function extractOperationSecurityMap(asyncapi) {
    const securityMap = {};

    try {
        const operations = asyncapi.operations && asyncapi.operations();
        if (operations) {
            // Handle AsyncAPI parser collection - use .all() method to get array
            const operationArray = operations.all ? operations.all() : Object.values(operations);

            operationArray.forEach((operation) => {
                // Get operation ID
                let operationId = null;
                if (operation._meta && operation._meta.id) {
                    operationId = operation._meta.id;
                } else if (operation.id && typeof operation.id === 'function') {
                    operationId = operation.id();
                } else if (operation.id) {
                    operationId = operation.id;
                }

                if (operationId) {
                    const securityAnalysis = analyzeOperationSecurity(operation);
                    securityMap[operationId] = securityAnalysis;
                }
            });
        }
    } catch (e) {
        console.warn('Error extracting operation security map:', e.message);
    }

    return securityMap;
}

// Export all functions
export {
    // Re-export common security utilities for backward compatibility
    analyzeOperationSecurity,
    operationHasSecurity as operationRequiresAuth,
    hasSecuritySchemes,

    // TypeScript client specific functions
    getSecuritySchemeType,
    extractOperationSecurityMap
};

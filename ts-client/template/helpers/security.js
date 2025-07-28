/**
 * Security analysis helper functions for TypeScript client template
 * Adapted from rust-server template helpers
 */

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
export function operationRequiresAuth(operation) {
    const analysis = analyzeOperationSecurity(operation);
    return analysis.hasSecurityRequirements;
}

/**
 * Checks if the AsyncAPI specification has security schemes defined
 *
 * @param {object} asyncapi - AsyncAPI specification object
 * @returns {boolean} True if security schemes are present
 */
export function hasSecuritySchemes(asyncapi) {
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
 * Get security scheme type from AsyncAPI security scheme definition
 *
 * @param {object} securityScheme - AsyncAPI security scheme object
 * @returns {string} Security scheme type ('jwt', 'basic', 'apikey', etc.)
 */
export function getSecuritySchemeType(securityScheme) {
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
export function extractOperationSecurityMap(asyncapi) {
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

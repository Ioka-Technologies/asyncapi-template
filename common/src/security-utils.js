/**
 * Security analysis utilities for AsyncAPI template generation
 *
 * This module provides functions for analyzing security requirements and
 * authentication schemes across different AsyncAPI templates.
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
export function operationHasSecurity(operation) {
    const analysis = analyzeOperationSecurity(operation);
    return analysis.hasSecurityRequirements;
}

/**
 * Alias for operationHasSecurity for TypeScript templates
 *
 * @param {object} operation - AsyncAPI operation object
 * @returns {boolean} True if operation requires authentication
 */
export function operationRequiresAuth(operation) {
    return operationHasSecurity(operation);
}

/**
 * Checks if the AsyncAPI specification has security schemes defined
 *
 * @param {object} asyncapi - AsyncAPI specification object
 * @param {boolean} enableAuth - Whether auth feature is enabled (optional, defaults to true)
 * @returns {boolean} True if security schemes are present and auth is enabled
 */
export function hasSecuritySchemes(asyncapi, enableAuth = true) {
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
 * Gets the security scheme name from a security scheme object
 *
 * @param {object} securityScheme - AsyncAPI security scheme object
 * @returns {string} Security scheme name
 */
export function getSecuritySchemeName(securityScheme) {
    try {
        if (securityScheme.name && typeof securityScheme.name === 'function') {
            return securityScheme.name();
        }
        if (securityScheme.name) {
            return securityScheme.name;
        }
        if (securityScheme._json && securityScheme._json.name) {
            return securityScheme._json.name;
        }
        return 'unknown';
    } catch (e) {
        return 'unknown';
    }
}

/**
 * Gets the security scheme location (header, query, cookie) for API key schemes
 *
 * @param {object} securityScheme - AsyncAPI security scheme object
 * @returns {string} Security scheme location ('header', 'query', 'cookie')
 */
export function getSecuritySchemeLocation(securityScheme) {
    try {
        if (securityScheme.in && typeof securityScheme.in === 'function') {
            return securityScheme.in();
        }
        if (securityScheme.in) {
            return securityScheme.in;
        }
        if (securityScheme._json && securityScheme._json.in) {
            return securityScheme._json.in;
        }
        return 'header'; // Default to header
    } catch (e) {
        return 'header';
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

/**
 * Gets all security schemes from the AsyncAPI specification
 *
 * @param {object} asyncapi - AsyncAPI specification object
 * @returns {object} Map of security scheme names to their definitions
 */
export function getAllSecuritySchemes(asyncapi) {
    try {
        const components = asyncapi.components();
        if (!components) return {};

        const securitySchemes = components.securitySchemes();
        if (!securitySchemes) return {};

        // Convert to plain object if it's a collection
        if (typeof securitySchemes === 'object' && securitySchemes.all) {
            const schemes = {};
            const schemeArray = securitySchemes.all();
            schemeArray.forEach(scheme => {
                const name = scheme.id ? scheme.id() : 'unknown';
                schemes[name] = scheme;
            });
            return schemes;
        }

        return securitySchemes;
    } catch (e) {
        console.warn('Error extracting security schemes:', e.message);
        return {};
    }
}

/**
 * Checks if a security scheme is of a specific type
 *
 * @param {object} securityScheme - AsyncAPI security scheme object
 * @param {string} expectedType - Expected security scheme type
 * @returns {boolean} True if the scheme matches the expected type
 */
export function isSecuritySchemeType(securityScheme, expectedType) {
    const actualType = getSecuritySchemeType(securityScheme);
    return actualType.toLowerCase() === expectedType.toLowerCase();
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
    case 'nats':
        return 4222;
    default:
        return 8080;
    }
}

/**
 * Validates that all server references in channels exist in the servers section
 *
 * @param {object} asyncapi - AsyncAPI specification object
 * @returns {object} Validation result with errors if any
 */
export function validateChannelServerReferences(asyncapi) {
    const result = {
        valid: true,
        errors: []
    };

    try {
        // Try multiple ways to get servers
        let servers = null;
        let serverNames = [];

        // Method 1: Try asyncapi.servers() function
        if (asyncapi.servers && typeof asyncapi.servers === 'function') {
            try {
                servers = asyncapi.servers();
                if (servers) {
                    // Check if this is a collection object (has iterator methods)
                    if (typeof servers[Symbol.iterator] === 'function') {
                        // It's iterable - iterate through the servers
                        serverNames = [];
                        for (const server of servers) {
                            const serverName = server.id && typeof server.id === 'function' ? server.id() : server.id;
                            if (serverName) {
                                serverNames.push(serverName);
                            }
                        }
                    } else {
                        // It's a plain object - use Object.keys
                        serverNames = Object.keys(servers);
                    }
                }
            } catch (e) {
                // Ignore and try other methods
            }
        }

        // Method 2: Try asyncapi._json.servers (raw JSON data)
        if (serverNames.length === 0 && asyncapi._json && asyncapi._json.servers) {
            servers = asyncapi._json.servers;
            serverNames = Object.keys(servers);
        }

        // Method 3: Try direct property access
        if (serverNames.length === 0 && asyncapi.servers && typeof asyncapi.servers === 'object') {
            servers = asyncapi.servers;
            serverNames = Object.keys(servers);
        }

        // Method 4: Try json() method if available
        if (serverNames.length === 0 && asyncapi.json && typeof asyncapi.json === 'function') {
            try {
                const jsonDoc = asyncapi.json();
                if (jsonDoc && jsonDoc.servers) {
                    servers = jsonDoc.servers;
                    serverNames = Object.keys(servers);
                }
            } catch (e) {
                // Ignore and try other methods
            }
        }

        // Note: We'll skip channel validation here to avoid circular dependency
        // This function can be enhanced later if needed
        console.warn('Channel server validation skipped to avoid circular dependency');

    } catch (e) {
        result.valid = false;
        result.errors.push({
            message: `Error validating channel server references: ${e.message}`
        });
    }

    return result;
}

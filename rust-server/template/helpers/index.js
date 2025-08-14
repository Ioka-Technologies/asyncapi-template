/**
 * Template-specific helper functions for Rust server template
 *
 * Most common utilities have been moved to the shared @common package.
 * This file now only contains template-specific functions that are unique
 * to the rust-server template.
 */

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
} from '../../../common/src/index.js';

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
 * This is specific to server-side operation analysis.
 *
 * @param {Array} channelOps - Array of channel operations
 * @param {string} channelName - Name of the channel
 * @param {string} originalChannelAddress - Original channel address with dynamic parameters
 * @returns {Array} Array of pattern objects
 */
export function analyzeOperationPattern(channelOps, channelName, originalChannelAddress = null) {
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
            message: receiveOp.messages[0],
            channelName: channelName,
            originalChannelAddress: originalChannelAddress || channelName, // Preserve original dynamic channel address
            channelFieldName: toRustFieldName(channelName),
            publisherName: toRustTypeName(channelName + '_channel_publisher'),
            publisherMethodName: toRustFieldName(receiveOp.name.replace(/^publish/, 'publish_')),
            payloadType: getPayloadRustTypeName(receiveOp.messages[0])
        });
    }

    return patterns;
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

/**
 * Groups publisher operations by channel for channel-based publisher organization
 *
 * @param {Array} allPatterns - Array of all operation patterns from all channels
 * @returns {Array} Array of channel publisher objects
 */
export function groupPublishersByChannel(allPatterns) {
    // Filter to only send_message patterns (receive operations)
    const publisherPatterns = allPatterns.filter(pattern => pattern.type === 'send_message');

    // Group by channel
    const channelGroups = {};

    for (const pattern of publisherPatterns) {
        const channelName = pattern.channelName;
        if (!channelGroups[channelName]) {
            channelGroups[channelName] = {
                channelName: channelName,
                originalChannelAddress: pattern.originalChannelAddress, // Preserve original dynamic channel address
                channelFieldName: pattern.channelFieldName,
                publisherName: pattern.publisherName,
                operations: []
            };
        }

        channelGroups[channelName].operations.push({
            operationName: pattern.operation.name,
            methodName: pattern.publisherMethodName,
            payloadType: pattern.payloadType,
            operation: pattern.operation,
            message: pattern.message,
            originalChannelAddress: pattern.originalChannelAddress // Pass through to operations
        });
    }

    // Convert to array and sort by channel name for consistent output
    return Object.values(channelGroups).sort((a, b) => a.channelName.localeCompare(b.channelName));
}

/**
 * Extracts server name from a $ref string
 *
 * @param {string} serverRef - Server reference like "#/servers/mqtt-server"
 * @returns {string|null} Server name or null if invalid
 */
export function extractServerNameFromRef(serverRef) {
    if (!serverRef || typeof serverRef !== 'string') return null;

    // Handle $ref format: "#/servers/server-name"
    const refMatch = serverRef.match(/^#\/servers\/(.+)$/);
    if (refMatch) {
        return refMatch[1];
    }

    return null;
}

/**
 * Analyzes channel server restrictions from AsyncAPI specification
 *
 * @param {object} asyncapi - AsyncAPI specification object
 * @returns {Array} Array of channel server mapping objects
 */
export function analyzeChannelServerMappings(asyncapi) {
    const mappings = [];

    try {
        const channels = asyncapi.channels();
        if (!channels) return mappings;

        for (const channel of channels) {
            const channelName = channel.id();
            let allowedServers = null; // null means available on all servers

            // Try to get servers from the channel object
            let channelServers = null;

            // Method 1: Try channel.servers() function
            if (channel.servers && typeof channel.servers === 'function') {
                try {
                    channelServers = channel.servers();
                } catch (e) {
                    // Ignore errors and try other methods
                }
            }

            // Method 2: Try channel._json.servers (raw JSON data)
            if (!channelServers && channel._json && channel._json.servers) {
                channelServers = channel._json.servers;
            }

            // Method 3: Try direct property access
            if (!channelServers && channel.servers && Array.isArray(channel.servers)) {
                channelServers = channel.servers;
            }

            if (channelServers && Array.isArray(channelServers) && channelServers.length > 0) {
                // Extract server names from $ref strings
                allowedServers = [];
                for (const serverRef of channelServers) {
                    let serverName = null;

                    // Handle different ways the server reference might be provided
                    if (typeof serverRef === 'string') {
                        serverName = extractServerNameFromRef(serverRef);
                    } else if (serverRef && serverRef.$ref) {
                        serverName = extractServerNameFromRef(serverRef.$ref);
                    } else if (serverRef && typeof serverRef.id === 'function') {
                        serverName = serverRef.id();
                    } else if (serverRef && typeof serverRef.id === 'string') {
                        serverName = serverRef.id;
                    }

                    if (serverName) {
                        allowedServers.push(serverName);
                    }
                }

                // If no valid server names were extracted, treat as available on all servers
                if (allowedServers.length === 0) {
                    allowedServers = null;
                }
            }

            mappings.push({
                channelName: channelName,
                allowedServers: allowedServers,
                rustChannelName: toRustIdentifier(channelName),
                description: channel.description && channel.description() || ''
            });
        }
    } catch (e) {
        console.warn('Error analyzing channel server mappings:', e.message);
    }

    return mappings;
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

        const channelMappings = analyzeChannelServerMappings(asyncapi);

        for (const mapping of channelMappings) {
            if (mapping.allowedServers) {
                for (const serverName of mapping.allowedServers) {
                    if (!serverNames.includes(serverName)) {
                        result.valid = false;
                        result.errors.push({
                            channel: mapping.channelName,
                            invalidServer: serverName,
                            message: `Channel '${mapping.channelName}' references server '${serverName}' which does not exist in the servers section`
                        });
                    }
                }
            }
        }
    } catch (e) {
        result.valid = false;
        result.errors.push({
            message: `Error validating channel server references: ${e.message}`
        });
    }

    return result;
}

/**
 * Checks if a channel is allowed on a specific server
 *
 * @param {string} channelName - Name of the channel
 * @param {string} serverName - Name of the server
 * @param {Array} channelMappings - Array of channel server mappings
 * @returns {boolean} True if channel is allowed on the server
 */
export function isChannelAllowedOnServer(channelName, serverName, channelMappings) {
    const mapping = channelMappings.find(m => m.channelName === channelName);
    if (!mapping) {
        // If no mapping found, assume channel is allowed on all servers
        return true;
    }

    // If allowedServers is null, channel is available on all servers
    if (mapping.allowedServers === null) {
        return true;
    }

    // Check if server is in the allowed list
    return mapping.allowedServers.includes(serverName);
}

/**
 * Extracts channel parameters from a dynamic channel address
 *
 * @param {string} channelAddress - Channel address like "device.{device_id}" or "user.{user_id}.notifications"
 * @returns {Array} Array of parameter objects with name and rustName
 */
export function extractChannelParameters(channelAddress) {
    if (!channelAddress) return [];

    const parameterRegex = /\{([^}]+)\}/g;
    const parameters = [];
    let match;

    while ((match = parameterRegex.exec(channelAddress)) !== null) {
        const paramName = match[1];
        parameters.push({
            name: paramName,
            rustName: toRustFieldName(paramName),
            placeholder: match[0] // The full {param_name} string
        });
    }

    return parameters;
}

/**
 * Generates Rust function parameters for dynamic channel parameters
 *
 * @param {Array} channelParameters - Array of channel parameter objects
 * @returns {string} Rust function parameter string
 */
export function generateChannelParameterArgs(channelParameters) {
    if (!channelParameters || channelParameters.length === 0) {
        return '';
    }

    return channelParameters.map(param =>
        `${param.rustName}: String`
    ).join(', ') + ', ';
}

/**
 * Generates Rust format string and arguments for dynamic channel resolution
 *
 * @param {string} channelAddress - Original channel address with parameters
 * @param {Array} channelParameters - Array of channel parameter objects
 * @returns {object} Object with formatString and formatArgs
 */
export function generateChannelFormatting(channelAddress, channelParameters) {
    if (!channelParameters || channelParameters.length === 0) {
        return {
            formatString: `"${channelAddress}".to_string()`,
            formatArgs: ''
        };
    }

    // Replace parameter placeholders with format placeholders
    let formatString = channelAddress;
    const formatArgs = [];

    for (const param of channelParameters) {
        formatString = formatString.replace(param.placeholder, '{}');
        formatArgs.push(param.rustName);
    }

    return {
        formatString: `format!("${formatString}", ${formatArgs.join(', ')})`,
        formatArgs: formatArgs.join(', ')
    };
}

// Import the common utilities we need for the server-specific functions
import { toRustFieldName, toRustTypeName, toRustIdentifier, getPayloadRustTypeName } from '../../../common/src/index.js';

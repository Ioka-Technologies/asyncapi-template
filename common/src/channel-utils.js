/**
 * Channel processing utilities for AsyncAPI template generation
 *
 * This module provides functions for handling channels, parameters, and
 * dynamic channel address resolution across different AsyncAPI templates.
 */

import { toRustFieldName, toRustIdentifier } from './string-utils.js';

/**
 * Gets the NATS subject from a channel address
 *
 * @param {object} channel - AsyncAPI channel object
 * @returns {string} NATS subject
 */
export function getNatsSubject(channel) {
    try {
        if (channel.address && typeof channel.address === 'function') {
            return channel.address();
        } else if (channel.address) {
            return channel.address;
        } else if (channel.id && typeof channel.id === 'function') {
            return channel.id();
        } else if (channel.id) {
            return channel.id;
        }
        return 'unknown.subject';
    } catch (e) {
        return 'unknown.subject';
    }
}

/**
 * Gets the channel address from a channel object
 * This is a more generic version of getNatsSubject that works for any protocol
 *
 * @param {object} channel - AsyncAPI channel object
 * @returns {string} Channel address
 */
export function getChannelAddress(channel) {
    try {
        if (channel.address && typeof channel.address === 'function') {
            return channel.address();
        } else if (channel.address) {
            return channel.address;
        } else if (channel.id && typeof channel.id === 'function') {
            return channel.id();
        } else if (channel.id) {
            return channel.id;
        }
        return 'unknown.address';
    } catch (e) {
        return 'unknown.address';
    }
}

/**
 * Checks if a channel address contains variables (dynamic channel)
 *
 * @param {string} address - Channel address
 * @returns {boolean} True if the address contains variables
 */
export function isDynamicChannel(address) {
    if (!address || typeof address !== 'string') return false;
    return /\{[^}]+\}/.test(address);
}

/**
 * Extracts variable names from a channel address
 *
 * @param {string} address - Channel address with variables
 * @returns {Array<string>} Array of variable names
 */
export function extractChannelVariables(address) {
    if (!address || typeof address !== 'string') return [];
    const matches = address.match(/\{([^}]+)\}/g);
    if (!matches) return [];
    return matches.map(match => match.slice(1, -1)); // Remove { and }
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
 * Gets channel parameters from a channel object
 *
 * @param {object} channel - AsyncAPI channel object
 * @returns {Array<object>} Array of parameter objects with name and description
 */
export function getChannelParameters(channel) {
    try {
        const parameters = [];

        // Try to get parameters from the channel
        let channelParams = null;
        if (channel.parameters && typeof channel.parameters === 'function') {
            channelParams = channel.parameters();
        } else if (channel.parameters) {
            channelParams = channel.parameters;
        } else if (channel._json && channel._json.parameters) {
            channelParams = channel._json.parameters;
        }

        if (channelParams) {
            // Handle different parameter formats
            if (typeof channelParams === 'object') {
                for (const [paramName, paramDef] of Object.entries(channelParams)) {
                    // Skip internal AsyncAPI parser properties
                    if (paramName.startsWith('_') || paramName === 'collections' || paramName === 'meta') {
                        continue;
                    }

                    let description = 'Channel parameter';

                    if (paramDef && typeof paramDef === 'object') {
                        if (typeof paramDef.description === 'string') {
                            description = paramDef.description;
                        } else if (typeof paramDef.description === 'function') {
                            try {
                                description = paramDef.description();
                            } catch (e) {
                                description = 'Channel parameter';
                            }
                        } else if (paramDef._json && paramDef._json.description) {
                            description = paramDef._json.description;
                        }
                    } else if (typeof paramDef === 'string') {
                        description = paramDef;
                    }

                    parameters.push({
                        name: paramName,
                        description: description,
                        rustName: toRustFieldName(paramName),
                        rustType: 'String' // For now, assume all parameters are strings
                    });
                }
            }
        }

        return parameters;
    } catch (e) {
        console.warn('Error extracting channel parameters:', e.message);
        return [];
    }
}

/**
 * Resolves a dynamic channel address with provided variable values
 *
 * @param {string} address - Channel address template with variables
 * @param {object} variables - Object mapping variable names to values
 * @returns {string} Resolved channel address
 */
export function resolveChannelAddress(address, variables) {
    if (!address || typeof address !== 'string') return address;
    if (!variables || typeof variables !== 'object') return address;

    let resolved = address;
    for (const [varName, varValue] of Object.entries(variables)) {
        const placeholder = `{${varName}}`;
        resolved = resolved.replace(new RegExp(placeholder.replace(/[{}]/g, '\\$&'), 'g'), varValue);
    }

    return resolved;
}

/**
 * Checks if a channel has dynamic parameters
 *
 * @param {object} channel - AsyncAPI channel object
 * @returns {boolean} True if the channel has parameters
 */
export function channelHasParameters(channel) {
    const address = getChannelAddress(channel);
    return isDynamicChannel(address);
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

/**
 * Generates TypeScript function parameters for dynamic channel parameters
 *
 * @param {Array} channelParameters - Array of channel parameter objects
 * @returns {string} TypeScript function parameter string
 */
export function generateTypeScriptChannelParameterArgs(channelParameters) {
    if (!channelParameters || channelParameters.length === 0) {
        return '';
    }

    return channelParameters.map(param =>
        `${param.name}: string`
    ).join(', ') + ', ';
}

/**
 * Generates TypeScript template literal for dynamic channel resolution
 *
 * @param {string} channelAddress - Original channel address with parameters
 * @param {Array} channelParameters - Array of channel parameter objects
 * @returns {string} TypeScript template literal string
 */
export function generateTypeScriptChannelFormatting(channelAddress, channelParameters) {
    if (!channelParameters || channelParameters.length === 0) {
        return `'${channelAddress}'`;
    }

    // Replace parameter placeholders with template literal placeholders
    let templateString = channelAddress;

    for (const param of channelParameters) {
        templateString = templateString.replace(param.placeholder, `\${${param.name}}`);
    }

    return `\`${templateString}\``;
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

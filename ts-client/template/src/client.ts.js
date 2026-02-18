/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import { operationRequiresAuth, extractOperationSecurityMap } from '../helpers/security.js';

// Helper functions for dynamic channels
function isDynamicChannel(address) {
    if (!address || typeof address !== 'string') return false;
    return /\{[^}]+\}/.test(address);
}

function extractChannelVariables(address) {
    if (!address || typeof address !== 'string') return [];
    const matches = address.match(/\{([^}]+)\}/g);
    if (!matches) return [];
    return matches.map(match => match.slice(1, -1)); // Remove { and }
}

function getChannelParameters(channel) {
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

                    // Create a valid TypeScript identifier
                    let tsName = paramName.replace(/[^a-zA-Z0-9]/g, '_');
                    if (/^[0-9]/.test(tsName)) {
                        tsName = 'param_' + tsName;
                    }
                    if (!tsName || tsName === '_') {
                        tsName = 'param';
                    }

                    parameters.push({
                        name: paramName,
                        description: description,
                        tsName: tsName,
                        tsType: 'string' // For now, assume all parameters are strings
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

function resolveChannelAddress(address, variables) {
    if (!address || typeof address !== 'string') return address;
    if (!variables || typeof variables !== 'object') return address;

    let resolved = address;
    for (const [varName, varValue] of Object.entries(variables)) {
        const placeholder = `{${varName}}`;
        resolved = resolved.replace(new RegExp(placeholder.replace(/[{}]/g, '\\$&'), 'g'), varValue);
    }

    return resolved;
}

function generateClient(asyncapi, clientName) {
    // Method name sanitization function
    function sanitizeMethodName(operationId) {
        if (!operationId) return 'unknownOperation';

        // Convert to camelCase and remove invalid characters
        let sanitized = operationId
            // Replace dots, hyphens, underscores, spaces, and forward slashes with camelCase
            .replace(/[.\-_\s/]+(.)/g, (_, char) => char.toUpperCase())
            // Remove any remaining invalid characters
            .replace(/[^a-zA-Z0-9]/g, '')
            // Ensure it starts with a lowercase letter if it starts with a number
            .replace(/^[^a-zA-Z]/, 'operation')
            // Ensure first character is lowercase
            .replace(/^[A-Z]/, char => char.toLowerCase());

        // Handle JavaScript reserved words
        const JS_RESERVED_WORDS = [
            'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default',
            'delete', 'do', 'else', 'export', 'extends', 'finally', 'for', 'function',
            'if', 'import', 'in', 'instanceof', 'new', 'return', 'super', 'switch',
            'this', 'throw', 'try', 'typeof', 'var', 'void', 'while', 'with', 'yield',
            'let', 'static', 'enum', 'implements', 'package', 'protected', 'interface',
            'private', 'public', 'async', 'await'
        ];

        if (JS_RESERVED_WORDS.includes(sanitized)) {
            sanitized = 'operation' + sanitized.charAt(0).toUpperCase() + sanitized.slice(1);
        }

        // Handle conflicts with existing class methods
        const CLASS_METHOD_NAMES = ['connect', 'disconnect', 'unsubscribe', 'constructor'];
        if (CLASS_METHOD_NAMES.includes(sanitized)) {
            sanitized = sanitized + 'Operation';
        }

        return sanitized;
    }

    let content = `import { TransportFactory } from './runtime/transports/factory';
import { Transport, TransportConfig, RequestOptions, MessageEnvelope } from './runtime/types';
import { AuthCredentials } from './runtime/auth/types';
import * as Models from './models';

export class ${clientName} {
    private transport: Transport;
    private config: TransportConfig;

    constructor(config: TransportConfig) {
        this.config = config;
        this.transport = TransportFactory.create(config);
    }

    async connect(): Promise<void> {
        await this.transport.connect();
    }

    async disconnect(): Promise<void> {
        await this.transport.disconnect();
    }

    /**
     * Unsubscribe from a specific channel
     * @param channel Channel to unsubscribe from
     * @param callback Optional specific callback to remove
     */
    unsubscribe(channel: string, callback?: (payload: any) => void): void {
        this.transport.unsubscribe(channel, callback);
    }

    /**
     * Update authentication configuration
     * @param auth New authentication configuration
     */
    updateAuth(auth: AuthCredentials): void {
        this.config.auth = auth;
        // If transport supports auth updates, update it
        if (this.transport && typeof (this.transport as any).updateAuth === 'function') {
            (this.transport as any).updateAuth(auth);
        }
    }

    /**
     * Get current authentication configuration
     * @returns Current auth configuration
     */
    getAuth(): AuthCredentials | undefined {
        return this.config.auth;
    }

    // Generated operation methods
`;

    // Extract channels and their operations for dynamic channel support
    const channelServices = [];
    if (asyncapi.channels) {
        const channels = asyncapi.channels();
        if (channels) {
            for (const [channelKey, channel] of Object.entries(channels)) {
                try {
                    const channelName = channel.id ? channel.id() : channelKey;
                    let channelAddress = null;
                    if (channel.address && typeof channel.address === 'function') {
                        channelAddress = channel.address();
                    } else if (channel.address) {
                        channelAddress = channel.address;
                    }

                    if (channelAddress) {
                        const isDynamic = isDynamicChannel(channelAddress);
                        const parameters = isDynamic ? getChannelParameters(channel) : [];

                        channelServices.push({
                            channelName,
                            channelAddress,
                            isDynamic,
                            parameters,
                            channel
                        });
                    }
                } catch (e) {
                    console.warn(`Error processing channel ${channelKey}:`, e.message);
                }
            }
        }
    }

    // We'll generate channel services after processing operations

    // Generate client accessor methods for dynamic channels
    const dynamicChannelServices = channelServices.filter(cs => cs.isDynamic);
    if (dynamicChannelServices.length > 0) {
        dynamicChannelServices.forEach(channelService => {
            const serviceName = `${channelService.channelName.charAt(0).toUpperCase() + channelService.channelName.slice(1)}Service`;

            // Extract variables from the channel address to get the actual parameter names
            const variables = extractChannelVariables(channelService.channelAddress);
            const actualParams = variables.map(varName => {
                const existingParam = channelService.parameters.find(p => p.name === varName);
                return {
                    name: varName,
                    tsName: varName.replace(/[^a-zA-Z0-9]/g, '_'),
                    tsType: 'string',
                    description: existingParam?.description || `${varName} parameter`
                };
            });

            const paramInterface = actualParams.map(p => `${p.tsName}: ${p.tsType}`).join(', ');
            const methodName = channelService.channelName.replace(/[^a-zA-Z0-9]/g, '');

            content += `
    /**
     * Access ${channelService.channelName} channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param ${actualParams.map(p => `${p.tsName} ${p.description}`).join('\n     * @param ')}
     * @returns ${serviceName} instance for the resolved channel
     *
     * @example
     * const service = client.${methodName}(${actualParams.map(p => `'${p.name.replace('_', '-')}'`).join(', ')});
     * await service.someOperation(payload);
     */
    ${methodName}(${paramInterface}): ${serviceName} {
        return new ${serviceName}(this.transport, ${actualParams.map(p => p.tsName).join(', ')});
    }
`;
        });
    }

    // Generate methods for each operation (AsyncAPI v3.0.0)
    if (asyncapi.operations) {
        const operations = asyncapi.operations();
        if (operations) {
            // Handle AsyncAPI parser collection - use .all() method to get array
            const operationArray = operations.all ? operations.all() : Object.values(operations);
            operationArray.forEach((operation) => {
                // Get operation ID from the operation object
                let operationId = null;
                if (operation._meta && operation._meta.id) {
                    operationId = operation._meta.id;
                } else if (operation.id && typeof operation.id === 'function') {
                    operationId = operation.id();
                } else if (operation.id) {
                    operationId = operation.id;
                }

                if (!operationId) {
                    return;
                }
                try {
                    // Get the channel reference
                    let channelRef = null;
                    let channelAddress = null;

                    // Get channel information from embedded channel data (AsyncAPI v3.x approach)
                    const embeddedChannel = operation._json && operation._json.channel;

                    if (embeddedChannel) {
                        // Get the channel unique object ID
                        const embeddedChannelId = embeddedChannel['x-parser-unique-object-id'];

                        if (embeddedChannelId) {
                            // Find the channel by its ID
                            const channels = asyncapi.channels();

                            // Look for the channel with matching ID
                            for (const [channelKey, channel] of Object.entries(channels || {})) {
                                if (channel.id && channel.id() === embeddedChannelId) {
                                    if (channel.address && typeof channel.address === 'function') {
                                        channelAddress = channel.address();
                                    } else if (channel.address) {
                                        channelAddress = channel.address;
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    // Fallback: try to get channel from $ref (AsyncAPI v2.x approach)
                    if (!channelAddress && operation._json && operation._json.channel && operation._json.channel.$ref) {
                        channelRef = operation._json.channel.$ref;

                        const channelName = channelRef.split('/').pop();

                        const channels = asyncapi.channels();
                        if (channels && channels[channelName]) {
                            const channel = channels[channelName];
                            if (channel.address && typeof channel.address === 'function') {
                                channelAddress = channel.address();
                            } else if (channel.address) {
                                channelAddress = channel.address;
                            }
                        }
                    }

                    // Get the action (send/receive)
                    let action = 'send';
                    if (operation.action && typeof operation.action === 'function') {
                        action = operation.action();
                    } else if (operation.action) {
                        action = operation.action;
                    }

                    // Get message types for this operation
                    let messageTypes = [];
                    try {
                        if (operation.messages && typeof operation.messages === 'function') {
                            const messages = operation.messages();
                            if (messages && typeof messages.all === 'function') {
                                // Handle AsyncAPI parser collection
                                const messageArray = messages.all();
                                messageTypes = messageArray.map(msg => {
                                    // Try to get message name from various sources
                                    if (msg.name && typeof msg.name === 'function') {
                                        return msg.name();
                                    } else if (msg.name) {
                                        return msg.name;
                                    } else if (msg._json && msg._json.name) {
                                        return msg._json.name;
                                    } else if (msg.$ref) {
                                        return msg.$ref.split('/').pop();
                                    }
                                    return null;
                                }).filter(Boolean);
                            } else if (Array.isArray(messages)) {
                                messageTypes = messages.map(msg => {
                                    // Try to get message name from various sources
                                    if (msg.name && typeof msg.name === 'function') {
                                        return msg.name();
                                    } else if (msg.name) {
                                        return msg.name;
                                    } else if (msg._json && msg._json.name) {
                                        return msg._json.name;
                                    } else if (msg.$ref) {
                                        return msg.$ref.split('/').pop();
                                    }
                                    return null;
                                }).filter(Boolean);
                            }
                        } else if (operation.messages && Array.isArray(operation.messages)) {
                            messageTypes = operation.messages.map(msg => {
                                // Try to get message name from various sources
                                if (msg.name && typeof msg.name === 'function') {
                                    return msg.name();
                                } else if (msg.name) {
                                    return msg.name;
                                } else if (msg._json && msg._json.name) {
                                    return msg._json.name;
                                } else if (msg.$ref) {
                                    return msg.$ref.split('/').pop();
                                }
                                return null;
                            }).filter(Boolean);
                        }

                        // Fallback: try to get from operation._json.messages
                        if (messageTypes.length === 0 && operation._json && operation._json.messages) {
                            messageTypes = operation._json.messages.map(msg => {
                                if (msg.name) {
                                    return msg.name;
                                } else if (msg['x-parser-unique-object-id']) {
                                    return msg['x-parser-unique-object-id'];
                                }
                                return null;
                            }).filter(Boolean);
                        }
                    } catch (msgError) {
                        // If we can't get messages, try to infer from channel
                    }

                    if (channelAddress) {
                        // Skip operations for dynamic channels - they'll be handled by channel services
                        const channelService = channelServices.find(cs => cs.channelAddress === channelAddress);
                        if (channelService && channelService.isDynamic) {
                            return; // Skip this operation for the main client
                        }

                        if (action === 'send') {
                            // Check if this is a request/response pattern
                            let hasReply = false;
                            let replyMessageTypes = [];

                            // Try multiple ways to access reply information
                            try {
                                // Method 1: Check operation.reply() function
                                if (operation.reply && typeof operation.reply === 'function') {
                                    const reply = operation.reply();
                                    if (reply) {
                                        hasReply = true;

                                        // Get reply messages
                                        if (reply.messages && typeof reply.messages === 'function') {
                                            const replyMessages = reply.messages();
                                            if (replyMessages && typeof replyMessages.all === 'function') {
                                                const messageArray = replyMessages.all();
                                                replyMessageTypes = messageArray.map(msg => {
                                                    if (msg.name && typeof msg.name === 'function') {
                                                        return msg.name();
                                                    } else if (msg.name) {
                                                        return msg.name;
                                                    } else if (msg._json && msg._json.name) {
                                                        return msg._json.name;
                                                    } else if (msg.$ref) {
                                                        return msg.$ref.split('/').pop();
                                                    }
                                                    return null;
                                                }).filter(Boolean);
                                            }
                                        }
                                    }
                                }

                                // Method 2: Check operation._json.reply
                                if (!hasReply && operation._json && operation._json.reply) {
                                    hasReply = true;
                                    const reply = operation._json.reply;

                                    if (reply.messages) {
                                        replyMessageTypes = reply.messages.map(msg => {
                                            if (msg.$ref) {
                                                return msg.$ref.split('/').pop();
                                            }
                                            return null;
                                        }).filter(Boolean);
                                    }
                                }

                            } catch (replyError) {
                                // Could not get reply messages for operation
                            }

                            // Sanitize the method name
                            const methodName = sanitizeMethodName(operationId);

                            if (hasReply) {
                                // Request/Response pattern - send and wait for response
                                const requestPayloadType = messageTypes.length > 0 ? `Models.${messageTypes[0]}` : 'any';
                                const responseType = replyMessageTypes.length > 0 ? `Models.${replyMessageTypes[0]}` : 'any';

                                content += `
    /**
     * ${methodName} - Request/Response operation
     * Original operation: ${operationId}
     * Channel: ${channelAddress}
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ${methodName}(payload: ${requestPayloadType}, options?: RequestOptions): Promise<${responseType}> {
        const envelope: MessageEnvelope = {
            operation: '${operationId}',
            payload,
            channel: '${channelAddress}'
        };
        return this.transport.send('${channelAddress}', envelope, options);
    }
`;
                            } else {
                                // Regular send operation (fire and forget)
                                const payloadType = messageTypes.length > 0 ? `Models.${messageTypes[0]}` : 'any';
                                content += `
    /**
     * ${methodName} - Send operation (fire and forget)
     * Original operation: ${operationId}
     * Channel: ${channelAddress}
     */
    async ${methodName}(payload: ${payloadType}, options?: RequestOptions): Promise<void> {
        const envelope: MessageEnvelope = {
            operation: '${operationId}',
            payload,
            channel: '${channelAddress}'
        };
        await this.transport.send('${channelAddress}', envelope, options);
    }
`;

                                // Also generate a subscription method for notification-type operations
                                // (send operations without replies are typically notifications/events)
                                const subscribeMethodName = `on${methodName.charAt(0).toUpperCase() + methodName.slice(1)}`;
                                content += `
    /**
     * ${subscribeMethodName} - Subscribe to ${operationId} notifications
     * Original operation: ${operationId}
     * Channel: ${channelAddress}
     * @param callback Function to call when a notification is received
     * @returns Unsubscribe function to stop listening for notifications
     */
    ${subscribeMethodName}(callback: (payload: ${payloadType}) => void): () => void {
        return this.transport.subscribe('${channelAddress}', '${operationId}', (envelope: MessageEnvelope) => {
            // Filter by operation to ensure we only handle messages for this specific operation
            if (envelope.operation === '${operationId}') {
                callback(envelope.payload);
            }
        });
    }
`;
                            }
                        } else if (action === 'receive') {
                            // Sanitize the method name
                            const methodName = sanitizeMethodName(operationId);

                            // Generate receive method (event listener setup)
                            const payloadType = messageTypes.length > 0 ? `Models.${messageTypes[0]}` : 'any';
                            content += `
    /**
     * ${methodName} - Receive operation
     * Original operation: ${operationId}
     * Channel: ${channelAddress}
     * @param callback Function to call when a message is received
     * @returns Unsubscribe function to stop listening for messages
     */
    ${methodName}(callback: (payload: ${payloadType}) => void): () => void {
        return this.transport.subscribe('${channelAddress}', '${operationId}', (envelope: MessageEnvelope) => {
            // Filter by operation to ensure we only handle messages for this specific operation
            if (envelope.operation === '${operationId}') {
                callback(envelope.payload);
            }
        });
    }
`;
                        }
                    }
                } catch (error) {
                    // Skip operations that can't be processed
                }
            });
        }
    }

    content += `
}
`;

    // Generate channel service classes for dynamic channels
    if (dynamicChannelServices.length > 0) {
        dynamicChannelServices.forEach(channelService => {
            const serviceName = `${channelService.channelName.charAt(0).toUpperCase() + channelService.channelName.slice(1)}Service`;

            // Extract variables from the channel address to get the actual parameter names
            const variables = extractChannelVariables(channelService.channelAddress);
            const actualParams = variables.map(varName => {
                const existingParam = channelService.parameters.find(p => p.name === varName);
                return {
                    name: varName,
                    tsName: varName.replace(/[^a-zA-Z0-9]/g, '_'),
                    tsType: 'string',
                    description: existingParam?.description || `${varName} parameter`
                };
            });

            const paramInterface = actualParams.map(p => `${p.tsName}: ${p.tsType}`).join(', ');

            content += `
/**
 * ${channelService.channelName} channel service with resolved parameters
 *
 * This service provides access to operations on the ${channelService.channelName} channel
 * with resolved channel parameters for dynamic routing.
 */
export class ${serviceName} {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, ${paramInterface}) {
        this.transport = transport;
        this.resolvedChannel = '${channelService.channelAddress}'${actualParams.map(p => `
            .replace('{${p.name}}', ${p.tsName})`).join('')};
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }
`;

            // Add operations for this dynamic channel
            if (asyncapi.operations) {
                const operations = asyncapi.operations();
                if (operations) {
                    const operationArray = operations.all ? operations.all() : Object.values(operations);
                    operationArray.forEach((operation) => {
                        let operationId = null;
                        if (operation._meta && operation._meta.id) {
                            operationId = operation._meta.id;
                        } else if (operation.id && typeof operation.id === 'function') {
                            operationId = operation.id();
                        } else if (operation.id) {
                            operationId = operation.id;
                        }

                        if (!operationId) return;

                        try {
                            // Check if this operation belongs to this dynamic channel
                            let channelAddress = null;
                            const embeddedChannel = operation._json && operation._json.channel;

                            if (embeddedChannel) {
                                const embeddedChannelId = embeddedChannel['x-parser-unique-object-id'];
                                if (embeddedChannelId) {
                                    const channels = asyncapi.channels();
                                    for (const [channelKey, channel] of Object.entries(channels || {})) {
                                        if (channel.id && channel.id() === embeddedChannelId) {
                                            if (channel.address && typeof channel.address === 'function') {
                                                channelAddress = channel.address();
                                            } else if (channel.address) {
                                                channelAddress = channel.address;
                                            }
                                            break;
                                        }
                                    }
                                }
                            }

                            if (channelAddress === channelService.channelAddress) {
                                // This operation belongs to this dynamic channel
                                let action = 'send';
                                if (operation.action && typeof operation.action === 'function') {
                                    action = operation.action();
                                } else if (operation.action) {
                                    action = operation.action;
                                }

                                // Get message types
                                let messageTypes = [];
                                if (operation.messages && typeof operation.messages === 'function') {
                                    const messages = operation.messages();
                                    if (messages && typeof messages.all === 'function') {
                                        const messageArray = messages.all();
                                        messageTypes = messageArray.map(msg => {
                                            if (msg.name && typeof msg.name === 'function') {
                                                return msg.name();
                                            } else if (msg.name) {
                                                return msg.name;
                                            }
                                            return null;
                                        }).filter(Boolean);
                                    }
                                }

                                const methodName = sanitizeMethodName(operationId);

                                if (action === 'send') {
                                    // Check for reply
                                    let hasReply = false;
                                    let replyMessageTypes = [];

                                    if (operation.reply && typeof operation.reply === 'function') {
                                        const reply = operation.reply();
                                        if (reply) {
                                            hasReply = true;
                                            if (reply.messages && typeof reply.messages === 'function') {
                                                const replyMessages = reply.messages();
                                                if (replyMessages && typeof replyMessages.all === 'function') {
                                                    const messageArray = replyMessages.all();
                                                    replyMessageTypes = messageArray.map(msg => {
                                                        if (msg.name && typeof msg.name === 'function') {
                                                            return msg.name();
                                                        } else if (msg.name) {
                                                            return msg.name;
                                                        }
                                                        return null;
                                                    }).filter(Boolean);
                                                }
                                            }
                                        }
                                    }

                                    if (hasReply) {
                                        const requestPayloadType = messageTypes.length > 0 ? `Models.${messageTypes[0]}` : 'any';
                                        const responseType = replyMessageTypes.length > 0 ? `Models.${replyMessageTypes[0]}` : 'any';

                                        content += `
    /**
     * ${methodName} - Request/Response operation
     * Original operation: ${operationId}
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ${methodName}(payload: ${requestPayloadType}, options?: RequestOptions): Promise<${responseType}> {
        const envelope: MessageEnvelope = {
            operation: '${operationId}',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }
`;
                                    } else {
                                        const payloadType = messageTypes.length > 0 ? `Models.${messageTypes[0]}` : 'any';
                                        content += `
    /**
     * ${methodName} - Send operation (fire and forget)
     * Original operation: ${operationId}
     */
    async ${methodName}(payload: ${payloadType}, options?: RequestOptions): Promise<void> {
        const envelope: MessageEnvelope = {
            operation: '${operationId}',
            payload,
            channel: this.resolvedChannel
        };
        await this.transport.send(this.resolvedChannel, envelope, options);
    }
`;

                                        // Also generate a subscription method for notification-type operations
                                        // (send operations without replies are typically notifications/events)
                                        const subscribeMethodName = `on${methodName.charAt(0).toUpperCase() + methodName.slice(1)}`;
                                        content += `
    /**
     * ${subscribeMethodName} - Subscribe to ${operationId} notifications
     * Original operation: ${operationId}
     * @param callback Function to call when a notification is received
     * @returns Unsubscribe function to stop listening for notifications
     */
    ${subscribeMethodName}(callback: (payload: ${payloadType}) => void): () => void {
        return this.transport.subscribe(this.resolvedChannel, '${operationId}', (envelope: MessageEnvelope) => {
            // Filter by operation to ensure we only handle messages for this specific operation
            if (envelope.operation === '${operationId}') {
                callback(envelope.payload);
            }
        });
    }
`;
                                    }
                                } else if (action === 'receive') {
                                    // Generate receive method (event listener setup) for dynamic channels
                                    const payloadType = messageTypes.length > 0 ? `Models.${messageTypes[0]}` : 'any';
                                    content += `
    /**
     * ${methodName} - Receive operation
     * Original operation: ${operationId}
     * @param callback Function to call when a message is received
     * @returns Unsubscribe function to stop listening for messages
     */
    ${methodName}(callback: (payload: ${payloadType}) => void): () => void {
        return this.transport.subscribe(this.resolvedChannel, '${operationId}', (envelope: MessageEnvelope) => {
            // Filter by operation to ensure we only handle messages for this specific operation
            if (envelope.operation === '${operationId}') {
                callback(envelope.payload);
            }
        });
    }
`;
                                }
                            }
                        } catch (error) {
                            // Skip operations that can't be processed
                        }
                    });
                }
            }

            content += `
}
`;
        });
    }

    content += `
export default ${clientName};
`;

    return content;
}

export default function ({ asyncapi, params }) {
    const title = asyncapi.info().title();

    // Always use the processed title, ignore params.clientName if it contains template variables
    let clientName = `${title.replace(/[^a-zA-Z0-9]/g, '')}Client`;

    // Only use params.clientName if it doesn't contain template variables
    if (params.clientName && !params.clientName.includes('{{')) {
        clientName = params.clientName;
    }

    const generatedContent = generateClient(asyncapi, clientName);

    return (
        <File name="client.ts">
            {generatedContent}
        </File>
    );
}

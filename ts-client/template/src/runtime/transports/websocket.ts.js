/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    const transports = (params.transports || 'websocket,http').split(',').map(t => t.trim());

    if (!transports.includes('websocket')) {
        return null;
    }

    return (
        <File name="websocket.ts">
            {`import { v4 as uuidv4 } from 'uuid';
import { Transport, TransportConfig, RequestOptions, ResponseHandler, MessageEnvelope, EnvelopeCallback } from '../types';
import { TransportError, ConnectionError, TimeoutError } from '../errors';
import { generateAuthHeaders, generateAuthQueryParams, hasAuthCredentials, AuthError, UnauthorizedError, AuthCredentials } from '../auth';
import { createRetryManager, getRetryConfig } from '../retry';

// Environment-aware WebSocket implementation
const getWebSocketImpl = (): typeof WebSocket => {
    if (typeof window !== 'undefined' && window.WebSocket) {
        // Browser environment - use native WebSocket
        return window.WebSocket;
    } else if (typeof global !== 'undefined') {
        // Node.js environment - try to require ws
        try {
            return require('ws');
        } catch (error) {
            throw new Error('WebSocket implementation not available. In Node.js, please install the "ws" package: npm install ws');
        }
    } else {
        throw new Error('WebSocket implementation not available in this environment');
    }
};

// Type definition that works for both browser and Node.js WebSocket
type WebSocketLike = {
    readonly readyState: number;
    readonly OPEN: number;
    send(data: string): void;
    close(): void;
    addEventListener?(type: string, listener: (event: any) => void): void;
    removeEventListener?(type: string, listener: (event: any) => void): void;
    on?(event: string, listener: (...args: any[]) => void): void;
    off?(event: string, listener: (...args: any[]) => void): void;
};

export class WebSocketTransport implements Transport {
    private ws: WebSocketLike | null = null;
    private WebSocketImpl: typeof WebSocket;
    private config: TransportConfig;
    private responseHandlers: Map<string, ResponseHandler> = new Map();
    private subscriptions: Map<string, Set<EnvelopeCallback>> = new Map();
    private operationSubscriptions: Map<string, Set<(payload: any) => void>> = new Map();
    private reconnectAttempts = 0;
    private maxReconnectAttempts = 5;
    private reconnectDelay = 1000;

    constructor(config: TransportConfig) {
        this.config = config;
        this.WebSocketImpl = getWebSocketImpl();
    }

    async connect(): Promise<void> {
        return new Promise((resolve, reject) => {
            try {
                this.ws = new this.WebSocketImpl(this.config.url) as WebSocketLike;

                // Handle both browser and Node.js WebSocket APIs
                if (typeof window !== 'undefined' && this.ws.addEventListener) {
                    // Browser WebSocket API
                    this.ws.addEventListener('open', () => {
                        this.reconnectAttempts = 0;
                        resolve();
                    });

                    this.ws.addEventListener('message', (event: MessageEvent) => {
                        this.handleMessage(event.data);
                    });

                    this.ws.addEventListener('close', () => {
                        this.handleDisconnect();
                    });

                    this.ws.addEventListener('error', (event: Event) => {
                        reject(new ConnectionError(\`WebSocket connection failed: \${event.type}\`));
                    });
                } else if (this.ws.on) {
                    // Node.js ws library API
                    this.ws.on('open', () => {
                        this.reconnectAttempts = 0;
                        resolve();
                    });

                    this.ws.on('message', (data: any) => {
                        this.handleMessage(data.toString());
                    });

                    this.ws.on('close', () => {
                        this.handleDisconnect();
                    });

                    this.ws.on('error', (error: any) => {
                        reject(new ConnectionError(\`WebSocket connection failed: \${error.message}\`));
                    });
                } else {
                    reject(new ConnectionError('WebSocket implementation does not support required event handling'));
                }
            } catch (error: any) {
                reject(new ConnectionError(\`Failed to create WebSocket: \${error.message}\`));
            }
        });
    }

    async disconnect(): Promise<void> {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }

    async send(channel: string, envelope: MessageEnvelope, options?: RequestOptions): Promise<any> {
        if (!this.ws || this.ws.readyState !== this.ws.OPEN) {
            throw new TransportError('WebSocket is not connected');
        }

        // Generate auth headers if credentials are available
        const authHeaders = this.config.auth ? generateAuthHeaders(this.config.auth) : {};

        // Ensure envelope has required fields
        const requestId = options?.correlationId || envelope.id || uuidv4();
        const messageEnvelope: MessageEnvelope = {
            ...envelope,
            id: requestId,
            channel: envelope.channel || channel,
            timestamp: envelope.timestamp || new Date().toISOString(),
            headers: {
                ...envelope.headers,
                ...authHeaders
            }
        };

        return new Promise((resolve, reject) => {
            const timeout = options?.timeout || 30000;
            const timeoutId = setTimeout(() => {
                this.responseHandlers.delete(requestId);
                reject(new TimeoutError(\`Request timeout after \${timeout}ms\`));
            }, timeout);

            this.responseHandlers.set(requestId, {
                resolve: (data) => {
                    clearTimeout(timeoutId);
                    resolve(data);
                },
                reject: (error) => {
                    clearTimeout(timeoutId);
                    reject(error);
                }
            });

            this.ws!.send(JSON.stringify(messageEnvelope));
        });
    }

    subscribe(channel: string, callback: (envelope: MessageEnvelope) => void): () => void {
        if (!this.subscriptions.has(channel)) {
            this.subscriptions.set(channel, new Set());
        }

        this.subscriptions.get(channel)!.add(callback);

        // Send subscription message to server using envelope format
        if (this.ws && this.ws.readyState === this.ws.OPEN) {
            // Generate auth headers if credentials are available
            const authHeaders = this.config.auth ? generateAuthHeaders(this.config.auth) : {};

            const subscribeEnvelope: MessageEnvelope = {
                operation: 'subscribe',
                channel,
                payload: { channel },
                timestamp: new Date().toISOString(),
                headers: authHeaders
            };
            this.ws.send(JSON.stringify(subscribeEnvelope));
        }

        // Return unsubscribe function
        return () => {
            this.unsubscribe(channel, callback);
        };
    }

    unsubscribe(channel: string, callback?: (envelope: MessageEnvelope) => void): void {
        const channelSubscriptions = this.subscriptions.get(channel);
        if (!channelSubscriptions) {
            return;
        }

        if (callback) {
            channelSubscriptions.delete(callback);
            if (channelSubscriptions.size === 0) {
                this.subscriptions.delete(channel);
                this.sendUnsubscribeMessage(channel);
            }
        } else {
            // Unsubscribe all callbacks for this channel
            this.subscriptions.delete(channel);
            this.sendUnsubscribeMessage(channel);
        }
    }

    /**
     * Subscribe to a specific operation on a channel
     * This provides operation-based filtering on the client side
     */
    subscribeToOperation(channel: string, operation: string, callback: (payload: any) => void): () => void {
        const operationKey = \`\${channel}:\${operation}\`;

        if (!this.operationSubscriptions.has(operationKey)) {
            this.operationSubscriptions.set(operationKey, new Set());
        }

        this.operationSubscriptions.get(operationKey)!.add(callback);

        // Subscribe to the channel if not already subscribed
        if (!this.subscriptions.has(channel)) {
            this.subscribe(channel, (envelope: MessageEnvelope) => {
                this.handleOperationMessage(envelope);
            });
        }

        // Return unsubscribe function
        return () => {
            const opCallbacks = this.operationSubscriptions.get(operationKey);
            if (opCallbacks) {
                opCallbacks.delete(callback);
                if (opCallbacks.size === 0) {
                    this.operationSubscriptions.delete(operationKey);
                }
            }
        };
    }

    private handleOperationMessage(envelope: MessageEnvelope): void {
        if (!envelope.operation || !envelope.channel) {
            return;
        }

        const operationKey = \`\${envelope.channel}:\${envelope.operation}\`;
        const operationCallbacks = this.operationSubscriptions.get(operationKey);

        if (operationCallbacks) {
            operationCallbacks.forEach(callback => {
                try {
                    callback(envelope.payload);
                } catch (error) {
                    console.error(\`Error in operation callback for \${envelope.operation}:\`, error);
                }
            });
        }
    }

    private sendUnsubscribeMessage(channel: string): void {
        if (this.ws && this.ws.readyState === this.ws.OPEN) {
            const unsubscribeMessage = {
                type: 'unsubscribe',
                channel,
                timestamp: new Date().toISOString()
            };
            this.ws.send(JSON.stringify(unsubscribeMessage));
        }
    }

    private handleMessage(data: string): void {
        try {
            const envelope: MessageEnvelope = JSON.parse(data);

            // Handle response messages (with ID for request/response correlation)
            if (envelope.id) {
                const handler = this.responseHandlers.get(envelope.id);
                if (handler) {
                    this.responseHandlers.delete(envelope.id);
                    if (envelope.error) {
                        handler.reject(new TransportError(\`\${envelope.error.code}: \${envelope.error.message}\`));
                    } else {
                        handler.resolve(envelope.payload);
                    }
                }
                return;
            }

            // Handle subscription messages (broadcast messages without correlation ID)
            if (envelope.channel) {
                const channelSubscriptions = this.subscriptions.get(envelope.channel);
                if (channelSubscriptions) {
                    channelSubscriptions.forEach(callback => {
                        try {
                            callback(envelope);
                        } catch (error) {
                            console.error(\`Error in subscription callback for channel \${envelope.channel}:\`, error);
                        }
                    });
                }

                // Also handle operation-based subscriptions
                this.handleOperationMessage(envelope);
            }
        } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
        }
    }

    private handleDisconnect(): void {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            setTimeout(() => {
                this.connect().then(() => {
                    // Re-subscribe to all channels after reconnection
                    this.resubscribeAll();
                }).catch(() => {
                    // Failed to reconnect
                });
            }, this.reconnectDelay * this.reconnectAttempts);
        }
    }

    private resubscribeAll(): void {
        if (this.ws && this.ws.readyState === this.ws.OPEN) {
            for (const channel of this.subscriptions.keys()) {
                const subscribeMessage = {
                    type: 'subscribe',
                    channel,
                    timestamp: new Date().toISOString()
                };
                this.ws.send(JSON.stringify(subscribeMessage));
            }
        }
    }

    /**
     * Update authentication configuration
     * @param auth New authentication configuration
     */
    updateAuth(auth: AuthCredentials): void {
        if (this.config) {
            this.config.auth = auth;
        }
        // Note: For WebSocket, auth is typically handled during connection
        // If you need to update auth for an active connection, you may need to reconnect
    }
}`}
        </File>
    );
};

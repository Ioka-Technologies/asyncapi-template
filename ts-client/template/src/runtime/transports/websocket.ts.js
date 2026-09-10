/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ({ asyncapi, params }) {
    const transports = (params.transports || 'websocket,http').split(',').map(t => t.trim());

    if (!transports.includes('websocket')) {
        return null;
    }

    return (
        <File name="websocket.ts">
            {`import { v4 as uuidv4 } from 'uuid';
import { Transport, TransportConfig, RequestOptions, ResponseHandler, MessageEnvelope, EnvelopeCallback, ReconnectConfig } from '../types';
import { TransportError, ConnectionError, TimeoutError } from '../errors';
import { generateAuthHeaders, generateAuthQueryParams, hasAuthCredentials, AuthError, UnauthorizedError, AuthCredentials } from '../auth';
import { createRetryManager, getRetryConfig } from '../retry';

// Environment-aware WebSocket implementation
const getWebSocketImpl = async (): Promise<any> => {
    if (typeof window !== 'undefined' && window.WebSocket) {
        // Browser environment - use native WebSocket
        return window.WebSocket;
    } else if (typeof global !== 'undefined') {
        // Node.js environment - try to import ws
        try {
            const { default: WebSocket } = await import('ws');
            return WebSocket;
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
    private WebSocketImpl: any;
    private config: TransportConfig;
    private responseHandlers: Map<string, ResponseHandler> = new Map();
    private subscriptions: Map<string, Set<EnvelopeCallback>> = new Map();
    private operationSubscriptions: Map<string, Set<(payload: any) => void>> = new Map();
    private channelOperations: Map<string, string> = new Map(); // Track operation for each channel

    // Reconnect state
    private intentionalDisconnect = false;
    private _isConnected = false;
    private reconnectAttempts = 0;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private connectPromise: Promise<void> | null = null;
    private pendingConnectionReject: ((error: Error) => void) | null = null;
    private connectionGeneration = 0;
    private hasConnectedSuccessfully = false;
    private reconnectConfig: Required<ReconnectConfig>;

    // Event listener registries (for application-layer listeners beyond config callbacks)
    private reconnectedListeners = new Set<() => void>();
    private disconnectedListeners = new Set<(reason: string) => void>();

    constructor(config: TransportConfig) {
        this.config = config;
        this.reconnectConfig = {
            enabled: config.reconnect?.enabled ?? true,
            maxAttempts: config.reconnect?.maxAttempts ?? 0, // 0 = unlimited
            baseDelay: config.reconnect?.baseDelay ?? 1000,
            maxDelay: config.reconnect?.maxDelay ?? 30000,
            backoffMultiplier: config.reconnect?.backoffMultiplier ?? 2,
            jitter: config.reconnect?.jitter ?? true,
        };
        // WebSocketImpl will be set during connect()
    }

    /**
     * Check if the transport is currently connected
     */
    isConnected(): boolean {
        return this._isConnected && this.ws !== null && this.ws.readyState === this.ws.OPEN;
    }

    /**
     * Register a callback for when the transport reconnects after a disconnect.
     * Returns an unsubscribe function.
     */
    onReconnected(callback: () => void): () => void {
        this.reconnectedListeners.add(callback);
        return () => { this.reconnectedListeners.delete(callback); };
    }

    /**
     * Register a callback for when the transport disconnects unexpectedly.
     * Returns an unsubscribe function.
     */
    onDisconnected(callback: (reason: string) => void): () => void {
        this.disconnectedListeners.add(callback);
        return () => { this.disconnectedListeners.delete(callback); };
    }

    connect(): Promise<void> {
        if (this.isConnected()) return Promise.resolve();
        if (this.connectPromise) return this.connectPromise;
        this.intentionalDisconnect = false;
        this.connectPromise = this.createConnection().finally(() => {
            this.connectPromise = null;
            if (!this.isConnected()) this.attemptReconnect();
        });
        return this.connectPromise;
    }

    private async createConnection(): Promise<void> {
        if (!this.WebSocketImpl) {
            this.WebSocketImpl = await getWebSocketImpl();
        }

        return new Promise((resolve, reject) => {
            let settled = false;
            this.pendingConnectionReject = reject;
            const generation = ++this.connectionGeneration;
            const fail = (error: Error): void => {
                if (!settled) { settled = true; reject(error); }
                this.pendingConnectionReject = null;
            };
            try {
                const socket = new this.WebSocketImpl(this.config.url) as WebSocketLike;
                this.ws = socket;
                const isCurrent = (): boolean => generation === this.connectionGeneration && this.ws === socket;

                // Handle both browser and Node.js WebSocket APIs
                if (typeof window !== 'undefined' && socket.addEventListener) {
                    // Browser WebSocket API
                    socket.addEventListener('open', () => {
                        if (!isCurrent()) return;
                        settled = true;
                        this.pendingConnectionReject = null;
                        const wasReconnect = this.hasConnectedSuccessfully;
                        this.hasConnectedSuccessfully = true;
                        this.reconnectAttempts = 0;
                        this._isConnected = true;
                        if (wasReconnect) {
                            this.config.connectionCallbacks?.onReconnected?.();
                            this.reconnectedListeners.forEach(cb => cb());
                            this.resubscribeAll();
                        } else {
                            this.config.connectionCallbacks?.onConnected?.();
                        }
                        resolve();
                    });

                    socket.addEventListener('message', (event: MessageEvent) => {
                        if (isCurrent()) this.handleMessage(event.data);
                    });

                    socket.addEventListener('close', () => {
                        if (!isCurrent()) return;
                        this._isConnected = false;
                        this.ws = null;
                        fail(new ConnectionError('WebSocket connection closed'));
                        this.handleDisconnect();
                    });

                    socket.addEventListener('error', (event: Event) => {
                        if (!isCurrent()) return;
                        if (!this._isConnected) {
                            // Error during initial connection
                            fail(new ConnectionError(\`WebSocket connection failed: \${event.type}\`));
                        } else {
                            // Error on established connection — handleDisconnect will be called by 'close'
                            console.error('WebSocket error on established connection:', event);
                            this.config.connectionCallbacks?.onError?.(
                                new ConnectionError('WebSocket error')
                            );
                        }
                    });
                } else if (socket.on) {
                    // Node.js ws library API
                    socket.on('open', () => {
                        if (!isCurrent()) return;
                        settled = true;
                        this.pendingConnectionReject = null;
                        const wasReconnect = this.hasConnectedSuccessfully;
                        this.hasConnectedSuccessfully = true;
                        this.reconnectAttempts = 0;
                        this._isConnected = true;
                        if (wasReconnect) {
                            this.config.connectionCallbacks?.onReconnected?.();
                            this.reconnectedListeners.forEach(cb => cb());
                            this.resubscribeAll();
                        } else {
                            this.config.connectionCallbacks?.onConnected?.();
                        }
                        resolve();
                    });

                    socket.on('message', (data: any) => {
                        if (isCurrent()) this.handleMessage(data.toString());
                    });

                    socket.on('close', () => {
                        if (!isCurrent()) return;
                        this._isConnected = false;
                        this.ws = null;
                        fail(new ConnectionError('WebSocket connection closed'));
                        this.handleDisconnect();
                    });

                    socket.on('error', (error: any) => {
                        if (!isCurrent()) return;
                        if (!this._isConnected) {
                            // Error during initial connection
                            fail(new ConnectionError(\`WebSocket connection failed: \${error.message}\`));
                        } else {
                            // Error on established connection — handleDisconnect will be called by 'close'
                            console.error('WebSocket error on established connection:', error);
                            this.config.connectionCallbacks?.onError?.(
                                new ConnectionError(\`WebSocket error: \${error.message}\`)
                            );
                        }
                    });
                } else {
                    fail(new ConnectionError('WebSocket implementation does not support required event handling'));
                }
            } catch (error: any) {
                fail(new ConnectionError(\`Failed to create WebSocket: \${error.message}\`));
            }
        });
    }

    async disconnect(): Promise<void> {
        this.intentionalDisconnect = true;
        this._isConnected = false;

        // Cancel any pending reconnect timer
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        this.connectionGeneration++;
        if (this.pendingConnectionReject) {
            this.pendingConnectionReject(new ConnectionError('Connection closed intentionally'));
            this.pendingConnectionReject = null;
        }

        // Reject all pending requests
        this.rejectPendingRequests('Connection closed intentionally');

        const socket = this.ws;
        this.ws = null;
        if (socket) {
            socket.close();
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

    subscribe(channel: string, operation: string, callback: (envelope: MessageEnvelope) => void): () => void {
        // When an operation is provided, use operation-based routing to extract the payload
        if (operation) {
            // Create a wrapper that extracts the payload from the envelope
            const payloadCallback = (payload: any) => {
                // Reconstruct the envelope for backward compatibility
                const envelope: MessageEnvelope = {
                    operation: operation,
                    channel: channel,
                    payload: payload,
                    timestamp: new Date().toISOString()
                };
                callback(envelope);
            };

            // Use operation-based subscription which correctly extracts the payload
            return this.subscribeToOperation(channel, operation, payloadCallback);
        }

        // Fallback to channel-based subscription for backward compatibility
        if (!this.subscriptions.has(channel)) {
            this.subscriptions.set(channel, new Set());
        }

        this.subscriptions.get(channel)!.add(callback);

        // Track the operation for this channel for reconnection purposes
        this.channelOperations.set(channel, operation);

        // Send subscription message to server using envelope format
        if (this.ws && this.ws.readyState === this.ws.OPEN) {
            // Generate auth headers if credentials are available
            const authHeaders = this.config.auth ? generateAuthHeaders(this.config.auth) : {};

            const subscribeEnvelope: MessageEnvelope = {
                operation: operation,  // Use the actual operation name
                channel,
                payload: { channel, operation },
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
                this.channelOperations.delete(channel); // Clean up operation tracking
                this.sendUnsubscribeMessage(channel);
            }
        } else {
            // Unsubscribe all callbacks for this channel
            this.subscriptions.delete(channel);
            this.channelOperations.delete(channel); // Clean up operation tracking
            this.sendUnsubscribeMessage(channel);
        }
    }

    /**
     * Subscribe to a specific operation on a channel
     * This provides operation-based filtering on the client side
     */
    subscribeToOperation(channel: string, operation: string, callback: (payload: any) => void): () => void {
        const operationKey = \`\${channel}::\${operation}\`;

        if (!this.operationSubscriptions.has(operationKey)) {
            this.operationSubscriptions.set(operationKey, new Set());
        }

        this.operationSubscriptions.get(operationKey)!.add(callback);

        // Subscribe to the channel if not already subscribed (use direct channel subscription to avoid circular call)
        if (!this.subscriptions.has(channel)) {
            // Direct channel subscription without going through the subscribe method
            this.subscriptions.set(channel, new Set());

            // Track the operation for this channel for reconnection purposes
            this.channelOperations.set(channel, operation);

            // Send subscription message to server using envelope format
            if (this.ws && this.ws.readyState === this.ws.OPEN) {
                // Generate auth headers if credentials are available
                const authHeaders = this.config.auth ? generateAuthHeaders(this.config.auth) : {};

                const requestId = uuidv4();
                const subscribeEnvelope: MessageEnvelope = {
                    id: requestId,
                    operation: operation,
                    channel,
                    payload: { channel, operation },
                    timestamp: new Date().toISOString(),
                    headers: authHeaders
                };
                this.ws.send(JSON.stringify(subscribeEnvelope));
            }
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

        const operationKey = \`\${envelope.channel}::\${envelope.operation}\`;
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

            // Check if this is actually a response to a pending request
            const isResponse = envelope.id && this.responseHandlers.has(envelope.id);

            if (isResponse) {
                // Handle as response message
                const handler = this.responseHandlers.get(envelope.id!)!;
                this.responseHandlers.delete(envelope.id!);
                if (envelope.error) {
                    handler.reject(new TransportError(\`\${envelope.error.code}: \${envelope.error.message}\`));
                } else {
                    handler.resolve(envelope.payload);
                }
                return;
            }

            // Handle as subscription message (even if it has an ID)
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
        const wasConnected = this._isConnected;
        this._isConnected = false;

        // Reject all pending request/response handlers immediately
        this.rejectPendingRequests('WebSocket connection lost');

        // Don't reconnect if this was intentional
        if (this.intentionalDisconnect) return;

        // Notify listeners of unexpected disconnect
        const reason = 'WebSocket connection lost unexpectedly';
        this.config.connectionCallbacks?.onDisconnected?.(reason);
        this.disconnectedListeners.forEach(cb => {
            try { cb(reason); } catch (e) { console.error('Error in disconnect listener:', e); }
        });

        // Start reconnection if enabled
        if (!this.reconnectConfig.enabled) {
            return;
        }

        this.attemptReconnect();
    }

    private attemptReconnect(): void {
        if (this.intentionalDisconnect || this.reconnectTimer || this.connectPromise) {
            return;
        }
        // Check if we've exceeded max attempts (0 = unlimited)
        if (this.reconnectConfig.maxAttempts > 0 &&
            this.reconnectAttempts >= this.reconnectConfig.maxAttempts) {
            console.error(\`WebSocket reconnect failed after \${this.reconnectAttempts} attempts\`);
            this.config.connectionCallbacks?.onReconnectFailed?.(this.reconnectAttempts);
            return;
        }

        this.reconnectAttempts++;
        const delay = this.calculateReconnectDelay(this.reconnectAttempts);

        console.log(\`WebSocket reconnecting in \${delay}ms (attempt \${this.reconnectAttempts})\`);
        this.config.connectionCallbacks?.onReconnecting?.(this.reconnectAttempts, delay);

        this.reconnectTimer = setTimeout(async () => {
            this.reconnectTimer = null;
            try {
                // Reset the intentional disconnect flag before reconnecting
                this.intentionalDisconnect = false;
                await this.connect();

            } catch (error) {
                // Try again
                this.attemptReconnect();
            }
        }, delay);
    }

    private calculateReconnectDelay(attempt: number): number {
        let delay = this.reconnectConfig.baseDelay *
            Math.pow(this.reconnectConfig.backoffMultiplier, attempt - 1);

        // Cap at max delay
        delay = Math.min(delay, this.reconnectConfig.maxDelay);

        // Add jitter
        if (this.reconnectConfig.jitter) {
            delay = delay * (0.5 + Math.random() * 0.5);
        }

        return Math.floor(delay);
    }

    private rejectPendingRequests(reason: string): void {
        for (const [requestId, handler] of this.responseHandlers) {
            handler.reject(new ConnectionError(reason));
        }
        this.responseHandlers.clear();
    }

    private resubscribeAll(): void {
        if (!this.ws || this.ws.readyState !== this.ws.OPEN) {
            return;
        }

        const authHeaders = this.config.auth ? generateAuthHeaders(this.config.auth) : {};

        // Collect all unique channel+operation pairs that need resubscription
        const subscriptionsToRestore = new Set<string>();

        // From channel-based subscriptions
        for (const channel of this.subscriptions.keys()) {
            const operation = this.channelOperations.get(channel);
            if (operation) {
                subscriptionsToRestore.add(\`\${channel}::\${operation}\`);
            }
        }

        // From operation-based subscriptions (these may have additional operations
        // on channels already tracked above)
        for (const operationKey of this.operationSubscriptions.keys()) {
            // operationKey format is "channel::operation"
            const separatorIndex = operationKey.indexOf('::');
            if (separatorIndex !== -1) {
                subscriptionsToRestore.add(operationKey);
            }
        }

        // Send subscribe messages for all unique channel+operation pairs
        for (const key of subscriptionsToRestore) {
            const separatorIndex = key.indexOf('::');
            const channel = key.substring(0, separatorIndex);
            const operation = key.substring(separatorIndex + 2);
            try {
                const subscribeEnvelope: MessageEnvelope = {
                    id: uuidv4(),
                    operation: operation,
                    channel: channel,
                    payload: { channel, operation },
                    timestamp: new Date().toISOString(),
                    headers: authHeaders
                };
                this.ws.send(JSON.stringify(subscribeEnvelope));
                console.log(\`Resubscribed to \${channel} (operation: \${operation})\`);
            } catch (error) {
                console.error(\`Failed to resubscribe to \${channel}:\`, error);
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
}

/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ({ asyncapi, params }) {
    return (
        <File name="types.ts">
            {`import { AuthCredentials, AuthEventCallbacks } from './auth';
import { RetryConfig, RetryPreset, RetryEventCallbacks } from './retry';

/**
 * Standard message envelope for all AsyncAPI communications
 */
export interface MessageEnvelope {
    operation: string;           // AsyncAPI operation ID
    id?: string;                // Correlation ID for request/response
    channel?: string;           // Optional channel context
    payload: any;               // Message payload
    timestamp?: string;         // Optional ISO 8601 timestamp
    headers?: Record<string, string>; // Transport-level headers (auth, routing, etc.)
    error?: {                   // Error information
        code: string;
        message: string;
    };
}

/**
 * Connection lifecycle event callbacks
 */
export interface ConnectionEventCallbacks {
    /** Called when the WebSocket connection is established (including reconnections) */
    onConnected?: () => void;

    /** Called when the WebSocket connection is lost unexpectedly */
    onDisconnected?: (reason: string) => void;

    /** Called when a reconnection attempt starts */
    onReconnecting?: (attempt: number, delay: number) => void;

    /** Called when reconnection succeeds after a disconnection */
    onReconnected?: () => void;

    /** Called when all reconnection attempts are exhausted (if a limit is set) */
    onReconnectFailed?: (attempts: number) => void;

    /** Called on any WebSocket error */
    onError?: (error: Error) => void;
}

/**
 * Configuration for WebSocket reconnection behavior
 */
export interface ReconnectConfig {
    /** Whether to automatically reconnect on disconnect. Default: true */
    enabled?: boolean;
    /** Maximum number of reconnect attempts. 0 = unlimited. Default: 0 (unlimited) */
    maxAttempts?: number;
    /** Initial delay in ms before first reconnect attempt. Default: 1000 */
    baseDelay?: number;
    /** Maximum delay in ms between reconnect attempts. Default: 30000 */
    maxDelay?: number;
    /** Backoff multiplier. Default: 2 */
    backoffMultiplier?: number;
    /** Add jitter to prevent thundering herd. Default: true */
    jitter?: boolean;
}

/**
 * Transport interface for sending and receiving messages
 */
export interface Transport {
    connect(): Promise<void>;
    disconnect(): Promise<void>;
    send(channel: string, envelope: MessageEnvelope, options?: RequestOptions): Promise<any>;
    subscribe(channel: string, operation: string, callback: (envelope: MessageEnvelope) => void): () => void;
    unsubscribe(channel: string, callback?: (envelope: MessageEnvelope) => void): void;

    /** Check if the transport is currently connected */
    isConnected(): boolean;

    /** Register a callback for when the transport reconnects after a disconnect */
    onReconnected(callback: () => void): () => void;

    /** Register a callback for when the transport disconnects unexpectedly */
    onDisconnected(callback: (reason: string) => void): () => void;
}

/**
 * Configuration for transport implementations
 */
export interface TransportConfig {
    type: 'websocket' | 'http';
    url: string;
    headers?: Record<string, string>;
    timeout?: number;
    auth?: AuthCredentials;                    // Authentication credentials
    retry?: RetryConfig | RetryPreset;         // Retry configuration
    authCallbacks?: AuthEventCallbacks;        // Auth event callbacks
    retryCallbacks?: RetryEventCallbacks;      // Retry event callbacks
    reconnect?: ReconnectConfig;               // Reconnection configuration
    connectionCallbacks?: ConnectionEventCallbacks; // Connection lifecycle callbacks
}

/**
 * Options for individual requests
 */
export interface RequestOptions {
    timeout?: number;
    correlationId?: string;                    // Override correlation ID
    retry?: RetryConfig | RetryPreset;         // Override retry config for this request
}

/**
 * Internal response handler for request/response patterns
 */
export interface ResponseHandler {
    resolve: (data: any) => void;
    reject: (error: Error) => void;
}

/**
 * Callback function for message subscriptions
 */
export type MessageCallback = (payload: any) => void;

/**
 * Function to unsubscribe from a channel
 */
export type UnsubscribeFunction = () => void;

/**
 * Envelope callback for transport-level message handling
 */
export type EnvelopeCallback = (envelope: MessageEnvelope) => void;`}
        </File>
    );
}

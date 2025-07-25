/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    return (
        <File name="types.ts">
            {`/**
 * Standard message envelope for all AsyncAPI communications
 */
export interface MessageEnvelope {
    operation: string;           // AsyncAPI operation ID
    id?: string;                // Correlation ID for request/response
    channel?: string;           // Optional channel context
    payload: any;               // Message payload
    timestamp?: string;         // Optional ISO 8601 timestamp
    error?: {                   // Error information
        code: string;
        message: string;
    };
}

/**
 * Transport interface for sending and receiving messages
 */
export interface Transport {
    connect(): Promise<void>;
    disconnect(): Promise<void>;
    send(channel: string, envelope: MessageEnvelope, options?: RequestOptions): Promise<any>;
    subscribe(channel: string, callback: (envelope: MessageEnvelope) => void): () => void;
    unsubscribe(channel: string, callback?: (envelope: MessageEnvelope) => void): void;
}

/**
 * Configuration for transport implementations
 */
export interface TransportConfig {
    type: 'websocket' | 'http';
    url: string;
    headers?: Record<string, string>;
    timeout?: number;
}

/**
 * Options for individual requests
 */
export interface RequestOptions {
    timeout?: number;
    correlationId?: string;     // Override correlation ID
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

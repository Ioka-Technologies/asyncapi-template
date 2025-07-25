/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    const transports = (params.transports || 'websocket,http').split(',').map(t => t.trim());

    if (!transports.includes('http')) {
        return null;
    }

    return (
        <File name="http.ts">
            {`import { Transport, TransportConfig, RequestOptions, MessageEnvelope } from '../types';
import { TransportError, ConnectionError, TimeoutError } from '../errors';

export class HttpTransport implements Transport {
    private config: TransportConfig;
    private baseUrl: string;

    constructor(config: TransportConfig) {
        this.config = config;
        this.baseUrl = config.url;
    }

    async connect(): Promise<void> {
        // HTTP doesn't require explicit connection
        return Promise.resolve();
    }

    async disconnect(): Promise<void> {
        // HTTP doesn't require explicit disconnection
        return Promise.resolve();
    }

    async send(channel: string, envelope: MessageEnvelope, options?: RequestOptions): Promise<any> {
        const url = \`\${this.baseUrl}/\${channel}\`;
        const timeout = options?.timeout || 30000;

        // Prepare the complete envelope for HTTP transport
        const messageEnvelope: MessageEnvelope = {
            ...envelope,
            channel: envelope.channel || channel,
            timestamp: envelope.timestamp || new Date().toISOString(),
            id: options?.correlationId || envelope.id
        };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Operation': envelope.operation,
                    'X-Correlation-ID': messageEnvelope.id || '',
                    ...this.config.headers
                },
                body: JSON.stringify(messageEnvelope),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                // Try to parse error response as envelope
                try {
                    const errorEnvelope: MessageEnvelope = await response.json();
                    if (errorEnvelope.error) {
                        throw new TransportError(\`\${errorEnvelope.error.code}: \${errorEnvelope.error.message}\`);
                    }
                } catch {
                    // Fall back to HTTP status error
                    throw new TransportError(\`HTTP request failed: \${response.status} \${response.statusText}\`);
                }
            }

            // Parse response as envelope
            const responseEnvelope: MessageEnvelope = await response.json();

            // Check for envelope-level errors
            if (responseEnvelope.error) {
                throw new TransportError(\`\${responseEnvelope.error.code}: \${responseEnvelope.error.message}\`);
            }

            return responseEnvelope.payload;
        } catch (error: any) {
            clearTimeout(timeoutId);

            if (error.name === 'AbortError') {
                throw new TimeoutError(\`Request timeout after \${timeout}ms\`);
            }

            // Re-throw TransportError as-is
            if (error instanceof TransportError) {
                throw error;
            }

            throw new TransportError(\`HTTP request failed: \${error.message}\`);
        }
    }

    subscribe(channel: string, callback: (envelope: MessageEnvelope) => void): () => void {
        // HTTP transport doesn't support real-time subscriptions
        // This is a placeholder implementation that logs a warning
        console.warn(\`HTTP transport does not support subscriptions. Channel '\${channel}' subscription ignored.\`);
        console.warn('Consider using WebSocket transport for real-time message subscriptions.');

        // Return a no-op unsubscribe function
        return () => {
            // No-op for HTTP transport
        };
    }

    unsubscribe(channel: string, callback?: (envelope: MessageEnvelope) => void): void {
        // HTTP transport doesn't support subscriptions, so nothing to unsubscribe
        console.warn(\`HTTP transport does not support subscriptions. Channel '\${channel}' unsubscribe ignored.\`);
    }
}`}
        </File>
    );
}

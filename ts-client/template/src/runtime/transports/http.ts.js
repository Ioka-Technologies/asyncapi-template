/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ({ asyncapi, params }) {
    const transports = (params.transports || 'websocket,http').split(',').map(t => t.trim());

    if (!transports.includes('http')) {
        return null;
    }

    return (
        <File name="http.ts">
            {`import { Transport, TransportConfig, RequestOptions, MessageEnvelope } from '../types';
import { TransportError, ConnectionError, TimeoutError } from '../errors';
import { generateAuthHeaders, generateAuthQueryParams, hasAuthCredentials, AuthError, UnauthorizedError, AuthCredentials } from '../auth';
import { createRetryManager, getRetryConfig } from '../retry';

export class HttpTransport implements Transport {
    private config: TransportConfig;
    private baseUrl: string;
    private retryManager: any;

    constructor(config: TransportConfig) {
        this.config = config;
        this.baseUrl = config.url;

        // Initialize retry manager if retry config is provided
        if (config.retry) {
            this.retryManager = createRetryManager(config.retry, config.retryCallbacks);
        }
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
        // Determine retry configuration (options override config)
        const retryConfig = options?.retry ? getRetryConfig(options.retry) :
                           this.config.retry ? getRetryConfig(this.config.retry) : null;

        const retryManager = retryConfig ? createRetryManager(retryConfig, this.config.retryCallbacks) : null;

        const sendOperation = async () => {
            return this.performHttpRequest(channel, envelope, options);
        };

        // Execute with retry if configured
        if (retryManager) {
            return retryManager.executeWithRetry(sendOperation, \`\${envelope.operation} on \${channel}\`);
        } else {
            return sendOperation();
        }
    }

    private async performHttpRequest(channel: string, envelope: MessageEnvelope, options?: RequestOptions): Promise<any> {
        let url = \`\${this.baseUrl}/\${channel}\`;
        const timeout = options?.timeout || this.config.timeout || 30000;

        // Generate auth headers if credentials are available
        const authHeaders = this.config.auth ? generateAuthHeaders(this.config.auth) : {};

        // Prepare the complete envelope for HTTP transport
        const messageEnvelope: MessageEnvelope = {
            ...envelope,
            channel: envelope.channel || channel,
            timestamp: envelope.timestamp || new Date().toISOString(),
            id: options?.correlationId || envelope.id || this.generateCorrelationId(),
            headers: {
                ...envelope.headers,
                ...authHeaders
            }
        };

        // Prepare headers
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'X-Operation': envelope.operation,
            'X-Correlation-ID': messageEnvelope.id || '',
            ...this.config.headers
        };

        // Add auth headers if auth is configured
        if (this.config.auth && hasAuthCredentials(this.config.auth)) {
            try {
                const authHeaders = generateAuthHeaders(this.config.auth);
                Object.assign(headers, authHeaders);
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                throw new AuthError(\`Failed to generate auth headers: \${errorMessage}\`);
            }
        }

        // Add auth query parameters if needed
        if (this.config.auth?.apikey?.location === 'query') {
            const authParams = generateAuthQueryParams(this.config.auth);
            const urlObj = new URL(url);
            Object.entries(authParams).forEach(([key, value]) => {
                urlObj.searchParams.set(key, value);
            });
            url = urlObj.toString();
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers,
                body: JSON.stringify(messageEnvelope),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            // Handle auth errors specifically
            if (response.status === 401) {
                // Call auth error callback if available
                if (this.config.authCallbacks?.onAuthError) {
                    const shouldRetry = await this.config.authCallbacks.onAuthError();
                    if (shouldRetry) {
                        // Retry the request with potentially updated auth
                        return this.performHttpRequest(channel, envelope, options);
                    }
                }
                throw new UnauthorizedError('Authentication failed');
            }

            if (!response.ok) {
                // Create error with status for retry logic
                const error = new TransportError(\`HTTP request failed: \${response.status} \${response.statusText}\`);
                (error as any).status = response.status;

                // Try to parse error response as envelope
                try {
                    const errorEnvelope: MessageEnvelope = await response.json();
                    if (errorEnvelope.error) {
                        error.message = \`\${errorEnvelope.error.code}: \${errorEnvelope.error.message}\`;
                    }
                } catch {
                    // Use the default error message
                }

                throw error;
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
                const timeoutError = new TimeoutError(\`Request timeout after \${timeout}ms\`);
                (timeoutError as any).code = 'TIMEOUT';
                throw timeoutError;
            }

            // Add error codes for retry logic
            if (error instanceof TransportError || error instanceof AuthError) {
                throw error;
            }

            // Network errors
            const networkError = new TransportError(\`HTTP request failed: \${error.message}\`);
            (networkError as any).code = 'NETWORK_ERROR';
            throw networkError;
        }
    }

    private generateCorrelationId(): string {
        return \`http-\${Date.now()}-\${Math.random().toString(36).substr(2, 9)}\`;
    }

    /**
     * Update authentication configuration
     * @param auth New authentication configuration
     */
    updateAuth(auth: AuthCredentials): void {
        if (this.config) {
            this.config.auth = auth;
        }
    }

    subscribe(channel: string, operation: string, callback: (envelope: MessageEnvelope) => void): () => void {
        // HTTP transport doesn't support real-time subscriptions
        // This is a placeholder implementation that logs a warning
        console.warn(\`HTTP transport does not support subscriptions. Operation '\${operation}' on channel '\${channel}' subscription ignored.\`);
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

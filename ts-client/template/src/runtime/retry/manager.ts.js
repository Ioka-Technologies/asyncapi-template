/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    return (
        <File name="manager.ts">
            {`import { RetryConfig, RetryEventCallbacks, MaxRetriesExceededError } from './types';
import { getRetryConfig } from './presets';

/**
 * Retry manager for handling exponential backoff and retry logic
 */
export class RetryManager {
    private config: RetryConfig;
    private callbacks?: RetryEventCallbacks;

    constructor(config: RetryConfig, callbacks?: RetryEventCallbacks) {
        this.config = config;
        this.callbacks = callbacks;
    }

    /**
     * Execute an operation with retry logic
     */
    async executeWithRetry<T>(
        operation: () => Promise<T>,
        operationName: string
    ): Promise<T> {
        if (!this.config.enabled) {
            return operation();
        }

        let lastError: Error;

        for (let attempt = 1; attempt <= this.config.maxAttempts; attempt++) {
            try {
                return await operation();
            } catch (error) {
                lastError = error as Error;

                // Check if error is retryable
                if (!this.isRetryable(error) || attempt === this.config.maxAttempts) {
                    if (attempt === this.config.maxAttempts && this.callbacks?.onRetryExhausted) {
                        this.callbacks.onRetryExhausted(operationName, lastError);
                    }
                    throw error;
                }

                // Calculate delay with exponential backoff and jitter
                const delay = this.calculateDelay(attempt);

                // Call retry callback
                if (this.callbacks?.onRetry) {
                    this.callbacks.onRetry(attempt, lastError, delay);
                }

                // Wait before retrying
                await this.sleep(delay);
            }
        }

        // This should never be reached, but TypeScript requires it
        throw new MaxRetriesExceededError(this.config.maxAttempts, lastError!);
    }

    /**
     * Check if an error is retryable based on configuration
     */
    private isRetryable(error: any): boolean {
        // Check HTTP status codes
        if (error.status && this.config.retryableStatusCodes.includes(error.status)) {
            return true;
        }

        // Check error codes
        if (error.code && this.config.retryableErrors.includes(error.code)) {
            return true;
        }

        // Check error names
        if (error.name && this.config.retryableErrors.includes(error.name)) {
            return true;
        }

        // Check error messages for common network errors
        if (error.message) {
            const message = error.message.toLowerCase();
            for (const retryableError of this.config.retryableErrors) {
                if (message.includes(retryableError.toLowerCase())) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Calculate delay with exponential backoff and optional jitter
     */
    private calculateDelay(attempt: number): number {
        let delay = this.config.baseDelay * Math.pow(this.config.backoffMultiplier, attempt - 1);

        // Apply maximum delay cap
        delay = Math.min(delay, this.config.maxDelay);

        // Add jitter to prevent thundering herd
        if (this.config.jitter) {
            delay = delay * (0.5 + Math.random() * 0.5);
        }

        return Math.floor(delay);
    }

    /**
     * Sleep for specified milliseconds
     */
    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Get current retry configuration
     */
    getConfig(): RetryConfig {
        return { ...this.config };
    }

    /**
     * Update retry configuration
     */
    updateConfig(config: Partial<RetryConfig>): void {
        this.config = { ...this.config, ...config };
    }
}

/**
 * Create a retry manager from config or preset
 */
export function createRetryManager(
    config: RetryConfig | string,
    callbacks?: RetryEventCallbacks
): RetryManager {
    const retryConfig = getRetryConfig(config as any);
    return new RetryManager(retryConfig, callbacks);
}
`}
        </File>
    );
};

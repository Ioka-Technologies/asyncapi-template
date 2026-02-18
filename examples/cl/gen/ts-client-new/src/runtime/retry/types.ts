/**
 * Retry configuration interface
 */
export interface RetryConfig {
    enabled: boolean;
    maxAttempts: number;
    baseDelay: number;        // Initial delay in ms
    maxDelay: number;         // Maximum delay in ms
    backoffMultiplier: number; // Exponential backoff multiplier
    jitter: boolean;          // Add randomization to prevent thundering herd
    retryableStatusCodes: number[]; // Which HTTP status codes to retry
    retryableErrors: string[];      // Which error types to retry
}

/**
 * Preset retry configurations
 */
export type RetryPreset = 'aggressive' | 'balanced' | 'conservative' | 'none';

/**
 * Retry event callbacks for monitoring
 */
export interface RetryEventCallbacks {
    /** Called before each retry attempt */
    onRetry?: (attempt: number, error: Error, delay: number) => void;

    /** Called when all retry attempts are exhausted */
    onRetryExhausted?: (operation: string, finalError: Error) => void;
}

/**
 * Retry-related error types
 */
export class RetryError extends Error {
    constructor(
        message: string,
        public attempts: number,
        public lastError: Error
    ) {
        super(message);
        this.name = 'RetryError';
    }
}

export class MaxRetriesExceededError extends RetryError {
    constructor(attempts: number, lastError: Error) {
        super(`Maximum retry attempts (${attempts}) exceeded`, attempts, lastError);
        this.name = 'MaxRetriesExceededError';
    }
}

/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    return (
        <File name="presets.ts">
            {`import { RetryConfig, RetryPreset } from './types';

/**
 * Predefined retry configuration presets
 */
export const RETRY_PRESETS: Record<RetryPreset, RetryConfig> = {
    none: {
        enabled: false,
        maxAttempts: 1,
        baseDelay: 0,
        maxDelay: 0,
        backoffMultiplier: 1,
        jitter: false,
        retryableStatusCodes: [],
        retryableErrors: []
    },

    conservative: {
        enabled: true,
        maxAttempts: 3,
        baseDelay: 1000,      // 1 second
        maxDelay: 10000,      // 10 seconds max
        backoffMultiplier: 2,
        jitter: true,
        retryableStatusCodes: [500, 502, 503, 504],
        retryableErrors: ['NETWORK_ERROR', 'TIMEOUT', 'ECONNRESET', 'ENOTFOUND']
    },

    balanced: {
        enabled: true,
        maxAttempts: 5,
        baseDelay: 500,       // 500ms
        maxDelay: 30000,      // 30 seconds max
        backoffMultiplier: 2,
        jitter: true,
        retryableStatusCodes: [429, 500, 502, 503, 504],
        retryableErrors: ['NETWORK_ERROR', 'TIMEOUT', 'CONNECTION_ERROR', 'ECONNRESET', 'ENOTFOUND', 'ETIMEDOUT']
    },

    aggressive: {
        enabled: true,
        maxAttempts: 10,
        baseDelay: 100,       // 100ms
        maxDelay: 60000,      // 1 minute max
        backoffMultiplier: 1.5,
        jitter: true,
        retryableStatusCodes: [408, 429, 500, 502, 503, 504],
        retryableErrors: ['NETWORK_ERROR', 'TIMEOUT', 'CONNECTION_ERROR', 'DNS_ERROR', 'ECONNRESET', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNREFUSED']
    }
};

/**
 * Get retry configuration from preset or return custom config
 */
export function getRetryConfig(config: RetryConfig | RetryPreset): RetryConfig {
    if (typeof config === 'string') {
        return RETRY_PRESETS[config];
    }
    return config;
}

/**
 * Merge custom retry config with preset defaults
 */
export function mergeRetryConfig(preset: RetryPreset, overrides: Partial<RetryConfig>): RetryConfig {
    const baseConfig = RETRY_PRESETS[preset];
    return {
        ...baseConfig,
        ...overrides
    };
}
`}
        </File>
    );
};

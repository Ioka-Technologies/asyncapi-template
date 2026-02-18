import { AuthCredentials, AuthError } from './types';

/**
 * Generate authentication headers based on credentials
 */
export function generateAuthHeaders(auth: AuthCredentials): Record<string, string> {
    const headers: Record<string, string> = {};

    if (auth.jwt) {
        headers['Authorization'] = `Bearer ${auth.jwt}`;
    } else if (auth.basic) {
        const credentials = btoa(`${auth.basic.username}:${auth.basic.password}`);
        headers['Authorization'] = `Basic ${credentials}`;
    } else if (auth.apikey) {
        if (auth.apikey.location === 'header') {
            headers[auth.apikey.name] = auth.apikey.key;
        }
        // Query parameters are handled in the transport layer
    }

    return headers;
}

/**
 * Generate query parameters for API key authentication
 */
export function generateAuthQueryParams(auth: AuthCredentials): Record<string, string> {
    const params: Record<string, string> = {};

    if (auth.apikey && auth.apikey.location === 'query') {
        params[auth.apikey.name] = auth.apikey.key;
    }

    return params;
}

/**
 * Validate auth credentials
 */
export function validateAuthCredentials(auth: AuthCredentials): void {
    if (auth.jwt) {
        if (typeof auth.jwt !== 'string' || auth.jwt.trim() === '') {
            throw new AuthError('JWT token must be a non-empty string', 'jwt');
        }
    }

    if (auth.basic) {
        if (!auth.basic.username || !auth.basic.password) {
            throw new AuthError('Basic auth requires both username and password', 'basic');
        }
        if (typeof auth.basic.username !== 'string' || typeof auth.basic.password !== 'string') {
            throw new AuthError('Basic auth username and password must be strings', 'basic');
        }
    }

    if (auth.apikey) {
        if (!auth.apikey.key || !auth.apikey.name) {
            throw new AuthError('API key auth requires both key and name', 'apikey');
        }
        if (typeof auth.apikey.key !== 'string' || typeof auth.apikey.name !== 'string') {
            throw new AuthError('API key and name must be strings', 'apikey');
        }
        if (!['header', 'query'].includes(auth.apikey.location)) {
            throw new AuthError('API key location must be either "header" or "query"', 'apikey');
        }
    }
}

/**
 * Check if auth credentials are provided
 */
export function hasAuthCredentials(auth?: AuthCredentials): boolean {
    if (!auth) return false;
    return !!(auth.jwt || auth.basic || auth.apikey);
}

/**
 * Get auth type from credentials
 */
export function getAuthType(auth: AuthCredentials): string | null {
    if (auth.jwt) return 'jwt';
    if (auth.basic) return 'basic';
    if (auth.apikey) return 'apikey';
    return null;
}

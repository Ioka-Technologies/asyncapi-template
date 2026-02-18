/**
 * Authentication credentials for different auth types
 */
export interface AuthCredentials {
    /** JWT Bearer token */
    jwt?: string;

    /** Basic authentication credentials */
    basic?: {
        username: string;
        password: string;
    };

    /** API Key authentication */
    apikey?: {
        key: string;
        location: 'header' | 'query';
        name: string;
    };
}

/**
 * Auth-related error types
 */
export class AuthError extends Error {
    constructor(message: string, public authType?: string) {
        super(message);
        this.name = 'AuthError';
    }
}

export class TokenExpiredError extends AuthError {
    constructor(message: string = 'Token has expired') {
        super(message, 'jwt');
        this.name = 'TokenExpiredError';
    }
}

export class UnauthorizedError extends AuthError {
    constructor(message: string = 'Unauthorized access') {
        super(message);
        this.name = 'UnauthorizedError';
    }
}

/**
 * Auth event callbacks for monitoring and token refresh
 */
export interface AuthEventCallbacks {
    /** Called when a 401 Unauthorized response is received */
    onAuthError?: () => Promise<boolean>;

    /** Called when token needs to be refreshed */
    onTokenRefresh?: (oldToken: string) => Promise<string>;
}

/**
 * Security requirement analysis result
 */
export interface SecurityRequirement {
    hasSecurityRequirements: boolean;
    securitySchemes: any[];
    requiresAuthentication: boolean;
}

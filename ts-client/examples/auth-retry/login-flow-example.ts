/**
 * Login Flow Example - JWT Token Management
 *
 * This example demonstrates how to handle a typical authentication flow:
 * 1. Start with no authentication (or basic auth for login)
 * 2. Call userLogin operation
 * 3. Extract JWT token from response
 * 4. Update client auth configuration
 * 5. Make authenticated requests with the JWT
 */

import React, { useState, useCallback, useEffect } from 'react';

// These would be imported from your generated client
// import { UserServiceClient } from './generated-client';
// import { AuthError, UnauthorizedError, AuthCredentials } from './generated-client';

// For this example, we'll use placeholder types and classes
interface AuthCredentials {
    jwt?: string;
    basic?: {
        username: string;
        password: string;
    };
    apikey?: {
        key: string;
        location: 'header' | 'query';
        name: string;
    };
}

class UserServiceClient {
    constructor(config: any) { }
    async connect(): Promise<void> { }
    async disconnect(): Promise<void> { }
    async userLogin(payload: any): Promise<any> { return {}; }
    async getUserProfile(payload: any): Promise<any> { return {}; }
    async updateUserPreferences(payload: any): Promise<void> { }
    userNotifications(callback: (notification: any) => void): () => void { return () => { }; }
    updateAuth(auth: AuthCredentials): void { }
    getAuth(): AuthCredentials | undefined { return {}; }
}

class AuthError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'AuthError';
    }
}

class UnauthorizedError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'UnauthorizedError';
    }
}

// Example login response type (this would be generated from your AsyncAPI spec)
interface LoginResponse {
    token: string;
    user: {
        id: string;
        email: string;
        name: string;
    };
    expiresAt: string;
}

// Example user profile type
interface UserProfile {
    id: string;
    email: string;
    name: string;
    preferences: {
        theme: string;
        notifications: boolean;
    };
    lastLoginAt: string;
}

async function loginFlowExample() {
    // Step 1: Create client without authentication (for login)
    const client = new UserServiceClient({
        type: 'http',
        url: 'https://api.example.com',
        retry: 'balanced'
        // No auth configuration initially
    });

    await client.connect();

    try {
        // Step 2: Perform login (this operation doesn't require auth)
        console.log('Logging in...');
        const loginResponse: LoginResponse = await client.userLogin({
            email: 'user@example.com',
            password: 'mypassword'
        });

        console.log('Login successful!', loginResponse.user);

        // Step 3: Update client auth configuration with JWT token
        client.updateAuth({
            jwt: loginResponse.token
        });

        console.log('Auth updated with JWT token');

        // Step 4: Now make authenticated requests
        // The JWT token will be automatically included in all subsequent requests
        const userProfile: UserProfile = await client.getUserProfile({
            userId: loginResponse.user.id
        });

        console.log('User profile retrieved:', userProfile);

        // Step 5: Make other authenticated operations
        await client.updateUserPreferences({
            userId: loginResponse.user.id,
            preferences: {
                theme: 'dark',
                notifications: true
            }
        });

        console.log('User preferences updated');

    } catch (error) {
        if (error instanceof UnauthorizedError) {
            console.error('Authentication failed:', error.message);
            // Handle login failure - show login form again
        } else if (error instanceof AuthError) {
            console.error('Auth configuration error:', error.message);
        } else {
            console.error('Unexpected error:', error);
        }
    } finally {
        await client.disconnect();
    }
}

/**
 * Advanced Login Flow with Token Refresh
 *
 * This example shows how to handle token refresh scenarios
 */
async function advancedLoginFlowExample() {
    let currentToken: string | null = null;
    let refreshToken: string | null = null;

    const client = new UserServiceClient({
        type: 'http',
        url: 'https://api.example.com',
        retry: 'balanced',
        authCallbacks: {
            onAuthError: async () => {
                // Handle 401 errors by attempting token refresh
                console.log('Auth error detected, attempting token refresh...');

                if (refreshToken) {
                    try {
                        const refreshResponse = await refreshJwtToken(refreshToken);
                        currentToken = refreshResponse.token;
                        refreshToken = refreshResponse.refreshToken;

                        // Update the client's auth configuration
                        client.updateAuth({
                            jwt: currentToken || undefined
                        });

                        console.log('Token refreshed successfully');
                        return true; // Retry the original request
                    } catch (refreshError) {
                        console.error('Token refresh failed:', refreshError);
                        // Redirect to login page
                        return false;
                    }
                }

                return false; // No refresh token available
            }
        }
    });

    await client.connect();

    try {
        // Initial login
        const loginResponse = await client.userLogin({
            email: 'user@example.com',
            password: 'mypassword'
        });

        currentToken = loginResponse.token;
        refreshToken = loginResponse.refreshToken; // Assuming your API provides refresh tokens

        // Set initial auth
        client.updateAuth({
            jwt: currentToken || undefined
        });

        // Make authenticated requests - token refresh will be handled automatically
        const userProfile = await client.getUserProfile({
            userId: loginResponse.user.id
        });

        console.log('User profile:', userProfile);

    } catch (error) {
        console.error('Login flow failed:', error);
    } finally {
        await client.disconnect();
    }
}

/**
 * WebSocket Login Flow Example
 *
 * For WebSocket connections, you typically need to reconnect after updating auth
 */
async function websocketLoginFlowExample() {
    // Step 1: Create WebSocket client without auth
    const client = new UserServiceClient({
        type: 'websocket',
        url: 'wss://api.example.com/ws',
        retry: 'balanced'
    });

    await client.connect();

    try {
        // Step 2: Login via WebSocket
        const loginResponse: LoginResponse = await client.userLogin({
            email: 'user@example.com',
            password: 'mypassword'
        });

        console.log('Login successful via WebSocket');

        // Step 3: Disconnect and reconnect with auth
        await client.disconnect();

        client.updateAuth({
            jwt: loginResponse.token
        });

        await client.connect(); // Reconnect with auth headers

        // Step 4: Subscribe to authenticated events
        const unsubscribe = client.userNotifications((notification) => {
            console.log('Received notification:', notification);
        });

        // Step 5: Make authenticated requests
        const userProfile = await client.getUserProfile({
            userId: loginResponse.user.id
        });

        console.log('User profile:', userProfile);

        // Clean up
        setTimeout(() => {
            unsubscribe();
            client.disconnect();
        }, 30000);

    } catch (error) {
        console.error('WebSocket login flow failed:', error);
        await client.disconnect();
    }
}

/**
 * React Hook Example for Login Flow
 */
function useAuthenticatedClient() {
    const [client, setClient] = useState(null as UserServiceClient | null);
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [user, setUser] = useState(null as any);

    const initializeClient = useCallback(() => {
        const newClient = new UserServiceClient({
            type: 'http',
            url: process.env.REACT_APP_API_URL || 'https://api.example.com',
            retry: 'balanced',
            authCallbacks: {
                onAuthError: async () => {
                    // Handle auth errors by clearing auth state
                    setIsAuthenticated(false);
                    setUser(null);
                    return false;
                }
            }
        });

        newClient.connect();
        setClient(newClient);
        return newClient;
    }, []);

    const login = useCallback(async (email: string, password: string) => {
        const currentClient = client || initializeClient();

        try {
            const loginResponse = await currentClient.userLogin({ email, password });

            // Update auth configuration
            currentClient.updateAuth({
                jwt: loginResponse.token
            });

            setIsAuthenticated(true);
            setUser(loginResponse.user);

            return loginResponse;
        } catch (error) {
            console.error('Login failed:', error);
            throw error;
        }
    }, [client, initializeClient]);

    const logout = useCallback(async () => {
        if (client) {
            // Clear auth
            client.updateAuth({});
            await client.disconnect();
        }

        setIsAuthenticated(false);
        setUser(null);
        setClient(null);
    }, [client]);

    useEffect(() => {
        return () => {
            if (client) {
                client.disconnect();
            }
        };
    }, [client]);

    return {
        client,
        isAuthenticated,
        user,
        login,
        logout,
        initializeClient
    };
}

// Helper function for token refresh (implement based on your API)
async function refreshJwtToken(refreshToken: string): Promise<{ token: string; refreshToken: string }> {
    const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refreshToken })
    });

    if (!response.ok) {
        throw new Error('Token refresh failed');
    }

    return response.json();
}

// Export examples
export {
    loginFlowExample,
    advancedLoginFlowExample,
    websocketLoginFlowExample,
    useAuthenticatedClient
};

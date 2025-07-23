/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function AuthMiddlewareRs() {
    return (
        <File name="middleware.rs">
            {`//! Authentication middleware for AsyncAPI message handlers

use crate::auth::{JwtValidator, Claims, RoleManager};
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::handlers::MessageContext;
use std::sync::Arc;
use tracing::{debug, warn, error};
use async_trait::async_trait;

/// Authentication middleware for validating JWT tokens and populating user context
pub struct AuthMiddleware {
    jwt_validator: Arc<JwtValidator>,
    role_manager: Arc<RoleManager>,
}

impl AuthMiddleware {
    /// Create a new authentication middleware
    pub fn new(jwt_validator: Arc<JwtValidator>, role_manager: Arc<RoleManager>) -> Self {
        Self {
            jwt_validator,
            role_manager,
        }
    }

    /// Extract JWT token from authorization header
    fn extract_token_from_header<'a>(&self, auth_header: &'a str) -> AsyncApiResult<&'a str> {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            Ok(token)
        } else if let Some(token) = auth_header.strip_prefix("bearer ") {
            Ok(token)
        } else {
            Err(Box::new(AsyncApiError::Authentication {
                message: "Invalid Authorization header format. Expected 'Bearer <token>'".to_string(),
                source: None,
            }))
        }
    }

    /// Validate JWT token and populate claims
    pub async fn validate_token(&self, token: &str) -> AsyncApiResult<Claims> {
        // Validate the JWT token
        let claims = self.jwt_validator.validate_token(token)?;

        // Load user permissions from role manager
        let user_permissions = self.role_manager
            .get_user_permissions(&claims.sub)
            .await;

        // Create enriched claims with current permissions
        let mut enriched_claims = claims;
        enriched_claims.permissions = user_permissions
            .into_iter()
            .map(|p| p.name)
            .collect();

        debug!(
            user_id = %enriched_claims.sub,
            roles = ?enriched_claims.roles,
            permissions_count = enriched_claims.permissions.len(),
            "Successfully validated JWT token"
        );

        Ok(enriched_claims)
    }

    /// Process authentication for a message context
    pub async fn authenticate_context(
        &self,
        context: &mut MessageContext,
        auth_header: Option<&str>,
    ) -> AsyncApiResult<()> {
        if let Some(header) = auth_header {
            // Extract and validate token
            let token = self.extract_token_from_header(header)?;
            let claims = self.validate_token(token).await?;

            // Set claims in context
            context.set_claims(claims);

            debug!(
                correlation_id = %context.correlation_id,
                "Authentication successful"
            );
        } else {
            warn!(
                correlation_id = %context.correlation_id,
                "No authorization header provided"
            );

            return Err(Box::new(AsyncApiError::Authentication {
                message: "Missing Authorization header".to_string(),
                source: None,
            }));
        }

        Ok(())
    }

    /// Check if the authenticated user has required permissions
    pub async fn check_permissions(
        &self,
        context: &MessageContext,
        required_permissions: &[String],
    ) -> AsyncApiResult<()> {
        let claims = context.claims()
            .ok_or_else(|| AsyncApiError::Authentication {
                message: "No authentication claims found in context".to_string(),
                source: None,
            })?;

        // Check if user has any of the required permissions
        let has_permission = required_permissions.iter().any(|required| {
            claims.permissions.iter().any(|user_perm| {
                // Exact match
                user_perm == required ||
                // Wildcard match (e.g., "admin:*" matches "admin:read")
                (user_perm.ends_with(":*") && required.starts_with(&user_perm[..user_perm.len()-1])) ||
                // Super admin wildcard
                user_perm == "*:*"
            })
        });

        if !has_permission {
            return Err(Box::new(AsyncApiError::Authorization {
                message: "Insufficient permissions for this operation".to_string(),
                required_permissions: required_permissions.to_vec(),
                user_permissions: claims.permissions.clone(),
            }));
        }

        debug!(
            user_id = %claims.sub,
            required_permissions = ?required_permissions,
            "Permission check passed"
        );

        Ok(())
    }

    /// Middleware function to authenticate and authorize message processing
    pub async fn process_with_auth<F, Fut>(
        &self,
        mut context: MessageContext,
        auth_header: Option<&str>,
        required_permissions: &[String],
        handler: F,
    ) -> AsyncApiResult<()>
    where
        F: FnOnce(MessageContext) -> Fut,
        Fut: std::future::Future<Output = AsyncApiResult<()>>,
    {
        // Authenticate the request
        self.authenticate_context(&mut context, auth_header).await?;

        // Check permissions if any are required
        if !required_permissions.is_empty() {
            self.check_permissions(&context, required_permissions).await?;
        }

        // Call the actual handler with authenticated context
        handler(context).await
    }
}

/// Trait for handlers that require authentication
#[async_trait]
pub trait AuthenticatedHandler {
    /// Handle an authenticated message
    async fn handle_authenticated(
        &self,
        context: MessageContext,
    ) -> AsyncApiResult<()>;

    /// Get required permissions for this handler
    fn required_permissions(&self) -> Vec<String> {
        vec![]
    }
}

/// Wrapper for authenticated message handlers
pub struct AuthenticatedMessageHandler<H> {
    handler: H,
    auth_middleware: Arc<AuthMiddleware>,
}

impl<H> AuthenticatedMessageHandler<H>
where
    H: AuthenticatedHandler + Send + Sync,
{
    /// Create a new authenticated message handler
    pub fn new(handler: H, auth_middleware: Arc<AuthMiddleware>) -> Self {
        Self {
            handler,
            auth_middleware,
        }
    }

    /// Process a message with authentication
    pub async fn process_message(
        &self,
        context: MessageContext,
        auth_header: Option<&str>,
    ) -> AsyncApiResult<()> {
        let required_permissions = self.handler.required_permissions();

        self.auth_middleware
            .process_with_auth(
                context,
                auth_header,
                &required_permissions,
                |ctx| self.handler.handle_authenticated(ctx),
            )
            .await
    }
}

/// Helper macro for creating authenticated handlers
#[macro_export]
macro_rules! authenticated_handler {
    ($handler:expr, $auth_middleware:expr, $permissions:expr) => {
        {
            struct Handler<H> {
                inner: H,
                permissions: Vec<String>,
            }

            #[async_trait]
            impl<H> AuthenticatedHandler for Handler<H>
            where
                H: Fn(MessageContext) -> std::pin::Pin<Box<dyn std::future::Future<Output = AsyncApiResult<()>> + Send>> + Send + Sync,
            {
                async fn handle_authenticated(&self, context: MessageContext) -> AsyncApiResult<()> {
                    (self.inner)(context).await
                }

                fn required_permissions(&self) -> Vec<String> {
                    self.permissions.clone()
                }
            }

            let handler = Handler {
                inner: $handler,
                permissions: $permissions.into_iter().map(|s| s.to_string()).collect(),
            };

            AuthenticatedMessageHandler::new(handler, $auth_middleware)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthConfig, Claims};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_extract_token_from_header() {
        let jwt_validator = Arc::new(JwtValidator::new_hmac(b"test-secret"));
        let role_manager = Arc::new(RoleManager::new());
        let middleware = AuthMiddleware::new(jwt_validator, role_manager);

        // Test valid Bearer token
        let result = middleware.extract_token_from_header("Bearer abc123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "abc123");

        // Test valid bearer token (lowercase)
        let result = middleware.extract_token_from_header("bearer xyz789");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "xyz789");

        // Test invalid format
        let result = middleware.extract_token_from_header("Invalid token");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_permission_checking() {
        let jwt_validator = Arc::new(JwtValidator::new_hmac(b"test-secret"));
        let role_manager = Arc::new(RoleManager::new());
        let middleware = AuthMiddleware::new(jwt_validator, role_manager);

        // Create test claims
        let claims = Claims {
            sub: "test_user".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["messages:read".to_string(), "profile:write".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
            iat: chrono::Utc::now().timestamp() as u64,
            iss: "test".to_string(),
            aud: "test".to_string(),
            custom: serde_json::Map::new(),
        };

        let mut context = MessageContext::new("test-channel", "test-operation");
        context.set_claims(claims);

        // Test permission that user has
        let result = middleware
            .check_permissions(&context, &["messages:read".to_string()])
            .await;
        assert!(result.is_ok());

        // Test permission that user doesn't have
        let result = middleware
            .check_permissions(&context, &["admin:delete".to_string()])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wildcard_permissions() {
        let jwt_validator = Arc::new(JwtValidator::new_hmac(b"test-secret"));
        let role_manager = Arc::new(RoleManager::new());
        let middleware = AuthMiddleware::new(jwt_validator, role_manager);

        // Create test claims with wildcard permission
        let claims = Claims {
            sub: "admin_user".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec!["messages:*".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
            iat: chrono::Utc::now().timestamp() as u64,
            iss: "test".to_string(),
            aud: "test".to_string(),
            custom: serde_json::Map::new(),
        };

        let mut context = MessageContext::new("test-channel", "test-operation");
        context.set_claims(claims);

        // Test that wildcard permission matches specific permission
        let result = middleware
            .check_permissions(&context, &["messages:read".to_string()])
            .await;
        assert!(result.is_ok());

        let result = middleware
            .check_permissions(&context, &["messages:write".to_string()])
            .await;
        assert!(result.is_ok());

        // Test that wildcard doesn't match different resource
        let result = middleware
            .check_permissions(&context, &["users:read".to_string()])
            .await;
        assert!(result.is_err());
    }
}
`}
        </File>
    );
}

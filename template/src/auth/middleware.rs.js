/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function AuthMiddlewareRs() {
    return (
        <File name="middleware.rs">
            {`//! Authentication middleware for message processing

use crate::auth::{AuthConfig, Claims, JwtValidator};
use crate::context::{ExecutionContext, RequestContext};
use crate::errors::{AsyncApiError, AsyncApiResult};
use crate::middleware::Middleware;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

/// Authentication middleware
pub struct AuthMiddleware {
    config: AuthConfig,
    jwt_validator: JwtValidator,
    rate_limiter: Option<RateLimiter>,
    session_manager: Option<SessionManager>,
}

impl AuthMiddleware {
    /// Create new authentication middleware
    pub fn new(config: AuthConfig) -> AsyncApiResult<Self> {
        let jwt_validator = Self::create_jwt_validator(&config)?;

        let rate_limiter = if let Some(ref rate_config) = config.rate_limiting {
            Some(RateLimiter::new(
                rate_config.max_attempts,
                Duration::from_secs(rate_config.window_seconds),
                Duration::from_secs(rate_config.lockout_seconds),
            ))
        } else {
            None
        };

        let session_manager = if let Some(ref session_config) = config.session {
            Some(SessionManager::new(
                Duration::from_secs(session_config.timeout_seconds),
                session_config.extend_on_activity,
                session_config.max_concurrent_sessions,
            ))
        } else {
            None
        };

        Ok(Self {
            config,
            jwt_validator,
            rate_limiter,
            session_manager,
        })
    }

    /// Create JWT validator from configuration
    fn create_jwt_validator(config: &AuthConfig) -> AsyncApiResult<JwtValidator> {
        let mut validator = match config.jwt.algorithm {
            crate::auth::config::JwtAlgorithm::HS256 => {
                let secret =
                    config
                        .jwt
                        .secret
                        .as_ref()
                        .ok_or_else(|| AsyncApiError::Configuration {
                            message: "JWT secret is required for HS256".to_string(),
                            metadata: crate::errors::ErrorMetadata::new(
                                crate::errors::ErrorSeverity::High,
                                crate::errors::ErrorCategory::Configuration,
                                false,
                            )
                            .with_context("field", "jwt.secret"),
                            source: None,
                        })?;
                JwtValidator::new_hmac(secret.as_bytes())
            }
            crate::auth::config::JwtAlgorithm::RS256 => {
                let public_key = config.jwt.public_key_pem.as_ref().ok_or_else(|| {
                    AsyncApiError::Configuration {
                        message: "RSA public key is required for RS256".to_string(),
                        metadata: crate::errors::ErrorMetadata::new(
                            crate::errors::ErrorSeverity::High,
                            crate::errors::ErrorCategory::Configuration,
                            false,
                        )
                        .with_context("field", "jwt.public_key_pem"),
                        source: None,
                    }
                })?;

                if let Some(private_key) = &config.jwt.private_key_pem {
                    JwtValidator::new_rsa_keypair(private_key.as_bytes(), public_key.as_bytes())?
                } else {
                    JwtValidator::new_rsa_public(public_key.as_bytes())?
                }
            }
        };

        // Configure validator with issuer and audience if specified
        if let Some(ref issuer) = config.jwt.issuer {
            validator = validator.with_issuer(issuer.clone());
        }

        if let Some(ref audience) = config.jwt.audience {
            validator = validator.with_audience(audience.clone());
        }

        validator = validator.with_leeway(config.jwt.leeway);

        Ok(validator)
    }

    /// Extract authentication token from context
    fn extract_token(&self, context: &RequestContext) -> AsyncApiResult<Option<String>> {
        // Try to get token from headers
        if let Some(auth_header) = context.get_header("authorization") {
            let token = JwtValidator::extract_bearer_token(auth_header)?;
            return Ok(Some(token.to_string()));
        }

        // Try to get token from metadata
        if let Some(token) = context.get_metadata("auth_token") {
            return Ok(Some(token.clone()));
        }

        // Try to get token from custom properties
        if let Some(token) = context.get_property("jwt_token") {
            return Ok(Some(token.clone()));
        }

        Ok(None)
    }

    /// Validate user permissions
    fn validate_permissions(&self, claims: &Claims) -> AsyncApiResult<()> {
        // Check required roles
        if !self.config.required_roles.is_empty() {
            let has_required_role = self
                .config
                .required_roles
                .iter()
                .any(|role| claims.has_role(role));

            if !has_required_role {
                return Err(AsyncApiError::Authorization {
                    message: format!(
                        "User lacks required roles: {:?}",
                        self.config.required_roles
                    ),
                    required_permissions: self.config.required_roles.clone(),
                    user_permissions: claims.roles.clone(),
                });
            }
        }

        // Check required permissions
        if !self.config.required_permissions.is_empty() {
            let has_required_permission = self
                .config
                .required_permissions
                .iter()
                .any(|perm| claims.has_permission(perm));

            if !has_required_permission {
                return Err(AsyncApiError::Authorization {
                    message: format!(
                        "User lacks required permissions: {:?}",
                        self.config.required_permissions
                    ),
                    required_permissions: self.config.required_permissions.clone(),
                    user_permissions: claims.permissions.clone(),
                });
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Middleware for AuthMiddleware {
    fn name(&self) -> &'static str {
        "auth"
    }

    async fn process_inbound(
        &self,
        _context: &crate::middleware::MiddlewareContext,
        payload: &[u8],
    ) -> AsyncApiResult<Vec<u8>> {
        // For auth middleware, we don't modify the payload, just validate authentication
        // The actual authentication logic would be handled at a higher level
        // This is a simplified implementation for the middleware trait
        Ok(payload.to_vec())
    }

    async fn process_outbound(
        &self,
        _context: &crate::middleware::MiddlewareContext,
        payload: &[u8],
    ) -> AsyncApiResult<Vec<u8>> {
        // No processing needed for outbound messages in auth middleware
        Ok(payload.to_vec())
    }
}

impl AuthMiddleware {
    /// Process authentication for a request context
    pub async fn process_request(
        &self,
        context: &mut crate::context::RequestContext,
        _execution_context: &crate::context::ExecutionContext,
    ) -> AsyncApiResult<()> {
        debug!("Processing authentication middleware");

        // Check rate limiting first
        if let Some(ref rate_limiter) = self.rate_limiter {
            let client_id = context.get_client_id().unwrap_or("unknown".to_string());
            if !rate_limiter.check_rate_limit(&client_id).await {
                warn!("Rate limit exceeded for client: {}", client_id);
                return Err(AsyncApiError::RateLimit {
                    message: "Authentication rate limit exceeded".to_string(),
                    retry_after: Some(
                        self.config
                            .rate_limit_lockout()
                            .unwrap_or(Duration::from_secs(900)),
                    ),
                });
            }
        }

        // Extract authentication token
        let token = match self.extract_token(context)? {
            Some(token) => token,
            None => {
                if self.config.allow_anonymous {
                    debug!("No authentication token found, allowing anonymous access");
                    context.set_property("authenticated".to_string(), "false".to_string());
                    return Ok(());
                } else {
                    return Err(AsyncApiError::Authentication {
                        message: "No authentication token provided".to_string(),
                        source: None,
                    });
                }
            }
        };

        // Validate JWT token
        let claims = match self.jwt_validator.validate_token(&token) {
            Ok(claims) => claims,
            Err(e) => {
                warn!("JWT validation failed: {}", e);

                // Record failed attempt for rate limiting
                if let Some(ref rate_limiter) = self.rate_limiter {
                    let client_id = context.get_client_id().unwrap_or("unknown".to_string());
                    rate_limiter.record_failed_attempt(&client_id).await;
                }

                return Err(e);
            }
        };

        // Validate permissions
        self.validate_permissions(&claims)?;

        // Check session if session management is enabled
        if let Some(ref session_manager) = self.session_manager {
            session_manager
                .validate_session(&claims.sub, &token)
                .await?;
        }

        // Store authentication information in context
        context.set_property("authenticated".to_string(), "true".to_string());
        context.set_property("user_id".to_string(), claims.sub.clone());
        context.set_property("user_roles".to_string(), claims.roles.join(","));
        context.set_property("user_permissions".to_string(), claims.permissions.join(","));

        // Store claims for use by handlers
        context.set_auth_claims(claims);

        debug!(
            "Authentication successful for user: {}",
            context
                .get_property("user_id")
                .unwrap_or(&"unknown".to_string())
        );
        Ok(())
    }
}

/// Rate limiter for authentication attempts
struct RateLimiter {
    max_attempts: u32,
    window: Duration,
    lockout: Duration,
    attempts: Arc<RwLock<HashMap<String, AttemptRecord>>>,
}

#[derive(Debug, Clone)]
struct AttemptRecord {
    count: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

impl RateLimiter {
    fn new(max_attempts: u32, window: Duration, lockout: Duration) -> Self {
        Self {
            max_attempts,
            window,
            lockout,
            attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn check_rate_limit(&self, client_id: &str) -> bool {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();

        let record = attempts
            .entry(client_id.to_string())
            .or_insert(AttemptRecord {
                count: 0,
                window_start: now,
                locked_until: None,
            });

        // Check if client is locked out
        if let Some(locked_until) = record.locked_until {
            if now < locked_until {
                return false;
            } else {
                // Lockout expired, reset
                record.locked_until = None;
                record.count = 0;
                record.window_start = now;
            }
        }

        // Check if we need to reset the window
        if now.duration_since(record.window_start) > self.window {
            record.count = 0;
            record.window_start = now;
        }

        record.count < self.max_attempts
    }

    async fn record_failed_attempt(&self, client_id: &str) {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();

        let record = attempts
            .entry(client_id.to_string())
            .or_insert(AttemptRecord {
                count: 0,
                window_start: now,
                locked_until: None,
            });

        record.count += 1;

        if record.count >= self.max_attempts {
            record.locked_until = Some(now + self.lockout);
            warn!(
                "Client {} locked out due to too many failed authentication attempts",
                client_id
            );
        }
    }
}

/// Session manager for tracking user sessions
struct SessionManager {
    timeout: Duration,
    extend_on_activity: bool,
    max_concurrent_sessions: Option<u32>,
    sessions: Arc<RwLock<HashMap<String, Vec<SessionInfo>>>>,
}

#[derive(Debug, Clone)]
struct SessionInfo {
    token_hash: String,
    created_at: Instant,
    last_activity: Instant,
}

impl SessionManager {
    fn new(
        timeout: Duration,
        extend_on_activity: bool,
        max_concurrent_sessions: Option<u32>,
    ) -> Self {
        Self {
            timeout,
            extend_on_activity,
            max_concurrent_sessions,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn validate_session(&self, user_id: &str, token: &str) -> AsyncApiResult<()> {
        let mut sessions = self.sessions.write().await;
        let now = Instant::now();
        let token_hash = self.hash_token(token);

        let user_sessions = sessions.entry(user_id.to_string()).or_insert_with(Vec::new);

        // Remove expired sessions
        user_sessions.retain(|session| now.duration_since(session.last_activity) <= self.timeout);

        // Find current session
        if let Some(session) = user_sessions
            .iter_mut()
            .find(|s| s.token_hash == token_hash)
        {
            // Check if session is expired
            if now.duration_since(session.last_activity) > self.timeout {
                return Err(AsyncApiError::Authentication {
                    message: "Session has expired".to_string(),
                    source: None,
                });
            }

            // Extend session if configured
            if self.extend_on_activity {
                session.last_activity = now;
            }

            Ok(())
        } else {
            // New session
            if let Some(max_sessions) = self.max_concurrent_sessions {
                if user_sessions.len() >= max_sessions as usize {
                    // Remove oldest session
                    user_sessions.sort_by_key(|s| s.created_at);
                    user_sessions.remove(0);
                }
            }

            user_sessions.push(SessionInfo {
                token_hash,
                created_at: now,
                last_activity: now,
            });

            Ok(())
        }
    }

    fn hash_token(&self, token: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        token.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;

    #[tokio::test]
    async fn test_rate_limiter() {
        let rate_limiter = RateLimiter::new(3, Duration::from_secs(60), Duration::from_secs(300));
        let client_id = "test_client";

        // Should allow initial attempts
        assert!(rate_limiter.check_rate_limit(client_id).await);
        assert!(rate_limiter.check_rate_limit(client_id).await);
        assert!(rate_limiter.check_rate_limit(client_id).await);

        // Record failed attempts
        rate_limiter.record_failed_attempt(client_id).await;
        rate_limiter.record_failed_attempt(client_id).await;
        rate_limiter.record_failed_attempt(client_id).await;

        // Should be locked out now
        assert!(!rate_limiter.check_rate_limit(client_id).await);
    }

    #[tokio::test]
    async fn test_session_manager() {
        let session_manager = SessionManager::new(Duration::from_secs(3600), true, Some(2));

        let user_id = "test_user";
        let token1 = "token1";
        let token2 = "token2";

        // Validate new sessions
        assert!(session_manager
            .validate_session(user_id, token1)
            .await
            .is_ok());
        assert!(session_manager
            .validate_session(user_id, token2)
            .await
            .is_ok());

        // Validate existing sessions
        assert!(session_manager
            .validate_session(user_id, token1)
            .await
            .is_ok());
        assert!(session_manager
            .validate_session(user_id, token2)
            .await
            .is_ok());
    }
}
`}
        </File>
    );
}

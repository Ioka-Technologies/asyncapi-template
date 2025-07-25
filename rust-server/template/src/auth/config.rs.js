/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function AuthConfigRs() {
    return (
        <File name="config.rs">
            {`//! Authentication configuration

use crate::errors::{AsyncApiError, AsyncApiResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWT configuration
    pub jwt: JwtConfig,
    /// Rate limiting configuration
    pub rate_limiting: Option<RateLimitConfig>,
    /// Session configuration
    pub session: Option<SessionConfig>,
    /// Required roles for access
    pub required_roles: Vec<String>,
    /// Required permissions for access
    pub required_permissions: Vec<String>,
    /// Whether to allow anonymous access
    pub allow_anonymous: bool,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT secret for HMAC algorithms
    pub secret: Option<String>,
    /// RSA private key PEM for signing (RS256)
    pub private_key_pem: Option<String>,
    /// RSA public key PEM for verification (RS256)
    pub public_key_pem: Option<String>,
    /// Expected issuer
    pub issuer: Option<String>,
    /// Expected audience
    pub audience: Option<String>,
    /// Token expiration time in seconds
    pub expires_in: u64,
    /// Leeway for time-based validations in seconds
    pub leeway: u64,
    /// Algorithm to use (HS256, RS256)
    pub algorithm: JwtAlgorithm,
}

/// JWT algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JwtAlgorithm {
    /// HMAC with SHA-256
    HS256,
    /// RSA with SHA-256
    RS256,
}

/// Rate limiting configuration for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of authentication attempts per window
    pub max_attempts: u32,
    /// Time window for rate limiting
    pub window_seconds: u64,
    /// Lockout duration after exceeding rate limit
    pub lockout_seconds: u64,
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session timeout in seconds
    pub timeout_seconds: u64,
    /// Whether to extend session on activity
    pub extend_on_activity: bool,
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: Option<u32>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt: JwtConfig::default(),
            rate_limiting: Some(RateLimitConfig::default()),
            session: Some(SessionConfig::default()),
            required_roles: Vec::new(),
            required_permissions: Vec::new(),
            allow_anonymous: false,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: None,
            private_key_pem: None,
            public_key_pem: None,
            issuer: None,
            audience: None,
            expires_in: 3600, // 1 hour
            leeway: 60,       // 1 minute
            algorithm: JwtAlgorithm::HS256,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_seconds: 300,  // 5 minutes
            lockout_seconds: 900, // 15 minutes
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 3600, // 1 hour
            extend_on_activity: true,
            max_concurrent_sessions: Some(5),
        }
    }
}

impl AuthConfig {
    /// Create a new authentication configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set JWT secret for HMAC algorithms
    pub fn with_jwt_secret(mut self, secret: String) -> Self {
        self.jwt.secret = Some(secret);
        self.jwt.algorithm = JwtAlgorithm::HS256;
        self
    }

    /// Set RSA key pair for RS256 algorithm
    pub fn with_rsa_keys(mut self, private_key_pem: String, public_key_pem: String) -> Self {
        self.jwt.private_key_pem = Some(private_key_pem);
        self.jwt.public_key_pem = Some(public_key_pem);
        self.jwt.algorithm = JwtAlgorithm::RS256;
        self
    }

    /// Set RSA public key for verification only
    pub fn with_rsa_public_key(mut self, public_key_pem: String) -> Self {
        self.jwt.public_key_pem = Some(public_key_pem);
        self.jwt.algorithm = JwtAlgorithm::RS256;
        self
    }

    /// Set JWT issuer
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.jwt.issuer = Some(issuer);
        self
    }

    /// Set JWT audience
    pub fn with_audience(mut self, audience: String) -> Self {
        self.jwt.audience = Some(audience);
        self
    }

    /// Set token expiration time
    pub fn with_expires_in(mut self, seconds: u64) -> Self {
        self.jwt.expires_in = seconds;
        self
    }

    /// Add required role
    pub fn with_required_role(mut self, role: String) -> Self {
        self.required_roles.push(role);
        self
    }

    /// Add required permission
    pub fn with_required_permission(mut self, permission: String) -> Self {
        self.required_permissions.push(permission);
        self
    }

    /// Allow anonymous access
    pub fn allow_anonymous(mut self) -> Self {
        self.allow_anonymous = true;
        self
    }

    /// Disable rate limiting
    pub fn without_rate_limiting(mut self) -> Self {
        self.rate_limiting = None;
        self
    }

    /// Configure rate limiting
    pub fn with_rate_limiting(mut self, config: RateLimitConfig) -> Self {
        self.rate_limiting = Some(config);
        self
    }

    /// Configure session management
    pub fn with_session_config(mut self, config: SessionConfig) -> Self {
        self.session = Some(config);
        self
    }

    /// Validate the authentication configuration
    pub fn validate(&self) -> AsyncApiResult<()> {
        // Validate JWT configuration
        match self.jwt.algorithm {
            JwtAlgorithm::HS256 => {
                if self.jwt.secret.is_none() {
                    return Err(Box::new(AsyncApiError::Configuration {
                        message: "JWT secret is required for HS256 algorithm".to_string(),
                        metadata: crate::errors::ErrorMetadata::new(
                            crate::errors::ErrorSeverity::High,
                            crate::errors::ErrorCategory::Configuration,
                            false,
                        )
                        .with_context("field", "jwt.secret"),
                        source: None,
                    }));
                }

                if let Some(ref secret) = self.jwt.secret {
                    if secret.len() < 32 {
                        return Err(Box::new(AsyncApiError::Configuration {
                            message: "JWT secret should be at least 32 characters long".to_string(),
                            metadata: crate::errors::ErrorMetadata::new(
                                crate::errors::ErrorSeverity::High,
                                crate::errors::ErrorCategory::Configuration,
                                false,
                            )
                            .with_context("field", "jwt.secret"),
                            source: None,
                        }));
                    }
                }
            }
            JwtAlgorithm::RS256 => {
                if self.jwt.public_key_pem.is_none() {
                    return Err(Box::new(AsyncApiError::Configuration {
                        message: "RSA public key is required for RS256 algorithm".to_string(),
                        metadata: crate::errors::ErrorMetadata::new(
                            crate::errors::ErrorSeverity::High,
                            crate::errors::ErrorCategory::Configuration,
                            false,
                        )
                        .with_context("field", "jwt.public_key_pem"),
                        source: None,
                    }));
                }
            }
        }

        // Validate expiration time
        if self.jwt.expires_in == 0 {
            return Err(Box::new(AsyncApiError::Configuration {
                message: "JWT expiration time must be greater than 0".to_string(),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Configuration,
                    false,
                )
                .with_context("field", "jwt.expires_in"),
                source: None,
            }));
        }

        // Validate rate limiting configuration
        if let Some(ref rate_limit) = self.rate_limiting {
            if rate_limit.max_attempts == 0 {
                return Err(Box::new(AsyncApiError::Configuration {
                    message: "Rate limit max_attempts must be greater than 0".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Configuration,
                        false,
                    )
                    .with_context("field", "rate_limiting.max_attempts"),
                    source: None,
                }));
            }

            if rate_limit.window_seconds == 0 {
                return Err(Box::new(AsyncApiError::Configuration {
                    message: "Rate limit window_seconds must be greater than 0".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Configuration,
                        false,
                    )
                    .with_context("field", "rate_limiting.window_seconds"),
                    source: None,
                }));
            }
        }

        // Validate session configuration
        if let Some(ref session) = self.session {
            if session.timeout_seconds == 0 {
                return Err(Box::new(AsyncApiError::Configuration {
                    message: "Session timeout must be greater than 0".to_string(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Configuration,
                        false,
                    )
                    .with_context("field", "session.timeout_seconds"),
                    source: None,
                }));
            }

            if let Some(max_sessions) = session.max_concurrent_sessions {
                if max_sessions == 0 {
                    return Err(Box::new(AsyncApiError::Configuration {
                        message: "Max concurrent sessions must be greater than 0".to_string(),
                        metadata: crate::errors::ErrorMetadata::new(
                            crate::errors::ErrorSeverity::High,
                            crate::errors::ErrorCategory::Configuration,
                            false,
                        )
                        .with_context("field", "session.max_concurrent_sessions"),
                        source: None,
                    }));
                }
            }
        }

        Ok(())
    }

    /// Create configuration from environment variables
    pub fn from_env() -> AsyncApiResult<Self> {
        let mut config = Self::default();

        // JWT configuration
        if let Ok(secret) = std::env::var("JWT_SECRET") {
            config.jwt.secret = Some(secret);
            config.jwt.algorithm = JwtAlgorithm::HS256;
        }

        if let Ok(private_key) = std::env::var("JWT_PRIVATE_KEY_PEM") {
            config.jwt.private_key_pem = Some(private_key);
            config.jwt.algorithm = JwtAlgorithm::RS256;
        }

        if let Ok(public_key) = std::env::var("JWT_PUBLIC_KEY_PEM") {
            config.jwt.public_key_pem = Some(public_key);
            if config.jwt.private_key_pem.is_none() {
                config.jwt.algorithm = JwtAlgorithm::RS256;
            }
        }

        if let Ok(issuer) = std::env::var("JWT_ISSUER") {
            config.jwt.issuer = Some(issuer);
        }

        if let Ok(audience) = std::env::var("JWT_AUDIENCE") {
            config.jwt.audience = Some(audience);
        }

        if let Ok(expires_in) = std::env::var("JWT_EXPIRES_IN") {
            config.jwt.expires_in =
                expires_in
                    .parse()
                    .map_err(|e| Box::new(AsyncApiError::Configuration {
                        message: format!("Invalid JWT_EXPIRES_IN value: {}", e),
                        metadata: crate::errors::ErrorMetadata::new(
                            crate::errors::ErrorSeverity::High,
                            crate::errors::ErrorCategory::Configuration,
                            false,
                        )
                        .with_context("field", "JWT_EXPIRES_IN"),
                        source: Some(Box::new(e)),
                    }))?;
        }

        // Rate limiting configuration
        if let Ok(max_attempts) = std::env::var("AUTH_RATE_LIMIT_MAX_ATTEMPTS") {
            if let Some(ref mut rate_limit) = config.rate_limiting {
                rate_limit.max_attempts =
                    max_attempts
                        .parse()
                        .map_err(|e| Box::new(AsyncApiError::Configuration {
                            message: format!("Invalid AUTH_RATE_LIMIT_MAX_ATTEMPTS value: {}", e),
                            metadata: crate::errors::ErrorMetadata::new(
                                crate::errors::ErrorSeverity::High,
                                crate::errors::ErrorCategory::Configuration,
                                false,
                            )
                            .with_context("field", "AUTH_RATE_LIMIT_MAX_ATTEMPTS"),
                            source: Some(Box::new(e)),
                        }))?;
            }
        }

        // Anonymous access
        if let Ok(allow_anon) = std::env::var("AUTH_ALLOW_ANONYMOUS") {
            config.allow_anonymous = allow_anon.to_lowercase() == "true";
        }

        config.validate()?;
        Ok(config)
    }

    /// Get the rate limit window as Duration
    pub fn rate_limit_window(&self) -> Option<Duration> {
        self.rate_limiting
            .as_ref()
            .map(|rl| Duration::from_secs(rl.window_seconds))
    }

    /// Get the rate limit lockout duration as Duration
    pub fn rate_limit_lockout(&self) -> Option<Duration> {
        self.rate_limiting
            .as_ref()
            .map(|rl| Duration::from_secs(rl.lockout_seconds))
    }

    /// Get the session timeout as Duration
    pub fn session_timeout(&self) -> Option<Duration> {
        self.session
            .as_ref()
            .map(|s| Duration::from_secs(s.timeout_seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuthConfig::default();
        assert!(config.validate().is_err()); // Should fail without secret
    }

    #[test]
    fn test_hmac_config() {
        let config = AuthConfig::new()
            .with_jwt_secret("this-is-a-very-long-secret-key-for-testing".to_string());

        assert!(config.validate().is_ok());
        assert_eq!(config.jwt.algorithm, JwtAlgorithm::HS256);
    }

    #[test]
    fn test_config_validation() {
        // Test short secret
        let config = AuthConfig::new().with_jwt_secret("short".to_string());
        assert!(config.validate().is_err());

        // Test zero expiration
        let mut config = AuthConfig::new()
            .with_jwt_secret("this-is-a-very-long-secret-key-for-testing".to_string());
        config.jwt.expires_in = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_builder_pattern() {
        let config = AuthConfig::new()
            .with_jwt_secret("this-is-a-very-long-secret-key-for-testing".to_string())
            .with_issuer("test-issuer".to_string())
            .with_audience("test-audience".to_string())
            .with_required_role("admin".to_string())
            .allow_anonymous();

        assert!(config.validate().is_ok());
        assert_eq!(config.jwt.issuer, Some("test-issuer".to_string()));
        assert_eq!(config.jwt.audience, Some("test-audience".to_string()));
        assert!(config.required_roles.contains(&"admin".to_string()));
        assert!(config.allow_anonymous);
    }
}
`}
        </File>
    );
}

//! Basic Authentication validator for HTTP Basic Auth

use crate::auth::Claims;
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use base64::{Engine as _, engine::general_purpose};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};
use async_trait::async_trait;

/// Basic authentication validator
#[derive(Debug)]
pub struct BasicAuthValidator {
    /// User credentials store (username -> password hash)
    user_store: HashMap<String, UserCredentials>,
    /// Default issuer for generated claims
    issuer: String,
    /// Default audience for generated claims
    audience: String,
}

/// User credentials with additional metadata
#[derive(Debug, Clone)]
pub struct UserCredentials {
    /// Password hash (bcrypt recommended)
    pub password_hash: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions/scopes
    pub scopes: Vec<String>,
    /// Whether the user account is active
    pub active: bool,
    /// Additional user metadata
    pub metadata: HashMap<String, String>,
}

impl BasicAuthValidator {
    /// Create a new basic auth validator
    pub fn new(issuer: String, audience: String) -> Self {
        Self {
            user_store: HashMap::new(),
            issuer,
            audience,
        }
    }

    /// Add a user to the credential store
    pub fn add_user(&mut self, username: String, credentials: UserCredentials) {
        self.user_store.insert(username, credentials);
    }

    /// Add a user with plain text password (will be hashed)
    pub fn add_user_with_password(
        &mut self,
        username: String,
        password: &str,
        roles: Vec<String>,
        scopes: Vec<String>,
    ) -> AsyncApiResult<()> {
        let password_hash = self.hash_password(password)?;
        let credentials = UserCredentials {
            password_hash,
            roles,
            scopes,
            active: true,
            metadata: HashMap::new(),
        };
        self.add_user(username, credentials);
        Ok(())
    }

    /// Hash a password using bcrypt
    fn hash_password(&self, password: &str) -> AsyncApiResult<String> {
        // In a real implementation, use bcrypt or similar
        // For now, we'll use a simple hash (NOT SECURE - for demo only)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        password.hash(&mut hasher);
        Ok(format!("hash_{result}", result = hasher.finish()))
    }

    /// Verify a password against a hash
    fn verify_password(&self, password: &str, hash: &str) -> AsyncApiResult<bool> {
        let computed_hash = self.hash_password(password)?;
        Ok(computed_hash == hash)
    }

    /// Extract credentials from Authorization header
    pub fn extract_basic_credentials(auth_header: &str) -> AsyncApiResult<(String, String)> {
        if !auth_header.starts_with("Basic ") {
            return Err(Box::new(AsyncApiError::Authentication {
                message: "Authorization header must start with 'Basic '".to_string(),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        let encoded = &auth_header[6..]; // Remove "Basic " prefix
        if encoded.is_empty() {
            return Err(Box::new(AsyncApiError::Authentication {
                message: "Empty basic auth credentials".to_string(),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        let decoded = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| Box::new(AsyncApiError::Authentication {
                message: format!("Invalid base64 encoding in basic auth: {e}"),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?;

        let credentials = String::from_utf8(decoded)
            .map_err(|e| Box::new(AsyncApiError::Authentication {
                message: format!("Invalid UTF-8 in basic auth credentials: {e}"),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?;

        let parts: Vec<&str> = credentials.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(Box::new(AsyncApiError::Authentication {
                message: "Invalid basic auth format, expected 'username:password'".to_string(),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    /// Validate basic auth credentials and return claims
    pub async fn validate_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> AsyncApiResult<Claims> {
        debug!("Validating basic auth credentials for user: {}", username);

        let user_creds = self.user_store.get(username)
            .ok_or_else(|| Box::new(AsyncApiError::Authentication {
                message: format!("User '{username}' not found"),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }))?;

        if !user_creds.active {
            return Err(Box::new(AsyncApiError::Authentication {
                message: format!("User '{username}' account is disabled"),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        if !self.verify_password(password, &user_creds.password_hash)? {
            warn!("Invalid password for user: {username}");
            return Err(Box::new(AsyncApiError::Authentication {
                message: "Invalid credentials".to_string(),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        // Create claims for authenticated user
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Box::new(AsyncApiError::Authentication {
                message: format!("Failed to get current time: {e}"),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?
            .as_secs();

        let mut claims = Claims {
            sub: username.to_string(),
            iat: now,
            exp: now + 3600, // 1 hour expiration
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            roles: user_creds.roles.clone(),
            scopes: user_creds.scopes.clone(),
            custom: serde_json::Map::new(),
        };

        // Add user metadata as custom claims
        for (key, value) in &user_creds.metadata {
            claims.custom.insert(
                key.clone(),
                serde_json::Value::String(value.clone())
            );
        }

        debug!(
            user = %username,
            roles = ?user_creds.roles,
            scopes = ?user_creds.scopes,
            "Basic auth validation successful"
        );

        Ok(claims)
    }

    /// Validate Authorization header with Basic auth
    pub async fn validate_auth_header(&self, auth_header: &str) -> AsyncApiResult<Claims> {
        let (username, password) = Self::extract_basic_credentials(auth_header)?;
        self.validate_credentials(&username, &password).await
    }
}

/// Trait for custom user stores
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Get user credentials by username
    async fn get_user(&self, username: &str) -> AsyncApiResult<Option<UserCredentials>>;

    /// Verify user password
    async fn verify_password(&self, username: &str, password: &str) -> AsyncApiResult<bool>;
}

/// Basic auth validator with custom user store
pub struct CustomBasicAuthValidator<T: UserStore> {
    user_store: T,
    issuer: String,
    audience: String,
}

impl<T: UserStore> CustomBasicAuthValidator<T> {
    /// Create validator with custom user store
    pub fn new(user_store: T, issuer: String, audience: String) -> Self {
        Self {
            user_store,
            issuer,
            audience,
        }
    }

    /// Validate credentials using custom user store
    pub async fn validate_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> AsyncApiResult<Claims> {
        debug!("Validating basic auth credentials with custom store for user: {}", username);

        let user_creds = self.user_store.get_user(username).await?
            .ok_or_else(|| Box::new(AsyncApiError::Authentication {
                message: format!("User '{username}' not found"),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }))?;

        if !user_creds.active {
            return Err(Box::new(AsyncApiError::Authentication {
                message: format!("User '{username}' account is disabled"),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        if !self.user_store.verify_password(username, password).await? {
            warn!("Invalid password for user: {}", username);
            return Err(Box::new(AsyncApiError::Authentication {
                message: "Invalid credentials".to_string(),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        // Create claims (similar to BasicAuthValidator)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Box::new(AsyncApiError::Authentication {
                message: format!("Failed to get current time: {e}"),
                auth_method: "basic".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?
            .as_secs();

        let mut claims = Claims {
            sub: username.to_string(),
            iat: now,
            exp: now + 3600,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            roles: user_creds.roles.clone(),
            scopes: user_creds.scopes.clone(),
            custom: serde_json::Map::new(),
        };

        // Add user metadata as custom claims
        for (key, value) in &user_creds.metadata {
            claims.custom.insert(
                key.clone(),
                serde_json::Value::String(value.clone())
            );
        }

        debug!(
            user = %username,
            roles = ?user_creds.roles,
            scopes = ?user_creds.scopes,
            "Custom basic auth validation successful"
        );

        Ok(claims)
    }

    /// Validate Authorization header with custom user store
    pub async fn validate_auth_header(&self, auth_header: &str) -> AsyncApiResult<Claims> {
        let (username, password) = BasicAuthValidator::extract_basic_credentials(auth_header)?;
        self.validate_credentials(&username, &password).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_basic_credentials() {
        // Test valid credentials
        let auth_header = "Basic dXNlcjpwYXNz"; // user:pass in base64
        let result = BasicAuthValidator::extract_basic_credentials(auth_header);
        assert!(result.is_ok());
        let (username, password) = result.unwrap();
        assert_eq!(username, "user");
        assert_eq!(password, "pass");

        // Test invalid format
        let invalid_header = "Bearer token123";
        let result = BasicAuthValidator::extract_basic_credentials(invalid_header);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_basic_auth_validation() {
        let mut validator = BasicAuthValidator::new(
            "test-issuer".to_string(),
            "test-audience".to_string()
        );

        // Add test user
        validator.add_user_with_password(
            "testuser".to_string(),
            "testpass",
            vec!["user".to_string()],
            vec!["read:messages".to_string()]
        ).unwrap();

        // Test valid credentials
        let claims = validator.validate_credentials("testuser", "testpass").await;
        assert!(claims.is_ok());
        let claims = claims.unwrap();
        assert_eq!(claims.sub, "testuser");
        assert!(claims.roles.contains(&"user".to_string()));
        assert!(claims.scopes.contains(&"read:messages".to_string()));

        // Test invalid credentials
        let result = validator.validate_credentials("testuser", "wrongpass").await;
        assert!(result.is_err());

        // Test non-existent user
        let result = validator.validate_credentials("nonexistent", "pass").await;
        assert!(result.is_err());
    }
}

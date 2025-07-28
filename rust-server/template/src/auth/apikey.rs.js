/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function AuthApiKeyRs() {
    return (
        <File name="apikey.rs">
            {`//! API Key Authentication validator

use crate::auth::Claims;
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};
use async_trait::async_trait;

/// API Key location in the request
#[derive(Debug, Clone, PartialEq)]
pub enum ApiKeyLocation {
    /// API key in header
    Header(String),
    /// API key in query parameter
    Query(String),
    /// API key in cookie
    Cookie(String),
}

impl ApiKeyLocation {
    /// Create header location
    pub fn header(name: &str) -> Self {
        Self::Header(name.to_string())
    }

    /// Create query parameter location
    pub fn query(name: &str) -> Self {
        Self::Query(name.to_string())
    }

    /// Create cookie location
    pub fn cookie(name: &str) -> Self {
        Self::Cookie(name.to_string())
    }

    /// Get the parameter name
    pub fn param_name(&self) -> &str {
        match self {
            Self::Header(name) | Self::Query(name) | Self::Cookie(name) => name,
        }
    }
}

/// API Key credentials with metadata
#[derive(Debug, Clone)]
pub struct ApiKeyCredentials {
    /// The API key value (hashed for security)
    pub key_hash: String,
    /// Associated user ID
    pub user_id: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions/scopes
    pub scopes: Vec<String>,
    /// Whether the API key is active
    pub active: bool,
    /// Key expiration timestamp (None = never expires)
    pub expires_at: Option<u64>,
    /// Rate limit per hour (None = no limit)
    pub rate_limit: Option<u32>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// API Key authentication validator
#[derive(Debug)]
pub struct ApiKeyValidator {
    /// API key store (key_hash -> credentials)
    key_store: HashMap<String, ApiKeyCredentials>,
    /// Where to look for the API key
    location: ApiKeyLocation,
    /// Default issuer for generated claims
    issuer: String,
    /// Default audience for generated claims
    audience: String,
}

impl ApiKeyValidator {
    /// Create a new API key validator
    pub fn new(location: ApiKeyLocation, issuer: String, audience: String) -> Self {
        Self {
            key_store: HashMap::new(),
            location,
            issuer,
            audience,
        }
    }

    /// Add an API key to the store
    pub fn add_api_key(&mut self, api_key: String, credentials: ApiKeyCredentials) {
        let key_hash = self.hash_api_key(&api_key);
        self.key_store.insert(key_hash, credentials);
    }

    /// Add an API key with basic information
    pub fn add_api_key_simple(
        &mut self,
        api_key: String,
        user_id: String,
        roles: Vec<String>,
        scopes: Vec<String>,
    ) {
        let credentials = ApiKeyCredentials {
            key_hash: self.hash_api_key(&api_key),
            user_id,
            roles,
            scopes,
            active: true,
            expires_at: None,
            rate_limit: None,
            metadata: HashMap::new(),
        };
        self.add_api_key(api_key, credentials);
    }

    /// Hash an API key for secure storage
    fn hash_api_key(&self, api_key: &str) -> String {
        // In a real implementation, use a proper hash function like SHA-256
        // For now, we'll use a simple hash (NOT SECURE - for demo only)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        api_key.hash(&mut hasher);
        format!("apikey_{result}", result = hasher.finish())
    }

    /// Extract API key from request based on configured location
    pub fn extract_api_key(&self, headers: &HashMap<String, String>) -> AsyncApiResult<String> {
        match &self.location {
            ApiKeyLocation::Header(header_name) => {
                headers.get(header_name)
                    .cloned()
                    .ok_or_else(|| Box::new(AsyncApiError::Authentication {
                        message: format!("Missing API key in header '{header_name}'"),
                        auth_method: "api_key".to_string(),
                        metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
                        source: None,
                    }))
            }
            ApiKeyLocation::Query(param_name) => {
                // For query parameters, we'd need to parse the URL
                // This is a simplified implementation
                headers.get(&format!("query_{param_name}"))
                    .cloned()
                    .ok_or_else(|| Box::new(AsyncApiError::Authentication {
                        message: format!("Missing API key in query parameter '{param_name}'"),
                        auth_method: "api_key".to_string(),
                        metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
                        source: None,
                    }))
            }
            ApiKeyLocation::Cookie(cookie_name) => {
                // For cookies, we'd need to parse the Cookie header
                // This is a simplified implementation
                if let Some(cookie_header) = headers.get("cookie") {
                    self.extract_cookie_value(cookie_header, cookie_name)
                } else {
                    Err(Box::new(AsyncApiError::Authentication {
                        message: format!("Missing API key in cookie '{cookie_name}'"),
                        auth_method: "api_key".to_string(),
                        metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
                        source: None,
                    }))
                }
            }
        }
    }

    /// Extract a specific cookie value from Cookie header
    fn extract_cookie_value(&self, cookie_header: &str, cookie_name: &str) -> AsyncApiResult<String> {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(eq_pos) = cookie.find('=') {
                let name = cookie[..eq_pos].trim();
                let value = cookie[eq_pos + 1..].trim();
                if name == cookie_name {
                    return Ok(value.to_string());
                }
            }
        }

        Err(Box::new(AsyncApiError::Authentication {
            message: format!("Cookie '{cookie_name}' not found"),
            auth_method: "api_key".to_string(),
            source: None,
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
        }))
    }

    /// Validate an API key and return claims
    pub async fn validate_api_key(&self, api_key: &str) -> AsyncApiResult<Claims> {
        debug!("Validating API key");

        let key_hash = self.hash_api_key(api_key);
        let key_creds = self.key_store.get(&key_hash)
            .ok_or_else(|| Box::new(AsyncApiError::Authentication {
                message: "Invalid API key".to_string(),
                auth_method: "api_key".to_string(),
                source: None,
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
            }))?;

        if !key_creds.active {
            return Err(Box::new(AsyncApiError::Authentication {
                message: "API key is disabled".to_string(),
                auth_method: "api_key".to_string(),
                source: None,
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
            }));
        }

        // Check expiration
        if let Some(expires_at) = key_creds.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| Box::new(AsyncApiError::Authentication {
                    message: format!("Failed to get current time: {e}"),
                    auth_method: "api_key".to_string(),
                    source: Some(Box::new(e)),
                    metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Security, false),
                }))?
                .as_secs();

            if now >= expires_at {
                return Err(Box::new(AsyncApiError::Authentication {
                    message: "API key has expired".to_string(),
                    auth_method: "api_key".to_string(),
                    source: None,
                    metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
                }));
            }
        }

        // Create claims for authenticated API key
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Box::new(AsyncApiError::Authentication {
                message: format!("Failed to get current time: {e}"),
                auth_method: "api_key".to_string(),
                source: Some(Box::new(e)),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Security, false),
            }))?
            .as_secs();

        let mut claims = Claims {
            sub: key_creds.user_id.clone(),
            iat: now,
            exp: key_creds.expires_at.unwrap_or(now + 86400), // Default 24h if no expiration
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            roles: key_creds.roles.clone(),
            scopes: key_creds.scopes.clone(),
            custom: serde_json::Map::new(),
        };

        // Add API key metadata as custom claims
        for (key, value) in &key_creds.metadata {
            claims.custom.insert(
                key.clone(),
                serde_json::Value::String(value.clone())
            );
        }

        // Add API key specific claims
        claims.custom.insert(
            "auth_method".to_string(),
            serde_json::Value::String("api_key".to_string())
        );

        if let Some(rate_limit) = key_creds.rate_limit {
            claims.custom.insert(
                "rate_limit".to_string(),
                serde_json::Value::Number(serde_json::Number::from(rate_limit))
            );
        }

        debug!(
            user_id = %key_creds.user_id,
            roles = ?key_creds.roles,
            scopes = ?key_creds.scopes,
            "API key validation successful"
        );

        Ok(claims)
    }

    /// Validate API key from request headers
    pub async fn validate_from_headers(&self, headers: &HashMap<String, String>) -> AsyncApiResult<Claims> {
        let api_key = self.extract_api_key(headers)?;
        self.validate_api_key(&api_key).await
    }

    /// Get the location where this validator looks for API keys
    pub fn location(&self) -> &ApiKeyLocation {
        &self.location
    }
}

/// Trait for custom API key stores
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Get API key credentials by key hash
    async fn get_api_key(&self, key_hash: &str) -> AsyncApiResult<Option<ApiKeyCredentials>>;

    /// Check if an API key is valid and active
    async fn is_key_valid(&self, api_key: &str) -> AsyncApiResult<bool>;

    /// Record API key usage for rate limiting
    async fn record_usage(&self, key_hash: &str) -> AsyncApiResult<()>;
}

/// API key validator with custom store
pub struct CustomApiKeyValidator<T: ApiKeyStore> {
    key_store: T,
    location: ApiKeyLocation,
    issuer: String,
    audience: String,
}

impl<T: ApiKeyStore> CustomApiKeyValidator<T> {
    /// Create validator with custom API key store
    pub fn new(key_store: T, location: ApiKeyLocation, issuer: String, audience: String) -> Self {
        Self {
            key_store,
            location,
            issuer,
            audience,
        }
    }

    /// Hash an API key (same as ApiKeyValidator)
    fn hash_api_key(&self, api_key: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        api_key.hash(&mut hasher);
        format!("apikey_{result}", result = hasher.finish())
    }

    /// Extract API key from request (same as ApiKeyValidator)
    pub fn extract_api_key(&self, headers: &HashMap<String, String>) -> AsyncApiResult<String> {
        match &self.location {
            ApiKeyLocation::Header(header_name) => {
                headers.get(header_name)
                    .cloned()
                    .ok_or_else(|| Box::new(AsyncApiError::Authentication {
                        message: format!("Missing API key in header '{header_name}'"),
                        auth_method: "api_key".to_string(),
                        source: None,
                        metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
                    }))
            }
            ApiKeyLocation::Query(param_name) => {
                headers.get(&format!("query_{param_name}"))
                    .cloned()
                    .ok_or_else(|| Box::new(AsyncApiError::Authentication {
                        message: format!("Missing API key in query parameter '{param_name}'"),
                        auth_method: "api_key".to_string(),
                        source: None,
                        metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
                    }))
            }
            ApiKeyLocation::Cookie(cookie_name) => {
                if let Some(cookie_header) = headers.get("cookie") {
                    self.extract_cookie_value(cookie_header, cookie_name)
                } else {
                    Err(Box::new(AsyncApiError::Authentication {
                        message: format!("Missing API key in cookie '{cookie_name}'"),
                        auth_method: "api_key".to_string(),
                        source: None,
                        metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
                    }))
                }
            }
        }
    }

    /// Extract cookie value (same as ApiKeyValidator)
    fn extract_cookie_value(&self, cookie_header: &str, cookie_name: &str) -> AsyncApiResult<String> {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(eq_pos) = cookie.find('=') {
                let name = cookie[..eq_pos].trim();
                let value = cookie[eq_pos + 1..].trim();
                if name == cookie_name {
                    return Ok(value.to_string());
                }
            }
        }

        Err(Box::new(AsyncApiError::Authentication {
            message: format!("Cookie '{cookie_name}' not found"),
            auth_method: "api_key".to_string(),
            source: None,
                        metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
        }))
    }

    /// Validate API key using custom store
    pub async fn validate_api_key(&self, api_key: &str) -> AsyncApiResult<Claims> {
        debug!("Validating API key with custom store");

        if !self.key_store.is_key_valid(api_key).await? {
            return Err(Box::new(AsyncApiError::Authentication {
                message: "Invalid or inactive API key".to_string(),
                auth_method: "api_key".to_string(),
                source: None,
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
            }));
        }

        let key_hash = self.hash_api_key(api_key);
        let key_creds = self.key_store.get_api_key(&key_hash).await?
            .ok_or_else(|| Box::new(AsyncApiError::Authentication {
                message: "API key not found".to_string(),
                auth_method: "api_key".to_string(),
                source: None,
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Security, false),
            }))?;

        // Record usage for rate limiting
        self.key_store.record_usage(&key_hash).await?;

        // Create claims (similar to ApiKeyValidator)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Box::new(AsyncApiError::Authentication {
                message: format!("Failed to get current time: {e}"),
                auth_method: "api_key".to_string(),
                source: Some(Box::new(e)),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Security, false),
            }))?
            .as_secs();

        let mut claims = Claims {
            sub: key_creds.user_id.clone(),
            iat: now,
            exp: key_creds.expires_at.unwrap_or(now + 86400),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            roles: key_creds.roles.clone(),
            scopes: key_creds.scopes.clone(),
            custom: serde_json::Map::new(),
        };

        // Add metadata as custom claims
        for (key, value) in &key_creds.metadata {
            claims.custom.insert(
                key.clone(),
                serde_json::Value::String(value.clone())
            );
        }

        claims.custom.insert(
            "auth_method".to_string(),
            serde_json::Value::String("api_key".to_string())
        );

        debug!(
            user_id = %key_creds.user_id,
            roles = ?key_creds.roles,
            scopes = ?key_creds.scopes,
            "Custom API key validation successful"
        );

        Ok(claims)
    }

    /// Validate API key from request headers using custom store
    pub async fn validate_from_headers(&self, headers: &HashMap<String, String>) -> AsyncApiResult<Claims> {
        let api_key = self.extract_api_key(headers)?;
        self.validate_api_key(&api_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_location() {
        let header_loc = ApiKeyLocation::header("X-API-Key");
        assert_eq!(header_loc.param_name(), "X-API-Key");

        let query_loc = ApiKeyLocation::query("api_key");
        assert_eq!(query_loc.param_name(), "api_key");

        let cookie_loc = ApiKeyLocation::cookie("auth_token");
        assert_eq!(cookie_loc.param_name(), "auth_token");
    }

    #[tokio::test]
    async fn test_api_key_validation() {
        let mut validator = ApiKeyValidator::new(
            ApiKeyLocation::header("X-API-Key"),
            "test-issuer".to_string(),
            "test-audience".to_string()
        );

        // Add test API key
        validator.add_api_key_simple(
            "test-key-123".to_string(),
            "user123".to_string(),
            vec!["api_user".to_string()],
            vec!["read:data".to_string()]
        );

        // Test valid API key
        let claims = validator.validate_api_key("test-key-123").await;
        assert!(claims.is_ok());
        let claims = claims.unwrap();
        assert_eq!(claims.sub, "user123");
        assert!(claims.roles.contains(&"api_user".to_string()));
        assert!(claims.scopes.contains(&"read:data".to_string()));

        // Test invalid API key
        let result = validator.validate_api_key("invalid-key").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_api_key_from_headers() {
        let validator = ApiKeyValidator::new(
            ApiKeyLocation::header("X-API-Key"),
            "test-issuer".to_string(),
            "test-audience".to_string()
        );

        let mut headers = HashMap::new();
        headers.insert("X-API-Key".to_string(), "test-key-123".to_string());

        let result = validator.extract_api_key(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-key-123");

        // Test missing header
        let empty_headers = HashMap::new();
        let result = validator.extract_api_key(&empty_headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_cookie_value() {
        let validator = ApiKeyValidator::new(
            ApiKeyLocation::cookie("auth_token"),
            "test-issuer".to_string(),
            "test-audience".to_string()
        );

        let cookie_header = "session_id=abc123; auth_token=xyz789; theme=dark";
        let result = validator.extract_cookie_value(cookie_header, "auth_token");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "xyz789");

        // Test missing cookie
        let result = validator.extract_cookie_value(cookie_header, "missing_cookie");
        assert!(result.is_err());
    }
}
`}
        </File>
    );
}

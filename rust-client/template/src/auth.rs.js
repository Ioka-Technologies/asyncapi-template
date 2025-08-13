/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    return (
        <File name="auth.rs">
            {`//! Authentication support for the NATS client

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Authentication credentials for different auth types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCredentials {
    /// JWT Bearer token
    pub jwt: Option<String>,
    /// Basic authentication credentials
    pub basic: Option<BasicAuth>,
    /// API Key authentication
    pub apikey: Option<ApiKeyAuth>,
}

/// Basic authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

/// API Key authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyAuth {
    pub key: String,
    pub name: String,
}

/// Auth-related error types
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("JWT token must be a non-empty string")]
    InvalidJwt,

    #[error("Basic auth requires both username and password")]
    InvalidBasicAuth,

    #[error("API key auth requires both key and name")]
    InvalidApiKey,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Unauthorized access")]
    Unauthorized,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
}

impl AuthCredentials {
    /// Create new JWT credentials
    pub fn jwt(token: impl Into<String>) -> Self {
        Self {
            jwt: Some(token.into()),
            basic: None,
            apikey: None,
        }
    }

    /// Create new Basic auth credentials
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            jwt: None,
            basic: Some(BasicAuth {
                username: username.into(),
                password: password.into(),
            }),
            apikey: None,
        }
    }

    /// Create new API key credentials for header
    pub fn apikey_header(name: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            jwt: None,
            basic: None,
            apikey: Some(ApiKeyAuth {
                key: key.into(),
                name: name.into(),
            }),
        }
    }

    /// Check if any credentials are provided
    pub fn has_credentials(&self) -> bool {
        self.jwt.is_some() || self.basic.is_some() || self.apikey.is_some()
    }

    /// Get the auth type as a string
    pub fn auth_type(&self) -> Option<&'static str> {
        if self.jwt.is_some() {
            Some("jwt")
        } else if self.basic.is_some() {
            Some("basic")
        } else if self.apikey.is_some() {
            Some("apikey")
        } else {
            None
        }
    }

    /// Validate the credentials
    pub fn validate(&self) -> Result<(), AuthError> {
        if let Some(ref jwt) = self.jwt {
            if jwt.trim().is_empty() {
                return Err(AuthError::InvalidJwt);
            }
        }

        if let Some(ref basic) = self.basic {
            if basic.username.is_empty() || basic.password.is_empty() {
                return Err(AuthError::InvalidBasicAuth);
            }
        }

        if let Some(ref apikey) = self.apikey {
            if apikey.key.is_empty() || apikey.name.is_empty() {
                return Err(AuthError::InvalidApiKey);
            }
        }

        Ok(())
    }
}

/// Generate authentication headers based on credentials
pub fn generate_auth_headers(auth: &AuthCredentials) -> HashMap<String, String> {
    let mut headers = HashMap::new();

    if let Some(ref jwt) = auth.jwt {
        headers.insert("Authorization".to_string(), format!("Bearer {}", jwt));
    } else if let Some(ref basic) = auth.basic {
        let credentials = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", basic.username, basic.password));
        headers.insert("Authorization".to_string(), format!("Basic {}", credentials));
    } else if let Some(ref apikey) = auth.apikey {
        headers.insert(apikey.name.clone(), apikey.key.clone());
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_credentials() {
        let auth = AuthCredentials::jwt("test-token");
        assert!(auth.has_credentials());
        assert_eq!(auth.auth_type(), Some("jwt"));
        assert!(auth.validate().is_ok());

        let headers = generate_auth_headers(&auth);
        assert_eq!(headers.get("Authorization"), Some(&"Bearer test-token".to_string()));
    }

    #[test]
    fn test_basic_credentials() {
        let auth = AuthCredentials::basic("user", "pass");
        assert!(auth.has_credentials());
        assert_eq!(auth.auth_type(), Some("basic"));
        assert!(auth.validate().is_ok());

        let headers = generate_auth_headers(&auth);
        let expected = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("user:pass"));
        assert_eq!(headers.get("Authorization"), Some(&expected));
    }

    #[test]
    fn test_apikey_header_credentials() {
        let auth = AuthCredentials::apikey_header("X-API-Key", "secret");
        assert!(auth.has_credentials());
        assert_eq!(auth.auth_type(), Some("apikey"));
        assert!(auth.validate().is_ok());

        let headers = generate_auth_headers(&auth);
        assert_eq!(headers.get("X-API-Key"), Some(&"secret".to_string()));
    }

    #[test]
    fn test_empty_credentials() {
        let auth = AuthCredentials {
            jwt: None,
            basic: None,
            apikey: None,
        };
        assert!(!auth.has_credentials());
        assert_eq!(auth.auth_type(), None);
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_invalid_jwt() {
        let auth = AuthCredentials::jwt("");
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_invalid_basic() {
        let auth = AuthCredentials::basic("", "pass");
        assert!(auth.validate().is_err());

        let auth = AuthCredentials::basic("user", "");
        assert!(auth.validate().is_err());
    }
}
`}
        </File>
    );
};

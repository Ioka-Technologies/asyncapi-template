/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function AuthJwtRs() {
    return (
        <File name="jwt.rs">
            {`//! JWT token validation and claims handling

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// Supported HMAC JWT algorithms
#[derive(Debug, Clone, Copy)]
pub enum JwtHMACAlgorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
}

impl std::fmt::Display for JwtHMACAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let algorithm_str = match self {
            JwtHMACAlgorithm::HS256 => "HS256",
            JwtHMACAlgorithm::HS384 => "HS384",
            JwtHMACAlgorithm::HS512 => "HS512",
        };
        write!(f, "{algorithm_str}")
    }
}

impl JwtHMACAlgorithm {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            JwtHMACAlgorithm::HS256 => "HS256",
            JwtHMACAlgorithm::HS384 => "HS384",
            JwtHMACAlgorithm::HS512 => "HS512",
        }
    }

    /// Convert to jsonwebtoken Algorithm
    pub fn to_jsonwebtoken_algorithm(&self) -> Algorithm {
        match self {
            JwtHMACAlgorithm::HS256 => Algorithm::HS256,
            JwtHMACAlgorithm::HS384 => Algorithm::HS384,
            JwtHMACAlgorithm::HS512 => Algorithm::HS512,
        }
    }
}

/// Supported RSA/ECDSA JWT algorithms
#[derive(Debug, Clone, Copy)]
pub enum JwtRSAAlgorithm {
    /// RSA using SHA-256
    RS256,
    /// RSA using SHA-384
    RS384,
    /// RSA using SHA-512
    RS512,
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
}

impl std::fmt::Display for JwtRSAAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let algorithm_str = match self {
            JwtRSAAlgorithm::RS256 => "RS256",
            JwtRSAAlgorithm::RS384 => "RS384",
            JwtRSAAlgorithm::RS512 => "RS512",
            JwtRSAAlgorithm::ES256 => "ES256",
            JwtRSAAlgorithm::ES384 => "ES384",
        };
        write!(f, "{algorithm_str}")
    }
}

impl JwtRSAAlgorithm {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            JwtRSAAlgorithm::RS256 => "RS256",
            JwtRSAAlgorithm::RS384 => "RS384",
            JwtRSAAlgorithm::RS512 => "RS512",
            JwtRSAAlgorithm::ES256 => "ES256",
            JwtRSAAlgorithm::ES384 => "ES384",
        }
    }

    /// Convert to jsonwebtoken Algorithm
    pub fn to_jsonwebtoken_algorithm(&self) -> Algorithm {
        match self {
            JwtRSAAlgorithm::RS256 => Algorithm::RS256,
            JwtRSAAlgorithm::RS384 => Algorithm::RS384,
            JwtRSAAlgorithm::RS512 => Algorithm::RS512,
            JwtRSAAlgorithm::ES256 => Algorithm::ES256,
            JwtRSAAlgorithm::ES384 => Algorithm::ES384,
        }
    }
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Issued at timestamp
    pub iat: u64,
    /// Expiration timestamp
    pub exp: u64,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// User roles
    pub roles: Vec<String>,
    /// OAuth2/OIDC scopes (unified authorization mechanism)
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Custom claims
    #[serde(flatten)]
    pub custom: serde_json::Map<String, serde_json::Value>,
}

impl Claims {
    /// Create new claims with expiration
    pub fn new(
        user_id: String,
        issuer: String,
        audience: String,
        expires_in_seconds: u64,
    ) -> AsyncApiResult<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Box::new(AsyncApiError::Authentication {
                message: format!("Failed to get current time: {e}"),
                auth_method: "jwt".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?
            .as_secs();

        Ok(Self {
            sub: user_id,
            iat: now,
            exp: now + expires_in_seconds,
            iss: issuer,
            aud: audience,
            roles: Vec::new(),
            scopes: Vec::new(),
            custom: serde_json::Map::new(),
        })
    }

    /// Add a role to the claims
    pub fn with_role(mut self, role: String) -> Self {
        self.roles.push(role);
        self
    }

    /// Add multiple roles to the claims
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles.extend(roles);
        self
    }


    /// Add a custom claim
    pub fn with_custom_claim<T: Serialize>(
        mut self,
        key: String,
        value: T,
    ) -> AsyncApiResult<Self> {
        let json_value =
            serde_json::to_value(value).map_err(|e| Box::new(AsyncApiError::Authentication {
                message: format!("Failed to serialize custom claim: {e}"),
                auth_method: "jwt".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Security,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?;
        self.custom.insert(key, json_value);
        Ok(self)
    }

    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.exp <= now
    }

    /// Check if the claims contain a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }

    /// Check if the claims contain any of the specified roles
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|role| self.has_role(role))
    }

    /// Check if the claims contain all of the specified roles
    pub fn has_all_roles(&self, roles: &[&str]) -> bool {
        roles.iter().all(|role| self.has_role(role))
    }


    /// Check if the claims contain a specific scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(&scope.to_string())
    }

    /// Check if the claims contain any of the specified scopes
    pub fn has_any_scope(&self, scopes: &[&str]) -> bool {
        scopes.iter().any(|scope| self.has_scope(scope))
    }

    /// Check if the claims contain all of the specified scopes
    pub fn has_all_scopes(&self, scopes: &[&str]) -> bool {
        scopes.iter().all(|scope| self.has_scope(scope))
    }

    /// Add a scope to the claims
    pub fn with_scope(mut self, scope: String) -> Self {
        self.scopes.push(scope);
        self
    }

    /// Add multiple scopes to the claims
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes.extend(scopes);
        self
    }

    /// Check if the claims have access to the required scope
    /// This method supports wildcard matching for hierarchical scopes.
    pub fn has_access(&self, required_scope: &str) -> bool {
        // Check exact scope match
        if self.has_scope(required_scope) {
            return true;
        }

        // Check wildcard scopes
        for scope in &self.scopes {
            if scope.ends_with(":*") {
                let prefix = &scope[..scope.len() - 1]; // Remove the '*'
                if required_scope.starts_with(prefix) {
                    return true;
                }
            }
            // Super admin wildcard
            if scope == "*:*" {
                return true;
            }
        }

        false
    }

    /// Check if the claims have any of the required accesses
    pub fn has_any_access(&self, required_scopes: &[&str]) -> bool {
        required_scopes.iter().any(|scope| self.has_access(scope))
    }

    /// Check if the claims have all of the required accesses
    pub fn has_all_access(&self, required_scopes: &[&str]) -> bool {
        required_scopes.iter().all(|scope| self.has_access(scope))
    }

    /// Get a custom claim value
    pub fn get_custom_claim<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> AsyncApiResult<Option<T>> {
        match self.custom.get(key) {
            Some(value) => {
                let result = serde_json::from_value(value.clone()).map_err(|e| {
                    Box::new(AsyncApiError::Authentication {
                        message: format!("Failed to deserialize custom claim '{key}': {e}"),
                        auth_method: "jwt".to_string(),
                        metadata: ErrorMetadata::new(
                            ErrorSeverity::Medium,
                            ErrorCategory::Security,
                            false,
                        ),
                        source: Some(Box::new(e)),
                    })
                })?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }
}

/// JWT token validator
pub struct JwtValidator {
    decoding_key: DecodingKey,
    validation: Validation,
    encoding_key: Option<EncodingKey>,
    hmac_algorithm: Option<JwtHMACAlgorithm>,
    rsa_algorithm: Option<JwtRSAAlgorithm>,
}

impl std::fmt::Debug for JwtValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtValidator")
            .field("validation", &self.validation)
            .field("has_encoding_key", &self.encoding_key.is_some())
            .field("hmac_algorithm", &self.hmac_algorithm)
            .field("rsa_algorithm", &self.rsa_algorithm)
            .finish()
    }
}

impl JwtValidator {
    /// Create a new JWT validator with HMAC secret
    pub fn new_hmac(secret: &[u8], algorithm: JwtHMACAlgorithm) -> Self {
        let mut validation = Validation::new(algorithm.to_jsonwebtoken_algorithm());
        validation.validate_exp = true;
        validation.validate_aud = false; // We'll validate audience manually if needed

        Self {
            decoding_key: DecodingKey::from_secret(secret),
            validation,
            encoding_key: Some(EncodingKey::from_secret(secret)),
            hmac_algorithm: Some(algorithm),
            rsa_algorithm: None,
        }
    }

    /// Create a new JWT validator with RSA public key
    pub fn new_rsa_public(public_key_pem: &[u8], algorithm: JwtRSAAlgorithm) -> AsyncApiResult<Self> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem).map_err(|e| {
                Box::new(AsyncApiError::Authentication {
                    message: format!("Invalid RSA public key: {e}"),
                    auth_method: "rsa".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Security,
                        false,
                    ),
                    source: Some(Box::new(e)),
                })
        })?;

        let mut validation = Validation::new(algorithm.to_jsonwebtoken_algorithm());
        validation.validate_exp = true;
        validation.validate_aud = false;

        Ok(Self {
            decoding_key,
            validation,
            encoding_key: None,
            hmac_algorithm: None,
            rsa_algorithm: Some(algorithm),
        })
    }

    /// Create a new JWT validator with RSA key pair
    pub fn new_rsa_keypair(private_key_pem: &[u8], public_key_pem: &[u8], algorithm: JwtRSAAlgorithm) -> AsyncApiResult<Self> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem).map_err(|e| {
            Box::new(AsyncApiError::Authentication {
                message: format!("Invalid RSA public key: {e}"),
                auth_method: "rsa".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: Some(Box::new(e)),
            })
        })?;

        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem).map_err(|e| {
            Box::new(AsyncApiError::Authentication {
                message: format!("Invalid RSA private key: {e}"),
                auth_method: "rsa".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: Some(Box::new(e)),
            })
        })?;

        let mut validation = Validation::new(algorithm.to_jsonwebtoken_algorithm());
        validation.validate_exp = true;
        validation.validate_aud = false;

        Ok(Self {
            decoding_key,
            validation,
            encoding_key: Some(encoding_key),
            hmac_algorithm: None,
            rsa_algorithm: Some(algorithm),
        })
    }

    /// Set required audience for validation
    pub fn with_audience(mut self, audience: String) -> Self {
        self.validation.validate_aud = true;
        self.validation.aud = Some(HashSet::from([audience]));
        self
    }

    /// Set required issuer for validation
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.validation.validate_exp = true;
        self.validation.iss = Some(HashSet::from([issuer]));
        self
    }

    /// Set leeway for time-based validations (in seconds)
    pub fn with_leeway(mut self, leeway_seconds: u64) -> Self {
        self.validation.leeway = leeway_seconds;
        self
    }

    /// Validate and decode a JWT token
    pub fn validate_token(&self, token: &str) -> AsyncApiResult<Claims> {
        debug!("Validating JWT token");

        let token_data =
            decode::<Claims>(token, &self.decoding_key, &self.validation).map_err(|e| {
                warn!("JWT validation failed: {}", e);
                Box::new(AsyncApiError::Authentication {
                    message: format!("Invalid JWT token: {e}"),
                    auth_method: "jwt".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Security,
                        false,
                    ),
                    source: Some(Box::new(e)),
                })
            })?;

        let claims = token_data.claims;

        // Additional custom validations
        if claims.is_expired() {
            return Err(Box::new(AsyncApiError::Authentication {
                message: "Token has expired".to_string(),
                auth_method: "jwt".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        debug!("JWT token validated successfully for user: {}", claims.sub);
        Ok(claims)
    }

    /// Generate a new JWT token (requires encoding key)
    pub fn generate_token(&self, claims: &Claims) -> AsyncApiResult<String> {
        let encoding_key =
            self.encoding_key
                .as_ref()
                .ok_or_else(|| Box::new(AsyncApiError::Authentication {
                    message: "No encoding key available for token generation".to_string(),
                    auth_method: "jwt".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Security,
                        false,
                    ),
                    source: None,
                }))?;

        let _header = Header::new(Algorithm::HS256); // Default to HS256, will be overridden for RSA

        // Note: EncodingKey doesn't expose its internal structure for pattern matching
        // We'll determine the algorithm based on the validation algorithm instead
        let algorithm = self.validation.algorithms.first().copied().unwrap_or(Algorithm::HS256);
        let header = Header::new(algorithm);

        encode(&header, claims, encoding_key).map_err(|e| Box::new(AsyncApiError::Authentication {
            message: format!("Failed to generate JWT token: {e}"),
            auth_method: "jwt".to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::Security,
                false,
            ),
            source: Some(Box::new(e)),
        }))
    }

    /// Extract token from Authorization header
    pub fn extract_bearer_token(auth_header: &str) -> AsyncApiResult<&str> {
        if !auth_header.starts_with("Bearer ") {
            return Err(Box::new(AsyncApiError::Authentication {
                message: "Authorization header must start with 'Bearer '".to_string(),
                auth_method: "bearer".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        let token = &auth_header[7..]; // Remove "Bearer " prefix
        if token.is_empty() {
            return Err(Box::new(AsyncApiError::Authentication {
                message: "Empty bearer token".to_string(),
                auth_method: "bearer".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: None,
            }));
        }

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_creation() {
        let claims = Claims::new(
            "user123".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600,
        )
        .unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.iss, "test-issuer");
        assert_eq!(claims.aud, "test-audience");
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_role_scopes() {
        let claims = Claims::new(
            "user123".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600,
        )
        .unwrap()
        .with_role("admin".to_string())
        .with_scope("read:users".to_string());

        assert!(claims.has_role("admin"));
        assert!(!claims.has_role("user"));
        assert!(claims.has_scope("read:users"));
        assert!(!claims.has_scope("write:users"));
        assert!(claims.has_access("read:users"));
    }

    #[test]
    fn test_jwt_hmac_roundtrip() {
        let secret = b"test-secret-key";
        let validator = JwtValidator::new_hmac(secret, JwtHMACAlgorithm::HS256);

        let claims = Claims::new(
            "user123".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600,
        )
        .unwrap();

        let token = validator.generate_token(&claims).unwrap();
        let decoded_claims = validator.validate_token(&token).unwrap();

        assert_eq!(claims.sub, decoded_claims.sub);
        assert_eq!(claims.iss, decoded_claims.iss);
        assert_eq!(claims.aud, decoded_claims.aud);
    }

    #[test]
    fn test_bearer_token_extraction() {
        let auth_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
        let token = JwtValidator::extract_bearer_token(auth_header).unwrap();
        assert_eq!(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

        let invalid_header = "Basic dXNlcjpwYXNz";
        assert!(JwtValidator::extract_bearer_token(invalid_header).is_err());
    }
}
`}
        </File>
    );
}

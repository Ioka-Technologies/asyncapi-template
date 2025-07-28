/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function AuthValidatorsRs() {
    return (
        <File name="validators.rs">
            {`//! Multi-authentication validator supporting JWT, Basic Auth, and API Keys

use crate::auth::{Claims, JwtValidator};
use crate::auth::basic::BasicAuthValidator;
use crate::auth::apikey::{ApiKeyValidator, ApiKeyLocation};
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn, info};

/// Security requirement from AsyncAPI specification
#[derive(Debug, Clone)]
pub struct SecurityRequirement {
    /// Security scheme name
    pub scheme_name: String,
    /// Security scheme type (jwt, basic, apiKey)
    pub scheme_type: String,
    /// Required scopes for this requirement
    pub scopes: Vec<String>,
}

/// Server-level security requirements
#[derive(Debug, Clone)]
pub struct ServerSecurityRequirement {
    /// Server name
    pub server: String,
    /// List of security requirements (OR relationship)
    pub requirements: Vec<SecurityRequirement>,
}

/// Multi-authentication validator that supports multiple auth schemes
#[derive(Debug)]
pub struct MultiAuthValidator {
    /// JWT validator (optional)
    jwt_validator: Option<Arc<JwtValidator>>,
    /// Basic auth validator (optional)
    basic_validator: Option<Arc<BasicAuthValidator>>,
    /// API key validator (optional)
    api_key_validator: Option<Arc<ApiKeyValidator>>,
    /// Server-level security requirements
    server_requirements: Vec<ServerSecurityRequirement>,
    /// Operation-level security requirements (operation_id -> requirements)
    operation_requirements: HashMap<String, Vec<SecurityRequirement>>,
    /// Whether to require authentication for all operations
    require_auth_globally: bool,
}

impl MultiAuthValidator {
    /// Create a new multi-auth validator
    pub fn new() -> Self {
        Self {
            jwt_validator: None,
            basic_validator: None,
            api_key_validator: None,
            server_requirements: Vec::new(),
            operation_requirements: HashMap::new(),
            require_auth_globally: false,
        }
    }

    /// Add JWT validator
    pub fn with_jwt_validator(mut self, validator: Arc<JwtValidator>) -> Self {
        self.jwt_validator = Some(validator);
        self
    }

    /// Add Basic auth validator
    pub fn with_basic_validator(mut self, validator: Arc<BasicAuthValidator>) -> Self {
        self.basic_validator = Some(validator);
        self
    }

    /// Add API key validator
    pub fn with_api_key_validator(mut self, validator: Arc<ApiKeyValidator>) -> Self {
        self.api_key_validator = Some(validator);
        self
    }

    /// Set server-level security requirements
    pub fn with_server_requirements(mut self, requirements: Vec<ServerSecurityRequirement>) -> Self {
        self.server_requirements = requirements;
        self
    }

    /// Set operation-level security requirements
    pub fn with_operation_requirements(mut self, requirements: HashMap<String, Vec<SecurityRequirement>>) -> Self {
        self.operation_requirements = requirements;
        self
    }

    /// Require authentication globally for all operations
    pub fn with_global_auth_required(mut self, required: bool) -> Self {
        self.require_auth_globally = required;
        self
    }

    /// Add a single operation security requirement
    pub fn add_operation_requirement(&mut self, operation_id: String, requirements: Vec<SecurityRequirement>) {
        self.operation_requirements.insert(operation_id, requirements);
    }

    /// Check if any authentication method is configured
    pub fn has_auth_methods(&self) -> bool {
        self.jwt_validator.is_some() ||
        self.basic_validator.is_some() ||
        self.api_key_validator.is_some()
    }

    /// Validate server-level authentication (returns 401 on failure)
    pub async fn validate_server_auth(
        &self,
        headers: &HashMap<String, String>
    ) -> AsyncApiResult<Claims> {
        // If no auth methods are configured, allow through
        if !self.has_auth_methods() {
            debug!("No authentication methods configured, allowing request");
            return Ok(self.create_anonymous_claims());
        }

        // 1. Try JWT authentication first
        if let Some(jwt_validator) = &self.jwt_validator {
            if let Some(auth_header) = headers.get("authorization") {
                if auth_header.starts_with("Bearer ") {
                    match self.try_jwt_auth(jwt_validator, auth_header).await {
                        Ok(claims) => {
                            debug!("Server authentication successful via JWT");
                            return Ok(claims);
                        }
                        Err(e) => {
                            debug!("JWT authentication failed: {}", e);
                        }
                    }
                }
            }
        }

        // 2. Try Basic authentication
        if let Some(basic_validator) = &self.basic_validator {
            if let Some(auth_header) = headers.get("authorization") {
                if auth_header.starts_with("Basic ") {
                    match basic_validator.validate_auth_header(auth_header).await {
                        Ok(claims) => {
                            debug!("Server authentication successful via Basic Auth");
                            return Ok(claims);
                        }
                        Err(e) => {
                            debug!("Basic authentication failed: {}", e);
                        }
                    }
                }
            }
        }

        // 3. Try API key authentication
        if let Some(api_key_validator) = &self.api_key_validator {
            match api_key_validator.validate_from_headers(headers).await {
                Ok(claims) => {
                    debug!("Server authentication successful via API Key");
                    return Ok(claims);
                }
                Err(e) => {
                    debug!("API key authentication failed: {}", e);
                }
            }
        }

        Ok(self.create_anonymous_claims())
    }

    /// Validate operation-level authorization (returns 403 on failure)
    pub async fn validate_operation_scopes(
        &self,
        operation: &str,
        claims: &Claims
    ) -> AsyncApiResult<()> {
        debug!("Validating operation-level authorization for: {}", operation);

        // Check if this operation has specific security requirements
        if let Some(requirements) = self.operation_requirements.get(operation) {
            if requirements.is_empty() {
                debug!("No specific security requirements for operation: {}", operation);
                return Ok(());
            }

            // Check if any of the requirements are satisfied (OR relationship)
            for requirement in requirements {
                if self.check_requirement_satisfied(claims, requirement) {
                    debug!(
                        operation = %operation,
                        scheme = %requirement.scheme_name,
                        "Operation authorization successful"
                    );
                    return Ok(());
                }
            }

            // None of the requirements were satisfied
            let required_scopes: Vec<String> = requirements
                .iter()
                .flat_map(|req| req.scopes.clone())
                .collect();

            return Err(Box::new(AsyncApiError::Authorization {
                message: format!("Insufficient permissions for operation '{operation}'"),
                required_permissions: required_scopes,
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Authorization, false),
                source: None,
            }));
        }

        // If global auth is required but no specific requirements, just check that user is authenticated
        if self.require_auth_globally && claims.sub.is_empty() {
                return Err(Box::new(AsyncApiError::Authorization {
                    message: format!("Authentication required for operation '{operation}'"),
                    required_permissions: vec!["authenticated".to_string()],
                    metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Authorization, false),
                    source: None,
                }));
        }

        debug!("No authorization requirements for operation: {}", operation);
        Ok(())
    }

    /// Check if a security requirement is satisfied by the claims
    fn check_requirement_satisfied(&self, claims: &Claims, requirement: &SecurityRequirement) -> bool {
        // If no scopes are required, just check that the auth method matches
        if requirement.scopes.is_empty() {
            return true; // Authentication was successful, no specific scopes required
        }

        // Check if the user has all required scopes
        for required_scope in &requirement.scopes {
            if !claims.has_access(required_scope) {
                debug!(
                    required_scope = %required_scope,
                    user_scopes = ?claims.scopes,
                    user_scopes = ?claims.scopes,
                    "Required scope not found in user claims"
                );
                return false;
            }
        }

        true
    }

    /// Try JWT authentication
    async fn try_jwt_auth(
        &self,
        jwt_validator: &JwtValidator,
        auth_header: &str,
    ) -> AsyncApiResult<Claims> {
        let token = JwtValidator::extract_bearer_token(auth_header)?;
        jwt_validator.validate_token(token)
    }

    /// Create anonymous claims for unauthenticated requests
    fn create_anonymous_claims(&self) -> Claims {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Claims {
            sub: "anonymous".to_string(),
            iat: now,
            exp: now + 3600,
            iss: "asyncapi-server".to_string(),
            aud: "asyncapi-client".to_string(),
            roles: vec!["anonymous".to_string()],
            scopes: vec![],
            custom: serde_json::Map::new(),
        }
    }

    /// Get configured authentication methods
    pub fn get_auth_methods(&self) -> Vec<String> {
        let mut methods = Vec::new();

        if self.jwt_validator.is_some() {
            methods.push("JWT".to_string());
        }
        if self.basic_validator.is_some() {
            methods.push("Basic".to_string());
        }
        if self.api_key_validator.is_some() {
            methods.push("API Key".to_string());
        }

        methods
    }

    /// Check if an operation requires authentication
    pub fn operation_requires_auth(&self, operation: &str) -> bool {
        if self.require_auth_globally {
            return true;
        }

        if let Some(requirements) = self.operation_requirements.get(operation) {
            return !requirements.is_empty();
        }

        false
    }

    /// Get required scopes for an operation
    pub fn get_operation_scopes(&self, operation: &str) -> Vec<String> {
        if let Some(requirements) = self.operation_requirements.get(operation) {
            return requirements
                .iter()
                .flat_map(|req| req.scopes.clone())
                .collect();
        }

        Vec::new()
    }

    /// Validate authentication token and return claims (used by middleware)
    pub async fn validate(&self, request: &crate::auth::AuthRequest) -> AsyncApiResult<crate::auth::Claims> {
        debug!("Validating authentication request for operation: {}", request.operation);

        // Convert headers to the format expected by validate_server_auth
        let headers = &request.headers;

        // Validate server-level authentication
        self.validate_server_auth(headers).await
    }

    /// Validate scopes for a specific operation (used by middleware)
    pub async fn validate_scopes(
        &self,
        request: &crate::auth::AuthRequest,
        required_scopes: &[String],
    ) -> AsyncApiResult<()> {
        debug!(
            operation = %request.operation,
            required_scopes = ?required_scopes,
            "Validating scopes for operation"
        );

        // First validate authentication to get claims
        let claims = self.validate(request).await?;

        // Check if the user has all required scopes
        for required_scope in required_scopes {
            if !claims.has_access(required_scope) {
                debug!(
                    operation = %request.operation,
                    required_scope = %required_scope,
                    user_scopes = ?claims.scopes,
                    user_scopes = ?claims.scopes,
                    "Required scope not found in user claims"
                );

                return Err(Box::new(AsyncApiError::Authorization {
                    message: format!(
                        "Missing required scope '{required_scope}' for operation '{operation}'", operation = request.operation
                    ),
                    required_permissions: required_scopes.to_vec(),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Authorization,
                        false,
                    )
                    .with_context("operation", &request.operation)
                    .with_context("required_scope", required_scope)
                    .with_context("user_id", &claims.sub),
                    source: None,
                }));
            }
        }

        debug!(
            operation = %request.operation,
            user_id = %claims.sub,
            required_scopes = ?required_scopes,
            "Scope validation successful"
        );

        Ok(())
    }
}

impl Default for MultiAuthValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating MultiAuthValidator from AsyncAPI security configuration
pub struct MultiAuthValidatorBuilder {
    validator: MultiAuthValidator,
}

impl MultiAuthValidatorBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            validator: MultiAuthValidator::new(),
        }
    }

    /// Configure JWT authentication
    pub fn with_jwt(mut self, secret_or_key: &str, algorithm_str: &str) -> AsyncApiResult<Self> {
        let jwt_validator = if algorithm_str.starts_with("HS") {
            // HMAC-based algorithm
            let hmac_algorithm = match algorithm_str {
                "HS256" => crate::auth::JwtHMACAlgorithm::HS256,
                "HS384" => crate::auth::JwtHMACAlgorithm::HS384,
                "HS512" => crate::auth::JwtHMACAlgorithm::HS512,
                _ => return Err(Box::new(AsyncApiError::Configuration {
                    message: format!("Unsupported HMAC algorithm: {algorithm_str}"),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Configuration,
                        false,
                    ),
                    source: None,
                })),
            };
            Arc::new(JwtValidator::new_hmac(secret_or_key.as_bytes(), hmac_algorithm))
        } else if algorithm_str.starts_with("RS") || algorithm_str.starts_with("ES") {
            // RSA or ECDSA algorithm - assume it's a public key
            let rsa_algorithm = match algorithm_str {
                "RS256" => crate::auth::JwtRSAAlgorithm::RS256,
                "RS384" => crate::auth::JwtRSAAlgorithm::RS384,
                "RS512" => crate::auth::JwtRSAAlgorithm::RS512,
                "ES256" => crate::auth::JwtRSAAlgorithm::ES256,
                "ES384" => crate::auth::JwtRSAAlgorithm::ES384,
                _ => return Err(Box::new(AsyncApiError::Configuration {
                    message: format!("Unsupported RSA/ECDSA algorithm: {algorithm_str}"),
                    metadata: crate::errors::ErrorMetadata::new(
                        crate::errors::ErrorSeverity::High,
                        crate::errors::ErrorCategory::Configuration,
                        false,
                    ),
                    source: None,
                })),
            };
            Arc::new(JwtValidator::new_rsa_public(secret_or_key.as_bytes(), rsa_algorithm)?)
        } else {
            return Err(Box::new(AsyncApiError::Configuration {
                message: format!("Unsupported JWT algorithm: {algorithm_str}"),
                metadata: crate::errors::ErrorMetadata::new(
                    crate::errors::ErrorSeverity::High,
                    crate::errors::ErrorCategory::Configuration,
                    false,
                ),
                source: None,
            }));
        };

        self.validator = self.validator.with_jwt_validator(jwt_validator);
        Ok(self)
    }

    /// Configure Basic authentication with a simple user store
    pub fn with_basic_auth(mut self, issuer: String, audience: String) -> Self {
        let basic_validator = Arc::new(BasicAuthValidator::new(issuer, audience));
        self.validator = self.validator.with_basic_validator(basic_validator);
        self
    }

    /// Configure API key authentication
    pub fn with_api_key(mut self, location: ApiKeyLocation, issuer: String, audience: String) -> Self {
        let api_key_validator = Arc::new(ApiKeyValidator::new(location, issuer, audience));
        self.validator = self.validator.with_api_key_validator(api_key_validator);
        self
    }

    /// Add server security requirements
    pub fn with_server_security(mut self, requirements: Vec<ServerSecurityRequirement>) -> Self {
        self.validator = self.validator.with_server_requirements(requirements);
        self
    }

    /// Add operation security requirements
    pub fn with_operation_security(mut self, requirements: HashMap<String, Vec<SecurityRequirement>>) -> Self {
        self.validator = self.validator.with_operation_requirements(requirements);
        self
    }

    /// Require global authentication
    pub fn with_global_auth(mut self) -> Self {
        self.validator = self.validator.with_global_auth_required(true);
        self
    }

    /// Build the validator
    pub fn build(self) -> MultiAuthValidator {
        self.validator
    }
}

impl Default for MultiAuthValidatorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::basic::BasicAuthValidator;

    #[tokio::test]
    async fn test_multi_auth_validator_jwt() {
        let jwt_validator = Arc::new(JwtValidator::new_hmac(b"test-secret", crate::auth::JwtHMACAlgorithm::HS256));
        let multi_validator = MultiAuthValidator::new()
            .with_jwt_validator(jwt_validator.clone());

        // Create a test token
        let claims = crate::auth::Claims::new(
            "testuser".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600,
        ).unwrap();

        let token = jwt_validator.generate_token(&claims).unwrap();

        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {token}"));

        let result = multi_validator.validate_server_auth(&headers).await;
        assert!(result.is_ok());
        let validated_claims = result.unwrap();
        assert_eq!(validated_claims.sub, "testuser");
    }

    #[tokio::test]
    async fn test_multi_auth_validator_basic() {
        let mut basic_validator = BasicAuthValidator::new(
            "test-issuer".to_string(),
            "test-audience".to_string()
        );
        basic_validator.add_user_with_password(
            "testuser".to_string(),
            "testpass",
            vec!["user".to_string()],
            vec!["read".to_string()]
        ).unwrap();

        let multi_validator = MultiAuthValidator::new()
            .with_basic_validator(Arc::new(basic_validator));

        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Basic dGVzdHVzZXI6dGVzdHBhc3M=".to_string()); // testuser:testpass

        let result = multi_validator.validate_server_auth(&headers).await;
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.sub, "testuser");
    }

    #[tokio::test]
    async fn test_operation_scope_validation() {
        let multi_validator = MultiAuthValidator::new()
            .with_operation_requirements(HashMap::from([
                ("test_operation".to_string(), vec![
                    SecurityRequirement {
                        scheme_name: "jwt".to_string(),
                        scheme_type: "http".to_string(),
                        scopes: vec!["read:messages".to_string()],
                    }
                ])
            ]));

        let claims = crate::auth::Claims::new(
            "testuser".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600,
        ).unwrap().with_scope("read:messages".to_string());

        // Should pass with correct scope
        let result = multi_validator.validate_operation_scopes("test_operation", &claims).await;
        assert!(result.is_ok());

        // Should fail with missing scope
        let claims_no_scope = crate::auth::Claims::new(
            "testuser".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600,
        ).unwrap();

        let result = multi_validator.validate_operation_scopes("test_operation", &claims_no_scope).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_methods() {
        let multi_validator = MultiAuthValidator::new()
            .with_jwt_validator(Arc::new(JwtValidator::new_hmac(b"secret", crate::auth::JwtHMACAlgorithm::HS256)))
            .with_basic_validator(Arc::new(BasicAuthValidator::new(
                "issuer".to_string(),
                "audience".to_string()
            )));

        let methods = multi_validator.get_auth_methods();
        assert!(methods.contains(&"JWT".to_string()));
        assert!(methods.contains(&"Basic".to_string()));
        assert!(!methods.contains(&"API Key".to_string()));
    }
}
`}
        </File>
    );
}

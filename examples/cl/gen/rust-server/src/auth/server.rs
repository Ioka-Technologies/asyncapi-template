//! Server-level authentication for AsyncAPI connections
//!
//! This module provides server-level authentication that acts as the first gate
//! before operation-level security checks. When a server has security requirements
//! in the AsyncAPI specification, a server auth handler must be provided.

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::{debug, warn};

/// Server-level authentication handler trait
///
/// Implement this trait to provide server-level authentication for connections.
/// This is the first authentication check that happens when a client connects
/// to a server that has security requirements in the AsyncAPI specification.
#[async_trait]
pub trait ServerAuthHandler: Send + Sync {
    /// Authenticate a connection request
    ///
    /// This method is called when a client attempts to connect to the server.
    /// It should validate the connection-level credentials and return an
    /// authentication context that will be available throughout the connection.
    async fn authenticate_connection(
        &self,
        request: &ServerAuthRequest,
    ) -> AsyncApiResult<ServerAuthContext>;

    /// Optional: Validate that the connection is still authenticated
    ///
    /// This can be called periodically to ensure the connection remains valid.
    /// Default implementation always returns true.
    async fn validate_connection(
        &self,
        context: &ServerAuthContext,
    ) -> AsyncApiResult<bool> {
        Ok(context.authenticated)
    }

    /// Optional: Handle connection termination
    ///
    /// Called when a connection is being closed, allowing cleanup of any
    /// connection-specific authentication state.
    async fn on_connection_close(&self, _context: &ServerAuthContext) -> AsyncApiResult<()> {
        Ok(())
    }
}

/// Server authentication request containing connection-level information
#[derive(Debug, Clone)]
pub struct ServerAuthRequest {
    /// HTTP-style headers (applicable to HTTP, WebSocket, etc.)
    pub headers: HashMap<String, String>,
    /// Query parameters from the connection URL
    pub query_params: HashMap<String, String>,
    /// Remote address of the connecting client
    pub remote_addr: Option<SocketAddr>,
    /// Protocol-specific authentication data
    pub protocol_data: ProtocolAuthData,
    /// Connection metadata
    pub metadata: HashMap<String, String>,
}

/// Protocol-specific authentication data
#[derive(Debug, Clone)]
pub enum ProtocolAuthData {
    /// HTTP protocol data
    Http {
        method: String,
        path: String,
        user_agent: Option<String>,
    },
    /// WebSocket protocol data
    WebSocket {
        subprotocols: Vec<String>,
        origin: Option<String>,
        user_agent: Option<String>,
    },
    /// MQTT protocol data
    Mqtt {
        client_id: String,
        username: Option<String>,
        password: Option<String>,
        clean_session: bool,
        keep_alive: u16,
    },
    /// Kafka protocol data
    Kafka {
        client_id: Option<String>,
        sasl_mechanism: Option<String>,
    },
    /// AMQP protocol data
    Amqp {
        virtual_host: Option<String>,
        username: Option<String>,
        password: Option<String>,
    },
    /// Generic protocol data for other protocols
    Generic {
        protocol: String,
        data: HashMap<String, String>,
    },
}

/// Server authentication context
///
/// This context is created after successful server-level authentication
/// and is available throughout the connection lifetime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthContext {
    /// Whether the connection is authenticated
    pub authenticated: bool,
    /// Principal identifier (user ID, client ID, etc.)
    pub principal: Option<String>,
    /// Server-level scopes granted to this connection
    pub server_scopes: Vec<String>,
    /// Session-specific data
    pub session_data: HashMap<String, serde_json::Value>,
    /// Connection metadata
    pub connection_metadata: HashMap<String, String>,
    /// Authentication timestamp
    pub authenticated_at: chrono::DateTime<chrono::Utc>,
    /// Optional expiration time for the authentication
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ServerAuthRequest {
    /// Create a new server auth request
    pub fn new(protocol_data: ProtocolAuthData) -> Self {
        Self {
            headers: HashMap::new(),
            query_params: HashMap::new(),
            remote_addr: None,
            protocol_data,
            metadata: HashMap::new(),
        }
    }

    /// Add a header to the request
    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    /// Add multiple headers to the request
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Add a query parameter to the request
    pub fn with_query_param(mut self, key: String, value: String) -> Self {
        self.query_params.insert(key, value);
        self
    }

    /// Set the remote address
    pub fn with_remote_addr(mut self, addr: SocketAddr) -> Self {
        self.remote_addr = Some(addr);
        self
    }

    /// Add metadata to the request
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Get authorization header value
    pub fn authorization_header(&self) -> Option<&String> {
        self.headers.get("authorization")
            .or_else(|| self.headers.get("Authorization"))
    }

    /// Extract bearer token from authorization header
    pub fn bearer_token(&self) -> Option<&str> {
        self.authorization_header()
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .or_else(|| self.authorization_header()
                .and_then(|auth| auth.strip_prefix("bearer ")))
    }

    /// Get API key from header or query parameter
    pub fn api_key(&self, header_name: &str, query_param_name: &str) -> Option<&String> {
        self.headers.get(header_name)
            .or_else(|| self.query_params.get(query_param_name))
    }
}

impl ServerAuthContext {
    /// Create a new authenticated server context
    pub fn authenticated(principal: String) -> Self {
        Self {
            authenticated: true,
            principal: Some(principal),
            server_scopes: Vec::new(),
            session_data: HashMap::new(),
            connection_metadata: HashMap::new(),
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
        }
    }

    /// Create an unauthenticated context
    pub fn unauthenticated() -> Self {
        Self {
            authenticated: false,
            principal: None,
            server_scopes: Vec::new(),
            session_data: HashMap::new(),
            connection_metadata: HashMap::new(),
            authenticated_at: chrono::Utc::now(),
            expires_at: None,
        }
    }

    /// Add a server-level scope
    pub fn with_scope(mut self, scope: String) -> Self {
        self.server_scopes.push(scope);
        self
    }

    /// Add multiple server-level scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.server_scopes.extend(scopes);
        self
    }

    /// Add session data
    pub fn with_session_data<T: Serialize>(
        mut self,
        key: String,
        value: T,
    ) -> AsyncApiResult<Self> {
        let json_value = serde_json::to_value(value).map_err(|e| {
            Box::new(AsyncApiError::Authentication {
                message: format!("Invalid authorization header format: {e}"),
                auth_method: "bearer".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Security,
                    false,
                ),
                source: Some(Box::new(e)),
            })
        })?;
        self.session_data.insert(key, json_value);
        Ok(self)
    }

    /// Set expiration time
    pub fn with_expiration(mut self, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Check if the context has a specific server scope
    pub fn has_server_scope(&self, scope: &str) -> bool {
        self.server_scopes.contains(&scope.to_string())
    }

    /// Check if the context has any of the specified server scopes
    pub fn has_any_server_scope(&self, scopes: &[&str]) -> bool {
        scopes.iter().any(|scope| self.has_server_scope(scope))
    }

    /// Check if the context has all of the specified server scopes
    pub fn has_all_server_scopes(&self, scopes: &[&str]) -> bool {
        scopes.iter().all(|scope| self.has_server_scope(scope))
    }

    /// Check if the authentication has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            chrono::Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Get session data value
    pub fn get_session_data<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> AsyncApiResult<Option<T>> {
        match self.session_data.get(key) {
            Some(value) => {
                let result = serde_json::from_value(value.clone()).map_err(|e| {
                    Box::new(AsyncApiError::Authentication {
                        message: format!("Failed to deserialize session data '{key}': {e}"),
                        auth_method: "session".to_string(),
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

    /// Get the principal identifier
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }
}

/// Default server auth handler that allows all connections
pub struct AllowAllServerAuthHandler;

#[async_trait]
impl ServerAuthHandler for AllowAllServerAuthHandler {
    async fn authenticate_connection(
        &self,
        _request: &ServerAuthRequest,
    ) -> AsyncApiResult<ServerAuthContext> {
        debug!("AllowAllServerAuthHandler: Allowing all connections");
        Ok(ServerAuthContext::authenticated("anonymous".to_string()))
    }
}

/// Server auth handler that rejects all connections
pub struct RejectAllServerAuthHandler;

#[async_trait]
impl ServerAuthHandler for RejectAllServerAuthHandler {
    async fn authenticate_connection(
        &self,
        _request: &ServerAuthRequest,
    ) -> AsyncApiResult<ServerAuthContext> {
        warn!("RejectAllServerAuthHandler: Rejecting connection");
        Err(Box::new(AsyncApiError::Authentication {
            message: "Server authentication required but no valid credentials provided".to_string(),
            auth_method: "required".to_string(),
            metadata: ErrorMetadata::new(
                ErrorSeverity::High,
                ErrorCategory::Security,
                false,
            ),
            source: None,
        }))
    }
}

/// JWT-based server authentication handler
pub struct JwtServerAuthHandler {
    jwt_validator: crate::auth::JwtValidator,
    required_scopes: Vec<String>,
}

impl JwtServerAuthHandler {
    /// Create a new JWT server auth handler
    pub fn new(jwt_validator: crate::auth::JwtValidator) -> Self {
        Self {
            jwt_validator,
            required_scopes: Vec::new(),
        }
    }

    /// Add required server-level scopes
    pub fn with_required_scopes(mut self, scopes: Vec<String>) -> Self {
        self.required_scopes = scopes;
        self
    }
}

#[async_trait]
impl ServerAuthHandler for JwtServerAuthHandler {
    async fn authenticate_connection(
        &self,
        request: &ServerAuthRequest,
    ) -> AsyncApiResult<ServerAuthContext> {
        // Extract JWT token from request
        let token = request
            .bearer_token()
            .or_else(|| request.query_params.get("token").map(|s| s.as_str()))
            .ok_or_else(|| {
                Box::new(AsyncApiError::Authentication {
                    message: "No JWT token provided in Authorization header or token query parameter".to_string(),
                    auth_method: "jwt".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Security,
                        false,
                    ),
                    source: None,
                })
            })?;

        // Validate the JWT token
        let claims = self.jwt_validator.validate_token(token)?;

        // Check required server-level scopes
        if !self.required_scopes.is_empty() {
            let has_required_scope = self.required_scopes.iter().any(|required_scope| {
                claims.scopes.iter().any(|user_scope| {
                    // Exact match
                    user_scope == required_scope ||
                    // Wildcard match (e.g., "server:*" matches "server:connect")
                    (user_scope.ends_with(":*") && required_scope.starts_with(&user_scope[..user_scope.len()-1])) ||
                    // Super admin wildcard
                    user_scope == "*:*"
                })
            });

            if !has_required_scope {
                return Err(Box::new(AsyncApiError::Authorization {
                    message: "Insufficient server-level permissions".to_string(),
                    required_permissions: self.required_scopes.clone(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Authorization,
                        false,
                    ),
                    source: None,
                }));
            }
        }

        debug!(
            principal = %claims.sub,
            server_scopes = ?claims.scopes,
            "JWT server authentication successful"
        );

        Ok(ServerAuthContext::authenticated(claims.sub)
            .with_scopes(claims.scopes)
            .with_expiration(
                chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                    .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1))
            ))
    }

    async fn validate_connection(
        &self,
        context: &ServerAuthContext,
    ) -> AsyncApiResult<bool> {
        Ok(context.authenticated && !context.is_expired())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_auth_request_builder() {
        let request = ServerAuthRequest::new(ProtocolAuthData::Http {
            method: "GET".to_string(),
            path: "/api/v1/test".to_string(),
            user_agent: Some("test-client".to_string()),
        })
        .with_header("Authorization".to_string(), "Bearer test-token".to_string())
        .with_query_param("api_key".to_string(), "test-key".to_string());

        assert_eq!(request.bearer_token(), Some("test-token"));
        assert_eq!(request.api_key("X-API-Key", "api_key"), Some(&"test-key".to_string()));
    }

    #[tokio::test]
    async fn test_server_auth_context() {
        let context = ServerAuthContext::authenticated("user123".to_string())
            .with_scope("server:connect".to_string())
            .with_scope("api:read".to_string());

        assert!(context.authenticated);
        assert_eq!(context.principal(), Some("user123"));
        assert!(context.has_server_scope("server:connect"));
        assert!(context.has_any_server_scope(&["server:connect", "admin:all"]));
        assert!(!context.has_all_server_scopes(&["server:connect", "admin:all"]));
        assert!(!context.is_expired());
    }

    #[tokio::test]
    async fn test_allow_all_handler() {
        let handler = AllowAllServerAuthHandler;
        let request = ServerAuthRequest::new(ProtocolAuthData::Generic {
            protocol: "test".to_string(),
            data: HashMap::new(),
        });

        let result = handler.authenticate_connection(&request).await;
        assert!(result.is_ok());

        let context = result.unwrap();
        assert!(context.authenticated);
        assert_eq!(context.principal(), Some("anonymous"));
    }

    #[tokio::test]
    async fn test_reject_all_handler() {
        let handler = RejectAllServerAuthHandler;
        let request = ServerAuthRequest::new(ProtocolAuthData::Generic {
            protocol: "test".to_string(),
            data: HashMap::new(),
        });

        let result = handler.authenticate_connection(&request).await;
        assert!(result.is_err());
    }
}

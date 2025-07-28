/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function AuthModRs() {
    return (
        <File name="mod.rs">
            {`//! Authentication and authorization module
//!
//! This module provides JWT-based authentication, role-based access control,
//! server-level authentication, and middleware for securing AsyncAPI message handlers.

pub mod config;
pub mod jwt;
pub mod rbac;
pub mod server;
pub mod basic;
pub mod apikey;
pub mod validators;

pub use config::AuthConfig;
pub use jwt::{Claims, JwtValidator, JwtHMACAlgorithm, JwtRSAAlgorithm};
pub use rbac::{Permission, Role, RoleManager};
pub use server::{
    ServerAuthHandler, ServerAuthRequest, ServerAuthContext, ProtocolAuthData,
    AllowAllServerAuthHandler, RejectAllServerAuthHandler, JwtServerAuthHandler,
};
pub use basic::{BasicAuthValidator, UserCredentials, UserStore, CustomBasicAuthValidator};
pub use apikey::{ApiKeyValidator, ApiKeyCredentials, ApiKeyLocation, ApiKeyStore, CustomApiKeyValidator};
pub use validators::{MultiAuthValidator, MultiAuthValidatorBuilder, SecurityRequirement, ServerSecurityRequirement};

/// Authentication method enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    /// Automatically detect authentication method
    Auto,
    /// JWT Bearer token authentication
    Jwt,
    /// HTTP Basic authentication
    Basic,
    /// API Key authentication
    ApiKey,
}

/// Authentication request structure
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// The operation being requested
    pub operation: String,
    /// Request headers
    pub headers: std::collections::HashMap<String, String>,
    /// Authentication method to use (or Auto for detection)
    pub method: AuthMethod,
}

impl AuthRequest {
    /// Create a new authentication request
    pub fn new(operation: String, headers: std::collections::HashMap<String, String>) -> Self {
        Self {
            operation,
            headers,
            method: AuthMethod::Auto,
        }
    }

    /// Create a new authentication request with specific method
    pub fn with_method(operation: String, headers: std::collections::HashMap<String, String>, method: AuthMethod) -> Self {
        Self {
            operation,
            headers,
            method,
        }
    }
}
`}
        </File>
    );
}

/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function AuthModRs() {
    return (
        <File name="mod.rs">
            {`//! Authentication and authorization module
//!
//! This module provides JWT-based authentication, role-based access control,
//! and middleware for securing AsyncAPI message handlers.

#[cfg(feature = "auth")]
pub mod config;
#[cfg(feature = "auth")]
pub mod jwt;
#[cfg(feature = "auth")]
pub mod middleware;
#[cfg(feature = "auth")]
pub mod rbac;

#[cfg(feature = "auth")]
pub use config::AuthConfig;
#[cfg(feature = "auth")]
pub use jwt::{Claims, JwtValidator};
#[cfg(feature = "auth")]
pub use middleware::AuthMiddleware;
#[cfg(feature = "auth")]
pub use rbac::{Permission, Role, RoleManager};

#[cfg(not(feature = "auth"))]
pub struct AuthConfig;

#[cfg(not(feature = "auth"))]
impl AuthConfig {
    pub fn new() -> Self {
        Self
    }

    pub fn validate(&self) -> crate::errors::AsyncApiResult<()> {
        Ok(())
    }
}

#[cfg(not(feature = "auth"))]
impl Clone for AuthConfig {
    fn clone(&self) -> Self {
        Self
    }
}
`}
        </File>
    );
}

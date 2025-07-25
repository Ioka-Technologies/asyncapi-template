//! Authentication and authorization module
//!
//! This module provides JWT-based authentication, role-based access control,
//! server-level authentication, and middleware for securing AsyncAPI message handlers.

pub mod config;
pub mod jwt;
pub mod middleware;
pub mod rbac;
pub mod server;

pub use config::AuthConfig;
pub use jwt::{Claims, JwtValidator};
pub use middleware::AuthMiddleware;
pub use rbac::{Permission, Role, RoleManager};
pub use server::{
    ServerAuthHandler, ServerAuthRequest, ServerAuthContext, ProtocolAuthData,
    AllowAllServerAuthHandler, RejectAllServerAuthHandler, JwtServerAuthHandler,
};

'use strict';

require('source-map-support/register');
var jsxRuntime = require('/Users/stevegraham/.nvm/versions/node/v20.0.0/lib/node_modules/@asyncapi/cli/node_modules/@asyncapi/generator-react-sdk/node_modules/react/cjs/react-jsx-runtime.production.min.js');

function AuthModRs() {
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "mod.rs",
    children: `//! Authentication and authorization module
//!
//! This module provides JWT-based authentication, role-based access control,
//! and middleware for securing AsyncAPI message handlers.

#[cfg(feature = "auth")]
pub mod jwt;
#[cfg(feature = "auth")]
pub mod middleware;
#[cfg(feature = "auth")]
pub mod rbac;
#[cfg(feature = "auth")]
pub mod config;

#[cfg(feature = "auth")]
pub use config::AuthConfig;
#[cfg(feature = "auth")]
pub use middleware::AuthMiddleware;
#[cfg(feature = "auth")]
pub use jwt::{JwtValidator, Claims};
#[cfg(feature = "auth")]
pub use rbac::{Role, Permission, RoleManager};

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
`
  });
}

module.exports = AuthModRs;
//# sourceMappingURL=mod.rs.js.map

/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function AuthRbacRs() {
    return (
        <File name="rbac.rs">
            {`//! Role-Based Access Control (RBAC) system

use crate::errors::{AsyncApiError, AsyncApiResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// A role in the RBAC system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Role {
    /// Role name
    pub name: String,
    /// Role description
    pub description: String,
    /// Permissions granted by this role
    pub permissions: HashSet<Permission>,
    /// Parent roles (for role inheritance)
    pub parent_roles: HashSet<String>,
    /// Whether this role is active
    pub active: bool,
}

impl Role {
    /// Create a new role
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            permissions: HashSet::new(),
            parent_roles: HashSet::new(),
            active: true,
        }
    }

    /// Add a permission to this role
    pub fn with_permission(mut self, permission: Permission) -> Self {
        self.permissions.insert(permission);
        self
    }

    /// Add multiple permissions to this role
    pub fn with_permissions(mut self, permissions: Vec<Permission>) -> Self {
        self.permissions.extend(permissions);
        self
    }

    /// Add a parent role for inheritance
    pub fn with_parent_role(mut self, parent_role: &str) -> Self {
        self.parent_roles.insert(parent_role.to_string());
        self
    }

    /// Check if this role has a specific permission
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Get all permissions including inherited ones
    pub fn get_all_permissions(&self, role_manager: &RoleManager) -> HashSet<Permission> {
        let mut all_permissions = self.permissions.clone();

        // Add permissions from parent roles
        for parent_name in &self.parent_roles {
            if let Some(parent_role) = role_manager.get_role(parent_name) {
                all_permissions.extend(parent_role.get_all_permissions(role_manager));
            }
        }

        all_permissions
    }
}

/// A permission in the RBAC system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Permission {
    /// Permission name (e.g., "read:users", "write:messages")
    pub name: String,
    /// Resource this permission applies to
    pub resource: String,
    /// Action this permission allows
    pub action: String,
    /// Optional conditions for this permission
    pub conditions: Option<PermissionConditions>,
}

impl Permission {
    /// Create a new permission
    pub fn new(resource: &str, action: &str) -> Self {
        Self {
            name: format!("{}:{}", action, resource),
            resource: resource.to_string(),
            action: action.to_string(),
            conditions: None,
        }
    }

    /// Create a permission with conditions
    pub fn with_conditions(mut self, conditions: PermissionConditions) -> Self {
        self.conditions = Some(conditions);
        self
    }

    /// Check if this permission matches a required permission
    pub fn matches(&self, required: &Permission) -> bool {
        // Basic name matching
        if self.name == required.name {
            return true;
        }

        // Wildcard matching
        if self.action == "*" && self.resource == required.resource {
            return true;
        }

        if self.resource == "*" && self.action == required.action {
            return true;
        }

        if self.action == "*" && self.resource == "*" {
            return true;
        }

        false
    }
}

/// Conditions that can be applied to permissions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PermissionConditions {
    /// Time-based conditions
    pub time_restrictions: Option<TimeRestrictions>,
    /// IP-based conditions
    pub ip_restrictions: Option<Vec<String>>,
    /// Custom conditions
    pub custom_conditions: HashMap<String, String>,
}

/// Time-based restrictions for permissions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TimeRestrictions {
    /// Start time (hour of day, 0-23)
    pub start_hour: Option<u8>,
    /// End time (hour of day, 0-23)
    pub end_hour: Option<u8>,
    /// Days of week (0=Sunday, 6=Saturday)
    pub allowed_days: Option<Vec<u8>>,
}

/// Role manager for RBAC operations
pub struct RoleManager {
    roles: Arc<RwLock<HashMap<String, Role>>>,
    user_roles: Arc<RwLock<HashMap<String, HashSet<String>>>>,
}

impl RoleManager {
    /// Create a new role manager
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
            user_roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a role manager with default roles
    pub async fn with_default_roles() -> Self {
        let manager = Self::new();
        manager.setup_default_roles().await;
        manager
    }

    /// Set up default roles for common use cases
    async fn setup_default_roles(&self) {
        // Admin role with all permissions
        let admin_role = Role::new("admin", "Administrator with full access")
            .with_permission(Permission::new("*", "*"));

        // User role with basic permissions
        let user_role = Role::new("user", "Regular user with basic access")
            .with_permission(Permission::new("messages", "read"))
            .with_permission(Permission::new("profile", "read"))
            .with_permission(Permission::new("profile", "write"));

        // Guest role with read-only access
        let guest_role = Role::new("guest", "Guest user with read-only access")
            .with_permission(Permission::new("messages", "read"));

        // Moderator role inheriting from user
        let moderator_role = Role::new("moderator", "Moderator with additional permissions")
            .with_parent_role("user")
            .with_permission(Permission::new("messages", "write"))
            .with_permission(Permission::new("messages", "delete"));

        self.add_role(admin_role).await.ok();
        self.add_role(user_role).await.ok();
        self.add_role(guest_role).await.ok();
        self.add_role(moderator_role).await.ok();
    }

    /// Add a role to the system
    pub async fn add_role(&self, role: Role) -> AsyncApiResult<()> {
        let mut roles = self.roles.write().await;

        if roles.contains_key(&role.name) {
            return Err(AsyncApiError::Authorization {
                message: format!("Role '{}' already exists", role.name),
                required_permissions: vec![],
                user_permissions: vec![],
            });
        }

        debug!("Adding role: {}", role.name);
        roles.insert(role.name.clone(), role);
        Ok(())
    }

    /// Get a role by name
    pub fn get_role(&self, name: &str) -> Option<Role> {
        // This is a simplified synchronous version for internal use
        // In a real implementation, you might want to use async here too
        if let Ok(roles) = self.roles.try_read() {
            roles.get(name).cloned()
        } else {
            None
        }
    }

    /// Get a role by name (async version)
    pub async fn get_role_async(&self, name: &str) -> Option<Role> {
        let roles = self.roles.read().await;
        roles.get(name).cloned()
    }

    /// Update a role
    pub async fn update_role(&self, role: Role) -> AsyncApiResult<()> {
        let mut roles = self.roles.write().await;

        if !roles.contains_key(&role.name) {
            return Err(AsyncApiError::Authorization {
                message: format!("Role '{}' does not exist", role.name),
                required_permissions: vec![],
                user_permissions: vec![],
            });
        }

        debug!("Updating role: {}", role.name);
        roles.insert(role.name.clone(), role);
        Ok(())
    }

    /// Remove a role
    pub async fn remove_role(&self, name: &str) -> AsyncApiResult<()> {
        let mut roles = self.roles.write().await;

        if roles.remove(name).is_none() {
            return Err(AsyncApiError::Authorization {
                message: format!("Role '{}' does not exist", name),
                required_permissions: vec![],
                user_permissions: vec![],
            });
        }

        debug!("Removed role: {}", name);

        // Remove role from all users
        let mut user_roles = self.user_roles.write().await;
        for user_role_set in user_roles.values_mut() {
            user_role_set.remove(name);
        }

        Ok(())
    }

    /// Assign a role to a user
    pub async fn assign_role_to_user(&self, user_id: &str, role_name: &str) -> AsyncApiResult<()> {
        // Check if role exists
        {
            let roles = self.roles.read().await;
            if !roles.contains_key(role_name) {
                return Err(AsyncApiError::Authorization {
                    message: format!("Role '{}' does not exist", role_name),
                    required_permissions: vec![],
                    user_permissions: vec![],
                });
            }
        }

        let mut user_roles = self.user_roles.write().await;
        let user_role_set = user_roles
            .entry(user_id.to_string())
            .or_insert_with(HashSet::new);
        user_role_set.insert(role_name.to_string());

        debug!("Assigned role '{}' to user '{}'", role_name, user_id);
        Ok(())
    }

    /// Remove a role from a user
    pub async fn remove_role_from_user(
        &self,
        user_id: &str,
        role_name: &str,
    ) -> AsyncApiResult<()> {
        let mut user_roles = self.user_roles.write().await;

        if let Some(user_role_set) = user_roles.get_mut(user_id) {
            user_role_set.remove(role_name);
            debug!("Removed role '{}' from user '{}'", role_name, user_id);
        }

        Ok(())
    }

    /// Get all roles for a user
    pub async fn get_user_roles(&self, user_id: &str) -> Vec<Role> {
        let user_roles = self.user_roles.read().await;
        let roles = self.roles.read().await;

        if let Some(role_names) = user_roles.get(user_id) {
            role_names
                .iter()
                .filter_map(|name| roles.get(name).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all permissions for a user (including inherited)
    pub async fn get_user_permissions(&self, user_id: &str) -> HashSet<Permission> {
        let user_roles = self.get_user_roles(user_id).await;
        let mut all_permissions = HashSet::new();

        for role in user_roles {
            all_permissions.extend(role.get_all_permissions(self));
        }

        all_permissions
    }

    /// Check if a user has a specific permission
    pub async fn user_has_permission(
        &self,
        user_id: &str,
        required_permission: &Permission,
    ) -> bool {
        let user_permissions = self.get_user_permissions(user_id).await;

        for permission in &user_permissions {
            if permission.matches(required_permission) {
                return true;
            }
        }

        false
    }

    /// Check if a user has any of the required permissions
    pub async fn user_has_any_permission(
        &self,
        user_id: &str,
        required_permissions: &[Permission],
    ) -> bool {
        for permission in required_permissions {
            if self.user_has_permission(user_id, permission).await {
                return true;
            }
        }
        false
    }

    /// Check if a user has all of the required permissions
    pub async fn user_has_all_permissions(
        &self,
        user_id: &str,
        required_permissions: &[Permission],
    ) -> bool {
        for permission in required_permissions {
            if !self.user_has_permission(user_id, permission).await {
                return false;
            }
        }
        true
    }

    /// List all roles
    pub async fn list_roles(&self) -> Vec<Role> {
        let roles = self.roles.read().await;
        roles.values().cloned().collect()
    }

    /// Get role statistics
    pub async fn get_statistics(&self) -> RoleStatistics {
        let roles = self.roles.read().await;
        let user_roles = self.user_roles.read().await;

        RoleStatistics {
            total_roles: roles.len(),
            total_users_with_roles: user_roles.len(),
            active_roles: roles.values().filter(|r| r.active).count(),
            roles_by_name: roles.keys().cloned().collect(),
        }
    }
}

impl Default for RoleManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the RBAC system
#[derive(Debug, Clone, Serialize)]
pub struct RoleStatistics {
    pub total_roles: usize,
    pub total_users_with_roles: usize,
    pub active_roles: usize,
    pub roles_by_name: Vec<String>,
}

/// Helper macros for creating permissions
#[macro_export]
macro_rules! permission {
    ($resource:expr, $action:expr) => {
        Permission::new($resource, $action)
    };
}

#[macro_export]
macro_rules! role {
    ($name:expr, $description:expr) => {
        Role::new($name, $description)
    };
    ($name:expr, $description:expr, [$($permission:expr),*]) => {
        Role::new($name, $description)
            $(.with_permission($permission))*
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_role_creation() {
        let role = Role::new("test_role", "Test role")
            .with_permission(Permission::new("messages", "read"))
            .with_permission(Permission::new("users", "write"));

        assert_eq!(role.name, "test_role");
        assert_eq!(role.permissions.len(), 2);
        assert!(role.has_permission(&Permission::new("messages", "read")));
    }

    #[tokio::test]
    async fn test_permission_matching() {
        let wildcard_permission = Permission::new("*", "read");
        let specific_permission = Permission::new("messages", "read");

        assert!(wildcard_permission.matches(&specific_permission));
        assert!(specific_permission.matches(&specific_permission));
    }

    #[tokio::test]
    async fn test_role_manager() {
        let manager = RoleManager::new();

        let role = Role::new("test_role", "Test role")
            .with_permission(Permission::new("messages", "read"));

        manager.add_role(role).await.unwrap();
        manager
            .assign_role_to_user("user1", "test_role")
            .await
            .unwrap();

        let user_roles = manager.get_user_roles("user1").await;
        assert_eq!(user_roles.len(), 1);
        assert_eq!(user_roles[0].name, "test_role");

        let has_permission = manager
            .user_has_permission("user1", &Permission::new("messages", "read"))
            .await;
        assert!(has_permission);
    }

    #[tokio::test]
    async fn test_role_inheritance() {
        let manager = RoleManager::new();

        let parent_role =
            Role::new("parent", "Parent role").with_permission(Permission::new("base", "read"));

        let child_role = Role::new("child", "Child role")
            .with_parent_role("parent")
            .with_permission(Permission::new("extra", "write"));

        manager.add_role(parent_role).await.unwrap();
        manager.add_role(child_role).await.unwrap();
        manager.assign_role_to_user("user1", "child").await.unwrap();

        // User should have permissions from both parent and child roles
        let has_parent_permission = manager
            .user_has_permission("user1", &Permission::new("base", "read"))
            .await;
        let has_child_permission = manager
            .user_has_permission("user1", &Permission::new("extra", "write"))
            .await;

        assert!(has_parent_permission);
        assert!(has_child_permission);
    }
}
`}
        </File>
    );
}

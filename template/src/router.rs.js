/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function RouterRs({ asyncapi, _params }) {
    // Get channels from the AsyncAPI spec
    const channels = asyncapi.channels();

    // Helper functions for Rust identifier generation
    function toRustIdentifier(str) {
        if (!str) return 'unknown';

        // Replace invalid characters with underscores
        let identifier = str
            .replace(/[^a-zA-Z0-9_]/g, '_')
            .replace(/^[0-9]/, '_$&') // Prefix numbers with underscore
            .replace(/_+/g, '_') // Collapse multiple underscores
            .replace(/^_+|_+$/g, ''); // Remove leading/trailing underscores

        // Ensure it doesn't start with a number
        if (/^[0-9]/.test(identifier)) {
            identifier = 'item_' + identifier;
        }

        // Ensure it's not empty
        if (!identifier) {
            identifier = 'unknown';
        }

        // Avoid Rust keywords
        const rustKeywords = [
            'as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern',
            'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match',
            'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self',
            'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe',
            'use', 'where', 'while', 'async', 'await', 'dyn'
        ];

        if (rustKeywords.includes(identifier)) {
            identifier = identifier + '_';
        }

        return identifier;
    }

    function toRustTypeName(str) {
        if (!str) return 'Unknown';

        const identifier = toRustIdentifier(str);

        // Convert to PascalCase
        return identifier
            .split('_')
            .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
            .join('');
    }

    function toRustFieldName(str) {
        if (!str) return 'unknown';

        const identifier = toRustIdentifier(str);

        // Convert to snake_case
        return identifier
            .replace(/([A-Z])/g, '_$1')
            .toLowerCase()
            .replace(/^_/, '')
            .replace(/_+/g, '_');
    }

    // Process channels and operations
    const channelData = [];
    if (channels) {
        Object.entries(channels).forEach(([channelName, channel]) => {
            const operations = [];

            // Get operations for this channel
            if (channel.operations) {
                Object.entries(channel.operations()).forEach(([opName, operation]) => {
                    operations.push({
                        name: opName,
                        rustName: toRustFieldName(opName),
                        action: operation.action && operation.action()
                    });
                });
            }

            channelData.push({
                name: channelName,
                rustName: toRustFieldName(channelName),
                typeName: toRustTypeName(channelName),
                operations
            });
        });
    }

    return (
        <File name="router.rs">
            {`//! Message routing system for AsyncAPI operations
//!
//! This module provides sophisticated message routing capabilities with:
//! - Pattern-based routing with wildcards and parameters
//! - Static route optimization for performance
//! - JSON field-based message matching
//! - Comprehensive error handling and logging
//! - Route validation and conflict detection

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Route matching strategy for different routing patterns
#[derive(Debug, Clone)]
pub enum RoutePattern {
    /// Exact string match for static routes (fastest)
    Static(String),
    /// Pattern with wildcards (* and **) and parameters (:param)
    Pattern {
        pattern: String,
        regex: Regex,
        parameters: Vec<String>,
    },
    /// JSON field-based matching for content-based routing
    JsonField {
        field_path: String,
        expected_value: Value,
    },
}

/// Route definition with pattern and target handler information
#[derive(Debug, Clone)]
pub struct Route {
    pub id: String,
    pub pattern: RoutePattern,
    pub channel: String,
    pub operation: String,
    pub priority: i32,
    pub description: Option<String>,
}

/// Parameters extracted from route matching
#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub route: Route,
    pub parameters: HashMap<String, String>,
    pub matched_value: Option<Value>,
}

/// High-performance message router with multiple matching strategies
#[derive(Debug)]
pub struct Router {
    /// Static routes for O(1) lookup performance
    static_routes: HashMap<String, Route>,
    /// Pattern routes with regex matching
    pattern_routes: Vec<Route>,
    /// JSON field routes for content-based routing
    json_field_routes: Vec<Route>,
    /// Route validation enabled
    validation_enabled: bool,
}

impl Router {
    /// Create a new router instance
    pub fn new() -> Self {
        Self {
            static_routes: HashMap::new(),
            pattern_routes: Vec::new(),
            json_field_routes: Vec::new(),
            validation_enabled: true,
        }
    }

    /// Initialize router with default routes from AsyncAPI specification
    pub async fn initialize_default_routes(&self) -> AsyncApiResult<()> {
        info!("Initializing default routes from AsyncAPI specification");

        // Routes are now handled by the HandlerRegistry
        // This method is kept for compatibility but routes are managed elsewhere

        info!("Default routes initialized successfully");
        Ok(())
    }

    /// Add a static route for exact string matching (highest performance)
    pub fn add_static_route(&mut self, path: &str, channel: &str, operation: &str) -> AsyncApiResult<()> {
        let route = Route {
            id: format!("static_{}_{}", channel, operation),
            pattern: RoutePattern::Static(path.to_string()),
            channel: channel.to_string(),
            operation: operation.to_string(),
            priority: 100, // Highest priority for static routes
            description: Some(format!("Static route for {}/{}", channel, operation)),
        };

        if self.validation_enabled {
            self.validate_route(&route)?;
        }

        debug!(
            route_id = %route.id,
            path = path,
            channel = channel,
            operation = operation,
            "Added static route"
        );

        self.static_routes.insert(path.to_string(), route);
        Ok(())
    }

    /// Add a pattern route with wildcards and parameters
    ///
    /// Supported patterns:
    /// - \`*\` matches any single path segment
    /// - \`**\` matches any number of path segments
    /// - \`:param\` captures a named parameter
    ///
    /// Examples:
    /// - \`users/*/profile\` matches \`users/123/profile\`
    /// - \`api/**/events\` matches \`api/v1/users/events\`
    /// - \`users/:id/posts/:post_id\` captures id and post_id parameters
    pub fn add_pattern_route(&mut self, pattern: &str, channel: &str, operation: &str) -> AsyncApiResult<()> {
        let (regex, parameters) = self.compile_pattern(pattern)?;

        let route = Route {
            id: format!("pattern_{}_{}", channel, operation),
            pattern: RoutePattern::Pattern {
                pattern: pattern.to_string(),
                regex,
                parameters,
            },
            channel: channel.to_string(),
            operation: operation.to_string(),
            priority: 50, // Medium priority for pattern routes
            description: Some(format!("Pattern route {} for {}/{}", pattern, channel, operation)),
        };

        if self.validation_enabled {
            self.validate_route(&route)?;
        }

        debug!(
            route_id = %route.id,
            pattern = pattern,
            channel = channel,
            operation = operation,
            "Added pattern route"
        );

        self.pattern_routes.push(route);
        self.pattern_routes.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(())
    }

    /// Add a JSON field-based route for content-based routing
    ///
    /// Routes messages based on JSON field values in the message payload.
    /// Useful for routing based on message type, user ID, or other content.
    ///
    /// Examples:
    /// - Field path: \`type\`, Expected value: \`"user_created"\`
    /// - Field path: \`metadata.source\`, Expected value: \`"payment_service"\`
    pub fn add_json_field_route(
        &mut self,
        field_path: &str,
        expected_value: Value,
        channel: &str,
        operation: &str,
    ) -> AsyncApiResult<()> {
        let route = Route {
            id: format!("json_{}_{}", channel, operation),
            pattern: RoutePattern::JsonField {
                field_path: field_path.to_string(),
                expected_value,
            },
            channel: channel.to_string(),
            operation: operation.to_string(),
            priority: 25, // Lower priority for JSON field routes
            description: Some(format!("JSON field route {} for {}/{}", field_path, channel, operation)),
        };

        if self.validation_enabled {
            self.validate_route(&route)?;
        }

        debug!(
            route_id = %route.id,
            field_path = field_path,
            channel = channel,
            operation = operation,
            "Added JSON field route"
        );

        self.json_field_routes.push(route);
        self.json_field_routes.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(())
    }

    /// Find the best matching route for a given path and optional JSON payload
    pub fn match_route(&self, path: &str, json_payload: Option<&Value>) -> AsyncApiResult<Option<RouteMatch>> {
        debug!(path = path, "Attempting to match route");

        // 1. Try static routes first (O(1) lookup)
        if let Some(route) = self.static_routes.get(path) {
            debug!(route_id = %route.id, "Matched static route");
            return Ok(Some(RouteMatch {
                route: route.clone(),
                parameters: HashMap::new(),
                matched_value: None,
            }));
        }

        // 2. Try pattern routes (ordered by priority)
        for route in &self.pattern_routes {
            if let RoutePattern::Pattern { regex, parameters, .. } = &route.pattern {
                if let Some(captures) = regex.captures(path) {
                    let mut route_params = HashMap::new();

                    for (i, param_name) in parameters.iter().enumerate() {
                        if let Some(capture) = captures.get(i + 1) {
                            route_params.insert(param_name.clone(), capture.as_str().to_string());
                        }
                    }

                    debug!(
                        route_id = %route.id,
                        parameters = ?route_params,
                        "Matched pattern route"
                    );

                    return Ok(Some(RouteMatch {
                        route: route.clone(),
                        parameters: route_params,
                        matched_value: None,
                    }));
                }
            }
        }

        // 3. Try JSON field routes if payload is provided
        if let Some(payload) = json_payload {
            for route in &self.json_field_routes {
                if let RoutePattern::JsonField { field_path, expected_value } = &route.pattern {
                    if let Some(field_value) = self.extract_json_field(payload, field_path) {
                        if field_value == *expected_value {
                            debug!(
                                route_id = %route.id,
                                field_path = field_path,
                                matched_value = ?field_value,
                                "Matched JSON field route"
                            );

                            return Ok(Some(RouteMatch {
                                route: route.clone(),
                                parameters: HashMap::new(),
                                matched_value: Some(field_value),
                            }));
                        }
                    }
                }
            }
        }

        debug!(path = path, "No matching route found");
        Ok(None)
    }

    /// Get all registered routes for inspection and debugging
    pub fn get_all_routes(&self) -> Vec<Route> {
        let mut routes = Vec::new();

        routes.extend(self.static_routes.values().cloned());
        routes.extend(self.pattern_routes.iter().cloned());
        routes.extend(self.json_field_routes.iter().cloned());

        routes.sort_by(|a, b| b.priority.cmp(&a.priority));
        routes
    }

    /// Remove a route by its ID
    pub fn remove_route(&mut self, route_id: &str) -> bool {
        // Try static routes
        if let Some(route) = self.static_routes.values().find(|r| r.id == route_id).cloned() {
            if let RoutePattern::Static(path) = &route.pattern {
                self.static_routes.remove(path);
                return true;
            }
        }

        // Try pattern routes
        if let Some(pos) = self.pattern_routes.iter().position(|r| r.id == route_id) {
            self.pattern_routes.remove(pos);
            return true;
        }

        // Try JSON field routes
        if let Some(pos) = self.json_field_routes.iter().position(|r| r.id == route_id) {
            self.json_field_routes.remove(pos);
            return true;
        }

        false
    }

    /// Clear all routes
    pub fn clear_routes(&mut self) {
        self.static_routes.clear();
        self.pattern_routes.clear();
        self.json_field_routes.clear();
    }

    /// Enable or disable route validation
    pub fn set_validation_enabled(&mut self, enabled: bool) {
        self.validation_enabled = enabled;
    }

    /// Compile a pattern string into a regex with parameter extraction
    fn compile_pattern(&self, pattern: &str) -> AsyncApiResult<(Regex, Vec<String>)> {
        let mut regex_pattern = String::new();
        let mut parameters = Vec::new();
        let mut chars = pattern.chars().peekable();

        regex_pattern.push('^');

        while let Some(ch) = chars.next() {
            match ch {
                '*' => {
                    if chars.peek() == Some(&'*') {
                        chars.next(); // consume second *
                        regex_pattern.push_str(".*");
                    } else {
                        regex_pattern.push_str("[^/]*");
                    }
                }
                ':' => {
                    // Extract parameter name
                    let mut param_name = String::new();
                    while let Some(&next_ch) = chars.peek() {
                        if next_ch.is_alphanumeric() || next_ch == '_' {
                            param_name.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }

                    if param_name.is_empty() {
                        return Err(Box::new(AsyncApiError::Validation {
                            message: "Empty parameter name in pattern".to_string(),
                            field: Some("pattern".to_string()),
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::Medium,
                                ErrorCategory::Validation,
                                false,
                            ),
                            source: None,
                        }));
                    }

                    parameters.push(param_name);
                    regex_pattern.push_str("([^/]+)");
                }
                '.' | '+' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\\\' => {
                    regex_pattern.push('\\\\');
                    regex_pattern.push(ch);
                }
                _ => {
                    regex_pattern.push(ch);
                }
            }
        }

        regex_pattern.push('$');

        let regex = Regex::new(&regex_pattern).map_err(|e| AsyncApiError::Validation {
            message: format!("Invalid regex pattern: {}", e),
            field: Some("pattern".to_string()),
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::Validation,
                false,
            ),
            source: Some(Box::new(e)),
        })?;

        Ok((regex, parameters))
    }

    /// Extract a field value from JSON using dot notation path
    fn extract_json_field(&self, json: &Value, field_path: &str) -> Option<Value> {
        let parts: Vec<&str> = field_path.split('.').collect();
        let mut current = json;

        for part in parts {
            match current {
                Value::Object(map) => {
                    current = map.get(part)?;
                }
                Value::Array(arr) => {
                    if let Ok(index) = part.parse::<usize>() {
                        current = arr.get(index)?;
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }

        Some(current.clone())
    }

    /// Validate a route for conflicts and correctness
    fn validate_route(&self, route: &Route) -> AsyncApiResult<()> {
        // Check for duplicate route IDs
        let all_routes = self.get_all_routes();
        if all_routes.iter().any(|r| r.id == route.id) {
            return Err(Box::new(AsyncApiError::Validation {
                message: format!("Route ID '{}' already exists", route.id),
                field: Some("route_id".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::Medium,
                    ErrorCategory::Validation,
                    false,
                ),
                source: None,
            }));
        }

        // Validate pattern syntax for pattern routes
        if let RoutePattern::Pattern { pattern, .. } = &route.pattern {
            // Pattern validation is done in compile_pattern
            self.compile_pattern(pattern)?;
        }

        Ok(())
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// JSON field matcher for content-based routing
#[derive(Debug, Clone)]
pub struct JsonFieldMatcher {
    pub field_path: String,
    pub expected_values: Vec<Value>,
    pub match_type: JsonMatchType,
}

/// Type of JSON field matching
#[derive(Debug, Clone)]
pub enum JsonMatchType {
    /// Exact value match
    Exact,
    /// Match any of the provided values
    AnyOf,
    /// Pattern matching for string values
    Pattern(Regex),
    /// Existence check (field must exist)
    Exists,
}

impl JsonFieldMatcher {
    /// Create a new exact match matcher
    pub fn exact(field_path: &str, value: Value) -> Self {
        Self {
            field_path: field_path.to_string(),
            expected_values: vec![value],
            match_type: JsonMatchType::Exact,
        }
    }

    /// Create a new "any of" matcher
    pub fn any_of(field_path: &str, values: Vec<Value>) -> Self {
        Self {
            field_path: field_path.to_string(),
            expected_values: values,
            match_type: JsonMatchType::AnyOf,
        }
    }

    /// Create a new existence matcher
    pub fn exists(field_path: &str) -> Self {
        Self {
            field_path: field_path.to_string(),
            expected_values: vec![],
            match_type: JsonMatchType::Exists,
        }
    }

    /// Check if the matcher matches the given JSON value
    pub fn matches(&self, json: &Value) -> bool {
        let field_value = self.extract_field_value(json);

        match &self.match_type {
            JsonMatchType::Exact => {
                if let Some(value) = field_value {
                    self.expected_values.first().is_some_and(|expected| value == *expected)
                } else {
                    false
                }
            }
            JsonMatchType::AnyOf => {
                if let Some(value) = field_value {
                    self.expected_values.iter().any(|expected| value == *expected)
                } else {
                    false
                }
            }
            JsonMatchType::Exists => field_value.is_some(),
            JsonMatchType::Pattern(_regex) => {
                // Pattern matching implementation would go here
                false
            }
        }
    }

    /// Extract field value using dot notation
    fn extract_field_value(&self, json: &Value) -> Option<Value> {
        let parts: Vec<&str> = self.field_path.split('.').collect();
        let mut current = json;

        for part in parts {
            match current {
                Value::Object(map) => {
                    current = map.get(part)?;
                }
                Value::Array(arr) => {
                    if let Ok(index) = part.parse::<usize>() {
                        current = arr.get(index)?;
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }

        Some(current.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_static_route_matching() {
        let mut router = Router::new();
        router.add_static_route("/users/profile", "users", "get_profile").unwrap();

        let result = router.match_route("/users/profile", None).unwrap();
        assert!(result.is_some());

        let route_match = result.unwrap();
        assert_eq!(route_match.route.channel, "users");
        assert_eq!(route_match.route.operation, "get_profile");
        assert!(route_match.parameters.is_empty());
    }

    #[test]
    fn test_pattern_route_matching() {
        let mut router = Router::new();
        router.add_pattern_route("/users/:id/posts/:post_id", "users", "get_post").unwrap();

        let result = router.match_route("/users/123/posts/456", None).unwrap();
        assert!(result.is_some());

        let route_match = result.unwrap();
        assert_eq!(route_match.route.channel, "users");
        assert_eq!(route_match.route.operation, "get_post");
        assert_eq!(route_match.parameters.get("id"), Some(&"123".to_string()));
        assert_eq!(route_match.parameters.get("post_id"), Some(&"456".to_string()));
    }

    #[test]
    fn test_json_field_matcher() {
        let matcher = JsonFieldMatcher::exact("type", json!("user_created"));
        let payload = json!({"type": "user_created", "user_id": 123});

        assert!(matcher.matches(&payload));

        let wrong_payload = json!({"type": "user_updated", "user_id": 123});
        assert!(!matcher.matches(&wrong_payload));
    }
}
`}
        </File>
    );
}

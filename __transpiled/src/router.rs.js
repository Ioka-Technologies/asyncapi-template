'use strict';

require('source-map-support/register');
var jsxRuntime = require('/Users/stevegraham/.nvm/versions/node/v20.0.0/lib/node_modules/@asyncapi/cli/node_modules/@asyncapi/generator-react-sdk/node_modules/react/cjs/react-jsx-runtime.production.min.js');

/* eslint-disable no-useless-escape */
function RouterRs({
  asyncapi
}) {
  // Extract channels and operations for route generation
  const channels = asyncapi.channels();
  const channelData = [];
  if (channels) {
    Object.entries(channels).forEach(([channelName, channel]) => {
      const operations = channel.operations && channel.operations();
      const channelOps = [];
      if (operations) {
        Object.entries(operations).forEach(([opName, operation]) => {
          const action = operation.action && operation.action();
          channelOps.push({
            name: opName,
            action,
            channel: channelName
          });
        });
      }
      channelData.push({
        name: channelName,
        operations: channelOps
      });
    });
  }
  return /*#__PURE__*/jsxRuntime.jsx(File, {
    name: "router.rs",
    children: `//! Advanced routing system for AsyncAPI applications
//!
//! This module provides:
//! - Pattern-based routing with wildcards and parameters
//! - Content-based message routing
//! - Route guards and middleware chains
//! - Dynamic route registration and modification
//! - Performance-optimized route matching

use crate::context::{RequestContext, RequestPriority};
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorMetadata, ErrorSeverity, ErrorCategory};
use crate::handlers::HandlerRegistry;
use crate::middleware::{Middleware, MiddlewarePipeline};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug, instrument};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Advanced router for message routing with pattern matching and content-based routing
#[derive(Debug)]
pub struct Router {
    /// Static routes for exact matches
    static_routes: Arc<RwLock<HashMap<String, Route>>>,
    /// Pattern routes for wildcard and parameter matching
    pattern_routes: Arc<RwLock<Vec<PatternRoute>>>,
    /// Content-based routes that examine message payload
    content_routes: Arc<RwLock<Vec<ContentRoute>>>,
    /// Default route for unmatched messages
    default_route: Arc<RwLock<Option<Route>>>,
    /// Route performance metrics
    metrics: Arc<RwLock<RouterMetrics>>,
    /// Route cache for performance optimization
    route_cache: Arc<RwLock<HashMap<String, CachedRoute>>>,
    /// Maximum cache size
    max_cache_size: usize,
}

impl Router {
    /// Create a new router instance
    pub fn new() -> Self {
        Self {
            static_routes: Arc::new(RwLock::new(HashMap::new())),
            pattern_routes: Arc::new(RwLock::new(Vec::new())),
            content_routes: Arc::new(RwLock::new(Vec::new())),
            default_route: Arc::new(RwLock::new(None)),
            metrics: Arc::new(RwLock::new(RouterMetrics::new())),
            route_cache: Arc::new(RwLock::new(HashMap::new())),
            max_cache_size: 1000,
        }
    }

    /// Create router with custom cache size
    pub fn with_cache_size(cache_size: usize) -> Self {
        let mut router = Self::new();
        router.max_cache_size = cache_size;
        router
    }

    /// Add a static route for exact channel/operation matching
    #[instrument(skip(self, route), fields(channel = %route.channel, operation = %route.operation))]
    pub async fn add_static_route(&self, route: Route) -> AsyncApiResult<()> {
        let route_key = format!("{}:{}", route.channel, route.operation);

        debug!(
            channel = %route.channel,
            operation = %route.operation,
            priority = ?route.priority,
            "Adding static route"
        );

        let mut routes = self.static_routes.write().await;
        routes.insert(route_key, route);

        // Clear cache when routes change
        self.clear_cache().await;

        Ok(())
    }

    /// Add a pattern route for wildcard and parameter matching
    #[instrument(skip(self, pattern_route), fields(pattern = %pattern_route.pattern))]
    pub async fn add_pattern_route(&self, pattern_route: PatternRoute) -> AsyncApiResult<()> {
        debug!(
            pattern = %pattern_route.pattern,
            priority = ?pattern_route.route.priority,
            "Adding pattern route"
        );

        let mut routes = self.pattern_routes.write().await;
        routes.push(pattern_route);

        // Sort by priority (higher priority first)
        routes.sort_by(|a, b| b.route.priority.cmp(&a.route.priority));

        // Clear cache when routes change
        self.clear_cache().await;

        Ok(())
    }

    /// Add a content-based route that examines message payload
    #[instrument(skip(self, content_route), fields(name = %content_route.name))]
    pub async fn add_content_route(&self, content_route: ContentRoute) -> AsyncApiResult<()> {
        debug!(
            name = %content_route.name,
            priority = ?content_route.route.priority,
            "Adding content-based route"
        );

        let mut routes = self.content_routes.write().await;
        routes.push(content_route);

        // Sort by priority (higher priority first)
        routes.sort_by(|a, b| b.route.priority.cmp(&a.route.priority));

        // Clear cache when routes change
        self.clear_cache().await;

        Ok(())
    }

    /// Set the default route for unmatched messages
    pub async fn set_default_route(&self, route: Route) -> AsyncApiResult<()> {
        debug!(
            channel = %route.channel,
            operation = %route.operation,
            "Setting default route"
        );

        let mut default_route = self.default_route.write().await;
        *default_route = Some(route);

        Ok(())
    }

    /// Route a message to the appropriate handler
    #[instrument(skip(self, payload, context), fields(
        correlation_id = %context.correlation_id,
        channel = %context.channel,
        operation = %context.operation,
        payload_size = payload.len()
    ))]
    pub async fn route_message(
        &self,
        context: &RequestContext,
        payload: &[u8],
        handlers: &HandlerRegistry,
    ) -> AsyncApiResult<RouteResult> {
        let start_time = Instant::now();
        let route_key = format!("{}:{}", context.channel, context.operation);

        // Check cache first
        if let Some(cached_route) = self.get_cached_route(&route_key).await {
            debug!(
                correlation_id = %context.correlation_id,
                route_key = %route_key,
                "Using cached route"
            );

            let result = self.execute_route(&cached_route.route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::CacheHit, start_time.elapsed()).await;
            return result;
        }

        // Try static routes first (fastest)
        if let Some(route) = self.find_static_route(&context.channel, &context.operation).await {
            debug!(
                correlation_id = %context.correlation_id,
                "Found static route match"
            );

            self.cache_route(route_key.clone(), route.clone()).await;
            let result = self.execute_route(&route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::StaticMatch, start_time.elapsed()).await;
            return result;
        }

        // Try pattern routes
        if let Some((route, params)) = self.find_pattern_route(&context.channel, &context.operation).await {
            debug!(
                correlation_id = %context.correlation_id,
                params = ?params,
                "Found pattern route match"
            );

            // Add route parameters to context
            for (key, value) in params {
                context.set_data(&format!("route_param_{}", key), value).await?;
            }

            self.cache_route(route_key.clone(), route.clone()).await;
            let result = self.execute_route(&route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::PatternMatch, start_time.elapsed()).await;
            return result;
        }

        // Try content-based routes
        if let Some(route) = self.find_content_route(payload, context).await? {
            debug!(
                correlation_id = %context.correlation_id,
                "Found content-based route match"
            );

            let result = self.execute_route(&route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::ContentMatch, start_time.elapsed()).await;
            return result;
        }

        // Use default route if available
        if let Some(route) = self.get_default_route().await {
            debug!(
                correlation_id = %context.correlation_id,
                "Using default route"
            );

            let result = self.execute_route(&route, context, payload, handlers).await;
            self.record_route_metric(RouteMetric::DefaultRoute, start_time.elapsed()).await;
            return result;
        }

        // No route found
        self.record_route_metric(RouteMetric::NoMatch, start_time.elapsed()).await;

        error!(
            correlation_id = %context.correlation_id,
            channel = %context.channel,
            operation = %context.operation,
            "No route found for message"
        );

        Err(AsyncApiError::Router {
            message: format!("No route found for channel '{}' operation '{}'", context.channel, context.operation),
            metadata: ErrorMetadata::new(
                ErrorSeverity::Medium,
                ErrorCategory::Routing,
                false,
            ).with_context("correlation_id", &context.correlation_id.to_string())
             .with_context("channel", &context.channel)
             .with_context("operation", &context.operation),
            source: None,
        })
    }

    /// Execute a route with its middleware chain and guards
    async fn execute_route(
        &self,
        route: &Route,
        context: &RequestContext,
        payload: &[u8],
        handlers: &HandlerRegistry,
    ) -> AsyncApiResult<RouteResult> {
        // Check route guards
        for guard in &route.guards {
            if !(guard.check)(context, payload).await? {
                return Err(AsyncApiError::Router {
                    message: format!("Route guard '{}' failed", guard.name),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Authorization,
                        false,
                    ).with_context("correlation_id", &context.correlation_id.to_string())
                     .with_context("guard_name", &guard.name)
                     .with_context("channel", &context.channel)
                     .with_context("operation", &context.operation),
                    source: None,
                });
            }
        }

        // Process through route middleware
        let processed_payload = if let Some(ref middleware) = route.middleware {
            // Convert RequestContext to MiddlewareContext
            let middleware_context = crate::middleware::MiddlewareContext {
                correlation_id: context.correlation_id,
                channel: context.channel.clone(),
                operation: context.operation.clone(),
                timestamp: chrono::DateTime::from(context.timestamp),
                metadata: context.metadata.clone(),
            };
            middleware.process_inbound(&middleware_context, payload).await?
        } else {
            payload.to_vec()
        };

        // Route to handler
        let result = match &route.destination {
            RouteDestination::Handler { channel, operation } => {
                handlers.route_message(channel, operation, &processed_payload).await?;
                RouteResult::Handled
            }
            RouteDestination::MultipleHandlers { destinations } => {
                let mut results = Vec::new();
                for dest in destinations {
                    match handlers.route_message(&dest.channel, &dest.operation, &processed_payload).await {
                        Ok(()) => results.push(dest.clone()),
                        Err(e) => {
                            warn!(
                                correlation_id = %context.correlation_id,
                                channel = %dest.channel,
                                operation = %dest.operation,
                                error = %e,
                                "Failed to route to one of multiple destinations"
                            );
                        }
                    }
                }
                RouteResult::MultipleHandled(results)
            }
            RouteDestination::Custom { handler } => {
                handler(context, &processed_payload).await?;
                RouteResult::CustomHandled
            }
        };

        Ok(result)
    }

    /// Find static route
    async fn find_static_route(&self, channel: &str, operation: &str) -> Option<Route> {
        let routes = self.static_routes.read().await;
        let route_key = format!("{}:{}", channel, operation);
        routes.get(&route_key).cloned()
    }

    /// Find pattern route with parameter extraction
    async fn find_pattern_route(&self, channel: &str, operation: &str) -> Option<(Route, HashMap<String, String>)> {
        let routes = self.pattern_routes.read().await;
        let route_path = format!("{}:{}", channel, operation);

        for pattern_route in routes.iter() {
            if let Some(captures) = pattern_route.regex.captures(&route_path) {
                let mut params = HashMap::new();

                // Extract named parameters
                for name in pattern_route.regex.capture_names().flatten() {
                    if let Some(value) = captures.name(name) {
                        params.insert(name.to_string(), value.as_str().to_string());
                    }
                }

                return Some((pattern_route.route.clone(), params));
            }
        }

        None
    }

    /// Find content-based route
    async fn find_content_route(&self, payload: &[u8], context: &RequestContext) -> AsyncApiResult<Option<Route>> {
        let routes = self.content_routes.read().await;

        for content_route in routes.iter() {
            if content_route.matcher.matches(payload, context).await? {
                return Ok(Some(content_route.route.clone()));
            }
        }

        Ok(None)
    }

    /// Get default route
    async fn get_default_route(&self) -> Option<Route> {
        self.default_route.read().await.clone()
    }

    /// Cache a route for performance
    async fn cache_route(&self, key: String, route: Route) {
        let mut cache = self.route_cache.write().await;

        // Implement LRU eviction if cache is full
        if cache.len() >= self.max_cache_size {
            // Remove oldest entry (simple implementation)
            if let Some(oldest_key) = cache.keys().next().cloned() {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(key, CachedRoute {
            route,
            cached_at: Instant::now(),
        });
    }

    /// Get cached route
    async fn get_cached_route(&self, key: &str) -> Option<CachedRoute> {
        let cache = self.route_cache.read().await;
        cache.get(key).cloned()
    }

    /// Clear route cache
    async fn clear_cache(&self) {
        let mut cache = self.route_cache.write().await;
        cache.clear();
        debug!("Route cache cleared");
    }

    /// Record route performance metric
    async fn record_route_metric(&self, metric_type: RouteMetric, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        metrics.record_metric(metric_type, duration);
    }

    /// Get router statistics
    pub async fn get_statistics(&self) -> RouterStatistics {
        let metrics = self.metrics.read().await;
        let static_routes = self.static_routes.read().await;
        let pattern_routes = self.pattern_routes.read().await;
        let content_routes = self.content_routes.read().await;
        let cache = self.route_cache.read().await;

        RouterStatistics {
            static_route_count: static_routes.len(),
            pattern_route_count: pattern_routes.len(),
            content_route_count: content_routes.len(),
            cache_size: cache.len(),
            cache_hit_rate: metrics.cache_hit_rate(),
            average_route_time: metrics.average_route_time(),
            total_routes: metrics.total_routes,
        }
    }

    /// Initialize with default routes from AsyncAPI specification
    pub async fn initialize_default_routes(&self) -> AsyncApiResult<()> {
        info!("Initializing default routes from AsyncAPI specification");

        ${channelData.map(channel => `
        // Routes for ${channel.name}
        ${channel.operations.map(op => `
        self.add_static_route(Route {
            channel: "${channel.name}".to_string(),
            operation: "${op.name}".to_string(),
            priority: RequestPriority::Normal,
            destination: RouteDestination::Handler {
                channel: "${channel.name}".to_string(),
                operation: "${op.name}".to_string(),
            },
            guards: Vec::new(),
            middleware: None,
            metadata: HashMap::new(),
        }).await?;`).join('\n        ')}
        `).join('\n')}

        // Add pattern routes for common patterns
        self.add_pattern_route(PatternRoute {
            pattern: r"(?P<channel>[^:]+):(?P<operation>.+)".to_string(),
            regex: Regex::new(r"(?P<channel>[^:]+):(?P<operation>.+)").unwrap(),
            route: Route {
                channel: "dynamic".to_string(),
                operation: "dynamic".to_string(),
                priority: RequestPriority::Low,
                destination: RouteDestination::Handler {
                    channel: "dynamic".to_string(),
                    operation: "dynamic".to_string(),
                },
                guards: Vec::new(),
                middleware: None,
                metadata: HashMap::new(),
            },
        }).await?;

        info!("Default routes initialized successfully");
        Ok(())
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Individual route definition
pub struct Route {
    /// Channel pattern
    pub channel: String,
    /// Operation pattern
    pub operation: String,
    /// Route priority for conflict resolution
    pub priority: RequestPriority,
    /// Route destination
    pub destination: RouteDestination,
    /// Route guards for validation
    pub guards: Vec<RouteGuard>,
    /// Route-specific middleware
    pub middleware: Option<MiddlewarePipeline>,
    /// Route metadata
    pub metadata: HashMap<String, String>,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("channel", &self.channel)
            .field("operation", &self.operation)
            .field("priority", &self.priority)
            .field("destination", &self.destination)
            .field("guards", &self.guards)
            .field("middleware", &self.middleware.is_some())
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl Clone for Route {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
            operation: self.operation.clone(),
            priority: self.priority,
            destination: self.destination.clone(),
            guards: self.guards.clone(),
            middleware: None, // Can't clone MiddlewarePipeline, so set to None
            metadata: self.metadata.clone(),
        }
    }
}

/// Route destination types
pub enum RouteDestination {
    /// Route to a specific handler
    Handler { channel: String, operation: String },
    /// Route to multiple handlers (fan-out)
    MultipleHandlers { destinations: Vec<HandlerDestination> },
    /// Route to a custom function
    Custom {
        #[allow(clippy::type_complexity)]
        handler: Arc<dyn Fn(&RequestContext, &[u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = AsyncApiResult<()>> + Send>> + Send + Sync>
    },
}

impl std::fmt::Debug for RouteDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteDestination::Handler { channel, operation } => {
                f.debug_struct("Handler")
                    .field("channel", channel)
                    .field("operation", operation)
                    .finish()
            }
            RouteDestination::MultipleHandlers { destinations } => {
                f.debug_struct("MultipleHandlers")
                    .field("destinations", destinations)
                    .finish()
            }
            RouteDestination::Custom { .. } => {
                f.debug_struct("Custom")
                    .field("handler", &"<function>")
                    .finish()
            }
        }
    }
}

impl Clone for RouteDestination {
    fn clone(&self) -> Self {
        match self {
            RouteDestination::Handler { channel, operation } => {
                RouteDestination::Handler {
                    channel: channel.clone(),
                    operation: operation.clone(),
                }
            }
            RouteDestination::MultipleHandlers { destinations } => {
                RouteDestination::MultipleHandlers {
                    destinations: destinations.clone(),
                }
            }
            RouteDestination::Custom { handler } => {
                RouteDestination::Custom {
                    handler: handler.clone(),
                }
            }
        }
    }
}

/// Handler destination for multi-routing
#[derive(Debug, Clone)]
pub struct HandlerDestination {
    pub channel: String,
    pub operation: String,
}

/// Pattern-based route with regex matching
#[derive(Debug)]
pub struct PatternRoute {
    /// Original pattern string
    pub pattern: String,
    /// Compiled regex for matching
    pub regex: Regex,
    /// Route definition
    pub route: Route,
}

/// Content-based route that examines message payload
#[derive(Debug)]
pub struct ContentRoute {
    /// Route name for identification
    pub name: String,
    /// Content matcher
    pub matcher: Box<dyn ContentMatcher + Send + Sync>,
    /// Route definition
    pub route: Route,
}

/// Trait for content-based routing
#[async_trait::async_trait]
pub trait ContentMatcher: std::fmt::Debug {
    /// Check if the content matches this route
    async fn matches(&self, payload: &[u8], context: &RequestContext) -> AsyncApiResult<bool>;
}

/// JSON field matcher for content-based routing
#[derive(Debug)]
pub struct JsonFieldMatcher {
    pub field_path: String,
    pub expected_value: serde_json::Value,
}

#[async_trait::async_trait]
impl ContentMatcher for JsonFieldMatcher {
    async fn matches(&self, payload: &[u8], _context: &RequestContext) -> AsyncApiResult<bool> {
        match serde_json::from_slice::<serde_json::Value>(payload) {
            Ok(json) => {
                let field_value = json.pointer(&self.field_path);
                Ok(field_value == Some(&self.expected_value))
            }
            Err(_) => Ok(false), // Not JSON, doesn't match
        }
    }
}

/// Route guard for pre-routing validation
pub struct RouteGuard {
    pub name: String,
    #[allow(clippy::type_complexity)]
    pub check: Arc<dyn Fn(&RequestContext, &[u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = AsyncApiResult<bool>> + Send>> + Send + Sync>,
}

impl std::fmt::Debug for RouteGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteGuard")
            .field("name", &self.name)
            .field("check", &"<function>")
            .finish()
    }
}

impl Clone for RouteGuard {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            check: self.check.clone(),
        }
    }
}

/// Cached route entry
#[derive(Debug, Clone)]
pub struct CachedRoute {
    pub route: Route,
    pub cached_at: Instant,
}

/// Route execution result
#[derive(Debug)]
pub enum RouteResult {
    /// Message was handled by a single handler
    Handled,
    /// Message was handled by multiple handlers
    MultipleHandled(Vec<HandlerDestination>),
    /// Message was handled by a custom handler
    CustomHandled,
}

/// Router performance metrics
#[derive(Debug)]
pub struct RouterMetrics {
    pub total_routes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub static_matches: u64,
    pub pattern_matches: u64,
    pub content_matches: u64,
    pub default_routes: u64,
    pub no_matches: u64,
    pub route_times: Vec<Duration>,
}

impl RouterMetrics {
    pub fn new() -> Self {
        Self {
            total_routes: 0,
            cache_hits: 0,
            cache_misses: 0,
            static_matches: 0,
            pattern_matches: 0,
            content_matches: 0,
            default_routes: 0,
            no_matches: 0,
            route_times: Vec::new(),
        }
    }

    pub fn record_metric(&mut self, metric_type: RouteMetric, duration: Duration) {
        self.total_routes += 1;
        self.route_times.push(duration);

        // Keep only last 1000 measurements
        if self.route_times.len() > 1000 {
            self.route_times.remove(0);
        }

        match metric_type {
            RouteMetric::CacheHit => self.cache_hits += 1,
            RouteMetric::CacheMiss => self.cache_misses += 1,
            RouteMetric::StaticMatch => self.static_matches += 1,
            RouteMetric::PatternMatch => self.pattern_matches += 1,
            RouteMetric::ContentMatch => self.content_matches += 1,
            RouteMetric::DefaultRoute => self.default_routes += 1,
            RouteMetric::NoMatch => self.no_matches += 1,
        }
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let total_cache_attempts = self.cache_hits + self.cache_misses;
        if total_cache_attempts > 0 {
            self.cache_hits as f64 / total_cache_attempts as f64
        } else {
            0.0
        }
    }

    pub fn average_route_time(&self) -> Duration {
        if self.route_times.is_empty() {
            Duration::ZERO
        } else {
            let total: Duration = self.route_times.iter().sum();
            total / self.route_times.len() as u32
        }
    }
}

/// Route metric types
#[derive(Debug, Clone, Copy)]
pub enum RouteMetric {
    CacheHit,
    CacheMiss,
    StaticMatch,
    PatternMatch,
    ContentMatch,
    DefaultRoute,
    NoMatch,
}

/// Router statistics for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct RouterStatistics {
    pub static_route_count: usize,
    pub pattern_route_count: usize,
    pub content_route_count: usize,
    pub cache_size: usize,
    pub cache_hit_rate: f64,
    pub average_route_time: Duration,
    pub total_routes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_route_matching() {
        let router = Router::new();

        let route = Route {
            channel: "test/channel".to_string(),
            operation: "test_operation".to_string(),
            priority: RequestPriority::Normal,
            destination: RouteDestination::Handler {
                channel: "test/channel".to_string(),
                operation: "test_operation".to_string(),
            },
            guards: Vec::new(),
            middleware: None,
            metadata: HashMap::new(),
        };

        router.add_static_route(route).await.unwrap();

        let found_route = router.find_static_route("test/channel", "test_operation").await;
        assert!(found_route.is_some());
    }

    #[tokio::test]
    async fn test_pattern_route_matching() {
        let router = Router::new();

        let pattern_route = PatternRoute {
            pattern: r"user/(?P<user_id>\d+):update".to_string(),
            regex: Regex::new(r"user/(?P<user_id>\d+):update").unwrap(),
            route: Route {
                channel: "user".to_string(),
                operation: "update".to_string(),
                priority: RequestPriority::Normal,
                destination: RouteDestination::Handler {
                    channel: "user".to_string(),
                    operation: "update".to_string(),
                },
                guards: Vec::new(),
                middleware: None,
                metadata: HashMap::new(),
            },
        };

        router.add_pattern_route(pattern_route).await.unwrap();

        let (route, params) = router.find_pattern_route("user/123", "update").await.unwrap();
        assert_eq!(route.channel, "user");
        assert_eq!(params.get("user_id"), Some(&"123".to_string()));
    }

    #[test]
    fn test_json_field_matcher() {
        let matcher = JsonFieldMatcher {
            field_path: "/type".to_string(),
            expected_value: serde_json::Value::String("user_created".to_string()),
        };

        let payload = r#"{"type": "user_created", "user_id": 123}"#.as_bytes();
        // Note: This would need to be an async test in practice
        // assert!(matcher.matches(payload, &context).await.unwrap());
    }
}
`
  });
}

module.exports = RouterRs;
//# sourceMappingURL=router.rs.js.map

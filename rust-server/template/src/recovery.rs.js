/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function RecoveryRs() {
    return (
        <File name="recovery.rs">
            {`//! Error recovery and resilience patterns for AsyncAPI operations
//!
//! This module provides:
//! - Retry mechanisms with exponential backoff
//! - Circuit breaker pattern for preventing cascade failures
//! - Bulkhead pattern for failure isolation
//! - Dead letter queue handling
//! - Graceful degradation strategies

use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Retry configuration for different operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Backoff multiplier for exponential backoff
    pub backoff_multiplier: f64,
    /// Maximum total time to spend retrying
    pub max_total_time: Duration,
    /// Jitter factor to add randomness to delays (0.0 to 1.0)
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            max_total_time: Duration::from_secs(300), // 5 minutes
            jitter_factor: 0.1,
        }
    }
}

impl RetryConfig {
    /// Create a conservative retry config for critical operations
    pub fn conservative() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 1.5,
            max_total_time: Duration::from_secs(600), // 10 minutes
            jitter_factor: 0.2,
        }
    }

    /// Create an aggressive retry config for non-critical operations
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 10,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.5,
            max_total_time: Duration::from_secs(120), // 2 minutes
            jitter_factor: 0.05,
        }
    }

    /// Create a fast retry config for real-time operations
    pub fn fast() -> Self {
        Self {
            max_attempts: 2,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(500),
            backoff_multiplier: 2.0,
            max_total_time: Duration::from_secs(5),
            jitter_factor: 0.1,
        }
    }
}

/// Retry strategy implementation with exponential backoff and jitter
pub struct RetryStrategy {
    config: RetryConfig,
    start_time: Instant,
    attempt: u32,
}

impl RetryStrategy {
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            attempt: 0,
        }
    }

    /// Execute an operation with retry logic
    pub async fn execute<F, Fut, T>(&mut self, operation: F) -> AsyncApiResult<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = AsyncApiResult<T>>,
    {
        loop {
            self.attempt += 1;

            debug!(
                attempt = self.attempt,
                max_attempts = self.config.max_attempts,
                "Executing operation with retry"
            );

            match operation().await {
                Ok(result) => {
                    if self.attempt > 1 {
                        info!(
                            attempt = self.attempt,
                            elapsed = ?self.start_time.elapsed(),
                            "Operation succeeded after retry"
                        );
                    }
                    return Ok(result);
                }
                Err(error) => {
                    // Check if we should retry
                    if !self.should_retry(&error) {
                        warn!(
                            attempt = self.attempt,
                            error = %error,
                            "Operation failed with non-retryable error"
                        );
                        return Err(error);
                    }

                    // Check if we've exceeded retry limits
                    if self.attempt >= self.config.max_attempts {
                        error!(
                            attempt = self.attempt,
                            max_attempts = self.config.max_attempts,
                            "Maximum retry attempts exceeded"
                        );
                        return Err(Box::new(AsyncApiError::Recovery {
                            message: format!(
                                "Operation failed after {} attempts: {}",
                                self.attempt, error
                            ),
                            attempts: self.attempt,
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::High,
                                ErrorCategory::Resource,
                                false,
                            ),
                            source: Some(Box::new(error)),
                        }));
                    }

                    // Check total time limit
                    if self.start_time.elapsed() >= self.config.max_total_time {
                        error!(
                            elapsed = ?self.start_time.elapsed(),
                            max_total_time = ?self.config.max_total_time,
                            "Maximum retry time exceeded"
                        );
                        return Err(Box::new(AsyncApiError::Recovery {
                            message: format!("Operation failed within time limit: {}", error),
                            attempts: self.attempt,
                            metadata: ErrorMetadata::new(
                                ErrorSeverity::High,
                                ErrorCategory::Resource,
                                false,
                            ),
                            source: Some(Box::new(error)),
                        }));
                    }

                    // Calculate delay and wait
                    let delay = self.calculate_delay();
                    warn!(
                        attempt = self.attempt,
                        delay_ms = delay.as_millis(),
                        error = %error,
                        "Operation failed, retrying after delay"
                    );

                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    fn should_retry(&self, error: &AsyncApiError) -> bool {
        // Don't retry non-retryable errors
        if !error.is_retryable() {
            return false;
        }

        // Don't retry validation or security errors
        !matches!(error.category(), ErrorCategory::Validation | ErrorCategory::Security)
    }

    fn calculate_delay(&self) -> Duration {
        let base_delay = self.config.initial_delay.as_millis() as f64
            * self.config.backoff_multiplier.powi((self.attempt - 1) as i32);

        let max_delay = self.config.max_delay.as_millis() as f64;
        let delay = base_delay.min(max_delay);

        // Add jitter to prevent thundering herd
        let jitter = delay * self.config.jitter_factor * (rand::random::<f64>() - 0.5);
        let final_delay = (delay + jitter).max(0.0) as u64;

        Duration::from_millis(final_delay)
    }

    /// Get current attempt number
    pub fn current_attempt(&self) -> u32 {
        self.attempt
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Circuit is closed, requests are allowed
    Closed,
    /// Circuit is open, requests are rejected
    Open,
    /// Circuit is half-open, testing if service has recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit
    pub failure_threshold: u32,
    /// Time to wait before transitioning from Open to HalfOpen
    pub recovery_timeout: Duration,
    /// Number of successful requests needed to close the circuit from HalfOpen
    pub success_threshold: u32,
    /// Time window for counting failures
    pub failure_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(60),
            success_threshold: 3,
            failure_window: Duration::from_secs(60),
        }
    }
}

/// Circuit breaker implementation for preventing cascade failures
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitBreakerState>>,
    failure_count: Arc<RwLock<u32>>,
    success_count: Arc<RwLock<u32>>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    last_state_change: Arc<RwLock<Instant>>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
            failure_count: Arc::new(RwLock::new(0)),
            success_count: Arc::new(RwLock::new(0)),
            last_failure_time: Arc::new(RwLock::new(None)),
            last_state_change: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Execute an operation through the circuit breaker
    pub async fn execute<F, Fut, T>(&self, operation: F) -> AsyncApiResult<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = AsyncApiResult<T>>,
    {
        // Check if circuit should transition states
        self.check_state_transition().await;

        let current_state = *self.state.read().await;

        match current_state {
            CircuitBreakerState::Open => {
                debug!("Circuit breaker is open, rejecting request");
                Err(Box::new(AsyncApiError::Resource {
                    message: "Circuit breaker is open".to_string(),
                    resource_type: "circuit_breaker".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Resource,
                        true,
                    ),
                    source: None,
                }))
            }
            CircuitBreakerState::Closed | CircuitBreakerState::HalfOpen => {
                match operation().await {
                    Ok(result) => {
                        self.record_success().await;
                        Ok(result)
                    }
                    Err(error) => {
                        self.record_failure().await;
                        Err(error)
                    }
                }
            }
        }
    }

    async fn record_success(&self) {
        let mut success_count = self.success_count.write().await;
        *success_count += 1;

        let current_state = *self.state.read().await;
        if current_state == CircuitBreakerState::HalfOpen
            && *success_count >= self.config.success_threshold {
            info!("Circuit breaker transitioning to Closed state");
            *self.state.write().await = CircuitBreakerState::Closed;
            *self.failure_count.write().await = 0;
            *success_count = 0;
            *self.last_state_change.write().await = Instant::now();
        }
    }

    async fn record_failure(&self) {
        let mut failure_count = self.failure_count.write().await;
        *failure_count += 1;
        *self.last_failure_time.write().await = Some(Instant::now());

        let current_state = *self.state.read().await;
        if current_state == CircuitBreakerState::Closed
            && *failure_count >= self.config.failure_threshold {
            warn!(
                failure_count = *failure_count,
                threshold = self.config.failure_threshold,
                "Circuit breaker transitioning to Open state"
            );
            *self.state.write().await = CircuitBreakerState::Open;
            *self.success_count.write().await = 0;
            *self.last_state_change.write().await = Instant::now();
        } else if current_state == CircuitBreakerState::HalfOpen {
            warn!("Circuit breaker transitioning back to Open state");
            *self.state.write().await = CircuitBreakerState::Open;
            *self.success_count.write().await = 0;
            *self.last_state_change.write().await = Instant::now();
        }
    }

    async fn check_state_transition(&self) {
        let current_state = *self.state.read().await;
        let last_change = *self.last_state_change.read().await;

        if current_state == CircuitBreakerState::Open
            && last_change.elapsed() >= self.config.recovery_timeout {
            info!("Circuit breaker transitioning to HalfOpen state");
            *self.state.write().await = CircuitBreakerState::HalfOpen;
            *self.last_state_change.write().await = Instant::now();
        }

        // Reset failure count if outside failure window
        if let Some(last_failure) = *self.last_failure_time.read().await {
            if last_failure.elapsed() >= self.config.failure_window {
                *self.failure_count.write().await = 0;
            }
        }
    }

    /// Get current circuit breaker state
    pub async fn state(&self) -> CircuitBreakerState {
        *self.state.read().await
    }

    /// Get current failure count
    pub async fn failure_count(&self) -> u32 {
        *self.failure_count.read().await
    }
}

/// Dead letter queue for handling unprocessable messages
#[derive(Debug)]
pub struct DeadLetterQueue {
    max_size: usize,
    messages: Arc<RwLock<Vec<DeadLetterMessage>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterMessage {
    pub id: String,
    pub original_channel: String,
    pub payload: Vec<u8>,
    pub error: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub retry_count: u32,
}

impl DeadLetterQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            messages: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a message to the dead letter queue
    pub async fn add_message(
        &self,
        channel: &str,
        payload: Vec<u8>,
        error: &AsyncApiError,
        retry_count: u32,
    ) -> AsyncApiResult<()> {
        let mut messages = self.messages.write().await;

        // Remove oldest message if at capacity
        if messages.len() >= self.max_size {
            messages.remove(0);
            warn!("Dead letter queue at capacity, removing oldest message");
        }

        let message = DeadLetterMessage {
            id: uuid::Uuid::new_v4().to_string(),
            original_channel: channel.to_string(),
            payload,
            error: error.to_string(),
            timestamp: chrono::Utc::now(),
            retry_count,
        };

        messages.push(message);
        info!(
            channel = channel,
            error = %error,
            queue_size = messages.len(),
            "Message added to dead letter queue"
        );

        Ok(())
    }

    /// Get all messages in the dead letter queue
    pub async fn get_messages(&self) -> Vec<DeadLetterMessage> {
        self.messages.read().await.clone()
    }

    /// Remove a message from the dead letter queue
    pub async fn remove_message(&self, message_id: &str) -> bool {
        let mut messages = self.messages.write().await;
        if let Some(pos) = messages.iter().position(|m| m.id == message_id) {
            messages.remove(pos);
            true
        } else {
            false
        }
    }

    /// Clear all messages from the dead letter queue
    pub async fn clear(&self) {
        let mut messages = self.messages.write().await;
        let count = messages.len();
        messages.clear();
        info!(cleared_count = count, "Dead letter queue cleared");
    }

    /// Get queue size
    pub async fn size(&self) -> usize {
        self.messages.read().await.len()
    }
}

/// Bulkhead pattern for isolating failures
#[derive(Debug)]
pub struct Bulkhead {
    name: String,
    semaphore: Arc<tokio::sync::Semaphore>,
    max_concurrent: usize,
    timeout: Duration,
}

impl Bulkhead {
    pub fn new(name: String, max_concurrent: usize, timeout: Duration) -> Self {
        Self {
            name,
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
            max_concurrent,
            timeout,
        }
    }

    /// Execute an operation within the bulkhead
    pub async fn execute<F, Fut, T>(&self, operation: F) -> AsyncApiResult<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = AsyncApiResult<T>>,
    {
        // Try to acquire permit with timeout
        let permit = match tokio::time::timeout(
            self.timeout,
            self.semaphore.acquire()
        ).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(Box::new(AsyncApiError::Resource {
                    message: format!("Bulkhead '{}' semaphore closed", self.name),
                    resource_type: "bulkhead".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::High,
                        ErrorCategory::Resource,
                        true,
                    ),
                    source: None,
                }));
            }
            Err(_) => {
                return Err(Box::new(AsyncApiError::Resource {
                    message: format!(
                        "Bulkhead '{}' timeout waiting for permit (max_concurrent: {})",
                        self.name, self.max_concurrent
                    ),
                    resource_type: "bulkhead".to_string(),
                    metadata: ErrorMetadata::new(
                        ErrorSeverity::Medium,
                        ErrorCategory::Resource,
                        true,
                    ),
                    source: None,
                }));
            }
        };

        debug!(
            bulkhead = %self.name,
            available_permits = self.semaphore.available_permits(),
            "Executing operation within bulkhead"
        );

        // Execute operation with permit held
        let result = operation().await;

        // Permit is automatically released when dropped
        drop(permit);

        result
    }

    /// Get current available permits
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// Recovery manager that coordinates all recovery strategies
#[derive(Debug)]
pub struct RecoveryManager {
    retry_configs: std::collections::HashMap<String, RetryConfig>,
    circuit_breakers: std::collections::HashMap<String, Arc<CircuitBreaker>>,
    dead_letter_queue: Arc<DeadLetterQueue>,
    bulkheads: std::collections::HashMap<String, Arc<Bulkhead>>,
}

impl RecoveryManager {
    pub fn new() -> Self {
        Self {
            retry_configs: std::collections::HashMap::new(),
            circuit_breakers: std::collections::HashMap::new(),
            dead_letter_queue: Arc::new(DeadLetterQueue::new(1000)),
            bulkheads: std::collections::HashMap::new(),
        }
    }

    /// Configure retry strategy for an operation type
    pub fn configure_retry(&mut self, operation_type: &str, config: RetryConfig) {
        self.retry_configs.insert(operation_type.to_string(), config);
    }

    /// Configure circuit breaker for a service
    pub fn configure_circuit_breaker(&mut self, service: &str, config: CircuitBreakerConfig) {
        let circuit_breaker = Arc::new(CircuitBreaker::new(config));
        self.circuit_breakers.insert(service.to_string(), circuit_breaker);
    }

    /// Configure bulkhead for a resource
    pub fn configure_bulkhead(&mut self, resource: &str, max_concurrent: usize, timeout: Duration) {
        let bulkhead = Arc::new(Bulkhead::new(resource.to_string(), max_concurrent, timeout));
        self.bulkheads.insert(resource.to_string(), bulkhead);
    }

    /// Get retry strategy for operation type
    pub fn get_retry_strategy(&self, operation_type: &str) -> RetryStrategy {
        let config = self.retry_configs
            .get(operation_type)
            .cloned()
            .unwrap_or_default();
        RetryStrategy::new(config)
    }

    /// Get circuit breaker for service
    pub fn get_circuit_breaker(&self, service: &str) -> Option<Arc<CircuitBreaker>> {
        self.circuit_breakers.get(service).cloned()
    }

    /// Get dead letter queue
    pub fn get_dead_letter_queue(&self) -> Arc<DeadLetterQueue> {
        self.dead_letter_queue.clone()
    }

    /// Get bulkhead for resource
    pub fn get_bulkhead(&self, resource: &str) -> Option<Arc<Bulkhead>> {
        self.bulkheads.get(resource).cloned()
    }
}

impl Default for RecoveryManager {
    fn default() -> Self {
        let mut manager = Self::new();

        // Configure default retry strategies
        manager.configure_retry("message_handler", RetryConfig::default());
        manager.configure_retry("connection", RetryConfig::conservative());
        manager.configure_retry("validation", RetryConfig::fast());

        // Configure default circuit breakers
        manager.configure_circuit_breaker("default", CircuitBreakerConfig::default());

        // Configure default bulkheads
        manager.configure_bulkhead("message_processing", 100, Duration::from_secs(30));
        manager.configure_bulkhead("connection_pool", 50, Duration::from_secs(10));

        manager
    }
}
`}
        </File>
    );
}

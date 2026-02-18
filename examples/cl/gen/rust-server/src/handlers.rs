//! Clean message handlers for AsyncAPI operations

use crate::context::RequestContext;
use crate::errors::{AsyncApiError, AsyncApiResult, ErrorCategory, ErrorMetadata, ErrorSeverity};
use crate::models::*;
use crate::recovery::{RecoveryManager, RetryConfig, MessageDirection};
use crate::transport::{MessageHandler, MessageMetadata, TransportManager, TransportMessage};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Context for message processing with correlation tracking and response routing
#[derive(Debug, Clone)]
pub struct MessageContext {
    pub correlation_id: Uuid,
    pub channel: String,
    pub operation: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub retry_count: u32,
    pub reply_to: Option<String>,
    pub headers: HashMap<String, String>,
    #[cfg(feature = "auth")]
    pub claims: Option<crate::auth::Claims>,
    pub middleware_context: Option<crate::middleware::MiddlewareContext>,
    pub publisher_context: Option<Arc<PublisherContext>>,
}

impl MessageContext {
    pub fn new(channel: &str, operation: &str) -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            channel: channel.to_string(),
            operation: operation.to_string(),
            timestamp: chrono::Utc::now(),
            retry_count: 0,
            reply_to: None,
            headers: HashMap::new(),
            #[cfg(feature = "auth")]
            claims: None,
            middleware_context: None,
            publisher_context: None,
        }
    }

    /// Get strongly-typed publishers for sending messages
    pub fn publishers(&self) -> Arc<PublisherContext> {
        self.publisher_context.as_ref()
            .expect("Publisher context not initialized - this should be set by the server infrastructure")
            .clone()
    }

    /// Set the publisher context (used by the server infrastructure)
    pub fn with_publishers(mut self, publishers: Arc<PublisherContext>) -> Self {
        self.publisher_context = Some(publishers);
        self
    }

    pub fn with_reply_to(mut self, reply_to: String) -> Self {
        self.reply_to = Some(reply_to);
        self
    }

    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_retry(&self, retry_count: u32) -> Self {
        let mut ctx = self.clone();
        ctx.retry_count = retry_count;
        ctx
    }

    /// Get the response channel for this request
    pub fn response_channel(&self) -> String {
        // Use reply_to if available, otherwise construct response channel
        if let Some(reply_to) = &self.reply_to {
            reply_to.clone()
        } else {
            // Default response channel pattern
            format!("{channel}/response", channel = self.channel)
        }
    }

    /// Get authentication claims if available
    #[cfg(feature = "auth")]
    pub fn claims(&self) -> Option<&crate::auth::Claims> {
        self.claims.as_ref()
    }

    /// Get authentication claims if available (auth feature disabled)
    #[cfg(not(feature = "auth"))]
    pub fn claims(&self) -> Option<&()> {
        None
    }

    /// Set authentication claims
    #[cfg(feature = "auth")]
    pub fn set_claims(&mut self, claims: crate::auth::Claims) {
        self.claims = Some(claims);
    }

    /// Set authentication claims (auth feature disabled)
    #[cfg(not(feature = "auth"))]
    pub fn set_claims(&mut self, _claims: ()) {
        // No-op when auth feature is disabled
    }
}

// Channel-based publisher infrastructure for "receive" operations (outgoing messages)

/// Channel publisher for connections channel operations
#[derive(Debug, Clone)]
pub struct ConnectionsChannelPublisher {
    transport_manager: Arc<TransportManager>,
}

impl ConnectionsChannelPublisher {
    /// Create a new channel publisher with the given transport manager
    pub fn new(transport_manager: Arc<TransportManager>) -> Self {
        Self { transport_manager }
    }

    /// Send a ConnectionStreamNotification message with automatic envelope wrapping and retry logic
    ///
    /// # Parameters
    /// * `cska_id` - cska_id parameter for dynamic channel resolution
    pub async fn connections_stream(
        &self,
        payload: ConnectionStreamNotification,
        cska_id: String, correlation_id: Option<String>,
    ) -> AsyncApiResult<()> {
        let correlation_id = correlation_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        // Resolve dynamic channel address with runtime parameters
        let channel_address = format!("connections.{}", cska_id);

        // Create MessageEnvelope with automatic serialization
        let envelope = MessageEnvelope::new("connections.stream", payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to create ConnectionStreamNotification envelope: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Validation,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?
            .with_correlation_id(correlation_id.clone())
            .with_channel(channel_address);

        // Send via transport manager with automatic retry logic for outgoing messages
        self.transport_manager.send_envelope(envelope).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send ConnectionStreamNotification message: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Network,
                    true,
                ),
                source: Some(e),
            }))
    }
}
/// Channel publisher for device channel operations
#[derive(Debug, Clone)]
pub struct DeviceChannelPublisher {
    transport_manager: Arc<TransportManager>,
}

impl DeviceChannelPublisher {
    /// Create a new channel publisher with the given transport manager
    pub fn new(transport_manager: Arc<TransportManager>) -> Self {
        Self { transport_manager }
    }

    /// Send a DeviceStatusUpdateNotification message with automatic envelope wrapping and retry logic
    ///
    /// # Parameters
    /// * `cska_id` - cska_id parameter for dynamic channel resolution
    pub async fn device_status_update(
        &self,
        payload: DeviceStatusUpdateNotification,
        cska_id: String, correlation_id: Option<String>,
    ) -> AsyncApiResult<()> {
        let correlation_id = correlation_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        // Resolve dynamic channel address with runtime parameters
        let channel_address = format!("device.{}", cska_id);

        // Create MessageEnvelope with automatic serialization
        let envelope = MessageEnvelope::new("device.status_update", payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to create DeviceStatusUpdateNotification envelope: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Validation,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?
            .with_correlation_id(correlation_id.clone())
            .with_channel(channel_address);

        // Send via transport manager with automatic retry logic for outgoing messages
        self.transport_manager.send_envelope(envelope).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send DeviceStatusUpdateNotification message: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Network,
                    true,
                ),
                source: Some(e),
            }))
    }
}
/// Channel publisher for metrics channel operations
#[derive(Debug, Clone)]
pub struct MetricsChannelPublisher {
    transport_manager: Arc<TransportManager>,
}

impl MetricsChannelPublisher {
    /// Create a new channel publisher with the given transport manager
    pub fn new(transport_manager: Arc<TransportManager>) -> Self {
        Self { transport_manager }
    }

    /// Send a MetricsStreamNotification message with automatic envelope wrapping and retry logic
    ///
    /// # Parameters
    /// * `cska_id` - cska_id parameter for dynamic channel resolution
    pub async fn metrics_stream(
        &self,
        payload: MetricsStreamNotification,
        cska_id: String, correlation_id: Option<String>,
    ) -> AsyncApiResult<()> {
        let correlation_id = correlation_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        // Resolve dynamic channel address with runtime parameters
        let channel_address = format!("metrics.{}", cska_id);

        // Create MessageEnvelope with automatic serialization
        let envelope = MessageEnvelope::new("metrics.stream", payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to create MetricsStreamNotification envelope: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Validation,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?
            .with_correlation_id(correlation_id.clone())
            .with_channel(channel_address);

        // Send via transport manager with automatic retry logic for outgoing messages
        self.transport_manager.send_envelope(envelope).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send MetricsStreamNotification message: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Network,
                    true,
                ),
                source: Some(e),
            }))
    }
}
/// Channel publisher for threats_ws channel operations
#[derive(Debug, Clone)]
pub struct ThreatsWsChannelPublisher {
    transport_manager: Arc<TransportManager>,
}

impl ThreatsWsChannelPublisher {
    /// Create a new channel publisher with the given transport manager
    pub fn new(transport_manager: Arc<TransportManager>) -> Self {
        Self { transport_manager }
    }

    /// Send a ThreatStreamNotification message with automatic envelope wrapping and retry logic
    ///
    /// # Parameters
    /// * `cska_id` - cska_id parameter for dynamic channel resolution
    pub async fn threats_stream(
        &self,
        payload: ThreatStreamNotification,
        cska_id: String, correlation_id: Option<String>,
    ) -> AsyncApiResult<()> {
        let correlation_id = correlation_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        // Resolve dynamic channel address with runtime parameters
        let channel_address = format!("threats.{}", cska_id);

        // Create MessageEnvelope with automatic serialization
        let envelope = MessageEnvelope::new("threats.stream", payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to create ThreatStreamNotification envelope: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Validation,
                    false,
                ),
                source: Some(Box::new(e)),
            }))?
            .with_correlation_id(correlation_id.clone())
            .with_channel(channel_address);

        // Send via transport manager with automatic retry logic for outgoing messages
        self.transport_manager.send_envelope(envelope).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send ThreatStreamNotification message: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(
                    ErrorSeverity::High,
                    ErrorCategory::Network,
                    true,
                ),
                source: Some(e),
            }))
    }
}

/// Auto-generated context containing all channel publishers for "receive" operations
#[derive(Debug, Clone)]
pub struct PublisherContext {
    /// Publisher for connections channel operations
    pub connections: ConnectionsChannelPublisher,
    /// Publisher for device channel operations
    pub device: DeviceChannelPublisher,
    /// Publisher for metrics channel operations
    pub metrics: MetricsChannelPublisher,
    /// Publisher for threats_ws channel operations
    pub threats_ws: ThreatsWsChannelPublisher,
}

impl PublisherContext {
    /// Create a new publisher context with all channel publishers initialized
    pub fn new(transport_manager: Arc<TransportManager>) -> Self {
        Self {
            connections: ConnectionsChannelPublisher::new(transport_manager.clone()),
            device: DeviceChannelPublisher::new(transport_manager.clone()),
            metrics: MetricsChannelPublisher::new(transport_manager.clone()),
            threats_ws: ThreatsWsChannelPublisher::new(transport_manager.clone()),
        }
    }
}


/// Business logic trait for auth channel operations
#[async_trait]
pub trait AuthService: Send + Sync {
    /// Handle auth.login request and return response
    async fn handle_auth_login(
        &self,
        request: LoginRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<LoginResponse>;
    /// Handle auth.logout request and return response
    async fn handle_auth_logout(
        &self,
        request: LogoutRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<LogoutResponse>;
}
/// Business logic trait for device channel operations
#[async_trait]
pub trait DeviceService: Send + Sync {
    /// Handle device.bootstrap request and return response
    async fn handle_device_bootstrap(
        &self,
        request: BootstrapDeviceRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<BootstrapDeviceResponse>;
    /// Handle device.get request and return response
    async fn handle_device_get(
        &self,
        request: GetDeviceRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<GetDeviceResponse>;
    /// Handle device.configure request and return response
    async fn handle_device_configure(
        &self,
        request: ConfigureDeviceRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ConfigureDeviceResponse>;
    /// Handle device.delete request and return response
    async fn handle_device_delete(
        &self,
        request: DeleteDeviceRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<DeleteDeviceResponse>;
    /// Handle device.list request and return response
    async fn handle_device_list(
        &self,
        request: ListDevicesRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ListDevicesResponse>;
    /// Handle device.update_metadata request and return response
    async fn handle_device_update_metadata(
        &self,
        request: UpdateDeviceMetadataRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<UpdateDeviceMetadataResponse>;
}
/// Business logic trait for network channel operations
#[async_trait]
pub trait NetworkService: Send + Sync {
    /// Handle network.topology request and return response
    async fn handle_network_topology(
        &self,
        request: GetNetworkTopologyRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<GetNetworkTopologyResponse>;
}
/// Business logic trait for provision channel operations
#[async_trait]
pub trait ProvisionService: Send + Sync {
    /// Handle provision.refresh request and return response
    async fn handle_provision_refresh(
        &self,
        request: ProvisionDeviceRefreshRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ProvisionDeviceRefreshResponse>;
}
/// Business logic trait for salting channel operations
#[async_trait]
pub trait SaltingService: Send + Sync {
    /// Handle salting.request request and return response
    async fn handle_salting_request(
        &self,
        request: SaltedKeyRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<SaltedKeyResponse>;
}
/// Business logic trait for threats_nats channel operations
#[async_trait]
pub trait ThreatsNatsService: Send + Sync {
    /// Handle threats.report request and return response
    async fn handle_threats_report(
        &self,
        request: ThreatReportRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ThreatReportResponse>;
}
/// Business logic trait for threats_ws channel operations
#[async_trait]
pub trait ThreatsWsService: Send + Sync {
    /// Handle threats.query request and return response
    async fn handle_threats_query(
        &self,
        request: ThreatQueryRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ThreatQueryResponse>;
    /// Handle threats.download_pcap request and return response
    async fn handle_threats_download_pcap(
        &self,
        request: ThreatPcapDownloadRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ThreatPcapDownloadResponse>;
}
/// Business logic trait for validator_connection channel operations
#[async_trait]
pub trait ValidatorConnectionService: Send + Sync {
    /// Handle validator_connection.report request and return response
    async fn handle_validator_connection_report(
        &self,
        request: ValidatorConnectionReport,
        context: &MessageContext,
    ) -> AsyncApiResult<ValidatorConnectionResponse>;
}
/// Business logic trait for connections channel operations
#[async_trait]
pub trait ConnectionsService: Send + Sync {
    /// Handle connections.query request and return response
    async fn handle_connections_query(
        &self,
        request: ConnectionQueryRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ConnectionQueryResponse>;
}
/// Business logic trait for metrics channel operations
#[async_trait]
pub trait MetricsService: Send + Sync {
    /// Handle metrics.query request and return response
    async fn handle_metrics_query(
        &self,
        request: MetricsQueryRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<MetricsQueryResponse>;
    /// Handle metrics.reset request and return response
    async fn handle_metrics_reset(
        &self,
        request: MetricsResetRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<MetricsResetResponse>;
}
/// Business logic trait for tags channel operations
#[async_trait]
pub trait TagsService: Send + Sync {
    /// Handle tags.create request and return response
    async fn handle_tags_create(
        &self,
        request: CreateTagRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<CreateTagResponse>;
    /// Handle tags.update request and return response
    async fn handle_tags_update(
        &self,
        request: UpdateTagRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<UpdateTagResponse>;
    /// Handle tags.delete request and return response
    async fn handle_tags_delete(
        &self,
        request: DeleteTagRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<DeleteTagResponse>;
    /// Handle tags.list request and return response
    async fn handle_tags_list(
        &self,
        request: ListTagsRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ListTagsResponse>;
}
/// Business logic trait for profiles channel operations
#[async_trait]
pub trait ProfilesService: Send + Sync {
    /// Handle profiles.create request and return response
    async fn handle_profiles_create(
        &self,
        request: CreateProfileRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<CreateProfileResponse>;
    /// Handle profiles.get request and return response
    async fn handle_profiles_get(
        &self,
        request: GetProfileRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<GetProfileResponse>;
    /// Handle profiles.update request and return response
    async fn handle_profiles_update(
        &self,
        request: UpdateProfileRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<UpdateProfileResponse>;
    /// Handle profiles.delete request and return response
    async fn handle_profiles_delete(
        &self,
        request: DeleteProfileRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<DeleteProfileResponse>;
    /// Handle profiles.list request and return response
    async fn handle_profiles_list(
        &self,
        request: ListProfilesRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<ListProfilesResponse>;
    /// Handle profiles.assign request and return response
    async fn handle_profiles_assign(
        &self,
        request: AssignProfileRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<AssignProfileResponse>;
    /// Handle profiles.unassign request and return response
    async fn handle_profiles_unassign(
        &self,
        request: UnassignProfileRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<UnassignProfileResponse>;
}
/// Business logic trait for settings channel operations
#[async_trait]
pub trait SettingsService: Send + Sync {
    /// Handle settings.get request and return response
    async fn handle_settings_get(
        &self,
        request: GetSettingsRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<GetSettingsResponse>;
    /// Handle settings.update request and return response
    async fn handle_settings_update(
        &self,
        request: UpdateSettingsRequest,
        context: &MessageContext,
    ) -> AsyncApiResult<UpdateSettingsResponse>;
}


/// Individual operation handler for auth.login
#[derive(Debug)]
pub struct AuthLoginOperationHandler<T: AuthService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: AuthService + ?Sized> AuthLoginOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: AuthService + ?Sized> crate::transport::MessageHandler for AuthLoginOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("auth", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_auth_login_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: AuthService + ?Sized> AuthLoginOperationHandler<T> {
    /// Handle auth.login request with strongly typed messages and automatic response
    pub async fn handle_auth_login_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<LoginResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: LoginRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid LoginRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_auth_login(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for auth.login operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for auth.login operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for auth.logout
#[derive(Debug)]
pub struct AuthLogoutOperationHandler<T: AuthService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: AuthService + ?Sized> AuthLogoutOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: AuthService + ?Sized> crate::transport::MessageHandler for AuthLogoutOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("auth", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_auth_logout_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: AuthService + ?Sized> AuthLogoutOperationHandler<T> {
    /// Handle auth.logout request with strongly typed messages and automatic response
    pub async fn handle_auth_logout_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<LogoutResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: LogoutRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid LogoutRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_auth_logout(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for auth.logout operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for auth.logout operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for device.bootstrap
#[derive(Debug)]
pub struct DeviceBootstrapOperationHandler<T: DeviceService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: DeviceService + ?Sized> DeviceBootstrapOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: DeviceService + ?Sized> crate::transport::MessageHandler for DeviceBootstrapOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("device", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_device_bootstrap_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: DeviceService + ?Sized> DeviceBootstrapOperationHandler<T> {
    /// Handle device.bootstrap request with strongly typed messages and automatic response
    pub async fn handle_device_bootstrap_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<BootstrapDeviceResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: BootstrapDeviceRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid BootstrapDeviceRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_device_bootstrap(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for device.bootstrap operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for device.bootstrap operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for device.get
#[derive(Debug)]
pub struct DeviceGetOperationHandler<T: DeviceService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: DeviceService + ?Sized> DeviceGetOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: DeviceService + ?Sized> crate::transport::MessageHandler for DeviceGetOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("device", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_device_get_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: DeviceService + ?Sized> DeviceGetOperationHandler<T> {
    /// Handle device.get request with strongly typed messages and automatic response
    pub async fn handle_device_get_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<GetDeviceResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: GetDeviceRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid GetDeviceRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_device_get(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for device.get operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for device.get operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for device.configure
#[derive(Debug)]
pub struct DeviceConfigureOperationHandler<T: DeviceService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: DeviceService + ?Sized> DeviceConfigureOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: DeviceService + ?Sized> crate::transport::MessageHandler for DeviceConfigureOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("device", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_device_configure_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: DeviceService + ?Sized> DeviceConfigureOperationHandler<T> {
    /// Handle device.configure request with strongly typed messages and automatic response
    pub async fn handle_device_configure_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ConfigureDeviceResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ConfigureDeviceRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ConfigureDeviceRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_device_configure(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for device.configure operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for device.configure operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for device.delete
#[derive(Debug)]
pub struct DeviceDeleteOperationHandler<T: DeviceService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: DeviceService + ?Sized> DeviceDeleteOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: DeviceService + ?Sized> crate::transport::MessageHandler for DeviceDeleteOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("device", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_device_delete_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: DeviceService + ?Sized> DeviceDeleteOperationHandler<T> {
    /// Handle device.delete request with strongly typed messages and automatic response
    pub async fn handle_device_delete_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<DeleteDeviceResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: DeleteDeviceRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid DeleteDeviceRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_device_delete(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for device.delete operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for device.delete operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for device.list
#[derive(Debug)]
pub struct DeviceListOperationHandler<T: DeviceService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: DeviceService + ?Sized> DeviceListOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: DeviceService + ?Sized> crate::transport::MessageHandler for DeviceListOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("device", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_device_list_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: DeviceService + ?Sized> DeviceListOperationHandler<T> {
    /// Handle device.list request with strongly typed messages and automatic response
    pub async fn handle_device_list_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ListDevicesResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ListDevicesRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ListDevicesRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_device_list(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for device.list operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for device.list operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for device.update_metadata
#[derive(Debug)]
pub struct DeviceUpdateMetadataOperationHandler<T: DeviceService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: DeviceService + ?Sized> DeviceUpdateMetadataOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: DeviceService + ?Sized> crate::transport::MessageHandler for DeviceUpdateMetadataOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("device", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_device_update_metadata_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: DeviceService + ?Sized> DeviceUpdateMetadataOperationHandler<T> {
    /// Handle device.update_metadata request with strongly typed messages and automatic response
    pub async fn handle_device_update_metadata_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<UpdateDeviceMetadataResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: UpdateDeviceMetadataRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid UpdateDeviceMetadataRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_device_update_metadata(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for device.update_metadata operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for device.update_metadata operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for network.topology
#[derive(Debug)]
pub struct NetworkTopologyOperationHandler<T: NetworkService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: NetworkService + ?Sized> NetworkTopologyOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: NetworkService + ?Sized> crate::transport::MessageHandler for NetworkTopologyOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("network", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_network_topology_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: NetworkService + ?Sized> NetworkTopologyOperationHandler<T> {
    /// Handle network.topology request with strongly typed messages and automatic response
    pub async fn handle_network_topology_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<GetNetworkTopologyResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: GetNetworkTopologyRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid GetNetworkTopologyRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_network_topology(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for network.topology operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for network.topology operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for provision.refresh
#[derive(Debug)]
pub struct ProvisionRefreshOperationHandler<T: ProvisionService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ProvisionService + ?Sized> ProvisionRefreshOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ProvisionService + ?Sized> crate::transport::MessageHandler for ProvisionRefreshOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("provision", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_provision_refresh_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ProvisionService + ?Sized> ProvisionRefreshOperationHandler<T> {
    /// Handle provision.refresh request with strongly typed messages and automatic response
    pub async fn handle_provision_refresh_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ProvisionDeviceRefreshResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ProvisionDeviceRefreshRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ProvisionDeviceRefreshRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_provision_refresh(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for provision.refresh operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for provision.refresh operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for salting.request
#[derive(Debug)]
pub struct SaltingRequestOperationHandler<T: SaltingService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: SaltingService + ?Sized> SaltingRequestOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: SaltingService + ?Sized> crate::transport::MessageHandler for SaltingRequestOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("salting", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_salting_request_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: SaltingService + ?Sized> SaltingRequestOperationHandler<T> {
    /// Handle salting.request request with strongly typed messages and automatic response
    pub async fn handle_salting_request_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<SaltedKeyResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: SaltedKeyRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid SaltedKeyRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_salting_request(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for salting.request operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for salting.request operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for threats.report
#[derive(Debug)]
pub struct ThreatsReportOperationHandler<T: ThreatsNatsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ThreatsNatsService + ?Sized> ThreatsReportOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ThreatsNatsService + ?Sized> crate::transport::MessageHandler for ThreatsReportOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("threats_nats", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_threats_report_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ThreatsNatsService + ?Sized> ThreatsReportOperationHandler<T> {
    /// Handle threats.report request with strongly typed messages and automatic response
    pub async fn handle_threats_report_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ThreatReportResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ThreatReportRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ThreatReportRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_threats_report(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for threats.report operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for threats.report operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for threats.query
#[derive(Debug)]
pub struct ThreatsQueryOperationHandler<T: ThreatsWsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ThreatsWsService + ?Sized> ThreatsQueryOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ThreatsWsService + ?Sized> crate::transport::MessageHandler for ThreatsQueryOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("threats_ws", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_threats_query_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ThreatsWsService + ?Sized> ThreatsQueryOperationHandler<T> {
    /// Handle threats.query request with strongly typed messages and automatic response
    pub async fn handle_threats_query_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ThreatQueryResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ThreatQueryRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ThreatQueryRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_threats_query(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for threats.query operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for threats.query operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for threats.download_pcap
#[derive(Debug)]
pub struct ThreatsDownloadPcapOperationHandler<T: ThreatsWsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ThreatsWsService + ?Sized> ThreatsDownloadPcapOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ThreatsWsService + ?Sized> crate::transport::MessageHandler for ThreatsDownloadPcapOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("threats_ws", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_threats_download_pcap_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ThreatsWsService + ?Sized> ThreatsDownloadPcapOperationHandler<T> {
    /// Handle threats.download_pcap request with strongly typed messages and automatic response
    pub async fn handle_threats_download_pcap_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ThreatPcapDownloadResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ThreatPcapDownloadRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ThreatPcapDownloadRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_threats_download_pcap(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for threats.download_pcap operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for threats.download_pcap operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for validator_connection.report
#[derive(Debug)]
pub struct ValidatorConnectionReportOperationHandler<T: ValidatorConnectionService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ValidatorConnectionService + ?Sized> ValidatorConnectionReportOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ValidatorConnectionService + ?Sized> crate::transport::MessageHandler for ValidatorConnectionReportOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("validator_connection", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_validator_connection_report_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ValidatorConnectionService + ?Sized> ValidatorConnectionReportOperationHandler<T> {
    /// Handle validator_connection.report request with strongly typed messages and automatic response
    pub async fn handle_validator_connection_report_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ValidatorConnectionResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ValidatorConnectionReport = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ValidatorConnectionReport: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_validator_connection_report(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for validator_connection.report operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for validator_connection.report operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for connections.query
#[derive(Debug)]
pub struct ConnectionsQueryOperationHandler<T: ConnectionsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ConnectionsService + ?Sized> ConnectionsQueryOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ConnectionsService + ?Sized> crate::transport::MessageHandler for ConnectionsQueryOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("connections", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_connections_query_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ConnectionsService + ?Sized> ConnectionsQueryOperationHandler<T> {
    /// Handle connections.query request with strongly typed messages and automatic response
    pub async fn handle_connections_query_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ConnectionQueryResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ConnectionQueryRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ConnectionQueryRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_connections_query(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for connections.query operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for connections.query operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for metrics.query
#[derive(Debug)]
pub struct MetricsQueryOperationHandler<T: MetricsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: MetricsService + ?Sized> MetricsQueryOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: MetricsService + ?Sized> crate::transport::MessageHandler for MetricsQueryOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("metrics", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_metrics_query_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: MetricsService + ?Sized> MetricsQueryOperationHandler<T> {
    /// Handle metrics.query request with strongly typed messages and automatic response
    pub async fn handle_metrics_query_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<MetricsQueryResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: MetricsQueryRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MetricsQueryRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_metrics_query(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for metrics.query operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for metrics.query operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for metrics.reset
#[derive(Debug)]
pub struct MetricsResetOperationHandler<T: MetricsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: MetricsService + ?Sized> MetricsResetOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: MetricsService + ?Sized> crate::transport::MessageHandler for MetricsResetOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("metrics", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_metrics_reset_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: MetricsService + ?Sized> MetricsResetOperationHandler<T> {
    /// Handle metrics.reset request with strongly typed messages and automatic response
    pub async fn handle_metrics_reset_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<MetricsResetResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: MetricsResetRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MetricsResetRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_metrics_reset(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for metrics.reset operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for metrics.reset operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for tags.create
#[derive(Debug)]
pub struct TagsCreateOperationHandler<T: TagsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: TagsService + ?Sized> TagsCreateOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: TagsService + ?Sized> crate::transport::MessageHandler for TagsCreateOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("tags", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_tags_create_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: TagsService + ?Sized> TagsCreateOperationHandler<T> {
    /// Handle tags.create request with strongly typed messages and automatic response
    pub async fn handle_tags_create_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<CreateTagResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: CreateTagRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid CreateTagRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_tags_create(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for tags.create operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for tags.create operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for tags.update
#[derive(Debug)]
pub struct TagsUpdateOperationHandler<T: TagsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: TagsService + ?Sized> TagsUpdateOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: TagsService + ?Sized> crate::transport::MessageHandler for TagsUpdateOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("tags", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_tags_update_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: TagsService + ?Sized> TagsUpdateOperationHandler<T> {
    /// Handle tags.update request with strongly typed messages and automatic response
    pub async fn handle_tags_update_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<UpdateTagResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: UpdateTagRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid UpdateTagRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_tags_update(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for tags.update operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for tags.update operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for tags.delete
#[derive(Debug)]
pub struct TagsDeleteOperationHandler<T: TagsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: TagsService + ?Sized> TagsDeleteOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: TagsService + ?Sized> crate::transport::MessageHandler for TagsDeleteOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("tags", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_tags_delete_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: TagsService + ?Sized> TagsDeleteOperationHandler<T> {
    /// Handle tags.delete request with strongly typed messages and automatic response
    pub async fn handle_tags_delete_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<DeleteTagResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: DeleteTagRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid DeleteTagRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_tags_delete(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for tags.delete operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for tags.delete operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for tags.list
#[derive(Debug)]
pub struct TagsListOperationHandler<T: TagsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: TagsService + ?Sized> TagsListOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: TagsService + ?Sized> crate::transport::MessageHandler for TagsListOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("tags", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_tags_list_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: TagsService + ?Sized> TagsListOperationHandler<T> {
    /// Handle tags.list request with strongly typed messages and automatic response
    pub async fn handle_tags_list_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ListTagsResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ListTagsRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ListTagsRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_tags_list(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for tags.list operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for tags.list operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for profiles.create
#[derive(Debug)]
pub struct ProfilesCreateOperationHandler<T: ProfilesService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ProfilesService + ?Sized> ProfilesCreateOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ProfilesService + ?Sized> crate::transport::MessageHandler for ProfilesCreateOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("profiles", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_profiles_create_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ProfilesService + ?Sized> ProfilesCreateOperationHandler<T> {
    /// Handle profiles.create request with strongly typed messages and automatic response
    pub async fn handle_profiles_create_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<CreateProfileResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: CreateProfileRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid CreateProfileRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_profiles_create(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for profiles.create operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for profiles.create operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for profiles.get
#[derive(Debug)]
pub struct ProfilesGetOperationHandler<T: ProfilesService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ProfilesService + ?Sized> ProfilesGetOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ProfilesService + ?Sized> crate::transport::MessageHandler for ProfilesGetOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("profiles", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_profiles_get_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ProfilesService + ?Sized> ProfilesGetOperationHandler<T> {
    /// Handle profiles.get request with strongly typed messages and automatic response
    pub async fn handle_profiles_get_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<GetProfileResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: GetProfileRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid GetProfileRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_profiles_get(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for profiles.get operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for profiles.get operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for profiles.update
#[derive(Debug)]
pub struct ProfilesUpdateOperationHandler<T: ProfilesService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ProfilesService + ?Sized> ProfilesUpdateOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ProfilesService + ?Sized> crate::transport::MessageHandler for ProfilesUpdateOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("profiles", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_profiles_update_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ProfilesService + ?Sized> ProfilesUpdateOperationHandler<T> {
    /// Handle profiles.update request with strongly typed messages and automatic response
    pub async fn handle_profiles_update_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<UpdateProfileResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: UpdateProfileRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid UpdateProfileRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_profiles_update(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for profiles.update operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for profiles.update operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for profiles.delete
#[derive(Debug)]
pub struct ProfilesDeleteOperationHandler<T: ProfilesService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ProfilesService + ?Sized> ProfilesDeleteOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ProfilesService + ?Sized> crate::transport::MessageHandler for ProfilesDeleteOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("profiles", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_profiles_delete_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ProfilesService + ?Sized> ProfilesDeleteOperationHandler<T> {
    /// Handle profiles.delete request with strongly typed messages and automatic response
    pub async fn handle_profiles_delete_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<DeleteProfileResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: DeleteProfileRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid DeleteProfileRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_profiles_delete(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for profiles.delete operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for profiles.delete operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for profiles.list
#[derive(Debug)]
pub struct ProfilesListOperationHandler<T: ProfilesService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ProfilesService + ?Sized> ProfilesListOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ProfilesService + ?Sized> crate::transport::MessageHandler for ProfilesListOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("profiles", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_profiles_list_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ProfilesService + ?Sized> ProfilesListOperationHandler<T> {
    /// Handle profiles.list request with strongly typed messages and automatic response
    pub async fn handle_profiles_list_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<ListProfilesResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: ListProfilesRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid ListProfilesRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_profiles_list(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for profiles.list operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for profiles.list operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for profiles.assign
#[derive(Debug)]
pub struct ProfilesAssignOperationHandler<T: ProfilesService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ProfilesService + ?Sized> ProfilesAssignOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ProfilesService + ?Sized> crate::transport::MessageHandler for ProfilesAssignOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("profiles", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_profiles_assign_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ProfilesService + ?Sized> ProfilesAssignOperationHandler<T> {
    /// Handle profiles.assign request with strongly typed messages and automatic response
    pub async fn handle_profiles_assign_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<AssignProfileResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: AssignProfileRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid AssignProfileRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_profiles_assign(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for profiles.assign operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for profiles.assign operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for profiles.unassign
#[derive(Debug)]
pub struct ProfilesUnassignOperationHandler<T: ProfilesService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: ProfilesService + ?Sized> ProfilesUnassignOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: ProfilesService + ?Sized> crate::transport::MessageHandler for ProfilesUnassignOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("profiles", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_profiles_unassign_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: ProfilesService + ?Sized> ProfilesUnassignOperationHandler<T> {
    /// Handle profiles.unassign request with strongly typed messages and automatic response
    pub async fn handle_profiles_unassign_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<UnassignProfileResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: UnassignProfileRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid UnassignProfileRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_profiles_unassign(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for profiles.unassign operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for profiles.unassign operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for settings.get
#[derive(Debug)]
pub struct SettingsGetOperationHandler<T: SettingsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: SettingsService + ?Sized> SettingsGetOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: SettingsService + ?Sized> crate::transport::MessageHandler for SettingsGetOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("settings", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_settings_get_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: SettingsService + ?Sized> SettingsGetOperationHandler<T> {
    /// Handle settings.get request with strongly typed messages and automatic response
    pub async fn handle_settings_get_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<GetSettingsResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: GetSettingsRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid GetSettingsRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_settings_get(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for settings.get operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for settings.get operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}
/// Individual operation handler for settings.update
#[derive(Debug)]
pub struct SettingsUpdateOperationHandler<T: SettingsService + ?Sized> {
    service: Arc<T>,
    recovery_manager: Arc<RecoveryManager>,
    transport_manager: Arc<TransportManager>,
}

impl<T: SettingsService + ?Sized> SettingsUpdateOperationHandler<T> {
    pub fn new(
        service: Arc<T>,
        recovery_manager: Arc<RecoveryManager>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            service,
            recovery_manager,
            transport_manager,
        }
    }
}

#[async_trait]
impl<T: SettingsService + ?Sized> crate::transport::MessageHandler for SettingsUpdateOperationHandler<T> {
    async fn handle_message(
        &self,
        payload: &[u8],
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create publisher context from transport manager
        let publishers = Arc::new(PublisherContext::new(self.transport_manager.clone()));

        // Create message context from metadata with publishers initialized
        let mut context = MessageContext::new("settings", &metadata.operation)
            .with_publishers(publishers);
        context.correlation_id = metadata.correlation_id;
        context.headers = metadata.headers.clone();
        context.reply_to = metadata.reply_to.clone();

        
        // Handle request/response operation
        let _ = self.handle_settings_update_request(payload, &context, metadata).await?;
        Ok(())
    }
}

impl<T: SettingsService + ?Sized> SettingsUpdateOperationHandler<T> {
    /// Handle settings.update request with strongly typed messages and automatic response
    pub async fn handle_settings_update_request(
        &self,
        payload: &[u8],
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<UpdateSettingsResponse> {
        // Parse and validate payload
        let envelope: MessageEnvelope = serde_json::from_slice(payload)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid MessageEnvelope: {e}"),
                field: Some("envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let request: UpdateSettingsRequest = envelope.extract_payload()
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Invalid UpdateSettingsRequest: {e}"),
                field: Some("payload".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::Medium, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        // Call business logic and handle errors
        match self.service.handle_settings_update(request, context).await {
            Ok(response) => {
                // Send successful response automatically with original request ID
                self.send_response(&response, &envelope, context, metadata).await?;
                Ok(response)
            }
            Err(error) => {
                // Send error response automatically with original request ID
                self.send_error_response(&error, &envelope, context, metadata).await?;
                Err(error)
            }
        }
    }

    /// Send error response for settings.update operation
    async fn send_error_response(
        &self,
        error: &AsyncApiError,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Convert the server error to wire format
        let wire_error = error.to_wire();

        // Create response envelope with error and the SAME ID as the request
        let mut response_envelope = MessageEnvelope::error_response(
            &format!("{}_response", context.operation),
            wire_error,
            Some(context.correlation_id.to_string()),
        );

        // CRITICAL: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for error response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize error response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers.insert("error".to_string(), "true".to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the respond method to send error response
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send error response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }

    /// Send response for settings.update operation
    async fn send_response<R: serde::Serialize>(
        &self,
        response: R,
        request_envelope: &MessageEnvelope,
        context: &MessageContext,
        metadata: &MessageMetadata,
    ) -> AsyncApiResult<()> {
        // Create response envelope with the SAME ID as the request for proper client correlation
        let mut response_envelope = MessageEnvelope::new(
            &format!("{}_response", context.operation),
            response
        ).map_err(|e| Box::new(AsyncApiError::Validation {
            message: format!("Failed to create response envelope: {e}"),
            field: Some("response_envelope".to_string()),
            metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
            source: Some(Box::new(e)),
        }))?;

        // CRITICAL FIX: Use the original request ID as the response ID for client correlation
        response_envelope.id = request_envelope.id.clone();

        // Set correlation_id for additional tracking (can be different from ID)
        response_envelope.correlation_id = Some(context.correlation_id.to_string());

        // Preserve the original channel
        response_envelope.channel = Some(context.channel.clone());

        // Create transport message for response
        let response_payload = serde_json::to_vec(&response_envelope)
            .map_err(|e| Box::new(AsyncApiError::Validation {
                message: format!("Failed to serialize response envelope: {e}"),
                field: Some("response_envelope".to_string()),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Validation, false),
                source: Some(Box::new(e)),
            }))?;

        let response_message = TransportMessage {
            metadata: crate::transport::MessageMetadata {
                content_type: Some("application/json".to_string()),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("correlation_id".to_string(), context.correlation_id.to_string());
                    headers
                },
                priority: None,
                ttl: None,
                reply_to: context.reply_to.clone(),
                operation: format!("{}_response", context.operation),
                correlation_id: context.correlation_id,
                source_transport: metadata.source_transport,
            },
            payload: response_payload,
        };

        // Create original metadata for respond method
        let original_metadata = crate::transport::MessageMetadata {
            content_type: Some("application/json".to_string()),
            headers: context.headers.clone(),
            priority: None,
            ttl: None,
            reply_to: context.reply_to.clone(),
            operation: context.operation.clone(),
            correlation_id: context.correlation_id,
            source_transport: metadata.source_transport,
        };

        // Use the new respond method instead of send_envelope for responses
        self.transport_manager.respond(response_message, &original_metadata).await
            .map_err(|e| Box::new(AsyncApiError::Protocol {
                message: format!("Failed to send response: {e}"),
                protocol: "transport".to_string(),
                metadata: ErrorMetadata::new(ErrorSeverity::High, ErrorCategory::Network, true),
                source: Some(e),
            }))
    }
}

/// Get operation security configuration based on AsyncAPI specification analysis
pub fn get_operation_security_config() -> HashMap<String, bool> {
    #[allow(unused_mut)]
    let mut config = HashMap::new();
    config.insert("auth.login".to_string(), true);
    config.insert("auth.logout".to_string(), true);
    config.insert("device.bootstrap".to_string(), true);
    config.insert("device.get".to_string(), true);
    config.insert("device.configure".to_string(), true);
    config.insert("device.delete".to_string(), true);
    config.insert("device.list".to_string(), true);
    config.insert("device.update_metadata".to_string(), true);
    config.insert("network.topology".to_string(), true);
    config.insert("provision.refresh".to_string(), true);
    config.insert("salting.request".to_string(), true);
    config.insert("threats.report".to_string(), true);
    config.insert("threats.query".to_string(), true);
    config.insert("threats.download_pcap".to_string(), true);
    config.insert("validator_connection.report".to_string(), true);
    config.insert("connections.query".to_string(), true);
    config.insert("metrics.query".to_string(), true);
    config.insert("metrics.reset".to_string(), true);
    config.insert("tags.create".to_string(), true);
    config.insert("tags.update".to_string(), true);
    config.insert("tags.delete".to_string(), true);
    config.insert("tags.list".to_string(), true);
    config.insert("profiles.create".to_string(), true);
    config.insert("profiles.get".to_string(), true);
    config.insert("profiles.update".to_string(), true);
    config.insert("profiles.delete".to_string(), true);
    config.insert("profiles.list".to_string(), true);
    config.insert("profiles.assign".to_string(), true);
    config.insert("profiles.unassign".to_string(), true);
    config.insert("settings.get".to_string(), true);
    config.insert("settings.update".to_string(), true);
    config
}

/// Handler registry for backwards compatibility
pub struct HandlerRegistry {
    recovery_manager: Arc<crate::recovery::RecoveryManager>,
    transport_manager: Arc<crate::transport::TransportManager>,
}

impl HandlerRegistry {
    pub fn new(
        recovery_manager: Arc<crate::recovery::RecoveryManager>,
        transport_manager: Arc<crate::transport::TransportManager>,
    ) -> Self {
        Self {
            recovery_manager,
            transport_manager,
        }
    }

    pub fn with_managers(
        recovery_manager: Arc<crate::recovery::RecoveryManager>,
        transport_manager: Arc<crate::transport::TransportManager>,
    ) -> Self {
        Self::new(recovery_manager, transport_manager)
    }

    /// Get the recovery manager
    pub fn recovery_manager(&self) -> &Arc<crate::recovery::RecoveryManager> {
        &self.recovery_manager
    }

    /// Get the transport manager
    pub fn transport_manager(&self) -> &Arc<crate::transport::TransportManager> {
        &self.transport_manager
    }
}

//! Generated NATS client for Channel Lock Device Management API

use crate::auth::AuthCredentials;
use crate::envelope::MessageEnvelope;
use crate::errors::{ClientError, ClientResult};
use crate::models::*;
use bytes::Bytes;

/// Channel Lock Device Management API NATS client
///
/// This client provides type-safe access to Channel Lock Device Management API operations via NATS messaging.
/// It supports request/reply, publish/subscribe, and other NATS patterns based on the AsyncAPI specification.
///
/// ## Features
///
/// - **Type Safety**: All operations use strongly-typed message structures
/// - **NATS Services API**: Request/reply operations use NATS Services for reliability
/// - **Message Envelopes**: All messages are wrapped in a standard envelope format
/// - **Error Handling**: Comprehensive error types for different failure modes
/// - **Async/Await**: Full async support with Tokio compatibility
/// - **Dynamic Channels**: Support for channels with variable parameters
///
/// ## Usage
///
/// ```ignore
/// use async_nats;
/// use your_crate::CSKAClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Connect to NATS server
///     let nats_client = async_nats::connect("nats://localhost:4222").await?;
///
///     // Create the AsyncAPI client
///     let client = CSKAClient::with(nats_client);
///
///     // For dynamic channels, use the channel service:
///     // let service = client.user_create("us-west-1");
///     // let result = service.create_user(payload).await?;
///
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CSKAClient {
    client: async_nats::Client,
    auth: Option<AuthCredentials>,
}

impl CSKAClient {
    /// Create a new client with an existing NATS client
    ///
    /// # Arguments
    /// * `client` - A connected async-nats::Client instance
    ///
    /// # Example
    /// ```ignore
    /// use async_nats;
    /// use your_crate::CSKAClient;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let nats_client = async_nats::connect("nats://localhost:4222").await?;
    ///     let client = CSKAClient::with(nats_client);
    ///     Ok(())
    /// }
    /// ```
    pub fn with(client: async_nats::Client) -> Self {
        Self { client, auth: None }
    }

    /// Create a new client by connecting to NATS server
    ///
    /// # Arguments
    /// * `url` - NATS server URL (e.g., "nats://localhost:4222")
    ///
    /// # Example
    /// ```ignore
    /// use your_crate::CSKAClient;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = CSKAClient::connect("nats://localhost:4222").await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn connect(url: &str) -> ClientResult<Self> {
        let client = async_nats::connect(url)
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;
        Ok(Self::with(client))
    }

    /// Get a reference to the underlying NATS client
    ///
    /// This allows access to low-level NATS operations if needed.
    pub fn nats_client(&self) -> &async_nats::Client {
        &self.client
    }

    /// Create a new client with authentication credentials
    ///
    /// # Arguments
    /// * `client` - A connected async-nats::Client instance
    /// * `auth` - Authentication credentials
    ///
    /// # Example
    /// ```ignore
    /// use async_nats;
    /// use your_crate::{CSKAClient, AuthCredentials};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let nats_client = async_nats::connect("nats://localhost:4222").await?;
    ///     let auth = AuthCredentials::jwt("your-jwt-token");
    ///     let client = CSKAClient::with_auth(nats_client, auth);
    ///     Ok(())
    /// }
    /// ```
    pub fn with_auth(client: async_nats::Client, auth: AuthCredentials) -> ClientResult<Self> {
        auth.validate()?;
        Ok(Self {
            client,
            auth: Some(auth),
        })
    }

    /// Update authentication credentials
    ///
    /// This method allows you to update the authentication credentials for an existing client.
    /// All subsequent operations will use the new credentials.
    ///
    /// # Arguments
    /// * `auth` - New authentication credentials
    ///
    /// # Example
    /// ```ignore
    /// use your_crate::AuthCredentials;
    ///
    /// let new_auth = AuthCredentials::jwt("new-jwt-token");
    /// client.update_auth(new_auth)?;
    /// ```
    pub fn update_auth(&mut self, auth: AuthCredentials) -> ClientResult<()> {
        auth.validate()?;
        self.auth = Some(auth);
        Ok(())
    }

    /// Remove authentication credentials
    ///
    /// After calling this method, subsequent operations will not include authentication headers.
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Get the current authentication credentials
    pub fn auth(&self) -> Option<&AuthCredentials> {
        self.auth.as_ref()
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// Access device channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.device("cska-id");
    /// let result = service.device_bootstrap(payload).await?;
    /// ```
    pub fn device(&self, cska_id: &str) -> DeviceService {
        let mut service = DeviceService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access provision channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.provision("cska-id");
    /// let result = service.provision_refresh(payload).await?;
    /// ```
    pub fn provision(&self, cska_id: &str) -> ProvisionService {
        let mut service = ProvisionService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access salting channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.salting("cska-id");
    /// let result = service.salting_request(payload).await?;
    /// ```
    pub fn salting(&self, cska_id: &str) -> SaltingService {
        let mut service = SaltingService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access threats_nats channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.threats_nats("cska-id");
    /// let result = service.threats_report(payload).await?;
    /// ```
    pub fn threats_nats(&self, cska_id: &str) -> ThreatsNatsService {
        let mut service = ThreatsNatsService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access threats_ws channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.threats_ws("cska-id");
    /// let result = service.threats_query(payload).await?;
    /// ```
    pub fn threats_ws(&self, cska_id: &str) -> ThreatsWsService {
        let mut service = ThreatsWsService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access validator_connection channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.validator_connection("cska-id");
    /// let result = service.validator_connection_report(payload).await?;
    /// ```
    pub fn validator_connection(&self, cska_id: &str) -> ValidatorConnectionService {
        let mut service = ValidatorConnectionService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access connections channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.connections("cska-id");
    /// let result = service.connections_query(payload).await?;
    /// ```
    pub fn connections(&self, cska_id: &str) -> ConnectionsService {
        let mut service = ConnectionsService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access metrics channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.metrics("cska-id");
    /// let result = service.metrics_query(payload).await?;
    /// ```
    pub fn metrics(&self, cska_id: &str) -> MetricsService {
        let mut service = MetricsService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access tags channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.tags("cska-id");
    /// let result = service.tags_create(payload).await?;
    /// ```
    pub fn tags(&self, cska_id: &str) -> TagsService {
        let mut service = TagsService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access profiles channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.profiles("cska-id");
    /// let result = service.profiles_create(payload).await?;
    /// ```
    pub fn profiles(&self, cska_id: &str) -> ProfilesService {
        let mut service = ProfilesService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// Access settings channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    ///
    /// # Example
    /// ```ignore
    /// let service = client.settings("cska-id");
    /// let result = service.settings_get(payload).await?;
    /// ```
    pub fn settings(&self, cska_id: &str) -> SettingsService {
        let mut service = SettingsService::new(self.client.clone(), cska_id);
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }

    /// auth.login - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<LoginResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn auth_login(&self, payload: LoginRequest) -> ClientResult<LoginResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("auth.login", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("auth.login", payload)
                .map_err(ClientError::Serialization)?
        };

        let response = self.client
            .request("auth", Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: LoginResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// auth.logout - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<LogoutResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn auth_logout(&self, payload: LogoutRequest) -> ClientResult<LogoutResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("auth.logout", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("auth.logout", payload)
                .map_err(ClientError::Serialization)?
        };

        let response = self.client
            .request("auth", Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: LogoutResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// network.topology - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<GetNetworkTopologyResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn network_topology(&self, payload: GetNetworkTopologyRequest) -> ClientResult<GetNetworkTopologyResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("network.topology", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("network.topology", payload)
                .map_err(ClientError::Serialization)?
        };

        let response = self.client
            .request("network", Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: GetNetworkTopologyResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// device channel service with resolved parameters
///
/// This service provides access to operations on the device channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct DeviceService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl DeviceService {
    /// Create a new device service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "device.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// device.bootstrap - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<BootstrapDeviceResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn device_bootstrap(&self, payload: BootstrapDeviceRequest) -> ClientResult<BootstrapDeviceResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("device.bootstrap", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("device.bootstrap", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: BootstrapDeviceResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// device.get - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<GetDeviceResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn device_get(&self, payload: GetDeviceRequest) -> ClientResult<GetDeviceResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("device.get", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("device.get", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: GetDeviceResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// device.configure - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ConfigureDeviceResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn device_configure(&self, payload: ConfigureDeviceRequest) -> ClientResult<ConfigureDeviceResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("device.configure", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("device.configure", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ConfigureDeviceResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// device.delete - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<DeleteDeviceResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn device_delete(&self, payload: DeleteDeviceRequest) -> ClientResult<DeleteDeviceResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("device.delete", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("device.delete", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: DeleteDeviceResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// device.list - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ListDevicesResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn device_list(&self, payload: ListDevicesRequest) -> ClientResult<ListDevicesResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("device.list", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("device.list", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ListDevicesResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// device.status_update - Subscribe operation
    ///
    /// Creates a subscription to receive messages from the specified subject.
    /// Returns a NATS subscriber that can be used to receive messages.
    ///
    /// # Returns
    /// * `ClientResult<async_nats::Subscriber>` - NATS subscriber for handling messages
    ///
    /// # Example
    /// ```no-run
    /// let mut subscriber = service.device_status_update().await?;
    /// while let Some(message) = subscriber.next().await {
    ///     let envelope = MessageEnvelope::from_bytes(&message.payload)?;
    ///     let payload: DeviceStatusUpdateNotification = envelope.extract_payload()?;
    ///     // Handle the message...
    /// }
    /// ```
    pub async fn device_status_update(&self) -> ClientResult<async_nats::Subscriber> {
        let subject = self.resolved_subject.clone();
        let subscriber = self.client
            .subscribe(subject)
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        Ok(subscriber)
    }

    /// device.update_metadata - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<UpdateDeviceMetadataResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn device_update_metadata(&self, payload: UpdateDeviceMetadataRequest) -> ClientResult<UpdateDeviceMetadataResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("device.update_metadata", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("device.update_metadata", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: UpdateDeviceMetadataResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// provision channel service with resolved parameters
///
/// This service provides access to operations on the provision channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct ProvisionService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl ProvisionService {
    /// Create a new provision service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "provision.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// provision.refresh - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ProvisionDeviceRefreshResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn provision_refresh(&self, payload: ProvisionDeviceRefreshRequest) -> ClientResult<ProvisionDeviceRefreshResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("provision.refresh", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("provision.refresh", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ProvisionDeviceRefreshResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// salting channel service with resolved parameters
///
/// This service provides access to operations on the salting channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct SaltingService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl SaltingService {
    /// Create a new salting service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "salt.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// salting.request - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<SaltedKeyResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn salting_request(&self, payload: SaltedKeyRequest) -> ClientResult<SaltedKeyResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("salting.request", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("salting.request", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: SaltedKeyResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// threats_nats channel service with resolved parameters
///
/// This service provides access to operations on the threats_nats channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct ThreatsNatsService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl ThreatsNatsService {
    /// Create a new threats_nats service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "threats.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// threats.report - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ThreatReportResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn threats_report(&self, payload: ThreatReportRequest) -> ClientResult<ThreatReportResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("threats.report", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("threats.report", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ThreatReportResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// threats_ws channel service with resolved parameters
///
/// This service provides access to operations on the threats_ws channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct ThreatsWsService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl ThreatsWsService {
    /// Create a new threats_ws service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "threats.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// threats.query - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ThreatQueryResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn threats_query(&self, payload: ThreatQueryRequest) -> ClientResult<ThreatQueryResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("threats.query", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("threats.query", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ThreatQueryResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// threats.stream - Subscribe operation
    ///
    /// Creates a subscription to receive messages from the specified subject.
    /// Returns a NATS subscriber that can be used to receive messages.
    ///
    /// # Returns
    /// * `ClientResult<async_nats::Subscriber>` - NATS subscriber for handling messages
    ///
    /// # Example
    /// ```no-run
    /// let mut subscriber = service.threats_stream().await?;
    /// while let Some(message) = subscriber.next().await {
    ///     let envelope = MessageEnvelope::from_bytes(&message.payload)?;
    ///     let payload: ThreatStreamNotification = envelope.extract_payload()?;
    ///     // Handle the message...
    /// }
    /// ```
    pub async fn threats_stream(&self) -> ClientResult<async_nats::Subscriber> {
        let subject = self.resolved_subject.clone();
        let subscriber = self.client
            .subscribe(subject)
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        Ok(subscriber)
    }

    /// threats.download_pcap - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ThreatPcapDownloadResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn threats_download_pcap(&self, payload: ThreatPcapDownloadRequest) -> ClientResult<ThreatPcapDownloadResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("threats.download_pcap", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("threats.download_pcap", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ThreatPcapDownloadResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// validator_connection channel service with resolved parameters
///
/// This service provides access to operations on the validator_connection channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct ValidatorConnectionService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl ValidatorConnectionService {
    /// Create a new validator_connection service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "validator_connection.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// validator_connection.report - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ValidatorConnectionResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn validator_connection_report(&self, payload: ValidatorConnectionReport) -> ClientResult<ValidatorConnectionResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("validator_connection.report", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("validator_connection.report", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ValidatorConnectionResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// connections channel service with resolved parameters
///
/// This service provides access to operations on the connections channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct ConnectionsService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl ConnectionsService {
    /// Create a new connections service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "connections.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// connections.query - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ConnectionQueryResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn connections_query(&self, payload: ConnectionQueryRequest) -> ClientResult<ConnectionQueryResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("connections.query", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("connections.query", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ConnectionQueryResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// connections.stream - Subscribe operation
    ///
    /// Creates a subscription to receive messages from the specified subject.
    /// Returns a NATS subscriber that can be used to receive messages.
    ///
    /// # Returns
    /// * `ClientResult<async_nats::Subscriber>` - NATS subscriber for handling messages
    ///
    /// # Example
    /// ```no-run
    /// let mut subscriber = service.connections_stream().await?;
    /// while let Some(message) = subscriber.next().await {
    ///     let envelope = MessageEnvelope::from_bytes(&message.payload)?;
    ///     let payload: ConnectionStreamNotification = envelope.extract_payload()?;
    ///     // Handle the message...
    /// }
    /// ```
    pub async fn connections_stream(&self) -> ClientResult<async_nats::Subscriber> {
        let subject = self.resolved_subject.clone();
        let subscriber = self.client
            .subscribe(subject)
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        Ok(subscriber)
    }
}

/// metrics channel service with resolved parameters
///
/// This service provides access to operations on the metrics channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct MetricsService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl MetricsService {
    /// Create a new metrics service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "metrics.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// metrics.query - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<MetricsQueryResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn metrics_query(&self, payload: MetricsQueryRequest) -> ClientResult<MetricsQueryResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("metrics.query", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("metrics.query", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: MetricsQueryResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// metrics.stream - Subscribe operation
    ///
    /// Creates a subscription to receive messages from the specified subject.
    /// Returns a NATS subscriber that can be used to receive messages.
    ///
    /// # Returns
    /// * `ClientResult<async_nats::Subscriber>` - NATS subscriber for handling messages
    ///
    /// # Example
    /// ```no-run
    /// let mut subscriber = service.metrics_stream().await?;
    /// while let Some(message) = subscriber.next().await {
    ///     let envelope = MessageEnvelope::from_bytes(&message.payload)?;
    ///     let payload: MetricsStreamNotification = envelope.extract_payload()?;
    ///     // Handle the message...
    /// }
    /// ```
    pub async fn metrics_stream(&self) -> ClientResult<async_nats::Subscriber> {
        let subject = self.resolved_subject.clone();
        let subscriber = self.client
            .subscribe(subject)
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        Ok(subscriber)
    }

    /// metrics.reset - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<MetricsResetResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn metrics_reset(&self, payload: MetricsResetRequest) -> ClientResult<MetricsResetResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("metrics.reset", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("metrics.reset", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: MetricsResetResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// tags channel service with resolved parameters
///
/// This service provides access to operations on the tags channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct TagsService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl TagsService {
    /// Create a new tags service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "tags.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// tags.create - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<CreateTagResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn tags_create(&self, payload: CreateTagRequest) -> ClientResult<CreateTagResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("tags.create", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("tags.create", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: CreateTagResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// tags.update - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<UpdateTagResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn tags_update(&self, payload: UpdateTagRequest) -> ClientResult<UpdateTagResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("tags.update", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("tags.update", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: UpdateTagResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// tags.delete - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<DeleteTagResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn tags_delete(&self, payload: DeleteTagRequest) -> ClientResult<DeleteTagResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("tags.delete", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("tags.delete", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: DeleteTagResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// tags.list - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ListTagsResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn tags_list(&self, payload: ListTagsRequest) -> ClientResult<ListTagsResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("tags.list", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("tags.list", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ListTagsResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// profiles channel service with resolved parameters
///
/// This service provides access to operations on the profiles channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct ProfilesService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl ProfilesService {
    /// Create a new profiles service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "profiles.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// profiles.create - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<CreateProfileResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn profiles_create(&self, payload: CreateProfileRequest) -> ClientResult<CreateProfileResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("profiles.create", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("profiles.create", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: CreateProfileResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// profiles.get - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<GetProfileResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn profiles_get(&self, payload: GetProfileRequest) -> ClientResult<GetProfileResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("profiles.get", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("profiles.get", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: GetProfileResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// profiles.update - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<UpdateProfileResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn profiles_update(&self, payload: UpdateProfileRequest) -> ClientResult<UpdateProfileResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("profiles.update", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("profiles.update", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: UpdateProfileResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// profiles.delete - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<DeleteProfileResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn profiles_delete(&self, payload: DeleteProfileRequest) -> ClientResult<DeleteProfileResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("profiles.delete", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("profiles.delete", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: DeleteProfileResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// profiles.list - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<ListProfilesResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn profiles_list(&self, payload: ListProfilesRequest) -> ClientResult<ListProfilesResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("profiles.list", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("profiles.list", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: ListProfilesResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// profiles.assign - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<AssignProfileResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn profiles_assign(&self, payload: AssignProfileRequest) -> ClientResult<AssignProfileResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("profiles.assign", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("profiles.assign", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: AssignProfileResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// profiles.unassign - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<UnassignProfileResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn profiles_unassign(&self, payload: UnassignProfileRequest) -> ClientResult<UnassignProfileResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("profiles.unassign", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("profiles.unassign", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: UnassignProfileResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

/// settings channel service with resolved parameters
///
/// This service provides access to operations on the settings channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct SettingsService {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl SettingsService {
    /// Create a new settings service with resolved parameters
    ///
    /// # Arguments
        /// * `cska_id` - cska_id parameter
    pub fn new(client: async_nats::Client, cska_id: &str) -> Self {
        let resolved_subject = "settings.{cska_id}".to_string()
            .replace("{cska_id}", cska_id);

        Self {
            client,
            resolved_subject,
            auth: None,
        }
    }

    /// Get the resolved subject for this channel service
    pub fn subject(&self) -> &str {
        &self.resolved_subject
    }

    /// Create a new service with authentication credentials
    pub fn with_auth(mut self, auth: AuthCredentials) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Update authentication credentials
    pub fn update_auth(&mut self, auth: AuthCredentials) {
        self.auth = Some(auth);
    }

    /// Remove authentication credentials
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.auth.as_ref().map_or(false, |auth| auth.has_credentials())
    }

    /// settings.get - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<GetSettingsResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn settings_get(&self, payload: GetSettingsRequest) -> ClientResult<GetSettingsResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("settings.get", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("settings.get", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: GetSettingsResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }

    /// settings.update - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * `payload` - Request payload
    ///
    /// # Returns
    /// * `ClientResult<UpdateSettingsResponse>` - The response from the server
    ///
    /// # Errors
    /// * `ClientError::Nats` - NATS operation failed
    /// * `ClientError::Serialization` - Failed to serialize/deserialize data
    /// * `ClientError::Timeout` - Request timed out
    /// * `ClientError::AsyncApi` - Server returned an error
    pub async fn settings_update(&self, payload: UpdateSettingsRequest) -> ClientResult<UpdateSettingsResponse> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("settings.update", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("settings.update", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.resolved_subject.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        // Check if the response contains an error
        if let Some(error) = response_envelope.error {
            return Err(ClientError::AsyncApi(Box::new(error)));
        }

        let result: UpdateSettingsResponse = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }
}

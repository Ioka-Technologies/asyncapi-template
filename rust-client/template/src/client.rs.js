/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import {
    toRustIdentifier,
    toRustTypeName,
    toRustFieldName,
    getPayloadRustTypeName,
    getNatsSubject,
    isDynamicChannel,
    extractChannelVariables,
    getChannelParameters,
    resolveChannelAddress,
    channelHasParameters,
    toPascalCase,
    isTemplateVariable
} from '../helpers/index.js';

export default function ClientRs({ asyncapi, params }) {
    const info = asyncapi.info();
    const title = info.title();

    // Resolve clientName parameter, falling back to extracted values if parameter contains template variables
    const clientName = (params.clientName && !isTemplateVariable(params.clientName))
        ? params.clientName
        : `${toPascalCase(title)}Client`;

    // Extract all operations from the AsyncAPI spec
    const allOperations = [];
    const processedOperations = new Set(); // Track processed operations to avoid duplicates

    // Skip processing operations from the operations collection since we'll get them from channels
    // This avoids duplicate operations and ensures we have proper channel context

    // Extract channels and their operations (AsyncAPI 3.x style)
    const channelServices = [];
    if (asyncapi.channels) {
        const channels = asyncapi.channels();
        if (channels) {
            for (const channel of channels) {
                try {
                    const channelName = channel.id();
                    const subject = getNatsSubject(channel);
                    const isDynamic = isDynamicChannel(subject);
                    const parameters = isDynamic ? getChannelParameters(channel) : [];

                    // Create channel service info
                    const channelService = {
                        channelName,
                        subject,
                        isDynamic,
                        parameters,
                        operations: []
                    };

                    if (channel.operations) {
                        const operations = channel.operations();
                        if (operations) {
                            for (const operation of operations) {
                                try {
                                    const operationId = operation.id ? operation.id() : null;
                                    if (!operationId) continue;

                                    const action = operation.action ? operation.action() : 'send';
                                    const messages = operation.messages ? operation.messages() : null;

                                    if (!messages || !messages.all) continue;

                                    const messageArray = messages.all();
                                    if (!messageArray || messageArray.length === 0) continue;

                                    const firstMessage = messageArray[0];
                                    const methodName = toRustFieldName(operationId);

                                    if (action === 'send') {
                                        const reply = operation.reply ? operation.reply() : null;
                                        if (reply) {
                                            const replyMessages = reply.messages ? reply.messages() : null;
                                            if (replyMessages && replyMessages.all) {
                                                const replyMessageArray = replyMessages.all();
                                                if (replyMessageArray && replyMessageArray.length > 0) {
                                                    const opInfo = {
                                                        type: 'request_reply',
                                                        operationName: operationId,
                                                        methodName,
                                                        requestType: getPayloadRustTypeName(firstMessage),
                                                        responseType: getPayloadRustTypeName(replyMessageArray[0]),
                                                        subject,
                                                        channelName
                                                    };
                                                    channelService.operations.push(opInfo);
                                                    allOperations.push(opInfo);
                                                    processedOperations.add(operationId);
                                                    continue;
                                                }
                                            }
                                        }

                                        const opInfo = {
                                            type: 'publish',
                                            operationName: operationId,
                                            methodName,
                                            payloadType: getPayloadRustTypeName(firstMessage),
                                            subject,
                                            channelName
                                        };
                                        channelService.operations.push(opInfo);
                                        allOperations.push(opInfo);
                                        processedOperations.add(operationId);

                                        // Also add a subscription method for notification-type operations
                                        // (send operations without replies are typically notifications/events)
                                        const subscribeOpInfo = {
                                            type: 'subscribe',
                                            operationName: operationId,
                                            methodName: `subscribe_to_${methodName}`,
                                            payloadType: getPayloadRustTypeName(firstMessage),
                                            subject,
                                            channelName
                                        };
                                        channelService.operations.push(subscribeOpInfo);
                                        allOperations.push(subscribeOpInfo);
                                    } else if (action === 'receive') {
                                        const opInfo = {
                                            type: 'subscribe',
                                            operationName: operationId,
                                            methodName: toRustFieldName(operationId.replace(/^receive/, 'subscribeTo')),
                                            payloadType: getPayloadRustTypeName(firstMessage),
                                            subject,
                                            channelName
                                        };
                                        channelService.operations.push(opInfo);
                                        allOperations.push(opInfo);
                                        processedOperations.add(operationId);
                                    }
                                } catch (e) {
                                    console.warn(`Error processing channel operation: ${e.message}`);
                                }
                            }
                        }
                    }

                    if (channelService.operations.length > 0) {
                        channelServices.push(channelService);
                    }
                } catch (e) {
                    console.warn(`Error processing channel: ${e.message}`);
                }
            }
        }
    }

    // Generate channel service structs for dynamic channels
    function generateChannelServices() {
        const dynamicChannels = channelServices.filter(cs => cs.isDynamic);
        if (dynamicChannels.length === 0) {
            return '';
        }

        return dynamicChannels.map(channelService => {
            const serviceName = `${toPascalCase(channelService.channelName)}Service`;

            // Extract variables from the channel address to get the actual parameter names
            const variables = extractChannelVariables(channelService.subject);
            const actualParams = variables.map(varName => ({
                name: varName,
                rustName: toRustFieldName(varName),
                description: channelService.parameters.find(p => p.name === varName)?.description || `${varName} parameter`
            }));

            const paramSignature = actualParams.map(p => `${p.rustName}: &str`).join(', ');
            const paramArgs = actualParams.map(p => `${p.rustName}: ${p.rustName}.to_string()`).join(', ');

            const serviceOperations = channelService.operations.map(op => {
                const resolvedSubject = 'resolved_subject';

                switch (op.type) {
                    case 'request_reply':
                        return `    /// ${op.operationName} - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * \`payload\` - Request payload
    ///
    /// # Returns
    /// * \`ClientResult<${op.responseType}>\` - The response from the server
    ///
    /// # Errors
    /// * \`ClientError::Nats\` - NATS operation failed
    /// * \`ClientError::Serialization\` - Failed to serialize/deserialize data
    /// * \`ClientError::Timeout\` - Request timed out
    pub async fn ${op.methodName}(&self, payload: ${op.requestType}) -> ClientResult<${op.responseType}> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("${op.operationName}", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("${op.operationName}", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.${resolvedSubject}.clone();
        let response = self.client
            .request(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        let result: ${op.responseType} = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }`;

                    case 'publish':
                        return `    /// ${op.operationName} - Publish operation
    ///
    /// Publishes a message using NATS publish (fire-and-forget).
    /// This is a one-way operation with no response expected.
    ///
    /// # Arguments
    /// * \`payload\` - Message payload to publish
    ///
    /// # Errors
    /// * \`ClientError::Nats\` - NATS operation failed
    /// * \`ClientError::Serialization\` - Failed to serialize data
    pub async fn ${op.methodName}(&self, payload: ${op.payloadType}) -> ClientResult<()> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("${op.operationName}", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("${op.operationName}", payload)
                .map_err(ClientError::Serialization)?
        };

        let subject = self.${resolvedSubject}.clone();
        self.client
            .publish(subject, Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        Ok(())
    }`;

                    case 'subscribe':
                        return `    /// ${op.operationName} - Subscribe operation
    ///
    /// Creates a subscription to receive messages from the specified subject.
    /// Returns a NATS subscriber that can be used to receive messages.
    ///
    /// # Returns
    /// * \`ClientResult<async_nats::Subscriber>\` - NATS subscriber for handling messages
    ///
    /// # Example
    /// \`\`\`no-run
    /// let mut subscriber = service.${op.methodName}().await?;
    /// while let Some(message) = subscriber.next().await {
    ///     let envelope = MessageEnvelope::from_bytes(&message.payload)?;
    ///     let payload: ${op.payloadType} = envelope.extract_payload()?;
    ///     // Handle the message...
    /// }
    /// \`\`\`
    pub async fn ${op.methodName}(&self) -> ClientResult<async_nats::Subscriber> {
        let subject = self.${resolvedSubject}.clone();
        let subscriber = self.client
            .subscribe(subject)
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        Ok(subscriber)
    }`;

                    default:
                        return '';
                }
            }).filter(method => method).join('\n\n');

            return `
/// ${channelService.channelName} channel service with resolved parameters
///
/// This service provides access to operations on the ${channelService.channelName} channel
/// with resolved channel parameters for dynamic routing.
#[derive(Debug, Clone)]
pub struct ${serviceName} {
    client: async_nats::Client,
    resolved_subject: String,
    auth: Option<AuthCredentials>,
}

impl ${serviceName} {
    /// Create a new ${channelService.channelName} service with resolved parameters
    ///
    /// # Arguments
    ${actualParams.map(p => `    /// * \`${p.rustName}\` - ${p.description}`).join('\n')}
    pub fn new(client: async_nats::Client, ${paramSignature}) -> Self {
        let resolved_subject = "${channelService.subject}".to_string()${actualParams.map((p, index) => {
                return `
            .replace("{${p.name}}", ${p.rustName})`;
            }).join('')};

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

${serviceOperations}
}`;
        }).join('\n');
    }

    // Generate client methods for static channels and channel service accessors for dynamic channels
    function generateClientMethods() {
        const staticOperations = allOperations.filter(op => {
            const channelService = channelServices.find(cs => cs.channelName === op.channelName);
            return !channelService || !channelService.isDynamic;
        });

        const dynamicChannelAccessors = channelServices.filter(cs => cs.isDynamic).map(channelService => {
            const serviceName = `${toPascalCase(channelService.channelName)}Service`;

            // Extract variables from the channel address to get the actual parameter names
            const variables = extractChannelVariables(channelService.subject);
            const actualParams = variables.map(varName => ({
                name: varName,
                rustName: toRustFieldName(varName),
                description: channelService.parameters.find(p => p.name === varName)?.description || `${varName} parameter`
            }));

            const paramSignature = actualParams.map(p => `${p.rustName}: &str`).join(', ');

            return `    /// Access ${channelService.channelName} channel operations with parameters
    ///
    /// Returns a service instance configured for the specific channel parameters.
    ///
    /// # Arguments
    ${actualParams.map(p => `    /// * \`${p.rustName}\` - ${p.description}`).join('\n')}
    ///
    /// # Example
    /// \`\`\`ignore
    /// let service = client.${toRustFieldName(channelService.channelName)}(${actualParams.map(p => `"${p.name.replace('_', '-')}"`).join(', ')});
    /// let result = service.${channelService.operations[0]?.methodName || 'operation'}(payload).await?;
    /// \`\`\`
    pub fn ${toRustFieldName(channelService.channelName)}(&self, ${paramSignature}) -> ${serviceName} {
        let mut service = ${serviceName}::new(self.client.clone(), ${actualParams.map(p => p.rustName).join(', ')});
        if let Some(ref auth) = self.auth {
            service.auth = Some(auth.clone());
        }
        service
    }`;
        });

        const staticMethods = staticOperations.map(pattern => {
            const subject = pattern.subject || pattern.channelName || 'unknown.subject';

            switch (pattern.type) {
                case 'request_reply':
                    return `    /// ${pattern.operationName} - Request/Reply operation
    ///
    /// Sends a request and waits for a response using NATS request/reply pattern.
    /// This operation uses the NATS Services API for reliable request/response messaging.
    ///
    /// # Arguments
    /// * \`payload\` - Request payload
    ///
    /// # Returns
    /// * \`ClientResult<${pattern.responseType}>\` - The response from the server
    ///
    /// # Errors
    /// * \`ClientError::Nats\` - NATS operation failed
    /// * \`ClientError::Serialization\` - Failed to serialize/deserialize data
    /// * \`ClientError::Timeout\` - Request timed out
    pub async fn ${pattern.methodName}(&self, payload: ${pattern.requestType}) -> ClientResult<${pattern.responseType}> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("${pattern.operationName}", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("${pattern.operationName}", payload)
                .map_err(ClientError::Serialization)?
        };

        let response = self.client
            .request("${subject}", Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        let response_envelope = MessageEnvelope::from_bytes(&response.payload)
            .map_err(|e| ClientError::InvalidEnvelope(e.to_string()))?;

        let result: ${pattern.responseType} = response_envelope.extract_payload()
            .map_err(ClientError::Serialization)?;

        Ok(result)
    }`;

                case 'publish':
                    return `    /// ${pattern.operationName} - Publish operation
    ///
    /// Publishes a message using NATS publish (fire-and-forget).
    /// This is a one-way operation with no response expected.
    ///
    /// # Arguments
    /// * \`payload\` - Message payload to publish
    ///
    /// # Errors
    /// * \`ClientError::Nats\` - NATS operation failed
    /// * \`ClientError::Serialization\` - Failed to serialize data
    pub async fn ${pattern.methodName}(&self, payload: ${pattern.payloadType}) -> ClientResult<()> {
        let envelope = if let Some(ref auth) = self.auth {
            MessageEnvelope::new_with_auth("${pattern.operationName}", payload, auth)
                .map_err(ClientError::Serialization)?
        } else {
            MessageEnvelope::new("${pattern.operationName}", payload)
                .map_err(ClientError::Serialization)?
        };

        self.client
            .publish("${subject}", Bytes::from(envelope.to_bytes()?))
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        Ok(())
    }`;

                case 'subscribe':
                    return `    /// ${pattern.operationName} - Subscribe operation
    ///
    /// Creates a subscription to receive messages from the specified subject.
    /// Returns a NATS subscriber that can be used to receive messages.
    ///
    /// # Returns
    /// * \`ClientResult<async_nats::Subscriber>\` - NATS subscriber for handling messages
    ///
    /// # Example
    /// \`\`\`ignore
    /// let mut subscriber = client.${pattern.methodName}().await?;
    /// while let Some(message) = subscriber.next().await {
    ///     let envelope = MessageEnvelope::from_bytes(&message.payload)?;
    ///     let payload: ${pattern.payloadType} = envelope.extract_payload()?;
    ///     // Handle the message...
    /// }
    /// \`\`\`
    pub async fn ${pattern.methodName}(&self) -> ClientResult<async_nats::Subscriber> {
        let subscriber = self.client
            .subscribe("${subject}")
            .await
            .map_err(|e| ClientError::Nats(Box::new(e)))?;

        Ok(subscriber)
    }`;

                default:
                    return '';
            }
        }).filter(method => method);

        const allMethods = [...dynamicChannelAccessors, ...staticMethods];

        if (allMethods.length === 0) {
            return `    // No operations found in AsyncAPI specification
    // You can add custom methods here`;
        }

        return allMethods.join('\n\n');
    }

    return (
        <File name="client.rs">
            {`//! Generated NATS client for ${title}

use crate::auth::AuthCredentials;
use crate::envelope::MessageEnvelope;
use crate::errors::{ClientError, ClientResult};
use crate::models::*;
use bytes::Bytes;

/// ${title} NATS client
///
/// This client provides type-safe access to ${title} operations via NATS messaging.
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
/// \`\`\`ignore
/// use async_nats;
/// use your_crate::${clientName};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Connect to NATS server
///     let nats_client = async_nats::connect("nats://localhost:4222").await?;
///
///     // Create the AsyncAPI client
///     let client = ${clientName}::with(nats_client);
///
///     // For dynamic channels, use the channel service:
///     // let service = client.user_create("us-west-1");
///     // let result = service.create_user(payload).await?;
///
///     Ok(())
/// }
/// \`\`\`
#[derive(Debug, Clone)]
pub struct ${clientName} {
    client: async_nats::Client,
    auth: Option<AuthCredentials>,
}

impl ${clientName} {
    /// Create a new client with an existing NATS client
    ///
    /// # Arguments
    /// * \`client\` - A connected async-nats::Client instance
    ///
    /// # Example
    /// \`\`\`ignore
    /// use async_nats;
    /// use your_crate::${clientName};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let nats_client = async_nats::connect("nats://localhost:4222").await?;
    ///     let client = ${clientName}::with(nats_client);
    ///     Ok(())
    /// }
    /// \`\`\`
    pub fn with(client: async_nats::Client) -> Self {
        Self { client, auth: None }
    }

    /// Create a new client by connecting to NATS server
    ///
    /// # Arguments
    /// * \`url\` - NATS server URL (e.g., "nats://localhost:4222")
    ///
    /// # Example
    /// \`\`\`ignore
    /// use your_crate::${clientName};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = ${clientName}::connect("nats://localhost:4222").await?;
    ///     Ok(())
    /// }
    /// \`\`\`
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
    /// * \`client\` - A connected async-nats::Client instance
    /// * \`auth\` - Authentication credentials
    ///
    /// # Example
    /// \`\`\`ignore
    /// use async_nats;
    /// use your_crate::{${clientName}, AuthCredentials};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let nats_client = async_nats::connect("nats://localhost:4222").await?;
    ///     let auth = AuthCredentials::jwt("your-jwt-token");
    ///     let client = ${clientName}::with_auth(nats_client, auth);
    ///     Ok(())
    /// }
    /// \`\`\`
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
    /// * \`auth\` - New authentication credentials
    ///
    /// # Example
    /// \`\`\`ignore
    /// use your_crate::AuthCredentials;
    ///
    /// let new_auth = AuthCredentials::jwt("new-jwt-token");
    /// client.update_auth(new_auth)?;
    /// \`\`\`
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

${generateClientMethods()}
}
${generateChannelServices()}
`}
        </File>
    );
}

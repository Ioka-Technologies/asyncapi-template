import { TransportFactory } from './runtime/transports/factory';
import { Transport, TransportConfig, RequestOptions, MessageEnvelope } from './runtime/types';
import { AuthCredentials } from './runtime/auth/types';
import * as Models from './models';

export class ChannelLockDeviceManagementAPIClient {
    private transport: Transport;
    private config: TransportConfig;

    constructor(config: TransportConfig) {
        this.config = config;
        this.transport = TransportFactory.create(config);
    }

    async connect(): Promise<void> {
        await this.transport.connect();
    }

    async disconnect(): Promise<void> {
        await this.transport.disconnect();
    }

    /**
     * Unsubscribe from a specific channel
     * @param channel Channel to unsubscribe from
     * @param callback Optional specific callback to remove
     */
    unsubscribe(channel: string, callback?: (payload: any) => void): void {
        this.transport.unsubscribe(channel, callback);
    }

    /**
     * Update authentication configuration
     * @param auth New authentication configuration
     */
    updateAuth(auth: AuthCredentials): void {
        this.config.auth = auth;
        // If transport supports auth updates, update it
        if (this.transport && typeof (this.transport as any).updateAuth === 'function') {
            (this.transport as any).updateAuth(auth);
        }
    }

    /**
     * Get current authentication configuration
     * @returns Current auth configuration
     */
    getAuth(): AuthCredentials | undefined {
        return this.config.auth;
    }

    // Generated operation methods

    /**
     * Access device channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns DeviceService instance for the resolved channel
     *
     * @example
     * const service = client.device('cska-id');
     * await service.someOperation(payload);
     */
    device(cska_id: string): DeviceService {
        return new DeviceService(this.transport, cska_id);
    }

    /**
     * Access provision channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns ProvisionService instance for the resolved channel
     *
     * @example
     * const service = client.provision('cska-id');
     * await service.someOperation(payload);
     */
    provision(cska_id: string): ProvisionService {
        return new ProvisionService(this.transport, cska_id);
    }

    /**
     * Access salting channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns SaltingService instance for the resolved channel
     *
     * @example
     * const service = client.salting('cska-id');
     * await service.someOperation(payload);
     */
    salting(cska_id: string): SaltingService {
        return new SaltingService(this.transport, cska_id);
    }

    /**
     * Access threats_nats channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns Threats_natsService instance for the resolved channel
     *
     * @example
     * const service = client.threatsnats('cska-id');
     * await service.someOperation(payload);
     */
    threatsnats(cska_id: string): Threats_natsService {
        return new Threats_natsService(this.transport, cska_id);
    }

    /**
     * Access threats_ws channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns Threats_wsService instance for the resolved channel
     *
     * @example
     * const service = client.threatsws('cska-id');
     * await service.someOperation(payload);
     */
    threatsws(cska_id: string): Threats_wsService {
        return new Threats_wsService(this.transport, cska_id);
    }

    /**
     * Access validator_connection channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns Validator_connectionService instance for the resolved channel
     *
     * @example
     * const service = client.validatorconnection('cska-id');
     * await service.someOperation(payload);
     */
    validatorconnection(cska_id: string): Validator_connectionService {
        return new Validator_connectionService(this.transport, cska_id);
    }

    /**
     * Access connections channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns ConnectionsService instance for the resolved channel
     *
     * @example
     * const service = client.connections('cska-id');
     * await service.someOperation(payload);
     */
    connections(cska_id: string): ConnectionsService {
        return new ConnectionsService(this.transport, cska_id);
    }

    /**
     * Access metrics channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns MetricsService instance for the resolved channel
     *
     * @example
     * const service = client.metrics('cska-id');
     * await service.someOperation(payload);
     */
    metrics(cska_id: string): MetricsService {
        return new MetricsService(this.transport, cska_id);
    }

    /**
     * Access tags channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns TagsService instance for the resolved channel
     *
     * @example
     * const service = client.tags('cska-id');
     * await service.someOperation(payload);
     */
    tags(cska_id: string): TagsService {
        return new TagsService(this.transport, cska_id);
    }

    /**
     * Access profiles channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns ProfilesService instance for the resolved channel
     *
     * @example
     * const service = client.profiles('cska-id');
     * await service.someOperation(payload);
     */
    profiles(cska_id: string): ProfilesService {
        return new ProfilesService(this.transport, cska_id);
    }

    /**
     * Access settings channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns SettingsService instance for the resolved channel
     *
     * @example
     * const service = client.settings('cska-id');
     * await service.someOperation(payload);
     */
    settings(cska_id: string): SettingsService {
        return new SettingsService(this.transport, cska_id);
    }

    /**
     * authLogin - Request/Response operation
     * Original operation: auth.login
     * Channel: auth
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async authLogin(payload: Models.LoginRequestPayload, options?: RequestOptions): Promise<Models.LoginResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'auth.login',
            payload,
            channel: 'auth'
        };
        return this.transport.send('auth', envelope, options);
    }

    /**
     * authLogout - Request/Response operation
     * Original operation: auth.logout
     * Channel: auth
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async authLogout(payload: Models.LogoutRequestPayload, options?: RequestOptions): Promise<Models.LogoutResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'auth.logout',
            payload,
            channel: 'auth'
        };
        return this.transport.send('auth', envelope, options);
    }

    /**
     * networkTopology - Request/Response operation
     * Original operation: network.topology
     * Channel: network
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async networkTopology(payload: Models.GetNetworkTopologyRequestPayload, options?: RequestOptions): Promise<Models.GetNetworkTopologyResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'network.topology',
            payload,
            channel: 'network'
        };
        return this.transport.send('network', envelope, options);
    }

}

/**
 * device channel service with resolved parameters
 *
 * This service provides access to operations on the device channel
 * with resolved channel parameters for dynamic routing.
 */
export class DeviceService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'device.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * deviceBootstrap - Request/Response operation
     * Original operation: device.bootstrap
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async deviceBootstrap(payload: Models.BootstrapDeviceRequestPayload, options?: RequestOptions): Promise<Models.BootstrapDeviceResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'device.bootstrap',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * deviceGet - Request/Response operation
     * Original operation: device.get
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async deviceGet(payload: Models.GetDeviceRequestPayload, options?: RequestOptions): Promise<Models.GetDeviceResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'device.get',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * deviceConfigure - Request/Response operation
     * Original operation: device.configure
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async deviceConfigure(payload: Models.ConfigureDeviceRequestPayload, options?: RequestOptions): Promise<Models.ConfigureDeviceResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'device.configure',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * deviceDelete - Request/Response operation
     * Original operation: device.delete
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async deviceDelete(payload: Models.DeleteDeviceRequestPayload, options?: RequestOptions): Promise<Models.DeleteDeviceResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'device.delete',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * deviceList - Request/Response operation
     * Original operation: device.list
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async deviceList(payload: Models.ListDevicesRequestPayload, options?: RequestOptions): Promise<Models.ListDevicesResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'device.list',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * deviceStatusUpdate - Receive operation
     * Original operation: device.status_update
     * @param callback Function to call when a message is received
     * @returns Unsubscribe function to stop listening for messages
     */
    deviceStatusUpdate(callback: (payload: Models.DeviceStatusUpdateNotificationPayload) => void): () => void {
        return this.transport.subscribe(this.resolvedChannel, 'device.status_update', (envelope: MessageEnvelope) => {
            // Filter by operation to ensure we only handle messages for this specific operation
            if (envelope.operation === 'device.status_update') {
                callback(envelope.payload);
            }
        });
    }

    /**
     * deviceUpdateMetadata - Request/Response operation
     * Original operation: device.update_metadata
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async deviceUpdateMetadata(payload: Models.UpdateDeviceMetadataRequestPayload, options?: RequestOptions): Promise<Models.UpdateDeviceMetadataResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'device.update_metadata',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * provision channel service with resolved parameters
 *
 * This service provides access to operations on the provision channel
 * with resolved channel parameters for dynamic routing.
 */
export class ProvisionService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'provision.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * provisionRefresh - Request/Response operation
     * Original operation: provision.refresh
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async provisionRefresh(payload: Models.ProvisionDeviceRefreshRequestPayload, options?: RequestOptions): Promise<Models.ProvisionDeviceRefreshResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'provision.refresh',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * salting channel service with resolved parameters
 *
 * This service provides access to operations on the salting channel
 * with resolved channel parameters for dynamic routing.
 */
export class SaltingService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'salt.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * saltingRequest - Request/Response operation
     * Original operation: salting.request
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async saltingRequest(payload: Models.SaltedKeyRequestPayload, options?: RequestOptions): Promise<Models.SaltedKeyResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'salting.request',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * threats_nats channel service with resolved parameters
 *
 * This service provides access to operations on the threats_nats channel
 * with resolved channel parameters for dynamic routing.
 */
export class Threats_natsService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'threats.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * threatsReport - Request/Response operation
     * Original operation: threats.report
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async threatsReport(payload: Models.ThreatReportRequestPayload, options?: RequestOptions): Promise<Models.ThreatReportResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'threats.report',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * threatsQuery - Request/Response operation
     * Original operation: threats.query
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async threatsQuery(payload: Models.ThreatQueryRequestPayload, options?: RequestOptions): Promise<Models.ThreatQueryResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'threats.query',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * threatsStream - Receive operation
     * Original operation: threats.stream
     * @param callback Function to call when a message is received
     * @returns Unsubscribe function to stop listening for messages
     */
    threatsStream(callback: (payload: Models.ThreatStreamNotificationPayload) => void): () => void {
        return this.transport.subscribe(this.resolvedChannel, 'threats.stream', (envelope: MessageEnvelope) => {
            // Filter by operation to ensure we only handle messages for this specific operation
            if (envelope.operation === 'threats.stream') {
                callback(envelope.payload);
            }
        });
    }

    /**
     * threatsDownloadPcap - Request/Response operation
     * Original operation: threats.download_pcap
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async threatsDownloadPcap(payload: Models.ThreatPcapDownloadRequestPayload, options?: RequestOptions): Promise<Models.ThreatPcapDownloadResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'threats.download_pcap',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * threats_ws channel service with resolved parameters
 *
 * This service provides access to operations on the threats_ws channel
 * with resolved channel parameters for dynamic routing.
 */
export class Threats_wsService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'threats.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * threatsReport - Request/Response operation
     * Original operation: threats.report
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async threatsReport(payload: Models.ThreatReportRequestPayload, options?: RequestOptions): Promise<Models.ThreatReportResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'threats.report',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * threatsQuery - Request/Response operation
     * Original operation: threats.query
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async threatsQuery(payload: Models.ThreatQueryRequestPayload, options?: RequestOptions): Promise<Models.ThreatQueryResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'threats.query',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * threatsStream - Receive operation
     * Original operation: threats.stream
     * @param callback Function to call when a message is received
     * @returns Unsubscribe function to stop listening for messages
     */
    threatsStream(callback: (payload: Models.ThreatStreamNotificationPayload) => void): () => void {
        return this.transport.subscribe(this.resolvedChannel, 'threats.stream', (envelope: MessageEnvelope) => {
            // Filter by operation to ensure we only handle messages for this specific operation
            if (envelope.operation === 'threats.stream') {
                callback(envelope.payload);
            }
        });
    }

    /**
     * threatsDownloadPcap - Request/Response operation
     * Original operation: threats.download_pcap
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async threatsDownloadPcap(payload: Models.ThreatPcapDownloadRequestPayload, options?: RequestOptions): Promise<Models.ThreatPcapDownloadResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'threats.download_pcap',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * validator_connection channel service with resolved parameters
 *
 * This service provides access to operations on the validator_connection channel
 * with resolved channel parameters for dynamic routing.
 */
export class Validator_connectionService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'validator_connection.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * validatorConnectionReport - Request/Response operation
     * Original operation: validator_connection.report
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async validatorConnectionReport(payload: Models.ValidatorConnectionReportPayload, options?: RequestOptions): Promise<Models.ValidatorConnectionResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'validator_connection.report',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * connections channel service with resolved parameters
 *
 * This service provides access to operations on the connections channel
 * with resolved channel parameters for dynamic routing.
 */
export class ConnectionsService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'connections.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * connectionsQuery - Request/Response operation
     * Original operation: connections.query
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async connectionsQuery(payload: Models.ConnectionQueryRequestPayload, options?: RequestOptions): Promise<Models.ConnectionQueryResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'connections.query',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * connectionsStream - Receive operation
     * Original operation: connections.stream
     * @param callback Function to call when a message is received
     * @returns Unsubscribe function to stop listening for messages
     */
    connectionsStream(callback: (payload: Models.ConnectionStreamNotificationPayload) => void): () => void {
        return this.transport.subscribe(this.resolvedChannel, 'connections.stream', (envelope: MessageEnvelope) => {
            // Filter by operation to ensure we only handle messages for this specific operation
            if (envelope.operation === 'connections.stream') {
                callback(envelope.payload);
            }
        });
    }

}

/**
 * metrics channel service with resolved parameters
 *
 * This service provides access to operations on the metrics channel
 * with resolved channel parameters for dynamic routing.
 */
export class MetricsService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'metrics.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * metricsQuery - Request/Response operation
     * Original operation: metrics.query
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async metricsQuery(payload: Models.MetricsQueryRequestPayload, options?: RequestOptions): Promise<Models.MetricsQueryResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'metrics.query',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * metricsStream - Receive operation
     * Original operation: metrics.stream
     * @param callback Function to call when a message is received
     * @returns Unsubscribe function to stop listening for messages
     */
    metricsStream(callback: (payload: Models.MetricsStreamNotificationPayload) => void): () => void {
        return this.transport.subscribe(this.resolvedChannel, 'metrics.stream', (envelope: MessageEnvelope) => {
            // Filter by operation to ensure we only handle messages for this specific operation
            if (envelope.operation === 'metrics.stream') {
                callback(envelope.payload);
            }
        });
    }

    /**
     * metricsReset - Request/Response operation
     * Original operation: metrics.reset
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async metricsReset(payload: Models.MetricsResetRequestPayload, options?: RequestOptions): Promise<Models.MetricsResetResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'metrics.reset',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * tags channel service with resolved parameters
 *
 * This service provides access to operations on the tags channel
 * with resolved channel parameters for dynamic routing.
 */
export class TagsService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'tags.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * tagsCreate - Request/Response operation
     * Original operation: tags.create
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async tagsCreate(payload: Models.CreateTagRequestPayload, options?: RequestOptions): Promise<Models.CreateTagResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'tags.create',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * tagsUpdate - Request/Response operation
     * Original operation: tags.update
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async tagsUpdate(payload: Models.UpdateTagRequestPayload, options?: RequestOptions): Promise<Models.UpdateTagResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'tags.update',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * tagsDelete - Request/Response operation
     * Original operation: tags.delete
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async tagsDelete(payload: Models.DeleteTagRequestPayload, options?: RequestOptions): Promise<Models.DeleteTagResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'tags.delete',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * tagsList - Request/Response operation
     * Original operation: tags.list
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async tagsList(payload: Models.ListTagsRequestPayload, options?: RequestOptions): Promise<Models.ListTagsResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'tags.list',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * profiles channel service with resolved parameters
 *
 * This service provides access to operations on the profiles channel
 * with resolved channel parameters for dynamic routing.
 */
export class ProfilesService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'profiles.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * profilesCreate - Request/Response operation
     * Original operation: profiles.create
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async profilesCreate(payload: Models.CreateProfileRequestPayload, options?: RequestOptions): Promise<Models.CreateProfileResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'profiles.create',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * profilesGet - Request/Response operation
     * Original operation: profiles.get
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async profilesGet(payload: Models.GetProfileRequestPayload, options?: RequestOptions): Promise<Models.GetProfileResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'profiles.get',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * profilesUpdate - Request/Response operation
     * Original operation: profiles.update
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async profilesUpdate(payload: Models.UpdateProfileRequestPayload, options?: RequestOptions): Promise<Models.UpdateProfileResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'profiles.update',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * profilesDelete - Request/Response operation
     * Original operation: profiles.delete
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async profilesDelete(payload: Models.DeleteProfileRequestPayload, options?: RequestOptions): Promise<Models.DeleteProfileResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'profiles.delete',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * profilesList - Request/Response operation
     * Original operation: profiles.list
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async profilesList(payload: Models.ListProfilesRequestPayload, options?: RequestOptions): Promise<Models.ListProfilesResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'profiles.list',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * profilesAssign - Request/Response operation
     * Original operation: profiles.assign
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async profilesAssign(payload: Models.AssignProfileRequestPayload, options?: RequestOptions): Promise<Models.AssignProfileResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'profiles.assign',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * profilesUnassign - Request/Response operation
     * Original operation: profiles.unassign
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async profilesUnassign(payload: Models.UnassignProfileRequestPayload, options?: RequestOptions): Promise<Models.UnassignProfileResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'profiles.unassign',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * settings channel service with resolved parameters
 *
 * This service provides access to operations on the settings channel
 * with resolved channel parameters for dynamic routing.
 */
export class SettingsService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'settings.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * settingsGet - Request/Response operation
     * Original operation: settings.get
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async settingsGet(payload: Models.GetSettingsRequestPayload, options?: RequestOptions): Promise<Models.GetSettingsResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'settings.get',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * settingsUpdate - Request/Response operation
     * Original operation: settings.update
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async settingsUpdate(payload: Models.UpdateSettingsRequestPayload, options?: RequestOptions): Promise<Models.UpdateSettingsResponsePayload> {
        const envelope: MessageEnvelope = {
            operation: 'settings.update',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

export default ChannelLockDeviceManagementAPIClient;

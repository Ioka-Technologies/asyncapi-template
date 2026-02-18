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
     * Access users channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns UsersService instance for the resolved channel
     *
     * @example
     * const service = client.users('cska-id');
     * await service.someOperation(payload);
     */
    users(cska_id: string): UsersService {
        return new UsersService(this.transport, cska_id);
    }

    /**
     * Access sso channel operations with parameters
     *
     * Returns a service instance configured for the specific channel parameters.
     *
     * @param cska_id cska_id parameter
     * @returns SsoService instance for the resolved channel
     *
     * @example
     * const service = client.sso('cska-id');
     * await service.someOperation(payload);
     */
    sso(cska_id: string): SsoService {
        return new SsoService(this.transport, cska_id);
    }

    /**
     * authLogout - Request/Response operation
     * Original operation: auth.logout
     * Channel: auth
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async authLogout(payload: Models.LogoutRequest, options?: RequestOptions): Promise<Models.LogoutResponse> {
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
    async networkTopology(payload: Models.GetNetworkTopologyRequest, options?: RequestOptions): Promise<Models.GetNetworkTopologyResponse> {
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
    async deviceBootstrap(payload: Models.BootstrapDeviceRequest, options?: RequestOptions): Promise<Models.BootstrapDeviceResponse> {
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
    async deviceGet(payload: Models.GetDeviceRequest, options?: RequestOptions): Promise<Models.GetDeviceResponse> {
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
    async deviceConfigure(payload: Models.ConfigureDeviceRequest, options?: RequestOptions): Promise<Models.ConfigureDeviceResponse> {
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
    async deviceDelete(payload: Models.DeleteDeviceRequest, options?: RequestOptions): Promise<Models.DeleteDeviceResponse> {
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
    async deviceList(payload: Models.ListDevicesRequest, options?: RequestOptions): Promise<Models.ListDevicesResponse> {
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
    deviceStatusUpdate(callback: (payload: Models.DeviceStatusUpdateNotification) => void): () => void {
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
    async deviceUpdateMetadata(payload: Models.UpdateDeviceMetadataRequest, options?: RequestOptions): Promise<Models.UpdateDeviceMetadataResponse> {
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
    async provisionRefresh(payload: Models.ProvisionDeviceRefreshRequest, options?: RequestOptions): Promise<Models.ProvisionDeviceRefreshResponse> {
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
    async saltingRequest(payload: Models.SaltedKeyRequest, options?: RequestOptions): Promise<Models.SaltedKeyResponse> {
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
    async threatsReport(payload: Models.ThreatReportRequest, options?: RequestOptions): Promise<Models.ThreatReportResponse> {
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
    async threatsQuery(payload: Models.ThreatQueryRequest, options?: RequestOptions): Promise<Models.ThreatQueryResponse> {
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
    threatsStream(callback: (payload: Models.ThreatStreamNotification) => void): () => void {
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
    async threatsDownloadPcap(payload: Models.ThreatPcapDownloadRequest, options?: RequestOptions): Promise<Models.ThreatPcapDownloadResponse> {
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
    async threatsReport(payload: Models.ThreatReportRequest, options?: RequestOptions): Promise<Models.ThreatReportResponse> {
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
    async threatsQuery(payload: Models.ThreatQueryRequest, options?: RequestOptions): Promise<Models.ThreatQueryResponse> {
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
    threatsStream(callback: (payload: Models.ThreatStreamNotification) => void): () => void {
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
    async threatsDownloadPcap(payload: Models.ThreatPcapDownloadRequest, options?: RequestOptions): Promise<Models.ThreatPcapDownloadResponse> {
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
    async validatorConnectionReport(payload: Models.ValidatorConnectionReport, options?: RequestOptions): Promise<Models.ValidatorConnectionResponse> {
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
    async connectionsQuery(payload: Models.ConnectionQueryRequest, options?: RequestOptions): Promise<Models.ConnectionQueryResponse> {
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
    connectionsStream(callback: (payload: Models.ConnectionStreamNotification) => void): () => void {
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
    async metricsQuery(payload: Models.MetricsQueryRequest, options?: RequestOptions): Promise<Models.MetricsQueryResponse> {
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
    metricsStream(callback: (payload: Models.MetricsStreamNotification) => void): () => void {
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
    async metricsReset(payload: Models.MetricsResetRequest, options?: RequestOptions): Promise<Models.MetricsResetResponse> {
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
    async tagsCreate(payload: Models.CreateTagRequest, options?: RequestOptions): Promise<Models.CreateTagResponse> {
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
    async tagsUpdate(payload: Models.UpdateTagRequest, options?: RequestOptions): Promise<Models.UpdateTagResponse> {
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
    async tagsDelete(payload: Models.DeleteTagRequest, options?: RequestOptions): Promise<Models.DeleteTagResponse> {
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
    async tagsList(payload: Models.ListTagsRequest, options?: RequestOptions): Promise<Models.ListTagsResponse> {
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
    async profilesCreate(payload: Models.CreateProfileRequest, options?: RequestOptions): Promise<Models.CreateProfileResponse> {
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
    async profilesGet(payload: Models.GetProfileRequest, options?: RequestOptions): Promise<Models.GetProfileResponse> {
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
    async profilesUpdate(payload: Models.UpdateProfileRequest, options?: RequestOptions): Promise<Models.UpdateProfileResponse> {
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
    async profilesDelete(payload: Models.DeleteProfileRequest, options?: RequestOptions): Promise<Models.DeleteProfileResponse> {
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
    async profilesList(payload: Models.ListProfilesRequest, options?: RequestOptions): Promise<Models.ListProfilesResponse> {
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
    async profilesAssign(payload: Models.AssignProfileRequest, options?: RequestOptions): Promise<Models.AssignProfileResponse> {
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
    async profilesUnassign(payload: Models.UnassignProfileRequest, options?: RequestOptions): Promise<Models.UnassignProfileResponse> {
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
    async settingsGet(payload: Models.GetSettingsRequest, options?: RequestOptions): Promise<Models.GetSettingsResponse> {
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
    async settingsUpdate(payload: Models.UpdateSettingsRequest, options?: RequestOptions): Promise<Models.UpdateSettingsResponse> {
        const envelope: MessageEnvelope = {
            operation: 'settings.update',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * users channel service with resolved parameters
 *
 * This service provides access to operations on the users channel
 * with resolved channel parameters for dynamic routing.
 */
export class UsersService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'users.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * usersCreate - Request/Response operation
     * Original operation: users.create
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async usersCreate(payload: Models.CreateUserRequest, options?: RequestOptions): Promise<Models.CreateUserResponse> {
        const envelope: MessageEnvelope = {
            operation: 'users.create',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * usersGet - Request/Response operation
     * Original operation: users.get
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async usersGet(payload: Models.GetUserRequest, options?: RequestOptions): Promise<Models.GetUserResponse> {
        const envelope: MessageEnvelope = {
            operation: 'users.get',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * usersList - Request/Response operation
     * Original operation: users.list
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async usersList(payload: Models.ListUsersRequest, options?: RequestOptions): Promise<Models.ListUsersResponse> {
        const envelope: MessageEnvelope = {
            operation: 'users.list',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * usersUpdate - Request/Response operation
     * Original operation: users.update
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async usersUpdate(payload: Models.UpdateUserRequest, options?: RequestOptions): Promise<Models.UpdateUserResponse> {
        const envelope: MessageEnvelope = {
            operation: 'users.update',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * usersDelete - Request/Response operation
     * Original operation: users.delete
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async usersDelete(payload: Models.DeleteUserRequest, options?: RequestOptions): Promise<Models.DeleteUserResponse> {
        const envelope: MessageEnvelope = {
            operation: 'users.delete',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * usersAddEmail - Request/Response operation
     * Original operation: users.add_email
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async usersAddEmail(payload: Models.AddUserEmailRequest, options?: RequestOptions): Promise<Models.AddUserEmailResponse> {
        const envelope: MessageEnvelope = {
            operation: 'users.add_email',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * usersRemoveEmail - Request/Response operation
     * Original operation: users.remove_email
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async usersRemoveEmail(payload: Models.RemoveUserEmailRequest, options?: RequestOptions): Promise<Models.RemoveUserEmailResponse> {
        const envelope: MessageEnvelope = {
            operation: 'users.remove_email',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

/**
 * sso channel service with resolved parameters
 *
 * This service provides access to operations on the sso channel
 * with resolved channel parameters for dynamic routing.
 */
export class SsoService {
    private transport: Transport;
    private resolvedChannel: string;

    constructor(transport: Transport, cska_id: string) {
        this.transport = transport;
        this.resolvedChannel = 'sso.{cska_id}'
            .replace('{cska_id}', cska_id);
    }

    /**
     * Get the resolved channel address for this service
     */
    getChannel(): string {
        return this.resolvedChannel;
    }

    /**
     * ssoGetSettings - Request/Response operation
     * Original operation: sso.get_settings
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ssoGetSettings(payload: Models.GetSsoSettingsRequest, options?: RequestOptions): Promise<Models.GetSsoSettingsResponse> {
        const envelope: MessageEnvelope = {
            operation: 'sso.get_settings',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * ssoConfigureProvider - Request/Response operation
     * Original operation: sso.configure_provider
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ssoConfigureProvider(payload: Models.ConfigureSsoProviderRequest, options?: RequestOptions): Promise<Models.ConfigureSsoProviderResponse> {
        const envelope: MessageEnvelope = {
            operation: 'sso.configure_provider',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * ssoUpdateProvider - Request/Response operation
     * Original operation: sso.update_provider
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ssoUpdateProvider(payload: Models.UpdateSsoProviderRequest, options?: RequestOptions): Promise<Models.UpdateSsoProviderResponse> {
        const envelope: MessageEnvelope = {
            operation: 'sso.update_provider',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * ssoDeleteProvider - Request/Response operation
     * Original operation: sso.delete_provider
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ssoDeleteProvider(payload: Models.DeleteSsoProviderRequest, options?: RequestOptions): Promise<Models.DeleteSsoProviderResponse> {
        const envelope: MessageEnvelope = {
            operation: 'sso.delete_provider',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * ssoEnableAuth - Request/Response operation
     * Original operation: sso.enable_auth
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ssoEnableAuth(payload: Models.EnableAuthRequest, options?: RequestOptions): Promise<Models.EnableAuthResponse> {
        const envelope: MessageEnvelope = {
            operation: 'sso.enable_auth',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * ssoDisableAuth - Request/Response operation
     * Original operation: sso.disable_auth
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ssoDisableAuth(payload: Models.DisableAuthRequest, options?: RequestOptions): Promise<Models.DisableAuthResponse> {
        const envelope: MessageEnvelope = {
            operation: 'sso.disable_auth',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * ssoInitiate - Request/Response operation
     * Original operation: sso.initiate
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ssoInitiate(payload: Models.SsoInitiateRequest, options?: RequestOptions): Promise<Models.SsoInitiateResponse> {
        const envelope: MessageEnvelope = {
            operation: 'sso.initiate',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

    /**
     * ssoCallback - Request/Response operation
     * Original operation: sso.callback
     * @param payload Request payload
     * @param options Request options
     * @returns Promise that resolves with the response
     */
    async ssoCallback(payload: Models.SsoCallbackRequest, options?: RequestOptions): Promise<Models.SsoCallbackResponse> {
        const envelope: MessageEnvelope = {
            operation: 'sso.callback',
            payload,
            channel: this.resolvedChannel
        };
        return this.transport.send(this.resolvedChannel, envelope, options);
    }

}

export default ChannelLockDeviceManagementAPIClient;

// Generated TypeScript models from AsyncAPI specification

/** LoginPayload */
export interface LoginPayload {
  /** Username for authentication */
  username: string;
  /** Password for authentication */
  password: string;
}

/** LoginResponsePayload */
export interface LoginResponsePayload {
  /** Whether login was successful */
  success: boolean;
  /** JWT token for authenticated requests */
  jwt: string;
  /** CSKA ID for which the login was performed */
  cskaId: number;
}

/** LogoutPayload */
export interface LogoutPayload {
  /** Session identifier to logout */
  sessionId: string;
}

/** LogoutResponsePayload */
export interface LogoutResponsePayload {
  /** Whether logout was successful */
  success: boolean;
  /** Success or error message */
  message: string;
}

/** BootstrapDevicePayload */
export interface BootstrapDevicePayload {
  /** Human-readable name for the device */
  device_name: string;
  /** Optional email address to send bootstrap credentials to */
  email?: string;
  /** URL of the UI for bootstrap email link (e.g., window.location.origin). Required if email is provided. */
  bootstrap_url?: string;
  /** Configuration for bootstrap with optional pre-provisioning support */
  configuration?: BootstrapDeviceConfiguration;
}

/** BootstrapDeviceResponsePayload */
export interface BootstrapDeviceResponsePayload {
  /** Whether the bootstrap was successful */
  success: boolean;
  /** Unique seat identifier for the bootstrapped device */
  seatId?: number;
  bootstrapCredentials?: DeviceCredentials;
  /** Success or error message */
  message: string;
}

/** GetDevicePayload */
export interface GetDevicePayload {
  /** Seat ID of the device to retrieve */
  seatId: number;
}

/** GetDeviceResponsePayload */
export interface GetDeviceResponsePayload {
  /** Whether the request was successful */
  success: boolean;
  device?: DeviceInfo;
  /** Success or error message */
  message: string;
}

/** ConfigureDevicePayload */
export interface ConfigureDevicePayload {
  /** Seat ID of the device to configure */
  seatId: number;
  configuration: DeviceConfiguration;
  /** Profile ID to assign to device. If null, device uses manual configuration from the configuration field. */
  profileId?: string;
}

/** ConfigureDeviceResponsePayload */
export interface ConfigureDeviceResponsePayload {
  /** Whether the configuration was successful */
  success: boolean;
  /** Success or error message */
  message: string;
}

/** DeleteDevicePayload */
export interface DeleteDevicePayload {
  /** Seat ID of the device to delete */
  seatId: number;
  /** Whether to force deletion even if device is active */
  force?: boolean;
}

/** DeleteDeviceResponsePayload */
export interface DeleteDeviceResponsePayload {
  /** Whether the deletion was successful */
  success: boolean;
  /** Success or error message */
  message: string;
}

/** Logging verbosity level */
export type LoggingLevel = 'debug' | 'info' | 'warn' | 'error';

/** Configuration for bootstrap with optional pre-provisioning support */
export interface BootstrapDeviceConfiguration {
  /** Logging verbosity level */
  loggingLevel?: LoggingLevel;
  /** Human-readable name of the device (overrides the device_name in the request) */
  deviceName?: string;
  /** Human-readable name of the CSKA that manages this device */
  cskaName?: string;
  /** List of IPv4 addresses (in dotted notation) that should be blocked at the source IP level for validator devices */
  blockedAddresses?: string[];
  /** Array of validation rules to apply (pre-provisioning support) */
  validationRules?: FilterValidationRule[];
  /** Array of signing rules to apply (pre-provisioning support) */
  signingRules?: FilterSignerRule[];
}

/** DeviceConfiguration */
export interface DeviceConfiguration {
  /** Logging verbosity level */
  loggingLevel?: LoggingLevel;
  /** Human-readable name of the device */
  deviceName?: string;
  /** Human-readable name of the CSKA that manages this device */
  cskaName?: string;
  /** List of seat IDs of signers that are blocked */
  blockedSigners?: number[];
  /** List of IPv4 addresses (in dotted notation) that should be blocked at the source IP level for validator devices */
  blockedAddresses?: string[];
  /** Array of validation rules to apply */
  validationRules?: FilterValidationRule[];
  /** Array of signing rules to apply */
  signingRules?: FilterSignerRule[];
}

/** FilterValidationRule */
export interface FilterValidationRule {
  /** Action to take for validation */
  action: FilterValidationAction;
  /** Network layer to apply the filter to */
  layer: FilterLayer;
  /** Algorithm to use for the filter */
  algo: FilterAlgo;
  /** cBPF rule string (e.g., "udp and port 8000") */
  rule: string;
  /** Drop packets with NewSessionHeader from remote CSKA and generate CrossCSKAThreat report */
  dropIfRemoteCska?: boolean;
}

/** FilterSignerRule */
export interface FilterSignerRule {
  /** Action to take for signing */
  action: FilterSigningAction;
  /** Network layer to apply the filter to */
  layer: FilterLayer;
  /** Algorithm to use for the filter */
  algo: FilterAlgo;
  /** cBPF rule string (e.g., "udp and port 8000") */
  rule: string;
}

/** Action to take for validation */
export type FilterValidationAction = 'accept' | 'drop' | 'validate' | 'validate_strip';

/** Action to take for signing */
export type FilterSigningAction = 'accept' | 'drop' | 'sign';

/** Network layer to apply the filter to */
export type FilterLayer = 'l567' | 'l4' | 'l3';

/** Algorithm to use for the filter */
export type FilterAlgo = 'xor' | 'sha512';

/** NetworkSettings */
export interface NetworkSettings {
  /** Port number for the device to listen on */
  listenPort?: number;
  /** List of allowed peer device IDs */
  allowedPeers?: string[];
  /** Whether to enable encryption for communications */
  encryptionEnabled?: boolean;
  /** Heartbeat interval in seconds */
  heartbeatInterval?: number;
}

/** DeviceCredentials */
export interface DeviceCredentials {
  /** Bootstrap credentials format version (currently 1) */
  version: number;
  /** Unique seat identifier for the device */
  seatId: number;
  /** Device seed for connecting to NATS */
  seed: string;
  /** JWT for authenticating the device */
  jwt: string;
  /** NATS leaf node URL for device connections */
  natsUrl: string;
  /** CSKA ID this device belongs to */
  cskaId: number;
}

/** ListDevicesPayload */
export interface ListDevicesPayload {
  filters?: DeviceFilters;
}

/** ListDevicesResponsePayload */
export interface ListDevicesResponsePayload {
  /** Whether the request was successful */
  success: boolean;
  /** List of devices */
  devices: DeviceInfo[];
  /** Success or error message */
  message: string;
}

/** DeviceFilters */
export interface DeviceFilters {
  /** Filter by device type */
  deviceType?: 'signer' | 'validator' | 'signer_validator' | 'unconfigured';
  /** Filter by device status */
  status?: 'active' | 'inactive' | 'provisioning' | 'error';
  /** Filter by profile ID (use "none" for devices without a profile) */
  profileId?: string;
  /** Filter by tag IDs (OR logic - matches devices with any of these tags) */
  tagIds?: string[];
}

/** DeviceInfo */
export interface DeviceInfo {
  /** Unique device seat identifier */
  seatId: number;
  /** Human-readable name for the device */
  deviceName: string;
  /** Optional email address associated with the device */
  email?: string;
  /** Type/function of the device (auto-computed from rules) */
  deviceType: 'signer' | 'validator' | 'signer_validator' | 'unconfigured';
  /** Current status of the device */
  status: DeviceStatus;
  /** When the device was last contacted */
  lastSeen?: string;
  /** When the device was created */
  createdAt: string;
  /** ID of the profile assigned to this device (if any) */
  profileId?: string;
  /** Name of the profile assigned to this device (if any) */
  profileName?: string;
  /** Tags assigned to this device */
  tags?: TagInfo[];
  deviceConfiguration: DeviceConfiguration;
  bootstrapCredentials?: DeviceCredentials;
}

/** Current status of the device */
export type DeviceStatus = 'active' | 'inactive' | 'provisioning' | 'error';

/** GetNetworkTopologyPayload */
export interface GetNetworkTopologyPayload {
  /** Unique identifier for the request */
  requestId: string;
}

/** GetNetworkTopologyResponsePayload */
export interface GetNetworkTopologyResponsePayload {
  /** Unique identifier matching the request */
  requestId: string;
  /** Whether the request was successful */
  success: boolean;
  networkData?: NetworkTopologyData;
  /** Success or error message */
  message: string;
}

/** NetworkTopologyData */
export interface NetworkTopologyData {
  /** List of network nodes (CSKAs and devices) */
  nodes: NetworkNode[];
  /** List of network links (ownership and communication) */
  links: NetworkLink[];
}

/** NetworkNode */
export interface NetworkNode {
  /** Unique identifier for the node */
  id: string;
  /** Type of network node */
  type: 'cska' | 'device' | 'threat_actor';
  /** Human-readable name for the node */
  name: string;
  /** Function of the device (only for device nodes) */
  function?: 'signer' | 'validator' | 'signer_validator' | 'unconfigured';
  /** Type of CSKA (only for CSKA nodes) */
  cskaType?: 'local' | 'remote';
  /** Source IP address (only for threat_actor nodes) */
  sourceIp?: string;
  /** Total number of threats from this actor (only for threat_actor nodes) */
  threatCount?: number;
}

/** NetworkLink */
export interface NetworkLink {
  /** ID of the source node */
  source: string;
  /** ID of the target node */
  target: string;
  /** Type of network link */
  type: 'ownership' | 'communication' | 'threat';
  /** Whether this link has detected threats (for communication links) */
  threat?: boolean;
  /** Description of the threat (if any) */
  threatDescription?: string;
  /** Number of threats on this link (for threat type links) */
  threatCount?: number;
}

/** DeviceStatusUpdatePayload */
export interface DeviceStatusUpdatePayload {
  /** Seat ID of the device whose status changed */
  seatId: number;
  /** Current status of the device */
  previousStatus: DeviceStatus;
  /** Current status of the device */
  newStatus: DeviceStatus;
  /** When the status change occurred */
  timestamp: string;
  deviceInfo: DeviceInfo;
  /** Reason for status change (e.g., "device_provisioned", "manual_update") */
  reason: string;
}

/** UpdateDeviceMetadataPayload */
export interface UpdateDeviceMetadataPayload {
  /** Seat ID of the device to update */
  seatId: number;
  /** List of tag IDs to assign to the device (replaces existing tags) */
  tagIds: string[];
}

/** UpdateDeviceMetadataResponsePayload */
export interface UpdateDeviceMetadataResponsePayload {
  /** Whether the update was successful */
  success: boolean;
  device?: DeviceInfo;
  /** Success or error message */
  message: string;
}

/** ProvisionDeviceRefreshRequestPayload */
export interface ProvisionDeviceRefreshRequestPayload {
  /** The public key for the user to be created */
  device_user_id_pub: string;
  /** The seat ID for the device */
  seat_id: number;
}

/** ProvisionDeviceRefreshResponsePayload */
export interface ProvisionDeviceRefreshResponsePayload {
  /** The device user JWT for the new user */
  device_user_jwt: string;
}

/** SaltedKeyRequestPayload */
export interface SaltedKeyRequestPayload {
  /** Version of the SaltedKeyRequest data structure */
  version: number;
  /** ID for the signer or validator */
  signer_id: SeatID;
  /** ID for the signer or validator */
  validator_id: SeatID;
  /** Index to use for salting the signing key */
  signing_salt_index: number;
  /** ID to salt a Key for a Channel */
  channel_id: ChannelID;
  /** IP address of the signer for threat reports */
  signer_ip: string;
  /** Port of the signer for threat reports */
  signer_port?: number;
  /** MAC address of the signer for threat reports */
  signer_mac?: number[];
  /** IP address of the validator for threat reports */
  validator_ip: string;
  /** Port of the validator for threat reports */
  validator_port?: number;
  /** MAC address of the validator for threat reports */
  validator_mac?: number[];
  /** Human-readable name of the validator for connection tracking */
  validator_name: string;
  /** CSKA ID of the validator for connection tracking */
  validator_cska_id: number;
  /** Human-readable name of the validator's CSKA for connection tracking */
  validator_cska_name: string;
}

/** SaltedKeyResponsePayload */
export interface SaltedKeyResponsePayload {
  /** Version of the SaltedKeyResponse data structure */
  version: number;
  /** A salted key for validation (16 bytes) */
  salted_key: Salt;
  /** Human-readable name of the signer for connection tracking */
  signer_name: string;
  /** Human-readable name of the signer's CSKA for connection tracking */
  signer_cska_name: string;
}

/** ID for the signer or validator */
export type SeatID = number;

/** ID to salt a Key for a Channel */
export type ChannelID = number;

/** A full signing key before salting (32 bytes) */
export type Key = number[];

/** A salted key for validation (16 bytes) */
export type Salt = number[];

/** SignerKey */
export interface SignerKey {
  /** Version of the SignerKey data structure */
  version: number;
  /** A full signing key before salting (32 bytes) */
  key: Key;
}

/** NewSessionHeader */
export interface NewSessionHeader {
  /** Channel ID for the session */
  channel_id: number;
  /** CSKA ID for the session */
  cska_id: number;
  /** Logical seat ID for the session */
  logical_seat_id: number;
}

/** HashDigests */
export interface HashDigests {
  /** Layer 3 hash digest */
  l3_digest: number;
  /** Layer 4 hash digest */
  l4_digest: number;
  /** Layer 5/6/7 hash digest */
  l567_digest: number;
}

/** ThreatReportPayload */
export interface ThreatReportPayload {
  /** Version of the ThreatReport data structure */
  version: number;
  /** Timestamp when threat was detected (milliseconds since epoch) */
  when: number;
  /** Type of threat detected */
  kind: ThreatKind;
  /** CSKA ID where threat was detected */
  cska_id: number;
  /** IP address of the signer */
  signer_ip: string;
  /** Port of the signer */
  signer_port?: number;
  /** MAC address of the signer */
  signer_mac?: number[];
  /** ID for the signer or validator */
  validator_id: SeatID;
  /** IP address of the validator */
  validator_ip: string;
  /** Port of the validator */
  validator_port?: number;
  /** MAC address of the validator */
  validator_mac?: number[];
  /** Additional information about the threat */
  info: string;
  /** Base64-encoded raw packet data starting from IP header (up to 100 bytes) */
  payload?: string;
  new_session_header?: NewSessionHeader;
  hash_digests?: HashDigests;
}

/** ThreatReportResponsePayload */
export interface ThreatReportResponsePayload {
  /** Whether the threat report was successfully processed */
  success: boolean;
  /** Success or error message */
  message: string;
}

/** ThreatQueryPayload */
export interface ThreatQueryPayload {
  /** Start timestamp for query range (milliseconds since epoch) */
  start_time: number;
  /** End timestamp for query range (milliseconds since epoch) */
  end_time: number;
  /** Filter by threat types (optional) */
  threat_kinds?: ThreatKind[];
  /** Filter by validator IDs (optional) */
  validator_ids?: SeatID[];
  /** Maximum number of results to return */
  limit?: number;
  /** Number of results to skip for pagination */
  offset?: number;
}

/** ThreatQueryResponsePayload */
export interface ThreatQueryResponsePayload {
  /** Whether the query was successful */
  success: boolean;
  /** Array of threat reports matching the query */
  threats: ThreatReportPayload[];
  /** Total number of threats matching the query (for pagination) */
  total_count: number;
  /** Success or error message */
  message: string;
}

/** ThreatStreamNotificationPayload */
export interface ThreatStreamNotificationPayload {
  threat_report: ThreatReportPayload;
  /** When the threat was archived (milliseconds since epoch) */
  archived_at: number;
}

/** Type of threat detected */
export type ThreatKind = 'unsigned' | 'protocol_violation' | 'version_mismatch' | 'signature_mismatch_l2' | 'signature_mismatch_l3' | 'signature_mismatch_l4' | 'signature_mismatch_l567' | 'invalid_signer_id' | 'expired_signer_id' | 'double_key_deref' | 'ddos' | 'cross_cska_threat';

/** ValidatorConnectionReportPayload */
export interface ValidatorConnectionReportPayload {
  /** ID for the signer or validator */
  validator_id: SeatID;
  /** Human-readable name of the validator */
  validator_name: string;
  /** CSKA ID of the validator */
  validator_cska_id: number;
  /** Human-readable name of the validator's CSKA */
  validator_cska_name: string;
  /** ID for the signer or validator */
  signer_id: SeatID;
  /** Human-readable name of the signer */
  signer_name: string;
  /** CSKA ID of the signer */
  signer_cska_id: number;
  /** Human-readable name of the signer's CSKA */
  signer_cska_name: string;
  /** ID to salt a Key for a Channel */
  channel_id: ChannelID;
  /** Timestamp when the connection was established (milliseconds since epoch) */
  timestamp: number;
}

/** ValidatorConnectionResponsePayload */
export interface ValidatorConnectionResponsePayload {
  /** Whether the connection report was successfully processed */
  success: boolean;
  /** Success or error message */
  message: string;
}

/** ConnectionQueryPayload */
export interface ConnectionQueryPayload {
  /** Filter by connection type */
  connection_type?: 'all' | 'signer_to_validator' | 'validator_to_signer';
  date_range?: DateRange;
  /** Filter by specific signer IDs (optional) */
  signer_ids?: SeatID[];
  /** Filter by specific validator IDs (optional) */
  validator_ids?: SeatID[];
  /** Filter by specific CSKA IDs (optional) */
  cska_ids?: number[];
  /** Filter by minimum connection count (optional) */
  min_connection_count?: number;
  pagination?: PaginationParams;
}

/** ConnectionQueryResponsePayload */
export interface ConnectionQueryResponsePayload {
  /** Whether the query was successful */
  success: boolean;
  /** Array of connection records matching the query */
  connections: ConnectionRecord[];
  /** Total number of connections matching the query (for pagination) */
  total_count: number;
  /** Success or error message */
  message: string;
}

/** ConnectionStreamNotificationPayload */
export interface ConnectionStreamNotificationPayload {
  /** Type of connection event */
  event_type: 'connection_established' | 'connection_updated' | 'device_offline' | 'topology_changed';
  connection_record?: ConnectionRecord;
  topology_delta?: TopologyDelta;
  /** Timestamp when the event occurred (milliseconds since epoch) */
  timestamp: number;
}

/** DateRange */
export interface DateRange {
  /** Start timestamp (milliseconds since epoch) */
  start_time: number;
  /** End timestamp (milliseconds since epoch) */
  end_time: number;
}

/** PaginationParams */
export interface PaginationParams {
  /** Maximum number of results to return */
  limit?: number;
  /** Number of results to skip for pagination */
  offset?: number;
}

/** ConnectionRecord */
export interface ConnectionRecord {
  /** Type of connection record */
  connection_type: 'signer_to_validator' | 'validator_to_signer';
  /** Signer device ID */
  signer_id: number;
  /** Human-readable name of the signer */
  signer_name: string;
  /** CSKA ID of the signer */
  signer_cska_id: number;
  /** Human-readable name of the signer's CSKA */
  signer_cska_name: string;
  /** Validator device ID */
  validator_id: number;
  /** Human-readable name of the validator */
  validator_name: string;
  /** CSKA ID of the validator */
  validator_cska_id: number;
  /** Human-readable name of the validator's CSKA */
  validator_cska_name: string;
  /** Timestamp when connection was first established (milliseconds since epoch) */
  first_seen: number;
  /** Timestamp when connection was last active (milliseconds since epoch) */
  last_seen: number;
  /** Number of times this connection has been established */
  connection_count: number;
}

/** TopologyDelta */
export interface TopologyDelta {
  /** Type of topology change */
  operation: 'add_node' | 'remove_node' | 'add_link' | 'remove_link' | 'update_link';
  node?: NetworkNode;
  link?: NetworkLink;
  /** Additional metadata about the change */
  metadata?: Record<string, any>;
}

/** MetricsQueryPayload */
export interface MetricsQueryPayload {
  /** Seat ID of the device to query metrics for */
  seat_id: number;
  /** Filter by specific metric names (optional, returns all if not specified) */
  metric_names?: string[];
  /** Start timestamp in milliseconds since epoch (optional) */
  start_time?: number;
  /** End timestamp in milliseconds since epoch (optional) */
  end_time?: number;
}

/** MetricsQueryResponsePayload */
export interface MetricsQueryResponsePayload {
  /** Whether the query was successful */
  success: boolean;
  /** Seat ID of the device */
  seat_id: number;
  /** Array of metric samples matching the query */
  samples: MetricSample[];
  /** Success or error message */
  message: string;
}

/** MetricsStreamNotificationPayload */
export interface MetricsStreamNotificationPayload {
  /** Seat ID of the device */
  seat_id: number;
  sample: MetricSample;
  /** Timestamp when the notification was sent (milliseconds since epoch) */
  timestamp: number;
}

/** MetricSample */
export interface MetricSample {
  /** Timestamp in milliseconds since epoch when metrics were collected */
  timestamp: number;
  /** Map of metric name to metric value (e.g., signed_packets, verified_packets, dropped_packets, threats) */
  metrics: Record<string, any>;
}

/** MetricsResetPayload */
export interface MetricsResetPayload {
  /** Seat ID of the device to reset metrics for */
  seat_id: number;
  /** Specific metric name to reset (e.g., "threats_detected") */
  metric_name: string;
}

/** MetricsResetResponsePayload */
export interface MetricsResetResponsePayload {
  /** Whether the reset was successful */
  success: boolean;
  /** Success or error message */
  message: string;
}

/** ThreatPcapDownloadPayload */
export interface ThreatPcapDownloadPayload {
  /** Source IP address to filter threats (e.g., "192.168.1.100") */
  source_ip: string;
  /** Start timestamp for query range (milliseconds since epoch) */
  start_time: number;
  /** End timestamp for query range (milliseconds since epoch) */
  end_time: number;
  /** Maximum number of packets to include in PCAP (enforced server-side) */
  limit?: number;
}

/** ThreatPcapDownloadResponsePayload */
export interface ThreatPcapDownloadResponsePayload {
  /** Whether the ZIP archive generation was successful */
  success: boolean;
  /** Base64-encoded ZIP archive containing threats.pcap and threats.json (only present if success is true) */
  pcap_data?: string;
  /** Suggested filename for the download (e.g., "threats-192.168.1.100.zip") */
  filename?: string;
  /** Number of packets included in the PCAP file within the ZIP */
  packet_count?: number;
  /** Success or error message */
  message: string;
}

/** TagInfo */
export interface TagInfo {
  /** Unique identifier for the tag */
  tagId: string;
  /** Human-readable name for the tag (unique within CSKA) */
  tagName: string;
  /** Optional color for UI display (hex format, e.g., "#FF5733") */
  color?: string;
  /** When the tag was created */
  createdAt: string;
  /** Number of devices using this tag (computed on query) */
  deviceCount?: number;
}

/** CreateTagPayload */
export interface CreateTagPayload {
  /** Human-readable name for the tag */
  tagName: string;
  /** Optional color for UI display (hex format) */
  color?: string;
}

/** CreateTagResponsePayload */
export interface CreateTagResponsePayload {
  /** Whether the tag was created successfully */
  success: boolean;
  tag?: TagInfo;
  /** Success or error message */
  message: string;
}

/** UpdateTagPayload */
export interface UpdateTagPayload {
  /** ID of the tag to update */
  tagId: string;
  /** New name for the tag */
  tagName?: string;
  /** New color for the tag */
  color?: string;
}

/** UpdateTagResponsePayload */
export interface UpdateTagResponsePayload {
  /** Whether the tag was updated successfully */
  success: boolean;
  tag?: TagInfo;
  /** Success or error message */
  message: string;
}

/** DeleteTagPayload */
export interface DeleteTagPayload {
  /** ID of the tag to delete */
  tagId: string;
}

/** DeleteTagResponsePayload */
export interface DeleteTagResponsePayload {
  /** Whether the tag was deleted successfully */
  success: boolean;
  /** Success or error message */
  message: string;
}

/** ListTagsPayload */
export interface ListTagsPayload {
  /** Whether to include device count for each tag */
  includeDeviceCount?: boolean;
}

/** ListTagsResponsePayload */
export interface ListTagsResponsePayload {
  /** Whether the request was successful */
  success: boolean;
  /** List of tags */
  tags: TagInfo[];
  /** Success or error message */
  message: string;
}

/** ProfileInfo */
export interface ProfileInfo {
  /** Unique identifier for the profile */
  profileId: string;
  /** Human-readable name for the profile */
  profileName: string;
  /** Optional description of the profile */
  description?: string;
  /** When the profile was created */
  createdAt: string;
  /** When the profile was last updated */
  updatedAt: string;
  /** Number of devices assigned to this profile (computed on query) */
  deviceCount?: number;
  /** Configuration settings stored in a profile (device name and logging level remain device-specific) */
  configuration: ProfileConfiguration;
}

/** Configuration settings stored in a profile (device name and logging level remain device-specific) */
export interface ProfileConfiguration {
  /** List of IPv4 addresses that should be blocked at the source IP level for validator devices */
  blockedAddresses?: string[];
  /** Array of validation rules to apply */
  validationRules?: FilterValidationRule[];
  /** Array of signing rules to apply */
  signingRules?: FilterSignerRule[];
}

/** CreateProfilePayload */
export interface CreateProfilePayload {
  /** Human-readable name for the profile */
  profileName: string;
  /** Optional description of the profile */
  description?: string;
  /** Configuration settings stored in a profile (device name and logging level remain device-specific) */
  configuration: ProfileConfiguration;
}

/** CreateProfileResponsePayload */
export interface CreateProfileResponsePayload {
  /** Whether the profile was created successfully */
  success: boolean;
  profile?: ProfileInfo;
  /** Success or error message */
  message: string;
}

/** GetProfilePayload */
export interface GetProfilePayload {
  /** ID of the profile to retrieve */
  profileId: string;
}

/** GetProfileResponsePayload */
export interface GetProfileResponsePayload {
  /** Whether the request was successful */
  success: boolean;
  profile?: ProfileInfo;
  /** Success or error message */
  message: string;
}

/** UpdateProfilePayload */
export interface UpdateProfilePayload {
  /** ID of the profile to update */
  profileId: string;
  /** New name for the profile */
  profileName?: string;
  /** New description for the profile */
  description?: string;
  /** Configuration settings stored in a profile (device name and logging level remain device-specific) */
  configuration?: ProfileConfiguration;
}

/** UpdateProfileResponsePayload */
export interface UpdateProfileResponsePayload {
  /** Whether the profile was updated successfully */
  success: boolean;
  profile?: ProfileInfo;
  /** Number of devices that received configuration updates */
  devicesUpdated?: number;
  /** Success or error message */
  message: string;
}

/** DeleteProfilePayload */
export interface DeleteProfilePayload {
  /** ID of the profile to delete */
  profileId: string;
}

/** DeleteProfileResponsePayload */
export interface DeleteProfileResponsePayload {
  /** Whether the profile was deleted successfully */
  success: boolean;
  /** Success or error message (will indicate "blocked" if devices are assigned) */
  message: string;
}

/** ListProfilesPayload */
export interface ListProfilesPayload {
  /** Whether to include device count for each profile */
  includeDeviceCount?: boolean;
}

/** ListProfilesResponsePayload */
export interface ListProfilesResponsePayload {
  /** Whether the request was successful */
  success: boolean;
  /** List of profiles */
  profiles: ProfileInfo[];
  /** Success or error message */
  message: string;
}

/** AssignProfilePayload */
export interface AssignProfilePayload {
  /** ID of the profile to assign devices to */
  profileId: string;
  /** List of device seat IDs to assign to the profile */
  seatIds: number[];
}

/** AssignProfileResponsePayload */
export interface AssignProfileResponsePayload {
  /** Whether the assignment was successful */
  success: boolean;
  /** Number of devices successfully assigned */
  assignedCount: number;
  /** List of seat IDs that failed to be assigned (if any) */
  failedSeatIds?: number[];
  /** Success or error message */
  message: string;
}

/** UnassignProfilePayload */
export interface UnassignProfilePayload {
  /** List of device seat IDs to remove from their profiles */
  seatIds: number[];
}

/** UnassignProfileResponsePayload */
export interface UnassignProfileResponsePayload {
  /** Whether the unassignment was successful */
  success: boolean;
  /** Number of devices successfully unassigned */
  unassignedCount: number;
  /** Success or error message */
  message: string;
}

/** Empty payload - no parameters needed to get settings */
export interface GetSettingsPayload {

}

/** GetSettingsResponsePayload */
export interface GetSettingsResponsePayload {
  /** Whether the request was successful */
  success: boolean;
  /** System-wide settings stored in NATS bucket */
  settings?: SystemSettings;
  /** Success or error message */
  message: string;
}

/** UpdateSettingsPayload */
export interface UpdateSettingsPayload {
  /** System-wide settings stored in NATS bucket */
  settings: SystemSettings;
}

/** UpdateSettingsResponsePayload */
export interface UpdateSettingsResponsePayload {
  /** Whether the update was successful */
  success: boolean;
  /** System-wide settings stored in NATS bucket */
  settings?: SystemSettings;
  /** Success or error message */
  message: string;
}

/** System-wide settings stored in NATS bucket */
export interface SystemSettings {
  /** Email notification configuration */
  email: EmailSettings;
}

/** Email notification configuration */
export interface EmailSettings {
  /** Whether email notifications are enabled */
  enabled: boolean;
  /** Email address to send from (required when enabled) */
  fromAddress?: string;
  /** Display name for the sender */
  fromName?: string;
  /** Type of email provider */
  activeProvider?: EmailProviderType;
  /** SendGrid email provider configuration */
  sendgrid?: SendGridConfig;
  /** Mailgun email provider configuration */
  mailgun?: MailgunConfig;
}

/** Type of email provider */
export type EmailProviderType = 'sendgrid' | 'mailgun';

/** SendGrid email provider configuration */
export interface SendGridConfig {
  /** SendGrid API key */
  apiKey: string;
}

/** Mailgun email provider configuration */
export interface MailgunConfig {
  /** Mailgun API key */
  apiKey: string;
  /** Mailgun sending domain (e.g., mail.yourcompany.com) */
  domain: string;
  /** Mailgun API region (US or EU) */
  region: MailgunRegion;
}

/** Mailgun API region (US or EU) */
export type MailgunRegion = 'us' | 'eu';


/** Login Request */
export interface LoginRequestPayload {
  /** Username for authentication */
  username: string;
  /** Password for authentication */
  password: string;
}

/** Logout Request */
export interface LogoutRequestPayload {
  /** Session identifier to logout */
  sessionId: string;
}

/** Bootstrap Device Request */
export interface BootstrapDeviceRequestPayload {
  /** Human-readable name for the device */
  device_name: string;
  /** Optional email address to send bootstrap credentials to */
  email?: string;
  /** URL of the UI for bootstrap email link (e.g., window.location.origin). Required if email is provided. */
  bootstrap_url?: string;
  /** Configuration for bootstrap with optional pre-provisioning support */
  configuration?: BootstrapDeviceConfiguration;
}

/** Get Device Request */
export interface GetDeviceRequestPayload {
  /** Seat ID of the device to retrieve */
  seatId: number;
}

/** Configure Device Request */
export interface ConfigureDeviceRequestPayload {
  /** Seat ID of the device to configure */
  seatId: number;
  configuration: DeviceConfiguration;
  /** Profile ID to assign to device. If null, device uses manual configuration from the configuration field. */
  profileId?: string;
}

/** Delete Device Request */
export interface DeleteDeviceRequestPayload {
  /** Seat ID of the device to delete */
  seatId: number;
  /** Whether to force deletion even if device is active */
  force?: boolean;
}

/** List Devices Request */
export interface ListDevicesRequestPayload {
  filters?: DeviceFilters;
}

/** Get Network Topology Request */
export interface GetNetworkTopologyRequestPayload {
  /** Unique identifier for the request */
  requestId: string;
}

/** Device Status Update Notification */
export interface DeviceStatusUpdateNotificationPayload {
  /** Seat ID of the device whose status changed */
  seatId: number;
  /** Current status of the device */
  previousStatus: DeviceStatus;
  /** Current status of the device */
  newStatus: DeviceStatus;
  /** When the status change occurred */
  timestamp: string;
  deviceInfo: DeviceInfo;
  /** Reason for status change (e.g., "device_provisioned", "manual_update") */
  reason: string;
}

/** Update Device Metadata Request */
export interface UpdateDeviceMetadataRequestPayload {
  /** Seat ID of the device to update */
  seatId: number;
  /** List of tag IDs to assign to the device (replaces existing tags) */
  tagIds: string[];
}

/** Threat Report Request */
export interface ThreatReportRequestPayload {
  /** Version of the ThreatReport data structure */
  version: number;
  /** Timestamp when threat was detected (milliseconds since epoch) */
  when: number;
  /** Type of threat detected */
  kind: ThreatKind;
  /** CSKA ID where threat was detected */
  cska_id: number;
  /** IP address of the signer */
  signer_ip: string;
  /** Port of the signer */
  signer_port?: number;
  /** MAC address of the signer */
  signer_mac?: number[];
  /** ID for the signer or validator */
  validator_id: SeatID;
  /** IP address of the validator */
  validator_ip: string;
  /** Port of the validator */
  validator_port?: number;
  /** MAC address of the validator */
  validator_mac?: number[];
  /** Additional information about the threat */
  info: string;
  /** Base64-encoded raw packet data starting from IP header (up to 100 bytes) */
  payload?: string;
  new_session_header?: NewSessionHeader;
  hash_digests?: HashDigests;
}

/** Threat Query Request */
export interface ThreatQueryRequestPayload {
  /** Start timestamp for query range (milliseconds since epoch) */
  start_time: number;
  /** End timestamp for query range (milliseconds since epoch) */
  end_time: number;
  /** Filter by threat types (optional) */
  threat_kinds?: ThreatKind[];
  /** Filter by validator IDs (optional) */
  validator_ids?: SeatID[];
  /** Maximum number of results to return */
  limit?: number;
  /** Number of results to skip for pagination */
  offset?: number;
}

/** Connection Query Request */
export interface ConnectionQueryRequestPayload {
  /** Filter by connection type */
  connection_type?: 'all' | 'signer_to_validator' | 'validator_to_signer';
  date_range?: DateRange;
  /** Filter by specific signer IDs (optional) */
  signer_ids?: SeatID[];
  /** Filter by specific validator IDs (optional) */
  validator_ids?: SeatID[];
  /** Filter by specific CSKA IDs (optional) */
  cska_ids?: number[];
  /** Filter by minimum connection count (optional) */
  min_connection_count?: number;
  pagination?: PaginationParams;
}

/** Metrics Query Request */
export interface MetricsQueryRequestPayload {
  /** Seat ID of the device to query metrics for */
  seat_id: number;
  /** Filter by specific metric names (optional, returns all if not specified) */
  metric_names?: string[];
  /** Start timestamp in milliseconds since epoch (optional) */
  start_time?: number;
  /** End timestamp in milliseconds since epoch (optional) */
  end_time?: number;
}

/** Metrics Reset Request */
export interface MetricsResetRequestPayload {
  /** Seat ID of the device to reset metrics for */
  seat_id: number;
  /** Specific metric name to reset (e.g., "threats_detected") */
  metric_name: string;
}

/** Threat PCAP Download Request */
export interface ThreatPcapDownloadRequestPayload {
  /** Source IP address to filter threats (e.g., "192.168.1.100") */
  source_ip: string;
  /** Start timestamp for query range (milliseconds since epoch) */
  start_time: number;
  /** End timestamp for query range (milliseconds since epoch) */
  end_time: number;
  /** Maximum number of packets to include in PCAP (enforced server-side) */
  limit?: number;
}

/** Create Tag Request */
export interface CreateTagRequestPayload {
  /** Human-readable name for the tag */
  tagName: string;
  /** Optional color for UI display (hex format) */
  color?: string;
}

/** Update Tag Request */
export interface UpdateTagRequestPayload {
  /** ID of the tag to update */
  tagId: string;
  /** New name for the tag */
  tagName?: string;
  /** New color for the tag */
  color?: string;
}

/** Delete Tag Request */
export interface DeleteTagRequestPayload {
  /** ID of the tag to delete */
  tagId: string;
}

/** List Tags Request */
export interface ListTagsRequestPayload {
  /** Whether to include device count for each tag */
  includeDeviceCount?: boolean;
}

/** Create Profile Request */
export interface CreateProfileRequestPayload {
  /** Human-readable name for the profile */
  profileName: string;
  /** Optional description of the profile */
  description?: string;
  /** Configuration settings stored in a profile (device name and logging level remain device-specific) */
  configuration: ProfileConfiguration;
}

/** Get Profile Request */
export interface GetProfileRequestPayload {
  /** ID of the profile to retrieve */
  profileId: string;
}

/** Update Profile Request */
export interface UpdateProfileRequestPayload {
  /** ID of the profile to update */
  profileId: string;
  /** New name for the profile */
  profileName?: string;
  /** New description for the profile */
  description?: string;
  /** Configuration settings stored in a profile (device name and logging level remain device-specific) */
  configuration?: ProfileConfiguration;
}

/** Delete Profile Request */
export interface DeleteProfileRequestPayload {
  /** ID of the profile to delete */
  profileId: string;
}

/** List Profiles Request */
export interface ListProfilesRequestPayload {
  /** Whether to include device count for each profile */
  includeDeviceCount?: boolean;
}

/** Assign Profile Request */
export interface AssignProfileRequestPayload {
  /** ID of the profile to assign devices to */
  profileId: string;
  /** List of device seat IDs to assign to the profile */
  seatIds: number[];
}

/** Unassign Profile Request */
export interface UnassignProfileRequestPayload {
  /** List of device seat IDs to remove from their profiles */
  seatIds: number[];
}

/** Get Settings Request */
export interface GetSettingsRequestPayload {

}

/** Update Settings Request */
export interface UpdateSettingsRequestPayload {
  /** System-wide settings stored in NATS bucket */
  settings: SystemSettings;
}


/** Union type for all message payloads */
export type MessagePayload = LoginRequestPayload | LoginResponsePayload | LogoutRequestPayload | LogoutResponsePayload | BootstrapDeviceRequestPayload | BootstrapDeviceResponsePayload | GetDeviceRequestPayload | GetDeviceResponsePayload | ConfigureDeviceRequestPayload | ConfigureDeviceResponsePayload | DeleteDeviceRequestPayload | DeleteDeviceResponsePayload | ListDevicesRequestPayload | ListDevicesResponsePayload | GetNetworkTopologyRequestPayload | GetNetworkTopologyResponsePayload | DeviceStatusUpdateNotificationPayload | UpdateDeviceMetadataRequestPayload | UpdateDeviceMetadataResponsePayload | ProvisionDeviceRefreshRequestPayload | ProvisionDeviceRefreshResponsePayload | SaltedKeyRequestPayload | SaltedKeyResponsePayload | ThreatReportRequestPayload | ThreatReportResponsePayload | ThreatQueryRequestPayload | ThreatQueryResponsePayload | ThreatStreamNotificationPayload | ValidatorConnectionReportPayload | ValidatorConnectionResponsePayload | ConnectionQueryRequestPayload | ConnectionQueryResponsePayload | ConnectionStreamNotificationPayload | MetricsQueryRequestPayload | MetricsQueryResponsePayload | MetricsStreamNotificationPayload | MetricsResetRequestPayload | MetricsResetResponsePayload | ThreatPcapDownloadRequestPayload | ThreatPcapDownloadResponsePayload | CreateTagRequestPayload | CreateTagResponsePayload | UpdateTagRequestPayload | UpdateTagResponsePayload | DeleteTagRequestPayload | DeleteTagResponsePayload | ListTagsRequestPayload | ListTagsResponsePayload | CreateProfileRequestPayload | CreateProfileResponsePayload | GetProfileRequestPayload | GetProfileResponsePayload | UpdateProfileRequestPayload | UpdateProfileResponsePayload | DeleteProfileRequestPayload | DeleteProfileResponsePayload | ListProfilesRequestPayload | ListProfilesResponsePayload | AssignProfileRequestPayload | AssignProfileResponsePayload | UnassignProfileRequestPayload | UnassignProfileResponsePayload | GetSettingsRequestPayload | GetSettingsResponsePayload | UpdateSettingsRequestPayload | UpdateSettingsResponsePayload;

/** Message type constants */
export const MessageTypes = {
  LOGINREQUEST: 'LoginRequest',
  LOGINRESPONSE: 'LoginResponse',
  LOGOUTREQUEST: 'LogoutRequest',
  LOGOUTRESPONSE: 'LogoutResponse',
  BOOTSTRAPDEVICEREQUEST: 'BootstrapDeviceRequest',
  BOOTSTRAPDEVICERESPONSE: 'BootstrapDeviceResponse',
  GETDEVICEREQUEST: 'GetDeviceRequest',
  GETDEVICERESPONSE: 'GetDeviceResponse',
  CONFIGUREDEVICEREQUEST: 'ConfigureDeviceRequest',
  CONFIGUREDEVICERESPONSE: 'ConfigureDeviceResponse',
  DELETEDEVICEREQUEST: 'DeleteDeviceRequest',
  DELETEDEVICERESPONSE: 'DeleteDeviceResponse',
  LISTDEVICESREQUEST: 'ListDevicesRequest',
  LISTDEVICESRESPONSE: 'ListDevicesResponse',
  GETNETWORKTOPOLOGYREQUEST: 'GetNetworkTopologyRequest',
  GETNETWORKTOPOLOGYRESPONSE: 'GetNetworkTopologyResponse',
  DEVICESTATUSUPDATENOTIFICATION: 'DeviceStatusUpdateNotification',
  UPDATEDEVICEMETADATAREQUEST: 'UpdateDeviceMetadataRequest',
  UPDATEDEVICEMETADATARESPONSE: 'UpdateDeviceMetadataResponse',
  PROVISIONDEVICEREFRESHREQUEST: 'ProvisionDeviceRefreshRequest',
  PROVISIONDEVICEREFRESHRESPONSE: 'ProvisionDeviceRefreshResponse',
  SALTEDKEYREQUEST: 'SaltedKeyRequest',
  SALTEDKEYRESPONSE: 'SaltedKeyResponse',
  THREATREPORTREQUEST: 'ThreatReportRequest',
  THREATREPORTRESPONSE: 'ThreatReportResponse',
  THREATQUERYREQUEST: 'ThreatQueryRequest',
  THREATQUERYRESPONSE: 'ThreatQueryResponse',
  THREATSTREAMNOTIFICATION: 'ThreatStreamNotification',
  VALIDATORCONNECTIONREPORT: 'ValidatorConnectionReport',
  VALIDATORCONNECTIONRESPONSE: 'ValidatorConnectionResponse',
  CONNECTIONQUERYREQUEST: 'ConnectionQueryRequest',
  CONNECTIONQUERYRESPONSE: 'ConnectionQueryResponse',
  CONNECTIONSTREAMNOTIFICATION: 'ConnectionStreamNotification',
  METRICSQUERYREQUEST: 'MetricsQueryRequest',
  METRICSQUERYRESPONSE: 'MetricsQueryResponse',
  METRICSSTREAMNOTIFICATION: 'MetricsStreamNotification',
  METRICSRESETREQUEST: 'MetricsResetRequest',
  METRICSRESETRESPONSE: 'MetricsResetResponse',
  THREATPCAPDOWNLOADREQUEST: 'ThreatPcapDownloadRequest',
  THREATPCAPDOWNLOADRESPONSE: 'ThreatPcapDownloadResponse',
  CREATETAGREQUEST: 'CreateTagRequest',
  CREATETAGRESPONSE: 'CreateTagResponse',
  UPDATETAGREQUEST: 'UpdateTagRequest',
  UPDATETAGRESPONSE: 'UpdateTagResponse',
  DELETETAGREQUEST: 'DeleteTagRequest',
  DELETETAGRESPONSE: 'DeleteTagResponse',
  LISTTAGSREQUEST: 'ListTagsRequest',
  LISTTAGSRESPONSE: 'ListTagsResponse',
  CREATEPROFILEREQUEST: 'CreateProfileRequest',
  CREATEPROFILERESPONSE: 'CreateProfileResponse',
  GETPROFILEREQUEST: 'GetProfileRequest',
  GETPROFILERESPONSE: 'GetProfileResponse',
  UPDATEPROFILEREQUEST: 'UpdateProfileRequest',
  UPDATEPROFILERESPONSE: 'UpdateProfileResponse',
  DELETEPROFILEREQUEST: 'DeleteProfileRequest',
  DELETEPROFILERESPONSE: 'DeleteProfileResponse',
  LISTPROFILESREQUEST: 'ListProfilesRequest',
  LISTPROFILESRESPONSE: 'ListProfilesResponse',
  ASSIGNPROFILEREQUEST: 'AssignProfileRequest',
  ASSIGNPROFILERESPONSE: 'AssignProfileResponse',
  UNASSIGNPROFILEREQUEST: 'UnassignProfileRequest',
  UNASSIGNPROFILERESPONSE: 'UnassignProfileResponse',
  GETSETTINGSREQUEST: 'GetSettingsRequest',
  GETSETTINGSRESPONSE: 'GetSettingsResponse',
  UPDATESETTINGSREQUEST: 'UpdateSettingsRequest',
  UPDATESETTINGSRESPONSE: 'UpdateSettingsResponse',
} as const;

/** Message type union */
export type MessageType = typeof MessageTypes[keyof typeof MessageTypes];



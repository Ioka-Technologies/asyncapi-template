// Generated TypeScript models from AsyncAPI specification

/** LogoutPayload */
export interface LogoutPayload {
  /** Session identifier to logout */
  sessionId: string;
}

/** LogoutResponsePayload */
export interface LogoutResponsePayload {
  [key: string]: any;
}

/** FilterValidationRule */
export interface FilterValidationRule {
  action: FilterValidationAction;
  layer: FilterLayer;
  algo: FilterAlgo;
  /** cBPF rule string (e.g., "udp and port 8000") */
  rule: string;
  /** Drop packets with NewSessionHeader from remote CSKA and generate CrossCSKAThreat report */
  dropIfRemoteCska?: boolean;
}

/** FilterSignerRule */
export interface FilterSignerRule {
  action: FilterSigningAction;
  layer: FilterLayer;
  algo: FilterAlgo;
  /** cBPF rule string (e.g., "udp and port 8000") */
  rule: string;
}

/** BaseDeviceConfiguration */
export interface BaseDeviceConfiguration {
  loggingLevel?: LoggingLevel;
  /** Human-readable name of the device */
  deviceName?: string;
  /** Human-readable name of the CSKA that manages this device */
  cskaName?: string;
  /** List of IPv4 addresses (in dotted notation) that should be blocked at the source IP level for validator devices */
  blockedAddresses?: string[];
  /** Array of validation rules to apply */
  validationRules?: FilterValidationRule[];
  /** Array of signing rules to apply */
  signingRules?: FilterSignerRule[];
}

/** BootstrapDeviceConfiguration */
export interface BootstrapDeviceConfiguration {
  loggingLevel?: LoggingLevel;
  /** Human-readable name of the device */
  deviceName?: string;
  /** Human-readable name of the CSKA that manages this device */
  cskaName?: string;
  /** List of IPv4 addresses (in dotted notation) that should be blocked at the source IP level for validator devices */
  blockedAddresses?: string[];
  /** Array of validation rules to apply */
  validationRules?: FilterValidationRule[];
  /** Array of signing rules to apply */
  signingRules?: FilterSignerRule[];
}

/** DeviceConfiguration */
export interface DeviceConfiguration {
  loggingLevel?: LoggingLevel;
  /** Human-readable name of the device */
  deviceName?: string;
  /** Human-readable name of the CSKA that manages this device */
  cskaName?: string;
  /** List of IPv4 addresses (in dotted notation) that should be blocked at the source IP level for validator devices */
  blockedAddresses?: string[];
  /** Array of validation rules to apply */
  validationRules?: FilterValidationRule[];
  /** Array of signing rules to apply */
  signingRules?: FilterSignerRule[];
  /** List of seat IDs of signers that are blocked */
  blockedSigners?: number[];
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

/** DeviceInfo */
export interface DeviceInfo {
  /** Unique device seat identifier */
  seatId: number;
  /** Human-readable name for the device */
  deviceName: string;
  /** Optional email address associated with the device */
  email?: string;
  deviceType: DeviceType;
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

/** DeviceFilters */
export interface DeviceFilters {
  deviceType?: DeviceType;
  status?: DeviceStatus;
  /** Filter by profile ID (use "none" for devices without a profile) */
  profileId?: string;
  /** Filter by tag IDs (OR logic - matches devices with any of these tags) */
  tagIds?: string[];
}

/** BootstrapDevicePayload */
export interface BootstrapDevicePayload {
  /** Human-readable name for the device */
  deviceName: string;
  /** Optional email address to send bootstrap credentials to */
  email?: string;
  /** URL of the UI for bootstrap email link (e.g., window.location.origin). Required if email is provided. */
  bootstrapUrl?: string;
  configuration?: BootstrapDeviceConfiguration;
}

/** GetDevicePayload */
export interface GetDevicePayload {
  [key: string]: any;
}

/** ConfigureDevicePayload */
export interface ConfigureDevicePayload {
  /** Seat ID of the device to configure */
  seatId: number;
  configuration: DeviceConfiguration;
  /** Profile ID to assign to device. If null, device uses manual configuration from the configuration field. */
  profileId?: string;
}

/** DeleteDevicePayload */
export interface DeleteDevicePayload {
  /** Seat ID of the device to delete */
  seatId: number;
  /** Whether to force deletion even if device is active */
  force?: boolean;
}

/** ListDevicesPayload */
export interface ListDevicesPayload {
  filters?: DeviceFilters;
}

/** UpdateDeviceMetadataPayload */
export interface UpdateDeviceMetadataPayload {
  /** Seat ID of the device to update */
  seatId: number;
  /** List of tag IDs to assign to the device (replaces existing tags) */
  tagIds: string[];
}

/** BootstrapDeviceResponsePayload */
export interface BootstrapDeviceResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  /** Unique seat identifier for the bootstrapped device */
  seatId?: number;
  bootstrapCredentials?: DeviceCredentials;
}

/** GetDeviceResponsePayload */
export interface GetDeviceResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  device?: DeviceInfo;
}

/** ConfigureDeviceResponsePayload */
export interface ConfigureDeviceResponsePayload {
  [key: string]: any;
}

/** DeleteDeviceResponsePayload */
export interface DeleteDeviceResponsePayload {
  [key: string]: any;
}

/** ListDevicesResponsePayload */
export interface ListDevicesResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  devices: DeviceInfo[];
}

/** UpdateDeviceMetadataResponsePayload */
export interface UpdateDeviceMetadataResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  device?: DeviceInfo;
}

/** DeviceStatusUpdatePayload */
export interface DeviceStatusUpdatePayload {
  /** Seat ID of the device whose status changed */
  seatId: number;
  previousStatus: DeviceStatus;
  newStatus: DeviceStatus;
  /** When the status change occurred */
  timestamp: string;
  deviceInfo: DeviceInfo;
  /** Reason for status change (e.g., "device_provisioned", "manual_update") */
  reason: string;
}

/** NetworkNode */
export interface NetworkNode {
  /** Unique identifier for the node */
  id: string;
  type: NetworkNodeType;
  /** Human-readable name for the node */
  name: string;
  /** Function of the device (only for device nodes) */
  function?: DeviceType;
  /** Type of CSKA (only for CSKA nodes) */
  cskaType?: CskaType;
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
  type: NetworkLinkType;
  /** Whether this link has detected threats (for communication links) */
  threat?: boolean;
  /** Description of the threat (if any) */
  threatDescription?: string;
  /** Number of threats on this link (for threat type links) */
  threatCount?: number;
}

/** NetworkTopologyData */
export interface NetworkTopologyData {
  /** List of network nodes (CSKAs and devices) */
  nodes: NetworkNode[];
  /** List of network links (ownership and communication) */
  links: NetworkLink[];
}

/** GetNetworkTopologyPayload */
export interface GetNetworkTopologyPayload {
  [key: string]: any;
}

/** GetNetworkTopologyResponsePayload */
export interface GetNetworkTopologyResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  networkData?: NetworkTopologyData;
}

/** ProvisionDeviceRefreshRequestPayload */
export interface ProvisionDeviceRefreshRequestPayload {
  /** The public key for the user to be created */
  deviceUserIdPub: string;
  /** The seat ID for the device */
  seatId: number;
}

/** ProvisionDeviceRefreshResponsePayload */
export interface ProvisionDeviceRefreshResponsePayload {
  /** The device user JWT for the new user */
  deviceUserJwt: string;
}

/** ProvisionDeviceRefreshPayload */
export interface ProvisionDeviceRefreshPayload {
  [key: string]: any;
}

/** SignerKey */
export interface SignerKey {
  /** Version of the SignerKey data structure */
  version: number;
  key: Key;
}

/** SaltedKeyRequestPayload */
export interface SaltedKeyRequestPayload {
  /** Version of the SaltedKeyRequest data structure */
  version: number;
  signerId: SeatId;
  validatorId: SeatId;
  /** Index to use for salting the signing key */
  signingSaltIndex: number;
  channelId: ChannelId;
  signerEndpoint: NetworkEndpoint;
  validatorEndpoint: NetworkEndpoint;
  /** Human-readable name of the validator for connection tracking */
  validatorName: string;
  validatorCskaId: CskaId;
  /** Human-readable name of the validator's CSKA for connection tracking */
  validatorCskaName: string;
}

/** SaltedKeyResponsePayload */
export interface SaltedKeyResponsePayload {
  /** Version of the SaltedKeyResponse data structure */
  version: number;
  saltedKey: Salt;
  /** Human-readable name of the signer for connection tracking */
  signerName: string;
  /** Human-readable name of the signer's CSKA for connection tracking */
  signerCskaName: string;
}

/** NewSessionHeader */
export interface NewSessionHeader {
  /** Channel ID for the session */
  channelId: number;
  /** CSKA ID for the session */
  cskaId: number;
  /** Logical seat ID for the session */
  logicalSeatId: number;
}

/** HashDigests */
export interface HashDigests {
  /** Layer 3 hash digest */
  l3Digest: number;
  /** Layer 4 hash digest */
  l4Digest: number;
  /** Layer 5/6/7 hash digest */
  l567Digest: number;
}

/** ThreatReport */
export interface ThreatReport {
  /** Version of the ThreatReport data structure */
  version: number;
  /** Timestamp when threat was detected (milliseconds since epoch) */
  when: number;
  kind: ThreatKind;
  /** CSKA ID where threat was detected */
  cskaId: number;
  signerEndpoint: NetworkEndpoint;
  validatorId: SeatId;
  validatorEndpoint: NetworkEndpoint;
  /** Additional information about the threat */
  info: string;
  /** Base64-encoded raw packet data starting from IP header (up to 100 bytes) */
  payload?: string;
  newSessionHeader?: NewSessionHeader;
  hashDigests?: HashDigests;
}

/** ThreatReportPayload */
export interface ThreatReportPayload {
  [key: string]: any;
}

/** ThreatQueryPayload */
export interface ThreatQueryPayload {
  /** Start timestamp (milliseconds since epoch) */
  startTime: number;
  /** End timestamp (milliseconds since epoch) */
  endTime: number;
  /** Maximum number of results to return */
  limit?: number;
  /** Number of results to skip for pagination */
  offset?: number;
  /** Filter by threat types (optional) */
  threatKinds?: ThreatKind[];
  /** Filter by validator IDs (optional) */
  validatorIds?: SeatId[];
}

/** ThreatPcapDownloadPayload */
export interface ThreatPcapDownloadPayload {
  /** Start timestamp (milliseconds since epoch) */
  startTime: number;
  /** End timestamp (milliseconds since epoch) */
  endTime: number;
  /** Source IP address to filter threats (e.g., "192.168.1.100") */
  sourceIp: string;
  /** Maximum number of packets to include in PCAP (enforced server-side) */
  limit?: number;
}

/** ThreatReportResponsePayload */
export interface ThreatReportResponsePayload {
  [key: string]: any;
}

/** ThreatQueryResponsePayload */
export interface ThreatQueryResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  /** Array of threat reports matching the query */
  threats: ThreatReport[];
  /** Total number of threats matching the query (for pagination) */
  totalCount: number;
}

/** ThreatPcapDownloadResponsePayload */
export interface ThreatPcapDownloadResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  /** Base64-encoded ZIP archive containing threats.pcap and threats.json (only present if success is true) */
  pcapData?: string;
  /** Suggested filename for the download (e.g., "threats-192.168.1.100.zip") */
  filename?: string;
  /** Number of packets included in the PCAP file within the ZIP */
  packetCount?: number;
}

/** ThreatStreamNotificationPayload */
export interface ThreatStreamNotificationPayload {
  threatReport: ThreatReport;
  /** When the threat was archived (milliseconds since epoch) */
  archivedAt: number;
}

/** ThreatStreamPayload */
export interface ThreatStreamPayload {
  [key: string]: any;
}

/** ConnectionRecord */
export interface ConnectionRecord {
  connectionType: ConnectionType;
  signerId: SeatId;
  /** Human-readable name of the signer */
  signerName: string;
  signerCskaId: CskaId;
  /** Human-readable name of the signer's CSKA */
  signerCskaName: string;
  validatorId: SeatId;
  /** Human-readable name of the validator */
  validatorName: string;
  validatorCskaId: CskaId;
  /** Human-readable name of the validator's CSKA */
  validatorCskaName: string;
  /** Timestamp when connection was first established (milliseconds since epoch) */
  firstSeen: number;
  /** Timestamp when connection was last active (milliseconds since epoch) */
  lastSeen: number;
  /** Number of times this connection has been established */
  connectionCount: number;
}

/** TopologyDelta */
export interface TopologyDelta {
  operation: TopologyOperation;
  /** Node that was affected (for node operations) */
  node?: NetworkNode;
  /** Link that was affected (for link operations) */
  link?: NetworkLink;
  /** Additional metadata about the change */
  metadata?: Record<string, any>;
}

/** ConnectionQueryPayload */
export interface ConnectionQueryPayload {
  /** Maximum number of results to return */
  limit?: number;
  /** Number of results to skip for pagination */
  offset?: number;
  connectionType?: ConnectionType;
  dateRange?: TimeRangeQuery;
  /** Filter by specific signer IDs (optional) */
  signerIds?: SeatId[];
  /** Filter by specific validator IDs (optional) */
  validatorIds?: SeatId[];
  /** Filter by specific CSKA IDs (optional) */
  cskaIds?: CskaId[];
  /** Filter by minimum connection count (optional) */
  minConnectionCount?: number;
}

/** ConnectionQueryResponsePayload */
export interface ConnectionQueryResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  /** Array of connection records matching the query */
  connections: ConnectionRecord[];
  /** Total number of connections matching the query (for pagination) */
  totalCount: number;
}

/** ConnectionStreamNotificationPayload */
export interface ConnectionStreamNotificationPayload {
  eventType: ConnectionEventType;
  /** The connection record that was affected */
  connectionRecord?: ConnectionRecord;
  /** Topology change information (optional) */
  topologyDelta?: TopologyDelta;
  /** Timestamp when the event occurred (milliseconds since epoch) */
  timestamp: number;
}

/** ValidatorConnectionReportPayload */
export interface ValidatorConnectionReportPayload {
  validatorId: SeatId;
  /** Human-readable name of the validator */
  validatorName: string;
  validatorCskaId: CskaId;
  /** Human-readable name of the validator's CSKA */
  validatorCskaName: string;
  signerId: SeatId;
  /** Human-readable name of the signer */
  signerName: string;
  signerCskaId: CskaId;
  /** Human-readable name of the signer's CSKA */
  signerCskaName: string;
  channelId: ChannelId;
  /** Timestamp when the connection was established (milliseconds since epoch) */
  timestamp: number;
}

/** ValidatorConnectionResponsePayload */
export interface ValidatorConnectionResponsePayload {
  [key: string]: any;
}

/** ConnectionStreamPayload */
export interface ConnectionStreamPayload {
  [key: string]: any;
}

/** MetricSample */
export interface MetricSample {
  /** Timestamp in milliseconds since epoch when metrics were collected */
  timestamp: number;
  /** Map of metric name to metric value (e.g., signed_packets, verified_packets, dropped_packets, threats) */
  metrics: Record<string, any>;
}

/** MetricsQueryPayload */
export interface MetricsQueryPayload {
  /** Seat ID of the device to query metrics for */
  seatId: number;
  /** Filter by specific metric names (optional, returns all if not specified) */
  metricNames?: string[];
  /** Start timestamp in milliseconds since epoch (optional) */
  startTime?: number;
  /** End timestamp in milliseconds since epoch (optional) */
  endTime?: number;
}

/** MetricsResetPayload */
export interface MetricsResetPayload {
  /** Seat ID of the device to reset metrics for */
  seatId: number;
  /** Specific metric name to reset (e.g., "threats_detected") */
  metricName: string;
}

/** MetricsQueryResponsePayload */
export interface MetricsQueryResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  /** Seat ID of the device */
  seatId: number;
  /** Array of metric samples matching the query */
  samples: MetricSample[];
}

/** MetricsResetResponsePayload */
export interface MetricsResetResponsePayload {
  [key: string]: any;
}

/** MetricsStreamNotificationPayload */
export interface MetricsStreamNotificationPayload {
  /** Seat ID of the device */
  seatId: number;
  /** Latest metric sample from the device */
  sample: MetricSample;
  /** Timestamp when the notification was sent (milliseconds since epoch) */
  timestamp: number;
}

/** MetricsStreamPayload */
export interface MetricsStreamPayload {
  [key: string]: any;
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

/** UpdateTagPayload */
export interface UpdateTagPayload {
  /** ID of the tag to update */
  tagId: string;
  /** New name for the tag */
  tagName?: string;
  /** New color for the tag */
  color?: string;
}

/** DeleteTagPayload */
export interface DeleteTagPayload {
  /** ID of the tag to delete */
  tagId: string;
}

/** ListTagsPayload */
export interface ListTagsPayload {
  /** Whether to include device count for each tag */
  includeDeviceCount?: boolean;
}

/** CreateTagResponsePayload */
export interface CreateTagResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  tag?: TagInfo;
}

/** UpdateTagResponsePayload */
export interface UpdateTagResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  tag?: TagInfo;
}

/** DeleteTagResponsePayload */
export interface DeleteTagResponsePayload {
  [key: string]: any;
}

/** ListTagsResponsePayload */
export interface ListTagsResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  tags: TagInfo[];
}

/** ProfileConfiguration */
export interface ProfileConfiguration {
  /** List of IPv4 addresses that should be blocked at the source IP level for validator devices */
  blockedAddresses?: string[];
  /** Array of validation rules to apply */
  validationRules?: FilterValidationRule[];
  /** Array of signing rules to apply */
  signingRules?: FilterSignerRule[];
}

/** ProfileInfo */
export interface ProfileInfo {
  /** When the entity was created */
  createdAt: string;
  /** When the entity was last updated */
  updatedAt: string;
  /** Unique identifier for the profile */
  profileId: string;
  /** Human-readable name for the profile */
  profileName: string;
  /** Optional description of the profile */
  description?: string;
  /** Number of devices assigned to this profile (computed on query) */
  deviceCount?: number;
  configuration: ProfileConfiguration;
}

/** CreateProfilePayload */
export interface CreateProfilePayload {
  /** Human-readable name for the profile */
  profileName: string;
  /** Optional description of the profile */
  description?: string;
  configuration: ProfileConfiguration;
}

/** GetProfilePayload */
export interface GetProfilePayload {
  /** ID of the profile to retrieve */
  profileId: string;
}

/** UpdateProfilePayload */
export interface UpdateProfilePayload {
  /** ID of the profile to update */
  profileId: string;
  /** New name for the profile */
  profileName?: string;
  /** New description for the profile */
  description?: string;
  configuration?: ProfileConfiguration;
}

/** DeleteProfilePayload */
export interface DeleteProfilePayload {
  /** ID of the profile to delete */
  profileId: string;
}

/** ListProfilesPayload */
export interface ListProfilesPayload {
  /** Whether to include device count for each profile */
  includeDeviceCount?: boolean;
}

/** AssignProfilePayload */
export interface AssignProfilePayload {
  /** ID of the profile to assign devices to */
  profileId: string;
  /** List of device seat IDs to assign to the profile */
  seatIds: number[];
}

/** UnassignProfilePayload */
export interface UnassignProfilePayload {
  /** List of device seat IDs to remove from their profiles */
  seatIds: number[];
}

/** CreateProfileResponsePayload */
export interface CreateProfileResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  profile?: ProfileInfo;
}

/** GetProfileResponsePayload */
export interface GetProfileResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  profile?: ProfileInfo;
}

/** UpdateProfileResponsePayload */
export interface UpdateProfileResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  profile?: ProfileInfo;
  /** Number of devices that received configuration updates */
  devicesUpdated?: number;
}

/** DeleteProfileResponsePayload */
export interface DeleteProfileResponsePayload {
  [key: string]: any;
}

/** ListProfilesResponsePayload */
export interface ListProfilesResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  profiles: ProfileInfo[];
}

/** AssignProfileResponsePayload */
export interface AssignProfileResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  /** Number of devices successfully assigned */
  assignedCount: number;
  /** List of seat IDs that failed to be assigned (if any) */
  failedSeatIds?: number[];
}

/** UnassignProfileResponsePayload */
export interface UnassignProfileResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  /** Number of devices successfully unassigned */
  unassignedCount: number;
}

/** SendGridConfig */
export interface SendGridConfig {
  /** SendGrid API key */
  apiKey: string;
}

/** MailgunConfig */
export interface MailgunConfig {
  /** Mailgun API key */
  apiKey: string;
  /** Mailgun sending domain (e.g., mail.yourcompany.com) */
  domain: string;
  region: MailgunRegion;
}

/** EmailSettings */
export interface EmailSettings {
  /** Whether email notifications are enabled */
  enabled: boolean;
  /** Email address to send from (required when enabled) */
  fromAddress?: string;
  /** Display name for the sender */
  fromName?: string;
  /** Currently active email provider (required when enabled) */
  activeProvider?: EmailProviderType;
  /** SendGrid provider configuration (preserved when switching providers) */
  sendgrid?: SendGridConfig;
  /** Mailgun provider configuration (preserved when switching providers) */
  mailgun?: MailgunConfig;
}

/** SystemSettings */
export interface SystemSettings {
  email: EmailSettings;
}

/** GetSettingsPayload */
export interface GetSettingsPayload {
  [key: string]: any;
}

/** UpdateSettingsPayload */
export interface UpdateSettingsPayload {
  settings: SystemSettings;
}

/** GetSettingsResponsePayload */
export interface GetSettingsResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  settings?: SystemSettings;
}

/** UpdateSettingsResponsePayload */
export interface UpdateSettingsResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  settings?: SystemSettings;
}

/** UserInfo */
export interface UserInfo {
  /** When the entity was created */
  createdAt: string;
  /** When the entity was last updated */
  updatedAt: string;
  /** Unique identifier for the user */
  userId: string;
  /** User's display name */
  name: string;
  /** List of email addresses associated with this user (first is primary) */
  emails: string[];
  role: UserRole;
  /** When the user last logged in (if ever) */
  lastLogin?: string;
}

/** CreateUserPayload */
export interface CreateUserPayload {
  /** User's display name */
  name: string;
  /** User's primary email address */
  email: string;
  /** User's role (defaults to admin) */
  role?: UserRole;
}

/** GetUserPayload */
export interface GetUserPayload {
  /** ID of the user to retrieve */
  userId: string;
}

/** ListUsersPayload */
export interface ListUsersPayload {
  [key: string]: any;
}

/** UpdateUserPayload */
export interface UpdateUserPayload {
  /** ID of the user to update */
  userId: string;
  /** New display name for the user */
  name?: string;
  /** New role for the user */
  role?: UserRole;
}

/** DeleteUserPayload */
export interface DeleteUserPayload {
  /** ID of the user to delete */
  userId: string;
}

/** AddUserEmailPayload */
export interface AddUserEmailPayload {
  /** ID of the user to add email to */
  userId: string;
  /** Email address to add */
  email: string;
}

/** RemoveUserEmailPayload */
export interface RemoveUserEmailPayload {
  /** ID of the user to remove email from */
  userId: string;
  /** Email address to remove */
  email: string;
}

/** CreateUserResponsePayload */
export interface CreateUserResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  user?: UserInfo;
}

/** GetUserResponsePayload */
export interface GetUserResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  user?: UserInfo;
}

/** ListUsersResponsePayload */
export interface ListUsersResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  users: UserInfo[];
}

/** UpdateUserResponsePayload */
export interface UpdateUserResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  user?: UserInfo;
}

/** DeleteUserResponsePayload */
export interface DeleteUserResponsePayload {
  [key: string]: any;
}

/** AddUserEmailResponsePayload */
export interface AddUserEmailResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  user?: UserInfo;
}

/** RemoveUserEmailResponsePayload */
export interface RemoveUserEmailResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  user?: UserInfo;
}

/** SsoProviderInfo */
export interface SsoProviderInfo {
  /** When the entity was created */
  createdAt: string;
  /** When the entity was last updated */
  updatedAt: string;
  /** Unique identifier for this provider configuration */
  providerId: string;
  providerType: SsoProviderType;
  /** Whether this provider is enabled */
  enabled: boolean;
  /** Display name for this provider (shown on login button) */
  displayName: string;
  /** OAuth client ID */
  clientId: string;
  /** Azure-specific tenant ID (use "common" for multi-tenant) */
  tenantId?: string;
  /** OAuth redirect URI (callback URL) */
  redirectUri: string;
  /** OAuth scopes to request */
  scopes: string[];
}

/** AuthSettingsInfo */
export interface AuthSettingsInfo {
  /** Whether authentication is enabled (middleware active) */
  authEnabled: boolean;
  /** Whether at least one SSO provider is configured */
  ssoConfigured: boolean;
  /** List of configured SSO providers */
  providers: SsoProviderInfo[];
  /** When auth settings were last updated */
  updatedAt: string;
}

/** GetSsoSettingsPayload */
export interface GetSsoSettingsPayload {
  [key: string]: any;
}

/** ConfigureSsoProviderPayload */
export interface ConfigureSsoProviderPayload {
  providerType: SsoProviderType;
  /** Display name for this provider (shown on login button) */
  displayName: string;
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret */
  clientSecret: string;
  /** Azure-specific tenant ID (use "common" for multi-tenant) */
  tenantId?: string;
  /** OAuth redirect URI (callback URL) */
  redirectUri: string;
  /** OAuth scopes to request (uses defaults if not provided) */
  scopes?: string[];
}

/** UpdateSsoProviderPayload */
export interface UpdateSsoProviderPayload {
  /** ID of the provider to update */
  providerId: string;
  /** Whether this provider is enabled */
  enabled?: boolean;
  /** Display name for this provider */
  displayName?: string;
  /** OAuth client ID */
  clientId?: string;
  /** OAuth client secret (only if changing) */
  clientSecret?: string;
  /** Azure-specific tenant ID */
  tenantId?: string;
  /** OAuth redirect URI */
  redirectUri?: string;
  /** OAuth scopes to request */
  scopes?: string[];
}

/** DeleteSsoProviderPayload */
export interface DeleteSsoProviderPayload {
  /** ID of the provider to delete */
  providerId: string;
}

/** EnableAuthPayload */
export interface EnableAuthPayload {
  [key: string]: any;
}

/** DisableAuthPayload */
export interface DisableAuthPayload {
  [key: string]: any;
}

/** SsoInitiatePayload */
export interface SsoInitiatePayload {
  providerType: SsoProviderType;
  /** URL to redirect to after successful login */
  redirectTo?: string;
}

/** SsoCallbackPayload */
export interface SsoCallbackPayload {
  /** Authorization code from OAuth provider */
  code?: string;
  /** State parameter for CSRF verification */
  state: string;
  /** Error code from OAuth provider (if any) */
  error?: string;
  /** Error description from OAuth provider (if any) */
  errorDescription?: string;
}

/** AuthSettingsResponsePayload */
export interface AuthSettingsResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  settings?: AuthSettingsInfo;
}

/** GetSsoSettingsResponsePayload */
export interface GetSsoSettingsResponsePayload {
  [key: string]: any;
}

/** ConfigureSsoProviderResponsePayload */
export interface ConfigureSsoProviderResponsePayload {
  [key: string]: any;
}

/** UpdateSsoProviderResponsePayload */
export interface UpdateSsoProviderResponsePayload {
  [key: string]: any;
}

/** DeleteSsoProviderResponsePayload */
export interface DeleteSsoProviderResponsePayload {
  [key: string]: any;
}

/** EnableAuthResponsePayload */
export interface EnableAuthResponsePayload {
  [key: string]: any;
}

/** DisableAuthResponsePayload */
export interface DisableAuthResponsePayload {
  [key: string]: any;
}

/** SsoInitiateResponsePayload */
export interface SsoInitiateResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  /** URL to redirect the user to for SSO login */
  authorizationUrl?: string;
  /** State parameter for CSRF protection */
  state?: string;
}

/** SsoCallbackResponsePayload */
export interface SsoCallbackResponsePayload {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
  /** JWT token for authenticated requests */
  jwt?: string;
  /** Authenticated user information */
  user?: UserInfo;
  /** URL to redirect to after successful login */
  redirectTo?: string;
}

/** BaseResponse */
export interface BaseResponse {
  /** Whether the operation was successful */
  success: boolean;
  /** Success or error message */
  message: string;
}

/** UuidPayload */
export interface UuidPayload {
  /** Unique identifier */
  id: string;
}

/** SeatIdPayload */
export interface SeatIdPayload {
  /** Device seat identifier */
  seatId: number;
}

/** Empty payload - no parameters needed */
export interface EmptyPayload {

}

/** Timestamps */
export interface Timestamps {
  /** When the entity was created */
  createdAt: string;
  /** When the entity was last updated */
  updatedAt: string;
}

/** CreatedTimestamp */
export interface CreatedTimestamp {
  /** When the entity was created */
  createdAt: string;
}

/** PaginationParams */
export interface PaginationParams {
  /** Maximum number of results to return */
  limit?: number;
  /** Number of results to skip for pagination */
  offset?: number;
}

/** PaginationInfo */
export interface PaginationInfo {
  /** Items per page */
  limit: number;
  /** Current offset */
  offset: number;
  /** Total number of items */
  totalItems: number;
}

/** TimeRangeQuery */
export interface TimeRangeQuery {
  /** Start timestamp (milliseconds since epoch) */
  startTime: number;
  /** End timestamp (milliseconds since epoch) */
  endTime: number;
}

/** TimeRangeQueryWithPagination */
export interface TimeRangeQueryWithPagination {
  /** Start timestamp (milliseconds since epoch) */
  startTime: number;
  /** End timestamp (milliseconds since epoch) */
  endTime: number;
  /** Maximum number of results to return */
  limit?: number;
  /** Number of results to skip for pagination */
  offset?: number;
}

/** MAC address as 6 bytes */
export type MacAddress = number[];

/** NetworkEndpoint */
export interface NetworkEndpoint {
  /** IP address */
  ip?: string;
  /** Port number */
  port?: number;
  mac?: MacAddress;
}

/** Unique seat identifier for a device */
export type SeatId = number;

/** Unique CSKA identifier */
export type CskaId = number;

/** Unique channel identifier */
export type ChannelId = number;

/** DeviceIdentity */
export interface DeviceIdentity {
  seatId: SeatId;
  /** Human-readable name of the device */
  deviceName: string;
  cskaId: CskaId;
  /** Human-readable name of the CSKA */
  cskaName: string;
}

/** A full signing key before salting (32 bytes) */
export type Key = number[];

/** A salted key for validation (16 bytes) */
export type Salt = number[];

/** Current status of the device */
export type DeviceStatus = 'active' | 'inactive' | 'provisioning' | 'error';

/** Type/function of the device (auto-computed from rules) */
export type DeviceType = 'signer' | 'validator' | 'signer_validator' | 'unconfigured';

/** Logging verbosity level */
export type LoggingLevel = 'debug' | 'info' | 'warn' | 'error';

/** Action to take for validation */
export type FilterValidationAction = 'accept' | 'drop' | 'validate' | 'validate_strip';

/** Action to take for signing */
export type FilterSigningAction = 'accept' | 'drop' | 'sign';

/** Network layer to apply the filter to */
export type FilterLayer = 'l567' | 'l4' | 'l3';

/** Algorithm to use for the filter */
export type FilterAlgo = 'xor' | 'sha512';

/** Type of threat detected */
export type ThreatKind = 'unsigned' | 'protocol_violation' | 'version_mismatch' | 'signature_mismatch_l2' | 'signature_mismatch_l3' | 'signature_mismatch_l4' | 'signature_mismatch_l567' | 'invalid_signer_id' | 'expired_signer_id' | 'double_key_deref' | 'ddos' | 'cross_cska_threat';

/** Type of network node */
export type NetworkNodeType = 'cska' | 'device' | 'threat_actor';

/** Type of network link */
export type NetworkLinkType = 'ownership' | 'communication' | 'threat';

/** Type of CSKA (local or remote) */
export type CskaType = 'local' | 'remote';

/** Type of connection for filtering */
export type ConnectionType = 'all' | 'signer_to_validator' | 'validator_to_signer';

/** Type of connection event */
export type ConnectionEventType = 'connection_established' | 'connection_updated' | 'device_offline' | 'topology_changed';

/** Type of topology change operation */
export type TopologyOperation = 'add_node' | 'remove_node' | 'add_link' | 'remove_link' | 'update_link';

/** Type of email provider */
export type EmailProviderType = 'sendgrid' | 'mailgun';

/** Mailgun API region (US or EU) */
export type MailgunRegion = 'us' | 'eu';

/** User role (currently only admin is supported) */
export type UserRole = 'admin';

/** Type of SSO provider */
export type SsoProviderType = 'azure' | 'google' | 'amazon';


/** LogoutRequest message */
export interface LogoutRequest {
  /** The message payload */
  payload: LogoutPayload;
}

/** LogoutResponse message */
export interface LogoutResponse {
  /** The message payload */
  payload: LogoutResponsePayload;
}

/** BootstrapDeviceRequest message */
export interface BootstrapDeviceRequest {
  /** The message payload */
  payload: BootstrapDevicePayload;
}

/** BootstrapDeviceResponse message */
export interface BootstrapDeviceResponse {
  /** The message payload */
  payload: BootstrapDeviceResponsePayload;
}

/** GetDeviceRequest message */
export interface GetDeviceRequest {
  /** The message payload */
  payload: GetDevicePayload;
}

/** GetDeviceResponse message */
export interface GetDeviceResponse {
  /** The message payload */
  payload: GetDeviceResponsePayload;
}

/** ConfigureDeviceRequest message */
export interface ConfigureDeviceRequest {
  /** The message payload */
  payload: ConfigureDevicePayload;
}

/** ConfigureDeviceResponse message */
export interface ConfigureDeviceResponse {
  /** The message payload */
  payload: ConfigureDeviceResponsePayload;
}

/** DeleteDeviceRequest message */
export interface DeleteDeviceRequest {
  /** The message payload */
  payload: DeleteDevicePayload;
}

/** DeleteDeviceResponse message */
export interface DeleteDeviceResponse {
  /** The message payload */
  payload: DeleteDeviceResponsePayload;
}

/** ListDevicesRequest message */
export interface ListDevicesRequest {
  /** The message payload */
  payload: ListDevicesPayload;
}

/** ListDevicesResponse message */
export interface ListDevicesResponse {
  /** The message payload */
  payload: ListDevicesResponsePayload;
}

/** DeviceStatusUpdateNotification message */
export interface DeviceStatusUpdateNotification {
  /** The message payload */
  payload: DeviceStatusUpdatePayload;
}

/** UpdateDeviceMetadataRequest message */
export interface UpdateDeviceMetadataRequest {
  /** The message payload */
  payload: UpdateDeviceMetadataPayload;
}

/** UpdateDeviceMetadataResponse message */
export interface UpdateDeviceMetadataResponse {
  /** The message payload */
  payload: UpdateDeviceMetadataResponsePayload;
}

/** GetNetworkTopologyRequest message */
export interface GetNetworkTopologyRequest {
  /** The message payload */
  payload: GetNetworkTopologyPayload;
}

/** GetNetworkTopologyResponse message */
export interface GetNetworkTopologyResponse {
  /** The message payload */
  payload: GetNetworkTopologyResponsePayload;
}

/** ProvisionDeviceRefreshRequest message */
export interface ProvisionDeviceRefreshRequest {
  /** The message payload */
  payload: ProvisionDeviceRefreshPayload;
}

/** ProvisionDeviceRefreshResponse message */
export interface ProvisionDeviceRefreshResponse {
  /** The message payload */
  payload: ProvisionDeviceRefreshResponsePayload;
}

/** SaltedKeyRequest message */
export interface SaltedKeyRequest {
  /** The message payload */
  payload: SaltedKeyRequestPayload;
}

/** SaltedKeyResponse message */
export interface SaltedKeyResponse {
  /** The message payload */
  payload: SaltedKeyResponsePayload;
}

/** ThreatReportRequest message */
export interface ThreatReportRequest {
  /** The message payload */
  payload: ThreatReportPayload;
}

/** ThreatReportResponse message */
export interface ThreatReportResponse {
  /** The message payload */
  payload: ThreatReportResponsePayload;
}

/** ThreatQueryRequest message */
export interface ThreatQueryRequest {
  /** The message payload */
  payload: ThreatQueryPayload;
}

/** ThreatQueryResponse message */
export interface ThreatQueryResponse {
  /** The message payload */
  payload: ThreatQueryResponsePayload;
}

/** ThreatStreamNotification message */
export interface ThreatStreamNotification {
  /** The message payload */
  payload: ThreatStreamPayload;
}

/** ThreatPcapDownloadRequest message */
export interface ThreatPcapDownloadRequest {
  /** The message payload */
  payload: ThreatPcapDownloadPayload;
}

/** ThreatPcapDownloadResponse message */
export interface ThreatPcapDownloadResponse {
  /** The message payload */
  payload: ThreatPcapDownloadResponsePayload;
}

/** ValidatorConnectionReport message */
export interface ValidatorConnectionReport {
  /** The message payload */
  payload: ValidatorConnectionReportPayload;
}

/** ValidatorConnectionResponse message */
export interface ValidatorConnectionResponse {
  /** The message payload */
  payload: ValidatorConnectionResponsePayload;
}

/** ConnectionQueryRequest message */
export interface ConnectionQueryRequest {
  /** The message payload */
  payload: ConnectionQueryPayload;
}

/** ConnectionQueryResponse message */
export interface ConnectionQueryResponse {
  /** The message payload */
  payload: ConnectionQueryResponsePayload;
}

/** ConnectionStreamNotification message */
export interface ConnectionStreamNotification {
  /** The message payload */
  payload: ConnectionStreamPayload;
}

/** MetricsQueryRequest message */
export interface MetricsQueryRequest {
  /** The message payload */
  payload: MetricsQueryPayload;
}

/** MetricsQueryResponse message */
export interface MetricsQueryResponse {
  /** The message payload */
  payload: MetricsQueryResponsePayload;
}

/** MetricsStreamNotification message */
export interface MetricsStreamNotification {
  /** The message payload */
  payload: MetricsStreamPayload;
}

/** MetricsResetRequest message */
export interface MetricsResetRequest {
  /** The message payload */
  payload: MetricsResetPayload;
}

/** MetricsResetResponse message */
export interface MetricsResetResponse {
  /** The message payload */
  payload: MetricsResetResponsePayload;
}

/** CreateTagRequest message */
export interface CreateTagRequest {
  /** The message payload */
  payload: CreateTagPayload;
}

/** CreateTagResponse message */
export interface CreateTagResponse {
  /** The message payload */
  payload: CreateTagResponsePayload;
}

/** UpdateTagRequest message */
export interface UpdateTagRequest {
  /** The message payload */
  payload: UpdateTagPayload;
}

/** UpdateTagResponse message */
export interface UpdateTagResponse {
  /** The message payload */
  payload: UpdateTagResponsePayload;
}

/** DeleteTagRequest message */
export interface DeleteTagRequest {
  /** The message payload */
  payload: DeleteTagPayload;
}

/** DeleteTagResponse message */
export interface DeleteTagResponse {
  /** The message payload */
  payload: DeleteTagResponsePayload;
}

/** ListTagsRequest message */
export interface ListTagsRequest {
  /** The message payload */
  payload: ListTagsPayload;
}

/** ListTagsResponse message */
export interface ListTagsResponse {
  /** The message payload */
  payload: ListTagsResponsePayload;
}

/** CreateProfileRequest message */
export interface CreateProfileRequest {
  /** The message payload */
  payload: CreateProfilePayload;
}

/** CreateProfileResponse message */
export interface CreateProfileResponse {
  /** The message payload */
  payload: CreateProfileResponsePayload;
}

/** GetProfileRequest message */
export interface GetProfileRequest {
  /** The message payload */
  payload: GetProfilePayload;
}

/** GetProfileResponse message */
export interface GetProfileResponse {
  /** The message payload */
  payload: GetProfileResponsePayload;
}

/** UpdateProfileRequest message */
export interface UpdateProfileRequest {
  /** The message payload */
  payload: UpdateProfilePayload;
}

/** UpdateProfileResponse message */
export interface UpdateProfileResponse {
  /** The message payload */
  payload: UpdateProfileResponsePayload;
}

/** DeleteProfileRequest message */
export interface DeleteProfileRequest {
  /** The message payload */
  payload: DeleteProfilePayload;
}

/** DeleteProfileResponse message */
export interface DeleteProfileResponse {
  /** The message payload */
  payload: DeleteProfileResponsePayload;
}

/** ListProfilesRequest message */
export interface ListProfilesRequest {
  /** The message payload */
  payload: ListProfilesPayload;
}

/** ListProfilesResponse message */
export interface ListProfilesResponse {
  /** The message payload */
  payload: ListProfilesResponsePayload;
}

/** AssignProfileRequest message */
export interface AssignProfileRequest {
  /** The message payload */
  payload: AssignProfilePayload;
}

/** AssignProfileResponse message */
export interface AssignProfileResponse {
  /** The message payload */
  payload: AssignProfileResponsePayload;
}

/** UnassignProfileRequest message */
export interface UnassignProfileRequest {
  /** The message payload */
  payload: UnassignProfilePayload;
}

/** UnassignProfileResponse message */
export interface UnassignProfileResponse {
  /** The message payload */
  payload: UnassignProfileResponsePayload;
}

/** GetSettingsRequest message */
export interface GetSettingsRequest {
  /** The message payload */
  payload: GetSettingsPayload;
}

/** GetSettingsResponse message */
export interface GetSettingsResponse {
  /** The message payload */
  payload: GetSettingsResponsePayload;
}

/** UpdateSettingsRequest message */
export interface UpdateSettingsRequest {
  /** The message payload */
  payload: UpdateSettingsPayload;
}

/** UpdateSettingsResponse message */
export interface UpdateSettingsResponse {
  /** The message payload */
  payload: UpdateSettingsResponsePayload;
}

/** CreateUserRequest message */
export interface CreateUserRequest {
  /** The message payload */
  payload: CreateUserPayload;
}

/** CreateUserResponse message */
export interface CreateUserResponse {
  /** The message payload */
  payload: CreateUserResponsePayload;
}

/** GetUserRequest message */
export interface GetUserRequest {
  /** The message payload */
  payload: GetUserPayload;
}

/** GetUserResponse message */
export interface GetUserResponse {
  /** The message payload */
  payload: GetUserResponsePayload;
}

/** ListUsersRequest message */
export interface ListUsersRequest {
  /** The message payload */
  payload: ListUsersPayload;
}

/** ListUsersResponse message */
export interface ListUsersResponse {
  /** The message payload */
  payload: ListUsersResponsePayload;
}

/** UpdateUserRequest message */
export interface UpdateUserRequest {
  /** The message payload */
  payload: UpdateUserPayload;
}

/** UpdateUserResponse message */
export interface UpdateUserResponse {
  /** The message payload */
  payload: UpdateUserResponsePayload;
}

/** DeleteUserRequest message */
export interface DeleteUserRequest {
  /** The message payload */
  payload: DeleteUserPayload;
}

/** DeleteUserResponse message */
export interface DeleteUserResponse {
  /** The message payload */
  payload: DeleteUserResponsePayload;
}

/** AddUserEmailRequest message */
export interface AddUserEmailRequest {
  /** The message payload */
  payload: AddUserEmailPayload;
}

/** AddUserEmailResponse message */
export interface AddUserEmailResponse {
  /** The message payload */
  payload: AddUserEmailResponsePayload;
}

/** RemoveUserEmailRequest message */
export interface RemoveUserEmailRequest {
  /** The message payload */
  payload: RemoveUserEmailPayload;
}

/** RemoveUserEmailResponse message */
export interface RemoveUserEmailResponse {
  /** The message payload */
  payload: RemoveUserEmailResponsePayload;
}

/** GetSsoSettingsRequest message */
export interface GetSsoSettingsRequest {
  /** The message payload */
  payload: GetSsoSettingsPayload;
}

/** GetSsoSettingsResponse message */
export interface GetSsoSettingsResponse {
  /** The message payload */
  payload: GetSsoSettingsResponsePayload;
}

/** ConfigureSsoProviderRequest message */
export interface ConfigureSsoProviderRequest {
  /** The message payload */
  payload: ConfigureSsoProviderPayload;
}

/** ConfigureSsoProviderResponse message */
export interface ConfigureSsoProviderResponse {
  /** The message payload */
  payload: ConfigureSsoProviderResponsePayload;
}

/** UpdateSsoProviderRequest message */
export interface UpdateSsoProviderRequest {
  /** The message payload */
  payload: UpdateSsoProviderPayload;
}

/** UpdateSsoProviderResponse message */
export interface UpdateSsoProviderResponse {
  /** The message payload */
  payload: UpdateSsoProviderResponsePayload;
}

/** DeleteSsoProviderRequest message */
export interface DeleteSsoProviderRequest {
  /** The message payload */
  payload: DeleteSsoProviderPayload;
}

/** DeleteSsoProviderResponse message */
export interface DeleteSsoProviderResponse {
  /** The message payload */
  payload: DeleteSsoProviderResponsePayload;
}

/** EnableAuthRequest message */
export interface EnableAuthRequest {
  /** The message payload */
  payload: EnableAuthPayload;
}

/** EnableAuthResponse message */
export interface EnableAuthResponse {
  /** The message payload */
  payload: EnableAuthResponsePayload;
}

/** DisableAuthRequest message */
export interface DisableAuthRequest {
  /** The message payload */
  payload: DisableAuthPayload;
}

/** DisableAuthResponse message */
export interface DisableAuthResponse {
  /** The message payload */
  payload: DisableAuthResponsePayload;
}

/** SsoInitiateRequest message */
export interface SsoInitiateRequest {
  /** The message payload */
  payload: SsoInitiatePayload;
}

/** SsoInitiateResponse message */
export interface SsoInitiateResponse {
  /** The message payload */
  payload: SsoInitiateResponsePayload;
}

/** SsoCallbackRequest message */
export interface SsoCallbackRequest {
  /** The message payload */
  payload: SsoCallbackPayload;
}

/** SsoCallbackResponse message */
export interface SsoCallbackResponse {
  /** The message payload */
  payload: SsoCallbackResponsePayload;
}


/** Union type for all message types */
export type Message = LogoutRequest | LogoutResponse | BootstrapDeviceRequest | BootstrapDeviceResponse | GetDeviceRequest | GetDeviceResponse | ConfigureDeviceRequest | ConfigureDeviceResponse | DeleteDeviceRequest | DeleteDeviceResponse | ListDevicesRequest | ListDevicesResponse | DeviceStatusUpdateNotification | UpdateDeviceMetadataRequest | UpdateDeviceMetadataResponse | GetNetworkTopologyRequest | GetNetworkTopologyResponse | ProvisionDeviceRefreshRequest | ProvisionDeviceRefreshResponse | SaltedKeyRequest | SaltedKeyResponse | ThreatReportRequest | ThreatReportResponse | ThreatQueryRequest | ThreatQueryResponse | ThreatStreamNotification | ThreatPcapDownloadRequest | ThreatPcapDownloadResponse | ValidatorConnectionReport | ValidatorConnectionResponse | ConnectionQueryRequest | ConnectionQueryResponse | ConnectionStreamNotification | MetricsQueryRequest | MetricsQueryResponse | MetricsStreamNotification | MetricsResetRequest | MetricsResetResponse | CreateTagRequest | CreateTagResponse | UpdateTagRequest | UpdateTagResponse | DeleteTagRequest | DeleteTagResponse | ListTagsRequest | ListTagsResponse | CreateProfileRequest | CreateProfileResponse | GetProfileRequest | GetProfileResponse | UpdateProfileRequest | UpdateProfileResponse | DeleteProfileRequest | DeleteProfileResponse | ListProfilesRequest | ListProfilesResponse | AssignProfileRequest | AssignProfileResponse | UnassignProfileRequest | UnassignProfileResponse | GetSettingsRequest | GetSettingsResponse | UpdateSettingsRequest | UpdateSettingsResponse | CreateUserRequest | CreateUserResponse | GetUserRequest | GetUserResponse | ListUsersRequest | ListUsersResponse | UpdateUserRequest | UpdateUserResponse | DeleteUserRequest | DeleteUserResponse | AddUserEmailRequest | AddUserEmailResponse | RemoveUserEmailRequest | RemoveUserEmailResponse | GetSsoSettingsRequest | GetSsoSettingsResponse | ConfigureSsoProviderRequest | ConfigureSsoProviderResponse | UpdateSsoProviderRequest | UpdateSsoProviderResponse | DeleteSsoProviderRequest | DeleteSsoProviderResponse | EnableAuthRequest | EnableAuthResponse | DisableAuthRequest | DisableAuthResponse | SsoInitiateRequest | SsoInitiateResponse | SsoCallbackRequest | SsoCallbackResponse;

/** Message type constants */
export const MessageTypes = {
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
  DEVICESTATUSUPDATENOTIFICATION: 'DeviceStatusUpdateNotification',
  UPDATEDEVICEMETADATAREQUEST: 'UpdateDeviceMetadataRequest',
  UPDATEDEVICEMETADATARESPONSE: 'UpdateDeviceMetadataResponse',
  GETNETWORKTOPOLOGYREQUEST: 'GetNetworkTopologyRequest',
  GETNETWORKTOPOLOGYRESPONSE: 'GetNetworkTopologyResponse',
  PROVISIONDEVICEREFRESHREQUEST: 'ProvisionDeviceRefreshRequest',
  PROVISIONDEVICEREFRESHRESPONSE: 'ProvisionDeviceRefreshResponse',
  SALTEDKEYREQUEST: 'SaltedKeyRequest',
  SALTEDKEYRESPONSE: 'SaltedKeyResponse',
  THREATREPORTREQUEST: 'ThreatReportRequest',
  THREATREPORTRESPONSE: 'ThreatReportResponse',
  THREATQUERYREQUEST: 'ThreatQueryRequest',
  THREATQUERYRESPONSE: 'ThreatQueryResponse',
  THREATSTREAMNOTIFICATION: 'ThreatStreamNotification',
  THREATPCAPDOWNLOADREQUEST: 'ThreatPcapDownloadRequest',
  THREATPCAPDOWNLOADRESPONSE: 'ThreatPcapDownloadResponse',
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
  CREATEUSERREQUEST: 'CreateUserRequest',
  CREATEUSERRESPONSE: 'CreateUserResponse',
  GETUSERREQUEST: 'GetUserRequest',
  GETUSERRESPONSE: 'GetUserResponse',
  LISTUSERSREQUEST: 'ListUsersRequest',
  LISTUSERSRESPONSE: 'ListUsersResponse',
  UPDATEUSERREQUEST: 'UpdateUserRequest',
  UPDATEUSERRESPONSE: 'UpdateUserResponse',
  DELETEUSERREQUEST: 'DeleteUserRequest',
  DELETEUSERRESPONSE: 'DeleteUserResponse',
  ADDUSEREMAILREQUEST: 'AddUserEmailRequest',
  ADDUSEREMAILRESPONSE: 'AddUserEmailResponse',
  REMOVEUSEREMAILREQUEST: 'RemoveUserEmailRequest',
  REMOVEUSEREMAILRESPONSE: 'RemoveUserEmailResponse',
  GETSSOSETTINGSREQUEST: 'GetSsoSettingsRequest',
  GETSSOSETTINGSRESPONSE: 'GetSsoSettingsResponse',
  CONFIGURESSOPROVIDERREQUEST: 'ConfigureSsoProviderRequest',
  CONFIGURESSOPROVIDERRESPONSE: 'ConfigureSsoProviderResponse',
  UPDATESSOPROVIDERREQUEST: 'UpdateSsoProviderRequest',
  UPDATESSOPROVIDERRESPONSE: 'UpdateSsoProviderResponse',
  DELETESSOPROVIDERREQUEST: 'DeleteSsoProviderRequest',
  DELETESSOPROVIDERRESPONSE: 'DeleteSsoProviderResponse',
  ENABLEAUTHREQUEST: 'EnableAuthRequest',
  ENABLEAUTHRESPONSE: 'EnableAuthResponse',
  DISABLEAUTHREQUEST: 'DisableAuthRequest',
  DISABLEAUTHRESPONSE: 'DisableAuthResponse',
  SSOINITIATEREQUEST: 'SsoInitiateRequest',
  SSOINITIATERESPONSE: 'SsoInitiateResponse',
  SSOCALLBACKREQUEST: 'SsoCallbackRequest',
  SSOCALLBACKRESPONSE: 'SsoCallbackResponse',
} as const;

/** Message type union */
export type MessageType = typeof MessageTypes[keyof typeof MessageTypes];



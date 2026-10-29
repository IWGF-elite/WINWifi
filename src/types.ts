export type FrequencyBand = '2.4 GHz' | '5 GHz' | '6 GHz';

export type SecurityType = 
  | 'Open' 
  | 'WEP-64/128' 
  | 'WPA-Personal (TKIP)' 
  | 'WPA2-Personal (AES)' 
  | 'WPA2-Enterprise (802.1X)' 
  | 'WPA3-Personal (SAE)' 
  | 'WPA3-Enterprise' 
  | 'OWE (Enhanced Open)';

export type CipherType = 'None' | 'WEP' | 'TKIP' | 'CCMP (AES)' | 'GCMP-256';

export type UIMode = 'beginner' | 'expert';

export type AssetClassification = 
  | 'Trusted' 
  | 'Corporate' 
  | 'Guest' 
  | 'IoT' 
  | 'Unknown' 
  | 'Suspicious' 
  | 'Rogue' 
  | 'Investigating';

export type AnalystClassification = 'Trusted' | 'False Positive' | 'Confirmed Rogue';

export type EnterpriseAssetType = 'Access Point' | 'Client Station' | 'IoT Gateway' | 'Sensor' | 'Other';
export type EnterpriseAssetClassification = 'Corporate' | 'Guest' | 'IoT' | 'Unknown' | 'Suspicious' | 'Rogue';
export type EnterpriseAssetApprovalStatus = 'Approved' | 'Unapproved' | 'Under Investigation' | 'Decommissioned' | 'Pending Review';

/** Authoritative per-project registry record, keyed by canonical MAC address. */
export interface EnterpriseAssetRecord {
  id: string;
  macAddress: string;
  ssid: string;
  assetType: EnterpriseAssetType;
  classification: EnterpriseAssetClassification;
  approvalStatus: EnterpriseAssetApprovalStatus;
  site: string;
  building: string;
  areaFloor: string;
  ownerDepartment: string;
  vendor: string;
  model: string;
  lastSeen: string;
  notes: string;
}

export interface WifiAdapter {
  id: string;
  name: string;
  description: string;
  macAddress: string;
  vendor: string;
  chipset: string;
  driverVersion: string;
  supportedBands: FrequencyBand[];
  monitorModeSupported: boolean;
  packetInjectionSupported: boolean;
  currentChannel: number;
  isChannelHopping: boolean;
  txPowerDbm: number;
  status: 'Ready' | 'Scanning' | 'Capturing' | 'Disabled';
  wlanApiStatus?: 'Connected' | 'Available' | 'Unavailable';
  npcapStatus?: 'Installed' | 'Not Installed' | 'Unknown';
}

export interface LocalNetworkInfo {
  adapterId: string;
  interfaceName: string;
  networkId: string;
  localIp: string;
  prefixLength: number;
  gatewayIp: string;
  dnsServers: string[];
  dhcpServers?: string[];
  status: 'Available' | 'Unavailable';
  reason: string;
  scannedAt?: string;
  portScanMode?: string;
  portsScanned?: number;
  cancelled?: boolean;
  devices?: LanDeviceRecord[];
}

export interface NetworkDoctorFinding {
  name: string;
  status: 'PASS' | 'WARN' | 'ALERT' | 'INFO';
  evidence: string;
}

export interface NetworkDoctorCheck {
  status: 'Complete' | 'Partial' | 'Unavailable';
  reason: string;
  checkedAt: string;
  adapterId: string;
  ssid: string;
  bssid: string;
  signal: string;
  signalDbm?: number | null;
  channel?: number | null;
  band: string;
  security: string;
  cipher: string;
  gatewayIp: string;
  gatewayMac: string;
  dnsServers: string[];
  gatewayMedianMs?: number | null;
  gatewayPacketLossPercent?: number | null;
  dnsLookupMs?: number | null;
  authorizedNeighborCount: number;
  observedAuthorizedChannels: number[];
  recommendedObservedChannel?: number | null;
  fingerprintVerdict: 'first-seen' | 'matches' | 'changed' | 'unavailable';
  fingerprintDifferences: string[];
  safeChecks: NetworkDoctorFinding[];
  conclusion: string;
  recommendation: string;
}

export interface NetworkTimelineBounds {
  hasData: boolean;
  earliestAt?: string | null;
  latestAt?: string | null;
  changeCount: number;
  legacyObservationCount: number;
  message: string;
}

export interface NetworkTimelineEntityState {
  entityType: 'AP' | 'DEVICE';
  entityKey: string;
  bssid?: string;
  ssid?: string;
  channel?: number | null;
  band?: string;
  frequencyMhz?: number | null;
  rssi?: number | null;
  signalQuality?: number | null;
  security?: string;
  cipher?: string;
  vendor?: string;
  channelWidth?: number | null;
  ipAddress?: string;
  macAddress?: string;
  hostname?: string;
  deviceType?: string;
  isOnline: boolean;
  isPresent: boolean;
  firstSeenAt?: string;
  lastSeenAt?: string;
}

export interface NetworkTimelineEvent {
  id: string;
  projectId: string;
  occurredAt: string;
  entityType: 'AP' | 'DEVICE';
  entityKey: string;
  eventType: string;
  summary: string;
  beforeStateJson: string;
  afterStateJson: string;
}

export interface NetworkTimelineState {
  hasData: boolean;
  asOf: string;
  source: string;
  message: string;
  accessPoints: NetworkTimelineEntityState[];
  devices: NetworkTimelineEntityState[];
  changes: NetworkTimelineEvent[];
}

export interface LocalConnectionRecord {
  protocol: 'TCP' | 'UDP' | string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  processId: number;
  processName: string;
}

export interface LocalNetworkActivity {
  status: 'Available' | 'Unavailable';
  reason: string;
  observedAt: string;
  trafficBytesStatus: string;
  connections: LocalConnectionRecord[];
}

export interface LanOpenPort {
  port: number;
  protocol: string;
  service: string;
  riskFlag: boolean;
  riskReason: string;
  banner: string;
}

export interface LanDeviceRecord {
  networkId: string;
  ipAddress: string;
  macAddress: string;
  vendor: string;
  hostname: string;
  deviceType: string;
  evidence: string[];
  openPorts: LanOpenPort[];
  isOnline: boolean;
  isNew: boolean;
  isKnown: boolean;
  isRandomizedMac: boolean;
  pingTtl?: number;
  osGuess: string;
  firstSeen: string;
  lastSeen: string;
}

export interface ClientDevice {
  macAddress: string;
  vendor: string;
  apBssid: string;
  connectedSsid?: string;
  rssi: number;
  packetsSent: number;
  dataRateMbps: number;
  lastSeen: string;
  firstSeen?: string;
  probes: string[];
  ipAssigned?: string;
  isAssociated?: boolean;
  eapolPacketsObserved?: number;
}

export type CapabilityStatus = 
  | 'Supported'
  | 'Available'
  | 'Unavailable'
  | 'Driver Required'
  | 'Hardware Required'
  | 'Not Exposed by Windows'
  | 'Not Verified';

export type CapabilityCategory = 
  | 'Radio & Spectrum'
  | 'Discovery & Ingestion'
  | 'Client Station Tracking'
  | 'Cryptographic & Forensics'
  | 'Compliance & Threat Intelligence'
  | 'Active Network Interaction';

export interface HardwareCapability {
  id: string;
  name: string;
  category: CapabilityCategory;
  status: CapabilityStatus;
  technicalDetails: string;
  windowsRestriction?: string;
  prerequisite?: string;
  dataOriginMapping?: 'LIVE_WINDOWS' | 'IMPORTED' | 'TRAINING' | 'EXTERNAL_TOOL';
  mitigationOrTool?: string;
}

export interface HandshakeInfo {
  apBssid: string;
  clientMac: string;
  ssid: string;
  type: 'WPA2 4-Way (EAPOL)' | 'WPA3 SAE (Commit/Confirm)' | 'PMKID EAPOL-M1';
  capturedSteps: ('M1' | 'M2' | 'M3' | 'M4')[];
  isComplete: boolean;
  replayCounterMatch: boolean;
  micVerified: boolean;
  capturedAt: string;
  anonce: string;
  snonce: string;
  micHex: string;
  eapolFrameHex?: string;
  hashcatFormat?: string;
  qualityScore?: number; // 0-100
  validationStatus?: 'VALID' | 'INCOMPLETE' | 'DUPLICATE' | 'MALFORMED' | 'SUSPICIOUS' | 'Valid' | 'Suspect' | 'Corrupt' | 'Incomplete';
  evidenceId?: string;
  origin?: DataOrigin;
  isSimulated?: boolean;
}

export interface SecurityIssue {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  recommendation: string;
  nistRef?: string;
  plainEnglishExplanation?: string;
}

export interface RiskFactor { name: string; points: number; evidence: string; }

export interface AccessPoint {
  bssid: string;
  ssid: string;
  rssi: number; // e.g. -45 dBm
  channel: number;
  band: FrequencyBand;
  channelWidthMhz: 20 | 40 | 80 | 160;
  security: SecurityType;
  cipher: CipherType;
  wpsEnabled: boolean;
  wpsLocked: boolean;
  wpsVersion?: string;
  pmfRequired: boolean; // Protected Management Frames (802.11w)
  pmfCapable?: boolean;
  pmfInformationAvailable?: boolean;
  vendor: string;
  oui?: string;
  beaconCount: number;
  dataPacketCount: number;
  firstSeen: string;
  lastSeen: string;
  lastSeenTime?: string;
  isActiveInCurrentScan?: boolean;
  disappearedScanCycles?: number;
  standard: '802.11b/g' | '802.11n (Wi-Fi 4)' | '802.11ac (Wi-Fi 5)' | '802.11ax (Wi-Fi 6)' | '802.11be (Wi-Fi 7)';
  clients: ClientDevice[];
  handshake?: HandshakeInfo;
  securityScore: number; // 0 (terrible) to 100 (excellent)
  riskScore?: number;
  riskFactors?: RiskFactor[];
  issues: SecurityIssue[];
  isRogueCandidate?: boolean;
  rogueConfidence?: number; // 0-100%
  rogueEvidence?: string[];
  
  // Asset Management Fields
  classification?: AssetClassification;
  ownership?: string;
  site?: string;
  building?: string;
  floor?: string;
  notes?: string;
  tags?: string[];
  approvedStatus?: 'Approved' | 'Unapproved' | 'Investigating' | 'Pending Review';
  historicalObservationsCount?: number;
  previousSecurity?: SecurityType;
  previousChannel?: number;
  dataSourceOrigin?: DataOrigin;
}

export interface PcapPacket {
  id: number;
  timestamp: string;
  frameNumber: number;
  frameType: string;
  subtype?: string;
  typeNumber?: number;
  subtypeNumber?: number;
  sourceMac: string;
  destMac: string;
  bssid: string;
  transmitterMac?: string;
  receiverMac?: string;
  channel: number;
  rssi: number;
  lengthBytes: number;
  radiotapPresent?: boolean;
  sequenceNumber?: number;
  fragmentNumber?: number;
  isRetry?: boolean;
  isProtected?: boolean;
  info: string;
  hexPreview: string;
  rawBytesHex?: string;
  rawBytesAscii?: string;
  expertInfo?: string;
  informationElements?: Record<string, string>;
  eapolFields?: Record<string, string>;
  networkProtocol?: string;
  applicationProtocol?: string;
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  conversationId?: string;
  tcpStreamId?: string;
  tcpSequenceNumber?: number;
  tcpAcknowledgmentNumber?: number;
  tcpFlags?: string;
  tcpPayloadHex?: string;
  networkFields?: Record<string, string>;
  isBookmarked?: boolean;
  evidenceId?: string;
  note?: string;
}

export interface SecurityChange {
  id: string;
  bssid: string;
  ssid: string;
  timestamp: string;
  type: 
    | 'security_downgrade' 
    | 'security_upgrade' 
    | 'new_bssid' 
    | 'bssid_disappeared' 
    | 'channel_change' 
    | 'vendor_change' 
    | 'pmf_change' 
    | 'wps_change'
    // Values actually published by the native analyzer's drift detector
    // (WinWiFi.Desktop/Services/SecurityAnalyzer.cs). Without these the live
    // payload was typed as impossible and readers switched on the wrong words.
    | 'pmf_disabled'
    | 'wps_enabled'
    | 'channel_shift'
    | 'bssid_drift'
    | 'vendor_mismatch';
  title: string;
  before: string;
  after: string;
  riskImpact: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  evidenceId?: string;
  evidenceIds?: string[];
}

export interface IncidentRecord {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number; // 0-100%
  status: 'Open' | 'Investigating' | 'Confirmed' | 'False Positive' | 'Resolved';
  createdAt: string;
  updatedAt: string;
  assignedTo: string;
  summary: string;
  bssidTarget?: string;
  ssidTarget?: string;
  evidenceIds: string[];
  notes: { timestamp: string; author: string; text: string }[];
  resolution?: string;
}

export interface EvidenceItem {
  id: string;
  timestamp: string;
  type: 'packet' | 'observation' | 'timeline' | 'pcap' | 'note' | 'handshake';
  title: string;
  source: string;
  checksum?: string;
  description: string;
  rawData?: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  epochMs: number;
  category: 'appearance' | 'disappearance' | 'security_change' | 'rogue_alert' | 'frame_traffic' | 'incident' | 'analyst_action';
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  bssid?: string;
  ssid?: string;
  evidenceId?: string;
}

export interface SecurityPolicyRule {
  id: string;
  name: string;
  description: string;
  requirement: string;
  evaluate: (ap: AccessPoint) => { passed: boolean; message: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' };
}

export interface SecurityPolicy {
  id: string;
  name: 'Corporate Policy' | 'Guest Policy' | 'IoT Policy' | 'High Security Policy' | 'Custom Policy';
  description: string;
  minSecurity: SecurityType;
  wpa3Required: boolean;
  pmfRequired: boolean;
  wpsProhibited: boolean;
  tkipProhibited: boolean;
  wepProhibited: boolean;
  openProhibited: boolean;
  maxSignalDbm?: number;
}

export interface PolicyEvaluationResult {
  apBssid: string;
  policyId: string;
  policyName: string;
  status: 'Compliant' | 'Warning' | 'Non-Compliant' | 'Unknown';
  classification?: AssetClassification;
  approvalStatus?: AccessPoint['approvedStatus'];
  failedRules: string[];
  passedRules: string[];
}

export interface SiteFloorRecord {
  id: string;
  name: string;
}

export interface SiteBuildingRecord {
  id: string;
  name: string;
  floors: SiteFloorRecord[];
}

export interface SiteRecord {
  id: string;
  name: string;
  buildings: SiteBuildingRecord[];
}

export interface EnterpriseScope {
  organization: string;
  site: string;
  building: string;
  area: string;
  assessmentId: string;
}

export type MaintenanceAction = 'Connect to network';
export type MaintenanceApprovalStatus = 'Pending' | 'Approved' | 'Rejected' | 'Expired' | 'Revoked';

export interface MaintenanceApprovalRecord {
  id: string;
  action: MaintenanceAction;
  bssid: string;
  ssid: string;
  adapterId: string;
  requester: string;
  approver: string;
  justification: string;
  requestedAt: string;
  approvedAt?: string;
  expiresAt: string;
  status: MaintenanceApprovalStatus;
  decidedAt?: string;
  decisionNote?: string;
  lastUsedAt?: string;
}

export interface MaintenanceRequestInput {
  action: MaintenanceAction;
  bssid: string;
  ssid: string;
  adapterId?: string;
  requester: string;
  justification: string;
  durationMinutes: number;
}

export interface AuditProject {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  location: string;
  auditorName: string;
  notes: string;
  targetBssid?: string;
  savedNetworksCount: number;
  capturedHandshakesCount: number;
  scope?: EnterpriseScope;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  occurredAt?: string;
  level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS' | 'SEC_ALERT';
  source: string;
  message: string;
}

export type ActiveTab = 
  | 'dashboard'
  | 'doctor'
  | 'time-machine'
  | 'discover'
  | 'discovery'
  | 'networks'
  | 'clients'
  | 'rf'
  | 'spectrum'
  | 'forensics'
  | 'packets'
  | 'threats'
  | 'alerts'
  | 'investigations'
  | 'handshakes'
  | 'projects'
  | 'database'
  | 'reports'
  | 'devices'
  | 'settings'
  | 'native-desktop';

export type DataOrigin = 'LIVE_WINDOWS' | 'OFFLINE' | 'IMPORTED' | 'TRAINING';

export type DataSourceProfile = 
  | 'LIVE_WINDOWS' 
  | 'OFFLINE' 
  | 'IMPORTED' 
  | 'REAL_PCAP' 
  | 'REAL_NETSH';

export type BridgeConnectionState = 'CONNECTED' | 'CONNECTING' | 'DISCONNECTED' | 'ERROR';

export interface BridgeConfig {
  baseUrl: string;
  allowRemote: boolean;
  pollIntervalMs: number;
  timeoutMs: number;
  autoReconnect: boolean;
}

export interface BridgeHealthStatus {
  status: string;
  version: string;
  engine: string;
  platform: string;
  isWindows: boolean;
  isNativeWlanAvailable: boolean;
  activeAdapterId?: string;
  activeAdapterName?: string;
  isScanning?: boolean;
  backgroundScanIntervalSeconds?: number;
  scanCyclesCompleted: number;
  accessPointsCount: number;
  incidentsCount: number;
  timestampUtc: string;
  capabilities?: {
    nativeWlanAvailable: boolean;
    nativeWlanReason: string;
    sqliteAvailable: boolean;
    sqliteReason: string;
    eapolParserAvailable: boolean;
    eapolParserReason: string;
    npcapInstalled: boolean;
    monitorModeSupported: boolean;
    monitorModeReason: string;
    captureDevice?: string;
  };
}

export interface BridgeScanStatus {
  isScanning: boolean;
  state: string;
  activeAdapterId?: string;
  scanCyclesCompleted: number;
  lastDiscoveredCount: number;
  diagnostics?: any;
}

export interface BridgeDiagnostics {
  lastScanDurationMs: number;
  lastDiscoveredBssCount: number;
  totalScanCycles: number;
  totalAdaptersDetected: number;
  telemetryState: string;
  isPInvokeActive: boolean;
  isNetshFallbackActive: boolean;
  lastErrorMessage?: string;
}

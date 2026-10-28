import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { PcapService } from '../src/services/pcapParser';
import { WifiEngine, isWebView2Host } from '../src/services/wifiEngine';
import { CapabilityMatrixService } from '../src/services/capabilityMatrix';
import { SqliteDatabaseService } from '../src/services/storage';
import { ThreatEngine } from '../src/services/threatEngine';
import { NativeBridgeClient } from '../src/services/bridgeClient';
import { PolicyEngine } from '../src/services/policyEngine';
import {
  mapNativeFindingsToIncidents,
  reconcileLiveIncidents,
  stableIncidentId,
  countOpenIncidents
} from '../src/services/incidentMapper';
import { mapStationClients } from '../src/services/stationClientMapper';
import {
  applyAssetsToAccessPoints,
  mergeAssetLists,
  mergeMissingFields,
  normalizeAsset,
  normalizeMac,
  parseAssetCsv,
  serializeAssetCsv
} from '../src/services/assetRegistry';
import {
  addBuilding,
  addFloor,
  addSite,
  countAssetsAtSite,
  countAssetsInBuilding,
  countAssetsOnFloor,
  deleteBuilding,
  deleteFloor,
  deleteSite,
  ensureScopeInDirectory,
  listBuildingNames,
  listFloorNames,
  listSiteNames,
  normalizeSiteDirectory,
  renameBuilding,
  renameBuildingInAssets,
  renameFloor,
  renameFloorInAssets,
  renameSite,
  renameSiteInAssets,
  sanitizeSiteName
} from '../src/services/siteDirectory';
import {
  approveMaintenance,
  countActiveApprovals,
  createMaintenanceRequest,
  findActiveApproval,
  getApprovalsForBssid,
  markApprovalUsed,
  normalizeMaintenanceApprovals,
  rejectMaintenance,
  revokeMaintenance,
  sanitizeMaintenanceText
} from '../src/services/maintenanceApproval';
import {
  MAX_AUDIT_RECORDS,
  appendAuditRecord,
  createAuditChain,
  genesisHash,
  headHashOf,
  normalizeAuditChain,
  resetAuditChain,
  sha256Hex,
  verifyAuditChain
} from '../src/services/auditChain';
import {
  can,
  normalizeOperatorRole,
  requireCapability,
  sanitizeOperatorName
} from '../src/services/operatorRoles';
import {
  MAX_ALERTS,
  acknowledgeAlert,
  evaluateAlerts,
  normalizeAlerts,
  reconcileAlerts,
  summarizeAlerts
} from '../src/services/alerts';
import { bridgeStatusView, classifyBridgeError, isEmbeddedDashboard, resolveBridgeBaseUrl } from '../src/services/bridgeStatus';
import {
  FIXTURE_ACCESS_POINTS,
  buildBeaconFrame,
  buildDataFrame,
  buildEapolFrame,
  buildRadiotapPcap
} from './fixtures';
import { NATIVE_TABLES, MAX_VIEW_ROWS, toNativeTableView } from '../src/services/nativeDatabaseView';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('========================================');
console.log(' WINWIFI AUTOMATED VERIFICATION SUITE   ');
console.log('========================================\n');

let passedCount = 0;
let totalCount = 0;

function runTest(name: string, fn: () => void) {
  totalCount++;
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passedCount++;
  } catch (err: any) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    process.exitCode = 1;
  }
}

// 1. Engine & Environment Sandbox
runTest('T1: System Capabilities & Detection', () => {
  const engine = WifiEngine.getInstance();
  const caps = engine.getSystemCapabilities();
  if (!caps.environment || !caps.pcapDissectorActive) {
    throw new Error('Capabilities incomplete');
  }
});

// 2. Binary PCAP Dissection
runTest('T2: Libpcap 2.4 Binary Dissection & Framing', () => {
  const pcap = PcapService.getInstance();
  const channels = [1, 6, 11, 36, 44];
  const frames = channels.map((channel, index) => buildBeaconFrame({
    bssid: `02:00:00:00:00:${String(index + 1).padStart(2, '0')}`,
    ssid: `T2 Fixture ${channel}`,
    channel,
    akmSuiteType: 2
  }));

  const parsed = pcap.parseBinaryPcap(buildRadiotapPcap(frames));
  if (parsed.packets.length !== frames.length) {
    throw new Error(`Expected ${frames.length} packets, got ${parsed.packets.length}`);
  }
  if (!parsed.summary || parsed.summary.totalPackets !== frames.length) {
    throw new Error('Summary mismatch');
  }
  if (parsed.accessPoints.length !== channels.length) {
    throw new Error(`Expected ${channels.length} BSS entries, got ${parsed.accessPoints.length}`);
  }
  const decodedChannels = parsed.accessPoints.map(ap => ap.channel).sort((a, b) => a - b);
  if (decodedChannels.join(',') !== channels.join(',')) {
    throw new Error(`DS-set channel decoding failed: ${decodedChannels.join(',')}`);
  }
  for (const ap of parsed.accessPoints) {
    if (ap.security !== 'WPA2-Personal (AES)' || ap.cipher !== 'CCMP (AES)') {
      throw new Error(`RSN IE decoding failed for ${ap.ssid}: ${ap.security}/${ap.cipher}`);
    }
  }
});

// 3. Frequency & Channel Math across 2.4 / 5 / 6 GHz
runTest('T3: RF Spectrum Math (2.4, 5, 6 GHz)', () => {
  const ch6 = PcapService.getChannelDetails(6);
  const ch14 = PcapService.getChannelDetails(14);
  const ch36 = PcapService.getChannelDetails(36);
  const ch149 = PcapService.getChannelDetails(149);
  const ch69 = PcapService.getChannelDetails(69);

  if (ch6.freqMhz !== 2437 || ch6.band !== '2.4 GHz') throw new Error('CH6 2.4GHz failed');
  if (ch14.freqMhz !== 2484 || ch14.band !== '2.4 GHz') throw new Error('CH14 2.4GHz failed');
  if (ch36.freqMhz !== 5180 || ch36.band !== '5 GHz') throw new Error('CH36 5GHz failed');
  if (ch149.freqMhz !== 5745 || ch149.band !== '5 GHz') throw new Error('CH149 5GHz failed');
  if (ch69.freqMhz !== 6295 || ch69.band !== '6 GHz') throw new Error('CH69 6GHz failed');
});

// 4. EAPOL 4-Way Handshake reconstruction from capture bytes
runTest('T4: EAPOL Metadata & Hashcat 22000 Structure From Frame Bytes', () => {
  const pcap = PcapService.getInstance();
  const apBssid = '02:00:00:00:00:0A';
  const clientMac = '02:00:00:00:00:0B';
  const toHex = (bytes: number[]) => bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  const anonce = Array.from({ length: 32 }, (_, i) => 0xA1 + (i % 16));
  const snonce = Array.from({ length: 32 }, (_, i) => 0x1B + (i % 16));
  const mic = Array.from({ length: 16 }, (_, i) => 0xF0 - i);

  const frames = [
    buildBeaconFrame({ bssid: apBssid, ssid: 'T4 Fixture Net', channel: 44, akmSuiteType: 1 }),
    buildEapolFrame({ apBssid, clientMac, step: 'M1', nonce: anonce, mic: new Array(16).fill(0), replayCounter: 1 }),
    buildEapolFrame({ apBssid, clientMac, step: 'M2', nonce: snonce, mic, replayCounter: 2 })
  ];

  const parsed = pcap.parseBinaryPcap(buildRadiotapPcap(frames));
  const handshake = parsed.handshakes[0];
  if (!handshake) throw new Error('No EAPOL handshake reconstructed from the fixture capture');
  if (handshake.apBssid !== apBssid || handshake.clientMac !== clientMac) {
    throw new Error(`Wrong MAC attribution: ${handshake.apBssid}/${handshake.clientMac}`);
  }
  if (handshake.ssid !== 'T4 Fixture Net') {
    throw new Error(`Handshake SSID was not taken from the beacon: ${handshake.ssid}`);
  }
  if (!handshake.isComplete || handshake.capturedSteps.length !== 2) {
    throw new Error(`Incomplete M-step tracking: ${handshake.capturedSteps.join(',')}`);
  }
  if (handshake.anonce !== toHex(anonce).toUpperCase() || handshake.snonce !== toHex(snonce).toUpperCase()) {
    throw new Error('Nonce bytes were mis-attributed between M1 and M2');
  }
  if (handshake.micHex !== toHex(mic).toUpperCase() || !handshake.micVerified) {
    throw new Error('M2 MIC was not recovered from the frame');
  }

  // The 22000 line is assembled only from bytes present in the capture.
  const line = handshake.hashcatFormat;
  if (!line?.startsWith('WPA*02*')) {
    throw new Error(`Missing 22000 line despite a complete M1/M2 pair: ${line ?? '(none)'}`);
  }
  const fields = line.split('*');
  if (fields.length !== 9) throw new Error(`Expected 8 delimited hash fields, got ${fields.length - 1}`);
  if (fields[2] !== toHex(mic).toLowerCase()) throw new Error('Hash MIC does not match the captured M2');
  if (fields[3] !== apBssid.replace(/:/g, '').toLowerCase()) throw new Error('Hash BSSID field wrong');
  if (fields[4] !== clientMac.replace(/:/g, '').toLowerCase()) throw new Error('Hash client field wrong');
  if (fields[6] !== toHex(anonce).toLowerCase()) throw new Error('Hash ANonce does not match the captured M1');
  if (!fields[7] || fields[7].length < 198) throw new Error('Hash EAPOL field is not the raw M2 payload');
});

// 5. Windows netsh Stream Parser
runTest('T5: Windows netsh wlan CLI Stream Parser', () => {
  const pcap = PcapService.getInstance();
  const sampleNetsh = `Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : Test_Netsh_Corp
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 82%
         Radio type         : 802.11ac
         Channel            : 44

SSID 2 : Open_Public
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : AA:BB:CC:DD:EE:FF
         Signal             : 60%
         Radio type         : 802.11n
         Channel            : 1`;

  const parsed = pcap.parseNetshOutput(sampleNetsh);
  if (parsed.accessPoints.length !== 2) {
    throw new Error(`Expected 2 APs, got ${parsed.accessPoints.length}`);
  }
  if (parsed.accessPoints[0].channel !== 44 || parsed.accessPoints[0].ssid !== 'Test_Netsh_Corp') {
    throw new Error('AP[0] data parsing error');
  }
});

// 6. Read-only view over the native SQLite database
runTest('T6: Native Database Table View & Bridge Read Wiring', () => {
  const records = [
    { bssid: 'AA:11:00:00:00:01', ssid: 'Fixture WPA3 Enterprise', channel: 36, pmfRequired: true, clients: [{ macAddress: 'AA:11:00:00:00:02' }], note: null },
    { bssid: 'AA:11:00:00:00:07', ssid: 'Fixture Open', channel: 11, pmfRequired: false, wpsEnabled: true, clients: [] }
  ];

  const view = toNativeTableView(records);
  if (view.rowCount !== 2 || view.truncated) throw new Error(`Row accounting wrong: ${view.rowCount}/${view.truncated}`);
  if (view.columns[0] !== 'bssid' || !view.columns.includes('wpsEnabled')) {
    throw new Error(`Column union incomplete: ${view.columns.join(',')}`);
  }
  if (view.rows.length !== 2 || view.rows[0].length !== view.columns.length) {
    throw new Error('Row width does not match the column set');
  }
  const cell = (row: number, column: string) => view.rows[row][view.columns.indexOf(column)];
  if (cell(0, 'pmfRequired') !== '1' || cell(1, 'pmfRequired') !== '0') throw new Error('Boolean cells are not SQL-shaped');
  if (cell(0, 'note') !== 'NULL') throw new Error('Null column not rendered as NULL');
  if (cell(1, 'wpsEnabled') !== '1') throw new Error(`Present boolean not rendered: ${cell(1, 'wpsEnabled')}`);
  if (cell(0, 'wpsEnabled') !== 'NULL') throw new Error(`Absent column rendered as ${cell(0, 'wpsEnabled')}`);
  if (cell(0, 'clients') !== '[{\"macAddress\":\"AA:11:00:00:00:02\"}]') {
    throw new Error(`Nested rows are not serialised: ${cell(0, 'clients')}`);
  }

  const capped = toNativeTableView(Array.from({ length: 250 }, (_, index) => ({ id: index })));
  if (capped.rows.length !== MAX_VIEW_ROWS || !capped.truncated || capped.rowCount !== 250) {
    throw new Error(`Row cap not enforced: ${capped.rows.length}/${capped.truncated}`);
  }
  if (toNativeTableView([]).columns.length !== 0) throw new Error('Empty result set reported columns');

  if (NATIVE_TABLES.length !== 7) throw new Error(`Expected 7 native tables, declared ${NATIVE_TABLES.length}`);
  if (NATIVE_TABLES.some(table => typeof table.load !== 'function')) {
    throw new Error('A declared table has no read path');
  }
});

// 7. NIST SP 800-153 posture heuristics on decoded beacons
runTest('T7: NIST SP 800-153 Risk Scoring & Penalty Heuristics', () => {
  const pcap = PcapService.getInstance();
  const frames = [
    buildBeaconFrame({ bssid: '02:00:00:00:00:21', ssid: 'T7 Open', channel: 6 }),
    buildBeaconFrame({ bssid: '02:00:00:00:00:22', ssid: 'T7 WEP', channel: 1, wpsEnabled: true }),
    buildBeaconFrame({ bssid: '02:00:00:00:00:23', ssid: 'T7 WPA2', channel: 11, akmSuiteType: 2 }),
    buildBeaconFrame({ bssid: '02:00:00:00:00:24', ssid: 'T7 WPA3', channel: 36, akmSuiteType: 8, pmfRequired: true })
  ];
  const parsed = pcap.parseBinaryPcap(buildRadiotapPcap(frames));
  const bySsid = new Map(parsed.accessPoints.map(ap => [ap.ssid, ap]));

  const open = bySsid.get('T7 Open');
  if (!open || open.security !== 'Open') throw new Error('Open beacon was not decoded from the capability bits');
  if (!open.issues.some(issue => issue.id === 'ISS-OPEN')) throw new Error('Missing cleartext finding on the Open network');
  if (open.securityScore > 40) throw new Error(`Open network scored too high: ${open.securityScore}`);

  const wep = bySsid.get('T7 WEP');
  if (!wep || !wep.security.includes('WEP')) throw new Error('WEP beacon was not decoded');
  if (!wep.issues.some(issue => issue.id === 'ISS-WEP' && issue.severity === 'CRITICAL')) {
    throw new Error('WEP is not reported as a critical cipher');
  }
  if (!wep.wpsEnabled || !wep.issues.some(issue => issue.id === 'ISS-WPS')) {
    throw new Error('WPS element was not decoded on the legacy network');
  }
  if (wep.securityScore > 10) throw new Error(`WEP + WPS scored too high: ${wep.securityScore}`);

  const wpa2 = bySsid.get('T7 WPA2');
  if (!wpa2 || wpa2.security !== 'WPA2-Personal (AES)') throw new Error('RSN element was not decoded');
  if (!wpa2.issues.some(issue => issue.id === 'ISS-PMF')) throw new Error('Missing PMF finding when 802.11w is optional');

  const wpa3 = bySsid.get('T7 WPA3');
  if (!wpa3 || !wpa3.security.includes('WPA3') || !wpa3.pmfRequired) {
    throw new Error(`WPA3/PMF beacon decoding failed: ${wpa3?.security}/${wpa3?.pmfRequired}`);
  }
  if (wpa3.securityScore !== 100 || wpa3.issues.length !== 0) {
    throw new Error(`A hardened network should score 100 with no findings, got ${wpa3.securityScore}/${wpa3.issues.length}`);
  }
});

// 8. Deterministic Rogue/Evil Twin Heuristic Tests
runTest('T8: Deterministic Evil Twin & Roaming Validation', () => {
  const threatEngine = ThreatEngine.getInstance();

  // Case A: Legitimate campus roaming APs (Matching SSID, Matching Vendor, Matching WPA2-Enterprise)
  const legitRoamingAps = [
    {
      bssid: '00:00:0C:01:02:01',
      ssid: 'Campus-Secure',
      security: 'WPA2-Enterprise',
      cipher: 'CCMP',
      vendor: 'Cisco Systems',
      securityScore: 85,
      band: '2.4 GHz',
      channel: 1,
      rssi: -65,
      history: []
    },
    {
      bssid: '00:00:0C:01:02:02',
      ssid: 'Campus-Secure',
      security: 'WPA2-Enterprise',
      cipher: 'CCMP',
      vendor: 'Cisco Systems',
      securityScore: 85,
      band: '5 GHz',
      channel: 36,
      rssi: -70,
      history: []
    }
  ];
  const roamResult = threatEngine.analyzeThreats(legitRoamingAps as any);
  if (roamResult.rogues.length > 0) {
    throw new Error(`False positive on legitimate roaming APs: ${roamResult.rogues[0].bssid}`);
  }

  // Case B: Evil Twin Downgrade Clone (Matching SSID, different security)
  const evilTwinAps = [
    {
      bssid: '00:00:0C:01:02:01',
      ssid: 'Campus-Secure',
      security: 'WPA2-Enterprise',
      cipher: 'CCMP',
      vendor: 'Cisco Systems',
      securityScore: 85,
      band: '2.4 GHz',
      channel: 1,
      rssi: -65,
      history: []
    },
    {
      bssid: 'AA:BB:CC:DD:EE:99',
      ssid: 'Campus-Secure',
      security: 'Open',
      cipher: 'None',
      vendor: 'Unknown',
      securityScore: 35,
      band: '2.4 GHz',
      channel: 1,
      rssi: -50,
      history: []
    }
  ];
  const evilResult = threatEngine.analyzeThreats(evilTwinAps as any);
  if (evilResult.rogues.length === 0 || evilResult.rogues[0].bssid !== 'AA:BB:CC:DD:EE:99') {
    throw new Error('Failed to flag Open Evil Twin clone of Campus-Secure');
  }
});

// 9. Station observation decoded from associated data frames
runTest('T9: Station Observer & Association State Mapping', () => {
  const pcap = PcapService.getInstance();
  const apBssid = '02:00:00:00:00:31';
  const clientMac = '02:00:00:00:00:32';
  const frames = [
    buildBeaconFrame({ bssid: apBssid, ssid: 'T9 Fixture Net', channel: 36, akmSuiteType: 2 }),
    buildDataFrame({ apBssid, clientMac }),
    buildDataFrame({ apBssid, clientMac })
  ];
  const parsed = pcap.parseBinaryPcap(buildRadiotapPcap(frames));
  const ap = parsed.accessPoints.find(entry => entry.bssid === apBssid);
  if (!ap) throw new Error('Beacon did not register the access point before station traffic');
  if (ap.clients.length !== 1) throw new Error(`Expected 1 associated station, got ${ap.clients.length}`);
  const client = ap.clients[0];
  if (client.macAddress !== clientMac || client.apBssid !== apBssid) {
    throw new Error(`Station mapping wrong: ${client.macAddress} on ${client.apBssid}`);
  }
  if (client.packetsSent !== 2) throw new Error(`Frame counting drift: packetsSent=${client.packetsSent}`);
  if (typeof client.rssi !== 'number' || client.rssi > 0) throw new Error(`Invalid client RSSI: ${client.rssi}`);
  if (typeof client.vendor !== 'string' || client.vendor.length === 0) {
    throw new Error('Vendor resolution returned no label for the observed station');
  }
});

// 10. Offline Self-Contained Verification (Zero external calls)
runTest('T10: Offline Architecture Integrity', () => {
  const srcFiles = ['wifiEngine.ts', 'pcapParser.ts', 'threatEngine.ts', 'storage.ts', 'policyEngine.ts'];
  for (const file of srcFiles) {
    const content = fs.readFileSync(path.join(__dirname, '../src/services', file), 'utf8');
    if (content.includes('fetch(') || content.includes('http://') || content.includes('https://api.')) {
      throw new Error(`External network call detected in offline service: ${file}`);
    }
  }
});

// 11. Incident Lifecycle State Transitions
runTest('T11: Incident Center Lifecycle Transitions', () => {
  const threatEngine = ThreatEngine.getInstance();
  threatEngine.setIncidents([]);
  if (threatEngine.getIncidents().length !== 0) throw new Error('Threat engine populated incidents without observed data');
  const inc = threatEngine.createIncident({
    title: 'Test incident', severity: 'LOW', confidence: 50, summary: 'Created by lifecycle test'
  });
  threatEngine.updateIncidentStatus(inc.id, 'Investigating', 'Verification tester note');
  const updated = threatEngine.getIncidents().find((i: any) => i.id === inc.id);
  if (!updated) throw new Error('Incident disappeared after lifecycle update');
  if (updated.status !== 'Investigating' || updated.notes.length === 0) {
    throw new Error('Incident lifecycle update failed');
  }
});

// 12. Bridge Contract & Serialization Verification
runTest('T12: Bridge Serialization & Property Naming Contract', () => {
  const bridge = NativeBridgeClient.getInstance();

  // Verify REST and SSE camelCase payload contract mapping
  const nativeCamelCasePayload = [
    {
      bssid: '00:11:22:33:44:55',
      ssid: 'Corp-Bridge-Test',
      channel: 36,
      band: '5 GHz',
      frequencyMHz: 5180,
      rssi: -55,
      signalQuality: 90,
      security: 'WPA3-Personal (SAE)',
      cipher: 'GCMP-256',
      phyType: '802.11ax',
      channelWidth: 80,
      vendor: 'Intel Corporate',
      beaconCount: 120,
      dataPacketCount: 340,
      securityScore: 95,
      isRogue: false,
      firstSeen: '2026-09-14 10:00:00',
      lastSeen: '2026-09-14 10:05:00',
      clients: [{ macAddress: 'AA:BB:CC:11:22:33', vendor: 'Apple', rssi: -60, packetsSent: 50, lastActivity: '10:04:00', probeRequests: [] }],
      securityIssues: [{ id: 'SEC-1', title: 'Test Issue', severity: 'LOW', description: 'Test', remediation: 'None', standardReference: 'NIST' }]
    }
  ];

  const taggedCamel = (bridge as any).tagOrigin(nativeCamelCasePayload, 'LIVE_WINDOWS');
  if (taggedCamel.length !== 1) throw new Error('Failed to tag camelCase payload');
  const ap = taggedCamel[0];
  if (ap.bssid !== '00:11:22:33:44:55' || ap.ssid !== 'Corp-Bridge-Test') throw new Error('BSSID/SSID mapping failure');
  if (ap.channel !== 36 || ap.band !== '5 GHz' || ap.frequencyMHz !== 5180) throw new Error('Channel/Band mapping failure');
  if (ap.dataSourceOrigin !== 'LIVE_WINDOWS') throw new Error('Origin tag mismatch');
  if (ap.issues.length !== 1 || ap.issues[0].id !== 'SEC-1') throw new Error('Issues array mapping failure');
  if (ap.clients.length !== 1 || ap.clients[0].macAddress !== 'AA:BB:CC:11:22:33') throw new Error('Clients array mapping failure');

  // Verify resilient handling of legacy PascalCase payload variants
  const legacyPascalPayload = [
    {
      Bssid: 'AA:BB:CC:DD:EE:FF',
      Ssid: 'Legacy-Pascal-AP',
      Channel: 6,
      Band: '2.4 GHz',
      FrequencyMHz: 2437,
      Rssi: -68,
      SignalQuality: 65,
      Security: 'WPA2-Personal (AES)',
      Cipher: 'CCMP (AES)',
      PhyType: '802.11n',
      ChannelWidth: 20,
      Vendor: 'Cisco',
      SecurityScore: 80,
      IsRogue: false,
      Clients: [],
      SecurityIssues: []
    }
  ];

  const taggedPascal = (bridge as any).tagOrigin(legacyPascalPayload, 'LIVE_WINDOWS');
  const apPascal = taggedPascal[0];
  if (apPascal.bssid !== 'AA:BB:CC:DD:EE:FF' || apPascal.ssid !== 'Legacy-Pascal-AP') throw new Error('Legacy PascalCase fallback mapping failure');
  if (apPascal.channel !== 6 || apPascal.band !== '2.4 GHz') throw new Error('Legacy PascalCase channel/band failure');

  // Native rogue detection is published as isRogue; every dashboard surface
  // reads isRogueCandidate, so the alias must carry it across both naming
  // styles, must not invent a candidate for a clean AP, and must not override
  // a candidate the client already resolved.
  const rogueCamel = (bridge as any).tagOrigin([{ bssid: 'AA:00:00:00:00:01', isRogue: true }], 'LIVE_WINDOWS')[0];
  if (rogueCamel.isRogueCandidate !== true) throw new Error('Native isRogue was not aliased to isRogueCandidate');
  const roguePascal = (bridge as any).tagOrigin([{ Bssid: 'AA:00:00:00:00:02', IsRogue: true }], 'LIVE_WINDOWS')[0];
  if (roguePascal.isRogueCandidate !== true) throw new Error('PascalCase IsRogue was not aliased to isRogueCandidate');
  const cleanAp = (bridge as any).tagOrigin([{ bssid: 'AA:00:00:00:00:03', isRogue: false }], 'LIVE_WINDOWS')[0];
  if (cleanAp.isRogueCandidate !== false) throw new Error('A clean access point was aliased as a rogue candidate');
  const explicitCandidate = (bridge as any).tagOrigin([{ bssid: 'AA:00:00:00:00:04', isRogue: false, isRogueCandidate: true }], 'LIVE_WINDOWS')[0];
  if (explicitCandidate.isRogueCandidate !== true) throw new Error('An explicit isRogueCandidate was overwritten by the alias');
});

runTest('T13: SSE Failure Falls Back and Reconnects', () => {
  const NativeEventSource = globalThis.EventSource;
  const nativeSetTimeout = globalThis.setTimeout;
  const retryCallbacks: Array<{ callback: (...args: any[]) => void; delay: number }> = [];
  class FakeEventSource {
    static instances: FakeEventSource[] = [];
    onopen: (() => void) | null = null;
    onerror: ((event: Event) => void) | null = null;
    closed = false;
    constructor(_url: string) { FakeEventSource.instances.push(this); }
    addEventListener(_event: string, _listener: EventListenerOrEventListenerObject) {}
    close() { this.closed = true; }
  }

  const client = new (NativeBridgeClient as any)();
  try {
    (globalThis as any).EventSource = FakeEventSource;
    (globalThis as any).setTimeout = (callback: (...args: any[]) => void, delay = 0) => {
      retryCallbacks.push({ callback, delay });
      return 123 as any;
    };
    client.state = 'CONNECTED';
    client.initEventSource();
    FakeEventSource.instances[0].onerror?.(new Event('error'));
    if (!FakeEventSource.instances[0].closed || !client.pollTimer) throw new Error('SSE failure did not close the stream and start polling fallback');
    const retry = retryCallbacks.find(item => item.delay === 10_000);
    if (!retry) throw new Error('SSE retry was not scheduled for 10 seconds');
    retry.callback();
    if (FakeEventSource.instances.length !== 2) throw new Error('SSE retry did not create a replacement event stream');
    client.disconnect();
  } finally {
    client.disconnect();
    (globalThis as any).EventSource = NativeEventSource;
    globalThis.setTimeout = nativeSetTimeout;
  }
});

runTest('T14: Policy Selection and Evidence Persistence', () => {
  const values = new Map<string, string>();
  const originalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
      clear: () => values.clear()
    }
  });
  try {
    const policyEngine = PolicyEngine.getInstance();
    policyEngine.setActivePolicy('high-sec-policy');
    if (policyEngine.getActivePolicy().id !== 'high-sec-policy') throw new Error('Selected policy was not activated');
    const weakAp = FIXTURE_ACCESS_POINTS.find(ap => ap.security === 'Open');
    if (!weakAp) throw new Error('No open AP available for policy evaluation');
    const result = policyEngine.evaluateAP(weakAp);
    if (result.status === 'Compliant' || result.policyName !== 'High Security Policy') throw new Error('Active policy did not evaluate the AP');
    if (values.get('winwifi_active_policy') !== 'high-sec-policy') throw new Error('Policy choice was not persisted');

    const db = SqliteDatabaseService.getInstance();
    const evidence = { id: 'EVD-test', timestamp: new Date(0).toISOString(), type: 'note' as const, title: 'Test evidence', source: 'test', description: 'Persistence check' };
    db.saveEvidenceItems([evidence]);
    if (db.getEvidenceItems()[0]?.id !== evidence.id) throw new Error('Evidence record failed to persist');
    db.deleteProjectData('project-to-delete');
    if (values.has('winwifi_sqlite_access_points_project-to-delete')) throw new Error('Project AP data was not removed');
  } finally {
    if (originalStorage) Object.defineProperty(globalThis, 'localStorage', originalStorage);
    else delete (globalThis as any).localStorage;
  }
});

runTest('T15: Findings vs Incidents Split, Deduplication & Stable IDs', () => {
  const finding = {
    id: 'THR-EVIL_TWIN-001122334455',
    category: 'Evil Twin',
    title: 'Evil Twin Clone of SSID "Campus-Secure"',
    severity: 'CRITICAL',
    confidence: 85,
    relatedBssid: '00:11:22:33:44:55',
    relatedSsid: 'Campus-Secure',
    evidence: 'security downgrade; OUI anomaly',
    explanation: 'Multiple independent indicators.',
    remediation: 'Locate and remove the transmitter.',
    detectedAt: '2026-10-28T10:00:00.000Z'
  };

  const forward = mapNativeFindingsToIncidents([finding, { ...finding }]);
  const reverse = mapNativeFindingsToIncidents([{ ...finding }, finding]);
  if (forward.length !== 1) throw new Error(`Duplicate delivery created ${forward.length} incidents`);
  if (forward[0].id !== reverse[0].id) throw new Error('Incident ID is not stable across delivery order');
  if (forward[0].id !== stableIncidentId('NATIVE', 'EVIL_TWIN', '00:11:22:33:44:55')) {
    throw new Error(`Unexpected stable ID: ${forward[0].id}`);
  }

  const otherType = mapNativeFindingsToIncidents([
    finding,
    { ...finding, id: 'THR-PMF_STRIPPED-001122334455', category: 'PMF Stripped' }
  ]);
  if (otherType.length !== 2) throw new Error('Same BSSID with a different finding type was incorrectly merged');

  // Analyst lifecycle must survive a rescan that re-reports the same finding.
  const investigating = { ...forward[0], status: 'Investigating' as const, notes: [...forward[0].notes, { timestamp: '2026-10-28T11:00:00.000Z', author: 'Analyst', text: 'Locating the transmitter.' }] };
  const reconciled = reconcileLiveIncidents(forward, [], [investigating]);
  if (reconciled.length !== 1) throw new Error(`Reconcile duplicated the incident (${reconciled.length})`);
  if (reconciled[0].status !== 'Investigating') throw new Error('Reconcile discarded the analyst status');
  if (!reconciled[0].notes.some(note => note.text === 'Locating the transmitter.')) throw new Error('Reconcile discarded the analyst note');

  // Per-AP configuration issues are findings, not incident cases.
  const apWithIssues = [{
    bssid: 'AA:BB:CC:DD:EE:FF', ssid: 'Open-Network', rssi: -60, channel: 6, band: '2.4 GHz',
    security: 'Open', cipher: 'None', securityScore: 55, issues: [{ id: 'VULN-OPEN-UNENCRYPTED', title: 'Unencrypted radio', severity: 'HIGH', description: 'Plaintext', recommendation: 'Upgrade' }]
  }];
  const apOnly = reconcileLiveIncidents([], apWithIssues as any, []);
  if (apOnly.length !== 0) throw new Error('Per-AP finding was incorrectly promoted to an incident');

  // Confirmed analyst cases survive only while the BSSID is still observed as rogue.
  const threatEngine = ThreatEngine.getInstance();
  threatEngine.setIncidents([]);
  const analystCase = threatEngine.createIncident({
    title: 'Confirmed Rogue Access Point: Campus-Secure',
    severity: 'CRITICAL',
    confidence: 95,
    bssid: '00:11:22:33:44:55',
    ssid: 'Campus-Secure',
    summary: 'Analyst confirmed the transmitter as unauthorized.'
  });
  const rogueAp = { bssid: '00:11:22:33:44:55', ssid: 'Campus-Secure', classification: 'Rogue', isRogueCandidate: true, issues: [] };
  const kept = reconcileLiveIncidents([], [rogueAp] as any, [analystCase]);
  const dropped = reconcileLiveIncidents([], [{ ...rogueAp, classification: 'Corporate', isRogueCandidate: false }] as any, [analystCase]);
  if (kept.length !== 1) throw new Error('Confirmed analyst case was dropped while the AP is still rogue');
  if (dropped.length !== 0) throw new Error('Stale analyst case survived after the AP was classified as corporate');

  // Repeated escalation requests must reuse the deterministic case, not collide or duplicate.
  const duplicate = threatEngine.createIncident({
    title: 'Confirmed Rogue Access Point: Campus-Secure',
    severity: 'CRITICAL',
    confidence: 95,
    bssid: '00:11:22:33:44:55',
    ssid: 'Campus-Secure',
    summary: 'Analyst confirmed the transmitter as unauthorized.'
  });
  if (duplicate.id !== analystCase.id || threatEngine.getIncidents().length !== 1) {
    throw new Error('createIncident did not deduplicate an existing case');
  }

  const ids = new Set<string>();
  for (let index = 0; index < 200; index++) {
    const created = threatEngine.createIncident({
      title: `Distinct case ${index}`,
      severity: 'LOW',
      confidence: 50,
      bssid: `02:00:00:00:${String(Math.floor(index / 256)).padStart(2, '0')}:${String(index % 256).padStart(2, '0')}`,
      summary: `Synthetic case ${index}`
    });
    ids.add(created.id);
  }
  if (ids.size !== 200) throw new Error(`Incident ID collision detected (${ids.size}/200 unique)`);
  if (countOpenIncidents(threatEngine.getIncidents()) !== threatEngine.getIncidents().length) {
    throw new Error('Open incident count drifted from the incident list');
  }
  threatEngine.setIncidents([]);
});

// 16. Capability claims must match the implementation.
runTest('T16: Capability Matrix Honesty', () => {
  const caps = WifiEngine.getInstance().getSystemCapabilities();
  if (isWebView2Host()) throw new Error('Node test host must not report a WebView2 runtime');
  if (caps.environment !== 'Browser Sandboxed DOM (Web Container)') {
    throw new Error(`Unexpected runtime environment: ${caps.environment}`);
  }
  if (caps.nativeWlanApiAccess) throw new Error('Dashboard reported direct wlanapi.dll access');

  const hashcat = CapabilityMatrixService.getInstance()
    .getCapabilities()
    .find(cap => cap.id === 'CAP_HASHCAT_EXPORT');
  if (!hashcat) throw new Error('Hashcat capability is missing from the matrix');
  if (hashcat.status === 'Supported') throw new Error('Hashcat export must not be reported as supported');
  if (!/does not emit/i.test(hashcat.technicalDetails)) {
    throw new Error('Hashcat capability details do not disclose missing export support');
  }
});

// 17. Runtime labels, version strings, and live-age freshness must stay honest.
runTest('T17: Runtime Label & Version Consistency', () => {
  const read = (relative: string) => fs.readFileSync(path.join(__dirname, '..', relative), 'utf8');

  const versions = [
    ['WinWiFi.Desktop/Program.cs', read('WinWiFi.Desktop/Program.cs')],
    ['WinWiFi.Desktop/Services/HttpBridgeServer.cs', read('WinWiFi.Desktop/Services/HttpBridgeServer.cs')],
    ['src/components/NativeDesktopPanel.tsx', read('src/components/NativeDesktopPanel.tsx')]
  ];
  for (const [name, content] of versions) {
    if (content.includes('3.0.1')) throw new Error(`${name} still advertises version 3.0.1`);
    if (!content.includes('3.0.3')) throw new Error(`${name} is missing the 3.0.3 version string`);
  }

  const clients = read('src/components/ClientObserver.tsx');
  if (!clients.includes('SYNTHETIC / NOT LIVE') || !clients.includes('isTrainingDataset')) {
    throw new Error('Client screen no longer labels training clients as synthetic');
  }

  const dashboard = read('src/components/CommandCenterDashboard.tsx');
  if (!dashboard.includes('window.setInterval') || !dashboard.includes('setNow(Date.now())')) {
    throw new Error('Live refresh age is not ticking');
  }

  const engine = read('src/services/wifiEngine.ts');
  if (!engine.includes('isWebView2Host') || !engine.includes('chrome?.webview')) {
    throw new Error('WebView2 runtime detection is missing');
  }
});

// 18. Every /api call and the SSE stream must carry the per-launch token.
runTest('T18: Per-Launch Bridge Token Wiring', () => {
  const NativeEventSource = globalThis.EventSource;
  let capturedUrl = '';
  class FakeEventSource {
    onopen: (() => void) | null = null;
    onerror: ((event: Event) => void) | null = null;
    constructor(url: string) { capturedUrl = url; }
    addEventListener(_event: string, _listener: EventListenerOrEventListenerObject) {}
    close() {}
  }

  const client = new (NativeBridgeClient as any)();
  try {
    (globalThis as any).EventSource = FakeEventSource;
    client.setToken('unit-test-token');
    client.projectId = 'proj-token';
    client.initEventSource();
    if (!capturedUrl.includes('token=unit-test-token')) {
      throw new Error('SSE stream omitted the bridge token');
    }
    if (!capturedUrl.includes('projectId=proj-token')) {
      throw new Error('SSE stream omitted the project scope');
    }
    if (client.getToken() !== 'unit-test-token') throw new Error('Bridge client did not retain the token');

    const source = fs.readFileSync(path.join(__dirname, '../src/services/bridgeClient.ts'), 'utf8');
    if (!source.includes("'X-WinWiFi-Token'")) throw new Error('REST requests do not send the bridge token header');
    const explained = (client as any).formatBridgeError(new Error('HTTP 401 Unauthorized'));
    if (!/token/i.test(explained)) throw new Error('Bridge client does not explain token rejection');
  } finally {
    client.disconnect();
    (globalThis as any).EventSource = NativeEventSource;
  }
});

runTest('T19: Browser Capture Parser Limits & Integrity Warnings', () => {
  const pcap = PcapService.getInstance();
  const buildHeader = (view: DataView, network: number) => {
    view.setUint32(0, 0xa1b2c3d4, true);
    view.setUint16(4, 2, true);
    view.setUint16(6, 4, true);
    view.setUint32(8, 0, true);
    view.setUint32(12, 0, true);
    view.setUint32(16, 65535, true);
    view.setUint32(20, network, true);
  };
  const buildBeacon = (ssidBytes: number[] = []) => {
    const frame = new Uint8Array(8 + 24 + 12 + 2 + ssidBytes.length);
    const view = new DataView(frame.buffer);
    frame[2] = 8; // radiotap length
    view.setUint16(8, 0x0080, true); // beacon
    frame.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 12);
    frame.set([0x10, 0x20, 0x30, 0x40, 0x50, 0x60], 18);
    frame.set([0x10, 0x20, 0x30, 0x40, 0x50, 0x60], 24);
    const ieOffset = 8 + 24 + 12;
    frame[ieOffset] = 0;
    frame[ieOffset + 1] = ssidBytes.length;
    frame.set(ssidBytes, ieOffset + 2);
    return frame;
  };
  const buildPcap = (network: number, packets: Uint8Array[]) => {
    const total = 24 + packets.reduce((sum, packet) => sum + 16 + packet.length, 0);
    const buffer = new ArrayBuffer(total);
    const view = new DataView(buffer);
    buildHeader(view, network);
    const data = new Uint8Array(buffer);
    let offset = 24;
    packets.forEach((packet, index) => {
      view.setUint32(offset, 1710000000 + index, true);
      view.setUint32(offset + 4, 0, true);
      view.setUint32(offset + 8, packet.length, true);
      view.setUint32(offset + 12, packet.length, true);
      data.set(packet, offset + 16);
      offset += 16 + packet.length;
    });
    return buffer;
  };

  const beacon = buildBeacon([0x53, 0x61, 0x66, 0x65]);
  const sanitized = pcap.parseBinaryPcap(buildPcap(127, [buildBeacon([0x45, 0x76, 0x69, 0x6c, 0x01, 0x4e, 0x65, 0x74])]));
  if (sanitized.accessPoints.length !== 1 || sanitized.accessPoints[0].ssid !== 'Evil?Net') {
    throw new Error(`SSID sanitization failed: ${sanitized.accessPoints[0]?.ssid ?? '(none)'}`);
  }

  const oversizedBuffer = new ArrayBuffer(40);
  const oversizedView = new DataView(oversizedBuffer);
  buildHeader(oversizedView, 127);
  oversizedView.setUint32(32, 0xfffffff0, true);
  oversizedView.setUint32(36, 0xfffffff0, true);
  const oversized = pcap.parseBinaryPcap(oversizedBuffer);
  if (!oversized.truncated || oversized.packets.length !== 0 || !oversized.warnings?.some(w => w.includes('per-frame limit'))) {
    throw new Error('Oversized record length was not rejected in the browser parser');
  }

  const truncatedBuffer = new ArrayBuffer(50);
  const truncatedView = new DataView(truncatedBuffer);
  buildHeader(truncatedView, 127);
  truncatedView.setUint32(32, 100, true);
  truncatedView.setUint32(36, 100, true);
  const truncated = pcap.parseBinaryPcap(truncatedBuffer);
  if (!truncated.truncated || !truncated.warnings?.some(w => /is truncated/i.test(w))) {
    throw new Error('Truncated record was not reported in the browser parser');
  }

  const zeroLength = new Uint8Array(24 + 16 + 16 + beacon.length);
  const zeroView = new DataView(zeroLength.buffer);
  buildHeader(zeroView, 127);
  zeroView.setUint32(24, 1710000000, true);
  zeroView.setUint32(32, 0, true);
  zeroView.setUint32(36, 0, true);
  zeroView.setUint32(40, 1710000001, true);
  zeroView.setUint32(48, beacon.length, true);
  zeroView.setUint32(52, beacon.length, true);
  zeroLength.set(beacon, 56);
  const zeroParsed = pcap.parseBinaryPcap(zeroLength.buffer);
  if (zeroParsed.packets.length !== 1 || !zeroParsed.warnings?.some(w => w.includes('zero captured bytes'))) {
    throw new Error('Zero-length record handling failed in the browser parser');
  }

  const badRadiotapFrame = buildBeacon([0x53]);
  badRadiotapFrame[2] = 100;
  const badRadiotap = pcap.parseBinaryPcap(buildPcap(127, [badRadiotapFrame]));
  if (badRadiotap.packets.length !== 0 || !badRadiotap.warnings?.some(w => w.includes('radiotap length'))) {
    throw new Error('Malformed radiotap header was not rejected in the browser parser');
  }

  let rejectedNetwork = false;
  try {
    pcap.parseBinaryPcap(buildPcap(1, [beacon]));
  } catch (error: any) {
    rejectedNetwork = /only dissects 802\.11/i.test(error.message);
  }
  if (!rejectedNetwork) {
    throw new Error('Browser parser accepted a non-802.11 link type');
  }
});

// 20. Enterprise Asset Registry & CSV
runTest('T20: Enterprise Asset Registry, MAC Identity & CSV Round-Trip', () => {
  if (normalizeMac('aa-bb-cc-dd-ee-ff') !== 'AA:BB:CC:DD:EE:FF' ||
      normalizeMac('02.11.22.33.44.55') !== '02:11:22:33:44:55') {
    throw new Error('MAC canonicalization failed');
  }
  for (const invalid of ['', 'nope', 'AA:BB:CC:DD:EE', 'FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00', 'GG:11:22:33:44:55']) {
    if (normalizeMac(invalid) !== null) throw new Error(`Invalid MAC accepted: ${invalid}`);
  }

  const csv = 'macAddress,ssid,classification,approvalStatus,notes\r\n' +
    'aa-bb-cc-dd-ee-ff,"Lab, West",Corporate,Approved,"Line one\r\nLine two and ""quoted"" text"\r\n' +
    '02:11:22:33:44:55,Printer,IoT,Investigating,"\'=HYPERLINK(""http://example.invalid"")"\r\n' +
    'not-a-mac,Bad,Corporate,Approved,ignored\r\n' +
    '02-11-22-33-44-55,Printer Updated,IoT,Investigating,"\'=HYPERLINK(""http://example.invalid"")"\r\n';

  const parsed = parseAssetCsv(csv);
  if (parsed.fatalError || parsed.rows.length !== 2 || parsed.rejected.length !== 1) {
    throw new Error(`CSV parse mismatch: rows=${parsed.rows.length}, rejected=${parsed.rejected.length}, fatal=${parsed.fatalError}`);
  }
  const lab = parsed.rows.find(row => row.asset.macAddress === 'AA:BB:CC:DD:EE:FF')!.asset;
  if (lab.ssid !== 'Lab, West' || lab.notes !== 'Line one\r\nLine two and "quoted" text') {
    throw new Error(`Quoted/multi-line CSV fields were not preserved: ${JSON.stringify(lab.notes)}`);
  }
  const printer = parsed.rows.find(row => row.asset.macAddress === '02:11:22:33:44:55')!.asset;
  if (printer.ssid !== 'Printer Updated' || printer.approvalStatus !== 'Under Investigation') {
    throw new Error('Duplicate MAC rows did not use the later record with canonical approval status');
  }
  if (!printer.notes.startsWith('=HYPERLINK')) {
    throw new Error(`CSV formula payload was not preserved for inspection: ${printer.notes}`);
  }

  const exported = serializeAssetCsv(parsed.rows.map(row => row.asset));
  if (!exported.includes('"\'=HYPERLINK')) {
    throw new Error('CSV export did not neutralize a formula-leading cell');
  }
  const roundTrip = parseAssetCsv(exported);
  const roundTripPrinter = roundTrip.rows.find(row => row.asset.macAddress === '02:11:22:33:44:55')!.asset;
  if (roundTrip.rows.length !== 2 || roundTripPrinter.notes !== printer.notes || roundTripPrinter.ssid !== printer.ssid) {
    throw new Error('CSV export/import did not round-trip asset data');
  }

  const normalized = normalizeAsset({ macAddress: 'aa-bb-cc-dd-ee-ff', assetType: 'Sensor', classification: 'Guest', approvalStatus: 'Approved', notes: 'ok' });
  if (!normalized.asset || normalized.asset.macAddress !== 'AA:BB:CC:DD:EE:FF' || normalized.asset.lastSeen.length < 19) {
    throw new Error('normalizeAsset did not canonicalize a valid record');
  }
  if (normalizeAsset({ macAddress: '02:11:22:33:44:55', classification: 'Made Up' as any }).asset) {
    throw new Error('An unsupported classification was accepted');
  }

  const original = parsed.rows[0].asset;
  const merged = mergeMissingFields({ ...original, id: 'AST-ORIGINAL', notes: 'prior' }, {
    asset: { ...original, notes: 'replaced' },
    provided: new Set(['notes']),
    rowNumber: 2
  });
  if (merged.id !== 'AST-ORIGINAL' || merged.notes !== 'replaced' || merged.site !== original.site) {
    throw new Error('mergeMissingFields did not preserve identity and unprovided fields');
  }

  const updatedList = mergeAssetLists([original], [{ ...original, id: 'AST-REPLACEMENT', classification: 'Guest' }]);
  if (updatedList.length !== 1 || updatedList[0].id !== 'AST-REPLACEMENT' || updatedList[0].classification !== 'Guest') {
    throw new Error('mergeAssetLists did not update by MAC');
  }

  const aps = applyAssetsToAccessPoints([
    { bssid: '02:11:22:33:44:55' } as any,
    { bssid: '02:AA:BB:CC:DD:EE' } as any
  ], [parsed.rows[1].asset]);
  if (aps[0].approvedStatus !== 'Investigating' || aps[0].classification !== 'IoT' || aps[1].approvedStatus !== undefined) {
    throw new Error('Registry metadata was not applied to the matching BSSID only');
  }
});

// 21. Classification-Routed Policies & Approval Enforcement
runTest('T21: Classification Routing & Approval Enforcement', () => {
  const engine = PolicyEngine.getInstance();
  engine.setActivePolicy('corp-policy');

  const base = (overrides: Record<string, unknown>) => ({
    bssid: '02:00:00:00:00:01',
    ssid: 'Policy-Test',
    security: 'WPA2-Enterprise (802.1X)',
    cipher: 'CCMP',
    wpsEnabled: false,
    pmfRequired: true,
    classification: 'Corporate',
    approvedStatus: 'Approved',
    ...overrides
  });

  const corporate = engine.evaluateAP(base({}) as any);
  if (corporate.policyId !== 'corp-policy' || corporate.status !== 'Compliant' || corporate.approvalStatus !== 'Approved') {
    throw new Error(`Corporate routing failed: ${corporate.policyId}/${corporate.status}`);
  }

  const guest = engine.evaluateAP(base({ classification: 'Guest', security: 'Open', cipher: 'None', pmfRequired: false, approvedStatus: undefined }) as any);
  if (guest.policyId !== 'guest-policy' || guest.status !== 'Compliant') {
    throw new Error(`Guest routing failed: ${guest.policyId}/${guest.status}`);
  }

  const iot = engine.evaluateAP(base({ classification: 'IoT', security: 'WPA2-Personal (AES)', pmfRequired: false, approvedStatus: undefined }) as any);
  if (iot.policyId !== 'iot-policy' || iot.status !== 'Compliant') {
    throw new Error(`IoT routing failed: ${iot.policyId}/${iot.status}`);
  }

  const rogue = engine.evaluateAP(base({ classification: 'Rogue', approvedStatus: undefined, security: 'WPA3-Enterprise' }) as any);
  if (rogue.policyId !== 'high-sec-policy' || rogue.status !== 'Non-Compliant' || !rogue.failedRules.some(rule => /rogue/i.test(rule))) {
    throw new Error(`Rogue classification was not enforced: ${rogue.policyId}/${rogue.status}`);
  }

  const suspicious = engine.evaluateAP(base({ classification: 'Suspicious', approvedStatus: undefined, security: 'WPA3-Enterprise' }) as any);
  if (suspicious.policyId !== 'high-sec-policy' || suspicious.status !== 'Warning') {
    throw new Error(`Suspicious classification was not a warning: ${suspicious.policyId}/${suspicious.status}`);
  }

  const unapproved = engine.evaluateAP(base({ approvedStatus: 'Unapproved' }) as any);
  if (unapproved.status !== 'Non-Compliant' || !unapproved.failedRules.some(rule => /Unapproved/.test(rule))) {
    throw new Error('Unapproved registry status did not fail the policy');
  }

  for (const status of ['Investigating', 'Pending Review'] as const) {
    const reviewing = engine.evaluateAP(base({ approvedStatus: status }) as any);
    if (reviewing.status !== 'Warning' || !reviewing.failedRules.some(rule => rule.includes('Registry approval'))) {
      throw new Error(`Registry status ${status} was not a warning: ${reviewing.status}`);
    }
  }

  engine.setActivePolicy('guest-policy');
  const unknown = engine.evaluateAP(base({ classification: 'Unknown', security: 'Open', cipher: 'None', pmfRequired: false, approvedStatus: undefined }) as any);
  if (unknown.policyId !== 'guest-policy' || unknown.status !== 'Compliant') {
    throw new Error(`Unknown classification did not fall back to the default policy: ${unknown.policyId}/${unknown.status}`);
  }

  const guestPolicy = engine.getPolicies().find(policy => policy.id === 'guest-policy')!;
  const explicit = engine.evaluateAP(base({ security: 'Open', cipher: 'None', pmfRequired: false }) as any, guestPolicy);
  if (explicit.policyId !== 'guest-policy' || explicit.policyName !== 'Guest Policy') {
    throw new Error('An explicit policy override did not take precedence over classification routing');
  }

  engine.setActivePolicy('corp-policy');
});

// 22. Site Directory Bounds, Rename Propagation & Scope Seeding
runTest('T22: Site Directory CRUD, Counts & Rename Propagation', () => {
  if (sanitizeSiteName('  \u0000 HQ \n\t Main  ') !== 'HQ Main') {
    throw new Error(`sanitizeSiteName did not strip control characters and collapse whitespace: ${JSON.stringify(sanitizeSiteName('  \u0000 HQ \n\t Main  '))}`);
  }
  if (sanitizeSiteName('x'.repeat(120)).length !== 80) {
    throw new Error('sanitizeSiteName did not cap names at 80 characters');
  }
  if (normalizeSiteDirectory('not-an-array').length !== 0 ||
      normalizeSiteDirectory([{ name: '' }, null, 42, { name: 'HQ' }]).length !== 1) {
    throw new Error('normalizeSiteDirectory accepted malformed input');
  }

  const raw = [
    { id: 'same', name: 'HQ', buildings: [{ id: 'b-same', name: 'Main', floors: [{ id: 'f-same', name: '3' }] }] },
    { id: 'same', name: 'hq', buildings: [] },
    { id: 'b-same', name: 'Branch', buildings: [{ id: 'b-same', name: 'Annex', floors: [{ id: 'f-same', name: '1' }, { id: 'f-same', name: '2' }] }] }
  ];
  const normalizedDirectory = normalizeSiteDirectory(raw);
  if (normalizedDirectory.length !== 2) {
    throw new Error(`Duplicate site names were not removed: ${normalizedDirectory.length}`);
  }
  const allIds = [
    ...normalizedDirectory.map(site => site.id),
    ...normalizedDirectory.flatMap(site => site.buildings.map(building => building.id)),
    ...normalizedDirectory.flatMap(site => site.buildings.flatMap(building => building.floors.map(floor => floor.id)))
  ];
  if (new Set(allIds).size !== allIds.length) {
    throw new Error('normalizeSiteDirectory did not regenerate duplicate IDs');
  }
  if (listSiteNames(normalizedDirectory).join('|') !== 'HQ|Branch' ||
      listBuildingNames(normalizedDirectory, 'hq').join('|') !== 'Main' ||
      listFloorNames(normalizedDirectory, 'hq', 'MAIN').join('|') !== '3') {
    throw new Error('Directory listing helpers are not case-insensitive');
  }

  let directory: ReturnType<typeof normalizeSiteDirectory> = [];
  const addSiteResult = addSite(directory, 'Headquarters');
  if (addSiteResult.error || addSiteResult.directory.length !== 1) {
    throw new Error(`addSite failed: ${addSiteResult.error}`);
  }
  directory = addSiteResult.directory;
  if (!addSite(directory, '  headquarters ').error) {
    throw new Error('addSite accepted a case-insensitive duplicate');
  }
  if (!addSite(directory, '   ').error) {
    throw new Error('addSite accepted an empty name');
  }
  const siteId = directory[0].id;

  directory = addBuilding(directory, siteId, 'Main').directory;
  const buildingId = directory[0].buildings[0].id;
  directory = addFloor(directory, siteId, buildingId, '3').directory;
  const floorId = directory[0].buildings[0].floors[0].id;
  if (!addBuilding(directory, siteId, 'main').error || !addFloor(directory, siteId, buildingId, '3').error) {
    throw new Error('addBuilding/addFloor accepted duplicates');
  }

  directory = renameSite(directory, siteId, 'HQ').directory;
  directory = renameBuilding(directory, siteId, buildingId, 'Main Campus').directory;
  directory = renameFloor(directory, siteId, buildingId, floorId, 'Floor 3').directory;
  if (directory[0].name !== 'HQ' || directory[0].buildings[0].name !== 'Main Campus' || directory[0].buildings[0].floors[0].name !== 'Floor 3') {
    throw new Error('Rename helpers did not apply the new names');
  }
  if (!renameSite(directory, 'missing', 'X').error || !renameBuilding(directory, siteId, 'missing', 'X').error || !renameFloor(directory, siteId, buildingId, 'missing', 'X').error) {
    throw new Error('Rename helpers accepted missing identifiers');
  }

  const asset = (overrides: Partial<any>): any => ({
    id: 'AST-1',
    macAddress: '02:00:00:00:00:01',
    ssid: 'Test',
    assetType: 'Access Point',
    classification: 'Corporate',
    approvalStatus: 'Approved',
    site: '',
    building: '',
    areaFloor: '',
    ownerDepartment: '',
    vendor: '',
    model: '',
    lastSeen: '2026-01-01 00:00:00',
    notes: '',
    ...overrides
  });
  const siteAsset = asset({ id: 'AST-HQ', macAddress: '02:00:00:00:00:01', site: 'HQ', building: 'Main Campus', areaFloor: 'Floor 3' });
  const caseAsset = asset({ id: 'AST-HQ-2', macAddress: '02:00:00:00:00:02', site: 'hq', building: 'main campus', areaFloor: 'floor 3' });
  const branchAsset = asset({ id: 'AST-BR', macAddress: '02:00:00:00:00:03', site: 'Branch', building: 'Annex', areaFloor: '1' });
  const assets = [siteAsset, caseAsset, branchAsset];

  if (countAssetsAtSite(assets, 'hq') !== 2 ||
      countAssetsInBuilding(assets, 'HQ', 'MAIN CAMPUS') !== 2 ||
      countAssetsOnFloor(assets, 'hq', 'main campus', 'floor 3') !== 2 ||
      countAssetsAtSite(assets, 'Branch') !== 1) {
    throw new Error('Location counts are not case-insensitive or are miscounted');
  }

  const renamedAssets = renameSiteInAssets(assets, 'HQ', 'Headquarters');
  if (renamedAssets[0].site !== 'Headquarters' || renamedAssets[1].site !== 'Headquarters' || renamedAssets[2] !== branchAsset) {
    throw new Error('renameSiteInAssets did not update matching records or preserve non-matches');
  }
  const renamedBuildings = renameBuildingInAssets(renamedAssets, 'headquarters', 'Main Campus', 'Building A');
  if (renamedBuildings[0].building !== 'Building A' || renamedBuildings[1].building !== 'Building A' || renamedBuildings[2] !== branchAsset) {
    throw new Error('renameBuildingInAssets did not scope the rename to the site');
  }
  const renamedFloors = renameFloorInAssets(renamedBuildings, 'Headquarters', 'building a', 'Floor 3', 'Level 3');
  if (renamedFloors[0].areaFloor !== 'Level 3' || renamedFloors[1].areaFloor !== 'Level 3' || renamedFloors[2] !== branchAsset) {
    throw new Error('renameFloorInAssets did not scope the rename to site and building');
  }
  if (renameSiteInAssets(assets, 'HQ', 'HQ') !== assets) {
    throw new Error('A no-op rename did not preserve array identity');
  }

  const removedFloor = deleteFloor(directory, siteId, buildingId, floorId);
  if (removedFloor.error || removedFloor.directory[0].buildings[0].floors.length !== 0) {
    throw new Error(`deleteFloor failed: ${removedFloor.error}`);
  }
  const removedBuilding = deleteBuilding(removedFloor.directory, siteId, buildingId);
  if (removedBuilding.error || removedBuilding.directory[0].buildings.length !== 0) {
    throw new Error(`deleteBuilding failed: ${removedBuilding.error}`);
  }
  if (!deleteBuilding(removedBuilding.directory, siteId, buildingId).error) {
    throw new Error('deleteBuilding accepted a missing building');
  }
  if (!deleteSite(directory, 'missing').error) {
    throw new Error('deleteSite accepted a missing site');
  }

  const seeded = ensureScopeInDirectory([], { organization: 'Org', site: 'HQ', building: 'Main', area: '3', assessmentId: 'A1' } as any);
  if (seeded.length !== 1 || seeded[0].name !== 'HQ' || seeded[0].buildings.length !== 1 || seeded[0].buildings[0].name !== 'Main') {
    throw new Error('ensureScopeInDirectory did not seed the project scope');
  }
  if (ensureScopeInDirectory(seeded, { site: 'hq', building: 'MAIN' } as any) !== seeded) {
    throw new Error('ensureScopeInDirectory changed an already-seeded directory');
  }
  if (ensureScopeInDirectory([], undefined).length !== 0) {
    throw new Error('ensureScopeInDirectory invented a site without a scope');
  }

  let capped = normalizeSiteDirectory([]);
  for (let index = 0; index < 50; index++) capped = addSite(capped, `Site ${index}`).directory;
  if (!addSite(capped, 'Site 51').error) {
    throw new Error('addSite ignored the 50-site cap');
  }
});

// 23. Maintenance Approval: two-person, time-boxed, BSSID-scoped
runTest('T23: Maintenance Approval Workflow', () => {
  const base = new Date('2026-10-01T12:00:00.000Z');
  const baseMs = base.getTime();
  const bssid = '02:00:00:00:00:AA';

  if (sanitizeMaintenanceText('  \u0000 Alice \n\t Smith  ', 80) !== 'Alice Smith') {
    throw new Error('sanitizeMaintenanceText did not strip control characters and collapse whitespace');
  }
  if (sanitizeMaintenanceText('x'.repeat(500), 400).length !== 400) {
    throw new Error('sanitizeMaintenanceText did not enforce the length cap');
  }
  if (normalizeMaintenanceApprovals('nope').length !== 0 ||
      normalizeMaintenanceApprovals([null, 42, {}, { action: 'Connect to network' }]).length !== 0) {
    throw new Error('normalizeMaintenanceApprovals accepted malformed records');
  }

  const request = {
    action: 'Connect to network' as const,
    bssid: '02-00-00-00-00-aa',
    ssid: 'QA-Lab',
    adapterId: 'adapter-1',
    requester: 'Alice',
    justification: 'Validate the new access point after maintenance.',
    durationMinutes: 30
  };

  if (!createMaintenanceRequest([], { ...request, bssid: 'not-a-mac' }, base).error) {
    throw new Error('createMaintenanceRequest accepted an invalid BSSID');
  }
  if (!createMaintenanceRequest([], { ...request, requester: 'A' }, base).error) {
    throw new Error('createMaintenanceRequest accepted a one-character requester');
  }
  if (!createMaintenanceRequest([], { ...request, justification: 'short' }, base).error) {
    throw new Error('createMaintenanceRequest accepted a short justification');
  }
  if (!createMaintenanceRequest([], { ...request, durationMinutes: 5 }, base).error ||
      !createMaintenanceRequest([], { ...request, durationMinutes: 600 }, base).error) {
    throw new Error('createMaintenanceRequest accepted a duration outside 15-480 minutes');
  }

  const created = createMaintenanceRequest([], request, base);
  if (created.error || !created.record) throw new Error(`Valid request failed: ${created.error}`);
  if (created.record.bssid !== bssid || created.record.status !== 'Pending' || created.record.requester !== 'Alice') {
    throw new Error('The request was not canonicalized or initialized as Pending');
  }
  if (Date.parse(created.record.expiresAt) !== baseMs + 30 * 60_000) {
    throw new Error('The approval window did not match the requested duration');
  }
  if (findActiveApproval(created.records, '0200000000aa', 'Connect to network', new Date(baseMs + 60_000))) {
    throw new Error('findActiveApproval returned a Pending request');
  }

  if (!approveMaintenance(created.records, created.record.id, 'alice', base).error) {
    throw new Error('The approver was allowed to be the requester');
  }
  if (!approveMaintenance(created.records, created.record.id, 'B', base).error) {
    throw new Error('The approver name was not required');
  }

  const approved = approveMaintenance(created.records, created.record.id, 'Bob', new Date(baseMs + 60_000));
  if (approved.error || !approved.record || approved.record.status !== 'Approved' || approved.record.approver !== 'Bob') {
    throw new Error(`Valid approval failed: ${approved.error}`);
  }
  if (!approved.record.approvedAt || !approved.record.decidedAt) {
    throw new Error('Approval did not record its decision timestamps');
  }
  if (!findActiveApproval(approved.records, '02:00:00:00:00:AA', 'Connect to network', new Date(baseMs + 2 * 60_000))) {
    throw new Error('findActiveApproval did not return the approved record');
  }
  if (findActiveApproval(approved.records, bssid, 'Connect to network', new Date(baseMs + 31 * 60_000))) {
    throw new Error('findActiveApproval returned an expired approval');
  }
  if (!approveMaintenance(created.records, created.record.id, 'Bob', new Date(baseMs + 31 * 60_000)).error) {
    throw new Error('An expired request was approved');
  }
  if (!approveMaintenance(approved.records, created.record.id, 'Carol', new Date(baseMs + 2 * 60_000)).error) {
    throw new Error('An already-approved request was approved again');
  }

  const used = markApprovalUsed(approved.records, created.record.id, new Date(baseMs + 3 * 60_000));
  if (used.error || !used.records[0].lastUsedAt) {
    throw new Error('markApprovalUsed did not record lastUsedAt');
  }
  if (used.records[0].status !== 'Approved') {
    throw new Error('markApprovalUsed consumed the approval');
  }
  if (!markApprovalUsed(created.records, created.record.id, new Date(baseMs + 3 * 60_000)).error) {
    throw new Error('markApprovalUsed accepted a Pending record');
  }

  if (!rejectMaintenance(created.records, created.record.id, 'Alice', 'no', base).error) {
    throw new Error('The requester was allowed to reject their own request');
  }
  const rejected = rejectMaintenance(created.records, created.record.id, 'Bob', 'Missing change ticket', base);
  if (rejected.error || !rejected.record || rejected.record.status !== 'Rejected' || rejected.record.decisionNote !== 'Missing change ticket') {
    throw new Error(`Valid rejection failed: ${rejected.error}`);
  }
  if (!rejectMaintenance(rejected.records, created.record.id, 'Carol', '', base).error) {
    throw new Error('An already-rejected request was rejected again');
  }
  if (findActiveApproval(rejected.records, bssid)) {
    throw new Error('A rejected request still granted an active approval');
  }

  const revoked = revokeMaintenance(approved.records, created.record.id, new Date(baseMs + 4 * 60_000));
  if (revoked.error || revoked.record?.status !== 'Revoked') {
    throw new Error(`Valid revocation failed: ${revoked.error}`);
  }
  if (findActiveApproval(revoked.records, bssid, 'Connect to network', new Date(baseMs + 5 * 60_000))) {
    throw new Error('A revoked approval still granted access');
  }
  if (!revokeMaintenance(revoked.records, created.record.id, base).error) {
    throw new Error('An already-revoked request was revoked again');
  }

  let many = created.records;
  for (let index = 1; index < 5; index++) {
    const next = createMaintenanceRequest(many, { ...request, requester: `Requester ${index}` }, base);
    if (next.error) throw new Error(`Request ${index} failed: ${next.error}`);
    many = next.records;
  }
  if (!createMaintenanceRequest(many, { ...request, requester: 'Requester 6' }, base).error) {
    throw new Error('createMaintenanceRequest exceeded the active-per-BSSID cap');
  }
  if (getApprovalsForBssid(many, '0200000000AA').length !== 5 || countActiveApprovals(many, base) !== 5) {
    throw new Error('Approval lookup or active counting is incorrect');
  }

  const expiredRaw = [{
    ...created.record,
    id: 'stale-1',
    requestedAt: new Date(baseMs - 40 * 24 * 60 * 60 * 1000).toISOString(),
    expiresAt: new Date(baseMs - 40 * 24 * 60 * 60 * 1000 + 30 * 60_000).toISOString()
  }, {
    ...created.record,
    id: 'stale-1',
    requestedAt: new Date(baseMs - 40 * 24 * 60 * 60 * 1000).toISOString(),
    expiresAt: new Date(baseMs - 40 * 24 * 60 * 60 * 1000 + 30 * 60_000).toISOString()
  }];
  const normalized = normalizeMaintenanceApprovals(expiredRaw, base);
  if (normalized.length !== 2 || normalized[0].id === normalized[1].id || normalized[0].status !== 'Expired') {
    throw new Error('Normalization did not regenerate duplicate IDs or expire stale Pending records');
  }

  const pruned = createMaintenanceRequest(normalized, { ...request, requester: 'Dana' }, base);
  if (pruned.error || pruned.records.length !== 1) {
    throw new Error(`Terminal records were not pruned after 30 days: ${pruned.error}`);
  }
  if (!pruned.records[0].id.startsWith('MAINT-')) {
    throw new Error('Pruning retained the stale records instead of the new request');
  }
});

// 24. Operator roles and the SHA-256 audit chain
runTest('T24: Operator Roles & Hash-Chained Audit Trail', () => {
  if (sha256Hex('') !== 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') {
    throw new Error('SHA-256 empty-string vector failed');
  }
  if (sha256Hex('abc') !== 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') {
    throw new Error('SHA-256 "abc" vector failed');
  }
  if (sha256Hex('The quick brown fox jumps over the lazy dog') !== 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592') {
    throw new Error('SHA-256 fox vector failed');
  }
  if (sha256Hex('a'.repeat(55)) === sha256Hex('a'.repeat(56)) || sha256Hex('a'.repeat(1000)).length !== 64) {
    throw new Error('SHA-256 padding-boundary determinism failed');
  }

  if (normalizeOperatorRole('Viewer') !== 'Viewer' || normalizeOperatorRole('root') !== 'Administrator') {
    throw new Error('normalizeOperatorRole did not bound unknown values');
  }
  if (!can('Viewer', 'view') || can('Viewer', 'connect_network') || can('Viewer', 'edit_assets')) {
    throw new Error('Viewer capabilities are incorrect');
  }
  if (!can('Auditor', 'connect_network') || !can('Auditor', 'request_maintenance') || can('Auditor', 'approve_maintenance') || can('Auditor', 'delete_assets')) {
    throw new Error('Auditor capabilities are incorrect');
  }
  if (!can('Administrator', 'approve_maintenance') || !can('Administrator', 'manage_projects') || !can('Administrator', 'clear_logs')) {
    throw new Error('Administrator capabilities are incomplete');
  }
  let denied = false;
  try { requireCapability('Viewer', 'connect_network', 'Connecting'); } catch { denied = true; }
  if (!denied) throw new Error('requireCapability allowed a Viewer connection');
  requireCapability('Auditor', 'connect_network', 'Connecting');
  if (sanitizeOperatorName('  \u0000 Alice \n Smith ') !== 'Alice Smith' || sanitizeOperatorName('') !== 'Local operator' || sanitizeOperatorName('x'.repeat(120)).length !== 80) {
    throw new Error('sanitizeOperatorName did not sanitize or bound the name');
  }

  const start = new Date('2026-10-02T09:00:00.000Z');
  const created = createAuditChain(start);
  if (created.version !== 1 || !created.chainId.startsWith('AUD-') || created.records.length !== 0 || created.createdAt !== start.toISOString()) {
    throw new Error('createAuditChain did not build a genesis chain');
  }
  if (verifyAuditChain(created).valid !== true || headHashOf(created) !== genesisHash(created.chainId)) {
    throw new Error('The empty chain did not verify against its genesis hash');
  }

  const first = appendAuditRecord(created, {
    action: 'ASSET_SAVE',
    subject: '02:00:00:00:00:AA',
    details: 'Saved a registry asset.'
  }, 'Alice Auditor', 'Auditor', start);
  if (first.error || !first.record) throw new Error(`First append failed: ${first.error}`);
  if (first.record.seq !== 1 || first.record.prevHash !== genesisHash(created.chainId) || first.record.hash.length !== 64 || first.record.timestamp !== start.toISOString()) {
    throw new Error('The first audit record is not linked to the genesis hash');
  }

  const second = appendAuditRecord(first.state, {
    action: 'MAINTENANCE_APPROVE',
    subject: 'QA-Lab (02:00:00:00:00:AA)',
    details: 'Approved request MAINT-1.'
  }, 'Bob Approver', 'Administrator', new Date(start.getTime() + 60_000));
  if (second.error || !second.record || second.record.seq !== 2 || second.record.prevHash !== first.record.hash) {
    throw new Error('The second audit record did not link to the first');
  }
  if (!verifyAuditChain(second.state).valid || verifyAuditChain(second.state).checked !== 2) {
    throw new Error('The two-record chain did not verify');
  }
  if (headHashOf(second.state) !== second.record.hash) {
    throw new Error('headHashOf did not return the latest hash');
  }

  const roundTrip = normalizeAuditChain(JSON.parse(JSON.stringify(second.state)));
  if (!verifyAuditChain(roundTrip).valid || roundTrip.records[1].actor !== 'Bob Approver') {
    throw new Error('A JSON round-trip did not preserve the chain');
  }

  const modified = normalizeAuditChain({
    ...second.state,
    records: second.state.records.map((record, index) => index === 0 ? { ...record, details: 'Altered after signing.' } : record)
  });
  if (verifyAuditChain(modified).valid || verifyAuditChain(modified).brokenAt !== 1) {
    throw new Error('A modified record was not detected');
  }

  const deleted = normalizeAuditChain({ ...second.state, records: [second.state.records[1]] });
  if (verifyAuditChain(deleted).valid || verifyAuditChain(deleted).brokenAt !== 1) {
    throw new Error('A deleted record was not detected');
  }

  const reordered = normalizeAuditChain({ ...second.state, records: [second.state.records[1], second.state.records[0]] });
  if (verifyAuditChain(reordered).valid) {
    throw new Error('A reordered chain was not detected');
  }

  const unlinked = normalizeAuditChain({
    ...second.state,
    records: second.state.records.map((record, index) => index === 1 ? { ...record, prevHash: '0'.repeat(64) } : record)
  });
  if (verifyAuditChain(unlinked).valid || verifyAuditChain(unlinked).brokenAt !== 2) {
    throw new Error('A broken hash link was not detected');
  }

  const unsupported = normalizeAuditChain({
    ...second.state,
    records: second.state.records.map((record, index) => index === 0 ? { ...record, action: 'INJECT' } : record)
  });
  if (unsupported.records[0].action !== 'UNSUPPORTED' || verifyAuditChain(unsupported).valid) {
    throw new Error('An unsupported action was not retained and rejected');
  }

  const unsanitized = appendAuditRecord(created, {
    action: 'CONNECT_ATTEMPT',
    subject: 's'.repeat(300),
    details: 'd'.repeat(600)
  }, '   ', 'Viewer', start);
  if (unsanitized.error || !unsanitized.record || unsanitized.record.actor !== 'Local operator' || unsanitized.record.subject.length !== 200 || unsanitized.record.details.length !== 500) {
    throw new Error('Audit text fields were not sanitized or bounded');
  }
  if (!appendAuditRecord(created, { action: 'ASSET_SAVE', subject: '', details: '' }, 'Alice', 'Auditor', start).error) {
    throw new Error('An audit record without a subject was accepted');
  }
  if (!appendAuditRecord(created, { action: 'NOPE' as any, subject: 'x', details: '' }, 'Alice', 'Auditor', start).error) {
    throw new Error('An unsupported audit action was accepted');
  }

  const fullChain = {
    ...created,
    records: Array.from({ length: MAX_AUDIT_RECORDS }, (_, index) => ({ ...first.record!, seq: index + 1 }))
  };
  if (!appendAuditRecord(fullChain, { action: 'ASSET_SAVE', subject: 'x', details: '' }, 'Alice', 'Auditor', start).error) {
    throw new Error('The audit chain cap was not enforced');
  }

  const rotated = resetAuditChain(second.state, 'Alice Auditor', 'Administrator', start);
  if (rotated.chainId === second.state.chainId || rotated.records.length !== 1 || rotated.records[0].action !== 'AUDIT_RESET') {
    throw new Error('resetAuditChain did not create a new chain with a reset record');
  }
  if (!rotated.records[0].details.includes(second.state.chainId) || !rotated.records[0].details.includes(headHashOf(second.state))) {
    throw new Error('The reset record did not archive the previous chain head');
  }
  if (!verifyAuditChain(rotated).valid) {
    throw new Error('The rotated chain did not verify');
  }
});

// 25. Local operations alerts
runTest('T25: Alert Rules, Deduplication & Acknowledgement', () => {
  const t0 = new Date('2026-10-03T10:00:00.000Z');
  const t1 = new Date(t0.getTime() + 5 * 60_000);
  const t2 = new Date(t0.getTime() + 10 * 60_000);
  const clean = {
    bssid: '02:00:00:00:00:01',
    ssid: 'Clean',
    security: 'WPA3-Personal (SAE)',
    cipher: 'GCMP-256',
    pmfRequired: true,
    pmfInformationAvailable: true,
    wpsEnabled: false,
    wpsLocked: false
  };
  const base = (overrides: Record<string, any> = {}) => ({ ...clean, ...overrides }) as any;
  const asset = (macAddress: string, overrides: Record<string, any> = {}) => ({
    macAddress,
    classification: 'Corporate',
    approvalStatus: 'Approved',
    ...overrides
  }) as any;

  if (evaluateAlerts([], []).length !== 0) {
    throw new Error('evaluateAlerts invented alerts without observations');
  }
  if (evaluateAlerts([base()], []).length !== 0) {
    throw new Error('An unenrolled, clean access point raised an alert');
  }

  const rogue = evaluateAlerts([base({ bssid: '0200000000aa', isRogueCandidate: true, rogueEvidence: ['BSSID mismatch'], rogueConfidence: 92 })], []);
  if (rogue.length !== 1 || rogue[0].ruleId !== 'ROGUE_AP' || rogue[0].severity !== 'Critical' || rogue[0].bssid !== '02:00:00:00:00:AA') {
    throw new Error('The rogue rule did not fire or canonicalize the BSSID');
  }
  if (!rogue[0].detail.includes('BSSID mismatch')) {
    throw new Error('The rogue alert did not use the first evidence line');
  }

  const duplicated = evaluateAlerts([
    base({ bssid: '02:00:00:00:00:02', isRogueCandidate: true }),
    base({ bssid: '02:00:00:00:00:02', isRogueCandidate: true })
  ], []);
  if (duplicated.length !== 1) {
    throw new Error('Duplicate observations produced duplicate alert candidates');
  }

  const openAa = asset('02:00:00:00:00:03');
  const weak = evaluateAlerts([base({ bssid: '02:00:00:00:00:03', security: 'Open', cipher: 'None' })], [openAa]);
  if (weak.length !== 1 || weak[0].ruleId !== 'WEAK_ENCRYPTION' || weak[0].severity !== 'High') {
    throw new Error('An enrolled open network did not raise a high-severity weak-encryption alert');
  }
  const wep = evaluateAlerts([base({ bssid: '02:00:00:00:00:04', security: 'WEP-64/128', cipher: 'WEP' })], [asset('02:00:00:00:00:04')]);
  if (!wep.some(candidate => candidate.ruleId === 'WEAK_ENCRYPTION' && candidate.severity === 'Critical')) {
    throw new Error('WEP did not raise a critical alert');
  }
  const tkip = evaluateAlerts([base({ bssid: '02:00:00:00:00:05', security: 'WPA-TKIP', cipher: 'TKIP' })], [asset('02:00:00:00:00:05')]);
  if (!tkip.some(candidate => candidate.ruleId === 'WEAK_ENCRYPTION' && candidate.severity === 'High')) {
    throw new Error('TKIP did not raise a high-severity alert');
  }

  const unapproved = evaluateAlerts([base({ bssid: '02:00:00:00:00:06' })], [asset('02:00:00:00:00:06', { approvalStatus: 'Decommissioned' })]);
  if (unapproved.length !== 1 || unapproved[0].ruleId !== 'UNAPPROVED_ASSET' || unapproved[0].severity !== 'High') {
    throw new Error('A decommissioned asset did not raise an unapproved-asset alert');
  }

  const pmf = evaluateAlerts([base({ bssid: '02:00:00:00:00:07', pmfRequired: false, pmfInformationAvailable: true })], [asset('02:00:00:00:00:07')]);
  if (!pmf.some(candidate => candidate.ruleId === 'PMF_NOT_REQUIRED' && candidate.severity === 'Medium')) {
    throw new Error('Missing PMF did not raise a medium alert');
  }
  const pmfUnknown = evaluateAlerts([base({ bssid: '02:00:00:00:00:08', pmfRequired: false, pmfInformationAvailable: false })], [asset('02:00:00:00:00:08')]);
  if (pmfUnknown.some(candidate => candidate.ruleId === 'PMF_NOT_REQUIRED')) {
    throw new Error('An unobserved PMF state raised an alert');
  }

  const wps = evaluateAlerts([base({ bssid: '02:00:00:00:00:09', wpsEnabled: true, wpsLocked: true })], [asset('02:00:00:00:00:09')]);
  const wpsAlert = wps.find(candidate => candidate.ruleId === 'WPS_ENABLED');
  if (!wpsAlert || wpsAlert.severity !== 'Medium' || !wpsAlert.detail.includes('locked')) {
    throw new Error('WPS did not raise a medium alert or report its lock state');
  }

  let state = reconcileAlerts([], rogue.concat(weak), t0);
  if (state.added !== 2 || state.records.length !== 2 || state.records.some(record => record.status !== 'Open' || !record.id.startsWith('ALT-'))) {
    throw new Error('Initial reconciliation did not create open alerts');
  }
  const firstAlert = state.records[0];
  const rogueAlert = state.records.find(record => record.ruleId === 'ROGUE_AP')!;
  const weakAlert = state.records.find(record => record.ruleId === 'WEAK_ENCRYPTION')!;
  if (!rogueAlert || !weakAlert) {
    throw new Error('The initial reconciliation did not retain both rule alerts');
  }
  if (firstAlert.firstSeenAt !== t0.toISOString() || firstAlert.lastSeenAt !== t0.toISOString()) {
    throw new Error('Initial alert timestamps are incorrect');
  }

  const stable = reconcileAlerts(state.records, rogue.concat(weak), t1);
  if (stable.added !== 0 || stable.resolved !== 0 || stable.updated !== 0 || stable.records.length !== 2) {
    throw new Error('An unchanged observation set churned alert state');
  }
  if (stable.records.find(record => record.id === firstAlert.id)?.lastSeenAt !== t1.toISOString()) {
    throw new Error('lastSeenAt did not advance on a repeat observation');
  }

  const changed = reconcileAlerts(stable.records, rogue.concat([{ ...weak[0], detail: 'Changed cipher detail.' }]), t2);
  if (changed.updated !== 1) {
    throw new Error('A material alert change was not counted');
  }

  const acked = acknowledgeAlert(changed.records, weakAlert.id, 'Alice Auditor', t1);
  if (acked.error || !acked.record || acked.record.status !== 'Acknowledged' || acked.record.acknowledgedBy !== 'Alice Auditor' || acked.record.acknowledgedAt !== t1.toISOString()) {
    throw new Error(`Acknowledging an open alert failed: ${acked.error}`);
  }
  if (!acknowledgeAlert(acked.records, weakAlert.id, 'Bob', t2).error) {
    throw new Error('An acknowledged alert was acknowledged twice');
  }
  if (!acknowledgeAlert(changed.records, weakAlert.id, 'A', t1).error) {
    throw new Error('A one-character acknowledging analyst was accepted');
  }

  const afterAck = reconcileAlerts(acked.records, rogue.concat(weak), t2);
  if (afterAck.records.find(record => record.id === weakAlert.id)?.status !== 'Acknowledged') {
    throw new Error('Reconciliation cleared an acknowledgement');
  }

  const resolvedState = reconcileAlerts(afterAck.records, rogue, t2);
  const resolvedRecord = resolvedState.records.find(record => record.id === weakAlert.id);
  if (resolvedState.resolved !== 1 || !resolvedRecord || resolvedRecord.status !== 'Resolved' || resolvedRecord.resolvedAt !== t2.toISOString()) {
    throw new Error('A vanished condition was not resolved');
  }
  if (!acknowledgeAlert(resolvedState.records, weakAlert.id, 'Bob', t2).error) {
    throw new Error('A resolved alert was acknowledged');
  }

  const summary = summarizeAlerts(resolvedState.records);
  if (summary.active !== 1 || summary.critical !== 1 || summary.open !== 1 || summary.acknowledged !== 0) {
    throw new Error('Alert summary counts are incorrect');
  }

  if (normalizeAlerts('nope').length !== 0 ||
      normalizeAlerts([null, 42, {}, { bssid: 'nope', ruleId: 'ROGUE_AP', severity: 'Critical', status: 'Open', firstSeenAt: t0.toISOString(), lastSeenAt: t0.toISOString() }]).length !== 0) {
    throw new Error('normalizeAlerts accepted malformed records');
  }
  const duplicateIds = normalizeAlerts([
    { ...firstAlert, id: 'same' },
    { ...firstAlert, id: 'same' }
  ], t0);
  if (duplicateIds.length !== 2 || duplicateIds[0].id === duplicateIds[1].id) {
    throw new Error('normalizeAlerts did not regenerate duplicate IDs');
  }
  const stale = normalizeAlerts([
    { ...firstAlert, id: 'old', status: 'Resolved', resolvedAt: new Date(t0.getTime() - 40 * 24 * 60 * 60 * 1000).toISOString() }
  ], t0);
  if (stale.length !== 0) {
    throw new Error('normalizeAlerts retained a resolved alert past 30 days');
  }

  const terminal = Array.from({ length: MAX_ALERTS }, (_, index) => ({
    ...firstAlert,
    id: `ALT-CAP-${index}`,
    bssid: `02:00:00:01:${Math.floor(index / 256).toString(16).padStart(2, '0').toUpperCase()}:${(index % 256).toString(16).padStart(2, '0').toUpperCase()}`,
    ruleId: 'WPS_ENABLED' as const,
    status: 'Resolved' as const,
    resolvedAt: t0.toISOString()
  }));
  const capped = reconcileAlerts(terminal, [rogue[0]], t2);
  if (capped.records.length !== MAX_ALERTS || !capped.records.some(record => record.ruleId === 'ROGUE_AP' && record.status === 'Open')) {
    throw new Error('The alert cap dropped the new active alert or exceeded the limit');
  }
});

// 27. Bridge offline/token status classification used by the header pill and offline panel
runTest('T26: Bridge Offline & Token-Mismatch Status Views', () => {
  if (classifyBridgeError('HTTP 401: A valid per-launch bridge token is required.') !== 'token') {
    throw new Error('A 401 response was not classified as a token problem');
  }
  if (classifyBridgeError('The local WinWiFi bridge rejected this dashboard session.') !== 'token') {
    throw new Error('A token rejection message was not classified as a token problem');
  }
  if (classifyBridgeError('Failed to fetch http://127.0.0.1:38989/api/status') !== 'offline') {
    throw new Error('A network failure was not classified as offline');
  }
  if (classifyBridgeError('NetworkError when attempting to fetch resource.') !== 'offline') {
    throw new Error('A NetworkError was not classified as offline');
  }
  if (classifyBridgeError('Bridge timeout: Request to /api/status exceeded 5000ms.') !== 'timeout') {
    throw new Error('A timeout was not classified as a timeout');
  }
  if (classifyBridgeError('Something unexpected happened') !== 'unknown') {
    throw new Error('An unrecognized error was not classified as unknown');
  }

  const connected = bridgeStatusView('CONNECTED', null);
  if (connected.label !== 'Connected' || connected.tone !== 'ok') {
    throw new Error('The connected status view is not labelled Connected/ok');
  }
  const offline = bridgeStatusView('ERROR', 'offline');
  if (offline.label !== 'Offline' || offline.tone !== 'bad') {
    throw new Error('The offline status view is not labelled Offline/bad');
  }
  if (!offline.description.includes('--bridge --port 38989') || !offline.description.includes('start-dev.ps1')) {
    throw new Error('The offline description does not tell the operator how to start the bridge');
  }
  const tokenMismatch = bridgeStatusView('ERROR', 'token');
  if (tokenMismatch.label !== 'Token mismatch' || tokenMismatch.tone !== 'bad') {
    throw new Error('A token mismatch is not labelled in the header view');
  }
  if (!tokenMismatch.description.includes('bridge.token')) {
    throw new Error('The token-mismatch description does not point at the bridge token file');
  }
  const connecting = bridgeStatusView('CONNECTING', null);
  if (connecting.label !== 'Connecting' || connecting.tone !== 'busy') {
    throw new Error('The connecting status view is not labelled Connecting/busy');
  }
  const disconnected = bridgeStatusView('DISCONNECTED', null);
  if (disconnected.label !== 'Offline') {
    throw new Error('A disconnected bridge is not shown as Offline');
  }
});

// 28. Embedded bridge base URL resolution (desktop WebView2 / daemon-hosted tab)
runTest('T27: Embedded Bridge Base URL Resolution', () => {
  const fallback = 'http://127.0.0.1:38989';

  // Page served by the bridge itself on a dynamically chosen port: the serving
  // origin must win over any stale saved config.
  if (resolveBridgeBaseUrl('127.0.0.1', '38991', '', fallback) !== 'http://127.0.0.1:38991') {
    throw new Error('An embedded page did not adopt the serving bridge origin');
  }
  if (resolveBridgeBaseUrl('localhost', '38992', '?token=abc', fallback) !== 'http://localhost:38992') {
    throw new Error('An embedded page with a token did not adopt the serving origin');
  }

  // Vite dev-server pages keep the default/saved bridge URL.
  if (resolveBridgeBaseUrl('localhost', '5173', '', fallback) !== fallback) {
    throw new Error('A Vite dev page must keep the configured bridge URL');
  }
  if (resolveBridgeBaseUrl('127.0.0.1', '3000', '', fallback) !== fallback) {
    throw new Error('A port-3000 dev page must keep the configured bridge URL');
  }

  // An explicit port parameter (start-dev.ps1) overrides everything.
  if (resolveBridgeBaseUrl('localhost', '5173', '?port=39123&x=1', fallback) !== 'http://127.0.0.1:39123') {
    throw new Error('A port query parameter did not override the bridge URL');
  }
  if (resolveBridgeBaseUrl('localhost', '5173', '?port=not-a-port', fallback) !== fallback) {
    throw new Error('A malformed port parameter was accepted');
  }

  // Non-loopback hosts never adopt the page origin as a bridge.
  if (resolveBridgeBaseUrl('example.com', '8080', '', fallback) !== fallback) {
    throw new Error('A non-loopback page origin was treated as the bridge');
  }
  // Empty port (default http/https) is not a bridge origin.
  if (resolveBridgeBaseUrl('localhost', '', '', fallback) !== fallback) {
    throw new Error('A page without an explicit port was treated as the bridge');
  }
});

// 29. The desktop shell never shows bridge internals the user would have to type
runTest('T28: Desktop Shell Wording Hides Bridge Internals', () => {
  const forbidden = ['38989', 'token', 'vite_winwifi', 'bridge.token', 'http://', 'start-dev.ps1', 'dotnet run', '--port'];
  const states: Array<[Parameters<typeof bridgeStatusView>[0], Parameters<typeof bridgeStatusView>[1]]> = [
    ['CONNECTED', null],
    ['CONNECTING', null],
    ['DISCONNECTED', null],
    ['ERROR', 'offline'],
    ['ERROR', 'token'],
    ['ERROR', 'timeout'],
    ['ERROR', 'unknown']
  ];
  for (const [state, kind] of states) {
    const shell = bridgeStatusView(state, kind, true);
    const text = `${shell.label} ${shell.title} ${shell.description}`.toLowerCase();
    for (const needle of forbidden) {
      if (text.includes(needle)) {
        throw new Error(`The desktop shell exposed "${needle}" while ${state}/${kind ?? 'none'}: ${shell.description}`);
      }
    }
  }

  // A developer running the dashboard in a browser still gets the exact command.
  const devOffline = bridgeStatusView('ERROR', 'offline', false);
  if (!devOffline.description.includes('--bridge --port 38989') || !devOffline.description.includes('start-dev.ps1')) {
    throw new Error('The developer offline description no longer explains how to start the bridge');
  }
  const devToken = bridgeStatusView('ERROR', 'token', false);
  if (!devToken.description.includes('VITE_WINWIFI_BRIDGE_TOKEN')) {
    throw new Error('The developer token description no longer points at the dev token');
  }

  // Without a browser window (Node test host) the shell flag stays false.
  if (isEmbeddedDashboard()) {
    throw new Error('isEmbeddedDashboard must be false when no window.location exists');
  }
});

// 29. Polling fallback must keep native incidents alive
runTest('T29: Polling Fallback Re-fetches Incidents And Drift Independently', () => {
  const nativeSetInterval = globalThis.setInterval;
  const ticks: Array<() => void> = [];
  (globalThis as any).setInterval = (cb: () => void) => { ticks.push(cb); return 1 as any; };

  const client = new (NativeBridgeClient as any)();
  try {
    let incidentCalls = 0;
    let driftCalls = 0;
    client.state = 'CONNECTED';
    client.getNetworks = async () => [];
    // The counter is incremented inside the async body, which runs synchronously
    // up to its first await, so the assertion below needs no timer pump.
    client.getIncidents = async () => { incidentCalls++; return [{ id: 'NATIVE-1' }]; };
    client.getDrifts = async () => { driftCalls++; return [{ id: 'DRIFT-1' }]; };

    client.startPolling();
    if (ticks.length !== 1) throw new Error('startPolling did not register a fallback tick');

    ticks[0]();
    if (incidentCalls !== 1) {
      throw new Error(
        `The polling fallback re-fetched incidents ${incidentCalls} times. While SSE is down it must fetch`
        + ' incidents every tick, otherwise every native incident is erased from the store.'
      );
    }
    if (driftCalls !== 1) {
      throw new Error('The polling fallback does not re-fetch configuration drift while SSE is down');
    }

    // One endpoint failing must not suppress the other.
    incidentCalls = 0;
    driftCalls = 0;
    client.getNetworks = () => Promise.reject(new Error('networks unavailable'));
    ticks[0]();
    if (incidentCalls !== 1) {
      throw new Error('A failing networks endpoint suppressed the incidents poll');
    }
    if (driftCalls !== 1) {
      throw new Error('A failing networks endpoint suppressed the drift poll');
    }

    // A failed drift request must be logged, never delivered to listeners: the
    // change-intelligence panel would read an empty delivery as "nothing changed".
    const bridgeSource = fs.readFileSync(path.join(__dirname, '../src/services/bridgeClient.ts'), 'utf8');
    const pollingStart = bridgeSource.indexOf('private startPolling');
    const pollingEnd = bridgeSource.indexOf('\n  private ', pollingStart + 1);
    const pollingBlock = bridgeSource.slice(pollingStart, pollingEnd < 0 ? undefined : pollingEnd);
    if (!/drifts\.status === 'fulfilled'[\s\S]{0,220}?this\.driftListeners\.forEach/.test(pollingBlock)) {
      throw new Error('The polling fallback delivers drift without checking that the request succeeded');
    }

    // The App-level half of the same defect: incidents must never be reconciled
    // with a placeholder empty finding list, which drops every native incident.
    const appSource = fs.readFileSync(path.join(__dirname, '../src/App.tsx'), 'utf8');
    if (/reconcileLiveIncidents\(\s*\[\s*\]/.test(appSource)) {
      throw new Error('App.tsx still reconciles incidents with a hardcoded empty findings array');
    }
  } finally {
    (globalThis as any).setInterval = nativeSetInterval;
    client.stopPolling();
  }
});

runTest('T30: Native Configuration Drift Reaches The Dashboard', () => {
  const NativeEventSource = globalThis.EventSource;
  const listeners = new Map<string, (event: { data: string }) => void>();
  class RecordingEventSource {
    onopen: (() => void) | null = null;
    onerror: ((event: Event) => void) | null = null;
    constructor(_url: string) { listeners.clear(); }
    addEventListener(event: string, listener: (payload: any) => void) { listeners.set(event, listener); }
    close() {}
  }

  const drift = {
    id: 'DRIFT-1',
    bssid: '00:11:22:33:44:55',
    ssid: 'Office',
    timestamp: '2026-10-28 09:00:00',
    type: 'channel_shift',
    title: 'Operating Channel Shift',
    before: 'Channel 6 (2.4 GHz)',
    after: 'Channel 1 (2.4 GHz)',
    riskImpact: 'LOW',
  };

  const client = new (NativeBridgeClient as any)();
  try {
    (globalThis as any).EventSource = RecordingEventSource;
    client.state = 'CONNECTED';

    // The polled endpoint contract: the bridge serves drift at /api/drifts.
    const requested: string[] = [];
    client.request = async (path: string) => { requested.push(path); return [drift]; };
    client.getDrifts();
    if (!requested.includes('/api/drifts')) {
      throw new Error(`getDrifts() did not request /api/drifts (requested: ${requested.join(', ') || 'nothing'})`);
    }

    const received: { value: any[] | null } = { value: null };
    const unsubscribe = client.onDrifts((value: any[]) => { received.value = value; });
    client.initEventSource();

    const scanResult = listeners.get('scan_result');
    if (!scanResult) throw new Error('The bridge client never subscribed to scan_result events');
    scanResult({ data: JSON.stringify({ accessPoints: [], incidents: [], drifts: [drift] }) });
    if (!received.value || received.value.length !== 1 || received.value[0].type !== 'channel_shift') {
      throw new Error('An SSE scan_result payload carrying drifts was not delivered to drift listeners');
    }

    received.value = null;
    scanResult({ data: JSON.stringify({ accessPoints: [], incidents: [] }) });
    if (received.value !== null) {
      throw new Error('A scan_result payload without drifts overwrote the drift listeners');
    }

    unsubscribe();
    received.value = null;
    scanResult({ data: JSON.stringify({ accessPoints: [], incidents: [], drifts: [drift] }) });
    if (received.value !== null) {
      throw new Error('Unsubscribing from onDrifts left a live listener behind');
    }

    // The App-level half: drift must feed the change-intelligence state, which
    // used to be produced only by the never-called browser-side threat engine.
    const appSource = fs.readFileSync(path.join(__dirname, '../src/App.tsx'), 'utf8');
    if (!/bridgeClient\.onDrifts\(/.test(appSource)) {
      throw new Error('App.tsx never subscribes to native configuration drift');
    }
    if (!/setSecurityChanges\(\s*drifts/.test(appSource)) {
      throw new Error('The drift subscription in App.tsx does not update the security change state');
    }
  } finally {
    client.disconnect();
    (globalThis as any).EventSource = NativeEventSource;
  }
});

runTest('T31: Station Client Records Map Without Inventing An Association', () => {
  const native = {
    macAddress: '02:11:22:33:44:55',
    vendor: 'Test Fixture',
    associatedApBssid: '10:20:30:40:50:60',
    associatedApSsid: 'Client Fixture',
    rssi: -65,
    channel: 6,
    packetsCount: 3,
    firstSeen: '2026-10-28 09:00:00',
    lastSeen: '2026-10-28 09:00:05',
    probeRequests: ['Office'],
    isAssociated: true,
    isRandomizedMac: true
  };
  const mapped = mapStationClients([native]);
  if (mapped.length !== 1) throw new Error('A native station record was not mapped to a client device');
  const client = mapped[0];
  if (client.apBssid !== '10:20:30:40:50:60' || client.connectedSsid !== 'Client Fixture') {
    throw new Error(`The native association was not carried over: ${JSON.stringify(client)}`);
  }
  if (client.packetsSent !== 3 || client.probes[0] !== 'Office' || !client.isAssociated) {
    throw new Error(`Native counters and probes were dropped: ${JSON.stringify(client)}`);
  }
  // Windows never reports a station rate, so nothing may claim one.
  if (client.dataRateMbps !== 0) throw new Error('A station data rate was invented for a record that has none');

  // A scan-derived placeholder is not an association and must not render as one.
  const unproven = mapStationClients([{
    macAddress: '02:AA:AA:AA:AA:AA',
    vendor: 'Unknown',
    associatedApBssid: 'Not Associated (Active Probing)',
    associatedApSsid: 'Searching...',
    packetsCount: 1,
    isAssociated: false
  }]);
  if (unproven.length !== 1 || unproven[0].apBssid !== '' || unproven[0].isAssociated) {
    throw new Error(`An unproven association was rendered as a real access point: ${JSON.stringify(unproven[0])}`);
  }

  const dashboardShaped = mapStationClients([{
    macAddress: '02:BB:BB:BB:BB:BB',
    vendor: 'Unknown',
    apBssid: '10:20:30:40:50:60',
    connectedSsid: 'Client Fixture',
    rssi: -50,
    packetsSent: 7,
    dataRateMbps: 0,
    lastSeen: '2026-10-28 09:00:05',
    probes: []
  }]);
  if (dashboardShaped.length !== 1 || dashboardShaped[0].packetsSent !== 7) {
    throw new Error('The dashboard-shaped client record no longer round-trips through the mapper');
  }

  const duplicated = mapStationClients([native, { ...native }, { macAddress: 'not-a-mac' }]);
  if (duplicated.length !== 1) {
    throw new Error(`Duplicate and malformed station records were not collapsed to one client (${duplicated.length})`);
  }

  const appSource = fs.readFileSync(path.join(__dirname, '../src/App.tsx'), 'utf8');
  if (!/bridgeClient\.onClients\(/.test(appSource)) {
    throw new Error('App.tsx never subscribes to the native station client stream');
  }
});

console.log(`\nResults: ${passedCount}/${totalCount} tests passed.\n`);

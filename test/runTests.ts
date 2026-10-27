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
  const engine = WifiEngine.getInstance();
  const pcap = PcapService.getInstance();
  const benchmarkAps = engine.getBenchmarkAccessPoints();
  const testPackets = engine.generatePackets(benchmarkAps);
  const binaryBytes = pcap.exportBinaryPcap(testPackets.slice(0, 5));
  const parsed = pcap.parseBinaryPcap(binaryBytes.buffer);
  if (parsed.packets.length !== 5) {
    throw new Error(`Expected 5 packets, got ${parsed.packets.length}`);
  }
  if (!parsed.summary || parsed.summary.totalPackets !== 5) {
    throw new Error('Summary mismatch');
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

// 4. EAPOL Cryptographic Handshake & Hashcat 22000
runTest('T4: Cryptographic Handshake & Hashcat 22000 Structure', () => {
  const engine = WifiEngine.getInstance();
  const benchmarkAps = engine.getBenchmarkAccessPoints();
  const apWithHandshake = benchmarkAps.find(a => a.handshake);
  if (!apWithHandshake || !apWithHandshake.handshake) {
    throw new Error('No handshake in benchmark');
  }
  const hs = apWithHandshake.handshake;
  if (!hs.hashcatFormat?.startsWith('WPA*02*')) {
    throw new Error(`Invalid Hashcat prefix: ${hs.hashcatFormat ?? '(missing)'}`);
  }
  if (!hs.capturedSteps || hs.capturedSteps.length < 2) {
    throw new Error('Incomplete handshake messages');
  }
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

// 6. SQLite Query Engine
runTest('T6: SQLite Client Storage & SQL Terminal', () => {
  const engine = WifiEngine.getInstance();
  const db = SqliteDatabaseService.getInstance();
  const benchmarkAps = engine.getBenchmarkAccessPoints();
  
  const resWhere = db.executeQuery('SELECT * FROM access_points WHERE score < 50;', benchmarkAps);
  const resLimit = db.executeQuery('SELECT ssid, bssid, channel FROM access_points ORDER BY channel LIMIT 3;', benchmarkAps);
  
  if (resWhere.rowCount === 0) throw new Error('WHERE query returned 0 rows');
  if (resLimit.rowCount !== 3) throw new Error(`LIMIT query returned ${resLimit.rowCount} rows`);
});

// 7. NIST SP 800-153 Policy & Rogue AP Engine
runTest('T7: NIST SP 800-153 Policy & Rogue AP Engine', () => {
  const engine = WifiEngine.getInstance();
  const benchmarkAps = engine.getBenchmarkAccessPoints();
  const rogue = benchmarkAps.find(a => a.isRogueCandidate);
  const wep = benchmarkAps.find(a => a.security.includes('WEP'));
  
  if (!rogue) throw new Error('Rogue candidate not detected');
  if (!wep || wep.securityScore > 40) throw new Error('WEP score not penalized appropriately');
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

// 9. Station / Client Tracking Source of Truth
runTest('T9: Station Observer & Association State Mapping', () => {
  const engine = WifiEngine.getInstance();
  const benchmarkAps = engine.getBenchmarkAccessPoints();
  const allClients = benchmarkAps.flatMap(a => a.clients);
  if (allClients.length === 0) throw new Error('No client stations available in benchmark');

  for (const client of allClients) {
    if (!client.macAddress || !client.vendor) throw new Error('Client record missing MAC or Vendor');
    if (typeof client.rssi !== 'number' || client.rssi > 0) throw new Error(`Invalid client RSSI: ${client.rssi}`);
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
    const weakAp = WifiEngine.getInstance().getBenchmarkAccessPoints().find(ap => ap.security === 'Open');
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
    if (!/rejected this dashboard session/i.test(source)) throw new Error('Bridge client does not explain token rejection');
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

console.log(`\nResults: ${passedCount}/${totalCount} tests passed.\n`);

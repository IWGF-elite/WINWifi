import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { PcapService } from '../src/services/pcapParser';
import { WifiEngine } from '../src/services/wifiEngine';
import { SqliteDatabaseService } from '../src/services/storage';
import { ThreatEngine } from '../src/services/threatEngine';
import { NativeBridgeClient } from '../src/services/bridgeClient';

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

console.log(`\nResults: ${passedCount}/${totalCount} tests passed.\n`);

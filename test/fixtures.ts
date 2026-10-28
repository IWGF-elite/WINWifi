import { AccessPoint } from '../src/types';

const beaconCount = 4200;
const dataPacketCount = 18000;

interface FixtureOptions {
  bssid: string;
  ssid: string;
  security: AccessPoint['security'];
  cipher: AccessPoint['cipher'];
  rssi: number;
  channel: number;
  band: AccessPoint['band'];
  standard: AccessPoint['standard'];
  vendor: string;
  securityScore: number;
  wpsEnabled?: boolean;
  pmfRequired?: boolean;
  isRogueCandidate?: boolean;
  clients?: AccessPoint['clients'];
  handshake?: AccessPoint['handshake'];
  issues?: AccessPoint['issues'];
}

const fixture = (options: FixtureOptions): AccessPoint => ({
  bssid: options.bssid,
  ssid: options.ssid,
  rssi: options.rssi,
  channel: options.channel,
  band: options.band,
  channelWidthMhz: options.band === '5 GHz' ? 80 : 20,
  security: options.security,
  cipher: options.cipher,
  wpsEnabled: options.wpsEnabled ?? false,
  wpsLocked: false,
  pmfRequired: options.pmfRequired ?? false,
  vendor: options.vendor,
  beaconCount,
  dataPacketCount,
  firstSeen: '10:02:14 AM',
  lastSeen: 'Just now',
  standard: options.standard,
  securityScore: options.securityScore,
  issues: options.issues ?? [],
  clients: options.clients ?? [],
  handshake: options.handshake,
  isRogueCandidate: options.isRogueCandidate
});

// Reference observations for engine tests only. These never enter a scan, a
// report or the project database; see the production rule in wifiEngine.ts.
export const FIXTURE_ACCESS_POINTS: AccessPoint[] = [
  fixture({
    bssid: 'AA:11:00:00:00:01',
    ssid: 'Fixture WPA3 Enterprise',
    security: 'WPA3-Enterprise',
    cipher: 'GCMP-256',
    rssi: -42,
    channel: 36,
    band: '5 GHz',
    standard: '802.11ax (Wi-Fi 6)',
    vendor: 'Fixture Vendor A',
    securityScore: 98,
    pmfRequired: true,
    handshake: {
      apBssid: 'AA:11:00:00:00:01',
      clientMac: 'AA:11:00:00:00:02',
      ssid: 'Fixture WPA3 Enterprise',
      type: 'WPA2 4-Way (EAPOL)',
      capturedSteps: ['M1', 'M2', 'M3', 'M4'],
      isComplete: true,
      replayCounterMatch: true,
      micVerified: true,
      capturedAt: '10:04:21 AM',
      anonce: 'A1B2C3D4E5F60718293A4B5C6D7E8F90',
      snonce: '0F1E2D3C4B5A69788796A5B4C3D2E1F0',
      micHex: '11223344556677889900AABBCCDDEEFF',
      qualityScore: 92,
      validationStatus: 'VALID',
      origin: 'IMPORTED'
    }
  }),
  fixture({
    bssid: 'AA:11:00:00:00:03',
    ssid: 'Fixture WPA2 Enterprise',
    security: 'WPA2-Enterprise (802.1X)',
    cipher: 'CCMP (AES)',
    rssi: -58,
    channel: 44,
    band: '5 GHz',
    standard: '802.11ac (Wi-Fi 5)',
    vendor: 'Fixture Vendor A',
    securityScore: 88,
    pmfRequired: true
  }),
  fixture({
    bssid: 'AA:11:00:00:00:04',
    ssid: 'Fixture WPA2 Enterprise',
    security: 'WPA2-Enterprise (802.1X)',
    cipher: 'CCMP (AES)',
    rssi: -71,
    channel: 1,
    band: '2.4 GHz',
    standard: '802.11n (Wi-Fi 4)',
    vendor: 'Fixture Vendor A',
    securityScore: 84,
    pmfRequired: true,
    clients: [
      {
        macAddress: 'AA:11:00:00:00:05',
        vendor: 'Fixture Vendor B',
        apBssid: 'AA:11:00:00:00:04',
        rssi: -74,
        packetsSent: 420,
        dataRateMbps: 144,
        lastSeen: 'Just now',
        probes: ['Fixture WPA2 Enterprise']
      }
    ]
  }),
  fixture({
    bssid: 'AA:11:00:00:00:06',
    ssid: 'Fixture WEP',
    security: 'WEP-64/128',
    cipher: 'WEP',
    rssi: -66,
    channel: 6,
    band: '2.4 GHz',
    standard: '802.11b/g',
    vendor: 'Fixture Vendor C',
    securityScore: 12,
    isRogueCandidate: true,
    issues: [
      {
        id: 'FIX-01',
        severity: 'CRITICAL',
        title: 'Obsolete Broken Cipher (WEP)',
        description: 'RC4 with a static 24-bit initialisation vector allows key recovery.',
        recommendation: 'Replace the network with WPA2 or WPA3.',
        nistRef: 'NIST SP 800-153'
      }
    ]
  }),
  fixture({
    bssid: 'AA:11:00:00:00:07',
    ssid: 'Fixture Open',
    security: 'Open',
    cipher: 'None',
    rssi: -45,
    channel: 11,
    band: '2.4 GHz',
    standard: '802.11n (Wi-Fi 4)',
    vendor: 'Fixture Vendor D',
    securityScore: 8,
    wpsEnabled: true,
    issues: [
      {
        id: 'FIX-02',
        severity: 'CRITICAL',
        title: 'Unauthenticated Open Network',
        description: 'Traffic is unencrypted and cannot be attributed to any subscriber.',
        recommendation: 'Deploy WPA3 or enterprise authentication.',
        nistRef: 'NIST SP 800-153'
      }
    ]
  })
];

const macBytes = (mac: string): number[] =>
  mac.split(':').map(part => {
    const byte = parseInt(part, 16);
    if (Number.isNaN(byte)) throw new Error(`Bad fixture MAC: ${mac}`);
    return byte;
  });

const ie = (tag: number, body: number[]): number[] => [tag, body.length, ...body];

export interface BeaconOptions {
  bssid: string;
  ssid: string;
  channel: number;
  /** Omitting the RSN element leaves the network Open or WEP, per the privacy bit. */
  akmSuiteType?: number;
  pmfRequired?: boolean;
  wpsEnabled?: boolean;
}

/** Beacon frame: 24-byte 802.11 header, fixed parameters, then SSID/DS/RSN elements. */
export const buildBeaconFrame = (options: BeaconOptions): Uint8Array => {
  const ap = macBytes(options.bssid);
  const ssidBytes = Array.from(new TextEncoder().encode(options.ssid));
  const privacy = options.akmSuiteType !== undefined || options.wpsEnabled;
  const bytes: number[] = [
    0x80, 0x00,
    0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ...ap,
    ...ap,
    0x00, 0x20,
    0, 0, 0, 0, 0, 0, 0, 0,
    0x64, 0x00,
    privacy ? 0x11 : 0x01, 0x00
  ];
  bytes.push(...ie(0, ssidBytes));
  bytes.push(...ie(1, [0x8c, 0x12, 0x98, 0x24]));
  bytes.push(...ie(3, [options.channel]));
  if (options.akmSuiteType !== undefined) {
    const caps = options.pmfRequired ? 0x80 : 0x00;
    bytes.push(...ie(48, [
      0x01, 0x00,
      0x00, 0x0f, 0xac, 0x04,
      0x01, 0x00,
      0x00, 0x0f, 0xac, 0x04,
      0x01, 0x00,
      0x00, 0x0f, 0xac, options.akmSuiteType,
      caps, 0x00
    ]));
  }
  if (options.wpsEnabled) {
    // Microsoft OUI 00:50:F2 with type 4 is the WPS descriptor element.
    bytes.push(...ie(221, [0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01]));
  }
  return new Uint8Array(bytes);
};

export interface EapolOptions {
  apBssid: string;
  clientMac: string;
  step: 'M1' | 'M2';
  nonce: number[];
  mic: number[];
  replayCounter: number;
}

/** Data frame carrying an LLC/SNAP-encapsulated EAPOL-Key message (M1 or M2). */
export const buildEapolFrame = (options: EapolOptions): Uint8Array => {
  const ap = macBytes(options.apBssid);
  const client = macBytes(options.clientMac);
  const fromAp = options.step === 'M1';
  // M1 asserts the Ack bit without a MIC; M2 asserts the MIC bit without Ack.
  const keyInfo = fromAp ? 0x0082 : 0x010a;
  const bytes: number[] = [
    0x08, 0x00,
    0x00, 0x00,
    ...(fromAp ? client : ap),
    ...(fromAp ? ap : client),
    ...ap,
    0x00, 0x20,
    // LLC/SNAP with EtherType 0x888E marks the payload as EAPOL.
    0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
    0x02, 0x03, 0x00, 0x5f,
    0x02,
    (keyInfo >> 8) & 0xff, keyInfo & 0xff,
    0x00, 0x10,
    0, 0, 0, 0, 0, 0, 0, options.replayCounter
  ];
  bytes.push(...options.nonce, ...new Array(16).fill(0), ...new Array(16).fill(0), ...options.mic, 0x00, 0x00);
  return new Uint8Array(bytes);
};

/** Ordinary LLC/SNAP data frame used to observe an associated station. */
export const buildDataFrame = (options: { apBssid: string; clientMac: string }): Uint8Array => {
  const ap = macBytes(options.apBssid);
  const client = macBytes(options.clientMac);
  const bytes: number[] = [
    0x08, 0x00,
    0x00, 0x00,
    ...ap,
    ...client,
    ...ap,
    0x00, 0x20,
    0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00
  ];
  return new Uint8Array(bytes);
};

/** libpcap global header plus an 8-byte radiotap preface per frame. */
export const buildRadiotapPcap = (frames: Uint8Array[]): ArrayBuffer => {
  const radiotapLength = 8;
  const total = 24 + frames.reduce((sum, frame) => sum + 16 + radiotapLength + frame.length, 0);
  const buffer = new ArrayBuffer(total);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 65535, true);
  view.setUint32(20, 127, true);
  let offset = 24;
  frames.forEach((frame, index) => {
    const captured = radiotapLength + frame.length;
    view.setUint32(offset, 1710000000 + index, true);
    view.setUint32(offset + 4, index * 1000, true);
    view.setUint32(offset + 8, captured, true);
    view.setUint32(offset + 12, captured, true);
    offset += 16;
    view.setUint16(offset + 2, radiotapLength, true);
    bytes.set(frame, offset + radiotapLength);
    offset += captured;
  });
  return buffer;
};

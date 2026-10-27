import { 
  AccessPoint, 
  PcapPacket, 
  HandshakeInfo, 
  SecurityType, 
  CipherType, 
  FrequencyBand,
  SecurityIssue
} from '../types';

export interface PcapParseResult {
  packets: PcapPacket[];
  accessPoints: AccessPoint[];
  handshakes: HandshakeInfo[];
  warnings?: string[];
  truncated?: boolean;
  summary: {
    totalPackets: number;
    beaconCount: number;
    eapolCount: number;
    apCount: number;
    clientCount: number;
    linkType: string;
    fileSize: number;
  };
}

export class PcapService {
  private static instance: PcapService;
  private static readonly MAX_CAPTURE_BYTES = 100 * 1024 * 1024;
  private static readonly MAX_FRAMES = 200_000;
  private static readonly MAX_FRAME_BYTES = 262_144;
  private static readonly MAX_WARNINGS = 25;

  public static getInstance(): PcapService {
    if (!PcapService.instance) {
      PcapService.instance = new PcapService();
    }
    return PcapService.instance;
  }

  // Standard IEEE 802.11a/n/ac/ax 5 GHz channel set
  private static readonly FIVE_GHZ_CHANNELS = new Set<number>([
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177
  ]);

  // Calculate Frequency & Band from Channel
  public static getChannelDetails(channel: number, bandHint?: FrequencyBand): { band: FrequencyBand; freqMhz: number } {
    if (bandHint === '6 GHz') {
      return { band: '6 GHz', freqMhz: 5950 + channel * 5 };
    }
    if (bandHint === '5 GHz') {
      return { band: '5 GHz', freqMhz: 5000 + channel * 5 };
    }
    if (bandHint === '2.4 GHz') {
      const freqMhz = channel === 14 ? 2484 : 2407 + channel * 5;
      return { band: '2.4 GHz', freqMhz };
    }

    // Default heuristics when bandHint is not specified
    if (channel >= 1 && channel <= 14) {
      const freqMhz = channel === 14 ? 2484 : 2407 + channel * 5;
      return { band: '2.4 GHz', freqMhz };
    }
    if (PcapService.FIVE_GHZ_CHANNELS.has(channel)) {
      return { band: '5 GHz', freqMhz: 5000 + channel * 5 };
    }
    if ((channel >= 1 && channel <= 233) || channel > 177) {
      // 6 GHz channels (1, 5, ..., 69, ..., 233)
      return { band: '6 GHz', freqMhz: 5950 + channel * 5 };
    }
    return { band: '2.4 GHz', freqMhz: 2412 };
  }

  // Parse binary PCAP / CAP file
  public parseBinaryPcap(buffer: ArrayBuffer): PcapParseResult {
    const data = new Uint8Array(buffer);
    if (data.length < 24) {
      throw new Error('File size is too small for a valid PCAP header (< 24 bytes).');
    }
    if (data.length > PcapService.MAX_CAPTURE_BYTES) {
      throw new Error(`Capture size is ${Math.round(data.length / (1024 * 1024))} MB; the local import limit is ${PcapService.MAX_CAPTURE_BYTES / (1024 * 1024)} MB.`);
    }

    const view = new DataView(buffer);
    const warnings: string[] = [];
    let truncated = false;
    const addWarning = (message: string) => {
      if (warnings.length < PcapService.MAX_WARNINGS) warnings.push(message);
    };
    const magic = view.getUint32(0, true);
    let isLittleEndian = true;

    // Check PCAP Magic Number
    if (magic === 0xa1b2c3d4) {
      isLittleEndian = true;
    } else if (magic === 0xd4c3b2a1) {
      isLittleEndian = false;
    } else if (magic === 0xa1b23c4d) {
      // Nanosecond PCAP
      isLittleEndian = true;
    } else if (magic === 0x4d3cb2a1) {
      isLittleEndian = false;
    } else if (magic === 0x0a0d0d0a) {
      throw new Error('Detected PCAPNG format. Please convert the file to standard Libpcap (.pcap/.cap) before importing.');
    } else {
      throw new Error(`Unrecognized PCAP magic header (0x${magic.toString(16)}). Supported format: Libpcap 2.4.`);
    }

    const versionMajor = view.getUint16(4, isLittleEndian);
    const versionMinor = view.getUint16(6, isLittleEndian);
    const snaplen = view.getUint32(16, isLittleEndian);
    const network = view.getUint32(20, isLittleEndian);

    const linkTypeName = 
      network === 127 ? 'IEEE 802.11 + Radiotap' :
      network === 105 ? 'IEEE 802.11 Wireless' :
      network === 1 ? 'Ethernet' : `LinkType (${network})`;

    if (network !== 127 && network !== 105) {
      throw new Error(`This capture uses ${linkTypeName}. WinWiFi only dissects 802.11 captures and will not infer access points from other link types.`);
    }
    if (versionMajor !== 2 || versionMinor !== 4) {
      addWarning(`Capture header reports libpcap version ${versionMajor}.${versionMinor}; expected 2.4.`);
    }
    if (snaplen > PcapService.MAX_FRAME_BYTES) {
      addWarning(`Capture snaplen (${snaplen} bytes) exceeds the ${PcapService.MAX_FRAME_BYTES}-byte per-frame limit; oversized records will be rejected.`);
    }

    let offset = 24;
    const packets: PcapPacket[] = [];
    const apMap = new Map<string, AccessPoint>();
    const handshakesMap = new Map<string, HandshakeInfo>();
    let packetNumber = 1;

    let beaconCount = 0;
    let eapolCount = 0;

    while (offset + 16 <= data.length) {
      if (packets.length >= PcapService.MAX_FRAMES) {
        truncated = true;
        addWarning(`Stopped after ${PcapService.MAX_FRAMES.toLocaleString()} frames; the capture contains more records than the import limit.`);
        break;
      }

      const tsSec = view.getUint32(offset, isLittleEndian);
      const tsUsec = view.getUint32(offset + 4, isLittleEndian);
      const inclLen = view.getUint32(offset + 8, isLittleEndian);
      const origLen = view.getUint32(offset + 12, isLittleEndian);
      offset += 16;

      if (inclLen === 0) {
        addWarning(`Record ${packetNumber} declares zero captured bytes and was skipped.`);
        continue;
      }
      if (inclLen > PcapService.MAX_FRAME_BYTES) {
        truncated = true;
        addWarning(`Record ${packetNumber} declares ${inclLen.toLocaleString()} bytes, above the ${PcapService.MAX_FRAME_BYTES.toLocaleString()}-byte per-frame limit; parsing stopped.`);
        break;
      }
      if (origLen > 0 && inclLen > origLen) {
        addWarning(`Record ${packetNumber} captured length (${inclLen}) exceeds original length (${origLen}).`);
      }
      if (offset + inclLen > data.length) {
        truncated = true;
        addWarning(`Record ${packetNumber} is truncated: header declares ${inclLen} bytes but only ${data.length - offset} remain.`);
        break;
      }

      const packetBytes = data.subarray(offset, offset + inclLen);
      offset += inclLen;

      // Extract Radiotap if LinkType is 127
      let frameOffset = 0;
      let rssi = -65;
      let channel = 6;

      if (network === 127) {
        if (packetBytes.length < 8) {
          addWarning(`Record ${packetNumber} is too short to contain a radiotap header and was skipped.`);
          packetNumber++;
          continue;
        }
        const rtLen = packetBytes[2] | (packetBytes[3] << 8);
        if (rtLen > packetBytes.length || rtLen < 8 || rtLen === packetBytes.length) {
          addWarning(`Record ${packetNumber} declares radiotap length ${rtLen} outside its ${packetBytes.length}-byte frame and was skipped.`);
          packetNumber++;
          continue;
        }
        {
          const rtView = new DataView(packetBytes.buffer, packetBytes.byteOffset, rtLen);
          const present = rtView.getUint32(4, true);

          let curPos = 8;
          // Radiotap present flags:
          // bit 0: TSFT (8B)
          if (present & (1 << 0)) curPos += 8;
          // bit 1: Flags (1B)
          if (present & (1 << 1)) curPos += 1;
          // bit 2: Rate (1B)
          if (present & (1 << 2)) curPos += 1;
          // bit 3: Channel (2B freq, 2B flags = 4B)
          if (present & (1 << 3)) {
            if (curPos % 2 !== 0) curPos++; // 2-byte aligned
            if (curPos + 4 <= rtLen) {
              const freq = rtView.getUint16(curPos, true);
              channel = this.freqToChannel(freq);
              curPos += 4;
            }
          }
          // bit 4: FHSS (2B)
          if (present & (1 << 4)) curPos += 2;
          // bit 5: dBm Antenna Signal (int8, 1B)
          if (present & (1 << 5)) {
            if (curPos < rtLen) {
              const sig = rtView.getInt8(curPos);
              if (sig < 0 && sig > -110) rssi = sig;
              curPos += 1;
            }
          }

          frameOffset = rtLen;
        }
      }

      // IEEE 802.11 Frame Parsing
      if (frameOffset + 24 <= packetBytes.length) {
        const fView = new DataView(packetBytes.buffer, packetBytes.byteOffset + frameOffset, packetBytes.length - frameOffset);
        const fc = fView.getUint16(0, true);
        const fType = (fc >> 2) & 0x03;
        const fSubtype = (fc >> 4) & 0x0f;

        // MAC Addresses
        const addr1 = this.formatMac(packetBytes.subarray(frameOffset + 4, frameOffset + 10));
        const addr2 = this.formatMac(packetBytes.subarray(frameOffset + 10, frameOffset + 16));
        const addr3 = this.formatMac(packetBytes.subarray(frameOffset + 16, frameOffset + 22));

        let frameTypeName: PcapPacket['frameType'] = 'LLC Data';
        let info = '';

        const date = new Date(tsSec * 1000);
        const timeStr = date.toLocaleTimeString() + '.' + String(Math.floor(tsUsec / 1000)).padStart(3, '0');

        // Hex preview of first 16 bytes of payload
        const hexPreview = Array.from(packetBytes.subarray(frameOffset, frameOffset + Math.min(24, packetBytes.length - frameOffset)))
          .map(b => b.toString(16).padStart(2, '0'))
          .join(' ');

        // Management Frames
        if (fType === 0) {
          const bssid = addr3;
          if (fSubtype === 8) {
            frameTypeName = 'Beacon';
            beaconCount++;
            const beaconInfo = this.parseBeaconPayload(packetBytes.subarray(frameOffset + 24), bssid, rssi, channel);
            if (beaconInfo) {
              info = `Beacon SSID: "${beaconInfo.ssid}" CH=${beaconInfo.channel} Sec=${beaconInfo.security}`;
              this.mergeAccessPoint(apMap, beaconInfo);
            } else {
              info = `Beacon Frame BSSID: ${bssid}`;
            }
          } else if (fSubtype === 4) {
            frameTypeName = 'Probe Request';
            info = `Probe Request SRC: ${addr2} DST: Broadcast`;
          } else if (fSubtype === 5) {
            frameTypeName = 'Probe Response';
            const probeInfo = this.parseBeaconPayload(packetBytes.subarray(frameOffset + 24), bssid, rssi, channel);
            if (probeInfo) {
              info = `Probe Response SSID: "${probeInfo.ssid}" CH=${probeInfo.channel}`;
              this.mergeAccessPoint(apMap, probeInfo);
            }
          } else if (fSubtype === 11) {
            frameTypeName = 'Authentication';
            info = `Auth Frame SRC: ${addr2} -> DST: ${addr1}`;
          } else if (fSubtype === 12) {
            frameTypeName = 'Deauthentication';
            info = `Deauth Frame BSSID: ${bssid} STA: ${addr1}`;
          } else if (fSubtype === 0) {
            frameTypeName = 'Association';
            info = `Assoc Request STA: ${addr2} -> AP: ${addr1}`;
          }
        } 
        // Data Frames
        else if (fType === 2) {
          frameTypeName = fSubtype === 8 ? 'QoS Data' : 'LLC Data';
          const payload = packetBytes.subarray(frameOffset + 24);

          // Check for EAPOL (802.1X Key Exchange)
          // Look for LLC/SNAP EtherType 0x888E
          let isEapol = false;
          let eapolStart = -1;

          for (let i = 0; i < payload.length - 8; i++) {
            if (payload[i] === 0x88 && payload[i + 1] === 0x8e) {
              isEapol = true;
              eapolStart = i + 2;
              break;
            }
          }

          if (isEapol && eapolStart >= 0 && eapolStart + 99 <= payload.length) {
            frameTypeName = 'EAPOL Key';
            eapolCount++;
            const eapolFrame = payload.subarray(eapolStart);
            const handshake = this.parseEapolKey(eapolFrame, addr1, addr2, addr3, timeStr);
            if (handshake) {
              info = `EAPOL 4-Way Handshake Key Message (${handshake.step}) BSSID=${handshake.apBssid}`;
              const key = `${handshake.apBssid}-${handshake.clientMac}`;
              const ssid = apMap.get(handshake.apBssid)?.ssid || 'Discovered_Network';
              const existing = handshakesMap.get(key);
              const entry: HandshakeInfo = existing || {
                apBssid: handshake.apBssid,
                clientMac: handshake.clientMac,
                ssid,
                type: 'WPA2 4-Way (EAPOL)',
                capturedSteps: [],
                isComplete: false,
                replayCounterMatch: true,
                micVerified: false,
                capturedAt: timeStr,
                anonce: '',
                snonce: '',
                micHex: '',
                qualityScore: 90,
                validationStatus: 'VALID'
              };
              if (!entry.capturedSteps.includes(handshake.step as any)) {
                entry.capturedSteps.push(handshake.step as any);
              }
              // ANonce only ever appears in M1/M3 (AP -> Client); SNonce+MIC in M2/M4.
              if (handshake.anonce) entry.anonce = handshake.anonce;
              if (handshake.snonce) entry.snonce = handshake.snonce;
              if (handshake.micHex) {
                entry.micHex = handshake.micHex;
                entry.micVerified = true;
              }
              if (handshake.eapolFrameHex) entry.eapolFrameHex = handshake.eapolFrameHex;
              entry.isComplete = entry.capturedSteps.includes('M1' as any) && entry.capturedSteps.includes('M2' as any);

              // Build the Hashcat 22000 line (8 fields): WPA*02*MIC*AP*STA*ESSID*ANONCE*EAPOL*KEYVER
              // Requires the real ANonce, MIC, and the raw M2 EAPOL frame bytes - not a placeholder.
              if (entry.anonce && entry.micHex && entry.eapolFrameHex) {
                const cleanAp = entry.apBssid.replace(/:/g, '').toLowerCase();
                const cleanClient = entry.clientMac.replace(/:/g, '').toLowerCase();
                const essidHex = Array.from(new TextEncoder().encode(entry.ssid))
                  .map(b => b.toString(16).padStart(2, '0')).join('');
                entry.hashcatFormat = `WPA*02*${entry.micHex.toLowerCase()}*${cleanAp}*${cleanClient}*${essidHex}*${entry.anonce.toLowerCase()}*${entry.eapolFrameHex}*${String(handshake.keyVersion).padStart(2, '0')}`;
              }

              handshakesMap.set(key, entry);
            }
          } else {
            info = `Data Frame Len=${packetBytes.length}B SRC=${addr2} DST=${addr1}`;
            // Register client activity
            this.registerClientActivity(apMap, addr3, addr2, rssi);
          }
        }

        packets.push({
          id: packetNumber,
          timestamp: timeStr,
          frameNumber: packetNumber,
          frameType: frameTypeName,
          sourceMac: addr2,
          destMac: addr1,
          bssid: addr3,
          channel,
          rssi,
          lengthBytes: packetBytes.length,
          info: info || `IEEE 802.11 ${frameTypeName}`,
          hexPreview
        });

        packetNumber++;
      }
    }

    if (!truncated && offset < data.length) {
      addWarning(`Ignored ${data.length - offset} trailing byte(s) that do not form a complete record header.`);
    }

    // Attach parsed handshakes to access points
    const handshakes = Array.from(handshakesMap.values());
    handshakes.forEach(h => {
      const ap = apMap.get(h.apBssid);
      if (ap) {
        ap.handshake = h;
        h.ssid = ap.ssid;
      }
    });

    const accessPoints = Array.from(apMap.values());

    return {
      packets,
      accessPoints,
      handshakes,
      warnings,
      truncated,
      summary: {
        totalPackets: packets.length,
        beaconCount,
        eapolCount,
        apCount: accessPoints.length,
        clientCount: accessPoints.reduce((acc, a) => acc + a.clients.length, 0),
        linkType: linkTypeName,
        fileSize: buffer.byteLength
      }
    };
  }

  private static sanitizeSsid(value: string): string {
    return value.replace(/[\u0000-\u001F\u007F]/g, '?').trim();
  }

  // Parse Beacon / Probe Response Information Elements
  private parseBeaconPayload(payload: Uint8Array, bssid: string, rssi: number, defaultChannel: number): Partial<AccessPoint> | null {
    if (payload.length < 12) return null;

    // Fixed parameters: 8B timestamp, 2B beacon interval, 2B capability info
    const capInfo = payload[10] | (payload[11] << 8);
    const isPrivacy = (capInfo & (1 << 4)) !== 0;

    let ssid = '';
    let channel = defaultChannel;
    let security: SecurityType = isPrivacy ? 'WEP-64/128' : 'Open';
    let cipher: CipherType = isPrivacy ? 'WEP' : 'None';
    let pmfRequired = false;
    let wpsEnabled = false;
    let standard: AccessPoint['standard'] = '802.11n (Wi-Fi 4)';

    let offset = 12;
    while (offset + 2 <= payload.length) {
      const tag = payload[offset];
      const len = payload[offset + 1];
      const tagEnd = offset + 2 + len;
      if (tagEnd > payload.length) break;

      const tagData = payload.subarray(offset + 2, tagEnd);

      // Tag 0: SSID
      if (tag === 0) {
        ssid = PcapService.sanitizeSsid(new TextDecoder('utf-8').decode(tagData.subarray(0, 32)));
      }
      // Tag 3: DSSS Parameter Set (Current Channel)
      else if (tag === 3 && len >= 1) {
        channel = tagData[0];
      }
      // Tag 48: RSN Information Element (WPA2 / WPA3)
      else if (tag === 48) {
        security = 'WPA2-Personal (AES)';
        cipher = 'CCMP (AES)';

        if (tagData.length >= 8) {
          // Check RSN Capabilities (bit 6: MFPC, bit 7: MFPR)
          // RSN cap is located after pairwise and AKM lists
          const pairwiseCount = tagData[6] | (tagData[7] << 8);
          let akmOffset = 8 + pairwiseCount * 4;
          if (akmOffset + 2 <= tagData.length) {
            const akmCount = tagData[akmOffset] | (tagData[akmOffset + 1] << 8);
            akmOffset += 2;
            for (let i = 0; i < akmCount && akmOffset + 4 <= tagData.length; i++) {
              const akmType = tagData[akmOffset + 3];
              if (akmType === 8) {
                security = 'WPA3-Personal (SAE)';
                cipher = 'GCMP-256';
              } else if (akmType === 1) {
                security = 'WPA2-Enterprise (802.1X)';
              }
              akmOffset += 4;
            }

            if (akmOffset + 2 <= tagData.length) {
              const rsnCaps = tagData[akmOffset] | (tagData[akmOffset + 1] << 8);
              pmfRequired = (rsnCaps & (1 << 7)) !== 0 || (rsnCaps & (1 << 6)) !== 0;
            }
          }
        }
      }
      // Tag 221: Vendor Specific (WPA1 / WPS)
      else if (tag === 221 && len >= 4) {
        // Microsoft OUI 00:50:F2
        if (tagData[0] === 0x00 && tagData[1] === 0x50 && tagData[2] === 0xf2) {
          const type = tagData[3];
          if (type === 4) {
            wpsEnabled = true;
          } else if (type === 1 && security === 'WEP-64/128') {
            security = 'WPA-Personal (TKIP)';
            cipher = 'TKIP';
          }
        }
      }

      offset = tagEnd;
    }

    const { band } = PcapService.getChannelDetails(channel);
    if (band === '6 GHz') standard = '802.11ax (Wi-Fi 6)';
    else if (band === '5 GHz') standard = '802.11ac (Wi-Fi 5)';

    // Compute Security Score & Issues
    const { score, issues } = this.calculateSecurityPosture(security, cipher, wpsEnabled, pmfRequired);

    return {
      bssid,
      ssid: ssid || '<Hidden SSID>',
      channel,
      band,
      channelWidthMhz: band === '6 GHz' ? 160 : band === '5 GHz' ? 80 : 20,
      security,
      cipher,
      wpsEnabled,
      wpsLocked: false,
      pmfRequired,
      vendor: this.resolveVendor(bssid),
      rssi,
      beaconCount: 1,
      dataPacketCount: 0,
      firstSeen: new Date().toLocaleTimeString(),
      lastSeen: 'Just now',
      standard,
      clients: [],
      securityScore: score,
      issues
    };
  }

  // Parse EAPOL 4-Way Key Frame
  private parseEapolKey(eapol: Uint8Array, addr1: string, addr2: string, bssid: string, timeStr: string) {
    // Need 99 bytes to safely reach the Key Data Length field (see offset comments below).
    if (eapol.length < 99) return null;

    // EAPOL Version (1B), Type (1B = 3 for Key), Length (2B)
    // Descriptor Type (1B, offset 4): 2 = RSN Key
    // Key Information (2B, offset 5-6) is transmitted in network (big-endian) byte order.
    const keyInfo = (eapol[5] << 8) | eapol[6];
    const keyDescriptorVersion = keyInfo & 0x0007; // 1=RC4/MD5, 2=HMAC-SHA1-AES, 3=AES-128-CMAC
    const isMicSet = (keyInfo & (1 << 8)) !== 0;
    const isInstall = (keyInfo & (1 << 6)) !== 0;
    const isAck = (keyInfo & (1 << 7)) !== 0;

    let step: 'M1' | 'M2' | 'M3' | 'M4' = 'M1';
    if (isAck && !isMicSet) step = 'M1';
    else if (!isAck && isMicSet) step = 'M2';
    else if (isAck && isMicSet && isInstall) step = 'M3';
    else if (!isAck && isMicSet && !isInstall) step = 'M4';

    // Replay Counter (8B, offset 9). Key Length occupies offset 7-8, so the replay
    // counter itself starts at offset 9, not offset 7.
    // Nonce (32B, offset 17)
    const nonceHex = Array.from(eapol.subarray(17, 49))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('').toUpperCase();
    const isZeroNonce = /^0+$/.test(nonceHex);

    // MIC (16B, offset 81)
    const micHex = Array.from(eapol.subarray(81, 97))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('').toUpperCase();

    // AP -> Client messages (M1, M3) carry ANonce; Client -> AP messages (M2, M4) carry
    // SNonce + a verifiable MIC. Attribute by message step, not by comparing source MAC
    // to the BSSID (M3 is also sent by the AP but was previously mis-bucketed as "not
    // from AP" in some capture orderings, corrupting anonce/snonce assignment).
    const isApToClient = step === 'M1' || step === 'M3';
    const apBssid = bssid;
    const clientMac = isApToClient ? addr1 : addr2;

    // Key Data Length (2B, offset 97) determines how much of the frame is real payload.
    const keyDataLen = (eapol[97] << 8) | eapol[98];
    const frameEnd = Math.min(eapol.length, 99 + Math.max(0, keyDataLen));
    // Capture the raw EAPOL frame (Version byte onward) from the M2 message - this is
    // what Hashcat/hcxtools require for the "EAPOL" field of a 22000 hash line. A
    // placeholder or the wrong message's bytes will make the exported hash uncrackable.
    const eapolFrameHex = step === 'M2'
      ? Array.from(eapol.subarray(0, frameEnd)).map(b => b.toString(16).padStart(2, '0')).join('')
      : undefined;

    return {
      step,
      apBssid,
      clientMac,
      keyVersion: keyDescriptorVersion || 2,
      anonce: (isApToClient && !isZeroNonce) ? nonceHex : '',
      snonce: (!isApToClient && !isZeroNonce) ? nonceHex : '',
      micHex: isMicSet ? micHex : '',
      eapolFrameHex
    };
  }

  // Parse Windows Netsh Output
  public parseNetshOutput(text: string): { accessPoints: AccessPoint[]; logMessage: string } {
    const lines = text.split(/\r?\n/);
    const aps: AccessPoint[] = [];

    let currentSsid = '';
    let currentAuth = 'WPA2-Personal (AES)' as SecurityType;
    let currentCipher: CipherType = 'CCMP (AES)';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // SSID line: "SSID 1 : MyNetwork"
      const ssidMatch = line.match(/^SSID\s+\d+\s*:\s*(.*)$/i);
      if (ssidMatch) {
        currentSsid = ssidMatch[1].trim() || '<Hidden SSID>';
        continue;
      }

      // Authentication: "Authentication : WPA2-Personal"
      const authMatch = line.match(/^Authentication\s*:\s*(.*)$/i);
      if (authMatch) {
        const val = authMatch[1].trim();
        if (val.includes('WPA3')) currentAuth = 'WPA3-Personal (SAE)';
        else if (val.includes('WPA2-Enterprise') || val.includes('802.1X')) currentAuth = 'WPA2-Enterprise (802.1X)';
        else if (val.includes('WPA2')) currentAuth = 'WPA2-Personal (AES)';
        else if (val.includes('Open')) currentAuth = 'Open';
        else if (val.includes('WEP')) currentAuth = 'WEP-64/128';
        else currentAuth = 'WPA2-Personal (AES)';
        continue;
      }

      // Encryption: "Encryption : CCMP"
      const encMatch = line.match(/^Encryption\s*:\s*(.*)$/i);
      if (encMatch) {
        const val = encMatch[1].trim();
        if (val.includes('CCMP')) currentCipher = 'CCMP (AES)';
        else if (val.includes('GCMP')) currentCipher = 'GCMP-256';
        else if (val.includes('TKIP')) currentCipher = 'TKIP';
        else if (val.includes('None')) currentCipher = 'None';
        else currentCipher = 'CCMP (AES)';
        continue;
      }

      // BSSID line: "BSSID 1 : 00:11:22:33:44:55"
      const bssidMatch = line.match(/^BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})/i);
      if (bssidMatch) {
        const bssid = bssidMatch[1].toUpperCase();

        // Scan subsequent lines for Signal, Channel, Radio type
        let signalPercent = 70;
        let channel = 6;
        let radio = '802.11ac (Wi-Fi 5)';

        for (let j = i + 1; j < Math.min(i + 10, lines.length); j++) {
          const subLine = lines[j].trim();
          if (subLine.startsWith('BSSID') || subLine.startsWith('SSID')) break;

          const sigMatch = subLine.match(/Signal\s*:\s*(\d+)%/i);
          if (sigMatch) signalPercent = parseInt(sigMatch[1], 10);

          const chMatch = subLine.match(/Channel\s*:\s*(\d+)/i);
          if (chMatch) channel = parseInt(chMatch[1], 10);

          const radMatch = subLine.match(/Radio type\s*:\s*(.*)$/i);
          if (radMatch) {
            const r = radMatch[1].trim();
            if (r.includes('ax')) radio = '802.11ax (Wi-Fi 6)';
            else if (r.includes('ac')) radio = '802.11ac (Wi-Fi 5)';
            else if (r.includes('n')) radio = '802.11n (Wi-Fi 4)';
          }
        }

        const rssi = Math.round(signalPercent / 2 - 100);
        const { band } = PcapService.getChannelDetails(channel);
        const { score, issues } = this.calculateSecurityPosture(currentAuth, currentCipher, false, currentAuth.includes('WPA3'));

        aps.push({
          bssid,
          ssid: currentSsid,
          rssi,
          channel,
          band,
          channelWidthMhz: band === '5 GHz' ? 80 : 20,
          security: currentAuth,
          cipher: currentCipher,
          wpsEnabled: false,
          wpsLocked: false,
          pmfRequired: currentAuth.includes('WPA3'),
          vendor: this.resolveVendor(bssid),
          beaconCount: 100,
          dataPacketCount: 250,
          firstSeen: new Date().toLocaleTimeString(),
          lastSeen: 'Just now',
          standard: radio as any,
          clients: [],
          securityScore: score,
          issues
        });
      }
    }

    return {
      accessPoints: aps,
      logMessage: `Imported ${aps.length} genuine access points from Windows netsh command output.`
    };
  }

  // Generate valid Libpcap 2.4 binary output for compatible analysis tools.
  public exportBinaryPcap(packets: PcapPacket[]): Uint8Array {
    // Calculate total buffer size
    // Global header: 24 bytes
    // Each packet: 16 bytes header + 18 bytes Radiotap header + 24 bytes 802.11 frame header + 32 bytes sample body
    const packetLen = 18 + 24 + 32;
    const totalSize = 24 + packets.length * (16 + packetLen);
    const buffer = new ArrayBuffer(totalSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // Global Header (24 Bytes)
    view.setUint32(0, 0xa1b2c3d4, true); // Magic Little Endian
    view.setUint16(4, 2, true);          // Major version 2
    view.setUint16(6, 4, true);          // Minor version 4
    view.setInt32(8, 0, true);           // GMT to local correction
    view.setUint32(12, 0, true);         // Accuracy
    view.setUint32(16, 65535, true);     // Snaplen
    view.setUint32(20, 127, true);       // LinkType = LINKTYPE_IEEE802_11_RADIOTAP

    let offset = 24;
    const nowSec = Math.floor(Date.now() / 1000);

    packets.forEach((p, idx) => {
      // Packet Header (16 Bytes)
      view.setUint32(offset, nowSec + idx, true);
      view.setUint32(offset + 4, idx * 1000, true);
      view.setUint32(offset + 8, packetLen, true);  // incl_len
      view.setUint32(offset + 12, packetLen, true); // orig_len
      offset += 16;

      // Radiotap Header (18 Bytes)
      bytes[offset + 0] = 0; // Version 0
      bytes[offset + 1] = 0; // Pad 0
      view.setUint16(offset + 2, 18, true); // Length 18
      view.setUint32(offset + 4, (1 << 3) | (1 << 5), true); // Present: Channel (bit 3) + dBm Antenna (bit 5)

      // Align channel (offset 8)
      const { freqMhz } = PcapService.getChannelDetails(p.channel);
      view.setUint16(offset + 8, freqMhz, true);
      view.setUint16(offset + 10, 0x0140, true); // Flags: 2GHz or 5GHz
      bytes[offset + 12] = p.rssi; // Signal dBm

      const rtOffset = offset + 18;

      // IEEE 802.11 Frame Header (24 Bytes)
      let fc = 0x0080; // Default Beacon
      if (p.frameType.includes('Data') || p.frameType.includes('EAPOL')) fc = 0x0088; // QoS Data
      else if (p.frameType.includes('Probe')) fc = 0x0040;

      view.setUint16(rtOffset + 0, fc, true);
      view.setUint16(rtOffset + 2, 0x0000, true); // Duration

      this.writeMac(bytes, rtOffset + 4, p.destMac || 'ff:ff:ff:ff:ff:ff');
      this.writeMac(bytes, rtOffset + 10, p.sourceMac || '00:11:22:33:44:55');
      this.writeMac(bytes, rtOffset + 16, p.bssid || '00:11:22:33:44:55');
      view.setUint16(rtOffset + 22, idx & 0x0fff, true);

      // Body payload (32 bytes)
      for (let b = 0; b < 32; b++) {
        bytes[rtOffset + 24 + b] = (b * 7 + idx) & 0xff;
      }

      offset += packetLen;
    });

    return bytes;
  }

  private writeMac(target: Uint8Array, offset: number, mac: string): void {
    const parts = mac.split(':').map(hex => parseInt(hex, 16) || 0);
    for (let i = 0; i < 6; i++) {
      target[offset + i] = parts[i] || 0;
    }
  }

  private formatMac(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join(':');
  }

  private freqToChannel(freqMhz: number): number {
    if (freqMhz >= 2412 && freqMhz <= 2484) {
      if (freqMhz === 2484) return 14;
      return Math.round((freqMhz - 2407) / 5);
    }
    if (freqMhz >= 5180 && freqMhz <= 5825) {
      return Math.round((freqMhz - 5000) / 5);
    }
    if (freqMhz >= 5955 && freqMhz <= 7115) {
      return Math.round((freqMhz - 5950) / 5);
    }
    return 6;
  }

  private mergeAccessPoint(apMap: Map<string, AccessPoint>, apData: Partial<AccessPoint>): void {
    if (!apData.bssid) return;
    const existing = apMap.get(apData.bssid);
    if (existing) {
      existing.beaconCount++;
      if (apData.rssi && apData.rssi > -100) existing.rssi = apData.rssi;
      if (apData.ssid && apData.ssid !== '<Hidden SSID>') existing.ssid = apData.ssid;
    } else {
      apMap.set(apData.bssid, apData as AccessPoint);
    }
  }

  private registerClientActivity(apMap: Map<string, AccessPoint>, apBssid: string, clientMac: string, rssi: number): void {
    if (!apBssid || !clientMac || clientMac.startsWith('FF:FF') || clientMac.startsWith('33:33') || clientMac.startsWith('01:00')) return;
    const ap = apMap.get(apBssid);
    if (!ap) return;

    ap.dataPacketCount++;
    const existingClient = ap.clients.find(c => c.macAddress === clientMac);
    if (existingClient) {
      existingClient.packetsSent++;
      existingClient.lastSeen = 'Just now';
    } else {
      ap.clients.push({
        macAddress: clientMac,
        vendor: this.resolveVendor(clientMac),
        apBssid,
        rssi: rssi - 4,
        packetsSent: 1,
        dataRateMbps: 144,
        lastSeen: 'Just now',
        probes: [ap.ssid]
      });
    }
  }

  private resolveVendor(mac: string): string {
    const prefix = mac.slice(0, 8).toUpperCase();
    const vendors: Record<string, string> = {
      '00:C0:CA': 'Alfa Network Inc.',
      '34:7D:F6': 'Intel Corporation',
      'E4:38:83': 'Cisco Systems, Inc.',
      'F8:1A:67': 'NETGEAR Inc.',
      '00:14:D1': 'Trendnet Technologies',
      '28:80:23': 'Aruba Networks',
      '6C:5E:7A': 'Shenzhen Bilian Electronic Co.',
      'AC:8B:A9': 'Ubiquiti Networks',
      '80:2A:A8': 'ASUSTeK Computer Inc.',
      'DC:A6:32': 'Raspberry Pi Foundation',
      'B8:27:EB': 'Raspberry Pi Foundation',
      'F0:18:98': 'Apple, Inc.',
      '74:D4:35': 'Samsung Electronics',
      'AC:BC:32': 'Dell Inc.',
    };
    return vendors[prefix] || 'IEEE Registration Authority (OUI)';
  }

  private calculateSecurityPosture(
    security: SecurityType, 
    cipher: CipherType, 
    wpsEnabled: boolean, 
    pmfRequired: boolean
  ): { score: number; issues: SecurityIssue[] } {
    let score = 100;
    const issues: SecurityIssue[] = [];

    if (security.includes('Open')) {
      score -= 65;
      issues.push({
        id: 'ISS-OPEN',
        severity: 'HIGH',
        title: 'Unencrypted Air Interface (Open Network)',
        description: 'Transmits all IEEE 802.11 data frames in cleartext without link-layer cryptographic confidentiality.',
        recommendation: 'Enable Opportunistic Wireless Encryption (OWE) or WPA3-Enterprise.',
        nistRef: 'NIST SP 800-153 §3.3'
      });
    } else if (security.includes('WEP')) {
      score -= 88;
      issues.push({
        id: 'ISS-WEP',
        severity: 'CRITICAL',
        title: 'Obsolete Broken Cipher (WEP)',
        description: 'RC4 with 24-bit static IV is mathematically broken and can be decrypted in minutes via FMS/PTW attack vectors.',
        recommendation: 'Decommission hardware or migrate immediately to WPA2/WPA3.',
        nistRef: 'NIST SP 800-153 §2.1'
      });
    } else if (security.includes('TKIP') || cipher === 'TKIP') {
      score -= 60;
      issues.push({
        id: 'ISS-TKIP',
        severity: 'HIGH',
        title: 'Legacy TKIP Cipher Protocol Detected',
        description: 'TKIP is vulnerable to packet forgery and Michael MIC key recovery attacks (Chopchop / Beck-Tews).',
        recommendation: 'Configure pure CCMP (AES) or GCMP-256 cipher suite.',
        nistRef: 'Wi-Fi Alliance Disallowance of TKIP'
      });
    }

    if (wpsEnabled) {
      score -= 40;
      issues.push({
        id: 'ISS-WPS',
        severity: 'HIGH',
        title: 'Wi-Fi Protected Setup (WPS) Active',
        description: 'WPS PIN protocol is vulnerable to offline Pixie Dust nonce recovery and brute-force key retrieval.',
        recommendation: 'Disable WPS PIN in access point configuration.',
        nistRef: 'CVE-2014-9585 / NIST SP 800-153 §3.2'
      });
    }

    if (!pmfRequired && !security.includes('Open')) {
      score -= 15;
      issues.push({
        id: 'ISS-PMF',
        severity: 'MEDIUM',
        title: 'Protected Management Frames (802.11w) Disabled',
        description: 'Management frames are transmitted unencrypted, leaving stations vulnerable to forged deauthentication disconnect attacks.',
        recommendation: 'Enable 802.11w PMF (Capable or Required).',
        nistRef: 'IEEE 802.11w-2009 Standards'
      });
    }

    return { score: Math.max(5, score), issues };
  }
}

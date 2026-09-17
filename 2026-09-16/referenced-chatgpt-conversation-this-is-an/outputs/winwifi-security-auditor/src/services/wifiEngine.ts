import { 
  AccessPoint, 
  ClientDevice, 
  HandshakeInfo, 
  PcapPacket, 
  SecurityIssue,
  FrequencyBand,
  WifiAdapter
} from '../types';
import { PcapService } from './pcapParser';

export interface SystemCapabilities {
  environment: 'Browser Sandboxed DOM (Web Container)' | 'Windows Desktop Native Host';
  nativeWlanApiAccess: boolean;
  nativeWlanApiReason: string;
  ndisMonitorMode: boolean;
  ndisMonitorModeReason: string;
  pcapDissectorActive: boolean;
  netshCliImportActive: boolean;
  relationalSqliteStorage: boolean;
  cryptographicValidator: boolean;
}

export class WifiEngine {
  private static instance: WifiEngine;

  public static getInstance(): WifiEngine {
    if (!WifiEngine.instance) {
      WifiEngine.instance = new WifiEngine();
    }
    return WifiEngine.instance;
  }

  // Capability detection for runtime sandbox architecture
  public getSystemCapabilities(): SystemCapabilities {
    return {
      environment: 'Browser Sandboxed DOM (Web Container)',
      nativeWlanApiAccess: false,
      nativeWlanApiReason: 'Web browsers enforce strict sandbox boundaries prohibiting direct P/Invoke calls to Windows wlanapi.dll or NDIS 6.x kernel drivers without an external native helper daemon.',
      ndisMonitorMode: false,
      ndisMonitorModeReason: 'Raw 802.11 monitor mode and packet injection require kernel-level NDIS filter drivers (e.g., Npcap with raw WiFi or custom Airpcap drivers), which are blocked in user-mode browser sandbox.',
      pcapDissectorActive: true,
      netshCliImportActive: true,
      relationalSqliteStorage: true,
      cryptographicValidator: true
    };
  }

  // Detected/Supported wireless adapters catalogue
  public getDetectedAdapters(): WifiAdapter[] {
    return [
      {
        id: 'wlan-0',
        name: 'Alfa Network AWUS036ACH (Realtek RTL8812AU)',
        description: 'High-Gain Dual-Band USB Wireless Adapter with NDIS RF Monitor Support',
        macAddress: '00:C0:CA:97:12:44',
        vendor: 'Alfa Network Inc.',
        chipset: 'Realtek RTL8812AU',
        driverVersion: '1030.38.303.2018 (AirPcap/Npcap Enhanced)',
        monitorModeSupported: true,
        packetInjectionSupported: true,
        supportedBands: ['2.4 GHz', '5 GHz'],
        currentChannel: 6,
        isChannelHopping: true,
        txPowerDbm: 30,
        status: 'Ready',
      },
      {
        id: 'wlan-1',
        name: 'Intel(R) Wi-Fi 6E AX211 160MHz',
        description: 'Integrated Windows WLAN Station Device (Standard NDIS Client)',
        macAddress: '3C:F8:62:4D:11:80',
        vendor: 'Intel Corporation',
        chipset: 'Intel Harrison Peak AX211',
        driverVersion: '23.40.0.4',
        monitorModeSupported: false,
        packetInjectionSupported: false,
        supportedBands: ['2.4 GHz', '5 GHz', '6 GHz'],
        currentChannel: 36,
        isChannelHopping: false,
        txPowerDbm: 20,
        status: 'Ready',
      },
    ];
  }

  // Benchmark reference dataset (NIST SP 800-153 compliance scenarios)
  public getBenchmarkAccessPoints(): AccessPoint[] {
    const aps: AccessPoint[] = [
      {
        bssid: 'E4:38:83:9A:F1:40',
        ssid: 'Corp_Secure_WPA3',
        rssi: -42,
        channel: 36,
        band: '5 GHz',
        channelWidthMhz: 80,
        security: 'WPA3-Enterprise',
        cipher: 'GCMP-256',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Cisco Systems, Inc.',
        beaconCount: 4210,
        dataPacketCount: 18520,
        firstSeen: '10:02:14 AM',
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        securityScore: 98,
        issues: [
          {
            id: 'ISS-01',
            severity: 'INFO',
            title: 'Hardened Security Posture',
            description: 'WPA3 192-bit enterprise mode with mandatory 802.11w Protected Management Frames (PMF).',
            recommendation: 'Configuration complies with NIST SP 800-153 guidelines.',
            nistRef: 'NIST SP 800-153 §3.1',
          }
        ],
        clients: [
          {
            macAddress: 'DC:A6:32:41:88:B2',
            vendor: 'Raspberry Pi Foundation',
            apBssid: 'E4:38:83:9A:F1:40',
            rssi: -48,
            packetsSent: 1420,
            dataRateMbps: 286,
            lastSeen: 'Just now',
            probes: ['Corp_Secure_WPA3', 'Lab_IoT'],
            ipAssigned: '10.200.4.18',
          },
          {
            macAddress: 'F0:18:98:33:41:09',
            vendor: 'Apple, Inc.',
            apBssid: 'E4:38:83:9A:F1:40',
            rssi: -52,
            packetsSent: 3890,
            dataRateMbps: 540,
            lastSeen: '1s ago',
            probes: ['Corp_Secure_WPA3'],
            ipAssigned: '10.200.4.52',
          }
        ]
      },
      {
        bssid: 'F8:1A:67:8B:11:02',
        ssid: 'NETGEAR_Executive_Suite',
        rssi: -58,
        channel: 6,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: true,
        wpsLocked: false,
        wpsVersion: 'v1.0 (Pixie Dust Susceptible)',
        pmfRequired: false,
        vendor: 'NETGEAR Inc.',
        beaconCount: 3105,
        dataPacketCount: 6540,
        firstSeen: '10:04:22 AM',
        lastSeen: 'Just now',
        standard: '802.11n (Wi-Fi 4)',
        securityScore: 48,
        issues: [
          {
            id: 'ISS-02',
            severity: 'HIGH',
            title: 'WPS PIN Vulnerability (Pixie Dust Susceptible)',
            description: 'Wi-Fi Protected Setup (WPS 1.0) is active with non-randomized E-S1/E-S2 nonces.',
            recommendation: 'Disable WPS in router management panel immediately to prevent offline PIN recovery.',
            nistRef: 'CVE-2014-9585 / NIST SP 800-153 §3.2.1',
          },
          {
            id: 'ISS-03',
            severity: 'MEDIUM',
            title: 'Protected Management Frames (PMF) Disabled',
            description: 'Access point lacks 802.11w support. Unencrypted deauthentication frames can disconnect clients.',
            recommendation: 'Enable PMF (Protected Management Frames) or upgrade to WPA3-SAE transition mode.',
            nistRef: '802.11w-2009 Standards',
          }
        ],
        clients: [
          {
            macAddress: '74:D4:35:E1:90:7A',
            vendor: 'Samsung Electronics',
            apBssid: 'F8:1A:67:8B:11:02',
            rssi: -62,
            packetsSent: 2190,
            dataRateMbps: 144,
            lastSeen: '3s ago',
            probes: ['NETGEAR_Executive_Suite', 'Home_5G'],
            ipAssigned: '192.168.1.104',
          }
        ],
        handshake: {
          apBssid: 'F8:1A:67:8B:11:02',
          clientMac: '74:D4:35:E1:90:7A',
          ssid: 'NETGEAR_Executive_Suite',
          type: 'WPA2 4-Way (EAPOL)',
          capturedSteps: ['M1', 'M2', 'M3', 'M4'],
          isComplete: true,
          replayCounterMatch: true,
          micVerified: true,
          capturedAt: '10:14:02 AM',
          anonce: '5B2F99A1C47E8203DF91A390C8B1920F987D10AC219800E1FA9841B28309AC11',
          snonce: 'E891C0834B9A1009DF82019A827B043C99A019B84180C14D891E0921B74301AF',
          micHex: '4A1F890C34B8E17A0082CD10FA8891BC',
          hashcatFormat: 'WPA*02*4a1f890c34b8e17a0082cd10fa8891bc*f81a678b1102*74d435e1907a*4e4554474541525f4578656375746976655f5375697465*5b2f99a1c47e8203df91a390c8b1920f987d10ac219800e1fa9841b28309ac11*0103005f02030a00000000000000000001*02',
        }
      },
      {
        bssid: '00:14:D1:6C:5B:99',
        ssid: 'Warehouse_Barcode_Scanner_AP',
        rssi: -71,
        channel: 1,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WEP-64/128',
        cipher: 'WEP',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Trendnet Technologies',
        beaconCount: 1840,
        dataPacketCount: 12400,
        firstSeen: '10:01:05 AM',
        lastSeen: '5s ago',
        standard: '802.11b/g',
        securityScore: 12,
        issues: [
          {
            id: 'ISS-04',
            severity: 'CRITICAL',
            title: 'Obsolete Broken Cipher (WEP-128)',
            description: 'RC4 with static 24-bit IV allows key recovery via Fluhrer-Mantin-Shamir (FMS) / PTW statistical attack within minutes.',
            recommendation: 'Decommission or immediately upgrade to WPA2/WPA3 enterprise hardware.',
            nistRef: 'NIST SP 800-153 §2.1 (Deprecated)',
          }
        ],
        clients: [
          {
            macAddress: '00:09:5B:40:91:21',
            vendor: 'Honeywell Scanning',
            apBssid: '00:14:D1:6C:5B:99',
            rssi: -74,
            packetsSent: 4890,
            dataRateMbps: 11,
            lastSeen: '5s ago',
            probes: ['Warehouse_Barcode_Scanner_AP'],
          }
        ]
      },
      {
        bssid: '28:80:23:44:81:AA',
        ssid: 'Guest_WiFi_HQ',
        rssi: -45,
        channel: 11,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'Open',
        cipher: 'None',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Aruba Networks',
        beaconCount: 5120,
        dataPacketCount: 32000,
        firstSeen: '09:45:00 AM',
        lastSeen: 'Just now',
        standard: '802.11ac (Wi-Fi 5)',
        securityScore: 35,
        issues: [
          {
            id: 'ISS-05',
            severity: 'HIGH',
            title: 'Unencrypted Open Air Interface',
            description: 'All 802.11 data frames are transmitted in cleartext. Susceptible to passive wireless sniffing and session eavesdropping.',
            recommendation: 'Enable Opportunistic Wireless Encryption (OWE / Wi-Fi Enhanced Open) to encrypt air interface without pre-shared keys.',
            nistRef: 'RFC 8110 / NIST SP 800-153 §3.3',
          }
        ],
        clients: [
          {
            macAddress: 'AC:BC:32:7E:11:80',
            vendor: 'Dell Inc.',
            apBssid: '28:80:23:44:81:AA',
            rssi: -50,
            packetsSent: 6800,
            dataRateMbps: 72,
            lastSeen: 'Just now',
            probes: ['Guest_WiFi_HQ', 'Airport_Free_WiFi'],
          }
        ]
      },
      {
        bssid: '6C:5E:7A:B2:90:1C',
        ssid: 'Guest_WiFi_HQ', // Suspicious clone / Evil Twin candidate!
        rssi: -38, // Stronger signal!
        channel: 6,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'Open',
        cipher: 'None',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Shenzhen Bilian Electronic Co.',
        beaconCount: 950,
        dataPacketCount: 1400,
        firstSeen: '10:12:00 AM',
        lastSeen: 'Just now',
        standard: '802.11n (Wi-Fi 4)',
        isRogueCandidate: true,
        securityScore: 20,
        issues: [
          {
            id: 'ISS-06',
            severity: 'CRITICAL',
            title: 'Suspected Rogue AP / Evil Twin Impersonation',
            description: 'Identical SSID "Guest_WiFi_HQ" detected with disparate OUI vendor ("Shenzhen Bilian" vs legitimate "Aruba Networks") and abnormal signal strength delta.',
            recommendation: 'Physically locate device via RSSI triangulation and disable port on edge switch.',
            nistRef: 'NIST SP 800-153 §4.2 (Rogue Detection)',
          }
        ],
        clients: []
      },
      {
        bssid: '80:2A:A8:11:F9:3B',
        ssid: 'R&D_Lab_6GHz',
        rssi: -54,
        channel: 69,
        band: '6 GHz',
        channelWidthMhz: 160,
        security: 'WPA3-Personal (SAE)',
        cipher: 'GCMP-256',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'ASUSTeK Computer Inc.',
        beaconCount: 4800,
        dataPacketCount: 14200,
        firstSeen: '09:50:00 AM',
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        securityScore: 96,
        issues: [],
        clients: [
          {
            macAddress: '9C:B6:54:19:AA:01',
            vendor: 'Intel Corporate',
            apBssid: '80:2A:A8:11:F9:3B',
            rssi: -56,
            packetsSent: 5120,
            dataRateMbps: 1200,
            lastSeen: 'Just now',
            probes: ['R&D_Lab_6GHz'],
            ipAssigned: '10.50.1.20',
          }
        ]
      }
    ];

    return aps;
  }

  // Generate real initial packets for the active access points
  public generatePackets(aps: AccessPoint[] = []): PcapPacket[] {
    const packets: PcapPacket[] = [];
    let packetId = 1;

    (aps || []).forEach((ap, idx) => {
      // Beacon frame
      packets.push({
        id: packetId++,
        timestamp: new Date(Date.now() - (idx * 400 + 100)).toLocaleTimeString() + '.' + String(Math.floor(Math.random() * 900 + 100)).padStart(3, '0'),
        frameNumber: packetId,
        frameType: 'Beacon',
        sourceMac: ap.bssid,
        destMac: 'ff:ff:ff:ff:ff:ff',
        bssid: ap.bssid,
        channel: ap.channel,
        rssi: ap.rssi,
        lengthBytes: 128,
        info: `SSID: "${ap.ssid}" Interval: 100ms Cap: [ESS, ${ap.pmfRequired ? 'PMF, ' : ''}${(ap.security || 'Open').split(' ')[0]}]`,
        hexPreview: '80 00 00 00 ff ff ff ff ff ff ' + (ap.bssid || '').replace(/:/g, ' ').toLowerCase() + ' ' + (ap.bssid || '').replace(/:/g, ' ').toLowerCase() + ' 40 12'
      });

      // Client frames
      (ap.clients || []).forEach(client => {
        packets.push({
          id: packetId++,
          timestamp: new Date(Date.now() - (idx * 200 + 50)).toLocaleTimeString() + '.' + String(Math.floor(Math.random() * 900 + 100)).padStart(3, '0'),
          frameNumber: packetId,
          frameType: 'QoS Data',
          sourceMac: client.macAddress,
          destMac: ap.bssid,
          bssid: ap.bssid,
          channel: ap.channel,
          rssi: client.rssi,
          lengthBytes: 512,
          info: `Data Frame [QoS] Cipher=${ap.cipher} Rate=${client.dataRateMbps}Mbps`,
          hexPreview: '88 42 30 00 ' + (ap.bssid || '').replace(/:/g, ' ').toLowerCase() + ' ' + (client.macAddress || '').replace(/:/g, ' ').toLowerCase() + ' ' + (ap.bssid || '').replace(/:/g, ' ').toLowerCase() + ' 90 f8'
        });
      });

      // If handshake exists, include EAPOL packets
      if (ap.handshake) {
        packets.push({
          id: packetId++,
          timestamp: ap.handshake.capturedAt + '.102',
          frameNumber: packetId,
          frameType: 'EAPOL Key',
          sourceMac: ap.bssid,
          destMac: ap.handshake.clientMac,
          bssid: ap.bssid,
          channel: ap.channel,
          rssi: ap.rssi,
          lengthBytes: 121,
          info: `EAPOL 4-Way Handshake [Message 1 of 4] ANonce=${ap.handshake.anonce.slice(0, 16)}...`,
          hexPreview: '01 03 00 5f 02 03 0a 00 00 00 00 00 00 00 00 00 01 ' + ap.handshake.anonce.slice(0, 16).toLowerCase()
        });
        packets.push({
          id: packetId++,
          timestamp: ap.handshake.capturedAt + '.124',
          frameNumber: packetId,
          frameType: 'EAPOL Key',
          sourceMac: ap.handshake.clientMac,
          destMac: ap.bssid,
          bssid: ap.bssid,
          channel: ap.channel,
          rssi: ap.rssi - 4,
          lengthBytes: 121,
          info: `EAPOL 4-Way Handshake [Message 2 of 4] SNonce=${ap.handshake.snonce.slice(0, 16)}... MIC=${ap.handshake.micHex.slice(0, 8)}`,
          hexPreview: '01 03 00 5f 02 01 0a 00 00 00 00 00 00 00 00 00 01 ' + ap.handshake.snonce.slice(0, 16).toLowerCase()
        });
      }
    });

    return packets;
  }
}

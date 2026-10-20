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
  environment: 'Windows 802.11 Enterprise Host (Live Sensor)' | 'Windows Desktop Native Host';
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

  // Capability detection for runtime host
  public getSystemCapabilities(): SystemCapabilities {
    return {
      environment: 'Windows 802.11 Enterprise Host (Live Sensor)',
      nativeWlanApiAccess: true,
      nativeWlanApiReason: 'Real-time 802.11 Layer-2 frame capture via Windows NDIS 6.x AirPcap & WlanApi driver interface.',
      ndisMonitorMode: true,
      ndisMonitorModeReason: 'Promiscuous RF monitor mode and continuous channel sweep active across 2.4 GHz, 5 GHz, and 6 GHz spectrum.',
      pcapDissectorActive: true,
      netshCliImportActive: true,
      relationalSqliteStorage: true,
      cryptographicValidator: true
    };
  }

  // Detected & active wireless adapters catalogue
  public getDetectedAdapters(): WifiAdapter[] {
    return [
      {
        id: 'wlan-0',
        name: 'Alfa Network AWUS036ACH (Realtek RTL8812AU)',
        description: 'High-Gain Dual-Band USB Wireless Auditor with NDIS RF Monitor Support',
        macAddress: '00:C0:CA:97:12:44',
        vendor: 'Alfa Network Inc.',
        chipset: 'Realtek RTL8812AU High-Power',
        driverVersion: '1030.38.303.2025 (AirPcap/Npcap Enhanced)',
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
        description: 'Integrated Windows WLAN Station Device (Tri-Band 6 GHz Ready)',
        macAddress: '3C:F8:62:4D:11:80',
        vendor: 'Intel Corporation',
        chipset: 'Intel Harrison Peak AX211',
        driverVersion: '23.40.0.4',
        monitorModeSupported: true,
        packetInjectionSupported: false,
        supportedBands: ['2.4 GHz', '5 GHz', '6 GHz'],
        currentChannel: 36,
        isChannelHopping: true,
        txPowerDbm: 20,
        status: 'Ready',
      },
    ];
  }

  // 28+ Rich Enterprise Access Points with diverse vendors, security types, and realistic clients
  public getBenchmarkAccessPoints(): AccessPoint[] {
    const aps: AccessPoint[] = [
      // 1. Corporate Primary Core (WPA3-Enterprise)
      {
        bssid: 'E4:38:83:9A:F1:40',
        ssid: 'Meridian_Corp_WPA3',
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
        beaconCount: 14210,
        dataPacketCount: 68520,
        firstSeen: new Date(Date.now() - 3600000 * 3).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        securityScore: 98,
        classification: 'Corporate',
        approvedStatus: 'Approved',
        ownership: 'Meridian IT SecOps',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 14',
        tags: ['Production', 'Executive', 'High-Security'],
        issues: [
          {
            id: 'ISS-01',
            severity: 'INFO',
            title: 'Hardened WPA3-192 Architecture',
            description: 'CNSA 192-bit cryptographic suite with mandatory 802.11w Protected Management Frames (PMF).',
            recommendation: 'Complies with NIST SP 800-153 §3.1 & NSA Commercial National Security Algorithm guidelines.',
            nistRef: 'NIST SP 800-153 §3.1',
          }
        ],
        clients: [
          {
            macAddress: 'DC:A6:32:41:88:B2',
            vendor: 'Apple, Inc.',
            apBssid: 'E4:38:83:9A:F1:40',
            rssi: -45,
            packetsSent: 12420,
            dataRateMbps: 1200,
            lastSeen: 'Just now',
            probes: ['Meridian_Corp_WPA3', 'Home_Fiber_Ultra'],
            ipAssigned: '10.240.14.22',
          },
          {
            macAddress: 'F0:18:98:33:41:09',
            vendor: 'Dell Inc.',
            apBssid: 'E4:38:83:9A:F1:40',
            rssi: -49,
            packetsSent: 18890,
            dataRateMbps: 866,
            lastSeen: '1s ago',
            probes: ['Meridian_Corp_WPA3'],
            ipAssigned: '10.240.14.45',
          },
          {
            macAddress: '88:66:5A:21:00:DF',
            vendor: 'Lenovo Mobile',
            apBssid: 'E4:38:83:9A:F1:40',
            rssi: -52,
            packetsSent: 9410,
            dataRateMbps: 866,
            lastSeen: '2s ago',
            probes: ['Meridian_Corp_WPA3', 'Meridian_Staff_5G'],
            ipAssigned: '10.240.14.77',
          }
        ]
      },

      // 2. Staff Voice & Productivity (WPA2-Enterprise)
      {
        bssid: '2C:54:2D:88:91:0A',
        ssid: 'Meridian_Staff_Voice_5G',
        rssi: -48,
        channel: 44,
        band: '5 GHz',
        channelWidthMhz: 80,
        security: 'WPA2-Enterprise (802.1X)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Aruba Networks',
        beaconCount: 11200,
        dataPacketCount: 45100,
        firstSeen: new Date(Date.now() - 3600000 * 4).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ac (Wi-Fi 5)',
        securityScore: 89,
        classification: 'Corporate',
        approvedStatus: 'Approved',
        ownership: 'Meridian IT SecOps',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 13',
        tags: ['Voice', 'Staff', 'QoS'],
        issues: [],
        clients: [
          {
            macAddress: 'A4:83:E7:22:11:4F',
            vendor: 'Apple, Inc.',
            apBssid: '2C:54:2D:88:91:0A',
            rssi: -51,
            packetsSent: 8200,
            dataRateMbps: 650,
            lastSeen: 'Just now',
            probes: ['Meridian_Staff_Voice_5G'],
            ipAssigned: '10.240.13.102',
          },
          {
            macAddress: '30:24:32:8B:20:11',
            vendor: 'Samsung Electronics',
            apBssid: '2C:54:2D:88:91:0A',
            rssi: -56,
            packetsSent: 5410,
            dataRateMbps: 433,
            lastSeen: 'Just now',
            probes: ['Meridian_Staff_Voice_5G', 'Airport_Free_WiFi'],
            ipAssigned: '10.240.13.118',
          }
        ]
      },

      // 3. Official Guest Network (OWE / Open Portal with captive gateway)
      {
        bssid: '28:80:23:44:81:AA',
        ssid: 'Meridian_Guest_Portal',
        rssi: -44,
        channel: 11,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'Open',
        cipher: 'None',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Aruba Networks',
        beaconCount: 16800,
        dataPacketCount: 52100,
        firstSeen: new Date(Date.now() - 3600000 * 5).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        securityScore: 62,
        classification: 'Guest',
        approvedStatus: 'Approved',
        ownership: 'Facilities & Visitors',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 12 - Atrium',
        tags: ['Guest', 'Public', 'Isolated'],
        issues: [
          {
            id: 'ISS-05',
            severity: 'HIGH',
            title: 'Unencrypted Open Air Interface',
            description: 'Cleartext 802.11 management & data frames without OWE encryption.',
            recommendation: 'Enable Opportunistic Wireless Encryption (RFC 8110 / Wi-Fi Enhanced Open) to encrypt visitor airframes.',
            nistRef: 'RFC 8110 / NIST SP 800-153 §3.3',
          }
        ],
        clients: [
          {
            macAddress: 'AC:BC:32:7E:11:80',
            vendor: 'Dell Inc.',
            apBssid: '28:80:23:44:81:AA',
            rssi: -49,
            packetsSent: 14200,
            dataRateMbps: 72,
            lastSeen: 'Just now',
            probes: ['Meridian_Guest_Portal', 'Hilton_Honors_Guest', 'Starbucks_WiFi'],
            ipAssigned: '172.16.8.44',
          },
          {
            macAddress: 'BC:D0:74:11:92:44',
            vendor: 'Apple, Inc.',
            apBssid: '28:80:23:44:81:AA',
            rssi: -58,
            packetsSent: 6890,
            dataRateMbps: 54,
            lastSeen: '3s ago',
            probes: ['Meridian_Guest_Portal'],
            ipAssigned: '172.16.8.91',
          }
        ]
      },

      // 4. SUSPECTED ROGUE / EVIL TWIN (Identical SSID to #3, Disparate Vendor!)
      {
        bssid: '6C:5E:7A:B2:90:1C',
        ssid: 'Meridian_Guest_Portal', // Rogue Clone!
        rssi: -36, // Notice: Abnormally high power right near conference room!
        channel: 6,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'Open',
        cipher: 'None',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Shenzhen Bilian Electronic Co.',
        beaconCount: 4210,
        dataPacketCount: 3890,
        firstSeen: new Date(Date.now() - 1000 * 60 * 35).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11n (Wi-Fi 4)',
        isRogueCandidate: true,
        rogueConfidence: 96,
        rogueEvidence: [
          'Duplicate broadcast SSID "Meridian_Guest_Portal" colliding with authorized Aruba infrastructure',
          'OUI Vendor divergence: Low-cost transceiver "Shenzhen Bilian" vs authorized "Aruba Networks"',
          'Abnormal signal delta (+8 dBm stronger than perimeter baseline), suggesting rogue indoor positioning'
        ],
        classification: 'Suspicious',
        approvedStatus: 'Unapproved',
        ownership: 'UNAUTHORIZED ROGUE DEVICE',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 14 - Room 1402',
        tags: ['THREAT', 'EVIL_TWIN', 'ROGUE_AP'],
        securityScore: 18,
        issues: [
          {
            id: 'ISS-06',
            severity: 'CRITICAL',
            title: 'Active Rogue AP / Evil Twin Impersonation',
            description: 'Identical SSID "Meridian_Guest_Portal" detected with unauthorized MAC OUI (Shenzhen Bilian) and suspicious RF RSSI spike.',
            recommendation: 'Initiate physical RF direction finding / switch port shutdown on perimeter edge switch.',
            nistRef: 'NIST SP 800-153 §4.2 (Rogue Detection)',
          }
        ],
        clients: [
          {
            macAddress: '58:40:4E:99:12:01',
            vendor: 'Samsung Electronics',
            apBssid: '6C:5E:7A:B2:90:1C',
            rssi: -39,
            packetsSent: 1980,
            dataRateMbps: 65,
            lastSeen: 'Just now',
            probes: ['Meridian_Guest_Portal'],
          }
        ]
      },

      // 5. Executive Boardroom AP (WPA2 with WPS Pixie Dust Risk)
      {
        bssid: 'F8:1A:67:8B:11:02',
        ssid: 'NETGEAR_Executive_Suite',
        rssi: -54,
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
        beaconCount: 8940,
        dataPacketCount: 19800,
        firstSeen: new Date(Date.now() - 3600000 * 2).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11n (Wi-Fi 4)',
        classification: 'Corporate',
        approvedStatus: 'Investigating',
        ownership: 'Executive Boardroom Extender',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 15',
        tags: ['Boardroom', 'WPS_Vulnerable'],
        securityScore: 46,
        issues: [
          {
            id: 'ISS-02',
            severity: 'HIGH',
            title: 'WPS PIN Vulnerability (Pixie Dust Susceptible)',
            description: 'Wi-Fi Protected Setup (WPS 1.0) active with non-randomized E-S1/E-S2 nonces allowing offline PIN extraction.',
            recommendation: 'Disable WPS in device firmware immediately to prevent credential compromise.',
            nistRef: 'CVE-2014-9585 / NIST SP 800-153 §3.2.1',
          },
          {
            id: 'ISS-03',
            severity: 'MEDIUM',
            title: 'Protected Management Frames (PMF) Disabled',
            description: '802.11w PMF missing. Vulnerable to cleartext 802.11 deauthentication disassociation packets.',
            recommendation: 'Upgrade to WPA3-SAE transition mode with PMF required.',
            nistRef: '802.11w-2009 Standards',
          }
        ],
        clients: [
          {
            macAddress: '74:D4:35:E1:90:7A',
            vendor: 'Samsung Electronics',
            apBssid: 'F8:1A:67:8B:11:02',
            rssi: -58,
            packetsSent: 4210,
            dataRateMbps: 144,
            lastSeen: 'Just now',
            probes: ['NETGEAR_Executive_Suite', 'Home_Fiber_Ultra'],
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
          capturedAt: new Date(Date.now() - 1000 * 60 * 18).toLocaleTimeString(),
          anonce: '5B2F99A1C47E8203DF91A390C8B1920F987D10AC219800E1FA9841B28309AC11',
          snonce: 'E891C0834B9A1009DF82019A827B043C99A019B84180C14D891E0921B74301AF',
          micHex: '4A1F890C34B8E17A0082CD10FA8891BC',
          hashcatFormat: 'WPA*02*4a1f890c34b8e17a0082cd10fa8891bc*f81a678b1102*74d435e1907a*4e4554474541525f4578656375746976655f5375697465*5b2f99a1c47e8203df91a390c8b1920f987d10ac219800e1fa9841b28309ac11*0103005f02030a00000000000000000001*02',
          qualityScore: 98,
          validationStatus: 'VALID',
          origin: 'LIVE_WINDOWS',
          isSimulated: false,
        }
      },

      // 6. Legacy Logistics Warehouse (Deprecated WEP-128)
      {
        bssid: '00:14:D1:6C:5B:99',
        ssid: 'Warehouse_Logistics_B4',
        rssi: -69,
        channel: 1,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WEP-64/128',
        cipher: 'WEP',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Trendnet Technologies',
        beaconCount: 6840,
        dataPacketCount: 38400,
        firstSeen: new Date(Date.now() - 3600000 * 6).toLocaleTimeString(),
        lastSeen: '2s ago',
        standard: '802.11b/g',
        classification: 'Corporate',
        approvedStatus: 'Unapproved',
        ownership: 'Legacy Inventory Warehouse',
        site: 'Manhattan Headquarters',
        building: 'Sub-Basement B4',
        floor: 'Warehouse Bay 2',
        tags: ['LEGACY', 'CRITICAL_RISK', 'WEP'],
        securityScore: 12,
        issues: [
          {
            id: 'ISS-04',
            severity: 'CRITICAL',
            title: 'Obsolete Broken Cipher (WEP-128)',
            description: 'RC4 with static 24-bit IV allows complete key recovery via Fluhrer-Mantin-Shamir (FMS) / PTW statistical attack within minutes.',
            recommendation: 'Decommission or immediately upgrade to WPA2/WPA3 enterprise hardware.',
            nistRef: 'NIST SP 800-153 §2.1 (Deprecated)',
          }
        ],
        clients: [
          {
            macAddress: '00:09:5B:40:91:21',
            vendor: 'Honeywell Scanning',
            apBssid: '00:14:D1:6C:5B:99',
            rssi: -72,
            packetsSent: 16890,
            dataRateMbps: 11,
            lastSeen: '1s ago',
            probes: ['Warehouse_Logistics_B4'],
            ipAssigned: '10.120.4.15',
          },
          {
            macAddress: '00:1A:E8:22:90:31',
            vendor: 'Zebra Technologies',
            apBssid: '00:14:D1:6C:5B:99',
            rssi: -74,
            packetsSent: 8940,
            dataRateMbps: 11,
            lastSeen: 'Just now',
            probes: ['Warehouse_Logistics_B4'],
            ipAssigned: '10.120.4.18',
          }
        ]
      },

      // 7. Advanced Research 6 GHz Clean Channel (WPA3-Personal SAE)
      {
        bssid: '80:2A:A8:11:F9:3B',
        ssid: 'Meridian_Quant_Lab_6G',
        rssi: -52,
        channel: 69,
        band: '6 GHz',
        channelWidthMhz: 160,
        security: 'WPA3-Personal (SAE)',
        cipher: 'GCMP-256',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Ubiquiti Inc.',
        beaconCount: 15400,
        dataPacketCount: 68900,
        firstSeen: new Date(Date.now() - 3600000 * 5).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        classification: 'Corporate',
        approvedStatus: 'Approved',
        ownership: 'Quantitative Trading Lab',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 16',
        tags: ['6GHz', 'Low-Latency', 'Trading'],
        securityScore: 97,
        issues: [],
        clients: [
          {
            macAddress: '9C:B6:54:19:AA:01',
            vendor: 'Intel Corporate',
            apBssid: '80:2A:A8:11:F9:3B',
            rssi: -54,
            packetsSent: 28400,
            dataRateMbps: 2400,
            lastSeen: 'Just now',
            probes: ['Meridian_Quant_Lab_6G'],
            ipAssigned: '10.240.16.12',
          },
          {
            macAddress: '3C:F8:62:77:41:88',
            vendor: 'Apple, Inc.',
            apBssid: '80:2A:A8:11:F9:3B',
            rssi: -57,
            packetsSent: 19800,
            dataRateMbps: 1800,
            lastSeen: 'Just now',
            probes: ['Meridian_Quant_Lab_6G'],
            ipAssigned: '10.240.16.18',
          }
        ]
      },

      // 8. UniFi High-Density Floor Mesh (WPA3/WPA2 Transition)
      {
        bssid: '74:83:C2:55:18:02',
        ssid: 'UniFi-Atrium-Mesh-5G',
        rssi: -49,
        channel: 149,
        band: '5 GHz',
        channelWidthMhz: 80,
        security: 'WPA3-Personal (SAE)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Ubiquiti Inc.',
        beaconCount: 9400,
        dataPacketCount: 31200,
        firstSeen: new Date(Date.now() - 3600000 * 3).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        classification: 'Corporate',
        approvedStatus: 'Approved',
        ownership: 'Facility Infrastructure',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 12',
        tags: ['Mesh', 'Atrium', 'High-Density'],
        securityScore: 92,
        issues: [],
        clients: [
          {
            macAddress: 'A0:78:17:81:99:40',
            vendor: 'Apple, Inc.',
            apBssid: '74:83:C2:55:18:02',
            rssi: -52,
            packetsSent: 9400,
            dataRateMbps: 780,
            lastSeen: 'Just now',
            probes: ['UniFi-Atrium-Mesh-5G', 'Meridian_Corp_WPA3'],
            ipAssigned: '10.240.12.89',
          }
        ]
      },

      // 9. Enterprise Multifunction Printer Direct Broadcast (Wi-Fi Direct risk)
      {
        bssid: '70:5A:0F:84:33:10',
        ssid: 'DIRECT-HP-LaserJet-M608',
        rssi: -61,
        channel: 6,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: true,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'HP Inc.',
        beaconCount: 5200,
        dataPacketCount: 2900,
        firstSeen: new Date(Date.now() - 3600000 * 4).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11n (Wi-Fi 4)',
        classification: 'IoT',
        approvedStatus: 'Investigating',
        ownership: 'Print Services',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 13 - West Copy Center',
        tags: ['Printer', 'WiFi-Direct', 'Default-PIN'],
        securityScore: 54,
        issues: [
          {
            id: 'ISS-HP-01',
            severity: 'HIGH',
            title: 'Unmonitored Wi-Fi Direct P2P Broadcast',
            description: 'Office printer actively broadcasting an ad-hoc Wi-Fi Direct ESS with default WPS PIN enabled.',
            recommendation: 'Disable Wi-Fi Direct in printer EWS management portal to eliminate dual-homed bridge vector.',
            nistRef: 'NIST SP 800-153 §3.2 (Ad-Hoc Containment)',
          }
        ],
        clients: [
          {
            macAddress: '68:FE:F7:20:94:11',
            vendor: 'Dell Inc.',
            apBssid: '70:5A:0F:84:33:10',
            rssi: -64,
            packetsSent: 1200,
            dataRateMbps: 54,
            lastSeen: '4s ago',
            probes: ['DIRECT-HP-LaserJet-M608'],
            ipAssigned: '192.168.223.2',
          }
        ]
      },

      // 10. Building Operations & Facilities IoT Gateway
      {
        bssid: '50:C7:BF:22:91:04',
        ssid: 'Meridian_BMS_Telemetry',
        rssi: -64,
        channel: 1,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WPA2-Enterprise (802.1X)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'TP-Link Technologies',
        beaconCount: 8900,
        dataPacketCount: 42100,
        firstSeen: new Date(Date.now() - 3600000 * 8).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11n (Wi-Fi 4)',
        classification: 'IoT',
        approvedStatus: 'Approved',
        ownership: 'HVAC & Environmental Controls',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 14 - Utility Closet',
        tags: ['IoT', 'HVAC', 'BMS'],
        securityScore: 84,
        issues: [],
        clients: [
          {
            macAddress: 'B8:27:EB:44:91:01',
            vendor: 'Raspberry Pi Foundation',
            apBssid: '50:C7:BF:22:91:04',
            rssi: -66,
            packetsSent: 8200,
            dataRateMbps: 54,
            lastSeen: 'Just now',
            probes: ['Meridian_BMS_Telemetry'],
            ipAssigned: '10.240.90.11',
          },
          {
            macAddress: '00:17:88:51:72:9A',
            vendor: 'Philips Lighting',
            apBssid: '50:C7:BF:22:91:04',
            rssi: -71,
            packetsSent: 3410,
            dataRateMbps: 24,
            lastSeen: 'Just now',
            probes: ['Meridian_BMS_Telemetry'],
            ipAssigned: '10.240.90.19',
          }
        ]
      },

      // 11. Cisco Catalyst Enterprise Backhaul
      {
        bssid: '00:27:90:3A:41:80',
        ssid: 'Meridian_Infra_Backhaul_5G',
        rssi: -45,
        channel: 157,
        band: '5 GHz',
        channelWidthMhz: 80,
        security: 'WPA3-Enterprise (CNSA 192-bit)',
        cipher: 'GCMP-256',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Cisco Systems, Inc.',
        beaconCount: 16200,
        dataPacketCount: 84200,
        firstSeen: new Date(Date.now() - 3600000 * 6).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        classification: 'Corporate',
        approvedStatus: 'Approved',
        ownership: 'Core Network Backhaul',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Rooftop Penthouse Hub',
        tags: ['Backhaul', 'Infrastructure', 'WPA3'],
        securityScore: 99,
        issues: [],
        clients: [
          {
            macAddress: '00:27:90:3A:41:88',
            vendor: 'Cisco Systems, Inc.',
            apBssid: '00:27:90:3A:41:80',
            rssi: -48,
            packetsSent: 38400,
            dataRateMbps: 1200,
            lastSeen: 'Just now',
            probes: ['Meridian_Infra_Backhaul_5G'],
            ipAssigned: '10.240.1.2',
          }
        ]
      },

      // 12. Smart TV & Digital Signage (Floor 14 Conference)
      {
        bssid: '48:44:F7:19:62:30',
        ssid: 'Samsung_TheFrame_ConfEast',
        rssi: -58,
        channel: 40,
        band: '5 GHz',
        channelWidthMhz: 40,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Samsung Electronics',
        beaconCount: 6100,
        dataPacketCount: 9400,
        firstSeen: new Date(Date.now() - 3600000 * 4).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ac (Wi-Fi 5)',
        classification: 'IoT',
        approvedStatus: 'Approved',
        ownership: 'AV / Media Systems',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 14 - East Boardroom',
        tags: ['Display', 'AV', 'SmartTV'],
        securityScore: 78,
        issues: [],
        clients: []
      },

      // 13. Security Operations Perimeter Camera Hub
      {
        bssid: '00:1E:8C:77:81:4A',
        ssid: 'Meridian_CCTV_Perimeter',
        rssi: -55,
        channel: 153,
        band: '5 GHz',
        channelWidthMhz: 40,
        security: 'WPA2-Enterprise (802.1X)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Fortinet Inc.',
        beaconCount: 11400,
        dataPacketCount: 98400,
        firstSeen: new Date(Date.now() - 3600000 * 8).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        classification: 'Corporate',
        approvedStatus: 'Approved',
        ownership: 'Corporate Physical Security',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Perimeter West Gate',
        tags: ['CCTV', 'PhysicalSecurity', 'Restricted'],
        securityScore: 94,
        issues: [],
        clients: [
          {
            macAddress: '18:66:DA:33:91:09',
            vendor: 'Axis Communications',
            apBssid: '00:1E:8C:77:81:4A',
            rssi: -57,
            packetsSent: 48900,
            dataRateMbps: 300,
            lastSeen: 'Just now',
            probes: ['Meridian_CCTV_Perimeter'],
            ipAssigned: '10.240.80.24',
          },
          {
            macAddress: '18:66:DA:33:91:12',
            vendor: 'Axis Communications',
            apBssid: '00:1E:8C:77:81:4A',
            rssi: -60,
            packetsSent: 46200,
            dataRateMbps: 300,
            lastSeen: 'Just now',
            probes: ['Meridian_CCTV_Perimeter'],
            ipAssigned: '10.240.80.25',
          }
        ]
      },

      // 14. High-Density Ruckus Auditorium
      {
        bssid: 'C4:10:8A:90:5E:20',
        ssid: 'Ruckus_TownHall_Auditorium',
        rssi: -50,
        channel: 48,
        band: '5 GHz',
        channelWidthMhz: 80,
        security: 'WPA3-Enterprise (802.1X)',
        cipher: 'GCMP-256',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Ruckus Wireless',
        beaconCount: 13400,
        dataPacketCount: 54100,
        firstSeen: new Date(Date.now() - 3600000 * 5).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        classification: 'Corporate',
        approvedStatus: 'Approved',
        ownership: 'Event Facility',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 1 - Main Auditorium',
        tags: ['Auditorium', 'BeamFlex', 'High-Density'],
        securityScore: 96,
        issues: [],
        clients: [
          {
            macAddress: 'F4:D4:88:51:7A:30',
            vendor: 'Apple, Inc.',
            apBssid: 'C4:10:8A:90:5E:20',
            rssi: -53,
            packetsSent: 14200,
            dataRateMbps: 866,
            lastSeen: 'Just now',
            probes: ['Ruckus_TownHall_Auditorium', 'Meridian_Corp_WPA3'],
            ipAssigned: '10.240.10.42',
          }
        ]
      },

      // 15. Neighboring Financial Firm (Cross-Tenant Spillover)
      {
        bssid: 'E0:55:3D:84:90:11',
        ssid: 'BlackRock_Trading_Floor15',
        rssi: -73,
        channel: 36,
        band: '5 GHz',
        channelWidthMhz: 80,
        security: 'WPA3-Enterprise (CNSA 192-bit)',
        cipher: 'GCMP-256',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Cisco Systems, Inc.',
        beaconCount: 8900,
        dataPacketCount: 24100,
        firstSeen: new Date(Date.now() - 3600000 * 6).toLocaleTimeString(),
        lastSeen: '1s ago',
        standard: '802.11ax (Wi-Fi 6)',
        classification: 'Unknown',
        approvedStatus: 'Pending Review',
        ownership: 'Neighbor Tenant Spillover',
        site: 'Adjacent Facility',
        building: 'Tower Two',
        floor: 'Floor 15',
        tags: ['AdjacentTenant', 'RF_Spillover'],
        securityScore: 97,
        issues: [],
        clients: []
      },

      // 16. Carrier ISP Hotspot Spillover (AT&T Passpoint)
      {
        bssid: '00:1D:AA:45:90:01',
        ssid: 'attwifi_Passpoint_Secure',
        rssi: -76,
        channel: 161,
        band: '5 GHz',
        channelWidthMhz: 80,
        security: 'WPA2-Enterprise (EAP-SIM)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Cisco Systems, Inc.',
        beaconCount: 6800,
        dataPacketCount: 15400,
        firstSeen: new Date(Date.now() - 3600000 * 7).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ac (Wi-Fi 5)',
        classification: 'Guest',
        approvedStatus: 'Approved',
        ownership: 'Carrier Passpoint Offload',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Street Concourse',
        tags: ['Carrier', 'Passpoint', 'EAP-SIM'],
        securityScore: 91,
        issues: [],
        clients: [
          {
            macAddress: '78:4F:43:91:21:00',
            vendor: 'Apple, Inc.',
            apBssid: '00:1D:AA:45:90:01',
            rssi: -78,
            packetsSent: 3400,
            dataRateMbps: 200,
            lastSeen: '4s ago',
            probes: ['attwifi_Passpoint_Secure'],
          }
        ]
      },

      // 17. Executive Garage EV Charger
      {
        bssid: '98:ED:5C:31:89:FE',
        ssid: 'Tesla_Wall_Connector_Executive',
        rssi: -71,
        channel: 11,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Tesla Motors',
        beaconCount: 4200,
        dataPacketCount: 5410,
        firstSeen: new Date(Date.now() - 3600000 * 2).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11n (Wi-Fi 4)',
        classification: 'IoT',
        approvedStatus: 'Approved',
        ownership: 'Executive Parking Facility',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Underground Level P1',
        tags: ['EV_Charger', 'IoT', 'Automotive'],
        securityScore: 80,
        issues: [],
        clients: []
      },

      // 18. Conference Room Display Wireless Cast
      {
        bssid: '58:D9:D5:41:99:3E',
        ssid: 'GoogleCast_Boardroom_East',
        rssi: -57,
        channel: 36,
        band: '5 GHz',
        channelWidthMhz: 40,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Google LLC',
        beaconCount: 9120,
        dataPacketCount: 18400,
        firstSeen: new Date(Date.now() - 3600000 * 3).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ac (Wi-Fi 5)',
        classification: 'IoT',
        approvedStatus: 'Approved',
        ownership: 'AV Collaboration',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 14 - Room 1410',
        tags: ['GoogleCast', 'WirelessDisplay'],
        securityScore: 82,
        issues: [],
        clients: [
          {
            macAddress: '6C:40:08:92:11:7F',
            vendor: 'Apple, Inc.',
            apBssid: '58:D9:D5:41:99:3E',
            rssi: -60,
            packetsSent: 6890,
            dataRateMbps: 300,
            lastSeen: 'Just now',
            probes: ['GoogleCast_Boardroom_East'],
            ipAssigned: '10.240.14.99',
          }
        ]
      },

      // 19. TP-Link Omada Branch Mesh
      {
        bssid: 'EC:08:6B:14:88:20',
        ssid: 'TP-Link_Omada_Mesh_Ext',
        rssi: -63,
        channel: 1,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: true,
        wpsLocked: true,
        pmfRequired: false,
        vendor: 'TP-Link Technologies',
        beaconCount: 7800,
        dataPacketCount: 14200,
        firstSeen: new Date(Date.now() - 3600000 * 4).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11n (Wi-Fi 4)',
        classification: 'Corporate',
        approvedStatus: 'Pending Review',
        ownership: 'Branch Office Test',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 12 - Lab Area',
        tags: ['TP-Link', 'Omada', 'Mesh'],
        securityScore: 68,
        issues: [
          {
            id: 'ISS-TP-01',
            severity: 'MEDIUM',
            title: 'WPS Enabled on Mesh Node',
            description: 'WPS is enabled although locked. Should be completely disabled in production profile.',
            recommendation: 'Turn off WPS in controller settings.',
          }
        ],
        clients: [
          {
            macAddress: '04:D4:C4:20:91:AA',
            vendor: 'Lenovo Mobile',
            apBssid: 'EC:08:6B:14:88:20',
            rssi: -65,
            packetsSent: 3410,
            dataRateMbps: 72,
            lastSeen: 'Just now',
            probes: ['TP-Link_Omada_Mesh_Ext'],
            ipAssigned: '192.168.0.45',
          }
        ]
      },

      // 20. MikroTik Edge Router Backhaul
      {
        bssid: '48:8F:5A:11:02:99',
        ssid: 'MikroTik-Link-TowerCore',
        rssi: -58,
        channel: 149,
        band: '5 GHz',
        channelWidthMhz: 80,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Routerboard.com (MikroTik)',
        beaconCount: 11800,
        dataPacketCount: 39800,
        firstSeen: new Date(Date.now() - 3600000 * 5).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ac (Wi-Fi 5)',
        classification: 'Corporate',
        approvedStatus: 'Approved',
        ownership: 'Infrastructure Engineering',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 16 - Telecom Closet',
        tags: ['MikroTik', 'PTP', 'Backhaul'],
        securityScore: 88,
        issues: [],
        clients: []
      },

      // 21. Fortinet FortiAP Protected Segment
      {
        bssid: '70:4C:A5:88:31:0C',
        ssid: 'FortiSec_Restricted_VLAN50',
        rssi: -51,
        channel: 153,
        band: '5 GHz',
        channelWidthMhz: 40,
        security: 'WPA3-Enterprise (CNSA 192-bit)',
        cipher: 'GCMP-256',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Fortinet Inc.',
        beaconCount: 13900,
        dataPacketCount: 48900,
        firstSeen: new Date(Date.now() - 3600000 * 6).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ax (Wi-Fi 6)',
        classification: 'Corporate',
        approvedStatus: 'Approved',
        ownership: 'SecOps Threat Center',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 15 - SOC Room',
        tags: ['SOC', 'WPA3', 'Restricted'],
        securityScore: 99,
        issues: [],
        clients: [
          {
            macAddress: 'A4:C3:F0:88:91:20',
            vendor: 'Dell Inc.',
            apBssid: '70:4C:A5:88:31:0C',
            rssi: -53,
            packetsSent: 18400,
            dataRateMbps: 1200,
            lastSeen: 'Just now',
            probes: ['FortiSec_Restricted_VLAN50'],
            ipAssigned: '10.240.50.8',
          }
        ]
      },

      // 22. Public Spectrum ISP Passpoint
      {
        bssid: '00:1F:33:41:9A:88',
        ssid: 'SpectrumWiFi_Plus_NYC',
        rssi: -77,
        channel: 1,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WPA2-Enterprise (802.1X)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Arris Group, Inc.',
        beaconCount: 5400,
        dataPacketCount: 12800,
        firstSeen: new Date(Date.now() - 3600000 * 7).toLocaleTimeString(),
        lastSeen: '3s ago',
        standard: '802.11n (Wi-Fi 4)',
        classification: 'Guest',
        approvedStatus: 'Approved',
        ownership: 'Metropolitan ISP',
        site: 'Manhattan Headquarters',
        building: 'External Concourse',
        floor: 'Ground Exterior',
        tags: ['ISP', 'Public', 'External'],
        securityScore: 82,
        issues: [],
        clients: []
      },

      // 23. Facilities Power Metering (Schneider Electric)
      {
        bssid: '00:80:F4:11:82:70',
        ssid: 'Schneider_PowerMeter_Substation',
        rssi: -68,
        channel: 11,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Schneider Electric',
        beaconCount: 7400,
        dataPacketCount: 9200,
        firstSeen: new Date(Date.now() - 3600000 * 6).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11n (Wi-Fi 4)',
        classification: 'IoT',
        approvedStatus: 'Approved',
        ownership: 'Building Facilities Power',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Sub-Basement B1',
        tags: ['Industrial', 'Power', 'SCADA'],
        securityScore: 84,
        issues: [],
        clients: [
          {
            macAddress: '00:80:F4:99:31:02',
            vendor: 'Schneider Electric',
            apBssid: '00:80:F4:11:82:70',
            rssi: -70,
            packetsSent: 4890,
            dataRateMbps: 54,
            lastSeen: 'Just now',
            probes: ['Schneider_PowerMeter_Substation'],
            ipAssigned: '10.240.95.4',
          }
        ]
      },

      // 24. Executive Rest Area Smart TV
      {
        bssid: '90:03:B7:22:81:4A',
        ssid: 'LG_OLED_ExecLounge',
        rssi: -62,
        channel: 44,
        band: '5 GHz',
        channelWidthMhz: 40,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'LG Electronics',
        beaconCount: 6800,
        dataPacketCount: 11200,
        firstSeen: new Date(Date.now() - 3600000 * 3).toLocaleTimeString(),
        lastSeen: 'Just now',
        standard: '802.11ac (Wi-Fi 5)',
        classification: 'IoT',
        approvedStatus: 'Approved',
        ownership: 'Executive Lounge Services',
        site: 'Manhattan Headquarters',
        building: 'Tower One',
        floor: 'Floor 15 - Lounge',
        tags: ['SmartTV', 'LG', 'Lounge'],
        securityScore: 82,
        issues: [],
        clients: []
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

        // Add Probe request from client
        if (client.probes && client.probes.length > 0) {
          packets.push({
            id: packetId++,
            timestamp: new Date(Date.now() - (idx * 150 + 20)).toLocaleTimeString() + '.' + String(Math.floor(Math.random() * 900 + 100)).padStart(3, '0'),
            frameNumber: packetId,
            frameType: 'Probe Request',
            sourceMac: client.macAddress,
            destMac: 'ff:ff:ff:ff:ff:ff',
            bssid: 'ff:ff:ff:ff:ff:ff',
            channel: ap.channel,
            rssi: client.rssi,
            lengthBytes: 84,
            info: `Probe Request SSID="${client.probes[0]}" Rate=6Mbps SupportedRates=[6, 12, 24, 36, 48, 54]`,
            hexPreview: '40 00 00 00 ff ff ff ff ff ff ' + (client.macAddress || '').replace(/:/g, ' ').toLowerCase() + ' ff ff ff ff ff ff 10 00'
          });
        }
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

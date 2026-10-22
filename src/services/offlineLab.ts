import { TrainingLabScenario, AccessPoint, PcapPacket, HandshakeInfo } from '../types';

export const TRAINING_SCENARIOS: TrainingLabScenario[] = [
  {
    id: 'LAB-01',
    title: 'Modern Secure Enterprise Baseline (Wi-Fi 6 / WPA3 / PMF)',
    category: 'Secure',
    difficulty: 'Beginner',
    description: 'Examine a properly architected enterprise wireless deployment adhering to NIST SP 800-153 and zero-trust principles.',
    learningObjectives: [
      'Understand WPA3-SAE Simultaneous Authentication of Equals',
      'Verify 802.11w Protected Management Frames (PMF) enforcement',
      'Inspect 802.11ax Wi-Fi 6 Information Elements'
    ],
    simulatedAPs: [
      {
        bssid: '00:11:22:33:44:00',
        ssid: 'Corp_Secure_HQ',
        rssi: -48,
        channel: 36,
        band: '5 GHz',
        channelWidthMhz: 80,
        security: 'WPA3-Personal (SAE)',
        cipher: 'GCMP-256',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Cisco Systems, Inc',
        oui: '00:11:22',
        beaconCount: 342,
        dataPacketCount: 1240,
        firstSeen: '10:00:00',
        lastSeen: '10:45:00',
        standard: '802.11ax (Wi-Fi 6)',
        clients: [
          {
            macAddress: '3C:F8:62:01:99:A1',
            vendor: 'Apple, Inc.',
            apBssid: '00:11:22:33:44:00',
            connectedSsid: 'Corp_Secure_HQ',
            rssi: -52,
            packetsSent: 412,
            dataRateMbps: 866,
            firstSeen: '10:05:00',
            lastSeen: '10:45:00',
            probes: ['Corp_Secure_HQ'],
            isAssociated: true,
            eapolPacketsObserved: 2
          }
        ],
        securityScore: 100,
        issues: [],
        classification: 'Corporate',
        approvedStatus: 'Approved',
        tags: ['Production', 'HQ-Floor-3', 'Cisco-Catalyst'],
        historicalObservationsCount: 1420
      }
    ],
    simulatedPackets: [
      {
        id: 1,
        timestamp: '10:00:00.100',
        frameNumber: 1,
        frameType: 'Beacon',
        sourceMac: '00:11:22:33:44:00',
        destMac: 'FF:FF:FF:FF:FF:FF',
        bssid: '00:11:22:33:44:00',
        channel: 36,
        rssi: -48,
        lengthBytes: 184,
        info: 'SSID: "Corp_Secure_HQ", Ch: 36, WPA3-SAE, PMF Mandatory',
        hexPreview: '00 00 18 00 2e 48 00 00 00 02 6c 09 a0 00 e4 00'
      }
    ],
    simulatedHandshakes: [],
    guidedExplanation: {
      overview: 'This scenario represents an ideal, modern corporate AP. It uses WPA3 with 256-bit Galois/Counter Mode Protocol (GCMP) and enforces Protected Management Frames.',
      whyItMatters: 'With PMF required, deauthentication spoofing attacks are impossible because management frames are cryptographically authenticated. Offline dictionary attacks are prevented by SAE Dragonfly exchange.',
      howToInvestigate: 'Observe the 100/100 posture score. Notice that WPS is absent and the PMF Required flag is active in RSN Tag 48.',
      remediation: 'No remediation needed. Use this profile as the organizational compliance baseline.'
    }
  },
  {
    id: 'LAB-02',
    title: 'Unencrypted Open Public Network Exposure',
    category: 'Vulnerability',
    difficulty: 'Beginner',
    description: 'Explore an unencrypted guest network transmitting cleartext frames across the 2.4 GHz spectrum.',
    learningObjectives: [
      'Recognize missing RSN/WPA Information Elements in beacon frames',
      'Understand passive eavesdropping risks on public airwaves',
      'Compare Open networks with OWE (Opportunistic Wireless Encryption)'
    ],
    simulatedAPs: [
      {
        bssid: '00:1A:2B:3C:4D:5E',
        ssid: 'Guest_Free_WiFi',
        rssi: -62,
        channel: 6,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'Open',
        cipher: 'None',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Ubiquiti Networks Inc.',
        oui: '00:1A:2B',
        beaconCount: 180,
        dataPacketCount: 650,
        firstSeen: '10:02:00',
        lastSeen: '10:45:00',
        standard: '802.11ac (Wi-Fi 5)',
        clients: [],
        securityScore: 60,
        issues: [
          {
            id: 'VULN-OPEN-UNENCRYPTED',
            severity: 'HIGH',
            title: 'Unencrypted 802.11 Wireless Medium',
            description: 'Radio layer traffic is transmitted in cleartext. Any nearby station can passively capture session tokens and credentials.',
            recommendation: 'Deploy Opportunistic Wireless Encryption (OWE / RFC 8110) or mandate VPN tunnels for guest clients.'
          }
        ],
        classification: 'Guest',
        approvedStatus: 'Pending Review',
        tags: ['Guest', 'Visitor-Lobby'],
        historicalObservationsCount: 420
      }
    ],
    simulatedPackets: [
      {
        id: 1,
        timestamp: '10:02:00.050',
        frameNumber: 1,
        frameType: 'Beacon',
        sourceMac: '00:1A:2B:3C:4D:5E',
        destMac: 'FF:FF:FF:FF:FF:FF',
        bssid: '00:1A:2B:3C:4D:5E',
        channel: 6,
        rssi: -62,
        lengthBytes: 112,
        info: 'SSID: "Guest_Free_WiFi", Ch: 6, Open (No RSN IE)',
        hexPreview: '00 00 18 00 2e 48 00 00 00 02 6c 09 a0 00 80 00'
      }
    ],
    simulatedHandshakes: [],
    guidedExplanation: {
      overview: 'Open networks provide zero cryptographic security at the 802.11 physical layer.',
      whyItMatters: 'Any passive eavesdropper using an inexpensive Wi-Fi adapter can capture unencrypted HTTP requests, DNS queries, and cleartext payloads without authenticating.',
      howToInvestigate: 'Notice the 60/100 score. The Security Analyzer flags VULN-OPEN-UNENCRYPTED because the beacon lacks RSN Tag 48.',
      remediation: 'Deploy Wi-Fi Enhanced Open (OWE / RFC 8110) which provides Diffie-Hellman encryption without requiring passwords.'
    }
  },
  {
    id: 'LAB-03',
    title: 'Critical Legacy WEP-128 Protocol Exposure',
    category: 'Vulnerability',
    difficulty: 'Intermediate',
    description: 'Inspect a legacy barcode scanner network still running deprecated WEP-128 encryption.',
    learningObjectives: [
      'Understand 24-bit Initialization Vector (IV) keystream reuse in RC4',
      'Audit PCI-DSS 4.0 Requirement 2.1 compliance failure',
      'Explain why WEP can be cracked in under 60 seconds'
    ],
    simulatedAPs: [
      {
        bssid: '00:14:D1:68:90:22',
        ssid: 'Warehouse_Barcodes',
        rssi: -71,
        channel: 11,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WEP-64/128',
        cipher: 'WEP',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'D-Link Corporation',
        oui: '00:14:D1',
        beaconCount: 410,
        dataPacketCount: 1890,
        firstSeen: '09:30:00',
        lastSeen: '10:45:00',
        standard: '802.11b/g',
        clients: [],
        securityScore: 40,
        issues: [
          {
            id: 'VULN-WEP-BROKEN',
            severity: 'CRITICAL',
            title: 'Deprecated Insecure WEP Encryption',
            description: 'The network is using 802.11 WEP encryption. Weak 24-bit IV keys can be cracked cryptanalytically in under 60 seconds using FMS/KoreK/PTW attacks.',
            recommendation: 'Migrate hardware immediately to WPA2-Enterprise or WPA3-SAE.'
          }
        ],
        classification: 'IoT',
        approvedStatus: 'Unapproved',
        tags: ['Warehouse-North', 'Legacy-HW', 'PCI-Violation'],
        historicalObservationsCount: 1120
      }
    ],
    simulatedPackets: [],
    simulatedHandshakes: [],
    guidedExplanation: {
      overview: 'WEP (Wired Equivalent Privacy) uses the stream cipher RC4 with a 24-bit Initialization Vector (IV). Because the IV is sent in the clear and frequently repeats, cryptanalytic statistical algorithms (such as PTW) recover the secret key from a few thousand packets.',
      whyItMatters: 'Total failure of network confidentiality and mutual authentication. Direct violation of PCI-DSS and NIST guidelines.',
      howToInvestigate: 'Score drops to 40/100. Finding VULN-WEP-BROKEN is marked with CRITICAL severity.',
      remediation: 'Retire legacy 802.11b devices and migrate to WPA2-AES or WPA3-SAE.'
    }
  },
  {
    id: 'LAB-05',
    title: 'Rogue AP / Evil Twin Corporate Impersonation',
    category: 'Threat',
    difficulty: 'Advanced',
    description: 'Detect an unauthorized clone broadcasting the corporate SSID "Corp_Secure" with an Open security configuration and rogue OUI.',
    learningObjectives: [
      'Correlate multi-factor indicators (SSID match, OUI divergence, security downgrade)',
      'Inspect automated Rogue AP confidence scoring (94%)',
      'Follow incident response triage in the Threat & Investigations Center'
    ],
    simulatedAPs: [
      {
        bssid: '00:11:22:33:44:01',
        ssid: 'Corp_Secure',
        rssi: -50,
        channel: 44,
        band: '5 GHz',
        channelWidthMhz: 40,
        security: 'WPA2-Enterprise (802.1X)',
        cipher: 'CCMP (AES)',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: true,
        vendor: 'Cisco Systems, Inc',
        oui: '00:11:22',
        beaconCount: 650,
        dataPacketCount: 2200,
        firstSeen: '08:00:00',
        lastSeen: '10:45:00',
        standard: '802.11ax (Wi-Fi 6)',
        clients: [],
        securityScore: 95,
        issues: [],
        classification: 'Corporate',
        approvedStatus: 'Approved',
        tags: ['HQ-Corporate', 'Authorized-AP'],
        historicalObservationsCount: 2800
      },
      {
        bssid: 'AA:BB:CC:DD:EE:99',
        ssid: 'Corp_Secure',
        rssi: -42,
        channel: 1,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'Open',
        cipher: 'None',
        wpsEnabled: false,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'Espressif Inc.',
        oui: 'AA:BB:CC',
        beaconCount: 45,
        dataPacketCount: 12,
        firstSeen: '10:35:00',
        lastSeen: '10:45:00',
        standard: '802.11n (Wi-Fi 4)',
        clients: [],
        securityScore: 20,
        issues: [
          {
            id: 'ROGUE-EVIL-TWIN',
            severity: 'CRITICAL',
            title: 'Suspected Evil Twin / Rogue AP Clone',
            description: 'An unauthorized clone of SSID "Corp_Secure" was identified with downgraded security (Open) compared to peer AP 00:11:22:33:44:01.',
            recommendation: 'Investigate physical location of BSSID. Blacklist client connection profiles.'
          }
        ],
        isRogueCandidate: true,
        rogueConfidence: 94,
        rogueEvidence: [
          'Same corporate SSID "Corp_Secure" cloned on unauthorized OUI (Espressif)',
          'Security downgrade: Authorized AP uses WPA2-Enterprise; clone uses Open',
          'Unexpected channel & band: 2.4 GHz Ch 1 vs authorized 5 GHz Ch 44',
          'First observed only 10 minutes ago with unusually strong -42 dBm signal'
        ],
        classification: 'Rogue',
        approvedStatus: 'Investigating',
        tags: ['SUSPICIOUS-CLONE', 'INC-00042'],
        historicalObservationsCount: 45
      }
    ],
    simulatedPackets: [],
    simulatedHandshakes: [],
    guidedExplanation: {
      overview: 'An attacker has deployed a portable rogue access point (e.g. Wi-Fi Pineapple or ESP8266) broadcasting the trusted corporate SSID "Corp_Secure" to trick mobile devices into auto-connecting.',
      whyItMatters: 'Victims connecting to the rogue AP have their traffic intercepted, credentials captured, or are redirected to credential-harvesting phishing portals.',
      howToInvestigate: 'Open the Threats tab and review the simulated divergence evidence. Use the incident workflow to record findings if you want to practice case handling.',
      remediation: 'Physically locate the rogue device using signal triangulation. Instruct employees not to connect to unencrypted versions of corporate SSIDs.'
    }
  },
  {
    id: 'LAB-07',
    title: 'Cryptographic Handshake Forensics & Hashcat Export',
    category: 'Forensic',
    difficulty: 'Advanced',
    description: 'Inspect captured 802.11 EAPOL 4-way key frames, examine ANonce/SNonce generation, and verify Hashcat Mode 22000 output.',
    learningObjectives: [
      'Trace the 4-way handshake exchange between Authenticator and Supplicant',
      'Validate Replay Counter synchronization between M1 and M2',
      'Examine 16-byte Message Integrity Code (MIC) and Hashcat 22000 format'
    ],
    simulatedAPs: [
      {
        bssid: 'F8:1A:67:8B:11:02',
        ssid: 'Netgear_Engineering',
        rssi: -58,
        channel: 6,
        band: '2.4 GHz',
        channelWidthMhz: 20,
        security: 'WPA2-Personal (AES)',
        cipher: 'CCMP (AES)',
        wpsEnabled: true,
        wpsLocked: false,
        pmfRequired: false,
        vendor: 'NETGEAR Inc.',
        oui: 'F8:1A:67',
        beaconCount: 520,
        dataPacketCount: 1640,
        firstSeen: '09:00:00',
        lastSeen: '10:45:00',
        standard: '802.11ac (Wi-Fi 5)',
        clients: [
          {
            macAddress: '3C:F8:62:01:99:A1',
            vendor: 'Intel Mobile',
            apBssid: 'F8:1A:67:8B:11:02',
            connectedSsid: 'Netgear_Engineering',
            rssi: -54,
            packetsSent: 340,
            dataRateMbps: 300,
            firstSeen: '09:15:00',
            lastSeen: '10:45:00',
            probes: ['Netgear_Engineering'],
            isAssociated: true,
            eapolPacketsObserved: 4
          }
        ],
        securityScore: 65,
        issues: [
          {
            id: 'VULN-WPS-PIN',
            severity: 'HIGH',
            title: 'Wi-Fi Protected Setup (WPS) Active',
            description: 'WPS PIN validation is active, exposing the AP to offline Pixie Dust PRNG recovery.',
            recommendation: 'Disable WPS completely in AP management firmware.'
          }
        ],
        classification: 'Corporate',
        approvedStatus: 'Approved',
        tags: ['Lab-Engineering'],
        historicalObservationsCount: 1640
      }
    ],
    simulatedPackets: [
      {
        id: 1,
        timestamp: '10:12:01.010',
        frameNumber: 1,
        frameType: 'EAPOL Key',
        sourceMac: 'F8:1A:67:8B:11:02',
        destMac: '3C:F8:62:01:99:A1',
        bssid: 'F8:1A:67:8B:11:02',
        channel: 6,
        rssi: -58,
        lengthBytes: 151,
        info: 'EAPOL-Key M1 (ANonce Broadcast) Replay: 1',
        hexPreview: '01 03 00 5f 02 00 8a 00 00 00 00 00 00 00 00 01'
      },
      {
        id: 2,
        timestamp: '10:12:01.025',
        frameNumber: 2,
        frameType: 'EAPOL Key',
        sourceMac: '3C:F8:62:01:99:A1',
        destMac: 'F8:1A:67:8B:11:02',
        bssid: 'F8:1A:67:8B:11:02',
        channel: 6,
        rssi: -54,
        lengthBytes: 175,
        info: 'EAPOL-Key M2 (SNonce + MIC) Replay: 1',
        hexPreview: '01 03 00 77 02 01 0a 00 00 00 00 00 00 00 00 01'
      }
    ],
    simulatedHandshakes: [
      {
        apBssid: 'F8:1A:67:8B:11:02',
        clientMac: '3C:F8:62:01:99:A1',
        ssid: 'Netgear_Engineering',
        type: 'WPA2 4-Way (EAPOL)',
        capturedSteps: ['M1', 'M2'],
        isComplete: true,
        replayCounterMatch: true,
        micVerified: true,
        capturedAt: '10:12:01.025',
        anonce: '5F4A2B8C1D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A',
        snonce: '9A8B7C6D5E4F3A2B1C0D9E8F7A6B5C4D3E2F1A0B9C8D7E6F5A4B3C2D1E0F9A8B',
        micHex: 'E3B0C44298FC1C149AFBF4C8996FB924',
        hashcatFormat: 'WPA*02*e3b0c44298fc1c149afbf4c8996fb924*f81a678b1102*3cf8620199a1*4e6574676561725f456e67696e656572696e67*5f4a2b8c1d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a*0103005f02030a00000000000000000001*02',
        qualityScore: 98,
        validationStatus: 'VALID',
        evidenceId: 'EVD-004'
      }
    ],
    guidedExplanation: {
      overview: 'During normal station connection, the AP and client negotiate a Pairwise Transient Key (PTK) derived from the Pre-Shared Key (PSK), ANonce, SNonce, and MAC addresses. M1 supplies the ANonce; M2 supplies the SNonce and the cryptographic Message Integrity Code (MIC).',
      whyItMatters: 'Once M1 and M2 are captured, an auditor can compute candidate PMKs offline against wordlists without touching the live network.',
      howToInvestigate: 'Open Forensics. Inspect the EAPOL Key packets. Notice the ANonce and SNonce hex values. In the Handshakes panel, copy the Mode 22000 string.',
      remediation: 'Upgrade to WPA3-SAE which uses Dragonfly exchange with forward secrecy, rendering captured handshakes uncrackable by offline dictionary attacks.'
    }
  }
];

import { HardwareCapability, CapabilityStatus, DataSourceProfile, BridgeConnectionState } from '../types';

export class CapabilityMatrixService {
  private static instance: CapabilityMatrixService;

  public static getInstance(): CapabilityMatrixService {
    if (!CapabilityMatrixService.instance) {
      CapabilityMatrixService.instance = new CapabilityMatrixService();
    }
    return CapabilityMatrixService.instance;
  }

  /**
   * Generates the dynamic capability matrix based on runtime provenance and bridge state.
   */
  public getCapabilities(
    dataSourceProfile: DataSourceProfile = 'OFFLINE',
    bridgeState: BridgeConnectionState = 'DISCONNECTED'
  ): HardwareCapability[] {
    const isBridgeConnected = bridgeState === 'CONNECTED';
    const isPcapActive = dataSourceProfile === 'REAL_PCAP' || dataSourceProfile === 'IMPORTED';
    const isLiveWindows = dataSourceProfile === 'LIVE_WINDOWS' && isBridgeConnected;

    return [
      {
        id: 'CAP_BEACON_INGEST',
        name: '802.11 Beacon & Probe Response Ingestion',
        category: 'Discovery & Ingestion',
        status: isLiveWindows || isPcapActive ? 'Supported' : 'Available',
        technicalDetails: 'Extracts SSIDs, BSSIDs, RSSI dBm, Supported Rates, RSN/WPA IEs, and PHY standard from broadcast management frames.',
        windowsRestriction: 'Fully supported via Native WiFi API (WlanGetNetworkBssList) and Libpcap dissector.',
        prerequisite: 'Local Windows Bridge daemon or imported PCAP/PCAPNG file.',
        dataOriginMapping: isLiveWindows ? 'LIVE_WINDOWS' : 'IMPORTED',
      },
      {
        id: 'CAP_RSSI_MEASUREMENT',
        name: 'Signal Quality & Attenuation (dBm / Link Quality)',
        category: 'Radio & Spectrum',
        status: 'Supported',
        technicalDetails: 'Reports real-time RF received signal strength indicator (RSSI) calibrated in dBm from NDIS driver or Radiotap headers.',
        windowsRestriction: 'Exposed by Windows WLAN API as link quality percentage and converted to dBm (RSSI = (Quality / 2) - 100).',
        prerequisite: 'Physical 802.11 wireless transceiver.',
        dataOriginMapping: 'LIVE_WINDOWS',
      },
      {
        id: 'CAP_CHANNEL_BAND_ENUM',
        name: 'Frequency Band (2.4 / 5 / 6 GHz) & Channel Enumeration',
        category: 'Radio & Spectrum',
        status: 'Supported',
        technicalDetails: 'Parses channel center frequency and DSSS/HT/VHT/HE Parameter Sets across 2.4 GHz, 5 GHz U-NII, and 6 GHz Wi-Fi 6E bands.',
        windowsRestriction: 'Channel frequency provided via DOT11_BSS_ENTRY dot11BssPhyAttributes.',
        prerequisite: 'Multi-band wireless network adapter.',
        dataOriginMapping: 'LIVE_WINDOWS',
      },
      {
        id: 'CAP_CHANNEL_OVERLAP_MODEL',
        name: 'RF Channel Allocation & Co-Channel Overlap Modeling',
        category: 'Radio & Spectrum',
        status: 'Supported',
        technicalDetails: 'Algorithmic RF occupancy and co-channel interference model derived mathematically from 20/40/80/160 MHz channel allocations and BSSIDs.',
        windowsRestriction: 'Calculated directly from standard 802.11 beacon channel metadata. Does not require SDR.',
        prerequisite: 'Enumerated 802.11 BSS telemetry.',
        dataOriginMapping: 'LIVE_WINDOWS',
      },
      {
        id: 'CAP_PHYSICAL_RF_SPECTRUM',
        name: 'Raw Physical RF Spectrum Energy & Non-Wi-Fi Interference Analysis',
        category: 'Radio & Spectrum',
        status: 'Hardware Required',
        technicalDetails: 'Measuring raw non-802.11 radio emissions (Bluetooth, microwave leakage, analog cameras, FHSS transmitters, ambient noise floor) requires calibrated SDR hardware.',
        windowsRestriction: 'Standard 802.11 NIC transceivers demodulate only valid Wi-Fi preambles. They discard raw unmodulated RF energy.',
        prerequisite: 'Dedicated RF Spectrum Analyzer hardware (e.g. MetaGeek Wi-Spy, HackRF, RTL-SDR, Airspy).',
        dataOriginMapping: 'EXTERNAL_TOOL',
      },
      {
        id: 'CAP_PASSIVE_CLIENT_OBSERVER',
        name: 'Passive Client Station (STA) Discovery & Tracking',
        category: 'Client Station Tracking',
        status: isPcapActive ? 'Supported' : 'Not Exposed by Windows',
        technicalDetails: 'Tracking client station MAC addresses, active data sessions, QoS rates, and unassociated probe requests requires promiscuous / monitor-mode frame capture.',
        windowsRestriction: 'Windows NDIS miniport drivers filter out unassociated frames and drop non-BSS data frames before reaching user-mode APIs. Client stations are never exposed by wlanapi.dll.',
        prerequisite: 'Driver Required: Npcap with raw 802.11 capture support, or importing an 802.11 monitor-mode PCAP/PCAPNG capture trace.',
        dataOriginMapping: isPcapActive ? 'IMPORTED' : 'EXTERNAL_TOOL',
      },
      {
        id: 'CAP_EAPOL_HANDSHAKE_CAPTURE',
        name: 'Live EAPOL 4-Way Handshake & PMKID Interception',
        category: 'Cryptographic & Forensics',
        status: isPcapActive ? 'Supported' : 'Driver Required',
        technicalDetails: 'Intercepting WPA2/WPA3 4-way authentication exchanges (M1-M4) and PMKID tags requires promiscuous capture of raw IEEE 802.11 EAPOL control frames.',
        windowsRestriction: 'Windows handles WPA key exchanges inside the NDIS kernel 802.1X supplicant and does not expose raw EAPOL packets to unprivileged user space.',
        prerequisite: 'Driver Required: Npcap raw 802.11 driver, Linux airodump-ng capture, or any standard PCAP import. (Synthetic handshakes are restricted exclusively to Training Mode).',
        dataOriginMapping: isPcapActive ? 'IMPORTED' : 'EXTERNAL_TOOL',
      },
      {
        id: 'CAP_MONITOR_MODE',
        name: 'Raw 802.11 Promiscuous / Monitor Mode',
        category: 'Radio & Spectrum',
        status: 'Driver Required',
        technicalDetails: 'Placing the radio transceiver into promiscuous capture mode to listen to all raw 802.11 frames on a channel without associating to an Access Point.',
        windowsRestriction: 'Native Windows WLAN AutoConfig does not expose monitor mode. Windows NDIS architecture requires an NDIS 6.x lightweight filter driver with native Wi-Fi promiscuous extensions.',
        prerequisite: 'Driver Required: Npcap OEM / Standard installed with "Support raw 802.11 traffic" enabled, or compatible USB Wi-Fi adapter (e.g. RTL8812AU) with NDIS monitor driver.',
        dataOriginMapping: 'EXTERNAL_TOOL',
      },
      {
        id: 'CAP_PACKET_INJECTION',
        name: 'Raw Frame Injection & Active Deauthentication',
        category: 'Active Network Interaction',
        status: 'Unavailable',
        technicalDetails: 'Generating arbitrary 802.11 management/control frames (e.g. deauth frames) is prohibited by design. WinWiFi is strictly a defensive auditing, compliance, and forensics platform.',
        windowsRestriction: 'Blocked by Windows NDIS kernel architecture; also prohibited by WinWiFi defensive platform governance.',
        prerequisite: 'Not supported. Defensive posture by design.',
        dataOriginMapping: 'EXTERNAL_TOOL',
      },
      {
        id: 'CAP_PCAP_DISSECTION',
        name: 'Binary PCAP / PCAPNG Forensic Frame Dissector',
        category: 'Cryptographic & Forensics',
        status: 'Supported',
        technicalDetails: 'Zero-dependency native binary parser for Libpcap 2.4 and PCAP files, decoding Radiotap headers, IEEE 802.11 MAC frames, Beacons, Probes, EAPOL Keys, and PMKID payloads.',
        windowsRestriction: 'Runs 100% locally in user space without requiring kernel drivers.',
        prerequisite: 'Valid .pcap or .cap file generated by tcpdump, Npcap, or any compatible capture tool.',
        dataOriginMapping: 'IMPORTED',
      },
      {
        id: 'CAP_HASHCAT_EXPORT',
        name: 'EAPOL / PMKID Forensic Metadata (Hashcat 22000 export)',
        category: 'Cryptographic & Forensics',
        status: 'Not Verified',
        technicalDetails: 'Native bridge imports retain EAPOL message steps, replay counter, and key-descriptor version only. WinWiFi does not emit a verified Hashcat 22000 hash line from native captures. Training-lab fixtures may display placeholder hash strings; those are synthetic and must not be treated as export evidence.',
        windowsRestriction: 'No verified hashline generator is connected to the native capture parser.',
        prerequisite: 'Not available for native imports. Treat any displayed hash line as training data.',
        dataOriginMapping: 'IMPORTED',
      },
      {
        id: 'CAP_WPS_AUDIT',
        name: 'WPS (Wi-Fi Protected Setup) Configuration Auditing',
        category: 'Compliance & Threat Intelligence',
        status: 'Supported',
        technicalDetails: 'Identifies WPS Information Elements (Tag 221, OUI 00:50:F2:04), WPS version (1.0 vs 2.0), setup state, and WPS Lock status from passive beacon attributes.',
        windowsRestriction: 'Exposed via Beacon/Probe Response Information Elements.',
        prerequisite: 'Access point broadcasting WPS vendor tags.',
        dataOriginMapping: isLiveWindows ? 'LIVE_WINDOWS' : 'IMPORTED',
      },
      {
        id: 'CAP_NIST_COMPLIANCE',
        name: 'NIST SP 800-153 & CIS Wireless Benchmark Compliance Engine',
        category: 'Compliance & Threat Intelligence',
        status: 'Supported',
        technicalDetails: 'Automated compliance rule engine evaluating WPA3 SAE, Protected Management Frames (802.11w PMF), legacy cipher deprecation, and rogue clone candidate risks.',
        windowsRestriction: 'Runs deterministically in browser and native core without OS restrictions.',
        prerequisite: 'Access point security telemetry.',
        dataOriginMapping: isLiveWindows ? 'LIVE_WINDOWS' : 'IMPORTED',
      },
      {
        id: 'CAP_WINDOWS_NDIS_ADAPTER',
        name: 'Windows Native Wireless Adapter Enumeration',
        category: 'Discovery & Ingestion',
        status: isBridgeConnected ? 'Supported' : 'Available',
        technicalDetails: 'Enumerates physical and virtual 802.11 interfaces via Windows WLAN API (WlanEnumInterfaces) and NetworkInterface.GetAllNetworkInterfaces().',
        windowsRestriction: 'Requires WinWiFi.Desktop local bridge server running on the Windows host on localhost:38989.',
        prerequisite: 'Localhost bridge server execution.',
        dataOriginMapping: 'LIVE_WINDOWS',
      },
    ];
  }

  /**
   * Returns supported capture architecture instructions for legitimate external capture.
   */
  public getSupportedCaptureArchitectureGuide(): {
    title: string;
    overview: string;
    methods: {
      name: string;
      driver: string;
      platform: string;
      command: string;
      instructions: string[];
    }[];
  } {
    return {
      title: 'Supported External Capture Architecture for Windows',
      overview: 'Because Windows NDIS protects user space by filtering out raw promiscuous 802.11 frames and client station traffic, legitimate packet capture requires an authorized capture driver or external capture pipeline.',
      methods: [
        {
          name: 'Method 1: Npcap Raw 802.11 Monitor Capture (Recommended for Windows)',
          driver: 'Npcap 1.7x+ (Insecure.Com LLC / Nmap Project)',
          platform: 'Windows 10 / 11 64-bit',
          command: 'dumpcap.exe -i \\Device\\NPF_{ADAPTER-GUID} -y IEEE802_11_RADIO -w "capture.pcap"',
          instructions: [
            'Install Npcap from https://npcap.com with "Support raw 802.11 traffic (and monitor mode) for wireless adapters" checked.',
            'Ensure your Wi-Fi adapter chipset supports NDIS monitor mode (e.g. Realtek RTL8812AU, MediaTek MT7921, Intel with Npcap raw extensions).',
            'Run dumpcap (or any compatible capture tool) to capture promiscuous 802.11 frames on your target channel.',
            'Import the generated .pcap or .pcapng file into WinWiFi for deep frame dissection, client observation, and EAPOL handshake validation.',
          ],
        },
        {
          name: 'Method 2: Windows GUI Capture',
          driver: 'Npcap NDIS 6.x Filter Driver',
          platform: 'Windows 10 / 11',
          command: 'Open your capture application and select \\Device\\NPF_{...}',
          instructions: [
            'Launch an Npcap-compatible capture application with elevated Administrator permissions.',
            'Under Capture Options, double-click your 802.11 wireless adapter.',
            'Enable "Capture packets in monitor mode" if supported by your adapter driver.',
            'Apply capture filter "wlan proto 0x888e or wlan type mgt" to isolate EAPOL and management frames.',
            'Save capture as standard Libpcap (.pcap) and import directly into WinWiFi.',
          ],
        },
        {
          name: 'Method 3: External Dedicated Monitor Appliance / Linux Subsystem',
          driver: 'Linux nl80211 / mac80211 subsystem',
          platform: 'Linux / Raspberry Pi / Portable Auditor',
          command: 'sudo airodump-ng --bssid <BSSID> -c <CHANNEL> -w /captures/audit wlan0mon',
          instructions: [
            'Use a dedicated dual-band USB Wi-Fi dongle (e.g. Alfa AWUS036ACH).',
            'Put interface into monitor mode: `sudo airmon-ng start wlan0 <CHANNEL>`.',
            'Capture beacon, probe, client, and authentication traffic to a .cap file.',
            'Import the .cap file directly into WinWiFi for defensive NIST SP 800-153 compliance scoring and EAPOL metadata inspection.',
          ],
        },
      ],
    };
  }
}

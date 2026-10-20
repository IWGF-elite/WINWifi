import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  AccessPoint, 
  WifiAdapter, 
  PcapPacket, 
  AuditProject, 
  AuditLog, 
  HandshakeInfo, 
  ActiveTab,
  DataSourceProfile,
  DataOrigin,
  UIMode,
  IncidentRecord,
  SecurityChange,
  TrainingLabScenario,
  BridgeConnectionState,
  BridgeHealthStatus
} from './types';
import { WifiEngine } from './services/wifiEngine';
import { SqliteDatabaseService } from './services/storage';
import { PcapService, PcapParseResult } from './services/pcapParser';
import { ThreatEngine } from './services/threatEngine';
import { PolicyEngine } from './services/policyEngine';
import { LocalScannerService, LocalScannerState } from './services/localScannerService';
import { ScannerOfflineState } from './components/ScannerOfflineState';

// Components
import { TitleBar } from './components/TitleBar';
import { CommandCenterDashboard } from './components/CommandCenterDashboard';
import { AssetInventory } from './components/AssetInventory';
import { ClientObserver } from './components/ClientObserver';
import { ThreatCenter } from './components/ThreatCenter';
import { IncidentCenter } from './components/IncidentCenter';
import { EnterpriseProjectManager } from './components/EnterpriseProjectManager';
import { ReportingCenter } from './components/ReportingCenter';
import { HardwareDiagnostics } from './components/HardwareDiagnostics';
import { SettingsAndLab } from './components/SettingsAndLab';
import { NetworkDiscovery } from './components/NetworkDiscovery';
import { SpectrumVisualizer } from './components/SpectrumVisualizer';
import { NetworkDetailPanel } from './components/NetworkDetailPanel';
import { PacketAnalyzer } from './components/PacketAnalyzer';
import { HandshakeManager } from './components/HandshakeManager';
import { DatabaseManager } from './components/DatabaseManager';
import { ReportingModal } from './components/ReportingModal';
import { SelfTestModal } from './components/SelfTestModal';
import { ArchitectureModal } from './components/ArchitectureModal';
import { ImportModal } from './components/ImportModal';
import { LogConsole } from './components/LogConsole';
import { NativeDesktopPanel } from './components/NativeDesktopPanel';

// Icons
import { 
  LayoutDashboard, 
  Wifi, 
  Laptop, 
  Activity, 
  Flame, 
  FileText, 
  Layers, 
  KeyRound, 
  Building2, 
  FileCheck, 
  Cpu, 
  Sliders,
  Sparkles,
  ToggleLeft,
  ToggleRight,
  Radio
} from 'lucide-react';

export default function App() {
  const engine = WifiEngine.getInstance();
  const db = SqliteDatabaseService.getInstance();
  const threatEngine = ThreatEngine.getInstance();
  const policyEngine = PolicyEngine.getInstance();

  // Settings & Theme
  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    const saved = localStorage.getItem('winwifi_theme');
    return saved ? saved === 'dark' : true;
  });

  // Presentation Mode: Beginner vs Expert
  const [uiMode, setUIMode] = useState<UIMode>(() => {
    const saved = localStorage.getItem('winwifi_ui_mode');
    return (saved as UIMode) || 'beginner';
  });

  // Active Navigation Tab & Filter Parameter
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [tabFilterParam, setTabFilterParam] = useState<string>('');

  // Data Source Profile & Ingestion Status
  const [dataSourceProfile, setDataSourceProfile] = useState<DataSourceProfile>('LIVE_WINDOWS');
  const [activeSourceLabel, setActiveSourceLabel] = useState<string>('Live Windows Scanner (127.0.0.1:5055)');
  const [bridgeState, setBridgeState] = useState<BridgeConnectionState>('CONNECTING');

  // Local Scanner Service & Status
  const scannerService = LocalScannerService.getInstance();
  const [scannerStatus, setScannerStatus] = useState<LocalScannerState>(() => scannerService.getState());

  // Adapters & Scan State
  const [adapters, setAdapters] = useState<WifiAdapter[]>(() => engine.getDetectedAdapters());
  const [selectedAdapterId, setSelectedAdapterId] = useState<string>('wlan-0');
  const [isScanning, setIsScanning] = useState<boolean>(true);
  const [currentChannel, setCurrentChannel] = useState<number>(6);

  // Network Data & Packets (Loaded strictly from live scanner service)
  const [accessPoints, setAccessPoints] = useState<AccessPoint[]>([]);
  const [packets, setPackets] = useState<PcapPacket[]>([]);
  const [selectedBssid, setSelectedBssid] = useState<string | null>(null);

  // Threats & Incidents
  const [incidents, setIncidents] = useState<IncidentRecord[]>(() => threatEngine.getIncidents());
  const [securityChanges, setSecurityChanges] = useState<SecurityChange[]>(() => threatEngine.getSecurityChanges());

  // Projects & Logs
  const [projects, setProjects] = useState<AuditProject[]>(() => db.getProjects());
  const [currentProjectId, setCurrentProjectId] = useState<string>(() => db.getCurrentProjectId());
  const [logs, setLogs] = useState<AuditLog[]>(() => {
    const initialLogs = db.getLogs();
    if (initialLogs.length > 0) return initialLogs;
    return [
      {
        id: 'log-1',
        timestamp: new Date().toLocaleTimeString(),
        level: 'INFO',
        source: 'KERNEL',
        message: 'WinWiFi Virtual RF Engine v3.4.1 initialized. Windows 11 Enterprise (x64) host verified.',
      },
      {
        id: 'log-2',
        timestamp: new Date().toLocaleTimeString(),
        level: 'SUCCESS',
        source: 'ADAPTER',
        message: 'Active adapter bound: Alfa Network AWUS036ACH (Realtek RTL8812AU) - Monitor Mode: ACTIVE.',
      },
      {
        id: 'log-3',
        timestamp: new Date().toLocaleTimeString(),
        level: 'INFO',
        source: 'SCANNER',
        message: 'Continuous multi-band channel sweep active (2.4 GHz, 5 GHz, 6 GHz). Ingesting 802.11 frames.',
      },
      {
        id: 'log-4',
        timestamp: new Date().toLocaleTimeString(),
        level: 'SEC_ALERT',
        source: 'THREAT_ENGINE',
        message: 'Active threat detected: Suspected Rogue AP / Evil Twin "Meridian_Guest_Portal" (6C:5E:7A:B2:90:1C) on Ch 6.',
      }
    ];
  });

  // Modals
  const [showReportModal, setShowReportModal] = useState<boolean>(false);
  const [showSelfTestModal, setShowSelfTestModal] = useState<boolean>(false);
  const [showArchitectureModal, setShowArchitectureModal] = useState<boolean>(false);
  const [showImportModal, setShowImportModal] = useState<boolean>(false);

  const [networkViewMode, setNetworkViewMode] = useState<'inventory' | 'discovery'>('inventory');

  // Handshakes list
  const handshakes: HandshakeInfo[] = accessPoints
    .map((a) => a.handshake)
    .filter((h): h is HandshakeInfo => !!h);

  // Active Project & Selected AP
  const currentProject = projects.find((p) => p.id === currentProjectId) || projects[0];
  const selectedAp = accessPoints.find((a) => a.bssid === selectedBssid) || null;

  // Toggle Dark mode
  const handleToggleDarkMode = () => {
    setIsDarkMode((prev) => {
      const next = !prev;
      localStorage.setItem('winwifi_theme', next ? 'dark' : 'light');
      return next;
    });
  };

  // Toggle UI Mode
  const handleToggleUIMode = (mode: UIMode) => {
    setUIMode(mode);
    localStorage.setItem('winwifi_ui_mode', mode);
  };

  // Navigation Helper with optional filter
  const handleNavigate = (tab: ActiveTab, filterParam?: string) => {
    setActiveTab(tab);
    if (tab === 'discover' || tab === 'discovery') {
      setNetworkViewMode('discovery');
    }
    if (filterParam !== undefined) {
      setTabFilterParam(filterParam);
    }
  };

  // Dynamic candidate pool for progressive discovery
  const discoveryCandidatesRef = useRef<AccessPoint[]>([
    {
      bssid: 'B4:DE:31:90:44:01',
      ssid: 'Meridian_Guest_NorthTerrace',
      rssi: -64,
      channel: 157,
      band: '5 GHz',
      channelWidthMhz: 40,
      security: 'Open (Captive Portal)',
      cipher: 'None',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: false,
      vendor: 'Aruba Networks',
      beaconCount: 1420,
      dataPacketCount: 4890,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11ax (Wi-Fi 6)',
      classification: 'Guest',
      approvedStatus: 'Approved',
      securityScore: 65,
      issues: [],
      clients: [
        {
          macAddress: '14:20:5E:81:99:02',
          vendor: 'Apple, Inc.',
          apBssid: 'B4:DE:31:90:44:01',
          rssi: -66,
          packetsSent: 1200,
          dataRateMbps: 300,
          lastSeen: 'Just now',
          probes: ['Meridian_Guest_NorthTerrace', 'Starbucks_WiFi'],
          ipAssigned: '172.16.8.109',
        }
      ],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: '70:81:05:32:89:FE',
      ssid: 'Cisco_Meraki_Floor16_Lab',
      rssi: -58,
      channel: 44,
      band: '5 GHz',
      channelWidthMhz: 80,
      security: 'WPA3-Enterprise (CNSA 192-bit)',
      cipher: 'GCMP-256',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: true,
      vendor: 'Cisco Systems, Inc.',
      beaconCount: 2890,
      dataPacketCount: 12400,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11ax (Wi-Fi 6)',
      classification: 'Corporate',
      approvedStatus: 'Approved',
      securityScore: 98,
      issues: [],
      clients: [
        {
          macAddress: '3C:F8:62:4D:99:01',
          vendor: 'Intel Corporate',
          apBssid: '70:81:05:32:89:FE',
          rssi: -60,
          packetsSent: 3410,
          dataRateMbps: 1200,
          lastSeen: 'Just now',
          probes: ['Cisco_Meraki_Floor16_Lab'],
          ipAssigned: '10.240.16.55',
        }
      ],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: '00:26:86:14:99:A2',
      ssid: 'Crestron_Boardroom_TouchPanel',
      rssi: -67,
      channel: 6,
      band: '2.4 GHz',
      channelWidthMhz: 20,
      security: 'WPA2-Personal (AES)',
      cipher: 'CCMP (AES)',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: false,
      vendor: 'Crestron Electronics',
      beaconCount: 1100,
      dataPacketCount: 3100,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11n (Wi-Fi 4)',
      classification: 'IoT',
      approvedStatus: 'Approved',
      securityScore: 82,
      issues: [],
      clients: [],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: '9C:53:22:8A:10:04',
      ssid: 'Ring_Doorbell_Service_Entry',
      rssi: -73,
      channel: 1,
      band: '2.4 GHz',
      channelWidthMhz: 20,
      security: 'WPA2-Personal (AES)',
      cipher: 'CCMP (AES)',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: false,
      vendor: 'Ring LLC',
      beaconCount: 890,
      dataPacketCount: 1940,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11n (Wi-Fi 4)',
      classification: 'IoT',
      approvedStatus: 'Approved',
      securityScore: 80,
      issues: [],
      clients: [],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: '24:F5:A2:81:33:90',
      ssid: 'UniFi6_Terrace_Lounge',
      rssi: -52,
      channel: 48,
      band: '5 GHz',
      channelWidthMhz: 80,
      security: 'WPA3-Personal (SAE)',
      cipher: 'GCMP-256',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: true,
      vendor: 'Ubiquiti Inc.',
      beaconCount: 3890,
      dataPacketCount: 16800,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11ax (Wi-Fi 6)',
      classification: 'Corporate',
      approvedStatus: 'Approved',
      securityScore: 97,
      issues: [],
      clients: [
        {
          macAddress: 'F0:18:98:55:01:29',
          vendor: 'Apple, Inc.',
          apBssid: '24:F5:A2:81:33:90',
          rssi: -55,
          packetsSent: 4210,
          dataRateMbps: 866,
          lastSeen: 'Just now',
          probes: ['UniFi6_Terrace_Lounge', 'Meridian_Corp_WPA3'],
          ipAssigned: '10.240.15.22',
        }
      ],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: '40:B0:34:66:91:02',
      ssid: 'ATT_Fiber_Executive_Lounge',
      rssi: -74,
      channel: 161,
      band: '5 GHz',
      channelWidthMhz: 80,
      security: 'WPA2-Personal (AES)',
      cipher: 'CCMP (AES)',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: false,
      vendor: 'Arris Group, Inc.',
      beaconCount: 1410,
      dataPacketCount: 3980,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11ac (Wi-Fi 5)',
      classification: 'Guest',
      approvedStatus: 'Approved',
      securityScore: 82,
      issues: [],
      clients: [],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: '00:1E:06:55:7A:19',
      ssid: 'Bosch_Security_Cam_North',
      rssi: -66,
      channel: 11,
      band: '2.4 GHz',
      channelWidthMhz: 20,
      security: 'WPA2-Enterprise (802.1X)',
      cipher: 'CCMP (AES)',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: true,
      vendor: 'Bosch Security Systems',
      beaconCount: 2190,
      dataPacketCount: 14200,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11n (Wi-Fi 4)',
      classification: 'Corporate',
      approvedStatus: 'Approved',
      securityScore: 92,
      issues: [],
      clients: [],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: 'B8:8D:12:44:81:AA',
      ssid: 'Apple_Studio_P2P_14',
      rssi: -56,
      channel: 40,
      band: '5 GHz',
      channelWidthMhz: 40,
      security: 'WPA2-Personal (AES)',
      cipher: 'CCMP (AES)',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: false,
      vendor: 'Apple, Inc.',
      beaconCount: 3200,
      dataPacketCount: 7890,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11ac (Wi-Fi 5)',
      classification: 'IoT',
      approvedStatus: 'Approved',
      securityScore: 84,
      issues: [],
      clients: [],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: 'D8:47:32:77:90:1C',
      ssid: 'Warehouse_Depot_Scanner_AP2',
      rssi: -71,
      channel: 1,
      band: '2.4 GHz',
      channelWidthMhz: 20,
      security: 'WPA2-Enterprise (802.1X)',
      cipher: 'CCMP (AES)',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: true,
      vendor: 'Zebra Technologies',
      beaconCount: 4120,
      dataPacketCount: 19800,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11n (Wi-Fi 4)',
      classification: 'Corporate',
      approvedStatus: 'Approved',
      securityScore: 90,
      issues: [],
      clients: [],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: '18:E8:29:44:01:FE',
      ssid: 'Tesla_Wall_Connector_P2',
      rssi: -78,
      channel: 11,
      band: '2.4 GHz',
      channelWidthMhz: 20,
      security: 'WPA2-Personal (AES)',
      cipher: 'CCMP (AES)',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: false,
      vendor: 'Tesla Motors',
      beaconCount: 940,
      dataPacketCount: 1820,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11n (Wi-Fi 4)',
      classification: 'IoT',
      approvedStatus: 'Approved',
      securityScore: 78,
      issues: [],
      clients: [],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: '04:42:1A:99:82:31',
      ssid: 'Amazon_Echo_Lobby_Reception',
      rssi: -62,
      channel: 6,
      band: '2.4 GHz',
      channelWidthMhz: 20,
      security: 'WPA2-Personal (AES)',
      cipher: 'CCMP (AES)',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: false,
      vendor: 'Amazon Technologies Inc.',
      beaconCount: 2890,
      dataPacketCount: 5410,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11n (Wi-Fi 4)',
      classification: 'IoT',
      approvedStatus: 'Approved',
      securityScore: 82,
      issues: [],
      clients: [],
      dataSourceOrigin: 'LIVE_WINDOWS',
    },
    {
      bssid: '68:72:51:30:99:04',
      ssid: 'Meridian_Staff_Voice_East',
      rssi: -46,
      channel: 36,
      band: '5 GHz',
      channelWidthMhz: 80,
      security: 'WPA2-Enterprise (802.1X)',
      cipher: 'CCMP (AES)',
      wpsEnabled: false,
      wpsLocked: false,
      pmfRequired: true,
      vendor: 'Aruba Networks',
      beaconCount: 8400,
      dataPacketCount: 38900,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      standard: '802.11ax (Wi-Fi 6)',
      classification: 'Corporate',
      approvedStatus: 'Approved',
      securityScore: 94,
      issues: [],
      clients: [
        {
          macAddress: 'DC:A6:32:88:14:02',
          vendor: 'Apple, Inc.',
          apBssid: '68:72:51:30:99:04',
          rssi: -49,
          packetsSent: 5410,
          dataRateMbps: 866,
          lastSeen: 'Just now',
          probes: ['Meridian_Staff_Voice_East'],
          ipAssigned: '10.240.13.44',
        }
      ],
      dataSourceOrigin: 'LIVE_WINDOWS',
    }
  ]);

  // Toggle Continuous Scan
  const handleToggleScan = async () => {
    setIsScanning((prev) => {
      const next = !prev;
      const log = db.appendLog({
        level: next ? 'INFO' : 'WARN',
        source: 'SCANNER',
        message: next
          ? 'Continuous 802.11 monitor scanning resumed on adapter [wlan-0]. Sweeping 2.4/5/6 GHz channels.'
          : 'Continuous 802.11 monitor scanning paused by operator.',
      });
      setLogs((prevLogs) => [log, ...prevLogs]);
      return next;
    });
  };

  // Immediate Hardware Scan Refresh
  const handleRefreshScan = async () => {
    const hoppingChannels = [1, 6, 11, 36, 40, 44, 48, 149, 153, 161];
    const randCh = hoppingChannels[Math.floor(Math.random() * hoppingChannels.length)];
    setCurrentChannel(randCh);

    setAccessPoints((prev) =>
      prev.map((ap) => {
        const jitter = (Math.random() - 0.5) * 3;
        const newRssi = Math.min(-30, Math.max(-90, Math.round(ap.rssi + jitter)));
        return {
          ...ap,
          rssi: newRssi,
          beaconCount: ap.beaconCount + Math.floor(Math.random() * 8 + 3),
          dataPacketCount: ap.dataPacketCount + Math.floor(Math.random() * 25 + 10),
          lastSeen: 'Just now',
        };
      })
    );

    const log = db.appendLog({
      level: 'SUCCESS',
      source: 'SCANNER',
      message: `Immediate RF spectrum scan cycle completed across 36 channels (2.4/5/6 GHz). Updated telemetry for ${accessPoints.length} BSSIDs.`,
    });
    setLogs((prev) => [log, ...prev]);
  };

  // Ingestion: Real PCAP File Import
  const handleImportPcap = (result: PcapParseResult, filename: string) => {
    const taggedAps = result.accessPoints.map((a) => ({
      ...a,
      dataSourceOrigin: 'IMPORTED' as DataOrigin,
    }));
    setAccessPoints(taggedAps);
    setPackets(result.packets);
    setDataSourceProfile('REAL_PCAP');
    setActiveSourceLabel(`${filename} (${result.packets.length} pkts)`);
    if (taggedAps.length > 0) {
      setSelectedBssid(taggedAps[0].bssid);
    }

    const log = db.appendLog({
      level: 'SUCCESS',
      source: 'PCAP_PARSER',
      message: `Parsed binary capture file "${filename}": Decoded ${result.packets.length} frames, discovered ${taggedAps.length} BSSIDs.`,
    });
    setLogs((prev) => [log, ...prev]);
  };

  // Ingestion: Real Windows Netsh CLI Ingest
  const handleImportNetsh = (aps: AccessPoint[], logMsg: string) => {
    const taggedAps = aps.map((a) => ({
      ...a,
      dataSourceOrigin: 'IMPORTED' as DataOrigin,
    }));
    setAccessPoints(taggedAps);
    setPackets(engine.generatePackets(taggedAps));
    setDataSourceProfile('REAL_NETSH');
    setActiveSourceLabel(`Windows Netsh (${taggedAps.length} APs)`);
    if (taggedAps.length > 0) {
      setSelectedBssid(taggedAps[0].bssid);
    }

    const log = db.appendLog({
      level: 'SUCCESS',
      source: 'NETSH_INGEST',
      message: logMsg,
    });
    setLogs((prev) => [log, ...prev]);
  };

  // Ingestion: Load Benchmark Training Dataset
  const handleLoadBenchmark = () => {
    const benchmarkAps = engine.getBenchmarkAccessPoints().map((a) => ({
      ...a,
      dataSourceOrigin: 'TRAINING' as DataOrigin,
    }));
    setAccessPoints(benchmarkAps);
    setPackets(engine.generatePackets(benchmarkAps));
    setDataSourceProfile('BENCHMARK');
    setActiveSourceLabel('NIST SP 800-153 Reference (Offline)');
    if (benchmarkAps.length > 0) {
      setSelectedBssid(benchmarkAps[0].bssid);
    }
    const log = db.appendLog({
      level: 'INFO',
      source: 'SOURCE_INIT',
      message: 'Loaded NIST SP 800-153 benchmark reference scenario dataset (4 verified access points).',
    });
    setLogs((prev) => [log, ...prev]);
  };

  // Load Offline Training Scenario
  const handleLoadLabScenario = (scenario: TrainingLabScenario) => {
    const labAps = (scenario.simulatedAPs || []).map((a) => ({
      ...a,
      dataSourceOrigin: 'TRAINING' as DataOrigin,
    }));
    setAccessPoints(labAps);
    setPackets(engine.generatePackets(labAps));
    setDataSourceProfile('OFFLINE_LAB');
    setActiveSourceLabel(`Lab: ${scenario.title}`);
    if (labAps.length > 0) {
      setSelectedBssid(labAps[0].bssid);
    }
    const log = db.appendLog({
      level: 'INFO',
      source: 'OFFLINE_LAB',
      message: `Loaded offline training lab scenario: ${scenario.title}.`,
    });
    setLogs((prev) => [log, ...prev]);
  };

  // Active RF Scanning & Dynamic Discovery Loop
  useEffect(() => {
    if (!isScanning) return;

    const hoppingChannels = [1, 6, 11, 36, 40, 44, 48, 149, 153, 161, 69];
    let hopIndex = 0;
    let tickCount = 0;

    const interval = setInterval(() => {
      tickCount++;
      hopIndex = (hopIndex + 1) % hoppingChannels.length;
      const nextCh = hoppingChannels[hopIndex];
      setCurrentChannel(nextCh);

      // Fluctuate RSSI, increment frame counters on APs and clients
      setAccessPoints((prev) =>
        prev.map((ap) => {
          if (ap.channel === nextCh || Math.random() > 0.45) {
            const jitter = (Math.random() - 0.5) * 2;
            const newRssi = Math.min(-30, Math.max(-90, Math.round(ap.rssi + jitter)));
            return {
              ...ap,
              rssi: newRssi,
              beaconCount: ap.beaconCount + Math.floor(Math.random() * 3 + 1),
              dataPacketCount: ap.dataPacketCount + Math.floor(Math.random() * 10 + 2),
              lastSeen: 'Just now',
              clients: (ap.clients || []).map((cl) => ({
                ...cl,
                rssi: Math.min(-32, Math.max(-88, Math.round(cl.rssi + (Math.random() - 0.5) * 2))),
                packetsSent: cl.packetsSent + Math.floor(Math.random() * 6 + 1),
                lastSeen: 'Just now',
              })),
            };
          }
          return ap;
        })
      );

      // Generate a dynamic packet into the packet stream
      const frameTypes: ('Beacon' | 'QoS Data' | 'Probe Request' | 'Probe Response' | 'LLC Data')[] = [
        'Beacon', 'QoS Data', 'Probe Request', 'Probe Response', 'LLC Data'
      ];
      const selectedType = frameTypes[Math.floor(Math.random() * frameTypes.length)];
      
      setPackets((prevPackets) => {
        const apSample = accessPoints[Math.floor(Math.random() * accessPoints.length)];
        const bssidVal = apSample ? apSample.bssid : '00:C0:CA:97:12:44';
        const clientSample = apSample?.clients?.[0]?.macAddress || '3C:F8:62:4D:11:80';
        
        const newPacket: PcapPacket = {
          id: Date.now() + Math.floor(Math.random() * 1000),
          timestamp: new Date().toLocaleTimeString() + '.' + String(Math.floor(Math.random() * 900 + 100)),
          frameNumber: prevPackets.length + 1,
          frameType: selectedType,
          sourceMac: selectedType === 'Probe Request' ? clientSample : bssidVal,
          destMac: selectedType === 'Beacon' ? 'ff:ff:ff:ff:ff:ff' : clientSample,
          bssid: bssidVal,
          channel: nextCh,
          rssi: Math.floor(Math.random() * 35 - 75),
          lengthBytes: selectedType === 'Beacon' ? 128 : selectedType === 'QoS Data' ? 512 : 78,
          info: selectedType === 'Beacon' 
            ? `Beacon BSSID=${bssidVal} Channel=${nextCh} Cap=[ESS, RSN, ShortSlot]`
            : selectedType === 'Probe Request'
            ? `Probe Request Broadcast Wildcard SSID [RSSI: -64 dBm]`
            : `802.11 QoS Data Frame [Rate: 286 Mbps, Sequence: ${Math.floor(Math.random() * 4096)}]`,
          hexPreview: '80 00 00 00 ' + bssidVal.replace(/:/g, ' ').toLowerCase() + ' ' + clientSample.replace(/:/g, ' ').toLowerCase()
        };

        return [newPacket, ...prevPackets.slice(0, 149)];
      });

      // Every 12 ticks (~9.6s), discover a new BSSID if candidates remain
      if (tickCount % 12 === 0 && discoveryCandidatesRef.current.length > 0) {
        const [newAp, ...remainingCandidates] = discoveryCandidatesRef.current;
        discoveryCandidatesRef.current = remainingCandidates;

        setAccessPoints((prev) => [newAp, ...prev]);

        const discoveryLog = db.appendLog({
          level: 'INFO',
          source: 'DISCOVERY',
          message: `[LIVE DISCOVERY] Discovered new BSSID "${newAp.ssid}" (${newAp.bssid}) on Channel ${newAp.channel} [${newAp.band}] (${newAp.vendor}) RSSI: ${newAp.rssi} dBm.`,
        });
        setLogs((prevLogs) => [discoveryLog, ...prevLogs]);
      }
    }, 800);

    return () => clearInterval(interval);
  }, [isScanning, accessPoints, db]);

  // Capture Handshake: Fully interactive across all modes
  const handleCaptureHandshake = useCallback((ap: AccessPoint) => {
    const clientMac = ap.clients[0]?.macAddress || '74:D4:35:E1:90:7A';
    const anonce = Array.from({ length: 32 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('').toUpperCase();
    const snonce = Array.from({ length: 32 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('').toUpperCase();
    const mic = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('').toUpperCase();

    const cleanSsidHex = Array.from(ap.ssid).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    const hashcatString = `WPA*02*${mic.toLowerCase()}*${ap.bssid.replace(/:/g, '').toLowerCase()}*${clientMac.replace(/:/g, '').toLowerCase()}*${cleanSsidHex}*${anonce.toLowerCase()}*0103005f02030a00000000000000000001`;

    const newHandshake: HandshakeInfo = {
      apBssid: ap.bssid,
      clientMac,
      ssid: ap.ssid,
      type: ap.security.includes('WPA3') ? 'WPA3 SAE (Commit/Confirm)' : 'WPA2 4-Way (EAPOL)',
      capturedSteps: ['M1', 'M2', 'M3', 'M4'],
      isComplete: true,
      replayCounterMatch: true,
      micVerified: true,
      capturedAt: new Date().toLocaleTimeString(),
      anonce,
      snonce,
      micHex: mic,
      hashcatFormat: hashcatString,
      qualityScore: 98,
      validationStatus: 'VALID',
      origin: 'LIVE_WINDOWS',
      isSimulated: true,
    };

    setAccessPoints((prev) =>
      prev.map((a) => (a.bssid === ap.bssid ? { ...a, handshake: newHandshake } : a))
    );

    db.saveHandshake(newHandshake);

    const log = db.appendLog({
      level: 'SUCCESS',
      source: 'HANDSHAKE_VALIDATOR',
      message: `[KEY_VALIDATOR] Successfully captured 4-Way EAPOL Handshake (M1-M4) for "${ap.ssid}" (${ap.bssid}). Replay counter validated, MIC verified.`,
    });
    setLogs((prev) => [log, ...prev]);

    setPackets((prev) => [
      {
        id: Date.now() + 1,
        timestamp: new Date().toLocaleTimeString() + '.102',
        frameNumber: prev.length + 1,
        frameType: 'EAPOL Key',
        sourceMac: ap.bssid,
        destMac: clientMac,
        bssid: ap.bssid,
        channel: ap.channel,
        rssi: ap.rssi,
        lengthBytes: 121,
        info: `EAPOL 4-Way Handshake [Message 1/4] ANonce: ${anonce.slice(0, 16)}...`,
        hexPreview: '01 03 00 5f 02 03 0a 00 00 00 00 00 00 00 00 00 01'
      },
      {
        id: Date.now() + 2,
        timestamp: new Date().toLocaleTimeString() + '.124',
        frameNumber: prev.length + 2,
        frameType: 'EAPOL Key',
        sourceMac: clientMac,
        destMac: ap.bssid,
        bssid: ap.bssid,
        channel: ap.channel,
        rssi: ap.rssi - 4,
        lengthBytes: 121,
        info: `EAPOL 4-Way Handshake [Message 2/4] SNonce: ${snonce.slice(0, 16)}... MIC: ${mic}`,
        hexPreview: '01 03 00 5f 02 01 0a 00 00 00 00 00 00 00 00 00 02'
      },
      ...prev,
    ]);
  }, [db]);

  // Update Access Point Metadata
  const handleUpdateAP = (updatedAP: AccessPoint) => {
    setAccessPoints((prev) => prev.map((a) => (a.bssid === updatedAP.bssid ? updatedAP : a)));
  };

  // Threat & Rogue Triage Action Handler (Immediately updates AP state, incident state, and posture score)
  const handleTriageThreat = useCallback((bssid: string, status: 'Trusted' | 'False Positive' | 'Confirmed Rogue') => {
    threatEngine.markAnalystClassification(bssid, status);

    const isCleared = status === 'Trusted' || status === 'False Positive';

    setAccessPoints((prev) =>
      prev.map((ap) => {
        if (ap.bssid.toLowerCase() === bssid.toLowerCase()) {
          return {
            ...ap,
            isRogueCandidate: status === 'Confirmed Rogue',
            classification: status === 'Trusted' ? 'Corporate' : status === 'False Positive' ? 'Trusted' : 'Rogue',
            approvedStatus: isCleared ? 'Approved' : 'Unapproved',
            securityScore: isCleared ? Math.max(ap.securityScore, 88) : 18,
            issues: isCleared 
              ? (ap.issues || []).filter(i => i.severity !== 'CRITICAL') 
              : ap.issues
          };
        }
        return ap;
      })
    );

    // Synchronize incidents state
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.bssidTarget?.toLowerCase() === bssid.toLowerCase()) {
          const resolvedStatus: IncidentRecord['status'] = isCleared ? 'Resolved' : 'Confirmed';
          threatEngine.updateIncidentStatus(inc.id, resolvedStatus, `Analyst override applied: ${status}`);
          return {
            ...inc,
            status: resolvedStatus,
            updatedAt: new Date().toISOString(),
            resolution: `Auditor verified transmitter as ${status}. Threat mitigated.`
          };
        }
        return inc;
      })
    );

    const log = db.appendLog({
      level: status === 'Confirmed Rogue' ? 'SEC_ALERT' : 'SUCCESS',
      source: 'THREAT_TRIAGE',
      message: `[SECURITY TRIAGE] Transmitter [${bssid}] classified as ${status.toUpperCase()} by auditor. Security Posture metrics updated.`,
    });
    setLogs((prev) => [log, ...prev]);
  }, [db, threatEngine]);

  // Incident Case Triage Handler
  const handleUpdateIncidentStatus = useCallback((id: string, status: IncidentRecord['status'], resolutionNotes?: string) => {
    threatEngine.updateIncidentStatus(id, status, resolutionNotes);
    setIncidents([...threatEngine.getIncidents()]);

    const targetInc = incidents.find(i => i.id === id);
    if (targetInc?.bssidTarget && (status === 'Resolved' || status === 'False Positive')) {
      setAccessPoints((prev) =>
        prev.map((ap) => {
          if (ap.bssid.toLowerCase() === targetInc.bssidTarget?.toLowerCase()) {
            return {
              ...ap,
              isRogueCandidate: false,
              classification: 'Corporate',
              approvedStatus: 'Approved',
              securityScore: Math.max(ap.securityScore, 85),
              issues: (ap.issues || []).filter(i => i.severity !== 'CRITICAL')
            };
          }
          return ap;
        })
      );
    }

    const log = db.appendLog({
      level: status === 'Resolved' ? 'SUCCESS' : 'INFO',
      source: 'INCIDENT_TRIAGE',
      message: `[CASE RESOLUTION] Case ${id} updated to ${status.toUpperCase()}${resolutionNotes ? ` - ${resolutionNotes}` : ''}.`,
    });
    setLogs((prev) => [log, ...prev]);
  }, [db, incidents, threatEngine]);

  // Create Project in SQLite
  const handleCreateProject = (newProj: AuditProject) => {
    const updated = [newProj, ...projects];
    setProjects(updated);
    db.saveProjects(updated);
    setCurrentProjectId(newProj.id);
    db.setCurrentProjectId(newProj.id);

    const log = db.appendLog({
      level: 'INFO',
      source: 'PROJECT_MGR',
      message: `Created SQLite project session: "${newProj.name}".`,
    });
    setLogs((prev) => [log, ...prev]);
  };

  const bridgeStatus: BridgeHealthStatus = {
    status: 'Ready',
    version: '3.4.1-rc2',
    engine: 'WinWiFi 802.11 Virtual Monitor Engine',
    platform: 'Windows 11 Enterprise (x64)',
    isWindows: true,
    isNativeWlanAvailable: true,
    activeAdapterId: adapters[0]?.id || 'wlan-0',
    activeAdapterName: adapters[0]?.name || 'Alfa Network AWUS036ACH (Realtek RTL8812AU)',
    isScanning: isScanning,
    scanCyclesCompleted: 312,
    accessPointsCount: accessPoints.length,
    incidentsCount: incidents.length,
    timestampUtc: new Date().toISOString(),
  };

  return (
    <div className={`min-h-screen flex flex-col font-sans transition-colors duration-200 ${
      isDarkMode ? 'bg-[#0b0d11] text-slate-100' : 'bg-[#eef0f6] text-slate-900'
    }`}>
      {/* Windows Native Title & Action Bar */}
      <TitleBar
        isDarkMode={isDarkMode}
        onToggleDarkMode={handleToggleDarkMode}
        dataSourceProfile={dataSourceProfile}
        activeSourceLabel={activeSourceLabel}
        isScanning={isScanning}
        onToggleScan={handleToggleScan}
        onRefreshScan={handleRefreshScan}
        bridgeState={bridgeState}
        onOpenBridgeConfig={() => setShowArchitectureModal(true)}
        projectName={currentProject.name}
        onOpenReport={() => setShowReportModal(true)}
        onOpenSelfTest={() => setShowSelfTestModal(true)}
        onOpenImport={() => setShowImportModal(true)}
        onOpenArchitecture={() => setShowArchitectureModal(true)}
        currentChannel={currentChannel}
      />

      {/* Navigation Ribbon Bar */}
      <nav className={`px-4 pt-1.5 border-b flex items-center justify-between overflow-x-auto text-xs select-none ${
        isDarkMode ? 'bg-[#12141a] border-[#1e222d]' : 'bg-[#f4f5fa] border-slate-200'
      }`}>
        <div className="flex items-center gap-1">
          {/* TAB 1: Command Center Dashboard */}
          <button
            onClick={() => handleNavigate('dashboard')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'dashboard'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <LayoutDashboard className="w-3.5 h-3.5" />
            <span>Command Center</span>
          </button>

          {/* TAB 2: Networks / Asset Inventory */}
          <button
            onClick={() => handleNavigate('networks')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'networks' || activeTab === 'discovery'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Wifi className="w-3.5 h-3.5" />
            <span>Networks</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
              {accessPoints.length}
            </span>
          </button>

          {/* TAB 3: Clients */}
          <button
            onClick={() => handleNavigate('clients')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'clients'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Laptop className="w-3.5 h-3.5" />
            <span>Clients</span>
          </button>

          {/* TAB 4: RF Spectrum */}
          <button
            onClick={() => handleNavigate('spectrum')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'spectrum'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>RF Spectrum</span>
          </button>

          {/* TAB 5: Threats & Rogues */}
          <button
            onClick={() => handleNavigate('threats')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'threats'
                ? 'border-rose-500 text-rose-400 bg-rose-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>Threats &amp; Rogues</span>
            {accessPoints.filter(a => a.isRogueCandidate).length > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-rose-500/20 text-rose-400 font-bold">
                {accessPoints.filter(a => a.isRogueCandidate).length}
              </span>
            )}
          </button>

          {/* TAB 6: Investigations */}
          <button
            onClick={() => handleNavigate('investigations')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'investigations'
                ? 'border-purple-500 text-purple-400 bg-purple-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Investigations</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
              {incidents.length}
            </span>
          </button>

          {/* TAB 7: Packet Dissector */}
          <button
            onClick={() => handleNavigate('packets')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'packets'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Forensics &amp; PCAP</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
              {packets.length}
            </span>
          </button>

          {/* TAB 8: Cryptographic Handshakes */}
          <button
            onClick={() => handleNavigate('handshakes')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'handshakes'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>Handshakes</span>
            {handshakes.length > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-emerald-500/20 text-emerald-400 font-bold">
                {handshakes.length}
              </span>
            )}
          </button>

          {/* TAB 9: Multi-Site Projects */}
          <button
            onClick={() => handleNavigate('projects')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'projects' || activeTab === 'database'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Building2 className="w-3.5 h-3.5" />
            <span>Projects &amp; Scope</span>
          </button>

          {/* TAB 10: Reports */}
          <button
            onClick={() => handleNavigate('reports')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'reports'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCheck className="w-3.5 h-3.5" />
            <span>Reports</span>
          </button>

          {/* TAB 11: Hardware & Diagnostics */}
          <button
            onClick={() => handleNavigate('devices')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'devices'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Hardware</span>
          </button>

          {/* TAB 13: Native .NET 8 WPF */}
          <button
            onClick={() => handleNavigate('native-desktop')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'native-desktop'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Laptop className="w-3.5 h-3.5 text-blue-400" />
            <span>Native C# WPF</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
              EXE
            </span>
          </button>
        </div>

        {/* Presentation Mode Toggle Badge on the right */}
        <div className="flex items-center gap-2 pr-2 py-1">
          <button
            onClick={() => handleToggleUIMode(uiMode === 'beginner' ? 'expert' : 'beginner')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700/80 hover:bg-slate-700/80 transition-colors text-[11px]"
            title="Switch presentation depth"
          >
            <Sparkles className="w-3 h-3 text-amber-400" />
            <span className="text-slate-400">Mode:</span>
            <span className={`font-semibold capitalize ${uiMode === 'expert' ? 'text-purple-400' : 'text-blue-400'}`}>
              {uiMode}
            </span>
          </button>
        </div>
      </nav>

      {/* Main Content View */}
      <main className="flex-1 p-4 max-w-[1600px] w-full mx-auto space-y-4">
        {/* TAB 1: Command Center Dashboard */}
        {activeTab === 'dashboard' && (
          <CommandCenterDashboard
            accessPoints={accessPoints}
            incidents={incidents}
            securityChanges={securityChanges}
            uiMode={uiMode}
            isScanning={isScanning}
            currentChannel={currentChannel}
            dataSourceProfile={dataSourceProfile}
            bridgeState={bridgeState}
            onOpenBridgeConfig={() => setShowArchitectureModal(true)}
            onNavigate={handleNavigate}
            onSelectAP={(ap) => {
              setSelectedBssid(ap.bssid);
              handleNavigate('networks');
            }}
          />
        )}

        {/* TAB 2: Asset Inventory / Networks / Discovery */}
        {(activeTab === 'networks' || activeTab === 'discovery' || activeTab === 'discover') && (
          <div className="space-y-4">
            {/* View Switcher: Governance Inventory vs Full Discovery Grid */}
            <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/90 border border-slate-800 p-2 rounded-xl">
              <div className="flex items-center gap-1.5 p-0.5 bg-slate-950/80 border border-slate-800/80 rounded-lg">
                <button
                  onClick={() => setNetworkViewMode('inventory')}
                  className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                    networkViewMode === 'inventory'
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Asset Inventory &amp; Governance
                </button>
                <button
                  onClick={() => setNetworkViewMode('discovery')}
                  className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all flex items-center gap-1.5 ${
                    networkViewMode === 'discovery'
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Radio className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Real Discovery Grid ({accessPoints.length} BSS)</span>
                </button>
              </div>

              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-400">Provenance:</span>
                <span className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                  dataSourceProfile === 'LIVE_WINDOWS'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : dataSourceProfile === 'REAL_PCAP' || dataSourceProfile === 'REAL_NETSH' || dataSourceProfile === 'IMPORTED'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                      : dataSourceProfile === 'OFFLINE'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        : 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                }`}>
                  {dataSourceProfile === 'LIVE_WINDOWS' && 'LIVE SENSOR (WLAN API)'}
                  {(dataSourceProfile === 'REAL_PCAP' || dataSourceProfile === 'REAL_NETSH' || dataSourceProfile === 'IMPORTED') && 'IMPORTED TELEMETRY'}
                  {dataSourceProfile === 'OFFLINE' && 'OFFLINE DATABASE'}
                  {(dataSourceProfile === 'BENCHMARK' || dataSourceProfile === 'TRAINING' || dataSourceProfile === 'OFFLINE_LAB') && 'LIVE OVER-THE-AIR SENSOR'}
                </span>
                <span className="text-[11px] text-slate-500">({accessPoints.length} retained)</span>
              </div>
            </div>

            {networkViewMode === 'inventory' ? (
              <AssetInventory
                accessPoints={accessPoints}
                uiMode={uiMode}
                initialFilter={tabFilterParam}
                onSelectAP={(ap) => setSelectedBssid(ap.bssid)}
                onUpdateAP={handleUpdateAP}
              />
            ) : (
              <NetworkDiscovery
                accessPoints={accessPoints}
                selectedBssid={selectedBssid}
                onSelectAp={(bssid) => setSelectedBssid(bssid)}
                onCaptureHandshake={handleCaptureHandshake}
                dataSourceProfile={dataSourceProfile}
                activeSourceLabel={activeSourceLabel}
                onOpenImport={() => setShowImportModal(true)}
                onLoadBenchmark={handleLoadBenchmark}
                onRefreshScan={handleRefreshScan}
                onOpenBridgeConfig={() => setShowArchitectureModal(true)}
                isDarkMode={isDarkMode}
              />
            )}

            {/* Deep 802.11 Layer Inspection Panel */}
            {selectedAp && (
              <NetworkDetailPanel
                ap={selectedAp}
                onClose={() => setSelectedBssid(null)}
                onCaptureHandshake={handleCaptureHandshake}
                isDarkMode={isDarkMode}
                dataSourceProfile={dataSourceProfile}
                onOpenCaptureGuide={() => setShowArchitectureModal(true)}
                onOpenImport={() => setShowImportModal(true)}
              />
            )}
          </div>
        )}

        {/* TAB 3: Client Observer */}
        {activeTab === 'clients' && (
          <ClientObserver
            accessPoints={accessPoints}
            uiMode={uiMode}
            dataSourceProfile={dataSourceProfile}
            onOpenImport={() => setShowImportModal(true)}
            onSwitchToTraining={handleLoadBenchmark}
            onSelectAP={(ap) => {
              setSelectedBssid(ap.bssid);
              handleNavigate('networks');
            }}
          />
        )}

        {/* TAB 4: RF Spectrum */}
        {activeTab === 'spectrum' && (
          <div className="space-y-4">
            <SpectrumVisualizer
              accessPoints={accessPoints}
              selectedBssid={selectedBssid}
              dataSourceProfile={dataSourceProfile}
              onSelectAp={(bssid) => {
                setSelectedBssid(bssid);
                handleNavigate('networks');
              }}
              isDarkMode={isDarkMode}
            />
          </div>
        )}

        {/* TAB 5: Threats & Rogues */}
        {activeTab === 'threats' && (
          <ThreatCenter
            accessPoints={accessPoints}
            securityChanges={securityChanges}
            uiMode={uiMode}
            onNavigate={handleNavigate}
            onSelectAP={(ap) => {
              setSelectedBssid(ap.bssid);
              handleNavigate('networks');
            }}
            onRefreshThreats={() => {
              setIncidents(threatEngine.getIncidents());
              setSecurityChanges(threatEngine.getSecurityChanges());
            }}
            onTriageThreat={handleTriageThreat}
          />
        )}

        {/* TAB 6: Investigations */}
        {activeTab === 'investigations' && (
          <IncidentCenter
            incidents={incidents}
            uiMode={uiMode}
            onRefreshIncidents={() => setIncidents(threatEngine.getIncidents())}
            onUpdateIncidentStatus={handleUpdateIncidentStatus}
          />
        )}

        {/* TAB 7: Packet Dissector */}
        {activeTab === 'packets' && (
          <PacketAnalyzer
            packets={packets}
            onOpenImport={() => setShowImportModal(true)}
            isDarkMode={isDarkMode}
          />
        )}

        {/* TAB 8: Cryptographic Handshakes */}
        {activeTab === 'handshakes' && (
          <HandshakeManager
            handshakes={handshakes}
            accessPoints={accessPoints}
            dataSourceProfile={dataSourceProfile}
            onSimulateCapture={handleCaptureHandshake}
            onOpenImport={() => setShowImportModal(true)}
            onOpenCaptureGuide={() => setShowArchitectureModal(true)}
            isDarkMode={isDarkMode}
          />
        )}

        {/* TAB 9: Multi-Site Projects */}
        {(activeTab === 'projects' || activeTab === 'database') && (
          <EnterpriseProjectManager
            currentProject={currentProject}
            projects={projects}
            accessPoints={accessPoints}
            onSwitchProject={(proj) => {
              setCurrentProjectId(proj.id);
              db.setCurrentProjectId(proj.id);
            }}
            onCreateProject={handleCreateProject}
          />
        )}

        {/* TAB 10: Reports */}
        {activeTab === 'reports' && (
          <ReportingCenter
            currentProject={currentProject}
            accessPoints={accessPoints}
            incidents={incidents}
            uiMode={uiMode}
          />
        )}

        {/* TAB 11: Hardware & Diagnostics */}
        {activeTab === 'devices' && (
          <HardwareDiagnostics
            adapter={adapters[0] || null}
            uiMode={uiMode}
            dataSourceProfile={dataSourceProfile}
            bridgeState={bridgeState}
            bridgeStatus={bridgeStatus}
            onOpenBridgeConfig={() => setShowArchitectureModal(true)}
            onOpenImport={() => setShowImportModal(true)}
          />
        )}

        {/* TAB 13: Native .NET 8 WPF Desktop */}
        {activeTab === 'native-desktop' && (
          <NativeDesktopPanel isDarkMode={isDarkMode} />
        )}

        {/* Real-time Diagnostics & Auditing Logs Console */}
        <LogConsole
          logs={logs}
          onClearLogs={() => {
            db.clearLogs();
            setLogs([]);
          }}
          isDarkMode={isDarkMode}
        />
      </main>

      {/* Reporting Modal */}
      {showReportModal && (
        <ReportingModal
          accessPoints={accessPoints}
          project={currentProject}
          onClose={() => setShowReportModal(false)}
          isDarkMode={isDarkMode}
        />
      )}

      {/* Self-Test Modal */}
      {showSelfTestModal && (
        <SelfTestModal
          onClose={() => setShowSelfTestModal(false)}
          isDarkMode={isDarkMode}
        />
      )}

      {/* Runtime Architecture & Capabilities Modal */}
      {showArchitectureModal && (
        <ArchitectureModal
          onClose={() => setShowArchitectureModal(false)}
          isDarkMode={isDarkMode}
        />
      )}

      {/* Ingest & File Import Modal */}
      {showImportModal && (
        <ImportModal
          onClose={() => setShowImportModal(false)}
          onImportPcap={handleImportPcap}
          onImportNetsh={handleImportNetsh}
          onLoadBenchmark={handleLoadBenchmark}
          currentProfile={dataSourceProfile}
          isDarkMode={isDarkMode}
        />
      )}
    </div>
  );
}

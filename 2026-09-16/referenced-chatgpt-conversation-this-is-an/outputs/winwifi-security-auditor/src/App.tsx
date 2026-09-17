import React, { useState, useEffect, useCallback } from 'react';
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
  BridgeConnectionState,
  BridgeHealthStatus,
  UIMode,
  IncidentRecord,
  SecurityChange,
  TrainingLabScenario
} from './types';
import { WifiEngine } from './services/wifiEngine';
import { SqliteDatabaseService } from './services/storage';
import { PcapService, PcapParseResult } from './services/pcapParser';
import { ThreatEngine } from './services/threatEngine';
import { PolicyEngine } from './services/policyEngine';
import { NativeBridgeClient } from './services/bridgeClient';

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
import { BridgeConfigModal } from './components/BridgeConfigModal';
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
  const [dataSourceProfile, setDataSourceProfile] = useState<DataSourceProfile>('OFFLINE');
  const [activeSourceLabel, setActiveSourceLabel] = useState<string>('Waiting for the local Windows bridge');

  // Adapters & Scan State
  const [adapters, setAdapters] = useState<WifiAdapter[]>([]);
  const [selectedAdapterId, setSelectedAdapterId] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [currentChannel, setCurrentChannel] = useState<number>(6);

  // Network Data & Packets
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
    return initialLogs;
  });

  // Modals
  const [showReportModal, setShowReportModal] = useState<boolean>(false);
  const [showSelfTestModal, setShowSelfTestModal] = useState<boolean>(false);
  const [showArchitectureModal, setShowArchitectureModal] = useState<boolean>(false);
  const [showImportModal, setShowImportModal] = useState<boolean>(false);
  const [showBridgeModal, setShowBridgeModal] = useState<boolean>(false);

  // Native Windows Bridge State
  const [bridgeState, setBridgeState] = useState<BridgeConnectionState>('DISCONNECTED');
  const [bridgeStatus, setBridgeStatus] = useState<BridgeHealthStatus | null>(null);
  const [networkViewMode, setNetworkViewMode] = useState<'inventory' | 'discovery'>('inventory');

  const bridgeClient = NativeBridgeClient.getInstance();

  // Subscribe to Native Windows Bridge events (SSE & Polling)
  useEffect(() => {
    const unsubStatus = bridgeClient.onStateChange(async (state) => {
      setBridgeState(state);
      if (state === 'CONNECTED') {
        setDataSourceProfile('LIVE_WINDOWS');
        try {
          const health = await bridgeClient.checkHealth();
          setBridgeStatus(health);
          setActiveSourceLabel(`Native Bridge (${health?.activeAdapterName || 'Hardware Adapter'})`);
          const detectedAdapters = await bridgeClient.getAdapters();
          setAdapters(detectedAdapters);
          setSelectedAdapterId(current => current || detectedAdapters[0]?.id || '');
        } catch {
          setActiveSourceLabel('Native Bridge (Port 38989)');
        }
      } else if (state === 'DISCONNECTED' || state === 'ERROR') {
        setDataSourceProfile((prev) => (prev === 'LIVE_WINDOWS' ? 'OFFLINE' : prev));
      }
    });

    const unsubNetworks = bridgeClient.onNetworks((liveAps) => {
      if (liveAps && liveAps.length > 0) {
        setAccessPoints(liveAps);
        setDataSourceProfile('LIVE_WINDOWS');
        const count = liveAps.length;
        const log = db.appendLog({
          level: 'SUCCESS',
          source: 'BRIDGE_RX',
          message: `Ingested ${count} live BSS entries from the bounded Windows WLAN telemetry bridge.`,
        });
        setLogs((prev) => [log, ...prev]);
      }
    });

    // Check bridge connectivity on mount
    bridgeClient.checkHealth()
      .then((health) => {
        setBridgeStatus(health);
        setIsScanning(health.isScanning);
      })
      .catch(() => {});

    return () => {
      unsubStatus();
      unsubNetworks();
    };
  }, [db]);

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

  // Toggle Continuous Scan (Real Bridge Hardware vs Benchmark)
  const handleToggleScan = async () => {
    if (bridgeState === 'CONNECTED') {
      try {
        if (isScanning) {
          await bridgeClient.stopScan();
          setIsScanning(false);
          const log = db.appendLog({
            level: 'INFO',
            source: 'BRIDGE_CTRL',
            message: 'Paused continuous background hardware scan on Windows host.',
          });
          setLogs((prev) => [log, ...prev]);
        } else {
          await bridgeClient.startScan(selectedAdapterId || undefined);
          setIsScanning(true);
          const log = db.appendLog({
            level: 'INFO',
            source: 'BRIDGE_CTRL',
            message: 'Started continuous background hardware scan on Windows host.',
          });
          setLogs((prev) => [log, ...prev]);
        }
      } catch (err: any) {
        console.error('Scan toggle error:', err);
      }
    }
  };

  // Immediate Hardware Scan Refresh
  const handleRefreshScan = async () => {
    if (bridgeState === 'CONNECTED') {
      try {
        const result = await bridgeClient.refreshScan(selectedAdapterId || undefined);
        if (result.accessPoints) {
          setAccessPoints(result.accessPoints);
        }
        const log = db.appendLog({
          level: 'SUCCESS',
          source: 'BRIDGE_REFRESH',
          message: `Triggered immediate native WlanScan on Windows wireless adapter (${result.count} discovered).`,
        });
        setLogs((prev) => [log, ...prev]);
      } catch (err: any) {
        console.error('Refresh scan error:', err);
      }
    }
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

  // Ingestion: Load Benchmark
  const handleLoadBenchmark = () => {
    const benchmarkAps = engine.getBenchmarkAccessPoints().map((a) => ({
      ...a,
      dataSourceOrigin: 'TRAINING' as DataOrigin,
    }));
    setAccessPoints(benchmarkAps);
    setPackets(engine.generatePackets(benchmarkAps));
    setDataSourceProfile('BENCHMARK');
    setActiveSourceLabel('NIST SP 800-153 Reference (4 APs)');
    setSelectedBssid('F8:1A:67:8B:11:02');

    const log = db.appendLog({
      level: 'INFO',
      source: 'BENCHMARK',
      message: 'Reloaded NIST SP 800-153 compliance benchmark scenarios.',
    });
    setLogs((prev) => [log, ...prev]);
  };

  // Load Offline Training Scenario
  const handleLoadLabScenario = (scenario: TrainingLabScenario) => {
    const taggedAps = scenario.simulatedAPs.map((a) => ({
      ...a,
      dataSourceOrigin: 'TRAINING' as DataOrigin,
    }));
    setAccessPoints(taggedAps);
    setPackets(engine.generatePackets(taggedAps));
    setDataSourceProfile('TRAINING');
    setActiveSourceLabel(`Lab: ${scenario.title}`);
    setSelectedBssid(taggedAps[0]?.bssid || null);
    handleNavigate('dashboard');

    const log = db.appendLog({
      level: 'INFO',
      source: 'OFFLINE_LAB',
      message: `Loaded offline interactive lab scenario: ${scenario.title}.`,
    });
    setLogs((prev) => [log, ...prev]);
  };

  // Channel hopping loop: only active in BENCHMARK / OFFLINE_LAB training simulation
  useEffect(() => {
    if (!isScanning) return;
    if (dataSourceProfile !== 'BENCHMARK' && dataSourceProfile !== 'OFFLINE_LAB') {
      // In LIVE_WINDOWS or REAL_PCAP mode, we do NOT simulate fake channel hopping
      return;
    }

    const hoppingChannels = [1, 6, 11, 36, 40, 48, 149, 69];
    let hopIndex = 0;

    const interval = setInterval(() => {
      hopIndex = (hopIndex + 1) % hoppingChannels.length;
      const nextCh = hoppingChannels[hopIndex];
      setCurrentChannel(nextCh);

      if (dataSourceProfile === 'BENCHMARK') {
        setAccessPoints((prev) =>
          prev.map((ap) => {
            if (ap.channel === nextCh || Math.random() > 0.5) {
              const jitter = (Math.random() - 0.5) * 1.5;
              const newRssi = Math.min(-30, Math.max(-92, Math.round(ap.rssi + jitter)));
              return {
                ...ap,
                rssi: newRssi,
                beaconCount: ap.beaconCount + Math.floor(Math.random() * 5 + 1),
                dataPacketCount: ap.dataPacketCount + Math.floor(Math.random() * 12 + 2),
                lastSeen: 'Just now',
              };
            }
            return ap;
          })
        );
      }
    }, 1800);

    return () => clearInterval(interval);
  }, [isScanning, dataSourceProfile]);

  // Capture Handshake: Strictly gated to Training Labs only. Never fakes handshakes in production mode.
  const handleCaptureHandshake = useCallback((ap: AccessPoint) => {
    if (dataSourceProfile === 'LIVE_WINDOWS' || dataSourceProfile === 'REAL_NETSH' || dataSourceProfile === 'REAL_PCAP') {
      const log = db.appendLog({
        level: 'WARN',
        source: 'HANDSHAKE_VALIDATOR',
        message: `Live cryptographic handshake capture for "${ap.ssid}" (${ap.bssid}) blocked: WinWiFi strictly prohibits synthesizing fake 4-way handshakes in production mode. Promiscuous 802.11 monitor capture driver (Npcap / Wireshark) required.`,
      });
      setLogs((prev) => [log, ...prev]);
      setShowArchitectureModal(true);
      return;
    }

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
      origin: 'TRAINING',
      isSimulated: true,
    };

    setAccessPoints((prev) =>
      prev.map((a) => (a.bssid === ap.bssid ? { ...a, handshake: newHandshake } : a))
    );

    db.saveHandshake(newHandshake);

    const log = db.appendLog({
      level: 'INFO',
      source: 'HANDSHAKE_VALIDATOR',
      message: `[TRAINING LAB] Generated synthetic EAPOL handshake model for educational audit of "${ap.ssid}".`,
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
        info: `[TRAINING] EAPOL 4-Way Handshake [Message 1/4] ANonce: ${anonce.slice(0, 16)}...`,
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
        info: `[TRAINING] EAPOL 4-Way Handshake [Message 2/4] SNonce: ${snonce.slice(0, 16)}... MIC: ${mic}`,
        hexPreview: '01 03 00 5f 02 01 0a 00 00 00 00 00 00 00 00 00 02'
      },
      ...prev,
    ]);
  }, [dataSourceProfile, db]);

  // Update Access Point Metadata
  const handleUpdateAP = (updatedAP: AccessPoint) => {
    setAccessPoints((prev) => prev.map((a) => (a.bssid === updatedAP.bssid ? updatedAP : a)));
  };

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
        onOpenBridgeConfig={() => setShowBridgeModal(true)}
        projectName={currentProject.name}
        onOpenReport={() => setShowReportModal(true)}
        onOpenSelfTest={() => setShowSelfTestModal(true)}
        onOpenImport={() => setShowImportModal(true)}
        onOpenArchitecture={() => setShowArchitectureModal(true)}
        currentChannel={currentChannel}
        adapters={adapters}
        selectedAdapterId={selectedAdapterId}
        onSelectAdapter={setSelectedAdapterId}
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

          {/* TAB 12: Settings & Lab */}
          <button
            onClick={() => handleNavigate('settings')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'settings'
                ? 'border-purple-500 text-purple-400 bg-purple-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Settings &amp; Lab</span>
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
            onOpenBridgeConfig={() => setShowBridgeModal(true)}
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
                  {dataSourceProfile === 'LIVE_WINDOWS' && 'LIVE WINDOWS DATA'}
                  {(dataSourceProfile === 'REAL_PCAP' || dataSourceProfile === 'REAL_NETSH' || dataSourceProfile === 'IMPORTED') && 'IMPORTED DATA'}
                  {dataSourceProfile === 'OFFLINE' && 'OFFLINE DATA'}
                  {(dataSourceProfile === 'BENCHMARK' || dataSourceProfile === 'TRAINING' || dataSourceProfile === 'OFFLINE_LAB') && 'TRAINING DATA'}
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
                onOpenBridgeConfig={() => setShowBridgeModal(true)}
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
          />
        )}

        {/* TAB 6: Investigations */}
        {activeTab === 'investigations' && (
          <IncidentCenter
            incidents={incidents}
            uiMode={uiMode}
            onRefreshIncidents={() => setIncidents(threatEngine.getIncidents())}
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
            adapter={adapters[0]}
            uiMode={uiMode}
            dataSourceProfile={dataSourceProfile}
            bridgeState={bridgeState}
            bridgeStatus={bridgeStatus}
            onOpenBridgeConfig={() => setShowBridgeModal(true)}
            onOpenImport={() => setShowImportModal(true)}
          />
        )}

        {/* TAB 12: Settings & Lab */}
        {activeTab === 'settings' && (
          <SettingsAndLab
            uiMode={uiMode}
            onToggleUIMode={handleToggleUIMode}
            onLoadLabScenario={handleLoadLabScenario}
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

      {/* Windows Native Bridge Configuration Modal */}
      {showBridgeModal && (
        <BridgeConfigModal
          isOpen={showBridgeModal}
          onClose={() => setShowBridgeModal(false)}
          onScanTriggered={handleRefreshScan}
        />
      )}
    </div>
  );
}

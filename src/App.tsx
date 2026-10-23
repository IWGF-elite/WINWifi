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
  BridgeConnectionState,
  BridgeHealthStatus,
  UIMode,
  IncidentRecord,
  EvidenceItem,
  SecurityChange,
  TrainingLabScenario,
  AnalystClassification
} from './types';
import { WifiEngine } from './services/wifiEngine';
import { SqliteDatabaseService } from './services/storage';
import { PcapService, PcapParseResult } from './services/pcapParser';
import { ThreatEngine } from './services/threatEngine';
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
import { ReportingModal } from './components/ReportingModal';
import { SelfTestModal } from './components/SelfTestModal';
import { ArchitectureModal } from './components/ArchitectureModal';
import { ImportModal } from './components/ImportModal';
import { BridgeConfigModal } from './components/BridgeConfigModal';
import { LogConsole } from './components/LogConsole';
import { NativeDesktopPanel } from './components/NativeDesktopPanel';

const applyAnalystOverrides = (
  accessPoints: AccessPoint[],
  overrides: Record<string, AnalystClassification>
): AccessPoint[] => accessPoints.map(ap => {
  const classification = overrides[ap.bssid.toUpperCase()];
  if (!classification) return ap;
  if (classification === 'Confirmed Rogue') {
    return { ...ap, classification: 'Rogue', isRogueCandidate: true, approvedStatus: 'Unapproved' };
  }
  return {
    ...ap,
    classification: 'Trusted',
    isRogueCandidate: false,
    approvedStatus: classification === 'Trusted' ? 'Approved' : 'Pending Review'
  };
});

// Convert findings produced by the native SecurityAnalyzer into the UI's
// investigation records. These records remain tied to a real BSSID and are
// refreshed on every Windows scan; no placeholder incidents are fabricated.
const mapNativeFindingsToIncidents = (findings: any[]): IncidentRecord[] => findings
  .filter(f => f && f.id && f.title)
  .map(f => {
    const severity = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(String(f.severity).toUpperCase())
      ? String(f.severity).toUpperCase() : 'MEDIUM') as IncidentRecord['severity'];
    const timestamp = f.detectedAt || new Date().toISOString();
    return {
      id: `NATIVE-${f.id}`,
      title: f.title,
      severity,
      confidence: Number(f.confidence) || 0,
      status: f.status === 'Resolved' ? 'Resolved' : f.status === 'False Positive' ? 'False Positive' : 'Open',
      createdAt: timestamp,
      updatedAt: timestamp,
      assignedTo: 'Windows WLAN Security Analyzer',
      summary: f.explanation || f.evidence || 'Finding reported by the native Windows WLAN security analyzer.',
      bssidTarget: f.relatedBssid || undefined,
      ssidTarget: f.relatedSsid || undefined,
      evidenceIds: [],
      notes: [{ timestamp, author: 'Native Security Analyzer', text: f.evidence || f.explanation || f.title }],
      resolution: f.remediation || undefined
    };
  });

const mapAccessPointIssuesToIncidents = (aps: AccessPoint[]): IncidentRecord[] => aps.flatMap(ap =>
  (ap.issues || []).filter(issue => issue && issue.id && issue.title).map(issue => {
    const timestamp = ap.lastSeen || new Date().toISOString();
    const severity = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(issue.severity) ? issue.severity : 'MEDIUM') as IncidentRecord['severity'];
    return {
      id: `NATIVE-AP-${ap.bssid.replace(/[^A-Z0-9]/gi, '')}-${issue.id}`,
      title: issue.title,
      severity,
      confidence: 100,
      status: 'Open',
      createdAt: timestamp,
      updatedAt: timestamp,
      assignedTo: 'Windows WLAN Security Analyzer',
      summary: issue.description,
      bssidTarget: ap.bssid,
      ssidTarget: ap.ssid,
      evidenceIds: [],
      notes: [{ timestamp, author: 'Windows WLAN Security Analyzer', text: issue.description }],
      resolution: issue.recommendation
    };
  })
);

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
  const dataSourceProfileRef = useRef(dataSourceProfile);
  useEffect(() => { dataSourceProfileRef.current = dataSourceProfile; }, [dataSourceProfile]);
  const [activeSourceLabel, setActiveSourceLabel] = useState<string>('Waiting for the local Windows bridge');
  const [lastLiveDataAt, setLastLiveDataAt] = useState<number | null>(null);
  // Adapters & Scan State
  const [adapters, setAdapters] = useState<WifiAdapter[]>([]);
  const [selectedAdapterId, setSelectedAdapterId] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [currentChannel, setCurrentChannel] = useState<number>(6);

  // Network Data & Packets
  const [accessPoints, setAccessPoints] = useState<AccessPoint[]>(() => {
    const projectId = db.getCurrentProjectId();
    return applyAnalystOverrides(db.getAccessPoints(projectId).filter(ap => ap.dataSourceOrigin !== 'TRAINING'), db.getAnalystOverrides(projectId));
  });
  const [packets, setPackets] = useState<PcapPacket[]>([]);
  const [selectedBssid, setSelectedBssid] = useState<string | null>(null);

  // Threats & Incidents
  const [incidents, setIncidents] = useState<IncidentRecord[]>(() => {
    const saved = db.getIncidents();
    return (saved ?? []).filter(incident => !['INC-00042', 'INC-00038'].includes(incident.id)).map(incident => ({ ...incident, notes: [...(incident.notes || [])], evidenceIds: [...(incident.evidenceIds || [])] }));
  });
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>(() => db.getEvidenceItems());
  const [securityChanges, setSecurityChanges] = useState<SecurityChange[]>(() => threatEngine.getSecurityChanges());

  // Projects & Logs
  const [projects, setProjects] = useState<AuditProject[]>(() => db.getProjects());
  const [currentProjectId, setCurrentProjectId] = useState<string>(() => db.getCurrentProjectId());
  const currentProjectIdRef = useRef(currentProjectId);
  useEffect(() => { currentProjectIdRef.current = currentProjectId; }, [currentProjectId]);
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
  const [bridgeNotice, setBridgeNotice] = useState('');

  // A Windows WLAN scan is periodic, not a continuous frame stream. Keep the
  // source labelled as live while the local bridge is connected; freshness is
  // shown separately by the toolbar badge. Previously this changed live data
  // to "OFFLINE" after 30 seconds even though the scanner was still running.

  const bridgeClient = NativeBridgeClient.getInstance();

  // Subscribe to Native Windows Bridge events (SSE & Polling)
  useEffect(() => {
    threatEngine.setIncidents(incidents);
    if (db.getIncidents() === null || db.getIncidents()?.some(incident => ['INC-00042', 'INC-00038'].includes(incident.id))) db.saveIncidents(incidents);
  // Keep the incident engine aligned with the user's persisted incident records.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const unsubStatus = bridgeClient.onStateChange(async (state) => {
      setBridgeState(state);
      if (state === 'CONNECTED') {
        setBridgeNotice('');
        setActiveSourceLabel('Windows bridge connected; waiting for WLAN observations');
        try {
          const health = await bridgeClient.checkHealth();
          setBridgeStatus(health);
          setIsScanning(health.isScanning ?? false);
          setActiveSourceLabel(`Native Bridge (${health?.activeAdapterName || 'Hardware Adapter'})`);
          const detectedAdapters = await bridgeClient.getAdapters();
          setAdapters(detectedAdapters);
          setSelectedAdapterId(current => current || detectedAdapters[0]?.id || '');
        } catch {
          setActiveSourceLabel('Native Bridge (Port 38989)');
        }
      } else if (state === 'DISCONNECTED' || state === 'ERROR') {
        setLastLiveDataAt(null);
        if (dataSourceProfileRef.current === 'LIVE_WINDOWS') {
          setAccessPoints([]);
          setDataSourceProfile('OFFLINE');
        }
        if (state === 'ERROR') setBridgeNotice(bridgeClient.getLastError() || 'Could not connect to the local Windows bridge.');
      }
    });

    const unsubNetworks = bridgeClient.onNetworks((liveAps) => {
      if (Array.isArray(liveAps)) {
        const projectId = currentProjectIdRef.current;
        const resolvedAps = applyAnalystOverrides(liveAps, db.getAnalystOverrides(projectId));
        if (resolvedAps.length > 0) {
          setAccessPoints(resolvedAps);
          setIncidents(previous => {
            const live = [...mapAccessPointIssuesToIncidents(resolvedAps), ...previous.filter(i => !i.id.startsWith('NATIVE-AP-'))];
            threatEngine.setIncidents(live);
            db.saveIncidents(live);
            return live;
          });
          db.saveAccessPoints(projectId, resolvedAps);
          setDataSourceProfile('LIVE_WINDOWS');
          setLastLiveDataAt(Date.now());
          setActiveSourceLabel(`Windows WLAN bridge (${resolvedAps.length} access points)`);
        }
        // Keep the last successful result visible when Windows temporarily
        // returns an empty cache during a radio refresh.
        if (resolvedAps.length > 0) {
          setSelectedBssid((current) => resolvedAps.some(ap => ap.bssid === current) ? current : resolvedAps[0]?.bssid ?? null);
        }
        const count = resolvedAps.length;
        const log = db.appendLog({
          level: count > 0 ? 'SUCCESS' : 'INFO',
          source: 'BRIDGE_RX',
          message: count > 0
            ? `Ingested ${count} live BSS entries from the Windows WLAN telemetry bridge.`
            : 'Windows bridge is connected; the WLAN scan cache currently contains no access points.',
        });
        setLogs((prev) => [log, ...prev]);
      }
    });

    const applyNativeIncidents = (findings: any[]) => {
      const native = mapNativeFindingsToIncidents(findings);
      setIncidents(previous => {
        const liveApIssues = previous.filter(incident => incident.id.startsWith('NATIVE-AP-'));
        const analyst = previous.filter(incident => !incident.id.startsWith('NATIVE-'));
        const merged = [...native, ...liveApIssues, ...analyst];
        threatEngine.setIncidents(merged);
        db.saveIncidents(merged);
        return merged;
      });
    };
    const unsubIncidents = bridgeClient.onIncidents(applyNativeIncidents);

    // Establish the connection and start event/polling updates on mount.
    void bridgeClient.connect();

    return () => {
      unsubStatus();
      unsubNetworks();
      unsubIncidents();
      bridgeClient.disconnect();
    };
  }, [bridgeClient, db, threatEngine]);

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

  const handleToggleFullscreen = async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.documentElement.requestFullscreen();
    } catch (err: any) {
      setBridgeNotice(`Full screen is unavailable in this browser: ${err?.message || 'request denied'}`);
    }
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
    if (bridgeClient.getState() !== 'CONNECTED') {
      setBridgeNotice('Scanning requires the WinWiFi Windows bridge running on this PC. A hosted Gemini Builder preview cannot access your local Wi-Fi adapter.');
      setShowBridgeModal(true);
      return;
    }
    try {
      const result = isScanning
        ? await bridgeClient.stopScan()
        : await bridgeClient.startScan(selectedAdapterId || undefined);
      setIsScanning(result.isScanning);
      setBridgeNotice(result.message);
      const log = db.appendLog({ level: 'INFO', source: 'BRIDGE_CTRL', message: result.message });
      setLogs((prev) => [log, ...prev]);
    } catch (err: any) {
      const message = `Scan control failed: ${err?.message || 'unknown bridge error'}`;
      setBridgeNotice(message);
      db.appendLog({ level: 'ERROR', source: 'BRIDGE_CTRL', message });
    }
  };

  // Immediate Hardware Scan Refresh
  const handleRefreshScan = async () => {
    if (bridgeClient.getState() !== 'CONNECTED') {
      setBridgeNotice('Refresh requires the WinWiFi Windows bridge. Connect it or load sample data to explore the dashboard.');
      setShowBridgeModal(true);
      return;
    }
    try {
      const result = await bridgeClient.refreshScan(selectedAdapterId || undefined);
      const resolvedAps = applyAnalystOverrides(result.accessPoints, db.getAnalystOverrides(currentProjectId));
      setAccessPoints(resolvedAps);
      setDataSourceProfile(resolvedAps.length ? 'LIVE_WINDOWS' : 'OFFLINE');
      setLastLiveDataAt(result.accessPoints.length ? Date.now() : null);
      setActiveSourceLabel(resolvedAps.length ? `Windows WLAN bridge (${resolvedAps.length} access points)` : 'Windows bridge connected; no WLAN observations returned');
      if (resolvedAps.length) db.saveAccessPoints(currentProjectId, resolvedAps);
      setSelectedBssid(resolvedAps[0]?.bssid ?? null);
      const log = db.appendLog({
        level: result.count > 0 ? 'SUCCESS' : 'INFO', source: 'BRIDGE_REFRESH',
        message: `Windows WLAN refresh completed (${result.count} access points returned).`,
      });
      setLogs((prev) => [log, ...prev]);
      setBridgeNotice(result.count > 0 ? `Refresh complete: ${result.count} access points found.` : 'Refresh completed; Windows returned no access points.');
    } catch (err: any) {
      const message = `Refresh failed: ${err?.message || 'unknown bridge error'}`;
      setBridgeNotice(message);
      db.appendLog({ level: 'ERROR', source: 'BRIDGE_REFRESH', message });
    }
  };

  // Ingestion: Real PCAP File Import
  const handleImportPcap = (result: PcapParseResult, filename: string) => {
    const taggedAps = applyAnalystOverrides(result.accessPoints.map((a) => ({
      ...a,
      dataSourceOrigin: 'IMPORTED' as DataOrigin,
    })), db.getAnalystOverrides(currentProjectId));
    setAccessPoints(taggedAps);
    setPackets(result.packets);
    const captureEvidence: EvidenceItem = {
      id: `PCAP-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: 'pcap',
      title: `Imported capture: ${filename}`,
      source: 'Local PCAP/PCAPNG file',
      description: `${result.summary.totalPackets} decoded frames, ${result.summary.apCount} access points, ${result.summary.eapolCount} EAPOL frames. Evidence is derived from the imported file.`
    };
    setEvidenceItems(previous => {
      const next = [captureEvidence, ...previous];
      db.saveEvidenceItems(next);
      return next;
    });
    db.saveAccessPoints(currentProjectId, taggedAps);
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

  const handleImportPcapFile = async (file: File) => {
    if (bridgeClient.getState() !== 'CONNECTED') {
      handleImportPcap(PcapService.getInstance().parseBinaryPcap(await file.arrayBuffer()), file.name);
      return;
    }
    const native = await bridgeClient.importPcap(file);
    const parsed: PcapParseResult = {
      packets: native.packets || [],
      accessPoints: (native.accessPoints || []).map((ap: any) => ({
        ...ap,
        channelWidthMhz: ap.channelWidthMhz ?? ap.channelWidth ?? 20,
        clients: ap.clients || [],
        issues: ap.securityIssues || ap.issues || [],
        dataSourceOrigin: 'IMPORTED' as DataOrigin
      })),
      handshakes: native.handshakes || [],
      summary: {
        totalPackets: native.totalFramesCount || 0,
        beaconCount: (native.packets || []).filter((p: any) => p.subtype === 'Beacon').length,
        eapolCount: (native.packets || []).filter((p: any) => String(p.subtype || p.frameType).includes('EAPOL')).length,
        apCount: (native.accessPoints || []).length,
        clientCount: (native.clients || []).length,
        linkType: native.linkTypeName || 'Native PCAP dissector',
        fileSize: file.size
      }
    };
    parsed.handshakes.forEach(handshake => {
      const ap = parsed.accessPoints.find(a => a.bssid?.toLowerCase() === handshake.apBssid?.toLowerCase());
      if (ap) ap.handshake = { ...handshake, origin: 'IMPORTED', isSimulated: false };
    });
    handleImportPcap(parsed, file.name);
  };

  // Ingestion: Real Windows Netsh CLI Ingest
  const handleImportNetsh = (aps: AccessPoint[], logMsg: string) => {
    const taggedAps = applyAnalystOverrides(aps.map((a) => ({
      ...a,
      dataSourceOrigin: 'IMPORTED' as DataOrigin,
    })), db.getAnalystOverrides(currentProjectId));
    setAccessPoints(taggedAps);
    setPackets([]);
    db.saveAccessPoints(currentProjectId, taggedAps);
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
    const benchmarkAps = applyAnalystOverrides(engine.getBenchmarkAccessPoints().map((a) => ({
      ...a,
      dataSourceOrigin: 'TRAINING' as DataOrigin,
    })), db.getAnalystOverrides(currentProjectId));
    setAccessPoints(benchmarkAps);
    db.saveAccessPoints(currentProjectId, benchmarkAps);
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
    const taggedAps = applyAnalystOverrides(scenario.simulatedAPs.map((a) => ({
      ...a,
      dataSourceOrigin: 'TRAINING' as DataOrigin,
    })), db.getAnalystOverrides(currentProjectId));
    setAccessPoints(taggedAps);
    db.saveAccessPoints(currentProjectId, taggedAps);
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

    const log = db.appendLog({
      level: 'WARN',
      source: 'HANDSHAKE_VALIDATOR',
      message: `Handshake capture is unavailable without an imported monitor-mode capture. No synthetic handshake was created for "${ap.ssid}".`,
    });
    setLogs((prev) => [log, ...prev]);
  }, [dataSourceProfile, db]);

  // Update Access Point Metadata
  const handleUpdateAP = (updatedAP: AccessPoint) => {
    const next = accessPoints.map((a) => (a.bssid === updatedAP.bssid ? updatedAP : a));
    setAccessPoints(next);
    db.saveAccessPoints(currentProjectId, next);
  };

  const handleClassifyAP = (bssid: string, classification: AnalystClassification) => {
    threatEngine.markAnalystClassification(bssid, classification);
    db.saveAnalystOverride(currentProjectId, bssid, classification);
    const target = accessPoints.find(ap => ap.bssid.toUpperCase() === bssid.toUpperCase());
    if (!target) return;
    handleUpdateAP(applyAnalystOverrides([target], { [bssid.toUpperCase()]: classification })[0]);
    if (classification === 'Confirmed Rogue' && !incidents.some(incident => incident.bssidTarget?.toUpperCase() === bssid.toUpperCase())) {
      threatEngine.createIncident({
        title: `Confirmed Rogue Access Point: ${target.ssid}`,
        severity: 'CRITICAL',
        confidence: target.rogueConfidence ?? 95,
        bssid,
        ssid: target.ssid,
        summary: `An analyst confirmed ${bssid} (${target.ssid}) as an unauthorized access point.`
      });
      refreshIncidents();
    }
  };

  const refreshIncidents = () => {
    const next = threatEngine.getIncidents().map(incident => ({
      ...incident,
      notes: [...(incident.notes || [])],
      evidenceIds: [...(incident.evidenceIds || [])]
    }));
    db.saveIncidents(next);
    setIncidents(next);
  };

  // Create Project in SQLite
  const handleCreateProject = (newProj: AuditProject) => {
    const updated = [newProj, ...projects];
    setProjects(updated);
    db.saveProjects(updated);
    setCurrentProjectId(newProj.id);
    db.setCurrentProjectId(newProj.id);
    setAccessPoints([]);
    setPackets([]);
    setSelectedBssid(null);
    setDataSourceProfile('OFFLINE');

    const log = db.appendLog({
      level: 'INFO',
      source: 'PROJECT_MGR',
      message: `Created SQLite project session: "${newProj.name}".`,
    });
    setLogs((prev) => [log, ...prev]);
  };

  const handleRenameProject = (projectId: string, name: string) => {
    const updated = projects.map(project => project.id === projectId
      ? { ...project, name, updatedAt: new Date().toISOString() }
      : project);
    setProjects(updated);
    db.saveProjects(updated);
  };

  const handleDeleteProject = (projectId: string) => {
    if (projects.length <= 1) return;
    const updated = projects.filter(project => project.id !== projectId);
    if (updated.length === projects.length) return;
    db.deleteProjectData(projectId);
    db.saveProjects(updated);
    setProjects(updated);
    if (currentProjectId === projectId) {
      const next = updated[0];
      db.setCurrentProjectId(next.id);
      setCurrentProjectId(next.id);
      const nextAps = applyAnalystOverrides(db.getAccessPoints(next.id).filter(ap => ap.dataSourceOrigin !== 'TRAINING'), db.getAnalystOverrides(next.id));
      setAccessPoints(nextAps);
      setPackets([]);
      setSelectedBssid(null);
      setDataSourceProfile('OFFLINE');
      setActiveSourceLabel(nextAps.length ? `Saved snapshot (${nextAps.length} access points)` : 'No saved network data in this project');
    }
    const log = db.appendLog({ level: 'INFO', source: 'PROJECT_MGR', message: `Deleted project "${projects.find(project => project.id === projectId)?.name || projectId}" and its saved network observations.` });
    setLogs(previous => [log, ...previous]);
  };

  const handleAddEvidence = (incidentId: string, evidence: EvidenceItem) => {
    const nextEvidence = [evidence, ...db.getEvidenceItems()];
    db.saveEvidenceItems(nextEvidence);
    setEvidenceItems(nextEvidence);
    const nextIncidents = threatEngine.getIncidents().map(incident => incident.id === incidentId
      ? { ...incident, evidenceIds: [...new Set([...(incident.evidenceIds || []), evidence.id])], updatedAt: new Date().toISOString() }
      : { ...incident, notes: [...(incident.notes || [])], evidenceIds: [...(incident.evidenceIds || [])] });
    threatEngine.setIncidents(nextIncidents);
    db.saveIncidents(nextIncidents);
    setIncidents(nextIncidents);
    const log = db.appendLog({ level: 'INFO', source: 'EVIDENCE', message: `Added evidence ${evidence.id} to incident ${incidentId}.` });
    setLogs(previous => [log, ...previous]);
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
        hasFreshLiveData={bridgeState === 'CONNECTED' && dataSourceProfile === 'LIVE_WINDOWS' && lastLiveDataAt !== null}
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
        onToggleFullscreen={handleToggleFullscreen}
      />

      {bridgeNotice && (
        <div role="status" className={`flex items-center justify-between gap-4 border-b px-4 py-2 text-xs ${
          bridgeState === 'ERROR' ? 'border-rose-500/30 bg-rose-500/10 text-rose-200' : 'border-blue-500/30 bg-blue-500/10 text-blue-100'
        }`}>
          <span>{bridgeNotice}</span>
          <button onClick={() => setBridgeNotice('')} className="rounded px-2 py-1 text-slate-300 hover:bg-white/10" aria-label="Dismiss message">Dismiss</button>
        </div>
      )}

      {/* Navigation Ribbon Bar */}
      <nav className={`winwifi-nav px-3 pt-1 border-b flex items-center justify-between overflow-x-auto text-xs select-none ${
        isDarkMode ? 'bg-[#12141a] border-[#1e222d]' : 'bg-[#f4f5fa] border-slate-200'
      }`}>
        <div className="flex items-center gap-0.5 min-w-max">
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
      <main className="flex-1 p-3 lg:p-4 max-w-[1440px] w-full mx-auto space-y-4">
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
            onOpenImport={() => setShowImportModal(true)}
            onLoadBenchmark={handleLoadBenchmark}
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
                  <span>Network Discovery Grid ({accessPoints.length} BSS)</span>
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
              refreshIncidents();
              setSecurityChanges([...threatEngine.getSecurityChanges()]);
            }}
            onClassifyAP={handleClassifyAP}
          />
        )}

        {/* TAB 6: Investigations */}
        {activeTab === 'investigations' && (
          <IncidentCenter
            incidents={incidents}
            evidenceItems={evidenceItems}
            accessPoints={accessPoints}
            uiMode={uiMode}
            onRefreshIncidents={refreshIncidents}
            onAddEvidence={handleAddEvidence}
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
            dataSourceProfile={dataSourceProfile}
            onSwitchProject={(proj) => {
              setCurrentProjectId(proj.id);
              db.setCurrentProjectId(proj.id);
              const projectAps = applyAnalystOverrides(db.getAccessPoints(proj.id).filter(ap => ap.dataSourceOrigin !== 'TRAINING'), db.getAnalystOverrides(proj.id));
              setAccessPoints(projectAps);
              setPackets([]);
              setSelectedBssid(null);
              setDataSourceProfile('OFFLINE');
              setActiveSourceLabel(projectAps.length > 0 ? `Saved snapshot (${projectAps.length} access points)` : 'No saved network data in this project');
            }}
            onCreateProject={handleCreateProject}
            onRenameProject={handleRenameProject}
            onDeleteProject={handleDeleteProject}
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
            accessPoints={accessPoints}
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
          onImportPcapFile={handleImportPcapFile}
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
          onConnectedDataReceived={handleRefreshScan}
          isDarkMode={isDarkMode}
        />
      )}
    </div>
  );
}

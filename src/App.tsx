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
  AnalystClassification,
  EnterpriseAssetRecord,
  EnterpriseScope,
  SiteRecord
} from './types';
import { WifiEngine } from './services/wifiEngine';
import { SqliteDatabaseService } from './services/storage';
import { PcapService, PcapParseResult } from './services/pcapParser';
import { ThreatEngine } from './services/threatEngine';
import { NativeBridgeClient } from './services/bridgeClient';
import {
  mapNativeFindingsToIncidents,
  reconcileLiveIncidents,
  countOpenIncidents
} from './services/incidentMapper';
import {
  applyAssetsToAccessPoints,
  formatUtcTimestamp,
  mergeAssetLists,
  mergeMissingFields,
  normalizeMac,
  parseAssetCsv,
  removeAssetFromAccessPoints,
  serializeAssetCsv
} from './services/assetRegistry';
import { ensureScopeInDirectory } from './services/siteDirectory';
import type { AssetImportSummary } from './components/EnterpriseRegistry';

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
import { StartupReadinessOverlay } from './components/StartupReadinessOverlay';

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
// investigation records. Per-AP configuration issues stay on the access point
// as findings; only threat-level detections become incident cases.


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
  const [connectedBssid, setConnectedBssid] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [currentChannel, setCurrentChannel] = useState<number>(6);

  // Network Data & Packets
  const [accessPoints, setAccessPoints] = useState<AccessPoint[]>(() => {
    const projectId = db.getCurrentProjectId();
    const resolved = applyAnalystOverrides(db.getAccessPoints(projectId).filter(ap => ap.dataSourceOrigin !== 'TRAINING'), db.getAnalystOverrides(projectId));
    return applyAssetsToAccessPoints(resolved, db.getEnterpriseAssets(projectId));
  });
  const accessPointsRef = useRef(accessPoints);
  useEffect(() => { accessPointsRef.current = accessPoints; }, [accessPoints]);

  // Enterprise asset registry: one authoritative record per MAC in this project.
  const [enterpriseAssets, setEnterpriseAssets] = useState<EnterpriseAssetRecord[]>(() => db.getEnterpriseAssets(db.getCurrentProjectId()));
  const enterpriseAssetsRef = useRef(enterpriseAssets);
  useEffect(() => { enterpriseAssetsRef.current = enterpriseAssets; }, [enterpriseAssets]);
  useEffect(() => {
    setAccessPoints(previous => {
      const next = applyAssetsToAccessPoints(previous, enterpriseAssets);
      return next.every((ap, index) => ap === previous[index]) ? previous : next;
    });
  }, [enterpriseAssets]);
  const [siteDirectory, setSiteDirectory] = useState<SiteRecord[]>(() => {
    const projectId = db.getCurrentProjectId();
    const raw = db.getSiteDirectory(projectId);
    const project = db.getProjects().find(candidate => candidate.id === projectId);
    const seeded = ensureScopeInDirectory(raw, project?.scope);
    if (seeded !== raw) db.saveSiteDirectory(seeded, projectId);
    return seeded;
  });
  const siteDirectoryRef = useRef(siteDirectory);
  useEffect(() => { siteDirectoryRef.current = siteDirectory; }, [siteDirectory]);

  const [packets, setPackets] = useState<PcapPacket[]>([]);
  const [selectedBssid, setSelectedBssid] = useState<string | null>(null);
  // A visual row/focus selection is not permission to open the inspection drawer.
  // The drawer receives its own state and is changed only by NetworkDiscovery's
  // explicit Inspect button.
  const [inspectedBssid, setInspectedBssid] = useState<string | null>(null);

  // Threats & Incidents
  const [incidents, setIncidents] = useState<IncidentRecord[]>(() => {
    const saved = db.getIncidents(db.getCurrentProjectId());
    return (saved ?? [])
      .filter(incident => !['INC-00042', 'INC-00038'].includes(incident.id))
      // Older builds promoted every per-AP configuration issue into a case.
      // Those findings now stay on the access point; drop the duplicates.
      .filter(incident => !incident.id.startsWith('NATIVE-AP-'))
      .map(incident => ({ ...incident, notes: [...(incident.notes || [])], evidenceIds: [...(incident.evidenceIds || [])] }));
  });
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>(() => db.getEvidenceItems(db.getCurrentProjectId()));
  const [securityChanges, setSecurityChanges] = useState<SecurityChange[]>(() => threatEngine.getSecurityChanges());

  // Projects & Logs
  const [projects, setProjects] = useState<AuditProject[]>(() => db.getProjects());
  const [currentProjectId, setCurrentProjectId] = useState<string>(() => db.getCurrentProjectId());
  const currentProjectIdRef = useRef(currentProjectId);
  useEffect(() => { currentProjectIdRef.current = currentProjectId; }, [currentProjectId]);
  const [logs, setLogs] = useState<AuditLog[]>(() => {
    const initialLogs = db.getLogs(db.getCurrentProjectId());
    return initialLogs;
  });

  // Modals
  const [showReportModal, setShowReportModal] = useState<boolean>(false);
  const [showSelfTestModal, setShowSelfTestModal] = useState<boolean>(false);
  const [showArchitectureModal, setShowArchitectureModal] = useState<boolean>(false);
  const [showImportModal, setShowImportModal] = useState<boolean>(false);
  const [showBridgeModal, setShowBridgeModal] = useState<boolean>(false);
  // This gate only closes when the operator explicitly opens the dashboard.
  const [showStartupReadiness, setShowStartupReadiness] = useState<boolean>(true);

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

  const commitEnterpriseAssets = useCallback((next: EnterpriseAssetRecord[], projectId: string) => {
    enterpriseAssetsRef.current = next;
    setEnterpriseAssets(next);
    db.saveEnterpriseAssets(projectId, next);
  }, [db]);

  // Native SQLite is authoritative when connected. Local-only records survive
  // and are replayed to the bridge instead of being silently dropped.
  const hydrateAssetsFromBridge = useCallback(async (projectId: string) => {
    if (bridgeClient.getState() !== 'CONNECTED') return;
    const nativeAssets = await bridgeClient.getEnterpriseAssets();
    if (currentProjectIdRef.current !== projectId) return;
    const merged = mergeAssetLists(db.getEnterpriseAssets(projectId), nativeAssets);
    commitEnterpriseAssets(merged, projectId);
    setAccessPoints(previous => applyAssetsToAccessPoints(previous, merged));

    const nativeMacs = new Set(nativeAssets.map(asset => normalizeMac(asset.macAddress)).filter((mac): mac is string => Boolean(mac)));
    for (const asset of merged) {
      const mac = normalizeMac(asset.macAddress);
      if (!mac || nativeMacs.has(mac)) continue;
      try {
        await bridgeClient.saveEnterpriseAsset(asset);
      } catch {
        // Keep the local record; the next reconnect retries the replay.
      }
    }
  }, [bridgeClient, db, commitEnterpriseAssets]);

  // Subscribe to Native Windows Bridge events (SSE & Polling)
  useEffect(() => {
    threatEngine.setIncidents(incidents);
    const projectId = db.getCurrentProjectId();
    const stored = db.getIncidents(projectId);
    const containsLegacyCases = !stored || stored.some(incident =>
      ['INC-00042', 'INC-00038'].includes(incident.id) || incident.id.startsWith('NATIVE-AP-'));
    if (containsLegacyCases) db.saveIncidents(incidents, projectId);
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
          const adapterId = detectedAdapters[0]?.id || '';
          setSelectedAdapterId(current => current || adapterId);
          const connection = await bridgeClient.getConnectionStatus(adapterId);
          setConnectedBssid(connection.state === 'Connected' ? connection.bssid : '');
          void hydrateAssetsFromBridge(currentProjectIdRef.current);
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
        const resolvedAps = applyAssetsToAccessPoints(
          applyAnalystOverrides(liveAps, db.getAnalystOverrides(projectId)),
          enterpriseAssetsRef.current);
        setAccessPoints(resolvedAps);
        setIncidents(previous => {
          const live = reconcileLiveIncidents([], resolvedAps, previous);
          threatEngine.setIncidents(live);
          db.saveIncidents(live, projectId);
          return live;
        });
        db.saveAccessPoints(projectId, resolvedAps);
        setDataSourceProfile('LIVE_WINDOWS');
        setLastLiveDataAt(Date.now());
        setActiveSourceLabel(`Windows WLAN bridge (${resolvedAps.length} access points)`);
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
      const projectId = currentProjectIdRef.current;
      setIncidents(previous => {
        const merged = reconcileLiveIncidents(native, accessPointsRef.current, previous);
        threatEngine.setIncidents(merged);
        db.saveIncidents(merged, projectId);
        return merged;
      });
    };
    const unsubIncidents = bridgeClient.onIncidents(applyNativeIncidents);

    // Establish the connection and start event/polling updates on mount.
    bridgeClient.setProject(currentProjectIdRef.current, projects.find(project => project.id === currentProjectIdRef.current)?.name);
    void bridgeClient.connect();

    return () => {
      unsubStatus();
      unsubNetworks();
      unsubIncidents();
      bridgeClient.disconnect();
    };
  }, [bridgeClient, db, threatEngine, hydrateAssetsFromBridge]);

  // Association state is independent from radio scanning. Poll it separately
  // so a Windows roam or disconnect immediately removes stale Connected badges.
  useEffect(() => {
    if (bridgeState !== 'CONNECTED' || !selectedAdapterId) {
      setConnectedBssid('');
      return;
    }
    let disposed = false;
    const refreshConnection = async () => {
      try {
        const connection = await bridgeClient.getConnectionStatus(selectedAdapterId);
        if (!disposed) setConnectedBssid(connection.state === 'Connected' ? connection.bssid : '');
      } catch {
        if (!disposed) setConnectedBssid('');
      }
    };
    void refreshConnection();
    const timer = window.setInterval(() => void refreshConnection(), 2500);
    return () => { disposed = true; window.clearInterval(timer); };
  }, [bridgeClient, bridgeState, selectedAdapterId]);

  // Handshakes list
  const handshakes: HandshakeInfo[] = accessPoints
    .map((a) => a.handshake)
    .filter((h): h is HandshakeInfo => !!h);

  const rogueFindings = accessPoints.filter(a => a.isRogueCandidate || a.classification === 'Rogue' || a.classification === 'Suspicious');
  const openIncidentCount = countOpenIncidents(incidents);

  // Active Project & Selected AP
  const currentProject = projects.find((p) => p.id === currentProjectId) || projects[0];
  const selectedAp = accessPoints.find((a) => a.bssid === inspectedBssid) || null;

  // A background scan may remove an AP. Closing an invalid drawer is safe, but
  // never retain its BSSID to reopen the drawer if that AP later reappears.
  useEffect(() => {
    if (inspectedBssid && !accessPoints.some(ap => ap.bssid === inspectedBssid)) {
      setInspectedBssid(null);
    }
  }, [accessPoints, inspectedBssid]);

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
      const resolvedAps = applyAssetsToAccessPoints(
        applyAnalystOverrides(result.accessPoints, db.getAnalystOverrides(currentProjectId)),
        enterpriseAssetsRef.current);
      setAccessPoints(resolvedAps);
      setDataSourceProfile(resolvedAps.length ? 'LIVE_WINDOWS' : 'OFFLINE');
      setLastLiveDataAt(result.accessPoints.length ? Date.now() : null);
      setActiveSourceLabel(resolvedAps.length ? `Windows WLAN bridge (${resolvedAps.length} access points)` : 'Windows bridge connected; no WLAN observations returned');
      if (resolvedAps.length) db.saveAccessPoints(currentProjectId, resolvedAps);
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

  const handleAuthorizedConnect = async (ap: AccessPoint, password: string, confirmed: boolean): Promise<string> => {
    if (bridgeClient.getState() !== 'CONNECTED') throw new Error('Windows bridge is not connected.');
    const result = await bridgeClient.connectAuthorizedNetwork({
      adapterId: selectedAdapterId,
      bssid: ap.bssid,
      ssid: ap.ssid,
      password: password || undefined,
      authorizationConfirmed: confirmed,
      authorizedBssids: confirmed ? [ap.bssid] : []
    });
    if (result.state === 'Connected') setConnectedBssid(result.bssid);
    const log = db.appendLog({ level: result.state === 'Failed' ? 'ERROR' : 'INFO', source: 'WLAN_CONNECT', message: `${result.state}: ${result.ssid || ap.ssid}. ${result.reason}` });
    setLogs(previous => [log, ...previous]);
    return `${result.state}: ${result.reason}`;
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
    // Import replaces the data set. It must never carry an open drawer over to
    // a coincidentally matching BSSID in the new capture.
    setInspectedBssid(null);
    if (taggedAps.length > 0) {
      setSelectedBssid(taggedAps[0].bssid);
    }

    const log = db.appendLog({
      level: 'SUCCESS',
      source: 'PCAP_PARSER',
      message: `Parsed binary capture file "${filename}": Decoded ${result.packets.length} frames, discovered ${taggedAps.length} BSSIDs.`,
    });
    const integrityLogs = (result.warnings ?? []).map((message) =>
      db.appendLog({ level: 'WARN', source: 'PCAP_PARSER', message })
    );
    if (result.truncated) {
      integrityLogs.push(db.appendLog({
        level: 'WARN',
        source: 'PCAP_PARSER',
        message: 'Capture parsing stopped at a safety limit; only the validated prefix is shown.',
      }));
    }
    setLogs((prev) => [...integrityLogs.reverse(), log, ...prev]);
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
      warnings: Array.isArray(native.parseWarnings) ? native.parseWarnings : [],
      truncated: Boolean(native.truncated),
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

    const importedFindings = Array.isArray(native.incidents) ? native.incidents : [];
    const importedIncidents = mapNativeFindingsToIncidents(importedFindings);
    if (importedIncidents.length > 0) {
      const projectId = currentProjectIdRef.current;
      setIncidents(previous => {
        const merged = reconcileLiveIncidents(importedIncidents, parsed.accessPoints, previous);
        threatEngine.setIncidents(merged);
        db.saveIncidents(merged, projectId);
        return merged;
      });
    }
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
    setInspectedBssid(null);
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
    setInspectedBssid(null);
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
    setInspectedBssid(null);
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
        message: `Live cryptographic handshake capture for "${ap.ssid}" (${ap.bssid}) blocked: WinWiFi strictly prohibits synthesizing fake 4-way handshakes in production mode. Promiscuous 802.11 monitor capture driver (Npcap or equivalent) required.`,
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

  const handleSiteDirectoryChange = useCallback((sites: SiteRecord[], changedAssets: EnterpriseAssetRecord[]) => {
    const projectId = currentProjectIdRef.current;
    siteDirectoryRef.current = sites;
    setSiteDirectory(sites);
    db.saveSiteDirectory(sites, projectId);

    if (changedAssets.length === 0) return;

    const next = mergeAssetLists(enterpriseAssetsRef.current, changedAssets);
    commitEnterpriseAssets(next, projectId);
    setAccessPoints(previous => applyAssetsToAccessPoints(previous, next));

    const countLabel = `${changedAssets.length} registry location record${changedAssets.length === 1 ? '' : 's'}`;
    if (bridgeClient.getState() !== 'CONNECTED') {
      const log = db.appendLog({
        level: 'INFO',
        source: 'SITE_DIRECTORY',
        message: `Updated ${countLabel} locally after a directory rename; native sync is deferred until the bridge reconnects.`,
      }, projectId);
      setLogs(previous => [log, ...previous]);
      return;
    }

    void Promise.allSettled(changedAssets.map(asset => bridgeClient.saveEnterpriseAsset(asset))).then(results => {
      if (currentProjectIdRef.current !== projectId) return;
      const failed = results.filter(result => result.status === 'rejected').length;
      const log = db.appendLog({
        level: failed ? 'WARN' : 'SUCCESS',
        source: 'SITE_DIRECTORY',
        message: failed
          ? `Updated ${countLabel} locally after a directory rename; ${failed} native sync${failed === 1 ? '' : 's'} failed and will retry on reconnect.`
          : `Updated ${countLabel} after a directory rename.`,
      }, projectId);
      setLogs(previous => [log, ...previous]);
    });
  }, [bridgeClient, commitEnterpriseAssets, db]);

  const handleSaveEnterpriseAsset = async (asset: EnterpriseAssetRecord) => {
    const projectId = currentProjectIdRef.current;
    const next = mergeAssetLists(enterpriseAssetsRef.current, [asset]);
    commitEnterpriseAssets(next, projectId);
    setAccessPoints(previous => applyAssetsToAccessPoints(previous, next));

    let syncError = '';
    if (bridgeClient.getState() === 'CONNECTED') {
      try {
        const response = await bridgeClient.saveEnterpriseAsset(asset);
        if (response?.asset) {
          const synced = mergeAssetLists(enterpriseAssetsRef.current, [response.asset]);
          commitEnterpriseAssets(synced, projectId);
          setAccessPoints(previous => applyAssetsToAccessPoints(previous, synced));
        }
      } catch (err: any) {
        syncError = err?.message || 'unknown bridge error';
      }
    }

    const log = db.appendLog({
      level: syncError ? 'WARN' : 'SUCCESS',
      source: 'ASSET_REGISTRY',
      message: syncError
        ? `Saved ${asset.macAddress} to the local project cache; native SQLite sync failed: ${syncError}`
        : `Saved ${asset.macAddress} (${asset.classification} / ${asset.approvalStatus}) to the project registry.`,
    });
    setLogs(previous => [log, ...previous]);

    if (syncError) {
      throw new Error(`Saved to the local project cache, but native SQLite sync failed: ${syncError}`);
    }
  };

  const handleDeleteEnterpriseAsset = async (macAddress: string) => {
    const mac = normalizeMac(macAddress);
    if (!mac) throw new Error('A valid MAC address is required to delete a registry record.');
    const projectId = currentProjectIdRef.current;
    const next = enterpriseAssetsRef.current.filter(asset => normalizeMac(asset.macAddress) !== mac);
    commitEnterpriseAssets(next, projectId);
    setAccessPoints(previous => {
      const cleaned = applyAnalystOverrides(
        removeAssetFromAccessPoints(previous, mac),
        db.getAnalystOverrides(projectId));
      db.saveAccessPoints(projectId, cleaned);
      return cleaned;
    });

    let syncError = '';
    if (bridgeClient.getState() === 'CONNECTED') {
      try {
        await bridgeClient.deleteEnterpriseAsset(mac);
      } catch (err: any) {
        syncError = err?.message || 'unknown bridge error';
      }
    }

    const log = db.appendLog({
      level: syncError ? 'WARN' : 'SUCCESS',
      source: 'ASSET_REGISTRY',
      message: syncError
        ? `Removed ${mac} from the local registry; native SQLite delete failed: ${syncError}`
        : `Removed ${mac} from the project registry. Captured evidence was left untouched.`,
    });
    setLogs(previous => [log, ...previous]);

    if (syncError) {
      throw new Error(`Removed from the local project cache, but native SQLite delete failed: ${syncError}`);
    }
  };

  const handleImportEnterpriseAssetsCsv = async (csv: string): Promise<AssetImportSummary> => {
    const parsed = parseAssetCsv(csv);
    if (parsed.fatalError) throw new Error(parsed.fatalError);
    if (parsed.rows.length === 0) {
      const details = parsed.rejected.slice(0, 5).join(' ');
      throw new Error(`No valid asset rows were found in the CSV.${details ? ` ${details}` : ''}`);
    }

    const projectId = currentProjectIdRef.current;
    const now = formatUtcTimestamp(new Date());
    let next = [...enterpriseAssetsRef.current];
    for (const row of parsed.rows) {
      const mac = normalizeMac(row.asset.macAddress);
      if (!mac) continue;
      const prior = next.find(asset => normalizeMac(asset.macAddress) === mac);
      if (prior) {
        const merged = mergeMissingFields(prior, row);
        if (!row.provided.has('lastSeen')) merged.lastSeen = prior.lastSeen;
        next = mergeAssetLists(next, [merged]);
      } else {
        next = mergeAssetLists(next, [{
          ...row.asset,
          lastSeen: row.provided.has('lastSeen') ? row.asset.lastSeen : now
        }]);
      }
    }
    commitEnterpriseAssets(next, projectId);
    setAccessPoints(previous => applyAssetsToAccessPoints(previous, next));

    const connected = bridgeClient.getState() === 'CONNECTED';
    let syncError = '';
    if (connected) {
      try {
        await bridgeClient.importEnterpriseAssetsCsv(csv);
        const nativeAssets = await bridgeClient.getEnterpriseAssets();
        if (currentProjectIdRef.current === projectId) {
          commitEnterpriseAssets(nativeAssets, projectId);
          setAccessPoints(previous => applyAssetsToAccessPoints(previous, nativeAssets));
        }
      } catch (err: any) {
        syncError = err?.message || 'unknown bridge error';
      }
    }

    for (const warning of parsed.warnings) {
      const log = db.appendLog({ level: 'WARN', source: 'ASSET_CSV', message: warning }, projectId);
      setLogs(previous => [log, ...previous]);
    }
    for (const rejection of parsed.rejected) {
      const log = db.appendLog({ level: 'WARN', source: 'ASSET_CSV', message: rejection }, projectId);
      setLogs(previous => [log, ...previous]);
    }
    const log = db.appendLog({
      level: syncError ? 'WARN' : 'SUCCESS',
      source: 'ASSET_CSV',
      message: `Asset CSV parsed ${parsed.rowsRead} row(s): ${parsed.rows.length} valid, ${parsed.rejected.length} rejected. ${syncError ? `Native sync failed: ${syncError}` : connected ? 'Saved to project SQLite.' : 'Saved to the local project cache.'}`,
    }, projectId);
    setLogs(previous => [log, ...previous]);

    const message = [
      `Read ${parsed.rowsRead} row(s): ${parsed.rows.length} valid record(s), ${parsed.rejected.length} rejected.`,
      parsed.warnings.length > 0 ? `${parsed.warnings.length} warning(s) written to the audit log.` : '',
      parsed.rejected.length > 0 ? `${parsed.rejected.length} rejection(s) written to the audit log.` : '',
      syncError
        ? `Local cache updated, but native SQLite sync failed: ${syncError}`
        : connected
          ? 'Validated records were written to the project SQLite registry.'
          : 'The Windows bridge is offline; validated records were cached for this project.'
    ].filter(Boolean).join('\n');

    return {
      imported: parsed.rows.length,
      rejected: parsed.rejected.length,
      warnings: parsed.warnings,
      message
    };
  };

  const handleExportEnterpriseAssetsCsv = () => {
    const assets = enterpriseAssetsRef.current;
    if (assets.length === 0) return;
    const csv = serializeAssetCsv(assets);
    const blob = new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `WinWiFi-Assets-${currentProjectIdRef.current}-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    const log = db.appendLog({
      level: 'INFO',
      source: 'ASSET_CSV',
      message: `Exported ${assets.length} enterprise asset record(s) to CSV. Formula-leading cells were neutralized.`,
    });
    setLogs(previous => [log, ...previous]);
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
    const projectId = currentProjectIdRef.current;
    const next = threatEngine.getIncidents().map(incident => ({
      ...incident,
      notes: [...(incident.notes || [])],
      evidenceIds: [...(incident.evidenceIds || [])]
    }));
    db.saveIncidents(next, projectId);
    setIncidents(next);
  };

  // Switching projects reloads every scoped entity so the dashboard never shows
  // a previous site's cases, evidence, or logs.
  const applyProjectWorkspace = (projectId: string, projectName?: string, scope?: EnterpriseScope) => {
    const savedAps = applyAnalystOverrides(
      db.getAccessPoints(projectId).filter(ap => ap.dataSourceOrigin !== 'TRAINING'),
      db.getAnalystOverrides(projectId));
    const savedIncidents = db.getIncidents(projectId) ?? [];
    const storedDirectory = db.getSiteDirectory(projectId);
    const localDirectory = ensureScopeInDirectory(storedDirectory, scope);
    if (localDirectory !== storedDirectory) db.saveSiteDirectory(localDirectory, projectId);
    siteDirectoryRef.current = localDirectory;
    setSiteDirectory(localDirectory);
    const localAssets = db.getEnterpriseAssets(projectId);
    enterpriseAssetsRef.current = localAssets;
    setEnterpriseAssets(localAssets);
    setAccessPoints(applyAssetsToAccessPoints(savedAps, localAssets));
    setIncidents(savedIncidents);
    threatEngine.setIncidents(savedIncidents);
    setEvidenceItems(db.getEvidenceItems(projectId));
    setLogs(db.getLogs(projectId));
    setPackets([]);
    setSelectedBssid(null);
    setInspectedBssid(null);
    setDataSourceProfile('OFFLINE');
    setActiveSourceLabel(savedAps.length
      ? `Saved snapshot (${savedAps.length} access points)`
      : 'No saved network data in this project');

    bridgeClient.setProject(projectId, projectName);
    if (bridgeClient.getState() !== 'CONNECTED') return;
    void bridgeClient.selectProject(projectId, projectName).then(async () => {
      if (currentProjectIdRef.current !== projectId) return;
      try {
        const nativeAps = await bridgeClient.getProjectAccessPoints(projectId);
        if (currentProjectIdRef.current === projectId && nativeAps.length > 0) {
          const resolved = applyAssetsToAccessPoints(
            applyAnalystOverrides(nativeAps, db.getAnalystOverrides(projectId)),
            enterpriseAssetsRef.current);
          setAccessPoints(resolved);
          db.saveAccessPoints(projectId, resolved);
          setActiveSourceLabel(`SQLite project snapshot (${resolved.length} access points)`);
        }
      } catch {
        // Keep the local snapshot already on screen when the bridge is unreachable.
      }
      await hydrateAssetsFromBridge(projectId).catch(() => {
        // The bridge may have dropped between the state check and the request.
      });
    }).catch(() => {
      // The bridge may have dropped between the state check and the request.
    });
  };

  // Create Project in SQLite
  const handleCreateProject = (newProj: AuditProject) => {
    const updated = [newProj, ...projects];
    setProjects(updated);
    db.saveProjects(updated);
    setCurrentProjectId(newProj.id);
    db.setCurrentProjectId(newProj.id);
    currentProjectIdRef.current = newProj.id;
    applyProjectWorkspace(newProj.id, newProj.name, newProj.scope);
    void bridgeClient.saveProject(newProj).catch(() => {
      // The local workspace is still usable while the native bridge is offline.
    });

    const log = db.appendLog({
      level: 'INFO',
      source: 'PROJECT_MGR',
      message: `Created SQLite project session: "${newProj.name}".`,
    }, newProj.id);
    setLogs((prev) => [log, ...prev]);
  };

  const handleRenameProject = (projectId: string, name: string) => {
    const updated = projects.map(project => project.id === projectId
      ? { ...project, name, updatedAt: new Date().toISOString() }
      : project);
    setProjects(updated);
    db.saveProjects(updated);
    const renamed = updated.find(project => project.id === projectId);
    if (renamed) {
      if (currentProjectIdRef.current === projectId) bridgeClient.setProject(projectId, name);
      void bridgeClient.saveProject(renamed).catch(() => {
        // Renaming is persisted locally first; the bridge syncs on reconnect.
      });
    }
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
      currentProjectIdRef.current = next.id;
      applyProjectWorkspace(next.id, next.name, next.scope);
    }
    const log = db.appendLog({ level: 'INFO', source: 'PROJECT_MGR', message: `Deleted project "${projects.find(project => project.id === projectId)?.name || projectId}" and its saved network observations.` });
    setLogs(previous => [log, ...previous]);
  };

  const handleAddEvidence = (incidentId: string, evidence: EvidenceItem) => {
    const projectId = currentProjectIdRef.current;
    const nextEvidence = [evidence, ...db.getEvidenceItems(projectId)];
    db.saveEvidenceItems(nextEvidence, projectId);
    setEvidenceItems(nextEvidence);
    const nextIncidents = threatEngine.getIncidents().map(incident => incident.id === incidentId
      ? { ...incident, evidenceIds: [...new Set([...(incident.evidenceIds || []), evidence.id])], updatedAt: new Date().toISOString() }
      : { ...incident, notes: [...(incident.notes || [])], evidenceIds: [...(incident.evidenceIds || [])] });
    threatEngine.setIncidents(nextIncidents);
    db.saveIncidents(nextIncidents, projectId);
    setIncidents(nextIncidents);
    const log = db.appendLog({ level: 'INFO', source: 'EVIDENCE', message: `Added evidence ${evidence.id} to incident ${incidentId}.` }, projectId);
    setLogs(previous => [log, ...previous]);
  };

  return (
    <div className={`min-h-screen flex flex-col font-sans transition-colors duration-200 ${
      isDarkMode ? 'bg-[#0b0d11] text-slate-100' : 'bg-[#eef0f6] text-slate-900'
    }`}>
      {showStartupReadiness && <StartupReadinessOverlay
        bridgeState={bridgeState}
        adapters={adapters}
        dataSourceProfile={dataSourceProfile}
        accessPointCount={accessPoints.length}
        error={bridgeNotice}
        onContinue={() => setShowStartupReadiness(false)}
      />}
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
            {rogueFindings.length > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-rose-500/20 text-rose-400 font-bold">
                {rogueFindings.length}
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
              {openIncidentCount}
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
            lastLiveDataAt={lastLiveDataAt}
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
                enterpriseAssets={enterpriseAssets}
                siteDirectory={siteDirectory}
                bridgeConnected={bridgeState === 'CONNECTED'}
                uiMode={uiMode}
                initialFilter={tabFilterParam}
                onSelectAP={(ap) => setSelectedBssid(ap.bssid)}
                onUpdateAP={handleUpdateAP}
                onSaveAsset={handleSaveEnterpriseAsset}
                onDeleteAsset={handleDeleteEnterpriseAsset}
                onImportAssetsCsv={handleImportEnterpriseAssetsCsv}
                onExportAssetsCsv={handleExportEnterpriseAssetsCsv}
                onManageScope={() => handleNavigate('settings')}
              />
            ) : (
              <NetworkDiscovery
                accessPoints={accessPoints}
                selectedBssid={selectedBssid}
                onSelectAp={(bssid) => {
                  // This callback is invoked only by NetworkDiscovery's Inspect button.
                  setSelectedBssid(bssid);
                  setInspectedBssid(bssid);
                }}
                onCaptureHandshake={handleCaptureHandshake}
                dataSourceProfile={dataSourceProfile}
                activeSourceLabel={activeSourceLabel}
                onOpenImport={() => setShowImportModal(true)}
                onLoadBenchmark={handleLoadBenchmark}
                onRefreshScan={handleRefreshScan}
                onOpenBridgeConfig={() => setShowBridgeModal(true)}
                isDarkMode={isDarkMode}
                connectedBssid={connectedBssid}
              />
            )}

            {/* Deep 802.11 Layer Inspection Panel */}
            {selectedAp && (
              <NetworkDetailPanel
                ap={selectedAp}
                onClose={() => setInspectedBssid(null)}
                onCaptureHandshake={handleCaptureHandshake}
                isDarkMode={isDarkMode}
                dataSourceProfile={dataSourceProfile}
                onOpenCaptureGuide={() => setShowArchitectureModal(true)}
                onOpenImport={() => setShowImportModal(true)}
                onConnect={handleAuthorizedConnect}
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
            incidents={incidents}
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
            enterpriseAssets={enterpriseAssets}
            siteDirectory={siteDirectory}
            dataSourceProfile={dataSourceProfile}
            onSwitchProject={(proj) => {
              setCurrentProjectId(proj.id);
              db.setCurrentProjectId(proj.id);
              currentProjectIdRef.current = proj.id;
              applyProjectWorkspace(proj.id, proj.name, proj.scope);
            }}
            onCreateProject={handleCreateProject}
            onRenameProject={handleRenameProject}
            onDeleteProject={handleDeleteProject}
            onSiteDirectoryChange={handleSiteDirectoryChange}
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
          bridgeStatus={bridgeStatus}
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

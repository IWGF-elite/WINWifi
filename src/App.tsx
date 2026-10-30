import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  AccessPoint, 
  ClientDevice,
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
  BridgeScanStatus,
  UIMode,
  IncidentRecord,
  EvidenceItem,
  SecurityChange,
  AnalystClassification,
  EnterpriseAssetRecord,
  EnterpriseScope,
  SiteRecord,
  MaintenanceApprovalRecord
} from './types';
import { WifiEngine } from './services/wifiEngine';
import { SqliteDatabaseService } from './services/storage';
import { PcapService, PcapParseResult } from './services/pcapParser';
import { ThreatEngine } from './services/threatEngine';
import { AppUpdateSnapshot, NativeBridgeClient } from './services/bridgeClient';
import {
  mapNativeFindingsToIncidents,
  reconcileLiveIncidents,
  countOpenIncidents
} from './services/incidentMapper';
import { mapStationClients } from './services/stationClientMapper';
import { isSuspiciousAccessPoint } from './services/threatMetrics';
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
import { downloadBlob } from './services/download';
import {
  approveMaintenance,
  createMaintenanceRequest,
  findActiveApproval,
  markApprovalUsed,
  rejectMaintenance,
  revokeMaintenance
} from './services/maintenanceApproval';
import { AuditAction, AuditChainState, appendAuditRecord, resetAuditChain } from './services/auditChain';
import {
  OperatorRole,
  can,
  normalizeOperatorRole,
  requireCapability,
  sanitizeOperatorName
} from './services/operatorRoles';
import {
  AlertRecord,
  acknowledgeAlert,
  evaluateAlerts,
  countAlertEligibleAccessPoints,
  reconcileAlerts,
  summarizeAlerts
} from './services/alerts';
import type { AssetImportSummary } from './components/EnterpriseRegistry';

// Components
import { TitleBar } from './components/TitleBar';
import { CommandCenterDashboard } from './components/CommandCenterDashboard';
import { AssetInventory } from './components/AssetInventory';
import { ClientObserver } from './components/ClientObserver';
import { ThreatCenter } from './components/ThreatCenter';
import { AlertsCenter } from './components/AlertsCenter';
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
import { NetworkDoctorPanel } from './components/NetworkDoctorPanel';
import { NetworkTimeMachinePanel } from './components/NetworkTimeMachinePanel';
import { WalkModePanel } from './components/WalkModePanel';
import { StartupReadinessOverlay } from './components/StartupReadinessOverlay';
import { BridgeErrorKind, bridgeStatusView, isEmbeddedDashboard } from './services/bridgeStatus';

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
  Radio,
  BellRing,
  Clock3,
  MapPin
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
  const [scannerState, setScannerState] = useState<string>('Idle');

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

  // Synthetic labs and offline snapshots are analysis material, not fresh
  // observations, so alerts are generated only from live scans and captures.
  useEffect(() => {
    const operational = dataSourceProfile === 'LIVE_WINDOWS' || dataSourceProfile === 'REAL_PCAP' || dataSourceProfile === 'REAL_NETSH';
    if (!operational || accessPoints.length === 0) return;
    const projectId = currentProjectIdRef.current;
    const result = reconcileAlerts(
      alertsRef.current,
      evaluateAlerts(accessPoints, enterpriseAssetsRef.current),
      new Date());
    if (result.added === 0 && result.resolved === 0 && result.updated === 0 && result.records.length === alertsRef.current.length) {
      return;
    }
    alertsRef.current = result.records;
    setAlerts(result.records);
    db.saveAlerts(result.records, projectId);
    if (result.added > 0 || result.resolved > 0) {
      const log = db.appendLog({
        level: result.added > 0 ? 'WARN' : 'INFO',
        source: 'ALERTS',
        message: `Alert reconciliation: ${result.added} new, ${result.resolved} resolved, ${result.updated} updated.`
      }, projectId);
      setLogs(previous => [log, ...previous]);
    }
  }, [accessPoints, enterpriseAssets, dataSourceProfile, db]);
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

  // Two-person, time-boxed approval for the only active action (network connect).
  const [maintenanceApprovals, setMaintenanceApprovals] = useState<MaintenanceApprovalRecord[]>(
    () => db.getMaintenanceApprovals(db.getCurrentProjectId()));
  const maintenanceApprovalsRef = useRef(maintenanceApprovals);
  useEffect(() => { maintenanceApprovalsRef.current = maintenanceApprovals; }, [maintenanceApprovals]);

  const [operatorName, setOperatorName] = useState<string>(
    () => localStorage.getItem('winwifi_operator_name') || 'Local operator');
  const operatorNameRef = useRef(operatorName);
  const [operatorRole, setOperatorRole] = useState<OperatorRole>(
    () => normalizeOperatorRole(localStorage.getItem('winwifi_operator_role')));
  const operatorRoleRef = useRef(operatorRole);
  useEffect(() => { operatorRoleRef.current = operatorRole; }, [operatorRole]);

  const [auditChain, setAuditChain] = useState<AuditChainState>(
    () => db.getAuditChain(db.getCurrentProjectId()));
  const auditChainRef = useRef(auditChain);
  useEffect(() => { auditChainRef.current = auditChain; }, [auditChain]);
  const [auditError, setAuditError] = useState('');

  const [alerts, setAlerts] = useState<AlertRecord[]>(() => db.getAlerts(db.getCurrentProjectId()));
  const alertsRef = useRef(alerts);
  useEffect(() => { alertsRef.current = alerts; }, [alerts]);

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
      // Older builds promoted every per-AP configuration issue into a case.
      // Those findings now stay on the access point; drop the duplicates.
      .filter(incident => !incident.id.startsWith('NATIVE-AP-'))
      .map(incident => ({ ...incident, notes: [...(incident.notes || [])], evidenceIds: [...(incident.evidenceIds || [])] }));
  });
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>(() => db.getEvidenceItems(db.getCurrentProjectId()));
  const [securityChanges, setSecurityChanges] = useState<SecurityChange[]>(() => threatEngine.getSecurityChanges());
  const [stationClients, setStationClients] = useState<ClientDevice[]>([]);

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
  // Shown until live data is flowing (then it dismisses itself) or until the
  // operator continues past it while the bridge is still reporting a problem.
  const [showStartupReadiness, setShowStartupReadiness] = useState<boolean>(true);
  const [startupHealthLoaded, setStartupHealthLoaded] = useState(false);
  const [startupAdaptersLoaded, setStartupAdaptersLoaded] = useState(false);
  const [startupScanStatusLoaded, setStartupScanStatusLoaded] = useState(false);
  const [startupNetworksLoaded, setStartupNetworksLoaded] = useState(false);
  const [startupSnapshotsLoaded, setStartupSnapshotsLoaded] = useState(false);
  const [startupLoadError, setStartupLoadError] = useState('');

  // Native Windows Bridge State
  const [bridgeState, setBridgeState] = useState<BridgeConnectionState>('DISCONNECTED');
  const [bridgeStatus, setBridgeStatus] = useState<BridgeHealthStatus | null>(null);
  const [appUpdateStatus, setAppUpdateStatus] = useState<AppUpdateSnapshot | null>(null);
  const [updatePromptDismissed, setUpdatePromptDismissed] = useState(false);
  const [networkViewMode, setNetworkViewMode] = useState<'inventory' | 'discovery'>('inventory');
  const [bridgeNotice, setBridgeNotice] = useState('');
  const [bridgeErrorKind, setBridgeErrorKind] = useState<BridgeErrorKind | null>(null);
  // The desktop shell serves this page and owns its own data connection, so the
  // bridge settings dialog — address, port, token — has nothing for a user to do.
  const embeddedShell = isEmbeddedDashboard();

  // Hide the readiness screen only after the real startup requests have
  // returned. An empty WLAN list is still a completed response, distinct from
  // a network request that has not completed yet.
  useEffect(() => {
    if (!showStartupReadiness) return;
    const startupDataReady = bridgeState === 'CONNECTED'
      && startupHealthLoaded
      && startupAdaptersLoaded
      && startupScanStatusLoaded
      && startupNetworksLoaded
      && startupSnapshotsLoaded;
    if (startupDataReady) setShowStartupReadiness(false);
  }, [showStartupReadiness, bridgeState, startupHealthLoaded, startupAdaptersLoaded, startupScanStatusLoaded, startupNetworksLoaded, startupSnapshotsLoaded]);

  // A Windows WLAN scan is periodic, not a continuous frame stream. Keep the
  // source labelled as live while the local bridge is connected; freshness is
  // shown separately by the toolbar badge. Previously this changed live data
  // to "OFFLINE" after 30 seconds even though the scanner was still running.

  const bridgeClient = NativeBridgeClient.getInstance();

  useEffect(() => {
    if (!embeddedShell || bridgeState !== 'CONNECTED') return;
    let active = true;
    const refreshUpdateStatus = async () => {
      try {
        const status = await bridgeClient.getAppUpdateStatus();
        if (active) setAppUpdateStatus(status);
      } catch { /* Update checks are best effort and never interrupt scanning. */ }
    };
    void refreshUpdateStatus();
    const timer = window.setInterval(() => void refreshUpdateStatus(), 1_000);
    return () => { active = false; window.clearInterval(timer); };
  }, [bridgeClient, bridgeState, embeddedShell]);

  const applyAppUpdate = async () => {
    try {
      const result = await bridgeClient.applyAppUpdate();
      if (!result.started) setBridgeNotice('The update could not be started. WinWiFi will keep running and retry on a later check.');
    } catch (error) {
      setBridgeNotice('The update could not be started. WinWiFi will continue running.');
    }
  };

  const deferAppUpdate = async () => {
    try {
      const result = await bridgeClient.deferAppUpdate();
      if (result.deferred) setUpdatePromptDismissed(true);
      else setBridgeNotice('The update could not be scheduled. WinWiFi will keep running normally.');
    } catch (error) {
      setBridgeNotice('The update could not be scheduled. WinWiFi will continue running.');
    }
  };

  const commitEnterpriseAssets = useCallback((next: EnterpriseAssetRecord[], projectId: string) => {
    enterpriseAssetsRef.current = next;
    setEnterpriseAssets(next);
    db.saveEnterpriseAssets(projectId, next);
  }, [db]);

  const commitMaintenanceApprovals = useCallback((next: MaintenanceApprovalRecord[], projectId: string) => {
    maintenanceApprovalsRef.current = next;
    setMaintenanceApprovals(next);
    db.saveMaintenanceApprovals(next, projectId);
  }, [db]);

  const commitAuditChain = useCallback((next: AuditChainState, projectId: string) => {
    auditChainRef.current = next;
    setAuditChain(next);
    db.saveAuditChain(next, projectId);
    setAuditError('');
  }, [db]);

  const recordAudit = useCallback((
    action: AuditAction,
    subject: string,
    details: string,
    projectId: string = currentProjectIdRef.current
  ): void => {
    const result = appendAuditRecord(
      auditChainRef.current,
      { action, subject, details },
      operatorNameRef.current,
      operatorRoleRef.current);
    if (result.error || !result.record) {
      setAuditError(result.error || 'The audit chain could not record this event.');
      return;
    }
    commitAuditChain(result.state, projectId);
  }, [commitAuditChain]);

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
  // Keep the incident engine aligned with the user's persisted incident records.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const applyScanStatus = (status: BridgeScanStatus) => {
      setIsScanning(Boolean(status.isScanning));
      if (status.state) setScannerState(status.state);
      setStartupScanStatusLoaded(true);
      setStartupLoadError('');
      const completedAt = status.lastScanCompletedAt ? Date.parse(status.lastScanCompletedAt) : NaN;
      if (Number.isFinite(completedAt)) {
        setLastLiveDataAt(current => current === null || completedAt > current ? completedAt : current);
      }
    };

    const unsubStatus = bridgeClient.onStateChange(async (state) => {
      setBridgeState(state);
      if (state === 'CONNECTED') {
        setBridgeNotice('');
        setBridgeErrorKind(null);
        setActiveSourceLabel('Windows bridge connected; waiting for WLAN observations');
        try {
          const health = await bridgeClient.checkHealth();
          setBridgeStatus(health);
          setStartupHealthLoaded(true);
          setIsScanning(health.isScanning ?? false);
          const scanStatus = await bridgeClient.getScanStatus().catch((error) => {
            setStartupLoadError(`Could not load scan status: ${error?.message || 'request failed'}`);
            return null;
          });
          if (scanStatus) applyScanStatus(scanStatus);
          setActiveSourceLabel(`Native Bridge (${health?.activeAdapterName || 'Hardware Adapter'})`);
          const detectedAdapters = await bridgeClient.getAdapters();
          setAdapters(detectedAdapters);
          setStartupAdaptersLoaded(true);
          const adapterId = detectedAdapters[0]?.id || '';
          setSelectedAdapterId(current => current || adapterId);
          const connection = await bridgeClient.getConnectionStatus(adapterId);
          setConnectedBssid(connection.state === 'Connected' ? connection.bssid : '');
          void hydrateAssetsFromBridge(currentProjectIdRef.current);
        } catch (error: any) {
          setStartupLoadError(`Could not finish loading Windows data: ${error?.message || 'request failed'}`);
          setActiveSourceLabel('Native Windows Bridge');
        }
      } else if (state === 'DISCONNECTED' || state === 'ERROR') {
        setLastLiveDataAt(null);
        setIsScanning(false);
        setScannerState(state === 'ERROR' ? 'Error' : 'Offline');
        if (dataSourceProfileRef.current === 'LIVE_WINDOWS') {
          setAccessPoints([]);
          setDataSourceProfile('OFFLINE');
        }
        if (state === 'ERROR') {
          setBridgeErrorKind(bridgeClient.getErrorKind());
          setBridgeNotice(bridgeClient.getLastError() || 'Could not connect to the local Windows bridge.');
        }
      }
    });

    const unsubNetworks = bridgeClient.onNetworks((liveAps) => {
      if (Array.isArray(liveAps)) {
        setStartupNetworksLoaded(true);
        const projectId = currentProjectIdRef.current;
        const resolvedAps = applyAssetsToAccessPoints(
          applyAnalystOverrides(liveAps, db.getAnalystOverrides(projectId)),
          enterpriseAssetsRef.current);
        setAccessPoints(resolvedAps);
        // The incidents listener runs in the same SSE frame, before React
        // re-renders, so the ref is updated here to keep analyst-case pruning
        // aligned with this scan. Incidents are owned by the incidents
        // listener only: reconciling them here with a placeholder empty
        // finding list erased every native incident on each poll tick.
        accessPointsRef.current = resolvedAps;
        db.saveAccessPoints(projectId, resolvedAps);
        setDataSourceProfile('LIVE_WINDOWS');
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

    // Configuration drift is detected natively against the analyzer's own scan
    // baseline. It was computed every cycle and then dropped, which left the
    // Security Change Intelligence panel permanently at zero.
    const unsubDrifts = bridgeClient.onDrifts((drifts) => {
      if (Array.isArray(drifts)) setSecurityChanges(drifts as SecurityChange[]);
    });

    // Station clients are the one surface the scan stream never carries: Windows
    // exposes BSS entries only, so these records come from dissected captures and
    // from the project database behind /api/clients. Subscribed before connect()
    // so the initial snapshot reaches it.
    const unsubClients = bridgeClient.onClients((clients) => {
      setStationClients(mapStationClients(clients));
    });
    const unsubScanStatus = bridgeClient.onScanStatus(applyScanStatus);

    // Establish the connection and start event/polling updates on mount.
    bridgeClient.setProject(currentProjectIdRef.current, projects.find(project => project.id === currentProjectIdRef.current)?.name);
    void bridgeClient.connect().then((connected) => {
      if (connected) {
        setStartupSnapshotsLoaded(true);
      } else {
        setStartupLoadError(bridgeClient.getLastError() || 'Could not load the initial dashboard data.');
      }
    });

    return () => {
      unsubStatus();
      unsubNetworks();
      unsubIncidents();
      unsubDrifts();
      unsubClients();
      unsubScanStatus();
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

  const rogueFindings = accessPoints.filter(isSuspiciousAccessPoint);
  const openIncidentCount = countOpenIncidents(incidents);
  const alertSummary = summarizeAlerts(alerts);

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
      setBridgeNotice('Refresh requires the local Windows bridge. Start the desktop app or import a capture file.');
      setShowBridgeModal(true);
      return;
    }
    try {
      const result = await bridgeClient.refreshScan(selectedAdapterId || undefined);
      const resolvedAps = applyAssetsToAccessPoints(
        applyAnalystOverrides(result.accessPoints, db.getAnalystOverrides(currentProjectId)),
        enterpriseAssetsRef.current);
      setAccessPoints(resolvedAps);
      setDataSourceProfile('LIVE_WINDOWS');
      setLastLiveDataAt(Date.now());
      setScannerState('Idle');
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

  const handleRequestMaintenance = async (
    ap: AccessPoint,
    requester: string,
    justification: string,
    durationMinutes: number
  ): Promise<void> => {
    requireCapability(operatorRoleRef.current, 'request_maintenance', 'Requesting maintenance approval');
    const projectId = currentProjectIdRef.current;
    const result = createMaintenanceRequest(maintenanceApprovalsRef.current, {
      action: 'Connect to network',
      bssid: ap.bssid,
      ssid: ap.ssid,
      adapterId: selectedAdapterId,
      requester,
      justification,
      durationMinutes
    });
    if (result.error || !result.record) {
      throw new Error(result.error || 'The maintenance request could not be created.');
    }
    commitMaintenanceApprovals(result.records, projectId);
    recordAudit('MAINTENANCE_REQUEST', `${result.record.ssid || '[hidden network]'} (${result.record.bssid})`, `Request ${result.record.id} by ${result.record.requester}; window ends ${result.record.expiresAt}.`, projectId);
    const log = db.appendLog({
      level: 'INFO',
      source: 'MAINTENANCE',
      message: `Maintenance request ${result.record.id} created for ${result.record.ssid || '[hidden network]'} (${result.record.bssid}); pending approval by a different analyst until ${new Date(result.record.expiresAt).toLocaleString()}.`,
    }, projectId);
    setLogs(previous => [log, ...previous]);
  };

  const handleApproveMaintenance = async (id: string, approver: string): Promise<void> => {
    requireCapability(operatorRoleRef.current, 'approve_maintenance', 'Approving maintenance requests');
    const projectId = currentProjectIdRef.current;
    const result = approveMaintenance(maintenanceApprovalsRef.current, id, approver);
    if (result.error || !result.record) {
      throw new Error(result.error || 'The maintenance approval could not be recorded.');
    }
    commitMaintenanceApprovals(result.records, projectId);
    recordAudit('MAINTENANCE_APPROVE', `${result.record.ssid || '[hidden network]'} (${result.record.bssid})`, `Request ${id} approved by ${result.record.approver}; expires ${result.record.expiresAt}.`, projectId);
    const log = db.appendLog({
      level: 'SUCCESS',
      source: 'MAINTENANCE',
      message: `Maintenance request ${id} approved by ${result.record.approver} for ${result.record.ssid || '[hidden network]'} (${result.record.bssid}); connect allowed until ${new Date(result.record.expiresAt).toLocaleString()}.`,
    }, projectId);
    setLogs(previous => [log, ...previous]);
  };

  const handleRejectMaintenance = async (id: string, approver: string, note: string): Promise<void> => {
    requireCapability(operatorRoleRef.current, 'approve_maintenance', 'Rejecting maintenance requests');
    const projectId = currentProjectIdRef.current;
    const result = rejectMaintenance(maintenanceApprovalsRef.current, id, approver, note);
    if (result.error || !result.record) {
      throw new Error(result.error || 'The maintenance rejection could not be recorded.');
    }
    commitMaintenanceApprovals(result.records, projectId);
    recordAudit('MAINTENANCE_REJECT', `${result.record.ssid || '[hidden network]'} (${result.record.bssid})`, `Request ${id} rejected by ${result.record.approver}${result.record.decisionNote ? `: ${result.record.decisionNote}` : '.'}`, projectId);
    const log = db.appendLog({
      level: 'WARN',
      source: 'MAINTENANCE',
      message: `Maintenance request ${id} rejected by ${result.record.approver}${result.record.decisionNote ? `: ${result.record.decisionNote}` : '.'}`,
    }, projectId);
    setLogs(previous => [log, ...previous]);
  };

  const handleRevokeMaintenance = async (id: string): Promise<void> => {
    requireCapability(operatorRoleRef.current, 'approve_maintenance', 'Revoking maintenance approvals');
    const projectId = currentProjectIdRef.current;
    const result = revokeMaintenance(maintenanceApprovalsRef.current, id);
    if (result.error || !result.record) {
      throw new Error(result.error || 'The maintenance approval could not be revoked.');
    }
    commitMaintenanceApprovals(result.records, projectId);
    recordAudit('MAINTENANCE_REVOKE', `${result.record.ssid || '[hidden network]'} (${result.record.bssid})`, `Request ${id} was revoked.`, projectId);
    const log = db.appendLog({
      level: 'WARN',
      source: 'MAINTENANCE',
      message: `Maintenance request ${id} was revoked; further connect attempts for ${result.record.bssid} require a new approval.`,
    }, projectId);
    setLogs(previous => [log, ...previous]);
  };

  const handleAuthorizedConnect = async (ap: AccessPoint, password: string, confirmed: boolean): Promise<string> => {
    requireCapability(operatorRoleRef.current, 'connect_network', 'Connecting this PC to a network');
    if (bridgeClient.getState() !== 'CONNECTED') throw new Error('Windows bridge is not connected.');
    if (!confirmed) throw new Error('Connection blocked: confirm that you own or are authorized to test this network.');
    const approval = findActiveApproval(maintenanceApprovalsRef.current, ap.bssid);
    if (!approval) {
      recordAudit('CONNECT_ATTEMPT', `${ap.ssid || '[hidden network]'} (${ap.bssid})`, 'Blocked: no active maintenance approval.');
      throw new Error('Connection blocked: this BSSID has no active maintenance approval. Request one in the inspection panel and have a different analyst approve it.');
    }
    const result = await bridgeClient.connectAuthorizedNetwork({
      adapterId: selectedAdapterId,
      bssid: ap.bssid,
      ssid: ap.ssid,
      password: password || undefined,
      authorizationConfirmed: confirmed,
      authorizedBssids: confirmed ? [ap.bssid] : []
    });
    if (result.state === 'Connected') setConnectedBssid(result.bssid);
    const used = markApprovalUsed(maintenanceApprovalsRef.current, approval.id);
    if (!used.error) commitMaintenanceApprovals(used.records, currentProjectIdRef.current);
    recordAudit('CONNECT_ATTEMPT', `${ap.ssid || '[hidden network]'} (${ap.bssid})`, `${result.state}: ${result.reason} Approval ${approval.id} by ${approval.approver}.`);
    const log = db.appendLog({
      level: result.state === 'Failed' ? 'ERROR' : 'INFO',
      source: 'WLAN_CONNECT',
      message: `${result.state}: ${result.ssid || ap.ssid}. ${result.reason} Approval ${approval.id} (approved by ${approval.approver}).`,
    });
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
    setStationClients(mapStationClients(native.clients));
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

  // Handshake records are populated from imported capture bytes only.
  const handleCaptureHandshake = useCallback((ap: AccessPoint) => {
    if (dataSourceProfile === 'LIVE_WINDOWS' || dataSourceProfile === 'REAL_NETSH' || dataSourceProfile === 'REAL_PCAP') {
      const log = db.appendLog({
        level: 'WARN',
        source: 'HANDSHAKE_VALIDATOR',
        message: `Live handshake capture is unavailable for "${ap.ssid}" (${ap.bssid}). Import an authorized 802.11 capture to inspect EAPOL frames.`,
      });
      setLogs((prev) => [log, ...prev]);
      setShowArchitectureModal(true);
      return;
    }

    const log = db.appendLog({
      level: 'WARN',
      source: 'HANDSHAKE_VALIDATOR',
      message: `No imported handshake capture is available for "${ap.ssid}" (${ap.bssid}).`,
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
    if (!can(operatorRoleRef.current, 'manage_sites')) {
      setAuditError('Editing the site directory is not allowed by the current local role.');
      return;
    }
    const projectId = currentProjectIdRef.current;
    siteDirectoryRef.current = sites;
    setSiteDirectory(sites);
    db.saveSiteDirectory(sites, projectId);
    recordAudit('SITE_DIRECTORY', 'Site directory updated', `${sites.length} site(s) saved; ${changedAssets.length} registry location record(s) updated.`, projectId);

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
  }, [bridgeClient, commitEnterpriseAssets, db, recordAudit]);

  const handleSaveEnterpriseAsset = async (asset: EnterpriseAssetRecord) => {
    requireCapability(operatorRoleRef.current, 'edit_assets', 'Editing registry assets');
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

    recordAudit('ASSET_SAVE', `${asset.macAddress} (${asset.classification} / ${asset.approvalStatus})`, syncError ? `Saved locally; native sync failed: ${syncError}` : 'Saved to the project registry.', projectId);

    if (syncError) {
      throw new Error(`Saved to the local project cache, but native SQLite sync failed: ${syncError}`);
    }
  };

  const handleDeleteEnterpriseAsset = async (macAddress: string) => {
    requireCapability(operatorRoleRef.current, 'delete_assets', 'Deleting registry assets');
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

    recordAudit('ASSET_DELETE', mac, syncError ? `Removed locally; native delete failed: ${syncError}` : 'Removed from the project registry; evidence untouched.', projectId);

    if (syncError) {
      throw new Error(`Removed from the local project cache, but native SQLite delete failed: ${syncError}`);
    }
  };

  const handleImportEnterpriseAssetsCsv = async (csv: string): Promise<AssetImportSummary> => {
    requireCapability(operatorRoleRef.current, 'import_assets', 'Importing asset CSV');
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

    recordAudit(
      'ASSET_IMPORT',
      `${parsed.rows.length} valid asset row(s)`,
      `${parsed.rejected.length} rejected; ${syncError ? `native sync failed: ${syncError}` : connected ? 'written to project SQLite.' : 'cached locally; bridge offline.'}`,
      projectId);

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
    if (!can(operatorRoleRef.current, 'export_report')) {
      setAuditError('Exporting the asset registry is not allowed by the current local role.');
      return;
    }
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
    recordAudit('ASSET_EXPORT', `${assets.length} asset record(s)`, 'Exported the registry to CSV; formula-leading cells were neutralized.');
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
    const localApprovals = db.getMaintenanceApprovals(projectId);
    maintenanceApprovalsRef.current = localApprovals;
    setMaintenanceApprovals(localApprovals);
    const localAudit = db.getAuditChain(projectId);
    auditChainRef.current = localAudit;
    setAuditChain(localAudit);
    setAuditError('');
    const localAlerts = db.getAlerts(projectId);
    alertsRef.current = localAlerts;
    setAlerts(localAlerts);
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
    if (!can(operatorRoleRef.current, 'manage_projects')) {
      setAuditError('Creating projects is not allowed by the current local role.');
      return;
    }
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
    recordAudit('PROJECT_CREATE', newProj.name, `Created project workspace ${newProj.id}.`, newProj.id);
  };

  const handleRenameProject = (projectId: string, name: string) => {
    if (!can(operatorRoleRef.current, 'manage_projects')) {
      setAuditError('Renaming projects is not allowed by the current local role.');
      return;
    }
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
    recordAudit('PROJECT_RENAME', name, `Renamed project ${projectId} to "${name}".`);
  };

  const handleDeleteProject = (projectId: string) => {
    if (!can(operatorRoleRef.current, 'manage_projects')) {
      setAuditError('Deleting projects is not allowed by the current local role.');
      return;
    }
    if (projects.length <= 1) return;
    const deletedName = projects.find(project => project.id === projectId)?.name || projectId;
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
    const log = db.appendLog({ level: 'INFO', source: 'PROJECT_MGR', message: `Deleted project "${deletedName}" and its saved network observations.` });
    setLogs(previous => [log, ...previous]);
    recordAudit('PROJECT_DELETE', deletedName, `Deleted project ${projectId} and its scoped workspace, including its audit chain.`);
  };

  const handleOperatorNameChange = (name: string) => {
    const next = name.slice(0, 80);
    operatorNameRef.current = next;
    setOperatorName(next);
    localStorage.setItem('winwifi_operator_name', next);
  };

  const handleOperatorRoleChange = (role: OperatorRole) => {
    const previous = operatorRoleRef.current;
    if (role === previous) return;
    operatorRoleRef.current = role;
    setOperatorRole(role);
    localStorage.setItem('winwifi_operator_role', role);
    recordAudit(
      'ROLE_CHANGE',
      `Local role: ${role}`,
      `Changed from ${previous} to ${role} for ${sanitizeOperatorName(operatorNameRef.current)}. This is a local guardrail, not authentication.`);
  };

  const handleExportAuditChain = async (): Promise<void> => {
    requireCapability(operatorRoleRef.current, 'export_report', 'Exporting the audit chain');
    const before = auditChainRef.current;
    recordAudit('AUDIT_EXPORT', 'Audit chain export', `Exported ${before.records.length} record(s); head ${before.records[before.records.length - 1]?.hash || 'genesis'}.`);
    const chain = auditChainRef.current;
    const blob = new Blob([JSON.stringify(chain, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `winwifi-audit-${currentProjectIdRef.current}-${new Date().toISOString().slice(0, 10)}.json`);
  };

  const handleResetAuditChain = async (): Promise<void> => {
    requireCapability(operatorRoleRef.current, 'manage_roles', 'Starting a new audit chain');
    const next = resetAuditChain(
      auditChainRef.current,
      sanitizeOperatorName(operatorNameRef.current),
      operatorRoleRef.current);
    commitAuditChain(next, currentProjectIdRef.current);
  };

  const handleAcknowledgeAlert = async (id: string): Promise<void> => {
    requireCapability(operatorRoleRef.current, 'manage_alerts', 'Acknowledging alerts');
    const projectId = currentProjectIdRef.current;
    const result = acknowledgeAlert(alertsRef.current, id, sanitizeOperatorName(operatorNameRef.current));
    if (result.error || !result.record) {
      throw new Error(result.error || 'The alert could not be acknowledged.');
    }
    alertsRef.current = result.records;
    setAlerts(result.records);
    db.saveAlerts(result.records, projectId);
    recordAudit('ALERT_ACK', `${result.record.title} · ${result.record.bssid}`, `Alert ${id} acknowledged by ${result.record.acknowledgedBy}.`, projectId);
    const log = db.appendLog({
      level: 'INFO',
      source: 'ALERTS',
      message: `Alert ${id} (${result.record.severity}) acknowledged by ${result.record.acknowledgedBy} for ${result.record.ssid || '[hidden network]'} (${result.record.bssid}).`,
    }, projectId);
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
    }`}>      {showStartupReadiness && <StartupReadinessOverlay
        bridgeState={bridgeState}
        adapters={adapters}
        healthLoaded={startupHealthLoaded}
        adaptersLoaded={startupAdaptersLoaded}
        scanStatusLoaded={startupScanStatusLoaded}
        networksLoaded={startupNetworksLoaded}
        snapshotsLoaded={startupSnapshotsLoaded}
        dataSourceProfile={dataSourceProfile}
        accessPointCount={accessPoints.length}
        error={startupLoadError || bridgeNotice}
        errorKind={bridgeErrorKind}
        onRetry={() => void bridgeClient.retryNow()}
        onContinue={() => setShowStartupReadiness(false)}
      />}
      {/* Windows Native Title & Action Bar */}
      <TitleBar
        isDarkMode={isDarkMode}
        onToggleDarkMode={handleToggleDarkMode}
        dataSourceProfile={dataSourceProfile}
        hasFreshLiveData={bridgeState === 'CONNECTED' && dataSourceProfile === 'LIVE_WINDOWS' && lastLiveDataAt !== null}
        scannerState={scannerState}
        lastScanCompletedAt={lastLiveDataAt}
        activeSourceLabel={activeSourceLabel}
        isScanning={isScanning}
        onToggleScan={handleToggleScan}
        onRefreshScan={handleRefreshScan}
        bridgeState={bridgeState}
        bridgeErrorKind={bridgeErrorKind}
        onOpenBridgeConfig={embeddedShell ? undefined : () => setShowBridgeModal(true)}
        projectName={currentProject.name}
        onOpenReport={() => setShowReportModal(true)}
        onOpenSelfTest={() => setShowSelfTestModal(true)}
        onOpenImport={() => setShowImportModal(true)}
        onOpenArchitecture={() => setShowArchitectureModal(true)}
        adapters={adapters}
        selectedAdapterId={selectedAdapterId}
        onSelectAdapter={setSelectedAdapterId}
        onToggleFullscreen={handleToggleFullscreen}
        updateStatus={appUpdateStatus}
        updatePromptDismissed={updatePromptDismissed}
        onApplyUpdate={() => void applyAppUpdate()}
        onDeferUpdate={() => void deferAppUpdate()}
      />

      {bridgeNotice && (() => {
        const view = bridgeStatusView(bridgeState, bridgeErrorKind);
        const isBridgeFailure = bridgeState === 'ERROR';
        return (
          <div
            role="status"
            className={`flex items-start justify-between gap-4 border-b px-4 py-2 text-xs ${
              isBridgeFailure
                ? view.tone === 'bad'
                  ? 'border-rose-500/30 bg-rose-500/10 text-rose-200'
                  : 'border-amber-500/30 bg-amber-500/10 text-amber-100'
                : 'border-blue-500/30 bg-blue-500/10 text-blue-100'
            }`}
          >
            <div className="min-w-0">
              <p className="font-semibold">{isBridgeFailure ? `${view.title}.` : 'Bridge notice'}</p>
              <p className="mt-0.5 leading-relaxed">{isBridgeFailure ? view.description : bridgeNotice}</p>
              {isBridgeFailure && (
                <p className="mt-1 text-[11px] opacity-70">
                  Retrying automatically every few seconds.{' '}
                  <button
                    onClick={() => void bridgeClient.retryNow()}
                    className="underline underline-offset-2 hover:text-white"
                  >
                    Retry now
                  </button>
                </p>
              )}
            </div>
            <button onClick={() => setBridgeNotice('')} className="shrink-0 rounded px-2 py-1 text-slate-300 hover:bg-white/10" aria-label="Dismiss message">Dismiss</button>
          </div>
        );
      })()}

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
            <span>Network Inventory</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
              {accessPoints.length}
            </span>
          </button>

          <button
            onClick={() => handleNavigate('doctor')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'doctor'
                ? 'border-cyan-500 text-cyan-300 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Network Diagnostics</span>
          </button>

          <button
            onClick={() => handleNavigate('time-machine')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'time-machine'
                ? 'border-cyan-500 text-cyan-300 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock3 className="w-3.5 h-3.5" />
            <span>Scan History</span>
          </button>

          <button
            onClick={() => handleNavigate('walk-mode')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'walk-mode'
                ? 'border-cyan-500 text-cyan-300 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <MapPin className="w-3.5 h-3.5" />
            <span>Signal Survey</span>
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
            <span>Client Devices</span>
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
            <span>Spectrum Analysis</span>
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
            <span>Threat Detection</span>
            {rogueFindings.length > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-rose-500/20 text-rose-400 font-bold">
                {rogueFindings.length}
              </span>
            )}
          </button>

          {/* TAB 6: Local Operations Alerts */}
          <button
            onClick={() => handleNavigate('alerts')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'alerts'
                ? 'border-amber-500 text-amber-400 bg-amber-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <BellRing className="w-3.5 h-3.5" />
            <span>Security Alerts</span>
            {alertSummary.active > 0 && (
              <span className={`ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-bold ${
                alertSummary.critical > 0 ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400'
              }`}>
                {alertSummary.active}
              </span>
            )}
          </button>

          {/* TAB 7: Investigations */}
          <button
            onClick={() => handleNavigate('investigations')}
            className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === 'investigations'
                ? 'border-purple-500 text-purple-400 bg-purple-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Incident Management</span>
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
            <span>Packet Analysis</span>
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
            <span>Handshake Analysis</span>
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
            <span>Projects &amp; Authorization</span>
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
            <span>Hardware &amp; Capabilities</span>
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
            <span>Settings &amp; Test Lab</span>
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
            <span>System Capabilities</span>
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
            dataSourceProfile={dataSourceProfile}
            bridgeState={bridgeState}
            lastLiveDataAt={lastLiveDataAt}
            onOpenBridgeConfig={embeddedShell ? undefined : () => setShowBridgeModal(true)}
            onOpenImport={() => setShowImportModal(true)}
            onNavigate={handleNavigate}
            onSelectAP={(ap) => {
              setSelectedBssid(ap.bssid);
              handleNavigate('networks');
            }}
          />

        )}

        {activeTab === 'doctor' && (
          <NetworkDoctorPanel
            adapterId={selectedAdapterId}
            bridgeConnected={bridgeState === 'CONNECTED'}
            isDarkMode={isDarkMode}
          />
        )}

        {activeTab === 'time-machine' && <NetworkTimeMachinePanel bridgeConnected={bridgeState === 'CONNECTED'} />}
        {activeTab === 'walk-mode' && <WalkModePanel accessPoints={accessPoints} bridgeConnected={bridgeState === 'CONNECTED'} />}

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
                onRefreshScan={handleRefreshScan}
                onOpenBridgeConfig={embeddedShell ? undefined : () => setShowBridgeModal(true)}
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
                maintenanceApprovals={maintenanceApprovals}
                onRequestMaintenance={handleRequestMaintenance}
                onApproveMaintenance={handleApproveMaintenance}
                canRequestMaintenance={can(operatorRole, 'request_maintenance')}
                canApproveMaintenance={can(operatorRole, 'approve_maintenance')}
                canConnect={can(operatorRole, 'connect_network')}
              />
            )}
          </div>
        )}

        {/* TAB 3: Client Observer */}
        {activeTab === 'clients' && (
          <ClientObserver
            accessPoints={accessPoints}
            stationClients={stationClients}
            uiMode={uiMode}
            dataSourceProfile={dataSourceProfile}
            selectedAdapterId={selectedAdapterId}
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

        {/* TAB 6: Local Operations Alerts */}
        {activeTab === 'alerts' && (
          <AlertsCenter
            alerts={alerts}
            openInvestigationsCount={countOpenIncidents(incidents)}
            operatorName={operatorName}
            canAcknowledge={can(operatorRole, 'manage_alerts')}
            liveObservationCount={dataSourceProfile === 'LIVE_WINDOWS' ? accessPoints.length : 0}
            alertEligibleObservationCount={countAlertEligibleAccessPoints(accessPoints, enterpriseAssets)}
            onAcknowledge={handleAcknowledgeAlert}
          />
        )}

        {/* TAB 7: Investigations */}
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
            onOpenBridgeConfig={embeddedShell ? undefined : () => setShowBridgeModal(true)}
            onOpenImport={() => setShowImportModal(true)}
          />
        )}

        {/* TAB 12: Settings & Lab */}
        {activeTab === 'settings' && (
          <SettingsAndLab
            uiMode={uiMode}
            accessPoints={accessPoints}
            onToggleUIMode={handleToggleUIMode}
            maintenanceApprovals={maintenanceApprovals}
            onApproveMaintenance={handleApproveMaintenance}
            onRejectMaintenance={handleRejectMaintenance}
            onRevokeMaintenance={handleRevokeMaintenance}
            auditChain={auditChain}
            operatorName={operatorName}
            operatorRole={operatorRole}
            onOperatorNameChange={handleOperatorNameChange}
            onOperatorRoleChange={handleOperatorRoleChange}
            onExportAudit={handleExportAuditChain}
            onResetAudit={handleResetAuditChain}
            auditError={auditError}
          />
        )}

        {/* TAB 13: Native .NET 8 WPF Desktop */}
        {activeTab === 'native-desktop' && (
          <NativeDesktopPanel isDarkMode={isDarkMode} />
        )}

        {/* Real-time Diagnostics & Auditing Logs Console */}
        <LogConsole
          logs={logs}
          canClearLogs={can(operatorRole, 'clear_logs')}
          onClearLogs={() => {
            if (!can(operatorRoleRef.current, 'clear_logs')) {
              setAuditError('Clearing diagnostic logs is not allowed by the current local role.');
              return;
            }
            recordAudit('LOG_CLEAR', 'Diagnostic logs cleared', `${logs.length} log entr${logs.length === 1 ? 'y' : 'ies'} removed; the audit chain was retained.`);
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
          dataSourceProfile={dataSourceProfile}
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
          currentProfile={dataSourceProfile}
          isDarkMode={isDarkMode}
        />
      )}

      {/* Windows Native Bridge Configuration Modal */}
      {showBridgeModal && !embeddedShell && (
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

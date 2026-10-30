import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Radio, 
  AlertTriangle, 
  Flame, 
  Cpu, 
  Activity, 
  ArrowUpRight, 
  Layers, 
  CheckCircle2, 
  Sparkles,
  ArrowRight
} from 'lucide-react';
import { 
  AccessPoint, 
  IncidentRecord, 
  SecurityChange, 
  UIMode, 
  ActiveTab,
  DataSourceProfile,
  BridgeConnectionState 
} from '../types';
import { countOpenIncidents } from '../services/incidentMapper';
import { countSuspiciousAccessPoints } from '../services/threatMetrics';
import { useScanActive } from '../contexts/ScanActivityContext';
import { ProcessingOrb } from './ProcessingOrb';

interface CommandCenterDashboardProps {
  accessPoints: AccessPoint[];
  incidents: IncidentRecord[];
  securityChanges: SecurityChange[];
  uiMode: UIMode;
  dataSourceProfile?: DataSourceProfile;
  bridgeState?: BridgeConnectionState;
  lastLiveDataAt?: number | null;
  onOpenBridgeConfig?: () => void;
  onOpenImport?: () => void;
  onNavigate: (tab: ActiveTab, filterParam?: string) => void;
  onSelectAP: (ap: AccessPoint) => void;
}

export const CommandCenterDashboard: React.FC<CommandCenterDashboardProps> = ({
  accessPoints = [],
  incidents = [],
  securityChanges = [],
  uiMode,
  dataSourceProfile = 'OFFLINE',
  bridgeState = 'DISCONNECTED',
  lastLiveDataAt = null,
  onOpenBridgeConfig,
  onOpenImport,
  onNavigate,
  onSelectAP
}) => {
  const isScanning = useScanActive();
  // Calculations
  const totalNetworks = accessPoints.length;
  const hasNetworkData = totalNetworks > 0;
  const approvedNetworks = accessPoints.filter(a => a.approvedStatus === 'Approved').length;
  const unknownNetworks = accessPoints.filter(a => a.approvedStatus === 'Pending Review' || a.approvedStatus === 'Unapproved' || !a.approvedStatus).length;
  const rogueNetworks = countSuspiciousAccessPoints(accessPoints);

  const criticalIssuesCount = accessPoints.reduce((acc, ap) => acc + (ap.issues || []).filter(i => i.severity === 'CRITICAL').length, 0);
  const highIssuesCount = accessPoints.reduce((acc, ap) => acc + (ap.issues || []).filter(i => i.severity === 'HIGH').length, 0);

  const avgSecurityScore = hasNetworkData
    ? Math.round(accessPoints.reduce((sum, ap) => sum + (ap.securityScore ?? 100), 0) / totalNetworks)
    : null;

  const openIncidents = countOpenIncidents(incidents || []);

  // Band counts
  const band24Count = accessPoints.filter(a => a.band === '2.4 GHz').length;
  const band5Count = accessPoints.filter(a => a.band === '5 GHz').length;
  const band6Count = accessPoints.filter(a => a.band === '6 GHz').length;

  // Channel distribution
  const channelCounts = accessPoints.reduce((acc: { [ch: number]: number }, ap) => {
    acc[ap.channel] = (acc[ap.channel] || 0) + 1;
    return acc;
  }, {});
  const topChannels = Object.entries(channelCounts)
    .sort((a, b) => (b[1] as number) - (a[1] as number))
    .slice(0, 6);

  const postureLabel = avgSecurityScore === null ? 'Awaiting observations' : avgSecurityScore >= 80 ? 'Resilient posture' : avgSecurityScore >= 60 ? 'Needs hardening' : 'Priority remediation';
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (lastLiveDataAt === null) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [lastLiveDataAt]);
  const liveAge = lastLiveDataAt === null ? null : Math.max(0, Math.floor((now - lastLiveDataAt) / 1000));
  const recentChanges = [...securityChanges]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 4);

  // Attention Items
  const attentionItems = [
    ...(unknownNetworks > 0 ? [{
      id: 'att-scope-review',
      title: `${unknownNetworks} Observed Networks Await Scope Review`,
      desc: 'Confirm ownership and authorization in Projects & Authorization before using scoped audit actions.',
      severity: 'MEDIUM',
      tab: 'projects' as ActiveTab,
      targetFilter: 'pending'
    }] : []),
    ...(rogueNetworks > 0 ? [{
      id: 'att-rogue',
      title: `${rogueNetworks} Suspected Rogue / Evil Twin APs Active`,
      desc: 'Unauthorized APs detected cloning corporate SSIDs or broadcasting downgraded ciphers.',
      severity: 'CRITICAL',
      tab: 'threats' as ActiveTab,
      targetFilter: 'rogue'
    }] : []),
    ...(criticalIssuesCount > 0 ? [{
      id: 'att-crit',
      title: `${criticalIssuesCount} Critical Wireless Vulnerabilities Flagged`,
      desc: 'Includes legacy WEP-128 encryption, broken authentication, or unencrypted cleartext corporate SSIDs.',
      severity: 'CRITICAL',
      tab: 'networks' as ActiveTab,
      targetFilter: 'critical'
    }] : []),
    ...(openIncidents > 0 ? [{
      id: 'att-inc',
      title: `${openIncidents} Active Security Investigations In Progress`,
      desc: 'Security incidents require auditor review, classification, and remediation sign-off.',
      severity: 'HIGH',
      tab: 'investigations' as ActiveTab,
      targetFilter: 'open'
    }] : []),
    ...((securityChanges?.length || 0) > 0 ? [{
      id: 'att-chg',
      title: `${securityChanges.length} Dynamic Wireless Changes Logged`,
      desc: 'Includes observed channel shifts, cipher modifications, and newly broadcasting transmitters.',
      severity: 'MEDIUM',
      tab: 'threats' as ActiveTab,
      targetFilter: 'changes'
    }] : [])
  ];

  return (
    <div className="space-y-6 pb-8">
      {/* Top Banner: Status & Health */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`w-14 h-14 rounded-2xl flex items-center justify-center font-bold text-2xl shadow-inner ${
              avgSecurityScore === null
                ? 'bg-slate-500/15 text-slate-300 border border-slate-500/30'
                : avgSecurityScore >= 80
                ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' 
                : avgSecurityScore >= 60 
                  ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' 
                  : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
            }`}>
              {avgSecurityScore ?? '—'}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-slate-100">Wireless Security Command Center</h1>
                <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded ${
                  avgSecurityScore === null ? 'bg-slate-500/20 text-slate-300' : avgSecurityScore >= 80 ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
                }`}>
                  {avgSecurityScore === null ? 'NO DATA' : avgSecurityScore >= 80 ? 'HEALTHY POSTURE' : 'ACTION REQUIRED'}
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-0.5">
                {!hasNetworkData
                  ? 'No network observations are loaded. Start a Windows WLAN scan or import a capture.'
                  : uiMode === 'beginner'
                  ? 'Overall security score based on encryption safety, rogue threats, and router settings.' 
                  : 'NIST SP 800-153 compliance posture across enumerated 802.11 physical transmitters and BSSIDs.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="px-3 py-2 rounded-lg bg-slate-800/80 border border-slate-700/60 text-xs">
              <div className="text-slate-400 flex items-center gap-1.5 font-medium">
                <Radio className="w-3.5 h-3.5 text-blue-400" />
                {dataSourceProfile === 'LIVE_WINDOWS' ? 'Windows WLAN Scan' : dataSourceProfile === 'REAL_PCAP' ? 'Capture Import' : dataSourceProfile === 'REAL_NETSH' ? 'Netsh Import' : 'No live observation'}
              </div>
              <div className="text-slate-200 font-bold mt-0.5">
                {dataSourceProfile === 'LIVE_WINDOWS'
                  ? (isScanning ? 'Windows WLAN Discovery' : 'Scan Paused')
                  : dataSourceProfile === 'REAL_PCAP'
                    ? 'Capture Ingested'
                    : dataSourceProfile === 'REAL_NETSH' ? 'Imported snapshot' : 'Waiting for data'}
              </div>
            </div>

            <button
              onClick={onOpenBridgeConfig}
              className={`px-3 py-2 rounded-lg border text-xs text-left transition-colors cursor-pointer ${
                bridgeState === 'CONNECTED'
                  ? 'bg-slate-800/80 border-slate-600/70 text-slate-200 hover:bg-slate-700/80'
                  : 'bg-slate-800/80 border-slate-700/60 text-slate-300 hover:bg-slate-700/50'
              }`}
              title="Click to configure Windows Native Bridge"
            >
              <div className="text-slate-400 flex items-center gap-1.5 font-medium">
                <Cpu className="w-3.5 h-3.5 text-slate-300" />
                Windows Bridge
              </div>
              <div className="font-bold mt-0.5 flex items-center gap-1.5">
                {bridgeState === 'CONNECTING' ? <ProcessingOrb state="connecting" size={20} label="Connecting to the Windows bridge" /> : <span className={`w-2 h-2 rounded-full ${
                  bridgeState === 'CONNECTED' ? 'bg-slate-300' : 'bg-slate-500'
                }`} />}
                <span>{bridgeState}</span>
              </div>
            </button>
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
        {/* Total Discovered */}
        <div 
          onClick={() => onNavigate('discover')}
          className="bg-slate-900/90 border border-slate-800 hover:border-blue-500/40 p-4 rounded-xl cursor-pointer transition-all hover:bg-slate-800/40"
        >
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>Discovered</span>
            <Radio className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{totalNetworks}</div>
          <div className="text-[11px] text-slate-500 mt-1">Unique BSSIDs</div>
        </div>

        {/* Approved Networks */}
        <div 
          onClick={() => onNavigate('networks', 'approved')}
          className="bg-slate-900/90 border border-slate-800 hover:border-emerald-500/40 p-4 rounded-xl cursor-pointer transition-all hover:bg-slate-800/40"
        >
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>Approved</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-300 mt-1">{approvedNetworks}</div>
          <div className="text-[11px] text-slate-500 mt-1">Manually approved baseline</div>
        </div>

        {/* Unknown Networks */}
        <div 
          onClick={() => onNavigate('networks', 'unknown')}
          className="bg-slate-900/90 border border-slate-800 hover:border-amber-500/40 p-4 rounded-xl cursor-pointer transition-all hover:bg-slate-800/40"
        >
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>Unknown</span>
            <Layers className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-300 mt-1">{unknownNetworks}</div>
          <div className="text-[11px] text-slate-500 mt-1">Pending Audit</div>
        </div>

        {/* Rogue Detections */}
        <div 
          onClick={() => onNavigate('threats')}
          className="bg-slate-900/90 border border-slate-800 hover:border-rose-500/40 p-4 rounded-xl cursor-pointer transition-all hover:bg-slate-800/40"
        >
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>Rogue / Clone</span>
            <Flame className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 mt-1">{rogueNetworks}</div>
          <div className="text-[11px] text-rose-500/80 mt-1">Suspicious APs</div>
        </div>

        {/* Critical Vulnerabilities */}
        <div 
          onClick={() => onNavigate('networks', 'critical')}
          className="bg-slate-900/90 border border-slate-800 hover:border-rose-500/40 p-4 rounded-xl cursor-pointer transition-all hover:bg-slate-800/40"
        >
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>Critical Risks</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-300 mt-1">{criticalIssuesCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">WEP / Downgrade</div>
        </div>

        {/* Active Investigations */}
        <div 
          onClick={() => onNavigate('investigations')}
          className="bg-slate-900/90 border border-slate-800 hover:border-purple-500/40 p-4 rounded-xl cursor-pointer transition-all hover:bg-slate-800/40"
        >
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>Incidents</span>
            <AlertTriangle className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-300 mt-1">{openIncidents}</div>
          <div className="text-[11px] text-slate-500 mt-1">Case Files Open</div>
        </div>
      </div>

      {/* Real change-aware posture panel: uses only native scan history and security-change records. */}
      <section className="overflow-hidden rounded-xl border border-sky-500/20 bg-[#0b1a30] shadow-sm">
        <div className="flex flex-col gap-5 p-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.16em] text-sky-300"><Activity className="h-4 w-4" /> Wireless change radar</div>
            <div className="mt-2 flex items-end gap-3"><span className="winwifi-gradient-value text-4xl font-black tracking-tight text-slate-50">{avgSecurityScore ?? '—'}</span><span className="mb-1 text-sm font-semibold text-sky-200">{postureLabel}</span></div>
            <p className="mt-2 max-w-xl text-xs leading-5 text-slate-400">Posture is calculated from the latest access point observations in this project. Changes appear after a completed scan or imported evidence records them.</p>
          </div>
          <div className="grid min-w-[360px] grid-cols-2 gap-2 sm:grid-cols-4">
            <div className="rounded-lg border border-slate-700/70 bg-slate-950/35 px-3 py-2.5"><p className="text-[10px] uppercase tracking-wide text-slate-500">Last observed</p><p className="mt-1 text-lg font-bold text-slate-100">{totalNetworks}</p><p className={`text-[10px] ${isScanning ? 'text-emerald-400' : 'text-amber-300'}`}>{isScanning ? (liveAge === null ? 'Waiting for native scan' : `Native refresh ${liveAge}s ago`) : (liveAge === null ? 'Scanner stopped' : `Stopped · last refresh ${liveAge}s ago`)}</p></div>
            <div className="rounded-lg border border-slate-700/70 bg-slate-950/35 px-3 py-2.5"><p className="text-[10px] uppercase tracking-wide text-slate-500">Changes</p><p className="mt-1 text-lg font-bold text-sky-300">{securityChanges.length}</p></div>
            <div className="rounded-lg border border-slate-700/70 bg-slate-950/35 px-3 py-2.5"><p className="text-[10px] uppercase tracking-wide text-slate-500">Rogue signals</p><p className="mt-1 text-lg font-bold text-rose-300">{rogueNetworks}</p></div>
            <button onClick={() => onNavigate('threats', 'changes')} className="rounded-lg border border-sky-500/30 bg-sky-500/10 px-3 py-2.5 text-left transition hover:bg-sky-500/20"><p className="text-[10px] uppercase tracking-wide text-sky-300">Review</p><p className="mt-1 text-xs font-bold text-slate-100">Open timeline →</p></button>
          </div>
        </div>
        {recentChanges.length > 0 && <div className="grid border-t border-slate-700/70 bg-slate-950/20 md:grid-cols-2 xl:grid-cols-4">{recentChanges.map(change => <button key={change.id} onClick={() => onNavigate('threats', 'changes')} className="border-b border-r border-slate-800/80 px-4 py-3 text-left transition hover:bg-slate-800/40 xl:border-b-0"><p className="truncate text-xs font-semibold text-slate-200">{change.title}</p><p className="mt-1 truncate text-[11px] text-slate-500">{change.ssid || change.bssid} · {change.before} → {change.after}</p></button>)}</div>}
      </section>

      {/* "What Needs Attention?" Direct Action Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <h2 className="text-base font-bold text-slate-100">What Needs Attention?</h2>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-medium">
              {attentionItems.length} items
            </span>
          </div>
          <span className="text-xs text-slate-500">Clicking an item jumps to relevant evidence</span>
        </div>

        {!hasNetworkData ? (
          <div className="flex flex-col items-center gap-3 py-6 text-center text-slate-300">
            <Radio className="w-8 h-8 text-blue-400" />
            <p className="max-w-xl text-sm text-slate-400">No scan data yet.</p>
            <div className="flex flex-wrap justify-center gap-2">
              <button onClick={onOpenBridgeConfig} className="rounded-lg border border-blue-500/40 bg-blue-600 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-500">Connect Windows bridge</button>
              <button onClick={onOpenImport} className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700">Import capture</button>
            </div>
          </div>
        ) : attentionItems.length === 0 ? (
          <div className="text-center py-8 text-slate-400 text-sm">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
            No command-center items are active. Review per-network risk factors and pending scope decisions in Network Inventory and Projects &amp; Authorization.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {attentionItems.map(item => (
              <div
                key={item.id}
                onClick={() => onNavigate(item.tab, item.targetFilter)}
                className={`p-3.5 rounded-lg border transition-all cursor-pointer flex items-start justify-between gap-3 ${
                  item.severity === 'CRITICAL'
                    ? 'bg-rose-500/10 border-rose-500/30 hover:bg-rose-500/15'
                    : 'bg-amber-500/10 border-amber-500/30 hover:bg-amber-500/15'
                }`}
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                      item.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                    }`}>
                      {item.severity}
                    </span>
                    <h3 className="text-sm font-semibold text-slate-100">{item.title}</h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{item.desc}</p>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-400 flex-shrink-0 mt-1 group-hover:translate-x-0.5 transition-transform" />
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Visual Distributions & Spectrum Snapshot */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Band Breakdown */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              Spectrum Band Distribution
            </h3>
            <span className="text-xs text-slate-500">2.4 / 5 / 6 GHz</span>
          </div>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-400">2.4 GHz (Legacy Coverage)</span>
                <span className="text-slate-200 font-semibold">{band24Count} APs ({totalNetworks ? Math.round((band24Count / totalNetworks)*100) : 0}%)</span>
              </div>
              <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="winwifi-chart-bar h-full rounded-full transition-all"
                  style={{ width: `${totalNetworks ? (band24Count / totalNetworks)*100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-400">5 GHz (High Performance)</span>
                <span className="text-slate-200 font-semibold">{band5Count} APs ({totalNetworks ? Math.round((band5Count / totalNetworks)*100) : 0}%)</span>
              </div>
              <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="winwifi-chart-bar h-full rounded-full transition-all"
                  style={{ width: `${totalNetworks ? (band5Count / totalNetworks)*100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-400">6 GHz (Wi-Fi 6E/7 Clean Spectrum)</span>
                <span className="text-slate-200 font-semibold">{band6Count} APs ({totalNetworks ? Math.round((band6Count / totalNetworks)*100) : 0}%)</span>
              </div>
              <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="winwifi-chart-bar h-full rounded-full transition-all"
                  style={{ width: `${totalNetworks ? (band6Count / totalNetworks)*100 : 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Channel Density */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400" />
              Most Congested Channels
            </h3>
            <button 
              onClick={() => onNavigate('rf')}
              className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1"
            >
              RF Map <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2.5">
            {topChannels.map(([ch, count]) => (
              <div key={ch} className="flex items-center justify-between text-xs py-1 px-2.5 rounded bg-slate-800/50">
                <span className="font-mono text-slate-300 font-medium">Channel {ch}</span>
                <span className="text-slate-400">{count} APs broadcasting</span>
              </div>
            ))}
            {topChannels.length === 0 && (
              <div className="text-xs text-slate-500 py-4 text-center">No channel telemetry gathered yet.</div>
            )}
          </div>
        </div>

        {/* Quick Security Recommendations */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-purple-400" />
              Remediation Checklist
            </h3>
            <span className="text-xs text-slate-500">NIST SP 800-153</span>
          </div>

          <ul className="space-y-2 text-xs text-slate-300">
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-1.5 flex-shrink-0" />
              <span>Enforce 802.11w Protected Management Frames on all corporate SSIDs.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 flex-shrink-0" />
              <span>Deactivate Wi-Fi Protected Setup (WPS) PIN registrars on perimeter routers.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 flex-shrink-0" />
              <span>Migrate remaining WPA-TKIP devices to WPA3-Enterprise or WPA2-AES.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 flex-shrink-0" />
              <span>Physically locate and decommission unauthorized access points.</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};

import React, { useState, useMemo } from 'react';
import { 
  AccessPoint, 
  FrequencyBand, 
  SecurityType,
  DataSourceProfile,
  DataOrigin 
} from '../types';
import { 
  Wifi, 
  Search, 
  ShieldAlert, 
  ShieldCheck, 
  KeyRound, 
  Users, 
  HardDrive, 
  AlertTriangle, 
  Filter, 
  ArrowUpDown,
  ExternalLink,
  Lock,
  Unlock,
  Radio,
  Upload,
  Sparkles,
  Terminal,
  RefreshCw,
  Server,
  ChevronLeft,
  ChevronRight,
  Database,
  FlaskConical,
  CheckCircle2
} from 'lucide-react';

interface NetworkDiscoveryProps {
  accessPoints: AccessPoint[];
  selectedBssid: string | null;
  onSelectAp: (bssid: string) => void;
  onCaptureHandshake: (ap: AccessPoint) => void;
  dataSourceProfile?: DataSourceProfile;
  activeSourceLabel?: string;
  onOpenImport?: () => void;
  onLoadBenchmark?: () => void;
  onRefreshScan?: () => void;
  onOpenBridgeConfig?: () => void;
  isDarkMode: boolean;
}

type SortField = 'rssi' | 'ssid' | 'channel' | 'securityScore' | 'clients' | 'dataPacketCount';

export const NetworkDiscovery: React.FC<NetworkDiscoveryProps> = ({
  accessPoints,
  selectedBssid,
  onSelectAp,
  onCaptureHandshake,
  dataSourceProfile = 'BENCHMARK',
  activeSourceLabel = 'Default',
  onOpenImport,
  onLoadBenchmark,
  onRefreshScan,
  onOpenBridgeConfig,
  isDarkMode,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [bandFilter, setBandFilter] = useState<string>('ALL');
  const [securityFilter, setSecurityFilter] = useState<string>('ALL');
  const [onlyVulnerable, setOnlyVulnerable] = useState<boolean>(false);
  const [sortField, setSortField] = useState<SortField>('rssi');
  const [sortAsc, setSortAsc] = useState<boolean>(false);

  // Presentation-only pagination (Dataset is never truncated)
  const [pageSize, setPageSize] = useState<number>(50);
  const [currentPage, setCurrentPage] = useState<number>(1);

  // Filter logic over 100% of discovered access points
  const filtered = useMemo(() => {
    return accessPoints.filter((ap) => {
      const matchesSearch = 
        ap.ssid.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ap.bssid.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ap.vendor.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesBand = bandFilter === 'ALL' || ap.band === bandFilter;
      
      let matchesSecurity = true;
      if (securityFilter === 'OPEN_WEP') {
        matchesSecurity = ap.security.includes('Open') || ap.security.includes('WEP');
      } else if (securityFilter === 'WPA2') {
        matchesSecurity = ap.security.includes('WPA2');
      } else if (securityFilter === 'WPA3') {
        matchesSecurity = ap.security.includes('WPA3');
      }

      const matchesVuln = !onlyVulnerable || (ap.riskScore ?? (100 - ap.securityScore)) >= 40 || ap.isRogueCandidate;

      return matchesSearch && matchesBand && matchesSecurity && matchesVuln;
    });
  }, [accessPoints, searchTerm, bandFilter, securityFilter, onlyVulnerable]);

  // Sorting logic over 100% of discovered access points
  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let diff = 0;
      if (sortField === 'rssi') diff = a.rssi - b.rssi;
      else if (sortField === 'ssid') diff = a.ssid.localeCompare(b.ssid);
      else if (sortField === 'channel') diff = a.channel - b.channel;
      else if (sortField === 'securityScore') diff = (a.riskScore ?? 100 - a.securityScore) - (b.riskScore ?? 100 - b.securityScore);
      else if (sortField === 'clients') diff = (a.clients?.length || 0) - (b.clients?.length || 0);
      else if (sortField === 'dataPacketCount') diff = a.dataPacketCount - b.dataPacketCount;
      return sortAsc ? diff : -diff;
    });
  }, [filtered, sortField, sortAsc]);

  // Total pages calculation for presentation layer
  const totalPages = pageSize > 0 ? Math.ceil(sorted.length / pageSize) : 1;
  const safeCurrentPage = Math.min(Math.max(currentPage, 1), totalPages || 1);

  // Sliced ONLY for UI viewport rendering
  const paginatedApList = useMemo(() => {
    if (pageSize <= 0) return sorted;
    const startIndex = (safeCurrentPage - 1) * pageSize;
    return sorted.slice(startIndex, startIndex + pageSize);
  }, [sorted, safeCurrentPage, pageSize]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false); // default descending (strongest signal first)
    }
  };

  const getOriginBadge = (origin?: DataOrigin) => {
    switch (origin) {
      case 'LIVE_WINDOWS':
        return (
          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 uppercase tracking-wide flex items-center gap-1">
            <Radio className="w-2.5 h-2.5" />
            LIVE
          </span>
        );
      case 'IMPORTED':
        return (
          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 uppercase tracking-wide flex items-center gap-1">
            <HardDrive className="w-2.5 h-2.5" />
            IMPORT
          </span>
        );
      case 'OFFLINE':
        return (
          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 uppercase tracking-wide flex items-center gap-1">
            <Database className="w-2.5 h-2.5" />
            OFFLINE
          </span>
        );
      case 'TRAINING':
      default:
        return (
          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-purple-500/20 text-purple-400 border border-purple-500/30 uppercase tracking-wide flex items-center gap-1">
            <FlaskConical className="w-2.5 h-2.5" />
            TRAIN
          </span>
        );
    }
  };

  // Helper for RSSI signal bar
  const renderSignalBars = (rssi: number) => {
    const level = rssi > -55 ? 4 : rssi > -68 ? 3 : rssi > -80 ? 2 : 1;
    const barColor = 
      level >= 4 ? 'bg-emerald-500' : 
      level === 3 ? 'bg-blue-500' : 
      level === 2 ? 'bg-amber-500' : 'bg-red-500';

    return (
      <div className="flex items-end gap-0.5 h-3.5 w-6" title={`${rssi} dBm`}>
        {[1, 2, 3, 4].map((bar) => (
          <div
            key={bar}
            className={`w-1 rounded-xs transition-all ${
              bar <= level ? barColor : isDarkMode ? 'bg-slate-700' : 'bg-slate-300'
            }`}
            style={{ height: `${bar * 25}%` }}
          />
        ))}
      </div>
    );
  };

  const getScoreBadge = (risk: number) => {
    if (risk >= 75) {
      return (
        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/10 text-red-400 border border-red-500/20">
          {risk}/100 Critical
        </span>
      );
    }
    if (risk >= 40) {
      return (
        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
          {risk}/100 High
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
        {risk}/100 {risk >= 15 ? 'Medium' : 'Low'}
      </span>
    );
  };

  return (
    <div className={`rounded-lg border shadow-xs flex flex-col transition-colors overflow-hidden ${
      isDarkMode ? 'bg-[#181a20] border-[#2c303b]' : 'bg-white border-slate-200'
    }`}>
      {/* Active Data Source & Provenance Ribbon */}
      <div className={`px-4 py-2.5 border-b flex flex-wrap items-center justify-between gap-2 text-xs ${
        dataSourceProfile === 'LIVE_WINDOWS'
          ? isDarkMode ? 'bg-emerald-950/30 border-emerald-900/50 text-emerald-300' : 'bg-emerald-50 border-emerald-200 text-emerald-800'
          : dataSourceProfile === 'REAL_PCAP' || dataSourceProfile === 'REAL_NETSH' || dataSourceProfile === 'IMPORTED'
            ? isDarkMode ? 'bg-cyan-950/30 border-cyan-900/50 text-cyan-300' : 'bg-cyan-50 border-cyan-200 text-cyan-800'
            : dataSourceProfile === 'OFFLINE'
              ? isDarkMode ? 'bg-amber-950/30 border-amber-900/50 text-amber-300' : 'bg-amber-50 border-amber-200 text-amber-800'
              : isDarkMode ? 'bg-purple-950/30 border-purple-900/50 text-purple-300' : 'bg-purple-50 border-purple-200 text-purple-800'
      }`}>
        <div className="flex flex-wrap items-center gap-2.5">
          {dataSourceProfile === 'LIVE_WINDOWS' && <Radio className="w-4 h-4 text-emerald-400 shrink-0 animate-pulse" />}
          {(dataSourceProfile === 'REAL_PCAP' || dataSourceProfile === 'IMPORTED') && <HardDrive className="w-4 h-4 text-cyan-400 shrink-0" />}
          {dataSourceProfile === 'REAL_NETSH' && <Terminal className="w-4 h-4 text-cyan-400 shrink-0" />}
          {dataSourceProfile === 'OFFLINE' && <Database className="w-4 h-4 text-amber-400 shrink-0" />}
          {(dataSourceProfile === 'BENCHMARK' || dataSourceProfile === 'TRAINING' || dataSourceProfile === 'OFFLINE_LAB') && (
            <FlaskConical className="w-4 h-4 text-purple-400 shrink-0" />
          )}
          
          <div>
            <div className="font-bold flex items-center gap-2">
              <span>
                {dataSourceProfile === 'LIVE_WINDOWS' && 'LIVE WINDOWS DATA (Native WLAN bridge)'}
                {dataSourceProfile === 'REAL_PCAP' && 'IMPORTED DATA (Binary PCAP / PCAPNG Dissection)'}
                {dataSourceProfile === 'REAL_NETSH' && 'IMPORTED DATA (Windows Netsh CLI Acquisition)'}
                {dataSourceProfile === 'OFFLINE' && 'OFFLINE DATA (Local Project SQLite Database)'}
                {(dataSourceProfile === 'BENCHMARK' || dataSourceProfile === 'TRAINING' || dataSourceProfile === 'OFFLINE_LAB') && (
                  'TRAINING DATA (NIST SP 800-153 Reference Benchmark)'
                )}
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded font-mono border bg-black/20 border-current/30">
                {accessPoints.length} BSS entries loaded
              </span>
            </div>
            <div className="text-[11px] opacity-80 mt-0.5">
              Source: {activeSourceLabel} • Displayed observations are available to analysis engines
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {onRefreshScan && (
            <button
              onClick={onRefreshScan}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold border transition-colors shadow-xs ${
                isDarkMode 
                  ? 'bg-blue-600/20 border-blue-500/40 text-blue-300 hover:bg-blue-600/30' 
                  : 'bg-blue-50 border-blue-300 text-blue-700 hover:bg-blue-100'
              }`}
              title="Trigger immediate hardware scan refresh"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Refresh Hardware Scan</span>
            </button>
          )}

          {onOpenBridgeConfig && (
            <button
              onClick={onOpenBridgeConfig}
              className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
                isDarkMode 
                  ? 'bg-slate-800 border-slate-700 hover:bg-slate-700 text-slate-200' 
                  : 'bg-white border-slate-300 hover:bg-slate-100 text-slate-700'
              }`}
            >
              <Server className="w-3 h-3 text-emerald-400" />
              <span>Bridge Settings</span>
            </button>
          )}

          {onOpenImport && (
            <button
              onClick={onOpenImport}
              className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
                isDarkMode 
                  ? 'bg-slate-800 border-slate-700 hover:bg-slate-700 text-slate-200' 
                  : 'bg-white border-slate-300 hover:bg-slate-100 text-slate-700'
              }`}
            >
              <Upload className="w-3 h-3 text-cyan-400" />
              <span>Import Capture</span>
            </button>
          )}
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className={`p-3 border-b flex flex-wrap items-center justify-between gap-3 text-xs ${
        isDarkMode ? 'border-[#252934] bg-[#1d2028]' : 'border-slate-200 bg-slate-50'
      }`}>
        {/* Search input */}
        <div className="relative min-w-[240px] flex-1 max-w-sm">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search by SSID, BSSID or Vendor..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className={`w-full pl-8 pr-3 py-1.5 rounded border text-xs outline-none transition-colors ${
              isDarkMode 
                ? 'bg-[#14161d] border-[#313746] text-slate-200 focus:border-blue-500 placeholder-slate-500' 
                : 'bg-white border-slate-300 text-slate-800 focus:border-blue-500 placeholder-slate-400'
            }`}
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Band Filter */}
          <select
            value={bandFilter}
            onChange={(e) => {
              setBandFilter(e.target.value);
              setCurrentPage(1);
            }}
            className={`px-2 py-1 rounded border text-xs outline-none cursor-pointer ${
              isDarkMode ? 'bg-[#14161d] border-[#313746] text-slate-200' : 'bg-white border-slate-300 text-slate-700'
            }`}
          >
            <option value="ALL">All Bands (2.4/5/6 GHz)</option>
            <option value="2.4 GHz">2.4 GHz Only</option>
            <option value="5 GHz">5 GHz Only</option>
            <option value="6 GHz">6 GHz Only</option>
          </select>

          {/* Security Filter */}
          <select
            value={securityFilter}
            onChange={(e) => {
              setSecurityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className={`px-2 py-1 rounded border text-xs outline-none cursor-pointer ${
              isDarkMode ? 'bg-[#14161d] border-[#313746] text-slate-200' : 'bg-white border-slate-300 text-slate-700'
            }`}
          >
            <option value="ALL">All Security Types</option>
            <option value="OPEN_WEP">Open & WEP (Insecure)</option>
            <option value="WPA2">WPA2 Networks</option>
            <option value="WPA3">WPA3 (SAE/Enterprise)</option>
          </select>

          {/* Vulnerability only checkbox */}
          <label className="flex items-center gap-1.5 cursor-pointer select-none text-slate-300 ml-1">
            <input
              type="checkbox"
              checked={onlyVulnerable}
              onChange={(e) => {
                setOnlyVulnerable(e.target.checked);
                setCurrentPage(1);
              }}
              className="rounded text-blue-600 focus:ring-0"
            />
            <span className="text-[11px] font-medium text-amber-400 flex items-center gap-1">
              <ShieldAlert className="w-3 h-3" />
              At-Risk Only
            </span>
          </label>
        </div>
      </div>

      {/* Access Points Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className={`border-b text-[11px] font-semibold text-slate-400 uppercase tracking-wider ${
              isDarkMode ? 'bg-[#15171e] border-[#252934]' : 'bg-slate-100 border-slate-200'
            }`}>
              <th className="py-2.5 px-3">
                <button 
                  onClick={() => toggleSort('ssid')} 
                  className="flex items-center gap-1 hover:text-slate-200"
                >
                  SSID / Network Name
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </button>
              </th>
              <th className="py-2.5 px-3">Origin</th>
              <th className="py-2.5 px-3">BSSID / MAC</th>
              <th className="py-2.5 px-3">
                <button 
                  onClick={() => toggleSort('rssi')} 
                  className="flex items-center gap-1 hover:text-slate-200"
                >
                  Signal (RSSI)
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </button>
              </th>
              <th className="py-2.5 px-3">
                <button 
                  onClick={() => toggleSort('channel')} 
                  className="flex items-center gap-1 hover:text-slate-200"
                >
                  CH / Band
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </button>
              </th>
              <th className="py-2.5 px-3">Security & Cipher</th>
              <th className="py-2.5 px-3">
                <button 
                  onClick={() => toggleSort('clients')} 
                  className="flex items-center gap-1 hover:text-slate-200"
                >
                  Clients
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </button>
              </th>
              <th className="py-2.5 px-3">
                <button 
                  onClick={() => toggleSort('dataPacketCount')} 
                  className="flex items-center gap-1 hover:text-slate-200"
                >
                  Packets
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </button>
              </th>
              <th className="py-2.5 px-3">
                <button 
                  onClick={() => toggleSort('securityScore')} 
                  className="flex items-center gap-1 hover:text-slate-200"
                >
                  Risk Score
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </button>
              </th>
              <th className="py-2.5 px-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className={`divide-y ${isDarkMode ? 'divide-[#242835]' : 'divide-slate-200'}`}>
            {paginatedApList.length === 0 ? (
              <tr>
                <td colSpan={10} className="py-12 px-4 text-center">
                  <div className="flex flex-col items-center justify-center max-w-md mx-auto space-y-3">
                    <div className="p-3 rounded-full bg-blue-500/10 text-blue-400">
                      <Radio className="w-8 h-8" />
                    </div>
                    <div>
                      <h4 className="text-sm font-semibold text-slate-200">
                        {accessPoints.length === 0 ? 'No Access Points Discovered' : 'No Networks Match Current Filters'}
                      </h4>
                      <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                        {accessPoints.length === 0 
                          ? 'Start the WinWiFi Native Bridge on your Windows host or import a capture to view live hardware telemetry.'
                          : 'Try clearing your search query or adjusting band and security filters.'}
                      </p>
                    </div>

                    {accessPoints.length === 0 && (
                      <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
                        {onOpenBridgeConfig && (
                          <button
                            onClick={onOpenBridgeConfig}
                            className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-xs transition-all flex items-center gap-1.5"
                          >
                            <Server className="w-3.5 h-3.5" />
                            <span>Configure Windows Bridge</span>
                          </button>
                        )}
                        {onOpenImport && (
                          <button
                            onClick={onOpenImport}
                            className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-xs transition-all flex items-center gap-1.5"
                          >
                            <Upload className="w-3.5 h-3.5" />
                            <span>Import .PCAP or Netsh</span>
                          </button>
                        )}
                        {onLoadBenchmark && (
                          <button
                            onClick={onLoadBenchmark}
                            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold shadow-xs transition-all flex items-center gap-1.5"
                          >
                            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                            <span>Load Benchmark</span>
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              paginatedApList.map((ap) => {
                const isSelected = ap.bssid === selectedBssid;
                const originType = ap.dataSourceOrigin || (
                  dataSourceProfile === 'LIVE_WINDOWS' ? 'LIVE_WINDOWS' :
                  dataSourceProfile === 'REAL_PCAP' || dataSourceProfile === 'REAL_NETSH' || dataSourceProfile === 'IMPORTED' ? 'IMPORTED' :
                  dataSourceProfile === 'OFFLINE' ? 'OFFLINE' : 'TRAINING'
                );

                return (
                  <tr
                    key={ap.bssid}
                    className={`transition-colors duration-150 ${
                      isSelected
                        ? isDarkMode 
                          ? 'bg-blue-900/25 border-l-2 border-l-blue-500' 
                          : 'bg-blue-50 border-l-2 border-l-blue-600'
                        : isDarkMode
                          ? 'hover:bg-[#1e222c]'
                          : 'hover:bg-slate-50'
                    }`}
                  >
                    {/* SSID with Rogue alert badge */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <div className="p-1.5 rounded bg-slate-500/10 text-slate-300">
                          <Wifi className="w-3.5 h-3.5" />
                        </div>
                        <div>
                          <div className="font-semibold text-slate-100 flex items-center gap-1.5">
                            <span>{ap.ssid || '<Hidden SSID>'}</span>
                            {ap.isRogueCandidate && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-red-500/20 text-red-400 border border-red-500/30 uppercase tracking-wider animate-pulse">
                                Rogue / Twin
                              </span>
                            )}
                            {ap.handshake && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                                4-Way Cap
                              </span>
                            )}
                          </div>
                          <div className="text-[10px] text-slate-400">
                            {ap.vendor} • {ap.standard}
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Origin Badge */}
                    <td className="py-3 px-3">
                      {getOriginBadge(originType)}
                    </td>

                    {/* BSSID */}
                    <td className="py-3 px-3 font-mono text-[11px] text-slate-300">
                      {ap.bssid}
                    </td>

                    {/* RSSI */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        {renderSignalBars(ap.rssi)}
                        <span className="font-mono text-xs">{ap.rssi} dBm</span>
                      </div>
                    </td>

                    {/* Channel & Band */}
                    <td className="py-3 px-3">
                      <div className="font-medium text-slate-200">
                        CH {ap.channel} ({ap.channelWidthMhz}MHz)
                      </div>
                      <div className="text-[10px] text-slate-400">{ap.band}</div>
                    </td>

                    {/* Security & Cipher */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5">
                        {ap.security.includes('Open') ? (
                          <Unlock className="w-3 h-3 text-amber-500" />
                        ) : (
                          <Lock className="w-3 h-3 text-blue-400" />
                        )}
                        <span className="font-medium text-slate-200">{ap.security}</span>
                      </div>
                      <div className="text-[10px] text-slate-400 flex items-center gap-2 mt-0.5">
                        <span>Cipher: {ap.cipher}</span>
                        {ap.wpsEnabled && (
                          <span className="text-amber-400 font-medium">WPS ON</span>
                        )}
                      </div>
                    </td>

                    {/* Clients */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5 text-slate-300">
                        <Users className="w-3.5 h-3.5 text-slate-400" />
                        <span className="font-mono">{dataSourceProfile === 'LIVE_WINDOWS' ? 'N/A (needs capture)' : (ap.clients?.length || 0)}</span>
                      </div>
                    </td>

                    {/* Packets */}
                    <td className="py-3 px-3">
                      <span className="font-mono text-slate-400">{dataSourceProfile === 'LIVE_WINDOWS' ? 'N/A (needs capture)' : ap.dataPacketCount.toLocaleString()}</span>
                    </td>

                    {/* Score */}
                    <td className="py-3 px-3">
                      {getScoreBadge(ap.riskScore ?? (100 - ap.securityScore))}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAp(ap.bssid);
                        }}
                        className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors border ${
                          isSelected
                            ? 'bg-blue-600 border-blue-500 text-white'
                            : isDarkMode
                              ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                              : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-100'
                        }`}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Presentation Pagination & Summary Footer */}
      <div className={`px-4 py-2.5 text-xs border-t flex flex-wrap items-center justify-between gap-3 text-slate-400 ${
        isDarkMode ? 'border-[#252934] bg-[#15171e]' : 'border-slate-200 bg-slate-50'
      }`}>
        <div className="flex flex-wrap items-center gap-4">
          <span>
            Discovered Networks: <strong className="text-slate-200 font-mono">{accessPoints.length}</strong>
          </span>
          <span>
            Matching Filters: <strong className="text-slate-200 font-mono">{sorted.length}</strong>
          </span>
          <span>
            Associated Clients: <strong className="text-slate-200 font-mono">{accessPoints.reduce((acc, a) => acc + (a.clients?.length || 0), 0)}</strong>
          </span>
          <span>
            Captured Handshakes: <strong className="text-emerald-400 font-mono">{accessPoints.filter(a => !!a.handshake).length}</strong>
          </span>
        </div>

        {/* Presentation-only pagination controls */}
        {sorted.length > 0 && (
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-400">Rows per page:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(parseInt(e.target.value));
                  setCurrentPage(1);
                }}
                className={`px-2 py-0.5 rounded border text-[11px] outline-none ${
                  isDarkMode ? 'bg-[#1a1d24] border-slate-700 text-slate-200' : 'bg-white border-slate-300 text-slate-700'
                }`}
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={250}>250</option>
                <option value={0}>All ({sorted.length})</option>
              </select>
            </div>

            {pageSize > 0 && totalPages > 1 && (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={safeCurrentPage <= 1}
                  className="p-1 rounded border border-slate-700 hover:bg-slate-700/50 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300"
                  title="Previous Page"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <span className="text-[11px] px-2 font-mono">
                  {safeCurrentPage} / {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={safeCurrentPage >= totalPages}
                  className="p-1 rounded border border-slate-700 hover:bg-slate-700/50 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300"
                  title="Next Page"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

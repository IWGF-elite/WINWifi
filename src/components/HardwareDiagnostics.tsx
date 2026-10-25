import React, { useState } from 'react';
import { 
  Cpu, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  ShieldCheck, 
  Radio, 
  Server, 
  Layers, 
  Terminal, 
  HelpCircle,
  Sparkles,
  ExternalLink,
  Filter,
  Check,
  Copy,
  Info,
  Download,
  FileCode
} from 'lucide-react';
import { 
  WifiAdapter, 
  UIMode, 
  DataSourceProfile, 
  BridgeConnectionState, 
  BridgeHealthStatus,
  CapabilityStatus,
  HardwareCapability 
} from '../types';
import { CapabilityMatrixService } from '../services/capabilityMatrix';

interface HardwareDiagnosticsProps {
  adapter?: WifiAdapter;
  uiMode: UIMode;
  dataSourceProfile?: DataSourceProfile;
  bridgeState?: BridgeConnectionState;
  bridgeStatus?: BridgeHealthStatus | null;
  onOpenBridgeConfig?: () => void;
  onOpenImport?: () => void;
}

export const HardwareDiagnostics: React.FC<HardwareDiagnosticsProps> = ({
  adapter,
  uiMode,
  dataSourceProfile = 'BENCHMARK',
  bridgeState = 'DISCONNECTED',
  bridgeStatus,
  onOpenBridgeConfig,
  onOpenImport
}) => {
  const [selectedStatusFilter, setSelectedStatusFilter] = useState<string>('all');
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<string>('all');
  const [copiedCommandIdx, setCopiedCommandIdx] = useState<number | null>(null);

  const capabilityService = CapabilityMatrixService.getInstance();
  const capabilities = capabilityService.getCapabilities(dataSourceProfile as DataSourceProfile, bridgeState as BridgeConnectionState);
  const captureGuide = capabilityService.getSupportedCaptureArchitectureGuide();

  // Filter capabilities
  const filteredCapabilities = capabilities.filter(cap => {
    if (selectedStatusFilter !== 'all' && cap.status !== selectedStatusFilter) return false;
    if (selectedCategoryFilter !== 'all' && cap.category !== selectedCategoryFilter) return false;
    return true;
  });

  const categories = Array.from(new Set(capabilities.map(c => c.category)));
  const statusTypes: CapabilityStatus[] = [
    'Supported',
    'Available',
    'Unavailable',
    'Driver Required',
    'Hardware Required',
    'Not Exposed by Windows',
    'Not Verified'
  ];

  const getStatusBadge = (status: CapabilityStatus) => {
    switch (status) {
      case 'Supported':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            SUPPORTED
          </span>
        );
      case 'Available':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30 flex items-center gap-1">
            <Radio className="w-3 h-3 text-blue-400" />
            AVAILABLE
          </span>
        );
      case 'Driver Required':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            DRIVER REQUIRED
          </span>
        );
      case 'Hardware Required':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30 flex items-center gap-1">
            <Cpu className="w-3 h-3 text-purple-400" />
            HARDWARE REQUIRED
          </span>
        );
      case 'Not Exposed by Windows':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1">
            <XCircle className="w-3 h-3 text-rose-400" />
            NOT EXPOSED BY WINDOWS
          </span>
        );
      case 'Unavailable':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-700 text-slate-300 border border-slate-600 flex items-center gap-1">
            <XCircle className="w-3 h-3 text-slate-400" />
            UNAVAILABLE
          </span>
        );
      case 'Not Verified':
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-yellow-500/20 text-yellow-300 border border-yellow-500/30 flex items-center gap-1">
            <HelpCircle className="w-3 h-3 text-yellow-400" />
            NOT VERIFIED
          </span>
        );
    }
  };

  const handleCopyCommand = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedCommandIdx(idx);
    setTimeout(() => setCopiedCommandIdx(null), 2000);
  };

  return (
    <div className="space-y-6 pb-8">
      {/* Top Banner: Real Hardware & Operating Environment Posture */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
              bridgeState === 'CONNECTED' 
                ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400'
                : 'bg-blue-500/15 border border-blue-500/30 text-blue-400'
            }`}>
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <div className="text-xs text-slate-500 font-mono">
                {bridgeState === 'CONNECTED' ? 'ACTIVE WINDOWS WIRELESS TRANSCEIVER' : 'HOST RUNTIME ENVIRONMENT'}
              </div>
              <h1 className="text-lg font-bold text-slate-100 mt-0.5">
                {bridgeState === 'CONNECTED'
                  ? bridgeStatus?.activeAdapterName || 'Windows NDIS Wireless Adapter'
                  : dataSourceProfile === 'REAL_PCAP'
                    ? 'Imported 802.11 Packet Forensics Session'
                    : 'Browser Sandbox Web Container (Bridge Offline)'}
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                {bridgeState === 'CONNECTED' ? (
                  <>
                    Active Adapter ID: <span className="font-mono text-slate-200">{bridgeStatus?.activeAdapterId || 'Default'}</span> • 
                    Platform: <span className="text-slate-200">{bridgeStatus?.platform || 'Windows 64-bit'}</span> • 
                    Cycles: <span className="text-emerald-400 font-semibold">{bridgeStatus?.scanCyclesCompleted || 0}</span>
                  </>
                ) : dataSourceProfile === 'REAL_PCAP' ? (
                  <>Decoded offline Libpcap/PCAPNG capture stream. Full promiscuous frame dissector active.</>
                ) : (
                  <>
                    Native Windows WLAN API (wlanapi.dll) requires the <span className="text-blue-400 font-semibold">WinWiFi.Desktop bridge</span> on localhost:38989.
                  </>
                )}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {bridgeState === 'CONNECTED' ? (
              <span className="px-3 py-1.5 rounded-lg bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-xs font-semibold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                Windows NDIS Bridge Connected
              </span>
            ) : (
              <button
                onClick={onOpenBridgeConfig}
                className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm"
              >
                <Server className="w-3.5 h-3.5" />
                <span>Connect Windows Bridge</span>
              </button>
            )}

            {onOpenImport && (
              <button
                onClick={onOpenImport}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                <span>Import PCAP Forensics</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Primary Capability Matrix Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-blue-400" />
              <span>Comprehensive 802.11 Hardware &amp; Windows Capability Matrix</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Defensive technical audit evaluating real capabilities, driver prerequisites, Windows NDIS boundaries, and external capture pathways.
            </p>
          </div>

          {/* Counts summary pill */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              {capabilities.filter(c => c.status === 'Supported').length} Supported
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
              {capabilities.filter(c => c.status === 'Driver Required').length} Driver Req.
            </span>
            <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
              {capabilities.filter(c => c.status === 'Not Exposed by Windows').length} OS Limited
            </span>
          </div>
        </div>

        {/* Filter controls */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/80 text-xs">
          <div className="flex items-center gap-1.5 text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span className="font-semibold">Filter Status:</span>
          </div>
          <button
            onClick={() => setSelectedStatusFilter('all')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all ${
              selectedStatusFilter === 'all'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({capabilities.length})
          </button>
          {statusTypes.map(st => {
            const count = capabilities.filter(c => c.status === st).length;
            if (count === 0) return null;
            return (
              <button
                key={st}
                onClick={() => setSelectedStatusFilter(st)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all ${
                  selectedStatusFilter === st
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {st} ({count})
              </button>
            );
          })}
        </div>

        {/* Detailed Capability Table */}
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-800/80 text-slate-300 font-semibold uppercase tracking-wider text-[10px] border-b border-slate-700">
              <tr>
                <th className="py-3 px-4">Capability &amp; Domain</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Operating Status</th>
                <th className="py-3 px-4">Technical Rationale &amp; Windows NDIS Architecture</th>
                <th className="py-3 px-4">Prerequisites / Driver</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-200">
              {filteredCapabilities.map(cap => (
                <tr key={cap.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-semibold text-slate-100">{cap.name}</div>
                    <div className="text-[10px] font-mono text-slate-500">{cap.id}</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="inline-flex shrink-0 whitespace-nowrap px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[10px]">
                      {cap.category}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    {getStatusBadge(cap.status)}
                  </td>
                  <td className="py-3 px-4 max-w-md">
                    <div className="text-slate-300">{cap.technicalDetails}</div>
                    {cap.windowsRestriction && (
                      <div className="text-[11px] text-slate-400 mt-1 flex items-start gap-1">
                        <Info className="w-3 h-3 text-blue-400 shrink-0 mt-0.5" />
                        <span>{cap.windowsRestriction}</span>
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-[11px]">
                    {cap.prerequisite || 'None'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Supported Capture Architecture Workflow Guide */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div>
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-bold text-slate-100">{captureGuide.title}</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
            {captureGuide.overview}
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {captureGuide.methods.map((method, idx) => (
            <div 
              key={idx}
              className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3"
            >
              <div className="space-y-2">
                <div className="font-bold text-xs text-slate-200 flex items-center justify-between">
                  <span>{method.name}</span>
                </div>
                <div className="text-[11px] text-slate-400">
                  <span className="text-slate-500">Driver: </span>
                  <strong className="text-slate-300">{method.driver}</strong>
                </div>

                <ul className="space-y-1.5 text-[11px] text-slate-400 list-disc list-inside">
                  {method.instructions.map((inst, i) => (
                    <li key={i} className="leading-tight">{inst}</li>
                  ))}
                </ul>
              </div>

              <div className="pt-2 border-t border-slate-800/80">
                <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                  <span>Execution Command:</span>
                  <button
                    onClick={() => handleCopyCommand(method.command, idx)}
                    className="text-blue-400 hover:text-blue-300 flex items-center gap-1 font-sans"
                  >
                    {copiedCommandIdx === idx ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800 font-mono text-[10px] text-slate-300 break-all select-all">
                  {method.command}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Defensive Ethics & Transparency Charter */}
      <div className="bg-slate-900/80 border border-blue-900/40 rounded-xl p-4 text-xs space-y-2">
        <div className="flex items-center gap-2 text-blue-400 font-bold">
          <ShieldCheck className="w-4 h-4" />
          <span>Defensive Audit &amp; Data Integrity Commitment</span>
        </div>
        <p className="text-slate-300 leading-relaxed text-[11px]">
          WinWiFi is architected exclusively for defensive wireless auditing, configuration compliance, and forensic packet inspection. 
          Misleading synthetic telemetry has been purged from production mode:
          client devices are strictly extracted from real frame decodes, and cryptographic handshakes require real forensic packet evidence or explicit offline training lab selection. 
          Offensive capabilities (packet injection, deauthentication jamming, evil twin rogue generation) are prohibited by design.
        </p>
      </div>
    </div>
  );
};

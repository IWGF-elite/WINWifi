import React, { useState } from 'react';
import { 
  Radio, 
  Play, 
  Square, 
  Sun, 
  Moon, 
  Maximize2,
  Minimize2,
  Minus,
  X,
  FileText,
  FlaskConical,
  Upload,
  Cpu,
  HardDrive,
  RefreshCw,
  Server,
  Database
} from 'lucide-react';
import { DataSourceProfile, BridgeConnectionState, WifiAdapter } from '../types';
import { BridgeErrorKind, bridgeStatusView } from '../services/bridgeStatus';
import { WinWiFiLogo } from './WinWiFiLogo';

interface TitleBarProps {
  isDarkMode: boolean;
  onToggleDarkMode: () => void;
  dataSourceProfile: DataSourceProfile;
  hasFreshLiveData?: boolean;
  activeSourceLabel: string;
  isScanning: boolean;
  onToggleScan: () => void;
  onRefreshScan?: () => void;
  bridgeState?: BridgeConnectionState;
  bridgeErrorKind?: BridgeErrorKind | null;
  onOpenBridgeConfig?: () => void;
  projectName: string;
  onOpenReport: () => void;
  onOpenSelfTest: () => void;
  onOpenImport: () => void;
  onOpenArchitecture: () => void;
  adapters: WifiAdapter[];
  selectedAdapterId: string;
  onSelectAdapter: (adapterId: string) => void;
  onToggleFullscreen: () => void;
}

export const TitleBar: React.FC<TitleBarProps> = ({
  isDarkMode,
  onToggleDarkMode,
  dataSourceProfile,
  hasFreshLiveData = false,
  activeSourceLabel,
  isScanning,
  onToggleScan,
  onRefreshScan,
  bridgeState = 'DISCONNECTED',
  bridgeErrorKind = null,
  onOpenBridgeConfig,
  projectName,
  onOpenReport,
  onOpenSelfTest,
  onOpenImport,
  onOpenArchitecture,
  adapters,
  selectedAdapterId,
  onSelectAdapter,
  onToggleFullscreen,
}) => {
  const [isFittedToScreen, setIsFittedToScreen] = useState(false);
  const nativeWindow = (action: 'minimize' | 'fit' | 'close') => {
    (window as any).chrome?.webview?.postMessage?.(`window:${action}`);
  };

  const beginNativeDrag = () => {
    // This is synchronous during the actual DOM mouse-down. postMessage is
    // intentionally not used because it reaches WPF after the gesture ends.
    (window as any).chrome?.webview?.hostObjects?.sync?.winWifiWindow?.BeginDrag?.();
  };

  const toggleWorkAreaFit = () => {
    nativeWindow('fit');
    setIsFittedToScreen(current => !current);
  };
  const getOriginBadge = () => {
    switch (dataSourceProfile) {
      case 'LIVE_WINDOWS':
        return {
          label: hasFreshLiveData ? 'LIVE WINDOWS DATA' : 'WAITING FOR SCAN',
          classes: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
          icon: <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
        };
      case 'REAL_PCAP':
      case 'REAL_NETSH':
      case 'IMPORTED':
        return {
          label: 'IMPORTED DATA',
          classes: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
          icon: <HardDrive className="w-3 h-3 text-cyan-400" />
        };
      case 'OFFLINE':
        return {
          label: 'OFFLINE DATA',
          classes: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
          icon: <Database className="w-3 h-3 text-amber-400" />
        };
      default:
        return {
          label: 'NO DATA',
          classes: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
          icon: <Database className="w-3 h-3 text-slate-400" />
        };
    }
  };

  const origin = getOriginBadge();

  return (
    <header className={`select-none border-b transition-colors duration-200 ${
      isDarkMode 
        ? 'bg-[#181a20] border-[#2c303b] text-slate-200' 
        : 'bg-[#f3f4f8] border-[#e2e4ea] text-slate-800'
    }`}>
      {/* Top Windows Chrome Bar */}
      <div className="winwifi-window-chrome flex items-center justify-between gap-2 overflow-hidden px-3 py-1.5 text-xs" onDoubleClick={toggleWorkAreaFit} onMouseDown={(event) => {
        if (event.button === 0 && !(event.target as HTMLElement).closest('button,select,input')) beginNativeDrag();
      }}>
        <div className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
          <WinWiFiLogo className="h-6 w-6 shrink-0 rounded-md shadow-sm" />
          <span className="truncate font-semibold tracking-wide text-xs">WinWiFi Security Auditor</span>
          <span className="winwifi-edition text-[10px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 font-mono">Enterprise v3.0</span>
          <span className="winwifi-project-separator text-slate-500">|</span>
          <span className="winwifi-project-name text-slate-400 font-medium truncate max-w-[200px]">{projectName}</span>
        </div>

        {/* Windows Window Controls */}
        <div className="winwifi-window-controls flex shrink-0 items-center gap-1">
          <button 
            onClick={onToggleDarkMode} 
            title={isDarkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
            className="p-1 rounded hover:bg-slate-700/30 text-slate-400 hover:text-slate-200 transition-colors mr-2"
          >
            {isDarkMode ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
          </button>

          <select
            value={selectedAdapterId}
            onChange={(event) => onSelectAdapter(event.target.value)}
            disabled={bridgeState !== 'CONNECTED' || adapters.length === 0 || isScanning}
            className="winwifi-adapter-select max-w-[220px] rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-200 disabled:cursor-not-allowed disabled:opacity-50"
            title="Select the Windows Wi-Fi adapter used for telemetry"
          >
            <option value="">{adapters.length ? 'Select adapter' : 'No Windows adapter detected'}</option>
            {adapters.map((adapter) => <option key={adapter.id} value={adapter.id}>{adapter.name}</option>)}
          </select>
          <div className="w-px h-3 bg-slate-700/40 mx-1" />
          <button onClick={onToggleFullscreen} className="p-1.5 rounded hover:bg-slate-700/20 text-slate-400 hover:text-slate-200" title="Toggle full screen" aria-label="Toggle full screen">
            <Maximize2 className="w-3 h-3" />
          </button>
          <button onClick={() => nativeWindow('minimize')} className="p-1.5 hover:bg-slate-700/20" title="Minimize"><Minus className="w-3.5 h-3.5" /></button>
          <button onClick={toggleWorkAreaFit} className="p-1.5 hover:bg-slate-700/20" title={isFittedToScreen ? "Restore managed window size" : "Fit window to screen"} aria-label={isFittedToScreen ? "Restore managed window size" : "Fit window to screen"}>
            {isFittedToScreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
          <button onClick={() => nativeWindow('close')} className="p-1.5 hover:bg-rose-600 hover:text-white" title="Close"><X className="w-3.5 h-3.5" /></button>
        </div>
      </div>

      {/* Main Action Toolbar (Ribbon) */}
      <div className={`flex flex-wrap items-center justify-between px-3 py-2 border-t text-xs gap-2 ${
        isDarkMode ? 'border-[#252934] bg-[#1c1f27]' : 'border-[#e6e8ee] bg-[#fafbff]'
      }`}>
        {/* Left: Scan Controls, Refresh, Bridge Pill & Data Origin */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Scan Toggle Button */}
          <button
            onClick={onToggleScan}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-medium shadow-xs transition-all ${
              isScanning
                ? 'bg-amber-600 hover:bg-amber-500 text-white ring-1 ring-amber-400/50'
                : 'bg-blue-600 hover:bg-blue-500 text-white ring-1 ring-blue-400/50'
            }`}
            title={isScanning ? "Stop continuous scanner" : "Start continuous scanner"}
          >
            {isScanning ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>Stop Scan</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Start Scan</span>
              </>
            )}
          </button>

          {/* Real Refresh Button */}
          {onRefreshScan && (
            <button
              onClick={onRefreshScan}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded border text-xs font-medium transition-colors ${
                isDarkMode
                  ? 'border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200'
                  : 'border-slate-300 bg-white hover:bg-slate-100 text-slate-700'
              }`}
              title="Trigger immediate hardware scan cycle and refresh network table"
            >
              <RefreshCw className="w-3.5 h-3.5 text-blue-400" />
              <span>Refresh</span>
            </button>
          )}

          {/* Prominent Data Origin Pill */}
          <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded border font-semibold tracking-wide text-[11px] ${origin.classes}`}>
            {origin.icon}
            <span>{origin.label}</span>
          </div>

          {/* Active Detail Label */}
          <span className="text-[11px] text-slate-400 max-w-[150px] truncate hidden sm:inline" title={activeSourceLabel}>
            ({activeSourceLabel})
          </span>

          {/* Native Bridge Pill */}
          {onOpenBridgeConfig && (() => {
            const view = bridgeStatusView(bridgeState, bridgeErrorKind);
            return (
              <button
                onClick={onOpenBridgeConfig}
                className={`flex items-center gap-1.5 px-2 py-1 rounded border text-[11px] font-mono transition-colors ${
                  view.tone === 'ok'
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20'
                    : view.tone === 'busy'
                      ? 'bg-blue-500/10 border-blue-500/30 text-blue-400 hover:bg-blue-500/20'
                      : view.tone === 'bad'
                        ? 'bg-rose-500/10 border-rose-500/30 text-rose-400 hover:bg-rose-500/20'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700/50'
                }`}
                title={`Windows Bridge Daemon (${view.label}) — click to configure`}
              >
                <Server className="w-3 h-3" />
                <span>Bridge: {view.label}</span>
              </button>
            );
          })()}

          {/* Import Data Button */}
          <button
            onClick={onOpenImport}
            className={`flex items-center gap-1 px-2.5 py-1 rounded border text-xs font-medium transition-colors ${
              isDarkMode 
                ? 'bg-slate-800 border-slate-700 hover:bg-slate-700 text-slate-200' 
                : 'bg-white border-slate-300 hover:bg-slate-100 text-slate-700'
            }`}
            title="Import .PCAP, .CAP, or Windows Netsh output"
          >
            <Upload className="w-3 h-3 text-blue-400" />
            <span>Import</span>
          </button>
        </div>

        {/* Right Tools: Self-Test & Reports */}
        <div className="flex items-center gap-2">
          <button
            onClick={onOpenArchitecture}
            className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 transition-colors"
            title="View system capabilities"
          >
            <Cpu className="w-3 h-3 text-purple-400" />
            <span className="hidden md:inline">Capabilities</span>
          </button>

          <button
            onClick={onOpenSelfTest}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-medium transition-colors ${
              isDarkMode 
                ? 'border-slate-700 bg-slate-800/60 hover:bg-slate-700 text-slate-200' 
                : 'border-slate-300 bg-white hover:bg-slate-100 text-slate-700'
            }`}
          >
            <FlaskConical className="w-3.5 h-3.5 text-purple-400" />
            <span>Self-Test</span>
          </button>

          <button
            onClick={onOpenReport}
            className={`flex items-center gap-1.5 px-3 py-1 rounded font-medium border text-xs transition-colors shadow-xs ${
              isDarkMode 
                ? 'bg-emerald-600/20 border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30' 
                : 'bg-emerald-50 border-emerald-300 text-emerald-700 hover:bg-emerald-100'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Report</span>
          </button>
        </div>
      </div>
    </header>
  );
};

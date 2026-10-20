import React, { useState } from 'react';
import { 
  AlertTriangle, 
  Terminal, 
  RefreshCw, 
  ExternalLink, 
  Copy, 
  Check, 
  Settings, 
  Radio, 
  ShieldAlert,
  Server
} from 'lucide-react';
import { LocalScannerState } from '../services/localScannerService';

interface ScannerOfflineStateProps {
  scannerStatus: LocalScannerState;
  onRetry: () => Promise<boolean>;
  onUpdateEndpoint: (url: string) => void;
  isDarkMode?: boolean;
}

export const ScannerOfflineState: React.FC<ScannerOfflineStateProps> = ({
  scannerStatus,
  onRetry,
  onUpdateEndpoint,
  isDarkMode = true,
}) => {
  const [isRetrying, setIsRetrying] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [showConfig, setShowConfig] = useState(false);
  const [endpointInput, setEndpointInput] = useState(scannerStatus.endpoint);

  const pythonCommand = 'python wifi_scanner_service.py';

  const handleCopy = () => {
    navigator.clipboard.writeText(pythonCommand);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const handleRetryClick = async () => {
    setIsRetrying(true);
    try {
      await onRetry();
    } finally {
      setIsRetrying(false);
    }
  };

  const handleSaveEndpoint = (e: React.FormEvent) => {
    e.preventDefault();
    if (endpointInput.trim()) {
      onUpdateEndpoint(endpointInput.trim());
      setShowConfig(false);
    }
  };

  return (
    <div className={`rounded-xl border p-6 md:p-8 space-y-6 shadow-sm ${
      isDarkMode 
        ? 'bg-[#151821] border-rose-500/30 text-slate-200' 
        : 'bg-white border-rose-200 text-slate-800'
    }`}>
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-rose-500/20 pb-5">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0">
            <Radio className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-slate-100">Local Wi-Fi Scanner Service Offline</h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                SERVICE UNREACHABLE
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-xl">
              WinWiFi is configured to consume live Wi-Fi telemetry from the local host daemon at{' '}
              <code className="text-rose-300 font-mono bg-rose-950/40 px-1 py-0.5 rounded border border-rose-900/60">
                {scannerStatus.endpoint}
              </code>
              . Simulated data generation is disabled.
            </p>
          </div>
        </div>

        {/* Retry & Config actions */}
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            onClick={() => setShowConfig(!showConfig)}
            className="px-3 py-2 rounded-lg text-xs font-medium border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-300 flex items-center gap-1.5 transition-colors"
          >
            <Settings className="w-3.5 h-3.5 text-slate-400" />
            <span>Endpoint Settings</span>
          </button>
          <button
            onClick={handleRetryClick}
            disabled={isRetrying}
            className="flex-1 sm:flex-initial px-4 py-2 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white flex items-center justify-center gap-2 shadow-xs transition-all disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRetrying ? 'animate-spin' : ''}`} />
            <span>{isRetrying ? 'Testing Connection...' : 'Retry Connection'}</span>
          </button>
        </div>
      </div>

      {/* Endpoint Configuration Bar (Collapsible) */}
      {showConfig && (
        <form onSubmit={handleSaveEndpoint} className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-blue-400" />
            <span>Scanner Service URL Configuration</span>
          </div>
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={endpointInput}
              onChange={(e) => setEndpointInput(e.target.value)}
              placeholder="http://127.0.0.1:5055/api/networks"
              className="flex-1 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 font-mono outline-hidden focus:border-blue-500"
            />
            <button
              type="submit"
              className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition-colors"
            >
              Update &amp; Reconnect
            </button>
          </div>
          <div className="text-[11px] text-slate-400">
            Default endpoint: <code className="text-slate-300">http://127.0.0.1:5055/api/networks</code> or <code className="text-slate-300">http://localhost:5055/api/networks</code>
          </div>
        </form>
      )}

      {/* Instructions Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        {/* Step 1 */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center gap-2 font-bold text-slate-200">
            <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-[11px]">1</span>
            <span>Install Dependencies</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            Ensure Python 3 is installed with Flask and Flask-CORS for local API serving:
          </p>
          <div className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-blue-300 select-all">
            pip install flask flask-cors
          </div>
        </div>

        {/* Step 2 */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center gap-2 font-bold text-slate-200">
            <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-[11px]">2</span>
            <span>Run Scanner Service</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            Execute the scanner script on the host machine to begin continuous <code>netsh</code> sweeps:
          </p>
          <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-emerald-300">
            <span>{pythonCommand}</span>
            <button
              onClick={handleCopy}
              className="text-slate-400 hover:text-slate-200 transition-colors ml-2"
              title="Copy command"
            >
              {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        {/* Step 3 */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center gap-2 font-bold text-slate-200">
            <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-[11px]">3</span>
            <span>Automatic Sync</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            Once running at <code>http://127.0.0.1:5055</code>, WinWiFi polls every 4 seconds, replacing this placeholder with real SSIDs, BSSIDs, and channels.
          </p>
          <div className="text-[11px] text-amber-400/90 font-medium flex items-center gap-1.5 pt-1">
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
            <span>Strict no-mock policy enforced</span>
          </div>
        </div>
      </div>

      {/* Diagnostics Footer */}
      <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono text-slate-400">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            <span>Status: Offline</span>
          </div>
          <span>•</span>
          <div>Target: <span className="text-slate-300">{scannerStatus.endpoint}</span></div>
          {scannerStatus.lastError && (
            <>
              <span>•</span>
              <div className="text-rose-400 truncate max-w-sm" title={scannerStatus.lastError}>
                Error: {scannerStatus.lastError}
              </div>
            </>
          )}
        </div>

        <div className="flex items-center gap-3">
          <span>Failed polls: {scannerStatus.consecutiveFailures}</span>
          <span>•</span>
          <span>Poll interval: 4000ms</span>
        </div>
      </div>
    </div>
  );
};

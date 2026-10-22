import React, { useState, useEffect } from 'react';
import { 
  Radio, 
  Wifi, 
  ShieldCheck, 
  RefreshCw, 
  Play, 
  Square, 
  CheckCircle2, 
  AlertTriangle, 
  X, 
  Copy, 
  Check, 
  ExternalLink, 
  Cpu, 
  HardDrive,
  Info,
  Server,
  Activity,
  Zap
} from 'lucide-react';
import { NativeBridgeClient } from '../services/bridgeClient';
import { 
  BridgeConnectionState, 
  BridgeConfig, 
  BridgeHealthStatus, 
  BridgeDiagnostics 
} from '../types';

interface BridgeConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  isDarkMode: boolean;
  onConnectedDataReceived?: () => void;
}

export const BridgeConfigModal: React.FC<BridgeConfigModalProps> = ({
  isOpen,
  onClose,
  isDarkMode,
  onConnectedDataReceived
}) => {
  const bridge = NativeBridgeClient.getInstance();

  const [config, setConfig] = useState<BridgeConfig>(() => bridge.getConfig());
  const [connectionState, setConnectionState] = useState<BridgeConnectionState>(() => bridge.getState());
  const [lastError, setLastError] = useState<string | null>(() => bridge.getLastError());
  const [health, setHealth] = useState<BridgeHealthStatus | null>(null);
  const [diagnostics, setDiagnostics] = useState<BridgeDiagnostics | null>(null);
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen) return;

    setConfig(bridge.getConfig());
    setConnectionState(bridge.getState());
    setLastError(bridge.getLastError());

    const unsubState = bridge.onStateChange((st) => {
      setConnectionState(st);
      if (st === 'CONNECTED') {
        fetchHealthAndDiag();
      }
    });

    const unsubDiag = bridge.onDiagnostics((diag) => {
      setDiagnostics(diag);
    });

    const unsubError = bridge.onError((err) => {
      setLastError(err);
    });

    if (bridge.getState() === 'CONNECTED') {
      fetchHealthAndDiag();
    }

    return () => {
      unsubState();
      unsubDiag();
      unsubError();
    };
  }, [isOpen]);

  const fetchHealthAndDiag = async () => {
    try {
      const h = await bridge.checkHealth();
      setHealth(h);
      const d = await bridge.getDiagnostics();
      setDiagnostics(d);
    } catch (e: any) {
      console.warn('Failed to fetch health/diag in modal', e);
      const message = e?.message || 'Unable to load bridge diagnostics.';
      setLastError(message);
      setTestResult(`Connected, but diagnostics could not be loaded: ${message}`);
    }
  };

  if (!isOpen) return null;

  const handleSaveConfig = () => {
    try {
      bridge.setConfig(config);
      setTestResult('Configuration saved. Reconnecting...');
      bridge.connect();
    } catch (err: any) {
      setTestResult(`Error: ${err.message}`);
    }
  };

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      bridge.setConfig(config);
      const success = await bridge.connect();
      if (success) {
        setTestResult('Successfully connected to WinWiFi Native Bridge!');
        await fetchHealthAndDiag();
        if (onConnectedDataReceived) onConnectedDataReceived();
      } else {
        setTestResult(`Connection failed: ${bridge.getLastError() || 'Bridge not reachable'}`);
      }
    } catch (err: any) {
      const message = err?.message || 'Unknown connection error.';
      setLastError(message);
      setTestResult(`Connection failed: ${message}`);
    } finally {
      setIsTesting(false);
    }
  };

  const handleTriggerStart = async () => {
    try {
      const res = await bridge.startScan();
      setTestResult(`Native scanner started: ${res.message}`);
    } catch (err: any) {
      setTestResult(`Failed to start scanner: ${err.message}`);
    }
  };

  const handleTriggerStop = async () => {
    try {
      const res = await bridge.stopScan();
      setTestResult(`Native scanner stopped: ${res.message}`);
    } catch (err: any) {
      setTestResult(`Failed to stop scanner: ${err.message}`);
    }
  };

  const handleTriggerRefresh = async () => {
    try {
      const res = await bridge.refreshScan();
      setTestResult(`Hardware refresh completed: Discovered ${res.count} BSS entries from Windows radio.`);
      if (onConnectedDataReceived) onConnectedDataReceived();
    } catch (err: any) {
      setTestResult(`Failed to refresh hardware scan: ${err.message}`);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedCmd(id);
      setTimeout(() => setCopiedCmd(null), 2000);
    }).catch(error => {
      const message = error instanceof Error ? error.message : 'Clipboard access was denied.';
      setLastError(message);
      setTestResult(`Could not copy command: ${message}`);
    });
  };

  const isLocal = (url: string) => {
    try {
      const u = new URL(url);
      const h = u.hostname.toLowerCase();
      return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]';
    } catch {
      return false;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className={`relative w-full max-w-2xl rounded-xl border shadow-2xl overflow-hidden flex flex-col max-h-[90vh] transition-colors ${
        isDarkMode ? 'bg-[#181a20] border-[#2c303b] text-slate-100' : 'bg-white border-slate-200 text-slate-900'
      }`}>
        {/* Header */}
        <div className={`px-5 py-4 border-b flex items-center justify-between ${
          isDarkMode ? 'border-[#262934] bg-[#1d2029]' : 'border-slate-200 bg-slate-50'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-600/15 text-blue-500 border border-blue-500/20">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold tracking-tight">Windows Native Bridge Configuration</h3>
              <p className="text-xs text-slate-400">Connect React to Windows WlanApi / NDIS Hardware Scanner</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-700/30 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4 overflow-y-auto flex-1 text-xs">
          {/* Connection Status Banner */}
          <div className={`p-3.5 rounded-lg border flex items-center justify-between gap-3 ${
            connectionState === 'CONNECTED'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : connectionState === 'CONNECTING'
                ? 'bg-blue-500/10 border-blue-500/30 text-blue-400'
                : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
          }`}>
            <div className="flex items-center gap-2.5">
              <span className="relative flex h-3 w-3">
                {connectionState === 'CONNECTED' && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                )}
                <span className={`relative inline-flex rounded-full h-3 w-3 ${
                  connectionState === 'CONNECTED' ? 'bg-emerald-500' :
                  connectionState === 'CONNECTING' ? 'bg-blue-500' : 'bg-amber-500'
                }`}></span>
              </span>
              <div>
                <span className="font-semibold text-xs uppercase tracking-wider">
                  Bridge Status: {connectionState}
                </span>
                <p className="text-[11px] opacity-80 mt-0.5">
                  {connectionState === 'CONNECTED' 
                    ? `Live connection active at ${config.baseUrl}`
                    : connectionState === 'CONNECTING'
                      ? `Attempting handshake with ${config.baseUrl}...`
                      : 'Not connected to local Windows daemon'}
                </p>
              </div>
            </div>

            <button
              onClick={handleTestConnection}
              disabled={isTesting}
              className={`px-3 py-1.5 rounded-md font-medium transition-all shadow-xs flex items-center gap-1.5 ${
                isTesting 
                  ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-500 text-white'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? 'animate-spin' : ''}`} />
              <span>{isTesting ? 'Connecting...' : 'Connect Now'}</span>
            </button>
          </div>

          {/* Test or Error Notification */}
          {testResult && (
            <div className={`p-3 rounded-lg border text-xs flex items-start gap-2 ${
              testResult.includes('Successfully')
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-red-500/10 border-red-500/30 text-red-300'
            }`}>
              {testResult.includes('Successfully') ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              )}
              <span className="leading-relaxed">{testResult}</span>
            </div>
          )}

          {lastError && connectionState !== 'CONNECTED' && (
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 space-y-1.5">
              <div className="flex items-center gap-1.5 font-semibold">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span>Diagnostic Notice:</span>
              </div>
              <p className="text-[11px] leading-relaxed opacity-90">{lastError}</p>
            </div>
          )}

          {/* Configuration Form */}
          <div className={`p-4 rounded-lg border space-y-3 ${
            isDarkMode ? 'border-[#262934] bg-[#1a1d24]' : 'border-slate-200 bg-slate-50'
          }`}>
            <h4 className="font-semibold text-xs text-slate-200 flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-blue-400" />
              <span>Bridge Endpoint Settings</span>
            </h4>

            <div className="space-y-2">
              <label className="block text-[11px] font-medium text-slate-300">
                Bridge Daemon Base URL (Localhost Only by Default)
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={config.baseUrl}
                  onChange={(e) => setConfig({ ...config, baseUrl: e.target.value })}
                  placeholder="http://127.0.0.1:38989"
                  className={`flex-1 px-3 py-1.5 rounded-md border text-xs font-mono transition-colors ${
                    isDarkMode 
                      ? 'bg-[#14161d] border-slate-700 text-slate-100 focus:border-blue-500' 
                      : 'bg-white border-slate-300 text-slate-900 focus:border-blue-600'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setConfig({ ...config, baseUrl: 'http://127.0.0.1:38989' })}
                  className="px-2.5 py-1.5 rounded border border-slate-700 hover:bg-slate-700/50 text-[11px] font-mono text-slate-300"
                >
                  :38989
                </button>
              </div>

              {!isLocal(config.baseUrl) && !config.allowRemote && (
                <div className="p-2 rounded bg-amber-500/10 border border-amber-500/20 text-amber-300 text-[11px]">
                  Warning: You entered a non-localhost address. For security, non-localhost connections require checking the "Allow remote bridge" flag below.
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Request Timeout (ms)</label>
                <input
                  type="number"
                  min="1000"
                  max="30000"
                  step="500"
                  value={config.timeoutMs}
                  onChange={(e) => setConfig({ ...config, timeoutMs: parseInt(e.target.value) || 5000 })}
                  className={`w-full px-2.5 py-1.5 rounded-md border text-xs ${
                    isDarkMode ? 'bg-[#14161d] border-slate-700 text-slate-100' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Polling Fallback Interval (ms)</label>
                <input
                  type="number"
                  min="1000"
                  max="15000"
                  step="500"
                  value={config.pollIntervalMs}
                  onChange={(e) => setConfig({ ...config, pollIntervalMs: parseInt(e.target.value) || 2500 })}
                  className={`w-full px-2.5 py-1.5 rounded-md border text-xs ${
                    isDarkMode ? 'bg-[#14161d] border-slate-700 text-slate-100' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
            </div>

            <div className="flex flex-col gap-1.5 pt-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.autoReconnect}
                  onChange={(e) => setConfig({ ...config, autoReconnect: e.target.checked })}
                  className="rounded text-blue-600 focus:ring-blue-500"
                />
                <span className="text-[11px] text-slate-300">Enable automatic reconnection with exponential backoff</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.allowRemote}
                  onChange={(e) => setConfig({ ...config, allowRemote: e.target.checked })}
                  className="rounded text-blue-600 focus:ring-blue-500"
                />
                <span className="text-[11px] text-slate-300">Allow remote non-localhost bridge addresses</span>
              </label>
            </div>
          </div>

          {/* Live Scanner Controls if Connected */}
          {connectionState === 'CONNECTED' && (
            <div className={`p-4 rounded-lg border space-y-3 ${
              isDarkMode ? 'border-[#262934] bg-[#1a1d24]' : 'border-slate-200 bg-slate-50'
            }`}>
              <h4 className="font-semibold text-xs text-slate-200 flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Zap className="w-3.5 h-3.5 text-amber-400" />
                  <span>Real Hardware Scanner Control</span>
                </span>
                {health && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-400">
                    Cycles: {health.scanCyclesCompleted} | APs: {health.accessPointsCount}
                  </span>
                )}
              </h4>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={handleTriggerStart}
                  className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium flex items-center gap-1.5 transition-colors"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Start Continuous Scan</span>
                </button>

                <button
                  onClick={handleTriggerStop}
                  className="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-white font-medium flex items-center gap-1.5 transition-colors"
                >
                  <Square className="w-3.5 h-3.5 fill-current" />
                  <span>Stop / Pause Scan</span>
                </button>

                <button
                  onClick={handleTriggerRefresh}
                  className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-medium flex items-center gap-1.5 transition-colors"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Immediate Hardware Refresh</span>
                </button>
              </div>

              {diagnostics && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-700/40 text-[11px]">
                  <div>
                    <span className="text-slate-400 block">Duration:</span>
                    <span className="font-mono font-semibold">{diagnostics.lastScanDurationMs}ms</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Discovered BSS:</span>
                    <span className="font-mono font-semibold text-emerald-400">{diagnostics.lastDiscoveredBssCount}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Total Cycles:</span>
                    <span className="font-mono font-semibold">{diagnostics.totalScanCycles}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Driver Stack:</span>
                    <span className="font-mono font-semibold text-blue-400">
                      {diagnostics.isPInvokeActive ? 'WlanApi P/Invoke' : diagnostics.isNetshFallbackActive ? 'Netsh CLI' : 'Virtual'}
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Quick Start Guide for Windows Host */}
          <div className={`p-4 rounded-lg border space-y-2 ${
            isDarkMode ? 'border-[#262934] bg-[#16181f]' : 'border-slate-200 bg-slate-100'
          }`}>
            <h4 className="font-semibold text-xs text-slate-200 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-blue-400" />
              <span>How to Start the Native Bridge on Windows</span>
            </h4>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Run either the WinWiFi Windows GUI application or the headless bridge daemon on your Windows machine:
            </p>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between p-2 rounded bg-black/40 border border-slate-800 font-mono text-[11px]">
                <span className="text-emerald-400 select-all">dotnet run --project WinWiFi.Desktop -- --bridge --port 38989</span>
                <button
                  onClick={() => copyToClipboard('dotnet run --project WinWiFi.Desktop -- --bridge --port 38989', 'cmd-1')}
                  className="p-1 rounded text-slate-400 hover:text-white"
                >
                  {copiedCmd === 'cmd-1' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>

              <div className="flex items-center justify-between p-2 rounded bg-black/40 border border-slate-800 font-mono text-[11px]">
                <span className="text-blue-400 select-all">winwifi-cli.exe --bridge --port 38989</span>
                <button
                  onClick={() => copyToClipboard('winwifi-cli.exe --bridge --port 38989', 'cmd-2')}
                  className="p-1 rounded text-slate-400 hover:text-white"
                >
                  {copiedCmd === 'cmd-2' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className={`px-5 py-3 border-t flex items-center justify-between ${
          isDarkMode ? 'border-[#262934] bg-[#1d2029]' : 'border-slate-200 bg-slate-50'
        }`}>
          <button
            onClick={handleSaveConfig}
            className="px-4 py-1.5 rounded-lg border border-slate-600 hover:bg-slate-700/40 text-xs font-medium transition-colors"
          >
            Save Settings
          </button>

          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-xs transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};

import React from 'react';
import { CheckCircle2, CircleDashed, KeyRound, RefreshCw, ShieldCheck, TriangleAlert, Wifi } from 'lucide-react';
import { BridgeConnectionState, DataSourceProfile, WifiAdapter } from '../types';
import { BridgeErrorKind, BRIDGE_RETRY_NOTE, bridgeStatusView, isEmbeddedDashboard } from '../services/bridgeStatus';
import { WinWiFiLogo } from './WinWiFiLogo';

interface StartupReadinessOverlayProps {
  bridgeState: BridgeConnectionState;
  adapters: WifiAdapter[];
  dataSourceProfile: DataSourceProfile;
  accessPointCount: number;
  error?: string;
  errorKind?: BridgeErrorKind | null;
  onRetry?: () => void;
  onContinue: () => void;
}

export const StartupReadinessOverlay: React.FC<StartupReadinessOverlayProps> = ({
  bridgeState, adapters, dataSourceProfile, accessPointCount, error, errorKind, onRetry, onContinue
}) => {
  const bridgeReady = bridgeState === 'CONNECTED';
  const scanReady = dataSourceProfile === 'LIVE_WINDOWS' && accessPointCount >= 0;
  const failed = bridgeState === 'ERROR';
  const shell = isEmbeddedDashboard();
  const view = bridgeStatusView(bridgeState, errorKind ?? null, shell);
  const steps = [
    { label: 'Checking Windows WLAN bridge', detail: bridgeReady ? 'Local bridge connected' : failed ? view.label : 'Starting the live data connection', done: bridgeReady, failed },
    { label: 'Detecting Wi-Fi adapters', detail: adapters.length ? `${adapters.length} adapter${adapters.length === 1 ? '' : 's'} available` : bridgeReady ? 'No adapter reported by Windows' : 'Waiting for bridge', done: bridgeReady && adapters.length > 0, failed: bridgeReady && adapters.length === 0 },
    { label: 'Loading authorized audit history', detail: 'Local project data is ready', done: true, failed: false },
    { label: 'Starting live telemetry', detail: scanReady ? `${accessPointCount} current BSSID${accessPointCount === 1 ? '' : 's'} observed` : bridgeReady ? 'Waiting for first WLAN observation' : 'Requires local bridge', done: scanReady, failed: false }
  ];

  const ready = bridgeReady && scanReady;
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-[#050912]/95 px-5 text-slate-100 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="WinWiFi readiness checks">
      <div className="relative w-full max-w-2xl overflow-hidden rounded-2xl border border-sky-400/25 bg-[#0a1425] shadow-2xl shadow-sky-950/50">
        <div className="absolute inset-x-0 top-0 h-1 bg-sky-400" />
        <div className="p-8 sm:p-10">
          <div className="flex items-center gap-4">
            <WinWiFiLogo className="h-12 w-12 shrink-0 rounded-xl shadow-lg shadow-sky-500/20" />
            <div><p className="text-xs font-bold tracking-[0.22em] text-sky-300">WINWIFI SECURITY AUDITOR</p><h1 className="mt-1 text-2xl font-bold tracking-tight">Preparing your local audit workspace</h1></div>
          </div>
          <p className="mt-4 max-w-xl text-sm leading-6 text-slate-400">Readiness checks are verified against this Windows device, its configured adapter, and the local audit workspace.</p>
          <div className="mt-8 space-y-3">
            {steps.map((step) => <div key={step.label} className="flex items-center gap-4 rounded-xl border border-slate-800 bg-slate-950/45 px-4 py-3.5">
              {step.done ? <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" /> : step.failed ? <TriangleAlert className="h-5 w-5 shrink-0 text-amber-400" /> : <CircleDashed className="h-5 w-5 shrink-0 animate-spin text-sky-400" />}
              <div className="min-w-0"><p className="text-sm font-semibold text-slate-200">{step.label}</p><p className="mt-0.5 text-xs text-slate-500">{step.detail}</p></div>
            </div>)}
          </div>
          {failed && (
            <div className="mt-5 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-100">
              <div className="flex items-center gap-1.5 font-semibold">
                {errorKind === 'token' ? <KeyRound className="h-3.5 w-3.5 text-amber-400" /> : <TriangleAlert className="h-3.5 w-3.5 text-amber-400" />}
                <span>{view.title}.</span>
              </div>
              <p className="mt-1 leading-relaxed">{view.description}</p>
              {!shell && error && <p className="mt-1 text-[11px] opacity-70">{error}</p>}
              <div className="mt-2.5 flex items-center gap-2">
                {onRetry && (
                  <button
                    onClick={onRetry}
                    className="flex items-center gap-1.5 rounded-lg bg-amber-500/20 px-3 py-1.5 font-semibold text-amber-100 transition hover:bg-amber-500/30"
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Retry connection
                  </button>
                )}
                <span className="text-[11px] opacity-70">{BRIDGE_RETRY_NOTE}</span>
              </div>
            </div>
          )}
          <div className="mt-7 flex items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-xs text-slate-500"><ShieldCheck className="h-4 w-4 text-emerald-400" /> Passive, defensive, authorized-scope workflow</div>
            {(ready || failed) && <button onClick={onContinue} className="rounded-lg bg-sky-500 px-4 py-2 text-sm font-bold text-slate-950 transition hover:bg-sky-400">{ready ? 'Open Command Center' : 'Continue to desktop'}</button>}
            {!ready && !failed && <div className="flex items-center gap-2 text-xs font-medium text-sky-300"><Wifi className="h-4 w-4 animate-pulse" /> Verifying local services</div>}
          </div>
        </div>
      </div>
    </div>
  );
};

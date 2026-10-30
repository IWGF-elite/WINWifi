import React from 'react';
import { CheckCircle2, KeyRound, RefreshCw, ShieldCheck, TriangleAlert } from 'lucide-react';
import { BridgeConnectionState, DataSourceProfile, WifiAdapter } from '../types';
import { BridgeErrorKind, BRIDGE_RETRY_NOTE, bridgeStatusView, isEmbeddedDashboard } from '../services/bridgeStatus';
import { WinWiFiLogo } from './WinWiFiLogo';
import { ProcessingOrb } from './ProcessingOrb';

interface StartupReadinessOverlayProps {
  bridgeState: BridgeConnectionState;
  adapters: WifiAdapter[];
  healthLoaded: boolean;
  adaptersLoaded: boolean;
  scanStatusLoaded: boolean;
  networksLoaded: boolean;
  snapshotsLoaded: boolean;
  dataSourceProfile: DataSourceProfile;
  accessPointCount: number;
  error?: string;
  errorKind?: BridgeErrorKind | null;
  onRetry?: () => void;
  onContinue: () => void;
}

export const StartupReadinessOverlay: React.FC<StartupReadinessOverlayProps> = ({
  bridgeState, adapters, healthLoaded, adaptersLoaded, scanStatusLoaded, networksLoaded, snapshotsLoaded,
  dataSourceProfile, accessPointCount, error, errorKind, onRetry, onContinue
}) => {
  const bridgeReady = bridgeState === 'CONNECTED';
  const scanReady = scanStatusLoaded && networksLoaded;
  const failed = bridgeState === 'ERROR' || Boolean(error);
  const shell = isEmbeddedDashboard();
  const view = bridgeStatusView(bridgeState, errorKind ?? null, shell);
  const steps = [
    { label: 'Checking Windows WLAN bridge', detail: healthLoaded ? 'Local bridge connected' : bridgeReady ? 'Loading bridge status' : failed ? view.label : 'Starting the live data connection', done: bridgeReady && healthLoaded, failed: bridgeState === 'ERROR' },
    { label: 'Detecting Wi-Fi adapters', detail: adaptersLoaded ? adapters.length ? `${adapters.length} adapter${adapters.length === 1 ? '' : 's'} available` : 'Windows reports no Wi-Fi adapters' : 'Waiting for the adapter list', done: adaptersLoaded, failed: false },
    { label: 'Loading authorized audit history', detail: snapshotsLoaded ? 'Project and dashboard records loaded' : 'Loading project and dashboard records', done: snapshotsLoaded, failed: false },
    { label: 'Starting live telemetry', detail: scanReady ? dataSourceProfile === 'LIVE_WINDOWS' ? `${accessPointCount} current BSSID${accessPointCount === 1 ? '' : 's'} observed` : 'Windows scan status and network response loaded' : !scanStatusLoaded ? 'Waiting for scan status' : 'Waiting for the Windows network list', done: scanReady, failed: false }
  ];
  const checksRunning = steps.some(step => !step.done && !step.failed);
  const pendingState = (label: string): 'working' | 'searching' | 'connecting' =>
    label.startsWith('Checking') ? 'connecting' : label.startsWith('Detecting') || label.startsWith('Starting') ? 'searching' : 'working';

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-[#050912]/95 px-5 text-slate-100 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="WinWiFi readiness checks">
      <div className="startup-readiness-card relative w-full max-w-5xl overflow-hidden rounded-[1.75rem] border border-sky-400/25 bg-[#0a1425] shadow-2xl shadow-sky-950/50">
        <div className="startup-readiness-accent absolute inset-x-0 top-0 h-1" />
        <div className="p-7 sm:p-10 lg:p-12">
          <div className="flex min-h-24 items-center gap-5 sm:gap-7">
            <WinWiFiLogo className="h-12 w-12 shrink-0 rounded-xl shadow-lg shadow-sky-500/20" />
            <div><p className="text-xs font-bold tracking-[0.22em] text-sky-300">WINWIFI SECURITY AUDITOR</p><h1 className="mt-1 text-2xl font-bold tracking-tight">Preparing your local audit workspace</h1></div>
            <ProcessingOrb
              state={checksRunning ? (bridgeReady ? 'working' : 'connecting') : 'breathing'}
              size={64}
              label={checksRunning ? 'Preparing the WinWiFi audit workspace' : 'WinWiFi workspace ready'}
              className="startup-readiness-orb ml-auto shrink-0"
            />
          </div>
          <p className="mt-4 max-w-xl text-sm leading-6 text-slate-400">Readiness checks are verified against this Windows device, its configured adapter, and the local audit workspace.</p>
          <div className="mt-8 space-y-3">
            {steps.map((step) => <div key={step.label} className="startup-readiness-step flex items-center gap-4 rounded-xl border border-slate-800 bg-slate-950/45 px-4 py-3.5">
              {step.done ? <CheckCircle2 className="h-5 w-5 shrink-0 text-slate-300" /> : step.failed ? <TriangleAlert className="h-5 w-5 shrink-0 text-amber-400" /> : <ProcessingOrb state={pendingState(step.label)} size={20} label={`${step.label} in progress`} />}
              <div className="min-w-0"><p className="text-sm font-semibold text-slate-200">{step.label}</p><p className="mt-0.5 text-xs text-slate-500">{step.detail}</p></div>
            </div>)}
          </div>
          {failed && (
            <div className="mt-5 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-100">
              <div className="flex items-center gap-1.5 font-semibold">
                {errorKind === 'token' ? <KeyRound className="h-3.5 w-3.5 text-amber-400" /> : <TriangleAlert className="h-3.5 w-3.5 text-amber-400" />}
                <span>{view.title}.</span>
              </div>
              <p className="mt-1 leading-relaxed">{error || view.description}</p>
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
            <div className="flex items-center gap-2 text-xs text-slate-500"><ShieldCheck className="h-4 w-4 text-slate-400" /> Passive, defensive, authorized-scope workflow</div>
            {!failed && checksRunning && <div className="flex items-center gap-2 text-xs font-medium text-slate-300"><ProcessingOrb state="connecting" size={20} label="Verifying local services" /> Verifying local services</div>}
            {!failed && !checksRunning && <div className="text-xs font-medium text-slate-400">Workspace ready</div>}
            <button onClick={onContinue} className="winwifi-primary-action rounded-xl px-5 py-3 text-sm font-bold text-white">Open Command Center</button>
          </div>
        </div>
      </div>
    </div>
  );
};

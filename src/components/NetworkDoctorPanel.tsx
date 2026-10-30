import React, { useState } from 'react';
import { Activity, AlertTriangle, Check, CircleHelp, RefreshCw, Router, ShieldAlert, ShieldCheck, Wifi } from 'lucide-react';
import { ProcessingOrb } from './ProcessingOrb';
import { NetworkDoctorCheck } from '../types';
import { NativeBridgeClient } from '../services/bridgeClient';

interface NetworkDoctorPanelProps {
  adapterId: string;
  bridgeConnected: boolean;
  isDarkMode: boolean;
}

const findingStyle: Record<string, string> = {
  PASS: 'border-emerald-500/25 bg-emerald-500/5 text-emerald-300',
  WARN: 'border-amber-500/25 bg-amber-500/5 text-amber-300',
  ALERT: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  INFO: 'border-slate-700 bg-slate-900/60 text-slate-300'
};

const verdictText: Record<string, { title: string; tone: string }> = {
  'first-seen': { title: 'First check for this network', tone: 'text-sky-300' },
  matches: { title: 'Fingerprint matches', tone: 'text-emerald-300' },
  changed: { title: 'Network details changed — possibly fake', tone: 'text-rose-300' },
  unavailable: { title: 'Fingerprint comparison unavailable', tone: 'text-amber-300' }
};

function Metric({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 min-w-0">
    <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</div>
    <div className="mt-1 truncate text-sm font-semibold text-slate-100" title={value}>{value}</div>
    {detail && <div className="mt-1 text-[11px] text-slate-500">{detail}</div>}
  </div>;
}

export const NetworkDoctorPanel: React.FC<NetworkDoctorPanelProps> = ({ adapterId, bridgeConnected, isDarkMode }) => {
  const [check, setCheck] = useState<NetworkDoctorCheck | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const runCheck = async (replaceFingerprint = false) => {
    setBusy(true);
    setError('');
    try {
      const result = await NativeBridgeClient.getInstance().checkCurrentNetwork(adapterId, replaceFingerprint);
      setCheck(result);
      if (result.status === 'Unavailable') setError(result.reason || 'Connect to Wi-Fi before running the check.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };

  const updateFingerprint = () => {
    if (window.confirm('Replace the saved fingerprint for this SSID with the details currently observed on the connected network?')) {
      void runCheck(true);
    }
  };

  const container = isDarkMode ? 'bg-slate-950 text-slate-100' : 'bg-white text-slate-900';
  const muted = isDarkMode ? 'text-slate-400' : 'text-slate-600';
  const verdict = check ? verdictText[check.fingerprintVerdict] : null;

  return <section className={`mx-auto w-full max-w-[1280px] space-y-4 rounded-xl ${container}`}>
    <header className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900 p-4">
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-cyan-300"><Activity className="h-5 w-5" /></div>
        <div className="min-w-0">
          <h1 className="text-lg font-bold">Network Diagnostics</h1>
          <p className={`text-xs ${muted}`}>Checks the connected Wi-Fi network, its saved fingerprint, and connection performance.</p>
        </div>
      </div>
      <button type="button" onClick={() => void runCheck()} disabled={!bridgeConnected || !adapterId || busy}
        className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-50">
        {busy ? <ProcessingOrb state="solving" size={20} label="Checking the current network connection" /> : check ? <RefreshCw className="h-4 w-4" /> : <Wifi className="h-4 w-4" />}
        {busy ? 'Checking connection…' : 'Check Network'}
      </button>
    </header>

    {!bridgeConnected && <div role="status" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">Connect the desktop bridge before checking the live network.</div>}
    {error && <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</div>}
    {!check && !error && <div className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
      <CircleHelp className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" />
      <p className={`text-sm ${muted}`}>Run Check Network while connected. It takes a short, passive reading of Windows connection details, the gateway, system DNS, and only currently observed access points already approved in this project.</p>
    </div>}

    {check?.status !== 'Unavailable' && check && <>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
        <Metric label="Connected SSID" value={check.ssid || 'N/A'} detail={check.bssid || undefined} />
        <Metric label="Signal" value={check.signal || 'N/A'} detail={check.channel ? `Channel ${check.channel} · ${check.band}` : check.band} />
        <Metric label="Security" value={check.security} detail={check.cipher} />
        <Metric label="Gateway" value={check.gatewayIp || 'N/A'} detail={check.gatewayMac || 'Router MAC not in ARP cache'} />
        <Metric label="Gateway response" value={check.gatewayMedianMs == null ? 'No reply' : `${Math.round(check.gatewayMedianMs)} ms`} detail={check.gatewayPacketLossPercent == null ? 'Not measured' : `${check.gatewayPacketLossPercent}% packet loss`} />
        <Metric label="DNS lookup" value={check.dnsLookupMs == null ? 'Unavailable' : `${Math.round(check.dnsLookupMs)} ms`} detail={check.dnsServers.length ? check.dnsServers.join(', ') : 'No DNS server reported'} />
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
        <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="mb-3 flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-cyan-300" /><h2 className="text-sm font-bold">Safe Check</h2></div>
          {check.fingerprintVerdict === 'changed' && <div className="mb-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3">
            <div className={`flex items-center gap-2 text-sm font-bold ${verdict?.tone}`}><ShieldAlert className="h-4 w-4" />{verdict?.title}</div>
            <ul className="mt-2 list-inside list-disc space-y-1 text-xs text-rose-100">{check.fingerprintDifferences.map((difference) => <li key={difference}>{difference}</li>)}</ul>
            <button type="button" onClick={updateFingerprint} className="mt-3 rounded-md border border-rose-400/40 px-3 py-1.5 text-xs font-semibold text-rose-100 hover:bg-rose-500/15">Trust this change and replace saved fingerprint</button>
          </div>}
          {check.fingerprintVerdict === 'first-seen' && <div className="mb-3 rounded-lg border border-sky-500/25 bg-sky-500/5 p-3 text-xs text-sky-100">{verdict?.title}. Basic connection, route, DNS, and security checks are available; a comparison will be possible on the next check.</div>}
          <div className="space-y-2">
            {check.safeChecks.map((finding, index) => <article key={`${finding.name}-${index}`} className={`rounded-lg border p-3 ${findingStyle[finding.status] || findingStyle.INFO}`}>
              <div className="flex items-center justify-between gap-3"><h3 className="text-xs font-bold">{finding.name}</h3><span className="text-[10px] font-bold tracking-wider">{finding.status}</span></div>
              <p className="mt-1 text-xs leading-relaxed opacity-85">{finding.evidence}</p>
            </article>)}
          </div>
          <p className="mt-3 text-[10px] text-slate-500">Checked {new Date(check.checkedAt).toLocaleString()} · Gateway and DNS response times are point-in-time readings and can vary.</p>
        </section>

        <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="mb-3 flex items-center gap-2"><Router className="h-4 w-4 text-amber-300" /><h2 className="text-sm font-bold">Wi-Fi Autopsy</h2></div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <div className={`text-[10px] font-semibold uppercase tracking-wider ${muted}`}>Network fingerprint</div>
            <div className={`mt-1 text-sm font-bold ${verdict?.tone || 'text-slate-300'}`}>{verdict?.title || 'Not checked'}</div>
            {check.fingerprintVerdict === 'unavailable' && <p className="mt-1 text-xs text-amber-200">{check.reason || 'Windows did not expose enough live values to save or compare a fingerprint.'}</p>}
          </div>
          <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <div className={`text-[10px] font-semibold uppercase tracking-wider ${muted}`}>Authorized channel observations</div>
            <p className="mt-1 text-sm text-slate-200">{check.authorizedNeighborCount} approved access point(s) observed on this band.</p>
            <p className="mt-1 text-xs text-slate-400">{check.observedAuthorizedChannels.length ? `Observed channels: ${check.observedAuthorizedChannels.join(', ')}` : 'No channel observations available.'}</p>
            <p className="mt-2 text-xs text-slate-300">{check.recommendedObservedChannel ? `Lowest-overlap observed channel: ${check.recommendedObservedChannel}. Ask the network owner before changing the router.` : 'No alternative channel recommendation: there are not enough authorized observations or no lower-overlap observed channel was found.'}</p>
          </div>
          <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <div className={`text-[10px] font-semibold uppercase tracking-wider ${muted}`}>Conclusion</div>
            <p className="mt-1 text-sm font-semibold text-slate-100">{check.conclusion || 'No conclusion available.'}</p>
            <p className="mt-2 text-xs leading-relaxed text-slate-400">{check.recommendation}</p>
          </div>
          {check.status === 'Partial' && <div className="mt-3 flex gap-2 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 text-xs text-amber-100"><AlertTriangle className="h-4 w-4 shrink-0" />{check.reason}</div>}
          {check.fingerprintVerdict === 'matches' && <div className="mt-3 flex items-center gap-2 text-xs text-emerald-300"><Check className="h-4 w-4" />Saved network details match this connection.</div>}
        </section>
      </div>
    </>}
  </section>;
};

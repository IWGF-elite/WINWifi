import React, { useEffect, useState } from 'react';
import { CheckCircle2, CircleHelp, XCircle } from 'lucide-react';
import { NativeBridgeClient } from '../services/bridgeClient';
import { BridgeHealthStatus } from '../types';

interface NativeDesktopPanelProps {
  isDarkMode: boolean;
}

export const NativeDesktopPanel: React.FC<NativeDesktopPanelProps> = ({ isDarkMode }) => {
  const [health, setHealth] = useState<BridgeHealthStatus | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const result = await NativeBridgeClient.getInstance().checkHealth();
        if (active) { setHealth(result); setError(''); }
      } catch (reason) {
        if (active) setError(reason instanceof Error ? reason.message : String(reason));
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  const caps = health?.capabilities;
  const cards = [
    { name: 'Windows WLAN scan', available: health?.isWindows === true && health.isNativeWlanAvailable, detail: caps?.nativeWlanReason || 'Waiting for a Windows service response.' },
    { name: 'PCAP / PCAPNG import', available: caps?.eapolParserAvailable === true, detail: caps?.eapolParserReason || 'Parser status is unavailable.' },
    { name: 'Local SQLite storage', available: caps?.sqliteAvailable === true, detail: caps?.sqliteReason || 'Storage status is unavailable.' },
    { name: 'Passive 802.11 capture', available: caps?.monitorModeSupported === true, detail: caps?.monitorModeReason || 'Capture status is unavailable.' }
  ];

  return <section className="mx-auto max-w-5xl space-y-4 p-4">
    <header className={`rounded-xl border p-5 ${isDarkMode ? 'border-slate-800 bg-slate-900' : 'border-slate-200 bg-white'}`}>
      <h1 className="text-lg font-bold text-slate-100">System Capabilities <span className="ml-2 text-xs font-medium text-slate-400">3.0.4</span></h1>
      <p className="mt-1 text-xs text-slate-400">Current status from this Windows device.</p>
      <div className="mt-3 text-xs text-slate-300">Service: <span className={health?.status === 'healthy' || health?.status === 'online' ? 'text-emerald-400' : 'text-amber-300'}>{health?.status || (error ? 'Unavailable' : 'Checking')}</span>{health?.activeAdapterName ? ` · Adapter: ${health.activeAdapterName}` : ''}</div>
      {error && <p role="status" className="mt-2 text-xs text-amber-300">{error}</p>}
    </header>
    <div className="grid gap-3 md:grid-cols-2">
      {cards.map(card => <article key={card.name} className={`rounded-xl border p-4 ${isDarkMode ? 'border-slate-800 bg-slate-900' : 'border-slate-200 bg-white'}`}>
        <div className="flex items-center gap-2">{card.available ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : health ? <XCircle className="h-4 w-4 text-amber-400" /> : <CircleHelp className="h-4 w-4 text-slate-400" />}<h2 className="text-sm font-semibold text-slate-100">{card.name}</h2><span className={`ml-auto text-[10px] uppercase ${card.available ? 'text-emerald-400' : 'text-amber-300'}`}>{card.available ? 'Available' : health ? 'Unavailable' : 'Checking'}</span></div>
        <p className="mt-2 text-xs text-slate-400">{card.detail}</p>
      </article>)}
    </div>
  </section>;
};

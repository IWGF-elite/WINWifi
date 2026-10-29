import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AccessPoint, WalkSignalReading } from '../types';
import { NativeBridgeClient } from '../services/bridgeClient';

interface WalkModePanelProps {
  accessPoints: AccessPoint[];
  bridgeConnected: boolean;
}

const currentDbm = (ap?: AccessPoint) => ap && Number.isFinite(ap.rssi) ? ap.rssi : null;
const qualityLabel = (dbm: number | null) => dbm === null ? 'No live reading' : dbm >= -55 ? 'Strong' : dbm >= -67 ? 'Good' : dbm >= -78 ? 'Weak' : 'Cold';
const qualityColor = (dbm: number) => dbm >= -55 ? 'bg-emerald-400' : dbm >= -67 ? 'bg-lime-400' : dbm >= -78 ? 'bg-amber-400' : 'bg-rose-500';

export const crossedSignalThreshold = (previousDbm: number | null, currentDbm: number | null, thresholdDbm: number) =>
  previousDbm !== null && currentDbm !== null && previousDbm < thresholdDbm && currentDbm >= thresholdDbm;

export const WalkModePanel: React.FC<WalkModePanelProps> = ({ accessPoints, bridgeConnected }) => {
  const bridge = useMemo(() => NativeBridgeClient.getInstance(), []);
  const liveAccessPoints = useMemo(() => bridgeConnected
    ? accessPoints
      .filter(ap => ap.dataSourceOrigin === 'LIVE_WINDOWS' && ap.isActiveInCurrentScan !== false && ap.bssid)
      .sort((a, b) => a.ssid.localeCompare(b.ssid) || a.bssid.localeCompare(b.bssid))
    : [], [accessPoints, bridgeConnected]);
  const [selectedBssid, setSelectedBssid] = useState('');
  const [locationName, setLocationName] = useState('');
  const [minimumSignal, setMinimumSignal] = useState(-67);
  const [beepEnabled, setBeepEnabled] = useState(false);
  const [readings, setReadings] = useState<WalkSignalReading[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const audioRef = useRef<AudioContext | null>(null);
  const previousRef = useRef<{ bssid: string; dbm: number | null }>({ bssid: '', dbm: null });

  const playSignalBeep = useCallback(async () => {
    const context = audioRef.current;
    if (!context) return false;
    try {
      if (context.state !== 'running') await context.resume();
      if (context.state !== 'running') return false;
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      const start = context.currentTime;
      oscillator.type = 'sine';
      oscillator.frequency.setValueAtTime(880, start);
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.08, start + 0.015);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.18);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start(start);
      oscillator.stop(start + 0.19);
      return true;
    } catch {
      return false;
    }
  }, []);

  const selectedAp = liveAccessPoints.find(ap => ap.bssid.toLowerCase() === selectedBssid.toLowerCase()) || liveAccessPoints[0];
  const dbm = currentDbm(selectedAp);

  const reload = useCallback(async () => {
    if (!bridgeConnected) return;
    try { setReadings(await bridge.getWalkSignalReadings()); setError(''); }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
  }, [bridge, bridgeConnected]);

  useEffect(() => { void reload(); }, [reload]);
  useEffect(() => {
    if (!selectedAp) return;
    setSelectedBssid(selectedAp.bssid);
  }, [selectedAp?.bssid]);

  useEffect(() => {
    const previous = previousRef.current;
    if (beepEnabled && selectedAp && previous.bssid === selectedAp.bssid && crossedSignalThreshold(previous.dbm, dbm, minimumSignal)) {
      void playSignalBeep().then(played => {
        if (!played) setError('Signal beep could not play. Press the signal beep button to reactivate Windows audio.');
      });
    }
    previousRef.current = { bssid: selectedAp?.bssid || '', dbm };
  }, [beepEnabled, dbm, minimumSignal, playSignalBeep, selectedAp]);

  const toggleBeep = async () => {
    if (beepEnabled) {
      setBeepEnabled(false);
      await audioRef.current?.close().catch(() => undefined);
      audioRef.current = null;
      setMessage('Signal beep turned off.');
      return;
    }
    const AudioContextType = window.AudioContext;
    if (!AudioContextType) { setError('Audio alerts are unavailable in this Windows audio environment.'); return; }
    try {
      audioRef.current = new AudioContextType();
      await audioRef.current.resume();
      const played = await playSignalBeep();
      if (!played) throw new Error('audio-playback-failed');
      previousRef.current = { bssid: selectedAp?.bssid || '', dbm };
      setBeepEnabled(true); setError(''); setMessage('Signal beep is on. Test tone played; it will sound when the selected network reaches the threshold.');
    } catch {
      await audioRef.current?.close().catch(() => undefined);
      audioRef.current = null;
      setError('Windows did not allow an audio alert to start. Check the device volume, then try again.');
    }
  };

  const recordLocation = async () => {
    if (!bridgeConnected || !selectedAp || !locationName.trim()) return;
    setBusy(true); setError(''); setMessage('');
    try {
      const reading = await bridge.recordWalkSignalReading(selectedAp.bssid, locationName.trim());
      setReadings(previous => [reading, ...previous]);
      setLocationName('');
      setMessage(`Saved ${reading.rssiDbm} dBm at ${reading.locationName}.`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };

  const locations = useMemo(() => {
    const grouped = new Map<string, WalkSignalReading[]>();
    for (const reading of readings.filter(item => item.bssid.toLowerCase() === (selectedAp?.bssid || '').toLowerCase())) {
      const list = grouped.get(reading.locationName) || [];
      list.push(reading); grouped.set(reading.locationName, list);
    }
    return [...grouped.entries()].map(([name, values]) => ({
      name,
      count: values.length,
      average: Math.round(values.reduce((sum, item) => sum + item.rssiDbm, 0) / values.length),
      latest: values[0].capturedAt
    })).sort((a, b) => a.name.localeCompare(b.name));
  }, [readings, selectedAp?.bssid]);

  const bars = dbm === null ? 0 : dbm >= -55 ? 4 : dbm >= -67 ? 3 : dbm >= -78 ? 2 : 1;

  return <div className="mx-auto w-full max-w-[1280px] space-y-4 text-slate-100">
    <header className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900 p-4">
      <div><h1 className="text-lg font-bold">Walk Mode &amp; Rogue Hunter</h1><p className="mt-1 text-xs text-slate-400">Track one access point’s live signal and save readings at locations you name.</p></div>
      <div className="flex flex-wrap gap-2"><button onClick={() => void reload()} disabled={!bridgeConnected || busy} className="whitespace-nowrap rounded-lg border border-slate-700 px-3 py-2 text-xs hover:bg-slate-800 disabled:opacity-50">Refresh locations</button><button onClick={() => void toggleBeep()} disabled={!selectedAp || !bridgeConnected} className={`whitespace-nowrap rounded-lg border px-3 py-2 text-xs font-semibold ${beepEnabled ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200' : 'border-slate-700 hover:bg-slate-800'}`}>{beepEnabled ? 'Signal beep on' : 'Enable signal beep'}</button></div>
    </header>
    {!bridgeConnected && <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">Connect the Windows bridge to use live signal readings.</p>}
    {error && <p role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</p>}
    {message && <p role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200">{message}</p>}
    <section className="grid gap-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(280px,0.8fr)]">
      <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <label className="block space-y-2 text-xs text-slate-400">Access point<select value={selectedAp?.bssid || ''} onChange={event => setSelectedBssid(event.target.value)} disabled={!liveAccessPoints.length} className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"><option value="">No live access points</option>{liveAccessPoints.map(ap => <option key={ap.bssid} value={ap.bssid}>{ap.ssid || '(hidden network)'} · {ap.bssid}</option>)}</select></label>
        {selectedAp ? <><div className="flex flex-wrap items-end justify-between gap-4"><div><div className="text-[11px] uppercase tracking-wide text-slate-500">Live signal</div><div className="mt-1 text-4xl font-black tabular-nums">{dbm ?? '—'}<span className="ml-1 text-base font-medium text-slate-400">dBm</span></div><div className="mt-1 text-sm font-semibold text-cyan-300">{qualityLabel(dbm)}</div></div><div className="flex h-14 items-end gap-1.5" aria-label={`Signal ${qualityLabel(dbm)}`}>{[0, 1, 2, 3].map(index => <span key={index} className={`w-7 rounded-t ${index < bars && dbm !== null ? qualityColor(dbm) : 'bg-slate-700'}`} style={{ height: `${16 + index * 10}px` }} />)}</div></div>
          <div className="text-[11px] text-slate-500">{selectedAp.ssid || 'Hidden network'} · {selectedAp.bssid} · Ch {selectedAp.channel} · {selectedAp.band}</div>
          <label className="block min-w-0 text-xs text-slate-400"><span className="block leading-5">Beep when signal reaches <strong className="font-semibold text-slate-200">{minimumSignal} dBm</strong></span><input aria-label="Signal threshold for beep alert" type="range" min="-85" max="-45" value={minimumSignal} onChange={event => setMinimumSignal(Number(event.target.value))} className="mt-2 block w-full accent-cyan-400" /></label>
        </> : <p className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-400">No current live WLAN scan reading is available. Turn on the Wi-Fi radio and refresh the scan.</p>}
      </div>
      <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4"><h2 className="text-sm font-bold">Save a named location</h2><p className="text-xs text-slate-400">Each saved point uses the current Windows scan reading. Enter a room or place name, then record while standing there.</p><label className="block space-y-2 text-xs text-slate-400">Location name<input value={locationName} onChange={event => setLocationName(event.target.value)} maxLength={128} placeholder="e.g. Conference room" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600" /></label><button onClick={() => void recordLocation()} disabled={!bridgeConnected || !selectedAp || !locationName.trim() || busy} className="w-full rounded-lg bg-cyan-600 px-3 py-2.5 text-sm font-bold text-white hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-50">{busy ? 'Saving…' : 'Record current signal'}</button></div>
    </section>
    <section className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4"><div className="flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-sm font-bold">Signal by named location</h2><p className="mt-1 text-[11px] text-slate-500">Average of real saved readings for the selected access point. Locations are labels, not GPS coordinates.</p></div><span className="text-xs text-slate-500">{locations.length} locations</span></div>
      {!locations.length ? <p className="rounded-lg border border-dashed border-slate-700 p-4 text-sm text-slate-500">No signal measurements have been saved for this access point. Record a reading at a named location to begin.</p> : <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">{locations.map(point => <article key={point.name} className="rounded-lg border border-slate-800 bg-slate-950/70 p-3"><div className="flex items-center justify-between gap-2"><h3 className="truncate text-sm font-semibold">{point.name}</h3><strong className="tabular-nums text-cyan-300">{point.average} dBm</strong></div><div className="mt-2 h-2 overflow-hidden rounded bg-slate-800"><div className={`h-full rounded ${qualityColor(point.average)}`} style={{ width: `${Math.max(0, Math.min(100, (point.average + 100) * 2))}%` }} /></div><p className="mt-2 text-[10px] text-slate-500">{point.count} real sample{point.count === 1 ? '' : 's'} · latest {new Date(point.latest).toLocaleString()}</p></article>)}</div>}
    </section>
  </div>;
};

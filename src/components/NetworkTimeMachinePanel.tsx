import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Clock3, LoaderCircle, Pause, Play, RefreshCw } from 'lucide-react';
import { NetworkTimelineBounds, NetworkTimelineEntityState, NetworkTimelineState } from '../types';
import { NativeBridgeClient } from '../services/bridgeClient';

interface NetworkTimeMachinePanelProps {
  bridgeConnected: boolean;
}

const timeValue = (value?: string | null) => value ? new Date(value).getTime() : 0;
const displayTime = (value?: string | null) => value ? new Date(value).toLocaleString() : 'Unknown';
const duration = (first?: string, last?: string) => {
  const milliseconds = Math.max(0, timeValue(last) - timeValue(first));
  if (!milliseconds) return 'Under one scan interval';
  const seconds = Math.floor(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
};

const entityLabel = (entity: NetworkTimelineEntityState) => entity.entityType === 'AP'
  ? (entity.ssid || '(hidden network)')
  : (entity.hostname || entity.ipAddress || 'Device');

const sameConfiguration = (left: NetworkTimelineEntityState, right?: NetworkTimelineEntityState) => !!right &&
  left.ssid === right.ssid && left.channel === right.channel && left.security === right.security &&
  left.cipher === right.cipher && left.band === right.band && left.isPresent === right.isPresent;

function EntityTable({ title, entities }: { title: string; entities: NetworkTimelineEntityState[] }) {
  return <section className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
    <header className="border-b border-slate-800 px-4 py-3 text-sm font-semibold text-slate-100">{title} <span className="ml-1 text-xs font-normal text-slate-500">{entities.length}</span></header>
    {!entities.length ? <p className="p-4 text-sm text-slate-500">No records existed at this point in the saved history.</p> :
      <div className="max-h-72 overflow-auto"><table className="w-full text-left text-xs"><thead className="sticky top-0 bg-slate-950 text-slate-400"><tr>
        <th className="px-3 py-2">Name / Address</th><th className="px-3 py-2">Details</th><th className="px-3 py-2">First seen</th><th className="px-3 py-2">Last seen</th><th className="px-3 py-2">Observed</th>
      </tr></thead><tbody>{entities.map(entity => <tr key={`${entity.entityType}-${entity.entityKey}`} className="border-t border-slate-800/70">
        <td className="px-3 py-2"><div className="font-medium text-slate-200">{entityLabel(entity)}</div><div className="font-mono text-[10px] text-slate-500">{entity.bssid || entity.ipAddress}</div></td>
        <td className="px-3 py-2 text-slate-300">{entity.entityType === 'AP' ? `${entity.security || 'Unknown'} · Ch ${entity.channel ?? '—'} · ${entity.vendor || 'Vendor unknown'}` : `${entity.macAddress || 'MAC unavailable'} · ${entity.deviceType || 'Type unknown'}`}</td>
        <td className="px-3 py-2 text-slate-400">{displayTime(entity.firstSeenAt)}</td><td className="px-3 py-2 text-slate-400">{displayTime(entity.lastSeenAt)}</td>
        <td className="px-3 py-2"><span className={entity.isPresent ? 'text-emerald-300' : 'text-slate-500'}>{entity.isPresent ? 'Present' : 'Not present'}</span><div className="text-[10px] text-slate-500">{duration(entity.firstSeenAt, entity.lastSeenAt)}</div></td>
      </tr>)}</tbody></table></div>}
  </section>;
}

export const NetworkTimeMachinePanel: React.FC<NetworkTimeMachinePanelProps> = ({ bridgeConnected }) => {
  const bridge = useMemo(() => NativeBridgeClient.getInstance(), []);
  const [bounds, setBounds] = useState<NetworkTimelineBounds | null>(null);
  const [selectedAt, setSelectedAt] = useState(0);
  const [compareAt, setCompareAt] = useState(0);
  const [current, setCurrent] = useState<NetworkTimelineState | null>(null);
  const [comparison, setComparison] = useState<NetworkTimelineState | null>(null);
  const [playing, setPlaying] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const selectedAtRef = useRef(selectedAt);
  const compareAtRef = useRef(compareAt);
  useEffect(() => { selectedAtRef.current = selectedAt; }, [selectedAt]);
  useEffect(() => { compareAtRef.current = compareAt; }, [compareAt]);

  const reload = useCallback(async () => {
    if (!bridgeConnected) return;
    setBusy(true); setError('');
    try {
      const next = await bridge.getNetworkTimelineBounds();
      setBounds(next);
      const earliest = timeValue(next.earliestAt), latest = timeValue(next.latestAt);
      if (next.hasData && earliest && latest) {
      const initial = selectedAtRef.current >= earliest && selectedAtRef.current <= latest ? selectedAtRef.current : latest;
      const comparisonPoint = compareAtRef.current >= earliest && compareAtRef.current <= latest ? compareAtRef.current : earliest;
        setSelectedAt(initial); setCompareAt(comparisonPoint);
      } else { setCurrent(null); setComparison(null); }
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  }, [bridge, bridgeConnected]);

  useEffect(() => { void reload(); }, [reload]);

  useEffect(() => {
    if (!bounds?.hasData || !selectedAt) return;
    let active = true;
    const load = async () => {
      setBusy(true); setError('');
      try {
        const [point, compare] = await Promise.all([
          bridge.getNetworkTimelineState(new Date(selectedAt).toISOString()),
          bridge.getNetworkTimelineState(new Date(compareAt || timeValue(bounds.earliestAt)).toISOString())
        ]);
        if (active) { setCurrent(point); setComparison(compare); }
      } catch (cause) { if (active) setError(cause instanceof Error ? cause.message : String(cause)); }
      finally { if (active) setBusy(false); }
    };
    void load();
    return () => { active = false; };
  }, [bridge, bounds, selectedAt, compareAt]);

  useEffect(() => {
    if (!playing || !bounds?.hasData) return;
    const min = timeValue(bounds.earliestAt), max = timeValue(bounds.latestAt);
    const timer = window.setInterval(() => setSelectedAt(value => value >= max ? min : Math.min(max, value + Math.max(1000, Math.floor((max - min) / 100)))), 900);
    return () => window.clearInterval(timer);
  }, [playing, bounds]);

  const min = timeValue(bounds?.earliestAt), max = timeValue(bounds?.latestAt);
  const previousAps = new Map((comparison?.accessPoints || []).map(ap => [ap.bssid || ap.entityKey, ap]));
  const changedAps = (current?.accessPoints || []).filter(ap => !sameConfiguration(ap, previousAps.get(ap.bssid || ap.entityKey)));
  const countsAtComparison = { aps: comparison?.accessPoints.filter(ap => ap.isPresent).length || 0, devices: comparison?.devices.filter(device => device.isPresent).length || 0 };
  const countsNow = { aps: current?.accessPoints.filter(ap => ap.isPresent).length || 0, devices: current?.devices.filter(device => device.isPresent).length || 0 };

  return <div className="mx-auto w-full max-w-[1280px] space-y-4 text-slate-100">
    <header className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900 p-4">
      <div className="flex items-center gap-3"><div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-cyan-300"><Clock3 className="h-5 w-5" /></div><div><h1 className="text-lg font-bold">Network Time Machine</h1><p className="text-xs text-slate-400">Review saved network observations and compare two points in time.</p></div></div>
      <button onClick={() => void reload()} disabled={!bridgeConnected || busy} className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold hover:bg-slate-800 disabled:opacity-50">{busy ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}Reload history</button>
    </header>
    {!bridgeConnected && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">Connect the Windows bridge to read local history.</div>}
    {error && <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</div>}
    {bounds?.hasData && min > 0 && max >= min ? <>
      <section className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="grid gap-4 lg:grid-cols-2">
          <label className="space-y-2 text-xs text-slate-400">View as of <span className="block font-medium text-slate-100">{displayTime(new Date(selectedAt).toISOString())}</span><input aria-label="History time" type="range" min={min} max={max} value={Math.min(max, Math.max(min, selectedAt))} onChange={event => { setPlaying(false); setSelectedAt(Number(event.target.value)); }} className="w-full accent-cyan-400" /></label>
          <label className="space-y-2 text-xs text-slate-400">Compare with <span className="block font-medium text-slate-100">{displayTime(new Date(compareAt).toISOString())}</span><input aria-label="Comparison time" type="range" min={min} max={max} value={Math.min(max, Math.max(min, compareAt))} onChange={event => setCompareAt(Number(event.target.value))} className="w-full accent-amber-400" /></label>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500"><span>{displayTime(bounds.earliestAt)} → {displayTime(bounds.latestAt)}</span><button onClick={() => setPlaying(value => !value)} className="inline-flex items-center gap-1 rounded-md border border-slate-700 px-2 py-1 text-slate-200">{playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}{playing ? 'Pause replay' : 'Replay history'}</button></div>
      </section>
      <section className="grid gap-3 sm:grid-cols-3"><div className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs">Saved legacy scan observations <strong className="ml-2 text-cyan-300">{bounds.legacyObservationCount.toLocaleString()}</strong></div><div className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs">Recorded changes <strong className="ml-2 text-cyan-300">{bounds.changeCount.toLocaleString()}</strong></div><div className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs">{countsAtComparison.aps} APs / {countsAtComparison.devices} devices → {countsNow.aps} APs / {countsNow.devices} devices</div></section>
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"><h2 className="text-sm font-bold">Changes since comparison point</h2><p className="mt-1 text-xs text-slate-500">{changedAps.length} access point(s) differ or were added/removed. Device changes are listed in the event timeline.</p>{changedAps.length > 0 && <div className="mt-3 flex flex-wrap gap-2">{changedAps.slice(0, 20).map(ap => <span key={ap.entityKey} className="rounded-md border border-amber-500/20 bg-amber-500/5 px-2 py-1 text-xs text-amber-200">{entityLabel(ap)} · {ap.isPresent ? 'present' : 'not present'}</span>)}</div>}</section>
      <EntityTable title="Access points at selected time" entities={current?.accessPoints || []} />
      <EntityTable title="Devices at selected time" entities={current?.devices || []} />
      <section className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60"><header className="border-b border-slate-800 px-4 py-3 text-sm font-semibold">Change timeline <span className="ml-1 text-xs font-normal text-slate-500">{current?.changes.length || 0}</span></header>{!current?.changes.length ? <p className="p-4 text-sm text-slate-500">No recorded changes by this time.</p> : <div className="max-h-80 overflow-auto">{[...current.changes].reverse().map(change => <div key={change.id} className="border-b border-slate-800/70 px-4 py-3"><div className="flex flex-wrap justify-between gap-2"><span className="text-xs font-semibold text-cyan-300">{change.eventType.replaceAll('_', ' ')}</span><time className="text-[10px] text-slate-500">{displayTime(change.occurredAt)}</time></div><p className="mt-1 text-xs text-slate-300">{change.summary}</p></div>)}</div>}</section>
    </> : <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5"><h2 className="text-sm font-semibold">{bounds?.message || 'History has not loaded yet.'}</h2><p className="mt-2 text-xs leading-relaxed text-slate-400">{bounds?.legacyObservationCount ? `${bounds.legacyObservationCount.toLocaleString()} earlier scan observations are available. Reload history to read them.` : 'History begins as live scans observe changes. There are no saved observations for this project yet.'}</p></section>}
  </div>;
};

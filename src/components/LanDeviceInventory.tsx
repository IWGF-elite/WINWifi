import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, Download, RefreshCw, Search, Router, ShieldAlert, Wifi, WifiOff } from 'lucide-react';
import { LanDeviceRecord, LocalNetworkActivity, LocalNetworkInfo } from '../types';
import { NativeBridgeClient } from '../services/bridgeClient';
import { downloadBlob } from '../services/download';
import { ProcessingOrb } from './ProcessingOrb';

interface Props { adapterId: string; }
type Filter = 'all' | 'online' | 'new' | 'known' | 'unknown';
type Sort = 'ip' | 'hostname' | 'vendor' | 'state';

const csv = (value: unknown) => '"' + String(value ?? '').replace(/"/g, '""') + '"';
const dateText = (value: string) => value ? new Date(value).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' }) : 'Not recorded';

export const formatScanAge = (scannedAt: string | undefined, now = Date.now()): string => {
  if (!scannedAt) return 'No completed scan yet';
  const timestamp = Date.parse(scannedAt);
  if (!Number.isFinite(timestamp)) return 'Scan time unavailable';
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < 60) return `Updated ${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `Updated ${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `Updated ${hours}h ${minutes % 60}m ago`;
};

const ScanAge: React.FC<{ scannedAt?: string; now: number }> = ({ scannedAt, now }) => {
  return <>{scannedAt ? `Last device check ${dateText(scannedAt)} · ${formatScanAge(scannedAt, now)}` : 'No live device check yet'}</>;
};

const formatAge = (timestamp: string | undefined, now: number): string => {
  if (!timestamp) return 'not recorded';
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed)) return 'time unavailable';
  return formatScanAge(new Date(parsed).toISOString(), now).replace(/^Updated /, '');
};

export const LanDeviceInventory: React.FC<Props> = ({ adapterId }) => {
  const [network, setNetwork] = useState<LocalNetworkInfo | null>(null);
  const [activity, setActivity] = useState<LocalNetworkActivity | null>(null);
  const [devices, setDevices] = useState<LanDeviceRecord[]>([]);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityError, setActivityError] = useState('');
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const [sort, setSort] = useState<Sort>('ip');
  const [selected, setSelected] = useState<LanDeviceRecord | null>(null);
  const [fullPortScan, setFullPortScan] = useState(false);
  const [probesPerSecond, setProbesPerSecond] = useState(100);
  const [checkingInventory, setCheckingInventory] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const inventoryRequestRef = useRef(false);
  const scanInProgressRef = useRef(false);

  const refreshInventory = useCallback(async (showFailure = false) => {
    if (!adapterId || inventoryRequestRef.current || scanInProgressRef.current) return;
    inventoryRequestRef.current = true;
    setCheckingInventory(true);
    try {
      const snapshot = await NativeBridgeClient.getInstance().getLocalNetworkDevices(adapterId);
      const refreshedDevices = snapshot.devices || [];
      setDevices(refreshedDevices);
      setNetwork(current => ({
        ...(current || snapshot),
        ...snapshot,
        devices: refreshedDevices,
        scannedAt: snapshot.scannedAt || current?.scannedAt
      }));
      if (showFailure) setError('');
    } catch (reason) {
      if (showFailure) setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      inventoryRequestRef.current = false;
      setCheckingInventory(false);
    }
  }, [adapterId]);

  const load = async () => {
    if (!adapterId) { setNetwork(null); setDevices([]); return; }
    const bridge = NativeBridgeClient.getInstance();
    setLoading(true);
    setActivityLoading(true);
    setError('');
    setActivityError('');
    const infoTask = bridge.getLocalNetworkInfo(adapterId).then(info => {
      setNetwork(current => ({ ...info, scannedAt: info.scannedAt || current?.scannedAt }));
    }).catch(reason => {
      setError(reason instanceof Error ? reason.message : String(reason));
    });
    const devicesTask = refreshInventory(true);
    const activityTask = bridge.getLocalNetworkActivity().then(currentActivity => {
      setActivity(currentActivity);
      setActivityError(currentActivity.status === 'Available' ? '' : currentActivity.reason || 'Windows did not return connection data.');
    }).catch(reason => {
      setActivityError(reason instanceof Error ? reason.message : String(reason));
    }).finally(() => {
      setActivityLoading(false);
    });
    await Promise.all([infoTask, devicesTask]);
    setLoading(false);
    await activityTask;
  };

  useEffect(() => {
    setNetwork(null);
    setDevices([]);
    setError('');
    void load();
  }, [adapterId]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!adapterId) return;
    const timer = window.setInterval(() => void refreshInventory(false), 4000);
    return () => window.clearInterval(timer);
  }, [adapterId, refreshInventory]);

  useEffect(() => {
    if (!selected) return;
    const current = devices.find(device => device.ipAddress === selected.ipAddress);
    if (current && current !== selected) setSelected(current);
  }, [devices, selected]);

  const scan = async () => {
    if (!adapterId || busy) return;
    scanInProgressRef.current = true;
    setBusy(true);
    setError('');
    try {
      const result = await NativeBridgeClient.getInstance().scanLocalNetwork(
        adapterId,
        { fullPortScan, probesPerSecond },
        network || undefined
      );
      const completedResult = {
        ...result,
        scannedAt: result.cancelled ? (result.scannedAt || network?.scannedAt) : (result.scannedAt || new Date().toISOString()),
        devices: [...(result.devices || [])]
      };
      setNetwork(completedResult);
      setDevices(completedResult.devices);
      if (result.cancelled) setError(result.reason || 'Scan cancelled.');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      scanInProgressRef.current = false;
      setBusy(false);
    }
  };

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return devices.filter(d => {
      if (filter === 'online' && !d.isOnline) return false;
      if (filter === 'new' && !d.isNew) return false;
      if (filter === 'known' && !d.isKnown) return false;
      if (filter === 'unknown' && d.isKnown) return false;
      return !q || [d.ipAddress, d.macAddress, d.hostname, d.vendor, d.deviceType].some(v => (v || '').toLowerCase().includes(q));
    }).sort((a, b) => {
      if (sort === 'hostname') return a.hostname.localeCompare(b.hostname) || a.ipAddress.localeCompare(b.ipAddress, undefined, { numeric: true });
      if (sort === 'vendor') return a.vendor.localeCompare(b.vendor) || a.ipAddress.localeCompare(b.ipAddress, undefined, { numeric: true });
      if (sort === 'state') return Number(b.isOnline) - Number(a.isOnline) || a.ipAddress.localeCompare(b.ipAddress, undefined, { numeric: true });
      return a.ipAddress.localeCompare(b.ipAddress, undefined, { numeric: true });
    });
  }, [devices, filter, search, sort]);

  const remoteIpSummary = useMemo(() => {
    const byIp = new Map<string, { tcp: number; udp: number; processes: Set<string> }>();
    for (const connection of activity?.connections || []) {
      if (!connection.remoteAddress || connection.remotePort <= 0) continue;
      const current = byIp.get(connection.remoteAddress) || { tcp: 0, udp: 0, processes: new Set<string>() };
      if (connection.protocol === 'TCP') current.tcp++;
      else current.udp++;
      current.processes.add(connection.processName || `PID ${connection.processId}`);
      byIp.set(connection.remoteAddress, current);
    }
    return [...byIp.entries()].map(([ipAddress, counts]) => ({ ipAddress, ...counts }))
      .sort((a, b) => (b.tcp + b.udp) - (a.tcp + a.udp) || a.ipAddress.localeCompare(b.ipAddress, undefined, { numeric: true }));
  }, [activity]);

  const exportCsv = () => {
    const fields = ['IP', 'MAC', 'Vendor', 'Hostname', 'Type', 'Online', 'Known', 'New', 'Randomized MAC', 'First seen', 'Last seen', 'Last checked', 'OS hint', 'Open TCP services'];
    const rows = visible.map(d => [d.ipAddress, d.macAddress, d.vendor, d.hostname, d.deviceType, d.isOnline, d.isKnown, d.isNew, d.isRandomizedMac, d.firstSeen, d.lastSeen, d.lastCheckedAt, d.osGuess, d.openPorts.map(p => p.port + '/' + p.service + (p.banner ? ' ' + p.banner : '')).join('; ')]);
    downloadBlob(new Blob([[fields, ...rows].map(row => row.map(csv).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }), 'winwifi-local-device-inventory.csv');
  };

  const markKnown = async (device: LanDeviceRecord) => {
    if (!network?.networkId) return;
    const next = !device.isKnown;
    await NativeBridgeClient.getInstance().setLanDeviceKnown(network.networkId, device.ipAddress, next);
    setDevices(current => current.map(d => d.ipAddress === device.ipAddress ? { ...d, isKnown: next } : d));
    if (selected?.ipAddress === device.ipAddress) setSelected({ ...device, isKnown: next });
  };

  return <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h2 className="text-sm font-bold text-slate-100">Devices on this network</h2>
        <p className="mt-1 text-[11px] text-slate-400">
          {network?.status === 'Available'
            ? network.interfaceName + ' · ' + network.networkId + ' · ' + network.localIp
            : network?.reason || 'Select a Wi-Fi adapter to read local network details.'}
        </p>
      </div>
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={exportCsv} disabled={!visible.length} className="rounded-md border border-slate-700 px-3 py-1.5 text-xs text-slate-200 disabled:opacity-40"><Download className="mr-1 inline h-3.5 w-3.5" />CSV</button>
        <button type="button" onClick={() => downloadBlob(new Blob([JSON.stringify(visible, null, 2)], { type: 'application/json' }), 'winwifi-local-device-inventory.json')} disabled={!visible.length} className="rounded-md border border-slate-700 px-3 py-1.5 text-xs text-slate-200 disabled:opacity-40">JSON</button>
        {!busy && <label className="flex items-center gap-1 text-[10px] text-slate-400"><input type="checkbox" checked={fullPortScan} onChange={e => setFullPortScan(e.target.checked)} />Full TCP range</label>}
        {fullPortScan && !busy && <label className="text-[10px] text-slate-400">Rate <select value={probesPerSecond} onChange={e => setProbesPerSecond(Number(e.target.value))} className="rounded border border-slate-700 bg-slate-950 px-1.5 py-1 text-slate-200"><option value={25}>25/s</option><option value={50}>50/s</option><option value={100}>100/s</option><option value={250}>250/s</option></select></label>}
        {!busy ? <button type="button" onClick={() => void scan()} disabled={!adapterId || loading} className="rounded-md bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white disabled:cursor-wait disabled:opacity-40">{loading ? <ProcessingOrb state="working" size={20} label="Loading network devices" className="mr-1 inline-block align-middle" /> : <RefreshCw className="mr-1 inline h-3.5 w-3.5" />}{loading ? 'Loading devices…' : fullPortScan ? 'Scan all TCP ports' : 'Scan local network'}</button> : <button type="button" onClick={() => void NativeBridgeClient.getInstance().cancelLocalNetworkScan()} className="rounded-md bg-rose-700 px-3 py-1.5 text-xs font-semibold text-white">Cancel scan</button>}
      </div>
    </div>
    {network?.status === 'Available' && <div className="mt-3 grid gap-2 text-xs sm:grid-cols-3">
      <div className="rounded bg-slate-950/70 p-3"><div className="text-slate-500">Gateway</div>
        {network.gatewayIp ? <div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-slate-200"><span>{network.gatewayIp}</span><a href={'http://' + network.gatewayIp + '/'} target="_blank" rel="noreferrer" className="rounded bg-blue-700 px-2 py-1 font-sans text-white">Open router page</a></div> : <div className="mt-1 text-slate-400">Not reported by Windows</div>}
      </div>
      <div className="rounded bg-slate-950/70 p-3"><div className="text-slate-500">DNS servers</div><div className="mt-1 break-all font-mono text-slate-200">{network.dnsServers?.length ? network.dnsServers.join(' · ') : 'Not reported by Windows'}</div></div>
      <div className="rounded bg-slate-950/70 p-3"><div className="text-slate-500">DHCP servers</div><div className="mt-1 break-all font-mono text-slate-200">{network.dhcpServers?.length ? network.dhcpServers.join(' · ') : 'Not reported by Windows'}</div></div>
    </div>}
    <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><Activity className="h-3.5 w-3.5 text-cyan-400" />Current PC connections</div>
        <button type="button" onClick={() => void load()} disabled={!adapterId || busy || loading || activityLoading} className="rounded border border-slate-700 px-2 py-1 text-[10px] text-slate-300 disabled:opacity-40">{loading || activityLoading ? 'Refreshing…' : 'Refresh'}</button>
      </div>
      {activity?.status === 'Available' ? <>
        <p className="mt-1 text-[10px] text-slate-500">Windows TCP connections and UDP endpoints with process ownership · checked {dateText(activity.observedAt)}</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-3">
          <div className="rounded bg-slate-900 p-2 text-[10px] text-slate-300">{activity.connections.filter(c => c.protocol === 'TCP' && c.remotePort > 0).length} TCP connections</div>
          <div className="rounded bg-slate-900 p-2 text-[10px] text-slate-300">{activity.connections.filter(c => c.protocol === 'UDP').length} UDP endpoints</div>
          <div className="rounded bg-slate-900 p-2 text-[10px] text-slate-300">{remoteIpSummary.length} remote IPs in current TCP connections</div>
        </div>
        <div className="mt-2 max-h-36 overflow-auto rounded border border-slate-800">
          <table className="min-w-full text-left text-[10px]"><thead className="sticky top-0 bg-slate-900 text-slate-500"><tr>{['Remote IP', 'TCP flows', 'Processes'].map(h => <th key={h} className="px-2 py-1.5">{h}</th>)}</tr></thead>
            <tbody>{remoteIpSummary.map(row => <tr key={row.ipAddress} className="border-t border-slate-800 text-slate-300"><td className="px-2 py-1 font-mono">{row.ipAddress}</td><td className="px-2 py-1">{row.tcp}</td><td className="px-2 py-1">{[...row.processes].join(', ')}</td></tr>)}</tbody>
          </table>
          {!remoteIpSummary.length && <p className="p-2 text-[10px] text-slate-500">Windows reported no remote TCP endpoints. Per-IP byte totals are unavailable without packet capture.</p>}
        </div>
        <div className="mt-2 max-h-52 overflow-auto rounded border border-slate-800">
          <table className="min-w-full text-left text-[10px]"><thead className="sticky top-0 bg-slate-900 text-slate-500"><tr>{['Protocol', 'Local endpoint', 'Remote endpoint', 'State', 'Process'].map(h => <th key={h} className="px-2 py-1.5">{h}</th>)}</tr></thead>
            <tbody>{activity.connections.slice(0, 500).map((c, i) => <tr key={`${c.protocol}-${c.localAddress}-${c.localPort}-${c.remoteAddress}-${c.remotePort}-${c.processId}-${i}`} className="border-t border-slate-800 text-slate-300">
              <td className="px-2 py-1">{c.protocol}</td><td className="px-2 py-1 font-mono">{c.localAddress}:{c.localPort}</td><td className="px-2 py-1 font-mono">{c.remoteAddress ? `${c.remoteAddress}:${c.remotePort}` : '—'}</td><td className="px-2 py-1">{c.state}</td><td className="px-2 py-1">{c.processName} ({c.processId})</td>
            </tr>)}</tbody>
          </table>
          {activity.connections.length > 500 && <p className="p-2 text-[10px] text-slate-500">Showing 500 of {activity.connections.length} endpoints. Refine through Windows networking tools for the full list.</p>}
          {!activity.connections.length && <p className="p-3 text-[10px] text-slate-500">Windows returned no active TCP connections or UDP endpoints.</p>}
        </div>
      </> : <p className="mt-2 text-[10px] text-amber-300" aria-live="polite">{activityLoading ? 'Reading the current Windows connection table…' : activityError || activity?.reason || 'Windows connection data unavailable.'}</p>}
    </div>
    <div className="mt-3 flex flex-wrap items-center gap-2">
      <label className="relative min-w-[180px] flex-1"><Search className="absolute left-2 top-2 h-3.5 w-3.5 text-slate-500" /><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search IP, MAC, vendor, hostname" className="w-full rounded border border-slate-700 bg-slate-950 py-1.5 pl-7 pr-2 text-xs text-slate-200" /></label>
      <select value={filter} onChange={e => setFilter(e.target.value as Filter)} className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-200">
        <option value="all">All devices</option><option value="online">Online</option><option value="new">New</option><option value="known">Known</option><option value="unknown">Unreviewed</option>
      </select>
      <label className="flex items-center gap-1 text-[10px] text-slate-500">Sort
        <select aria-label="Sort devices" value={sort} onChange={e => setSort(e.target.value as Sort)} className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-200">
          <option value="ip">IP address</option><option value="hostname">Hostname</option><option value="vendor">Vendor</option><option value="state">Online first</option>
        </select>
      </label>
      <span className="inline-flex items-center gap-1.5 text-[10px] text-slate-400" role="status" aria-live="polite">
        {busy ? <><ProcessingOrb state="searching" size={20} label="Scanning the local network" /> Scanning…</> : loading ? <><ProcessingOrb state="working" size={20} label="Loading the device inventory" /> Loading inventory…</> : <>
          <Activity className="h-3 w-3 text-cyan-400" />
          <ScanAge scannedAt={network?.scannedAt} now={now} />
        </>}
      </span>
    </div>
    {error && <div className="mt-2 rounded border border-rose-800 bg-rose-950/40 p-2 text-xs text-rose-300">{error}</div>}
    {busy && <div className="mt-2 rounded border border-amber-700/50 bg-amber-950/30 p-2 text-[11px] text-amber-200" role="status" aria-live="polite">{fullPortScan ? `Probing ports 1–65535 on discovered hosts at ${probesPerSecond} attempts per second. The duration depends on responding devices; the scan can be cancelled at any time.` : 'Discovering devices and checking common services on the selected network. This can take several seconds; the scan can be cancelled at any time.'}</div>}
    {!busy && (checkingInventory || network?.checkingDevices) && <div className="mt-2 flex items-center gap-2 text-[10px] text-cyan-300" role="status" aria-live="polite"><ProcessingOrb state="searching" size={20} label="Checking known devices and discovering new hosts" />Checking known devices and discovering new hosts in the background…</div>}
    {network?.scannedAt && <p className="mt-2 text-[10px] text-slate-500">{network.portScanMode || 'Common ports'} · {network.portsScanned ?? 0} port attempts{network.cancelled ? ' · cancelled' : ''}</p>}
    <div className="mt-3 overflow-auto rounded border border-slate-800">
      <table className="min-w-full text-left text-[11px]">
        <thead className="bg-slate-950 text-slate-400"><tr>{['State', 'IP address', 'MAC address', 'Vendor', 'Hostname', 'Type', 'Ports', 'Review'].map(h => <th key={h} className="whitespace-nowrap px-2 py-2">{h}</th>)}</tr></thead>
        <tbody>{visible.map(d => <tr key={d.ipAddress} className="border-t border-slate-800 text-slate-300 hover:bg-slate-800/60">
          <td className="whitespace-nowrap px-2 py-2"><div className="flex items-center gap-1.5">{d.isOnline ? <Wifi className="h-3.5 w-3.5 text-emerald-400" /> : <WifiOff className="h-3.5 w-3.5 text-slate-500" />}<span className={d.isOnline ? 'text-emerald-300' : 'text-slate-400'}>{d.isOnline ? 'Online' : 'Offline'}</span></div><div className="mt-0.5 text-[9px] text-slate-500">Checked {formatAge(d.lastCheckedAt, now)} · last seen {formatAge(d.lastSeen, now)}</div></td>
          <td className="whitespace-nowrap px-2 py-2 font-mono"><button onClick={() => setSelected(d)} className="text-blue-300 hover:underline">{d.ipAddress}</button>{d.isNew && <span className="ml-1 rounded bg-amber-500/15 px-1 text-amber-300">NEW</span>}</td>
          <td className="whitespace-nowrap px-2 py-2 font-mono">{d.macAddress || 'Not in ARP cache'}{d.isRandomizedMac && <span title="Locally administered MAC" className="ml-1 text-amber-300">LAA</span>}</td>
          <td className="whitespace-nowrap px-2 py-2">{d.vendor}</td><td className="whitespace-nowrap px-2 py-2">{d.hostname || 'Not resolved'}</td><td className="whitespace-nowrap px-2 py-2">{d.deviceType}</td>
          <td className="px-2 py-2">{d.openPorts.length ? d.openPorts.map(p => <span key={p.port} title={p.riskReason || p.service} className={'mr-1 inline-flex rounded px-1 ' + (p.riskFlag ? 'bg-amber-500/15 text-amber-300' : 'bg-slate-800 text-slate-300')}>{p.port}</span>) : '—'}</td>
          <td className="whitespace-nowrap px-2 py-2"><button onClick={() => void markKnown(d)} className="rounded border border-slate-700 px-2 py-1 text-[10px]">{d.isKnown ? 'Known' : 'Mark known'}</button></td>
        </tr>)}</tbody>
      </table>
      {!visible.length && <div className="p-5 text-center text-xs text-slate-500">No LAN devices recorded. Scan the local network to discover responding hosts.</div>}
    </div>
    {selected && <div className="mt-3 rounded-lg border border-blue-800/60 bg-slate-950 p-3">
      <div className="flex items-center justify-between"><div className="flex items-center gap-2 text-sm font-semibold text-slate-100">{selected.deviceType === 'Gateway' ? <Router className="h-4 w-4 text-blue-400" /> : <ShieldAlert className="h-4 w-4 text-slate-400" />}{selected.ipAddress} · {selected.hostname || 'Unknown host'}</div><button onClick={() => setSelected(null)} className="text-xs text-slate-400">Close</button></div>
      <div className="mt-2 grid gap-2 text-[11px] text-slate-300 sm:grid-cols-2">
        <div>MAC: {selected.macAddress || 'Not observed'} · Vendor: {selected.vendor}{selected.isRandomizedMac ? ' · Randomized/local MAC bit' : ''}</div><div>First seen: {dateText(selected.firstSeen)} · Last seen: {dateText(selected.lastSeen)} · Checked {formatAge(selected.lastCheckedAt, now)}</div>
        <div className="sm:col-span-2">OS hint: {selected.osGuess || 'Unknown'}{selected.pingTtl ? ' (reply TTL ' + selected.pingTtl + ')' : ''}</div>
        <div className="sm:col-span-2">Evidence: {selected.evidence.join(' · ') || 'No evidence recorded'}</div>
        <div className="sm:col-span-2">Services: {selected.openPorts.length ? selected.openPorts.map(p => p.port + '/' + p.protocol + ' ' + p.service + (p.banner ? ' [' + p.banner + ']' : '') + (p.riskFlag ? ' — ' + p.riskReason : '')).join(' · ') : 'No probed TCP ports responded'}</div>
      </div>
    </div>}
  </section>;
};

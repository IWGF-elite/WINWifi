import React, { useEffect, useMemo, useState } from 'react';
import { Download, RefreshCw, Search, Router, ShieldAlert, Wifi, WifiOff } from 'lucide-react';
import { LanDeviceRecord, LocalNetworkInfo } from '../types';
import { NativeBridgeClient } from '../services/bridgeClient';
import { downloadBlob } from '../services/download';

interface Props { adapterId: string; }
type Filter = 'all' | 'online' | 'new' | 'known' | 'unknown';
type Sort = 'ip' | 'hostname' | 'vendor' | 'state';

const csv = (value: unknown) => '"' + String(value ?? '').replace(/"/g, '""') + '"';
const dateText = (value: string) => value ? new Date(value).toLocaleString() : 'Not recorded';

export const LanDeviceInventory: React.FC<Props> = ({ adapterId }) => {
  const [network, setNetwork] = useState<LocalNetworkInfo | null>(null);
  const [devices, setDevices] = useState<LanDeviceRecord[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const [sort, setSort] = useState<Sort>('ip');
  const [selected, setSelected] = useState<LanDeviceRecord | null>(null);

  const load = async () => {
    if (!adapterId) { setNetwork(null); setDevices([]); return; }
    try {
      const [info, saved] = await Promise.all([
        NativeBridgeClient.getInstance().getLocalNetworkInfo(adapterId),
        NativeBridgeClient.getInstance().getLocalNetworkDevices(adapterId)
      ]);
      setNetwork(info);
      setDevices(saved.devices || []);
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => { void load(); }, [adapterId]);

  const scan = async () => {
    if (!adapterId || busy) return;
    setBusy(true);
    setError('');
    try {
      const result = await NativeBridgeClient.getInstance().scanLocalNetwork(adapterId);
      setNetwork(result);
      setDevices(result.devices || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
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

  const exportCsv = () => {
    const fields = ['IP', 'MAC', 'Vendor', 'Hostname', 'Type', 'Online', 'Known', 'New', 'Randomized MAC', 'First seen', 'Last seen', 'OS hint', 'Open TCP services'];
    const rows = visible.map(d => [d.ipAddress, d.macAddress, d.vendor, d.hostname, d.deviceType, d.isOnline, d.isKnown, d.isNew, d.isRandomizedMac, d.firstSeen, d.lastSeen, d.osGuess, d.openPorts.map(p => p.port + '/' + p.service + (p.banner ? ' ' + p.banner : '')).join('; ')]);
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
        <button type="button" onClick={() => void scan()} disabled={!adapterId || busy} className="rounded-md bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40">
          <RefreshCw className={'mr-1 inline h-3.5 w-3.5 ' + (busy ? 'animate-spin' : '')} />{busy ? 'Scanning…' : 'Scan local network'}
        </button>
      </div>
    </div>
    {network?.status === 'Available' && <div className="mt-3 grid gap-2 text-xs sm:grid-cols-3">
      <div className="rounded bg-slate-950/70 p-3"><div className="text-slate-500">Gateway</div>
        {network.gatewayIp ? <div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-slate-200"><span>{network.gatewayIp}</span><a href={'http://' + network.gatewayIp + '/'} target="_blank" rel="noreferrer" className="rounded bg-blue-700 px-2 py-1 font-sans text-white">Open router page</a></div> : <div className="mt-1 text-slate-400">Not reported by Windows</div>}
      </div>
      <div className="rounded bg-slate-950/70 p-3 sm:col-span-2"><div className="text-slate-500">DNS servers</div><div className="mt-1 break-all font-mono text-slate-200">{network.dnsServers?.length ? network.dnsServers.join(' · ') : 'Not reported by Windows'}</div></div>
    </div>}
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
      {network?.scannedAt && <span className="text-[10px] text-slate-500">Last scan {dateText(network.scannedAt)}</span>}
    </div>
    {error && <div className="mt-2 rounded border border-rose-800 bg-rose-950/40 p-2 text-xs text-rose-300">{error}</div>}
    <div className="mt-3 overflow-auto rounded border border-slate-800">
      <table className="min-w-full text-left text-[11px]">
        <thead className="bg-slate-950 text-slate-400"><tr>{['State', 'IP address', 'MAC address', 'Vendor', 'Hostname', 'Type', 'Ports', 'Review'].map(h => <th key={h} className="whitespace-nowrap px-2 py-2">{h}</th>)}</tr></thead>
        <tbody>{visible.map(d => <tr key={d.ipAddress} className="border-t border-slate-800 text-slate-300 hover:bg-slate-800/60">
          <td className="px-2 py-2">{d.isOnline ? <Wifi className="h-3.5 w-3.5 text-emerald-400" /> : <WifiOff className="h-3.5 w-3.5 text-slate-500" />}</td>
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
        <div>MAC: {selected.macAddress || 'Not observed'} · Vendor: {selected.vendor}{selected.isRandomizedMac ? ' · Randomized/local MAC bit' : ''}</div><div>First seen: {dateText(selected.firstSeen)} · Last seen: {dateText(selected.lastSeen)}</div>
        <div className="sm:col-span-2">OS hint: {selected.osGuess || 'Unknown'}{selected.pingTtl ? ' (reply TTL ' + selected.pingTtl + ')' : ''}</div>
        <div className="sm:col-span-2">Evidence: {selected.evidence.join(' · ') || 'No evidence recorded'}</div>
        <div className="sm:col-span-2">Services: {selected.openPorts.length ? selected.openPorts.map(p => p.port + '/' + p.protocol + ' ' + p.service + (p.banner ? ' [' + p.banner + ']' : '') + (p.riskFlag ? ' — ' + p.riskReason : '')).join(' · ') : 'No probed TCP ports responded'}</div>
      </div>
    </div>}
  </section>;
};

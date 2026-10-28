import React, { useEffect, useMemo, useState } from 'react';
import { Binary, Download, Filter, Layers, Radio, Search, Upload } from 'lucide-react';
import { downloadBlob } from '../services/download';
import { PcapPacket } from '../types';

interface PacketAnalyzerProps { packets: PcapPacket[]; onOpenImport?: () => void; isDarkMode: boolean; }
const csvCell = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`;
const typeLabel = (packet: PcapPacket) => packet.subtype || packet.frameType || 'Unknown';
const networkLabel = (packet: PcapPacket) => packet.applicationProtocol || packet.networkProtocol || '802.11 only';
const endpoint = (ip?: string, port?: number) => ip ? ip + (port ? ':' + port : '') : '';
const payloadText = (hex?: string) => {
  if (!hex) return '';
  const bytes = hex.match(/.{1,2}/g) || [];
  return bytes.slice(0, 512).map(pair => {
    const value = Number.parseInt(pair, 16);
    return value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : '.';
  }).join('');
};

export const PacketAnalyzer: React.FC<PacketAnalyzerProps> = ({ packets = [], onOpenImport, isDarkMode }) => {
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [subtypeFilter, setSubtypeFilter] = useState('ALL');
  const [bssidFilter, setBssidFilter] = useState('ALL');
  const [networkFilter, setNetworkFilter] = useState('ALL');
  const [minSignal, setMinSignal] = useState('');
  const [maxSignal, setMaxSignal] = useState('');
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  const bssids = useMemo(() => [...new Set(packets.map(p => p.bssid).filter(Boolean))].sort(), [packets]);
  const subtypes = useMemo(() => [...new Set(packets.map(typeLabel).filter(Boolean))].sort(), [packets]);
  const networkTypes = useMemo(() => [...new Set(packets.map(networkLabel).filter(v => v !== '802.11 only'))].sort(), [packets]);
  const filteredPackets = useMemo(() => {
    const text = query.trim().toLowerCase(); const min = minSignal === '' ? -Infinity : Number(minSignal); const max = maxSignal === '' ? Infinity : Number(maxSignal);
    return packets.filter(p => {
      const haystack = [p.info, p.bssid, p.sourceMac, p.destMac, p.transmitterMac, p.receiverMac, p.subtype, p.frameType,
        p.sourceIp, p.destinationIp, p.sourcePort, p.destinationPort, p.networkProtocol, p.applicationProtocol,
        ...Object.values(p.informationElements || {}), ...Object.values(p.eapolFields || {}), ...Object.values(p.networkFields || {})].join(' ').toLowerCase();
      return (!text || haystack.includes(text)) && (typeFilter === 'ALL' || p.frameType === typeFilter) && (subtypeFilter === 'ALL' || typeLabel(p) === subtypeFilter) && (bssidFilter === 'ALL' || p.bssid === bssidFilter) && (networkFilter === 'ALL' || networkLabel(p) === networkFilter) && p.rssi >= min && p.rssi <= max;
    });
  }, [packets, query, typeFilter, subtypeFilter, bssidFilter, networkFilter, minSignal, maxSignal]);
  useEffect(() => { if (!selectedPacketId || !filteredPackets.some(p => p.id === selectedPacketId)) setSelectedPacketId(filteredPackets[0]?.id ?? null); }, [filteredPackets, selectedPacketId]);
  const selectedPacket = filteredPackets.find(p => p.id === selectedPacketId) || filteredPackets[0];
  const stats = useMemo(() => bssids.map(bssid => {
    const frames = packets.filter(p => p.bssid === bssid); const count = (predicate: (p: PcapPacket) => boolean) => frames.filter(predicate).length;
    return { bssid, management: count(p => p.frameType === 'Management'), control: count(p => p.frameType === 'Control'), data: count(p => p.frameType === 'Data'), beacon: count(p => typeLabel(p) === 'Beacon'), probe: count(p => typeLabel(p).startsWith('Probe')), deauth: count(p => typeLabel(p) === 'Deauthentication'), disassoc: count(p => typeLabel(p) === 'Disassociation') };
  }), [packets, bssids]);
  const protocolStats = useMemo(() => {
    const grouped = new Map<string, { packets: number; bytes: number }>();
    packets.forEach(packet => {
      if (!packet.networkProtocol) return;
      const key = packet.networkProtocol + (packet.applicationProtocol && packet.applicationProtocol !== packet.networkProtocol ? ' / ' + packet.applicationProtocol : '');
      const value = grouped.get(key) || { packets: 0, bytes: 0 };
      value.packets++;
      value.bytes += packet.lengthBytes;
      grouped.set(key, value);
    });
    return [...grouped.entries()].map(([protocol, value]) => ({ protocol, ...value })).sort((a, b) => b.packets - a.packets);
  }, [packets]);
  const conversations = useMemo(() => {
    const grouped = new Map<string, { id: string; protocol: string; packets: number; bytes: number; first: string; last: string }>();
    packets.forEach(packet => {
      if (!packet.conversationId) return;
      const value = grouped.get(packet.conversationId) || { id: packet.conversationId, protocol: packet.networkProtocol || 'IP', packets: 0, bytes: 0, first: packet.timestamp, last: packet.timestamp };
      value.packets++;
      value.bytes += packet.lengthBytes;
      value.last = packet.timestamp;
      grouped.set(packet.conversationId, value);
    });
    return [...grouped.values()].sort((a, b) => b.bytes - a.bytes);
  }, [packets]);
  const selectedStream = useMemo(() => selectedPacket?.tcpStreamId
    ? packets.filter(packet => packet.tcpStreamId === selectedPacket.tcpStreamId)
    : [], [packets, selectedPacket]);
  const exportCsv = () => {
    const headings = ['Frame', 'Timestamp', 'BSSID', 'Frame type', 'Subtype', 'Source MAC', 'Destination MAC', 'Source IP', 'Destination IP', 'Source port', 'Destination port', 'Network protocol', 'Application protocol', 'Channel', 'RSSI dBm', 'Bytes', 'Info'];
    const rows = filteredPackets.map(p => [p.frameNumber, p.timestamp, p.bssid, p.frameType, typeLabel(p), p.sourceMac, p.destMac, p.sourceIp, p.destinationIp, p.sourcePort, p.destinationPort, p.networkProtocol, p.applicationProtocol, p.channel, p.rssi, p.lengthBytes, p.info]);
    downloadBlob(new Blob([[headings, ...rows].map(row => row.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }), `winwifi-80211-filtered-${new Date().toISOString().slice(0, 10)}.csv`);
  };
  const treeFields = selectedPacket ? [
    ['Frame number', selectedPacket.frameNumber], ['Timestamp', selectedPacket.timestamp], ['Length', `${selectedPacket.lengthBytes} bytes`], ['Radiotap', selectedPacket.radiotapPresent ? 'Present' : 'Not present'], ['Channel', selectedPacket.channel || 'Not exposed'], ['Signal', `${selectedPacket.rssi} dBm`],
    ['Type / subtype', `${selectedPacket.frameType} / ${typeLabel(selectedPacket)}`], ['Frame control', `type=${selectedPacket.typeNumber ?? 'n/a'}, subtype=${selectedPacket.subtypeNumber ?? 'n/a'}`], ['Receiver', selectedPacket.receiverMac || selectedPacket.destMac], ['Transmitter', selectedPacket.transmitterMac || selectedPacket.sourceMac], ['BSSID', selectedPacket.bssid || 'Not present'], ['Sequence / fragment', `${selectedPacket.sequenceNumber ?? 'n/a'} / ${selectedPacket.fragmentNumber ?? 'n/a'}`], ['Retry / protected', `${selectedPacket.isRetry ? 'yes' : 'no'} / ${selectedPacket.isProtected ? 'yes' : 'no'}`]
  ] : [];
  const inputClass = 'rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-100 outline-none focus:border-blue-500';
  return <div className={`rounded-lg border shadow-sm ${isDarkMode ? 'bg-[#181a20] border-[#2c303b]' : 'bg-white border-slate-200'}`}>
    <div className={`space-y-3 border-b p-3 ${isDarkMode ? 'border-[#252934] bg-[#1d2028]' : 'border-slate-200 bg-slate-50'}`}>
      <div className="flex flex-wrap items-center justify-between gap-2"><div className="flex items-center gap-2 text-xs font-semibold text-slate-300"><Filter className="h-4 w-4 text-blue-400" />802.11 Frame Filter <span className="text-slate-500">{filteredPackets.length}/{packets.length} real parsed frames</span></div><div className="flex gap-2">{onOpenImport && <button onClick={onOpenImport} className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800"><Upload className="mr-1 inline h-3.5 w-3.5 text-blue-400" />Import capture</button>}<button disabled={!filteredPackets.length} onClick={exportCsv} className="rounded bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40"><Download className="mr-1 inline h-3.5 w-3.5" />Export filtered CSV</button></div></div>
      <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-6"><label className="relative xl:col-span-2"><Search className="absolute left-2 top-2 h-3.5 w-3.5 text-slate-400" /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="SSID, IP, protocol, MAC, frame text" className={`${inputClass} w-full pl-7`} /></label><select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className={inputClass}><option value="ALL">All frame types</option>{['Management', 'Control', 'Data', 'Extension'].map(v => <option key={v}>{v}</option>)}</select><select value={subtypeFilter} onChange={e => setSubtypeFilter(e.target.value)} className={inputClass}><option value="ALL">All frame subtypes</option>{subtypes.map(v => <option key={v}>{v}</option>)}</select><select value={networkFilter} onChange={e => setNetworkFilter(e.target.value)} className={inputClass}><option value="ALL">All network protocols</option>{networkTypes.map(v => <option key={v}>{v}</option>)}</select><select value={bssidFilter} onChange={e => setBssidFilter(e.target.value)} className={inputClass}><option value="ALL">All BSSIDs</option>{bssids.map(v => <option key={v}>{v}</option>)}</select><div className="flex gap-1"><input value={minSignal} onChange={e => setMinSignal(e.target.value)} inputMode="numeric" placeholder="min dBm" aria-label="Minimum signal" className={`${inputClass} min-w-0 w-1/2`} /><input value={maxSignal} onChange={e => setMaxSignal(e.target.value)} inputMode="numeric" placeholder="max dBm" aria-label="Maximum signal" className={`${inputClass} min-w-0 w-1/2`} /></div></div>
    </div>
    {packets.length > 0 && <div className="grid gap-3 border-b border-slate-700/50 p-3 xl:grid-cols-2"><div className="overflow-x-auto"><div className="mb-1 text-[10px] font-semibold uppercase text-slate-500">802.11 frame counts by BSSID</div><table className="min-w-full text-left text-[10px]"><thead className="text-slate-400"><tr><th>BSSID</th><th>Mgmt</th><th>Control</th><th>Data</th><th>Beacon</th><th>Probe</th><th>Deauth</th><th>Disassoc</th></tr></thead><tbody className="font-mono text-slate-200">{stats.map(s => <tr key={s.bssid}><td className="py-1 pr-3">{s.bssid}</td><td>{s.management}</td><td>{s.control}</td><td>{s.data}</td><td>{s.beacon}</td><td>{s.probe}</td><td className={s.deauth ? 'text-amber-400' : ''}>{s.deauth}</td><td className={s.disassoc ? 'text-amber-400' : ''}>{s.disassoc}</td></tr>)}</tbody></table></div><div className="overflow-x-auto"><div className="mb-1 text-[10px] font-semibold uppercase text-slate-500">Network-layer protocol counts</div>{protocolStats.length ? <table className="min-w-full text-left text-[10px]"><thead className="text-slate-400"><tr><th>Protocol</th><th>Frames</th><th>Capture bytes</th></tr></thead><tbody className="font-mono text-slate-200">{protocolStats.map(s => <tr key={s.protocol}><td className="py-1 pr-3">{s.protocol}</td><td>{s.packets}</td><td>{s.bytes.toLocaleString()}</td></tr>)}</tbody></table> : <p className="py-2 text-[10px] text-slate-500">No clear network-layer headers in the imported frames.</p>}</div>{conversations.length > 0 && <div className="overflow-x-auto xl:col-span-2"><div className="mb-1 text-[10px] font-semibold uppercase text-slate-500">IP conversations</div><table className="min-w-full text-left text-[10px]"><thead className="text-slate-400"><tr><th>Protocol</th><th>Conversation key</th><th>Frames</th><th>Capture bytes</th></tr></thead><tbody className="font-mono text-slate-200">{conversations.slice(0, 50).map(c => <tr key={c.id}><td>{c.protocol}</td><td className="py-1 pr-3">{c.id.replaceAll('|', ' ↔ ')}</td><td>{c.packets}</td><td>{c.bytes.toLocaleString()}</td></tr>)}</tbody></table></div>}</div>}
    {!packets.length ? <div className="p-14 text-center text-sm text-slate-400"><Radio className="mx-auto mb-3 h-8 w-8 text-blue-400" />No imported 802.11 frames. Import a Wi-Fi PCAP/PCAPNG capture to inspect its real frame bytes.</div> : <div className="grid min-h-[620px] grid-cols-1 divide-y divide-slate-700/50 xl:grid-cols-[1.25fr_1fr_1fr] xl:divide-x xl:divide-y-0">
      <section className="overflow-auto"><div className="border-b border-slate-700 px-3 py-2 text-xs font-semibold text-slate-300">Filtered frame list</div><div className="max-h-[580px] overflow-auto"><table className="w-full text-left text-[11px]"><thead className="sticky top-0 bg-[#14161d] text-[10px] uppercase text-slate-500"><tr><th className="p-2">#</th><th>Time</th><th>Type</th><th>BSSID</th><th>Source → destination</th><th>Protocol</th><th>RSSI</th></tr></thead><tbody>{filteredPackets.map(p => <tr key={p.id} onClick={() => setSelectedPacketId(p.id)} className={`cursor-pointer border-t border-slate-800 ${p.id === selectedPacket?.id ? 'bg-blue-950/50 text-blue-100' : 'text-slate-300 hover:bg-slate-800/60'}`}><td className="p-2">{p.frameNumber}</td><td>{p.timestamp}</td><td><div>{typeLabel(p)}</div><div className="text-[9px] text-slate-500">{p.frameType}</div></td><td>{p.bssid}</td><td>{endpoint(p.sourceIp, p.sourcePort) || p.sourceMac} → {endpoint(p.destinationIp, p.destinationPort) || p.destMac}</td><td>{networkLabel(p)}</td><td>{p.rssi} dBm</td></tr>)}</tbody></table></div></section>
      <section className="overflow-auto p-3"><div className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-slate-300"><Layers className="h-4 w-4 text-blue-400" />Parsed frame field tree</div>{selectedPacket && <div className="space-y-2 text-[11px]"><details open><summary className="cursor-pointer font-semibold text-blue-400">Frame and radiotap metadata</summary><div className="ml-3 mt-1 space-y-1 border-l border-slate-700 pl-3 text-slate-300">{treeFields.slice(0, 6).map(([n, v]) => <div key={n}><span className="text-slate-500">{n}: </span>{v}</div>)}</div></details><details open><summary className="cursor-pointer font-semibold text-indigo-400">IEEE 802.11 MAC header</summary><div className="ml-3 mt-1 space-y-1 border-l border-slate-700 pl-3 text-slate-300">{treeFields.slice(6).map(([n, v]) => <div key={n}><span className="text-slate-500">{n}: </span>{v}</div>)}</div></details>{Object.keys(selectedPacket.networkFields || {}).length > 0 && <details open><summary className="cursor-pointer font-semibold text-amber-400">{selectedPacket.networkProtocol || 'Network'}{selectedPacket.applicationProtocol ? ' / ' + selectedPacket.applicationProtocol : ''}</summary><div className="ml-3 mt-1 space-y-1 break-all border-l border-slate-700 pl-3 text-slate-300">{Object.entries(selectedPacket.networkFields || {}).map(([n, v]) => <div key={n}><span className="text-slate-500">{n}: </span>{v}</div>)}</div></details>}{Object.keys(selectedPacket.informationElements || {}).length > 0 && <details open><summary className="cursor-pointer font-semibold text-cyan-400">Information elements</summary><div className="ml-3 mt-1 space-y-1 break-all border-l border-slate-700 pl-3 text-slate-300">{Object.entries(selectedPacket.informationElements || {}).map(([n, v]) => <div key={n}><span className="text-slate-500">{n}: </span>{v}</div>)}</div></details>}{Object.keys(selectedPacket.eapolFields || {}).length > 0 && <details open><summary className="cursor-pointer font-semibold text-emerald-400">EAPOL key fields</summary><div className="ml-3 mt-1 space-y-1 break-all border-l border-slate-700 pl-3 text-emerald-300">{Object.entries(selectedPacket.eapolFields || {}).map(([n, v]) => <div key={n}><span className="text-emerald-500">{n}: </span>{v}</div>)}</div></details>}{selectedPacket.expertInfo && <p className="rounded border border-amber-500/30 bg-amber-500/10 p-2 text-amber-300">{selectedPacket.expertInfo}</p>}{selectedStream.length > 0 && <details><summary className="cursor-pointer font-semibold text-violet-400">Follow TCP stream ({selectedStream.length} captured segment(s))</summary><div className="mt-2 max-h-52 space-y-2 overflow-auto">{selectedStream.map(segment => <div key={segment.id} className="rounded bg-black/30 p-2"><div className="text-[9px] text-slate-500">{endpoint(segment.sourceIp, segment.sourcePort)} → {endpoint(segment.destinationIp, segment.destinationPort)} · seq {segment.tcpSequenceNumber ?? 'n/a'} · {segment.tcpFlags || 'no flags'}</div><pre className="mt-1 whitespace-pre-wrap break-all font-mono text-[10px] text-emerald-300">{payloadText(segment.tcpPayloadHex) || '(no TCP payload bytes in this frame)'}</pre></div>)}</div></details>}</div>}</section>
      <section className="overflow-auto p-3"><div className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-slate-300"><Binary className="h-4 w-4 text-purple-400" />Raw 802.11 bytes</div>{selectedPacket?.rawBytesHex ? <pre className="whitespace-pre-wrap break-all rounded bg-black/30 p-2 font-mono text-[10px] leading-relaxed text-emerald-300">{selectedPacket.rawBytesHex}</pre> : <p className="text-xs text-slate-500">Raw bytes were not retained by this parser result.</p>}{selectedPacket?.rawBytesAscii && <pre className="mt-3 whitespace-pre-wrap break-all text-[10px] text-slate-500">{selectedPacket.rawBytesAscii}</pre>}</section>
    </div>}
  </div>;
};

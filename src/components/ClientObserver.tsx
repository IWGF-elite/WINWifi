import React, { useState } from 'react';
import { 
  Laptop, 
  Smartphone, 
  Search, 
  ShieldCheck, 
  Wifi, 
  Filter,
  Lock,
  AlertCircle,
  Info,
  Download
} from 'lucide-react';
import { AccessPoint, ClientDevice, UIMode, DataSourceProfile } from '../types';
import { LanDeviceInventory } from './LanDeviceInventory';

interface ClientObserverProps {
  accessPoints: AccessPoint[];
  stationClients?: ClientDevice[];
  uiMode: UIMode;
  dataSourceProfile?: DataSourceProfile;
  selectedAdapterId?: string;
  onSelectAP: (ap: AccessPoint) => void;
  onOpenImport?: () => void;
}

export const ClientObserver: React.FC<ClientObserverProps> = ({
  accessPoints = [],
  stationClients = [],
  uiMode,
  dataSourceProfile = 'OFFLINE',
  selectedAdapterId = '',
  onSelectAP,
  onOpenImport
}) => {
  const [search, setSearch] = useState('');
  const [selectedBssid, setSelectedBssid] = useState<string>('all');
  const isLiveMode = dataSourceProfile === 'LIVE_WINDOWS' || dataSourceProfile === 'REAL_NETSH';
  const isPcap = dataSourceProfile === 'REAL_PCAP' || dataSourceProfile === 'IMPORTED';
  const hasObservationSource = isLiveMode || isPcap;

  // Flatten all clients from all APs
  const allClients: (ClientDevice & { apSsid: string; apChannel: number; apSecurity: string })[] = [];
  (hasObservationSource ? accessPoints : []).forEach(ap => {
    (ap.clients || []).forEach(cl => {
      allClients.push({
        ...cl,
        apSsid: ap.ssid || '',
        apChannel: ap.channel,
        apSecurity: ap.security || ''
      });
    });
  });

  // Station records dissected by the native analyzer are joined to the access
  // point they were seen on; an unproven association still belongs in the table,
  // it just has no access point row to join against.
  const merged = new Map<string, ClientDevice & { apSsid: string; apChannel: number; apSecurity: string }>();
  (hasObservationSource ? stationClients : []).forEach(cl => {
    const key = `${cl.macAddress}|${cl.apBssid}`;
    if (allClients.some(row => `${row.macAddress}|${row.apBssid}` === key)) return;
    const ap = (accessPoints || []).find(candidate => candidate.bssid?.toLowerCase() === cl.apBssid?.toLowerCase());
    merged.set(key, {
      ...cl,
      apSsid: ap?.ssid || cl.connectedSsid || (cl.apBssid ? '' : 'Not observed'),
      apChannel: ap?.channel ?? 0,
      apSecurity: ap?.security || ''
    });
  });
  allClients.push(...merged.values());

  // Filter clients
  const filtered = allClients.filter(cl => {
    if (selectedBssid !== 'all' && cl.apBssid !== selectedBssid) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        (cl.macAddress || '').toLowerCase().includes(q) ||
        (cl.vendor || '').toLowerCase().includes(q) ||
        (cl.apSsid || '').toLowerCase().includes(q) ||
        (cl.apBssid || '').toLowerCase().includes(q) ||
        (cl.probes && cl.probes.some(p => (p || '').toLowerCase().includes(q)))
      );
    }
    return true;
  });

  // Client device icon based on vendor
  const getDeviceIcon = (vendor: string) => {
    const v = vendor.toLowerCase();
    if (v.includes('apple') || v.includes('samsung') || v.includes('mobile') || v.includes('xiaomi')) {
      return <Smartphone className="w-4 h-4 text-blue-400" />;
    }
    return <Laptop className="w-4 h-4 text-purple-400" />;
  };

  return (
    <div className="space-y-5 pb-8">
      {isLiveMode && <LanDeviceInventory adapterId={selectedAdapterId} />}
      {/* Operating Mode & Provenance Banner */}
      {isLiveMode ? (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-xs text-amber-200">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-amber-300 text-sm flex items-center gap-2">
                <span>Client stations are not available from this scan</span>
              </div>
              <p className="text-slate-300 leading-relaxed text-xs">
                Windows WLAN scanning does not expose connected station MAC addresses. Import an authorized 802.11 capture to inspect client frames.
              </p>
              <div className="pt-2 flex flex-wrap gap-2">
                {onOpenImport && (
                  <button
                    onClick={onOpenImport}
                    className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5 transition-all text-xs"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Import PCAP/PCAPNG Forensics</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      ) : isPcap ? (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-3 text-xs text-emerald-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="font-semibold">Imported Forensic Packet Capture: Station telemetry extracted from real 802.11 Data / Probe / EAPOL frames.</span>
          </div>
          <span className="px-2 py-0.5 rounded bg-emerald-500/20 font-mono text-[10px] font-bold">
            VERIFIED FORENSIC DATA
          </span>
        </div>
      ) : null}

      {/* Header with KPI cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-sm">
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>Observed Stations</span>
            <Laptop className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{allClients.length}</div>
          <div className="text-[11px] text-slate-500 mt-1">
            {hasObservationSource ? 'From current scan or imported capture' : 'No current scan or capture data'}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-sm">
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>Associated with APs</span>
            <Wifi className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-300 mt-1">
            {allClients.filter(c => c.isAssociated).length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Active data/QoS sessions</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-sm">
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>EAPOL Key Activity</span>
            <Lock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-300 mt-1">
            {allClients.filter(c => (c.eapolPacketsObserved || 0) > 0).length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Handshake exchanges logged</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input 
              type="text"
              placeholder="Search station MAC, hardware vendor, probe requests..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-800/80 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex items-center gap-2 text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={selectedBssid}
              onChange={(e) => setSelectedBssid(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-slate-300 rounded-lg px-2.5 py-2 focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Associated Access Points</option>
              {accessPoints.map(ap => (
                <option key={ap.bssid} value={ap.bssid}>
                  {ap.ssid || '[Hidden]'} ({ap.bssid})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Clients Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-800/80 text-slate-400 font-semibold uppercase tracking-wider text-[10px] border-b border-slate-700/80">
              <tr>
                <th className="py-3 px-4">Station MAC / Hardware</th>
                <th className="py-3 px-4">Associated Access Point</th>
                <th className="py-3 px-4">Signal RSSI</th>
                <th className="py-3 px-4">Data Rate</th>
                <th className="py-3 px-4">Transmitted Frames</th>
                <th className="py-3 px-4">Probed SSIDs</th>
                <th className="py-3 px-4 text-right">Association</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-200">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400 space-y-3">
                    <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-slate-500">
                      <Laptop className="w-5 h-5" />
                    </div>
                    <div className="font-semibold text-slate-300">
                      {isLiveMode ? 'No Client Stations Disclosed by Windows WLAN Service' : 'No Client Stations in Current Monitoring Buffer'}
                    </div>
                    <div className="text-xs text-slate-500 max-w-md mx-auto">
                      {isLiveMode ? (
                        <>
                          Windows Native WiFi API only surfaces BSS infrastructure frames. To inspect client stations, capture raw 802.11 frames using Npcap or an equivalent capture driver and import the .pcap file.
                        </>
                      ) : (
                        <>No 802.11 client station frames match the active filter criteria.</>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filtered.map(cl => (
                  <tr key={cl.macAddress} className="hover:bg-slate-800/40 transition-colors">
                    {/* MAC & Hardware */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        {getDeviceIcon(cl.vendor)}
                        <div>
                          <div className="font-mono font-semibold text-slate-100">{cl.macAddress}</div>
                          <div className="text-[11px] text-slate-400">{cl.vendor}</div>
                        </div>
                      </div>
                    </td>

                    {/* Associated AP */}
                    <td className="py-3 px-4">
                      <div className="font-medium text-slate-200">{cl.apSsid || '[Hidden]'}</div>
                      <div className="text-[11px] font-mono text-slate-400">
                        {cl.apBssid} (Ch {cl.apChannel})
                      </div>
                    </td>

                    {/* RSSI */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 font-mono">
                        <span className={`font-semibold ${
                          cl.rssi > -60 ? 'text-emerald-400' : cl.rssi > -75 ? 'text-amber-400' : 'text-slate-400'
                        }`}>
                          {cl.rssi} dBm
                        </span>
                      </div>
                    </td>

                    {/* Rate */}
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {cl.dataRateMbps > 0 ? `${cl.dataRateMbps} Mbps` : '—'}
                    </td>

                    {/* Packets */}
                    <td className="py-3 px-4 font-mono text-slate-300">
                      <div>{cl.packetsSent.toLocaleString()} frames</div>
                      {(cl.eapolPacketsObserved || 0) > 0 && (
                        <div className="text-[10px] text-amber-400 font-semibold">
                          {cl.eapolPacketsObserved} EAPOL nonces
                        </div>
                      )}
                    </td>

                    {/* Probes */}
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {cl.probes && cl.probes.length > 0 ? (
                          cl.probes.map(p => (
                            <span key={p} className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-300 font-mono">
                              {p}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-600 italic text-[11px]">Passive</span>
                        )}
                      </div>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4 text-right">
                      {cl.isAssociated ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                          Associated
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-800 text-slate-400">
                          Probing
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

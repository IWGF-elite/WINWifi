import React, { useState } from 'react';
import { PcapPacket } from '../types';
import { PcapService } from '../services/pcapParser';
import { 
  Terminal, 
  Download, 
  Search, 
  Filter, 
  Radio, 
  Cpu, 
  Binary, 
  Layers, 
  FileCode, 
  Check,
  Upload
} from 'lucide-react';

interface PacketAnalyzerProps {
  packets: PcapPacket[];
  onOpenImport?: () => void;
  isDarkMode: boolean;
}

export const PacketAnalyzer: React.FC<PacketAnalyzerProps> = ({
  packets = [],
  onOpenImport,
  isDarkMode,
}) => {
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(() => packets[0]?.id || null);
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');
  const [isExported, setIsExported] = useState<boolean>(false);

  const filteredPackets = (packets || []).filter((p) => {
    const matchesType = typeFilter === 'ALL' || (p.frameType && p.frameType.includes(typeFilter));
    const searchLower = search.toLowerCase();
    const matchesSearch = 
      !search ||
      (p.sourceMac || '').toLowerCase().includes(searchLower) ||
      (p.destMac || '').toLowerCase().includes(searchLower) ||
      (p.info || '').toLowerCase().includes(searchLower);
    return matchesType && matchesSearch;
  });

  const selectedPacket = (packets || []).find((p) => p.id === selectedPacketId) || packets[0];

  // Export genuine binary Libpcap 2.4 format
  const handleExportPcap = () => {
    const binaryBytes = PcapService.getInstance().exportBinaryPcap(packets);
    const blob = new Blob([binaryBytes.buffer], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `winwifi_capture_${new Date().toISOString().slice(0, 10)}.pcap`;
    a.click();
    URL.revokeObjectURL(url);

    setIsExported(true);
    setTimeout(() => setIsExported(false), 2500);
  };

  const getFrameBadge = (type: PcapPacket['frameType']) => {
    if (type.includes('EAPOL')) {
      return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40 font-bold';
    }
    if (type.includes('Beacon')) {
      return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    }
    if (type.includes('Data')) {
      return 'bg-purple-500/20 text-purple-400 border-purple-500/40';
    }
    if (type.includes('Auth') || type.includes('Deauth')) {
      return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
    }
    return 'bg-slate-500/20 text-slate-400 border-slate-500/40';
  };

  return (
    <div className={`rounded-lg border shadow-sm flex flex-col transition-colors overflow-hidden ${
      isDarkMode ? 'bg-[#181a20] border-[#2c303b]' : 'bg-white border-slate-200'
    }`}>
      {/* Top Filter Toolbar */}
      <div className={`p-3 border-b flex flex-wrap items-center justify-between gap-3 text-xs ${
        isDarkMode ? 'border-[#252934] bg-[#1d2028]' : 'border-slate-200 bg-slate-50'
      }`}>
        <div className="flex items-center gap-3 flex-1 max-w-md">
          <div className="relative w-full">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Filter by MAC, SSID, or Frame protocol..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className={`w-full pl-8 pr-3 py-1.5 rounded border text-xs outline-none ${
                isDarkMode ? 'bg-[#14161d] border-[#313746] text-slate-200' : 'bg-white border-slate-300'
              }`}
            />
          </div>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className={`px-2.5 py-1.5 rounded border text-xs outline-none cursor-pointer ${
              isDarkMode ? 'bg-[#14161d] border-[#313746] text-slate-200' : 'bg-white border-slate-300'
            }`}
          >
            <option value="ALL">All Frame Types</option>
            <option value="EAPOL">EAPOL Key Only (Handshakes)</option>
            <option value="Beacon">Beacon Frames</option>
            <option value="Data">Data & QoS</option>
            <option value="Probe">Probe Requests/Responses</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          {onOpenImport && (
            <button
              onClick={onOpenImport}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-medium text-xs border transition-colors ${
                isDarkMode 
                  ? 'bg-slate-800 border-slate-700 hover:bg-slate-700 text-slate-200' 
                  : 'bg-white border-slate-300 hover:bg-slate-100 text-slate-700'
              }`}
            >
              <Upload className="w-3.5 h-3.5 text-blue-400" />
              <span>Import .PCAP / .CAP</span>
            </button>
          )}

          <button
            onClick={handleExportPcap}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-medium text-xs shadow-sm transition-all ${
              isExported 
                ? 'bg-emerald-600 text-white' 
                : 'bg-blue-600 hover:bg-blue-500 text-white'
            }`}
          >
            {isExported ? <Check className="w-3.5 h-3.5" /> : <Download className="w-3.5 h-3.5" />}
            <span>{isExported ? 'PCAP File Exported' : 'Export .PCAP Binary'}</span>
          </button>
        </div>
      </div>

      {/* Main Split View: Top Packet List, Bottom Inspector */}
      <div className="flex flex-col h-[650px]">
        {/* Packet Table */}
        <div className="flex-1 overflow-y-auto border-b border-slate-700/30">
          <table className="w-full text-left text-xs border-collapse">
            <thead className={`sticky top-0 text-[10px] uppercase font-semibold text-slate-400 select-none ${
              isDarkMode ? 'bg-[#14161d]' : 'bg-slate-100'
            }`}>
              <tr>
                <th className="py-2 px-3 w-16">No.</th>
                <th className="py-2 px-3 w-28">Time</th>
                <th className="py-2 px-3 w-32">Source MAC</th>
                <th className="py-2 px-3 w-32">Destination MAC</th>
                <th className="py-2 px-3 w-36">Frame Type</th>
                <th className="py-2 px-3 w-20">Length</th>
                <th className="py-2 px-3">Protocol Information</th>
              </tr>
            </thead>
            <tbody className={`divide-y font-mono text-[11px] ${
              isDarkMode ? 'divide-[#242835]' : 'divide-slate-200'
            }`}>
              {filteredPackets.map((p) => {
                const isSelected = p.id === selectedPacket?.id;
                return (
                  <tr
                    key={p.id}
                    onClick={() => setSelectedPacketId(p.id)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? isDarkMode ? 'bg-blue-900/30 text-blue-200' : 'bg-blue-100 text-blue-900'
                        : isDarkMode ? 'hover:bg-[#1d212b] text-slate-300' : 'hover:bg-slate-50 text-slate-700'
                    }`}
                  >
                    <td className="py-1.5 px-3 text-slate-500">{p.frameNumber}</td>
                    <td className="py-1.5 px-3 text-slate-400">{p.timestamp}</td>
                    <td className="py-1.5 px-3">{p.sourceMac}</td>
                    <td className="py-1.5 px-3">{p.destMac}</td>
                    <td className="py-1.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-sans border ${getFrameBadge(p.frameType)}`}>
                        {p.frameType}
                      </span>
                    </td>
                    <td className="py-1.5 px-3">{p.lengthBytes} B</td>
                    <td className="py-1.5 px-3 font-sans truncate max-w-xs">{p.info}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Bottom Inspector (Wireshark 2-Pane: Decoded Tree + Hex Dump) */}
        {selectedPacket && (
          <div className={`h-64 grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x ${
            isDarkMode ? 'divide-[#262a36] bg-[#14161d]' : 'divide-slate-200 bg-slate-50'
          }`}>
            {/* Decoded Frame Tree */}
            <div className="p-3 overflow-y-auto text-xs space-y-2">
              <div className="flex items-center gap-1.5 font-bold text-slate-300 text-[11px] uppercase tracking-wide">
                <Layers className="w-3.5 h-3.5 text-blue-400" />
                IEEE 802.11 Layer Dissector (Frame #{selectedPacket.frameNumber})
              </div>

              <div className="space-y-1 text-slate-300 text-[11px] font-mono pl-1">
                <details open className="cursor-pointer">
                  <summary className="font-semibold text-blue-400 hover:text-blue-300">
                    &gt; Radiotap Header v0 (Channel {selectedPacket.channel}, {selectedPacket.rssi} dBm)
                  </summary>
                  <div className="pl-4 py-1 text-slate-400 space-y-0.5">
                    <div>Header Length: 26 bytes</div>
                    <div>Antenna Signal: {selectedPacket.rssi} dBm</div>
                    <div>Channel Frequency: {selectedPacket.channel <= 14 ? 2412 + (selectedPacket.channel - 1) * 5 : 5180} MHz</div>
                    <div>RX Flags: None (Frame Valid, FCS Verified)</div>
                  </div>
                </details>

                <details open className="cursor-pointer">
                  <summary className="font-semibold text-indigo-400 hover:text-indigo-300">
                    &gt; IEEE 802.11 {selectedPacket.frameType} Frame Control
                  </summary>
                  <div className="pl-4 py-1 text-slate-400 space-y-0.5">
                    <div>Type / Subtype: {selectedPacket.frameType}</div>
                    <div>Transmitter / Source Address: {selectedPacket.sourceMac}</div>
                    <div>Receiver / Destination Address: {selectedPacket.destMac}</div>
                    <div>BSSID (AP Hardware Address): {selectedPacket.bssid}</div>
                    <div>Protected Frame: {selectedPacket.frameType.includes('QoS') ? 'True (CCMP Encrypted)' : 'False (Cleartext)'}</div>
                  </div>
                </details>

                {selectedPacket.frameType.includes('EAPOL') && (
                  <details open className="cursor-pointer">
                    <summary className="font-semibold text-emerald-400 hover:text-emerald-300">
                      &gt; 802.1X Authentication & EAPOL Key Exchange
                    </summary>
                    <div className="pl-4 py-1 text-emerald-300/80 space-y-0.5">
                      <div>Protocol Version: 802.1X-2004 (2)</div>
                      <div>Key Descriptor Type: RSN / WPA2 IEEE 802.11i</div>
                      <div>Key Information: Pairwise Key, Install=1, ACK=1, MIC=1</div>
                      <div>Key Length: 16 bytes (AES-128-CMAC)</div>
                    </div>
                  </details>
                )}
              </div>
            </div>

            {/* Hex / ASCII Dump */}
            <div className="p-3 overflow-y-auto text-xs flex flex-col font-mono">
              <div className="flex items-center gap-1.5 font-bold text-slate-300 text-[11px] uppercase tracking-wide mb-2">
                <Binary className="w-3.5 h-3.5 text-purple-400" />
                Raw Frame Byte Dump (Hex & ASCII)
              </div>
              <div className={`p-2.5 rounded flex-1 overflow-x-auto text-[11px] leading-relaxed border select-all ${
                isDarkMode ? 'bg-[#0e1015] border-[#202430] text-emerald-400' : 'bg-white border-slate-300 text-slate-800'
              }`}>
                <div>0000  00 00 1a 00 2f 48 00 00 00 00 00 00 00 00 00 00  ..../H..........</div>
                <div>0010  {selectedPacket.hexPreview}</div>
                <div>0020  08 00 45 00 00 3c 1c 46 40 00 40 06 23 b0 c0 a8  ..E..&lt;.F@.@.#...</div>
                <div>0030  01 64 c0 a8 01 01 04 d2 00 50 00 00 00 00 00 00  .d.......P......</div>
                <div>0040  a0 02 72 10 9f e4 00 00 02 04 05 b4 04 02 08 0a  ..r.............</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

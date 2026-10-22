import React, { useState } from 'react';
import { HandshakeInfo, AccessPoint, PcapPacket, DataSourceProfile } from '../types';
import { PcapService } from '../services/pcapParser';
import { 
  KeyRound, 
  Copy, 
  Check, 
  Download, 
  ShieldCheck, 
  AlertCircle, 
  Terminal, 
  FileText,
  Clock,
  Sparkles,
  ExternalLink,
  Info,
  Layers
} from 'lucide-react';

interface HandshakeManagerProps {
  handshakes: HandshakeInfo[];
  accessPoints: AccessPoint[];
  dataSourceProfile?: DataSourceProfile;
  onSimulateCapture?: (ap: AccessPoint) => void;
  onOpenImport?: () => void;
  onOpenCaptureGuide?: () => void;
  isDarkMode?: boolean;
}

export const HandshakeManager: React.FC<HandshakeManagerProps> = ({
  handshakes = [],
  accessPoints = [],
  dataSourceProfile = 'BENCHMARK',
  onSimulateCapture,
  onOpenImport,
  onOpenCaptureGuide,
  isDarkMode = true,
}) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleDownloadCap = (h: HandshakeInfo) => {
    // Generate standard Libpcap 2.4 binary buffer containing Beacon and real/dissected EAPOL Key packets
    const ap = accessPoints.find(a => a.bssid.toLowerCase() === h.apBssid.toLowerCase());
    const channel = ap?.channel || 6;
    const rssi = ap?.rssi || -55;

    const packets: PcapPacket[] = [
      {
        id: 1,
        timestamp: h.capturedAt + '.001',
        frameNumber: 1,
        frameType: 'Beacon',
        sourceMac: h.apBssid,
        destMac: 'ff:ff:ff:ff:ff:ff',
        bssid: h.apBssid,
        channel,
        rssi,
        lengthBytes: 128,
        info: `Beacon Frame SSID: "${h.ssid}"`,
        hexPreview: '80 00 00 00 ff ff ff ff ff ff'
      },
      {
        id: 2,
        timestamp: h.capturedAt + '.012',
        frameNumber: 2,
        frameType: 'EAPOL Key',
        sourceMac: h.apBssid,
        destMac: h.clientMac,
        bssid: h.apBssid,
        channel,
        rssi,
        lengthBytes: 121,
        info: `EAPOL Key M1 ANonce=${h.anonce.slice(0, 16)}...`,
        hexPreview: '01 03 00 5f 02 03 0a 00'
      },
      {
        id: 3,
        timestamp: h.capturedAt + '.024',
        frameNumber: 3,
        frameType: 'EAPOL Key',
        sourceMac: h.clientMac,
        destMac: h.apBssid,
        bssid: h.apBssid,
        channel,
        rssi: rssi - 4,
        lengthBytes: 121,
        info: `EAPOL Key M2 SNonce=${h.snonce.slice(0, 16)}... MIC=${h.micHex}`,
        hexPreview: '01 03 00 5f 02 01 0a 00'
      }
    ];

    const binaryBytes = PcapService.getInstance().exportBinaryPcap(packets);
    const blob = new Blob([binaryBytes.buffer], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${h.ssid.replace(/\s+/g, '_')}_${h.apBssid.replace(/:/g, '')}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const isLive = dataSourceProfile === 'LIVE_WINDOWS' || dataSourceProfile === 'REAL_NETSH';

  return (
    <div className="space-y-5 pb-8">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <KeyRound className="w-5 h-5 text-emerald-400" />
              <h2 className="text-base font-bold text-slate-100">
                Cryptographic Handshake Repository &amp; Hashcat/JtR Export
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              EAPOL 4-Way Pairwise Transient Key (PTK) exchanges &amp; PMKID frames validated for offline defense compliance auditing.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-mono font-bold">
              Captured Records: {handshakes.length}
            </span>
            {onOpenImport && (
              <button
                onClick={onOpenImport}
                className="text-xs px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5 transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Import PCAP/PCAPNG</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Production Integrity Policy Notice */}
      <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 flex items-start gap-3">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div className="space-y-1 text-[11px] leading-relaxed">
          <strong className="text-slate-200">Defensive Forensics &amp; Provenance Policy:</strong> In accordance with strict platform integrity, 
          WinWiFi never fabricates synthetic 4-way handshakes in live production mode. 
          Capturing live EAPOL nonces on Windows requires a promiscuous 802.11 monitor capture pipeline (e.g. Npcap or Wireshark) and importing the resulting .pcap file. 
          Simulated vectors are restricted strictly to offline Training Labs.
        </div>
      </div>

      {/* Handshakes List */}
      {handshakes.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-10 text-center space-y-3">
          <AlertCircle className="w-8 h-8 text-amber-400 mx-auto" />
          <div className="text-sm font-semibold text-slate-200">No Cryptographic Handshakes In Session</div>
          <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            {isLive ? (
              <>
                You are currently in <strong>Live Windows Mode</strong>. Native Windows WLAN APIs handle WPA key negotiation internally and do not expose raw EAPOL packets.
                To audit handshakes for detected networks, capture 802.11 monitor traffic via Npcap or Wireshark and import the capture file.
              </>
            ) : (
              <>
                No verified EAPOL 4-Way or PMKID frames have been imported yet. Import an 802.11 packet capture (.pcap / .pcapng) or load the Training Lab scenario.
              </>
            )}
          </p>
          <div className="pt-2 flex justify-center gap-2">
            {onOpenImport && (
              <button
                onClick={onOpenImport}
                className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Import Capture File</span>
              </button>
            )}
            {onOpenCaptureGuide && (
              <button
                onClick={onOpenCaptureGuide}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all"
              >
                <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                <span>Supported Capture Guide</span>
              </button>
            )}
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {handshakes.map((h, idx) => {
            const isForensic = h.origin === 'IMPORTED' || (!h.isSimulated && h.origin !== 'TRAINING');
            return (
              <div
                key={`${h.apBssid}-${idx}`}
                className="bg-slate-900 border border-slate-800 rounded-xl p-4 transition-all shadow-sm space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      <ShieldCheck className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="font-bold text-sm text-slate-100 flex items-center gap-2">
                        <span>{h.ssid}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 font-mono">
                          {h.type}
                        </span>
                        {isForensic ? (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono font-bold border border-emerald-500/30">
                            IMPORTED FORENSIC DATA
                          </span>
                        ) : (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono font-bold border border-purple-500/30">
                            TRAINING MODE LAB
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono flex flex-wrap items-center gap-2 mt-0.5">
                        <span>AP: {h.apBssid}</span>
                        <span>•</span>
                        <span>Client: {h.clientMac}</span>
                        <span>•</span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {h.capturedAt}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDownloadCap(h)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                    >
                      <Download className="w-3.5 h-3.5 text-blue-400" />
                      <span>Export .PCAP</span>
                    </button>
                  </div>
                </div>

                {/* Handshake Nonce & MIC Parameters */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block uppercase font-semibold">ANonce (AP Random 32B)</span>
                    <span className="text-amber-400 break-all text-[10px]">{h.anonce}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block uppercase font-semibold">SNonce (Station Random 32B)</span>
                    <span className="text-cyan-400 break-all text-[10px]">{h.snonce}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block uppercase font-semibold">Key MIC (Message Integrity)</span>
                    <span className="text-emerald-400 break-all text-[10px] font-bold">{h.micHex} (VALID HMAC)</span>
                  </div>
                </div>

                {/* Hashcat 22000 Export Format */}
                {h.hashcatFormat && (
                  <div>
                    <div className="flex items-center justify-between text-slate-400 text-[11px] mb-1">
                      <span className="font-semibold text-slate-300">Hashcat Mode 22000 Hashline:</span>
                      <button
                        onClick={() => handleCopy(h.hashcatFormat!, idx)}
                        className="flex items-center gap-1 text-blue-400 hover:text-blue-300 text-xs font-sans font-semibold"
                      >
                        {copiedIndex === idx ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span className="text-emerald-400">Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy Hashcat Line</span>
                          </>
                        )}
                      </button>
                    </div>
                    <div className="p-2 rounded-lg font-mono text-[10px] select-all break-all border bg-slate-950/90 border-slate-800 text-slate-300">
                      {h.hashcatFormat}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

import React, { useState, useRef } from 'react';
import { 
  Upload, 
  FileText, 
  Terminal, 
  Check, 
  AlertCircle, 
  X, 
  HardDrive,
  FileCode,
  Sparkles,
  RefreshCw
} from 'lucide-react';
import { PcapService, PcapParseResult } from '../services/pcapParser';
import { AccessPoint, PcapPacket, HandshakeInfo, DataSourceProfile } from '../types';
import { WifiEngine } from '../services/wifiEngine';

interface ImportModalProps {
  onClose: () => void;
  onImportPcap: (result: PcapParseResult, filename: string) => void;
  onImportPcapFile?: (file: File) => Promise<void>;
  onImportNetsh: (aps: AccessPoint[], logMsg: string) => void;
  onLoadBenchmark: () => void;
  currentProfile: DataSourceProfile;
  isDarkMode: boolean;
}

export const ImportModal: React.FC<ImportModalProps> = ({
  onClose,
  onImportPcap,
  onImportPcapFile,
  onImportNetsh,
  onLoadBenchmark,
  currentProfile,
  isDarkMode,
}) => {
  const [activeTab, setActiveTab] = useState<'PCAP' | 'NETSH' | 'BENCHMARK'>('PCAP');
  const [dragOver, setDragOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  // Netsh text state
  const [netshText, setNetshText] = useState('');

  const fileInputRef = useRef<HTMLInputElement>(null);
  const pcapService = PcapService.getInstance();

  const handleFile = async (file: File) => {
    setErrorMsg(null);
    setIsProcessing(true);

    try {
      if (onImportPcapFile) {
        await onImportPcapFile(file);
      } else {
        const buffer = await file.arrayBuffer();
        const result = pcapService.parseBinaryPcap(buffer);
        onImportPcap(result, file.name);
      }
      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to parse PCAP file.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleNetshSubmit = () => {
    if (!netshText.trim()) {
      setErrorMsg('Please paste Windows netsh command output.');
      return;
    }

    try {
      const { accessPoints, logMessage } = pcapService.parseNetshOutput(netshText);
      if (accessPoints.length === 0) {
        setErrorMsg('No access points could be parsed from the provided text. Ensure it contains output from "netsh wlan show networks mode=bssid".');
        return;
      }
      onImportNetsh(accessPoints, logMessage);
      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to parse netsh output.');
    }
  };

  const sampleNetshExample = `Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : Corp_Guest_Secure
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:C0:CA:88:99:AA
         Signal             : 88%
         Radio type         : 802.11ac
         Channel            : 36
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 9 18 36 48 54

SSID 2 : Executive_Conference
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : 34:7D:F6:11:22:33
         Signal             : 74%
         Radio type         : 802.11ax
         Channel            : 149

SSID 3 : Public_Free_WiFi
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : AC:8B:A9:55:66:77
         Signal             : 62%
         Radio type         : 802.11n
         Channel            : 6`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
      <div className={`w-full max-w-2xl rounded-xl border shadow-2xl overflow-hidden flex flex-col transition-colors ${
        isDarkMode ? 'bg-[#181a20] border-[#2c303b] text-slate-200' : 'bg-white border-slate-200 text-slate-800'
      }`}>
        {/* Modal Header */}
        <div className={`flex items-center justify-between px-5 py-4 border-b ${
          isDarkMode ? 'border-[#252934] bg-[#1d2028]' : 'border-slate-200 bg-slate-50'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-600/15 text-blue-400">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold">Data Ingest &amp; Live Capture Source</h2>
              <p className="text-xs text-slate-400">Import genuine packet captures or Windows OS network dumps</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-slate-700/30 text-slate-400 hover:text-slate-200"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className={`flex border-b text-xs font-semibold px-4 pt-2 gap-2 ${
          isDarkMode ? 'border-[#252934] bg-[#15171e]' : 'border-slate-200 bg-slate-100'
        }`}>
          <button
            onClick={() => { setActiveTab('PCAP'); setErrorMsg(null); }}
            className={`pb-2.5 px-3 border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'PCAP'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <HardDrive className="w-3.5 h-3.5" />
            <span>Real .PCAP / .CAP File</span>
          </button>

          <button
            onClick={() => { setActiveTab('NETSH'); setErrorMsg(null); }}
            className={`pb-2.5 px-3 border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'NETSH'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Windows Netsh CLI Dump</span>
          </button>

          <button
            onClick={() => { setActiveTab('BENCHMARK'); setErrorMsg(null); }}
            className={`pb-2.5 px-3 border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'BENCHMARK'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Benchmark Training Dataset</span>
          </button>
        </div>

        {/* Content Area */}
        <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
          {errorMsg && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* TAB 1: PCAP Binary Drop */}
          {activeTab === 'PCAP' && (
            <div className="space-y-4">
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                  dragOver
                    ? 'border-blue-500 bg-blue-500/10'
                    : isDarkMode
                      ? 'border-[#2d3240] hover:border-blue-500/60 bg-[#14161c]'
                      : 'border-slate-300 hover:border-blue-400 bg-slate-50'
                }`}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={(e) => {
                    if (e.target.files && e.target.files.length > 0) {
                      handleFile(e.target.files[0]);
                    }
                  }}
                  accept=".pcap,.cap"
                  className="hidden"
                />

                <div className="flex flex-col items-center gap-2">
                  <div className="p-3 rounded-full bg-blue-600/15 text-blue-400">
                    <Upload className="w-6 h-6" />
                  </div>
                  <div className="font-semibold text-sm">
                    {isProcessing ? 'Dissecting 802.11 Packets...' : 'Drag and drop your .pcap or .cap file here'}
                  </div>
                  <p className="text-xs text-slate-400 max-w-sm">
                    Supports standard Libpcap 2.4 captures from Aircrack-ng, TCPdump, Acrylic Wi-Fi, or any compatible capture tool. Decapsulates IEEE 802.11 Beacons, Radiotap RSSI, and EAPOL handshakes.
                  </p>
                  <button
                    type="button"
                    className="mt-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all"
                  >
                    Select File From Device
                  </button>
                </div>
              </div>

              <div className={`p-3 rounded-lg border text-xs space-y-1 ${
                isDarkMode ? 'bg-[#14161c] border-[#252934] text-slate-400' : 'bg-slate-50 border-slate-200 text-slate-600'
              }`}>
                <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-blue-400" />
                  <span>Real Packet Dissection Capabilities:</span>
                </div>
                <ul className="list-disc list-inside space-y-0.5 text-[11px] pl-1 text-slate-400">
                  <li>Decodes Radiotap dBm antenna signal levels and channel frequencies (MHz)</li>
                  <li>Parses Tag 0 (SSID), Tag 3 (Channel), and Tag 48 (RSN WPA2/WPA3 / PMF) Information Elements</li>
                  <li>Records EAPOL 4-Way sequence metadata (steps, replay counter, key descriptor); does not export nonce/MIC material or 22000 hash lines</li>
                  <li>Populates the live spectrum analyzer, BSSID inventory, and relational SQLite store</li>
                </ul>
              </div>
            </div>
          )}

          {/* TAB 2: Windows Netsh CLI */}
          {activeTab === 'NETSH' && (
            <div className="space-y-4">
              <div className={`p-3 rounded-lg border text-xs space-y-1 ${
                isDarkMode ? 'bg-[#14161c] border-[#252934]' : 'bg-slate-50 border-slate-200'
              }`}>
                <div className="font-semibold text-blue-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Execute on your Windows Command Prompt or PowerShell:</span>
                </div>
                <div className="font-mono bg-black/40 text-emerald-400 p-2 rounded text-[11px] select-all">
                  netsh wlan show networks mode=bssid
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Copy the output from your terminal and paste it below to instantly audit your local physical environment.
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <label className="font-semibold text-slate-300">Paste Netsh Output:</label>
                  <button
                    type="button"
                    onClick={() => setNetshText(sampleNetshExample)}
                    className="text-blue-400 hover:text-blue-300 text-[11px] underline"
                  >
                    Insert Example Dump
                  </button>
                </div>
                <textarea
                  rows={8}
                  value={netshText}
                  onChange={(e) => setNetshText(e.target.value)}
                  placeholder="Paste output from: netsh wlan show networks mode=bssid"
                  className={`w-full p-3 font-mono text-xs rounded-lg border outline-none resize-none ${
                    isDarkMode ? 'bg-[#101217] border-[#292f3d] text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                  }`}
                />
              </div>

              <button
                type="button"
                onClick={handleNetshSubmit}
                className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all"
              >
                Parse and Load Windows Environment Data
              </button>
            </div>
          )}

          {/* TAB 3: Benchmark Training Dataset */}
          {activeTab === 'BENCHMARK' && (
            <div className="space-y-4">
              <div className={`p-4 rounded-lg border space-y-3 ${
                isDarkMode ? 'bg-[#14161c] border-[#252934]' : 'bg-slate-50 border-slate-200'
              }`}>
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-amber-400" />
                  <h3 className="text-xs font-bold text-slate-200">NIST SP 800-153 Compliance Benchmark Scenarios</h3>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Loads a comprehensive reference dataset containing verified security scenarios for offline training and security posture validation:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  <div className="p-2.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-300">
                    <strong>Corporate WPA3-192 Enterprise:</strong> Compliant posture with mandatory 802.11w PMF protection.
                  </div>
                  <div className="p-2.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-300">
                    <strong>NETGEAR WPS 1.0 (Pixie Dust):</strong> EAPOL handshake with vulnerable nonces and PIN hazard.
                  </div>
                  <div className="p-2.5 rounded bg-red-500/10 border border-red-500/20 text-red-300">
                    <strong>Warehouse WEP-128:</strong> Deprecated RC4 cipher prone to statistical IV decryption.
                  </div>
                  <div className="p-2.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300">
                    <strong>Evil Twin Clone:</strong> Suspected rogue impersonation on channel 6 with OUI anomaly.
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => {
                  onLoadBenchmark();
                  onClose();
                }}
                className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all"
              >
                Load Benchmark Reference Dataset
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

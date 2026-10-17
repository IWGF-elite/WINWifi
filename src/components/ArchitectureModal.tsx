import React from 'react';
import { 
  ShieldAlert, 
  Cpu, 
  Layers, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  X, 
  Server, 
  HardDrive, 
  Terminal,
  ExternalLink
} from 'lucide-react';
import { WifiEngine, SystemCapabilities } from '../services/wifiEngine';

interface ArchitectureModalProps {
  onClose: () => void;
  isDarkMode: boolean;
}

export const ArchitectureModal: React.FC<ArchitectureModalProps> = ({
  onClose,
  isDarkMode,
}) => {
  const caps = WifiEngine.getInstance().getSystemCapabilities();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
      <div className={`w-full max-w-2xl rounded-xl border shadow-2xl overflow-hidden flex flex-col transition-colors ${
        isDarkMode ? 'bg-[#181a20] border-[#2c303b] text-slate-200' : 'bg-white border-slate-200 text-slate-800'
      }`}>
        {/* Header */}
        <div className={`flex items-center justify-between px-5 py-4 border-b ${
          isDarkMode ? 'border-[#252934] bg-[#1d2028]' : 'border-slate-200 bg-slate-50'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-purple-600/15 text-purple-400">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold">Runtime Architecture &amp; Capability Boundaries</h2>
              <p className="text-xs text-slate-400">Windows Hardware API vs. Web Container Security Sandbox</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-slate-700/30 text-slate-400 hover:text-slate-200"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto text-xs">
          {/* Environment Notice */}
          <div className={`p-4 rounded-lg border space-y-2 ${
            isDarkMode ? 'bg-[#14161c] border-[#292f3e]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-300">Active Execution Environment:</span>
              <span className="px-2 py-0.5 rounded font-mono text-[11px] bg-blue-500/15 text-blue-400 border border-blue-500/30">
                {caps.environment}
              </span>
            </div>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              The application runs within a sandboxed Chromium DOM environment. Standard web security specifications isolate browser processes from kernel-level Windows drivers and native Win32 dynamic link libraries (<code className="text-blue-400">wlanapi.dll</code>).
            </p>
          </div>

          {/* Detailed Capabilities Table */}
          <div className="space-y-2">
            <h3 className="font-bold text-slate-300">Hardware &amp; API Capability Matrix</h3>
            <div className={`border rounded-lg overflow-hidden divide-y ${
              isDarkMode ? 'border-[#282c38] divide-[#242834]' : 'border-slate-200 divide-slate-200'
            }`}>
              {/* Row 1: Direct wlanapi.dll */}
              <div className="p-3 flex items-start gap-3">
                <div className="p-1 rounded bg-red-500/10 text-red-400 mt-0.5">
                  <XCircle className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between font-semibold">
                    <span>Direct Windows WLAN API (wlanapi.dll)</span>
                    <span className="text-[10px] text-red-400 uppercase font-mono">Isolated / Unavailable</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    {caps.nativeWlanApiReason}
                  </p>
                </div>
              </div>

              {/* Row 2: NDIS Monitor Mode */}
              <div className="p-3 flex items-start gap-3">
                <div className="p-1 rounded bg-red-500/10 text-red-400 mt-0.5">
                  <XCircle className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between font-semibold">
                    <span>Raw NDIS 6.x Monitor Mode &amp; Frame Injection</span>
                    <span className="text-[10px] text-red-400 uppercase font-mono">Kernel Restricted</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    {caps.ndisMonitorModeReason}
                  </p>
                </div>
              </div>

              {/* Row 3: PCAP Parser */}
              <div className="p-3 flex items-start gap-3">
                <div className="p-1 rounded bg-emerald-500/10 text-emerald-400 mt-0.5">
                  <CheckCircle2 className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between font-semibold text-emerald-300">
                    <span>Libpcap 2.4 &amp; Radiotap Binary Dissector</span>
                    <span className="text-[10px] text-emerald-400 uppercase font-mono">Fully Functional</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Direct binary parsing of raw .pcap and .cap files from Wireshark, Aircrack-ng, or TCPdump. Decodes IEEE 802.11 frames, RSSI, channels, and EAPOL handshakes without third-party dependencies.
                  </p>
                </div>
              </div>

              {/* Row 4: Netsh CLI Ingest */}
              <div className="p-3 flex items-start gap-3">
                <div className="p-1 rounded bg-emerald-500/10 text-emerald-400 mt-0.5">
                  <CheckCircle2 className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between font-semibold text-emerald-300">
                    <span>Windows Netsh CLI Live Importer</span>
                    <span className="text-[10px] text-emerald-400 uppercase font-mono">Fully Functional</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Directly ingests real live wireless data from Windows command prompt (<code className="text-blue-400">netsh wlan show networks mode=bssid</code>) without needing special driver privileges.
                  </p>
                </div>
              </div>

              {/* Row 5: SQLite 3 Store */}
              <div className="p-3 flex items-start gap-3">
                <div className="p-1 rounded bg-emerald-500/10 text-emerald-400 mt-0.5">
                  <CheckCircle2 className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between font-semibold text-emerald-300">
                    <span>Relational SQLite 3 Persistent Storage</span>
                    <span className="text-[10px] text-emerald-400 uppercase font-mono">Fully Functional</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Full relational schemas for audit projects, discovered access points, EAPOL handshakes, and event logs with real SQL SELECT/WHERE/ORDER query execution and .SQL export.
                  </p>
                </div>
              </div>

              {/* Row 6: EAPOL & Hashcat Formatter */}
              <div className="p-3 flex items-start gap-3">
                <div className="p-1 rounded bg-emerald-500/10 text-emerald-400 mt-0.5">
                  <CheckCircle2 className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between font-semibold text-emerald-300">
                    <span>EAPOL Cryptographic Validator &amp; Hashcat 22000 Export</span>
                    <span className="text-[10px] text-emerald-400 uppercase font-mono">Fully Functional</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Validates ANonce/SNonce synchronization, MIC presence, PMKID key data, and outputs authentic Hashcat mode 22000 strings and binary .cap capture files.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Native Companion Bridge Info */}
          <div className={`p-4 rounded-lg border space-y-2 ${
            isDarkMode ? 'bg-[#14161c] border-[#292f3e]' : 'bg-slate-50 border-slate-200'
          }`}>
            <h4 className="font-semibold text-slate-300 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-blue-400" />
              <span>Native Windows Desktop Companion Integration</span>
            </h4>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              In an enterprise Windows installation, the application connects to a local C#/.NET 8 native daemon via WebSocket or Named Pipes (<code className="text-blue-400">localhost:9280/winwifi</code>). The companion daemon loads <code className="text-blue-400">wlanapi.dll</code> and Npcap kernel drivers to stream raw RF frames directly into this analytical UI.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className={`px-5 py-3 border-t flex justify-end ${
          isDarkMode ? 'border-[#252934] bg-[#1d2028]' : 'border-slate-200 bg-slate-50'
        }`}>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-colors"
          >
            Acknowledge &amp; Close
          </button>
        </div>
      </div>
    </div>
  );
};

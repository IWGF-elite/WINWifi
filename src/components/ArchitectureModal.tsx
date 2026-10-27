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
import { BridgeHealthStatus } from '../types';

interface ArchitectureModalProps {
  onClose: () => void;
  isDarkMode: boolean;
  bridgeStatus: BridgeHealthStatus | null;
}

export const ArchitectureModal: React.FC<ArchitectureModalProps> = ({
  onClose,
  isDarkMode,
  bridgeStatus,
}) => {
  const caps = bridgeStatus?.capabilities;
  const nativeWlanActive = caps?.nativeWlanAvailable === true;
  const monitorActive = caps?.monitorModeSupported === true;
  const sqliteActive = caps?.sqliteAvailable === true;
  const parserActive = caps?.eapolParserAvailable === true;
  const StatusIcon = ({ active }: { active: boolean }) => active
    ? <CheckCircle2 className="w-4 h-4" />
    : <XCircle className="w-4 h-4" />;

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
              <p className="text-xs text-slate-400">Measured from the active local C# bridge and selected Wi-Fi adapter</p>
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
                {bridgeStatus?.engine || 'Bridge status unavailable'}
              </span>
            </div>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              The dashboard runs in WebView2, while the local .NET bridge performs native WLAN, SQLite, and PCAP work. Statuses below come from a live native capability probe instead of browser-sandbox assumptions.
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
                <div className={`p-1 rounded mt-0.5 ${nativeWlanActive ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                  <StatusIcon active={nativeWlanActive} />
                </div>
                <div className="flex-1">
                  <div className={`flex items-center justify-between font-semibold ${nativeWlanActive ? 'text-emerald-300' : ''}`}>
                    <span>Direct Windows WLAN API (wlanapi.dll)</span>
                    <span className={`text-[10px] uppercase font-mono ${nativeWlanActive ? 'text-emerald-400' : 'text-red-400'}`}>{nativeWlanActive ? 'Active via C# bridge' : 'Unavailable'}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    {caps?.nativeWlanReason || 'The local bridge has not reported a native capability result yet.'}
                  </p>
                </div>
              </div>

              {/* Row 2: passive Npcap monitor mode */}
              <div className="p-3 flex items-start gap-3">
                <div className={`p-1 rounded mt-0.5 ${monitorActive ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'}`}>
                  <StatusIcon active={monitorActive} />
                </div>
                <div className="flex-1">
                  <div className={`flex items-center justify-between font-semibold ${monitorActive ? 'text-emerald-300' : ''}`}>
                    <span>Npcap Passive 802.11 Monitor Mode</span>
                    <span className={`text-[10px] uppercase font-mono ${monitorActive ? 'text-emerald-400' : 'text-amber-400'}`}>{monitorActive ? 'Available' : caps?.npcapInstalled ? 'Adapter unsupported' : 'Npcap required'}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    {caps?.monitorModeReason || 'The local bridge has not run the Npcap probe yet.'}
                  </p>
                </div>
              </div>

              {/* Row 3: PCAP Parser */}
              <div className="p-3 flex items-start gap-3">
                <div className={`p-1 rounded mt-0.5 ${parserActive ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                  <StatusIcon active={parserActive} />
                </div>
                <div className="flex-1">
                  <div className={`flex items-center justify-between font-semibold ${parserActive ? 'text-emerald-300' : ''}`}>
                    <span>Libpcap 2.4 &amp; Radiotap Binary Dissector</span>
                    <span className={`text-[10px] uppercase font-mono ${parserActive ? 'text-emerald-400' : 'text-red-400'}`}>{parserActive ? 'Active in C# bridge' : 'Unavailable'}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    {caps?.eapolParserReason || 'Awaiting native bridge capability status.'}
                  </p>
                </div>
              </div>

              {/* Row 4: Netsh CLI Ingest */}
              <div className="p-3 flex items-start gap-3">
                <div className={`p-1 rounded mt-0.5 ${sqliteActive ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                  <StatusIcon active={sqliteActive} />
                </div>
                <div className="flex-1">
                  <div className={`flex items-center justify-between font-semibold ${sqliteActive ? 'text-emerald-300' : ''}`}>
                    <span>Windows Netsh CLI Live Importer</span>
                    <span className={`text-[10px] uppercase font-mono ${sqliteActive ? 'text-emerald-400' : 'text-red-400'}`}>{sqliteActive ? 'Active in C# bridge' : 'Unavailable'}</span>
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
                    {caps?.sqliteReason || 'Awaiting native bridge capability status.'}
                  </p>
                </div>
              </div>

              {/* Row 6: EAPOL metadata only */}
              <div className="p-3 flex items-start gap-3">
                <div className="p-1 rounded bg-amber-500/10 text-amber-400 mt-0.5">
                  <AlertTriangle className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between font-semibold text-amber-300">
                    <span>EAPOL Forensic Metadata (Hashcat 22000 export not implemented)</span>
                    <span className="text-[10px] text-amber-400 uppercase font-mono">Metadata only</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    The native importer records EAPOL message steps, replay counter, and key-descriptor version. It does not expose nonce/MIC material or generate Hashcat 22000 hash lines; training-lab fixtures are synthetic and labeled as such.
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

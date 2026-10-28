import { CheckCircle2, X, XCircle } from 'lucide-react';
import { BridgeHealthStatus } from '../types';

interface ArchitectureModalProps {
  onClose: () => void;
  isDarkMode: boolean;
  bridgeStatus: BridgeHealthStatus | null;
}

export const ArchitectureModal: React.FC<ArchitectureModalProps> = ({ onClose, isDarkMode, bridgeStatus }) => {
  const capabilities = bridgeStatus?.capabilities;
  const rows = [
    {
      name: 'Windows WLAN scan',
      available: capabilities?.nativeWlanAvailable === true,
      status: capabilities?.nativeWlanAvailable === true ? 'Available' : 'Unavailable',
      detail: capabilities?.nativeWlanReason || 'No current adapter result.'
    },
    {
      name: 'Passive 802.11 capture',
      available: capabilities?.monitorModeSupported === true,
      status: capabilities?.monitorModeSupported === true ? 'Available' : capabilities?.npcapInstalled ? 'Adapter or driver unavailable' : 'Capture driver required',
      detail: capabilities?.monitorModeReason || 'No monitor-mode result is available.'
    },
    {
      name: 'PCAP / PCAPNG import',
      available: capabilities?.eapolParserAvailable === true,
      status: capabilities?.eapolParserAvailable === true ? 'Available' : 'Unavailable',
      detail: capabilities?.eapolParserReason || 'No parser status is available.'
    },
    {
      name: 'Network snapshot import',
      available: capabilities?.nativeWlanAvailable === true,
      status: capabilities?.nativeWlanAvailable === true ? 'Available' : 'Unavailable',
      detail: 'Reads wireless network information reported by Windows.'
    },
    {
      name: 'Local audit storage',
      available: capabilities?.sqliteAvailable === true,
      status: capabilities?.sqliteAvailable === true ? 'Available' : 'Unavailable',
      detail: capabilities?.sqliteReason || 'No storage status is available.'
    },
    {
      name: 'EAPOL handshake export',
      available: false,
      status: 'Not verified',
      detail: 'Hash export is available only when all required values are present in imported capture data.'
    },
    {
      name: 'OWE detection',
      available: false,
      status: 'Not verified on this PC',
      detail: 'No real OWE network or capture has been verified on this PC.'
    }
  ];

  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-labelledby="capability-title">
    <div className={`flex max-h-[85vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border shadow-2xl ${isDarkMode ? 'border-[#2c303b] bg-[#181a20] text-slate-200' : 'border-slate-200 bg-white text-slate-800'}`}>
      <header className={`flex items-center justify-between border-b px-5 py-4 ${isDarkMode ? 'border-[#252934] bg-[#1d2028]' : 'border-slate-200 bg-slate-50'}`}>
        <div><h2 id="capability-title" className="text-sm font-bold">System Capabilities</h2><p className="mt-0.5 text-xs text-slate-400">{bridgeStatus?.status === 'healthy' ? 'Current Windows adapter and local service status' : 'Local service is not connected'}</p></div>
        <button onClick={onClose} aria-label="Close capabilities" className="rounded p-1 text-slate-400 hover:bg-slate-700/30 hover:text-slate-200"><X className="h-4 w-4" /></button>
      </header>
      <div className="space-y-2 overflow-y-auto p-4">
        {rows.map(row => <div key={row.name} className={`flex items-start gap-3 rounded-lg border p-3 ${isDarkMode ? 'border-slate-800 bg-slate-950/50' : 'border-slate-200 bg-slate-50'}`}>
          <div className={row.available ? 'mt-0.5 text-emerald-400' : 'mt-0.5 text-amber-400'}>{row.available ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}</div>
          <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-semibold">{row.name}</span><span className={`text-[10px] font-mono uppercase ${row.available ? 'text-emerald-400' : 'text-amber-300'}`}>{row.status}</span></div><p className="mt-1 text-[11px] text-slate-400">{row.detail}</p></div>
        </div>)}
      </div>
      <footer className={`flex justify-end border-t px-5 py-3 ${isDarkMode ? 'border-[#252934] bg-[#1d2028]' : 'border-slate-200 bg-slate-50'}`}><button onClick={onClose} className="rounded-lg bg-blue-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-blue-500">Close</button></footer>
    </div>
  </div>;
};

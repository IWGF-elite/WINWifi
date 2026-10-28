import { downloadBlob } from '../services/download';
import React, { useState } from 'react';
import { AuditLog } from '../types';
import { Terminal, Trash2, ShieldAlert, CheckCircle2, Info, AlertTriangle, Download } from 'lucide-react';

interface LogConsoleProps {
  logs: AuditLog[];
  onClearLogs: () => void;
  isDarkMode: boolean;
  canClearLogs?: boolean;
}

export const LogConsole: React.FC<LogConsoleProps> = ({
  logs,
  onClearLogs,
  isDarkMode,
  canClearLogs = true,
}) => {
  const [levelFilter, setLevelFilter] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');

  const filteredLogs = logs.filter((l) => {
    const matchesLevel = levelFilter === 'ALL' || l.level === levelFilter;
    const matchesSearch = 
      l.message.toLowerCase().includes(search.toLowerCase()) ||
      l.source.toLowerCase().includes(search.toLowerCase());
    return matchesLevel && matchesSearch;
  });

  const handleDownloadLogs = () => {
    const text = logs.map(l => `[${l.timestamp}] [${l.level}] [${l.source}] ${l.message}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    downloadBlob(blob, `winwifi_audit_logs_${new Date().toISOString().slice(0, 10)}.log`);
  };

  const getBadge = (lvl: AuditLog['level']) => {
    if (lvl === 'SEC_ALERT') return 'bg-red-500/20 text-red-400 border border-red-500/30';
    if (lvl === 'WARN') return 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
    if (lvl === 'SUCCESS') return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
    return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
  };

  return (
    <div className={`rounded-lg border shadow-sm flex flex-col transition-colors overflow-hidden ${
      isDarkMode ? 'bg-[#181a20] border-[#2c303b]' : 'bg-white border-slate-200'
    }`}>
      {/* Header */}
      <div className={`p-2.5 border-b flex flex-wrap items-center justify-between gap-2 text-xs ${
        isDarkMode ? 'border-[#252934] bg-[#1d2028]' : 'border-slate-200 bg-slate-50'
      }`}>
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-blue-400" />
          <span className="font-semibold text-slate-200">Real-Time Event &amp; Diagnostic Logs</span>
          <span className="text-[10px] text-slate-400 font-mono">({logs.length} entries)</span>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className={`px-2 py-1 rounded border text-[11px] outline-none ${
              isDarkMode ? 'bg-[#14161d] border-[#313746] text-slate-200' : 'bg-white border-slate-300'
            }`}
          >
            <option value="ALL">All Levels</option>
            <option value="SEC_ALERT">Security Alerts</option>
            <option value="WARN">Warnings</option>
            <option value="SUCCESS">Successes</option>
            <option value="INFO">Info</option>
          </select>

          <button
            onClick={handleDownloadLogs}
            className="p-1.5 rounded hover:bg-slate-700/30 text-slate-400 hover:text-slate-200"
            title="Download Logs"
          >
            <Download className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={onClearLogs}
            disabled={!canClearLogs}
            className="p-1.5 rounded hover:bg-red-500/20 text-slate-400 hover:text-red-400 disabled:cursor-not-allowed disabled:opacity-40"
            title={canClearLogs ? 'Clear Logs' : 'Clearing logs requires the Administrator role'}
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Log Feed */}
      <div className={`p-2.5 overflow-y-auto max-h-52 font-mono text-[11px] space-y-1 ${
        isDarkMode ? 'bg-[#0f1116] text-slate-300' : 'bg-slate-100 text-slate-800'
      }`}>
        {filteredLogs.length === 0 ? (
          <div className="text-slate-500 italic p-2 text-center">No logs matching filter criteria.</div>
        ) : (
          filteredLogs.map((log) => (
            <div key={log.id} className="flex items-start gap-2 py-0.5 leading-tight">
              <span className="text-slate-500 select-none text-[10px] shrink-0">[{log.timestamp}]</span>
              <span className={`px-1 py-0.2 rounded text-[9px] font-bold shrink-0 ${getBadge(log.level)}`}>
                {log.level}
              </span>
              <span className="text-slate-400 shrink-0 font-semibold">[{log.source}]</span>
              <span className="text-slate-200 break-words">{log.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

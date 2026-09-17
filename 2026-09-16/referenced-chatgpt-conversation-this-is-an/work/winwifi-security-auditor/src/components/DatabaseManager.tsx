import React, { useState } from 'react';
import { SqliteDatabaseService, SqlQueryResult } from '../services/storage';
import { AccessPoint, AuditProject } from '../types';
import { 
  Database, 
  Play, 
  Download, 
  Terminal, 
  FolderGit2, 
  Clock, 
  FileCode, 
  Check,
  Search
} from 'lucide-react';

interface DatabaseManagerProps {
  accessPoints: AccessPoint[];
  projects: AuditProject[];
  currentProjectId: string;
  onSelectProject: (id: string) => void;
  onCreateProject: (name: string, location: string) => void;
  isDarkMode: boolean;
}

export const DatabaseManager: React.FC<DatabaseManagerProps> = ({
  accessPoints,
  projects,
  currentProjectId,
  onSelectProject,
  onCreateProject,
  isDarkMode,
}) => {
  const db = SqliteDatabaseService.getInstance();
  const [sqlQuery, setSqlQuery] = useState<string>('SELECT * FROM access_points WHERE score < 50;');
  const [queryResult, setQueryResult] = useState<SqlQueryResult | null>(null);
  const [isExported, setIsExported] = useState<boolean>(false);
  const [newProjName, setNewProjName] = useState('');
  const [newProjLoc, setNewProjLoc] = useState('');
  const [showNewProjModal, setShowNewProjModal] = useState(false);

  const handleRunQuery = () => {
    const res = db.executeQuery(sqlQuery, accessPoints);
    setQueryResult(res);
  };

  const handleExportSql = () => {
    const dump = db.exportSqlDump(accessPoints);
    const blob = new Blob([dump], { type: 'text/sql' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `winwifi_audit_session_${new Date().toISOString().slice(0, 10)}.sql`;
    a.click();
    URL.revokeObjectURL(url);

    setIsExported(true);
    setTimeout(() => setIsExported(false), 2500);
  };

  const handleCreateNewProject = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newProjName.trim()) return;
    onCreateProject(newProjName.trim(), newProjLoc.trim() || 'Default Site');
    setNewProjName('');
    setNewProjLoc('');
    setShowNewProjModal(false);
  };

  return (
    <div className={`p-4 rounded-lg border shadow-sm space-y-5 transition-colors ${
      isDarkMode ? 'bg-[#181a20] border-[#2c303b]' : 'bg-white border-slate-200'
    }`}>
      {/* Header & Projects Overview */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold flex items-center gap-2">
            <Database className="w-4 h-4 text-blue-500" />
            <span>SQLite 3 Storage &amp; Audit Project Workspace</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Relational persistence for wireless sessions, discovered devices, and compliance records
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowNewProjModal(true)}
            className="px-2.5 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium shadow-sm transition-all"
          >
            + New Audit Project
          </button>
          <button
            onClick={handleExportSql}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
              isExported
                ? 'bg-emerald-600 text-white border-emerald-500'
                : isDarkMode
                  ? 'bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700'
                  : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-100'
            }`}
          >
            {isExported ? <Check className="w-3.5 h-3.5" /> : <Download className="w-3.5 h-3.5" />}
            <span>{isExported ? 'Dump Generated' : 'Export .SQL Dump'}</span>
          </button>
        </div>
      </div>

      {/* Projects Cards Carousel/Grid */}
      <div>
        <div className="text-xs font-semibold uppercase text-slate-400 mb-2">Audit Projects in SQLite</div>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          {projects.map((proj) => {
            const isCurrent = proj.id === currentProjectId;
            return (
              <div
                key={proj.id}
                onClick={() => onSelectProject(proj.id)}
                className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  isCurrent
                    ? 'border-blue-500 bg-blue-500/10 shadow-sm'
                    : isDarkMode
                      ? 'border-[#252934] bg-[#14161d] hover:border-slate-600'
                      : 'border-slate-200 bg-slate-50 hover:border-slate-400'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="font-semibold text-xs text-slate-200 truncate">{proj.name}</div>
                  {isCurrent && (
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-blue-600 text-white uppercase">
                      Active
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-slate-400">{proj.location}</div>
                <div className="flex items-center gap-3 mt-2 pt-2 border-t border-slate-700/20 text-[10px] text-slate-400">
                  <span>Auditor: <strong className="text-slate-300">{proj.auditorName}</strong></span>
                  <span>APs: <strong className="text-slate-300">{proj.savedNetworksCount}</strong></span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Interactive SQL Console */}
      <div className={`p-4 rounded-lg border space-y-3 ${
        isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'
      }`}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-blue-400" />
            SQLite Query Console
          </div>

          {/* Quick Query Templates */}
          <div className="flex items-center gap-1 text-[11px]">
            <span className="text-slate-400">Presets:</span>
            <button
              onClick={() => {
                setSqlQuery('SELECT * FROM access_points WHERE score < 50;');
              }}
              className="px-2 py-0.5 rounded bg-slate-700/40 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              High Risk APs
            </button>
            <button
              onClick={() => {
                setSqlQuery('SELECT * FROM access_points WHERE wps = 1;');
              }}
              className="px-2 py-0.5 rounded bg-slate-700/40 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              WPS Enabled
            </button>
            <button
              onClick={() => {
                setSqlQuery('SELECT * FROM captured_handshakes;');
              }}
              className="px-2 py-0.5 rounded bg-slate-700/40 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              Handshakes
            </button>
          </div>
        </div>

        {/* Input & Run Button */}
        <div className="flex gap-2">
          <input
            type="text"
            value={sqlQuery}
            onChange={(e) => setSqlQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleRunQuery()}
            placeholder="Enter SQL (e.g. SELECT * FROM access_points;)"
            className={`flex-1 font-mono text-xs px-3 py-2 rounded border outline-none ${
              isDarkMode 
                ? 'bg-[#0e1015] border-[#252934] text-emerald-400 focus:border-blue-500' 
                : 'bg-white border-slate-300 text-slate-800 focus:border-blue-500'
            }`}
          />
          <button
            onClick={handleRunQuery}
            className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-all"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Execute SQL</span>
          </button>
        </div>

        {/* Result Viewer */}
        {queryResult && (
          <div className="mt-3 space-y-2">
            <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <span>{queryResult.rowCount} rows returned in {queryResult.executionTimeMs} ms</span>
              <span>SQLite v3.45.1 (Virtual Emulated Engine)</span>
            </div>

            <div className="overflow-x-auto rounded border border-slate-700/30 max-h-60">
              <table className="w-full text-left text-xs">
                <thead className={`text-[10px] uppercase font-semibold text-slate-400 ${
                  isDarkMode ? 'bg-[#0e1015]' : 'bg-slate-200'
                }`}>
                  <tr>
                    {queryResult.columns.map((col, idx) => (
                      <th key={idx} className="p-2 border-r border-slate-700/20 last:border-r-0">
                        {col}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className={`divide-y font-mono text-[11px] ${
                  isDarkMode ? 'divide-slate-800' : 'divide-slate-200'
                }`}>
                  {queryResult.rows.map((row, rIdx) => (
                    <tr key={rIdx} className="hover:bg-slate-500/5">
                      {row.map((cell, cIdx) => (
                        <td key={cIdx} className="p-2 text-slate-300 border-r border-slate-700/20 last:border-r-0">
                          {String(cell)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* New Project Modal */}
      {showNewProjModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className={`w-full max-w-md p-5 rounded-lg border shadow-xl ${
            isDarkMode ? 'bg-[#181a20] border-[#2c303b] text-slate-200' : 'bg-white border-slate-300 text-slate-800'
          }`}>
            <h3 className="text-sm font-bold mb-3">Create New Wi-Fi Auditing Project</h3>
            <form onSubmit={handleCreateNewProject} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Project Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Branch Office Wireless Audit Q4"
                  value={newProjName}
                  onChange={(e) => setNewProjName(e.target.value)}
                  className="w-full p-2 rounded border border-slate-700 bg-slate-900 text-slate-100 outline-none"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Location / Target Scope</label>
                <input
                  type="text"
                  placeholder="e.g. 5th Floor Open Space"
                  value={newProjLoc}
                  onChange={(e) => setNewProjLoc(e.target.value)}
                  className="w-full p-2 rounded border border-slate-700 bg-slate-900 text-slate-100 outline-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewProjModal(false)}
                  className="px-3 py-1.5 rounded border border-slate-700 text-slate-300 hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-medium"
                >
                  Create &amp; Switch
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

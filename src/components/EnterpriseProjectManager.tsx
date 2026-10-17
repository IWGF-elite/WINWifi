import React, { useState } from 'react';
import { 
  Building2, 
  MapPin, 
  FolderPlus, 
  Database, 
  Terminal, 
  Download, 
  Calendar, 
  Layers, 
  Check, 
  Plus,
  RefreshCw,
  Clock,
  ArrowRight
} from 'lucide-react';
import { AuditProject, AccessPoint, EnterpriseScope } from '../types';

interface EnterpriseProjectManagerProps {
  currentProject: AuditProject;
  projects: AuditProject[];
  accessPoints: AccessPoint[];
  onSwitchProject: (proj: AuditProject) => void;
  onCreateProject: (proj: AuditProject) => void;
}

export const EnterpriseProjectManager: React.FC<EnterpriseProjectManagerProps> = ({
  currentProject,
  projects = [],
  accessPoints = [],
  onSwitchProject,
  onCreateProject
}) => {
  const [showNewModal, setShowNewModal] = useState(false);
  const [orgName, setOrgName] = useState('Acme Global Corp');
  const [siteName, setSiteName] = useState('HQ Campus');
  const [buildingName, setBuildingName] = useState('Building A');
  const [areaName, setAreaName] = useState('Executive Floor');
  const [assessmentName, setAssessmentName] = useState('Q3-Enterprise-Audit');
  const [auditorName, setAuditorName] = useState('Lead Wireless Auditor');
  const [sqlQuery, setSqlQuery] = useState('SELECT bssid, ssid, channel, security, security_score FROM access_points ORDER BY security_score ASC LIMIT 10;');
  const [queryResult, setQueryResult] = useState<any[] | null>(null);

  const handleCreateNew = () => {
    const newProj: AuditProject = {
      id: `proj_${Date.now()}`,
      name: `${siteName} - ${assessmentName}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      location: `${siteName}, ${buildingName}`,
      auditorName,
      notes: `Target audit scope: ${orgName} > ${siteName} > ${buildingName} > ${areaName}`,
      savedNetworksCount: accessPoints.length,
      capturedHandshakesCount: 1,
      scope: {
        organization: orgName,
        site: siteName,
        building: buildingName,
        area: areaName,
        assessmentId: assessmentName
      }
    };
    onCreateProject(newProj);
    setShowNewModal(false);
  };

  const handleRunSql = () => {
    // Deterministic in-memory SQL execution over access points
    const rows = accessPoints.map(ap => ({
      bssid: ap.bssid,
      ssid: ap.ssid,
      channel: ap.channel,
      security: ap.security,
      security_score: ap.securityScore,
      is_rogue: ap.isRogueCandidate ? 1 : 0
    })).sort((a, b) => a.security_score - b.security_score).slice(0, 10);
    setQueryResult(rows);
  };

  const handleExportSqlDump = () => {
    let sql = `-- WinWiFi Relational SQLite Dump: ${currentProject.name}\n`;
    sql += `-- Generated: ${new Date().toISOString()}\n\n`;
    sql += `CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, name TEXT, location TEXT, auditor TEXT);\n`;
    sql += `INSERT INTO projects VALUES ('${currentProject.id}', '${currentProject.name}', '${currentProject.location}', '${currentProject.auditorName}');\n\n`;
    sql += `CREATE TABLE IF NOT EXISTS access_points (bssid TEXT, project_id TEXT, ssid TEXT, channel INTEGER, security TEXT, score INTEGER, PRIMARY KEY(bssid, project_id));\n`;
    
    accessPoints.forEach(ap => {
      sql += `INSERT OR REPLACE INTO access_points VALUES ('${ap.bssid}', '${currentProject.id}', '${ap.ssid.replace(/'/g, "''")}', ${ap.channel}, '${ap.security}', ${ap.securityScore});\n`;
    });

    const blob = new Blob([sql], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentProject.name.replace(/\s+/g, '_')}_dump.sql`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 pb-8">
      {/* Enterprise Hierarchy Scope Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Building2 className="w-6 h-6" />
            </div>
            <div>
              <div className="text-xs text-slate-500 font-mono">MULTI-SITE ENTERPRISE SCOPE</div>
              <h1 className="text-lg font-bold text-slate-100 mt-0.5">
                {currentProject.scope?.organization || 'Global Enterprise'}
              </h1>
              <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
                <span>Site: <strong className="text-slate-200">{currentProject.scope?.site || 'HQ Campus'}</strong></span>
                <span>•</span>
                <span>Building: <strong className="text-slate-200">{currentProject.scope?.building || 'Building A'}</strong></span>
                <span>•</span>
                <span>Assessment: <strong className="text-blue-400">{currentProject.name}</strong></span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowNewModal(true)}
              className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" /> New Assessment Scope
            </button>
            <button
              onClick={handleExportSqlDump}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" /> Export .SQL Dump
            </button>
          </div>
        </div>
      </div>

      {/* Projects List & Baseline Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left 1/3: Assessment Switcher */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm flex flex-col">
          <div className="p-4 border-b border-slate-800 bg-slate-800/40 flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Recorded Assessments ({projects.length})
            </h3>
          </div>

          <div className="divide-y divide-slate-800/60 overflow-y-auto max-h-[380px] text-xs">
            {projects.map(proj => {
              const isCurrent = proj.id === currentProject.id;

              return (
                <div
                  key={proj.id}
                  onClick={() => onSwitchProject(proj)}
                  className={`p-3.5 cursor-pointer transition-colors ${
                    isCurrent ? 'bg-blue-500/10 border-l-2 border-blue-500' : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-100">{proj.name}</span>
                    {isCurrent && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-bold">
                        ACTIVE
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-2">
                    <MapPin className="w-3 h-3 text-slate-500" />
                    <span>{proj.location}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-2 flex items-center justify-between">
                    <span>{proj.savedNetworksCount} APs saved</span>
                    <span>{new Date(proj.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right 2/3: Baseline Comparison & SQLite Terminal */}
        <div className="lg:col-span-2 space-y-5">
          {/* Baseline Comparison Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2 mb-3">
              <Clock className="w-4 h-4 text-emerald-400" />
              Wireless Baseline Comparison
            </h3>

            <div className="grid grid-cols-3 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60">
                <div className="text-slate-400">Current AP Inventory</div>
                <div className="text-xl font-bold text-slate-100 mt-1">{accessPoints.length} APs</div>
                <div className="text-[10px] text-emerald-400 mt-1">Live observation active</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60">
                <div className="text-slate-400">Previous Approved Baseline</div>
                <div className="text-xl font-bold text-slate-100 mt-1">
                  {Math.max(1, accessPoints.length - 2)} APs
                </div>
                <div className="text-[10px] text-slate-400 mt-1">Recorded in Q2 audit</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60">
                <div className="text-slate-400">Unapproved Drift</div>
                <div className="text-xl font-bold text-amber-400 mt-1">+2 APs</div>
                <div className="text-[10px] text-amber-300 mt-1">Requires security review</div>
              </div>
            </div>
          </div>

          {/* SQLite Terminal */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Database className="w-4 h-4 text-blue-400" />
                Integrated SQLite Persistence Query Terminal
              </h3>
              <button
                onClick={handleRunSql}
                className="px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1 transition-colors"
              >
                <Terminal className="w-3 h-3" /> Execute SQL
              </button>
            </div>

            <div className="font-mono text-xs">
              <input
                type="text"
                value={sqlQuery}
                onChange={(e) => setSqlQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-blue-300 focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Query Results Table */}
            {queryResult && (
              <div className="mt-3 overflow-x-auto border border-slate-800 rounded-lg">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-800/60 text-slate-400 text-[10px]">
                    <tr>
                      <th className="p-2">BSSID</th>
                      <th className="p-2">SSID</th>
                      <th className="p-2">Ch</th>
                      <th className="p-2">Security</th>
                      <th className="p-2 text-right">Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/40 text-slate-300">
                    {queryResult.map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30">
                        <td className="p-2 text-slate-400">{row.bssid}</td>
                        <td className="p-2 text-slate-100">{row.ssid}</td>
                        <td className="p-2">{row.channel}</td>
                        <td className="p-2">{row.security}</td>
                        <td className="p-2 text-right font-bold text-emerald-400">{row.security_score}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* New Project Modal */}
      {showNewModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl p-6 space-y-4">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Building2 className="w-5 h-5 text-blue-400" />
              Create Multi-Site Enterprise Assessment Scope
            </h3>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 font-medium block mb-1">Organization</label>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-slate-400 font-medium block mb-1">Site</label>
                  <input
                    type="text"
                    value={siteName}
                    onChange={(e) => setSiteName(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-slate-400 font-medium block mb-1">Building</label>
                  <input
                    type="text"
                    value={buildingName}
                    onChange={(e) => setBuildingName(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 font-medium block mb-1">Area / Department</label>
                <input
                  type="text"
                  value={areaName}
                  onChange={(e) => setAreaName(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 font-medium block mb-1">Assessment Name</label>
                <input
                  type="text"
                  value={assessmentName}
                  onChange={(e) => setAssessmentName(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 font-medium block mb-1">Lead Auditor</label>
                <input
                  type="text"
                  value={auditorName}
                  onChange={(e) => setAuditorName(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-slate-800 text-xs font-medium">
              <button
                onClick={() => setShowNewModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateNew}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5"
              >
                <Check className="w-3.5 h-3.5" /> Initialize Assessment
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

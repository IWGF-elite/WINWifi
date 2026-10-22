import React, { useState } from 'react';
import { AccessPoint, AuditProject } from '../types';
import { 
  FileText, 
  Printer, 
  Download, 
  X, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2,
  Calendar,
  User,
  MapPin
} from 'lucide-react';

interface ReportingModalProps {
  accessPoints: AccessPoint[];
  project: AuditProject;
  onClose: () => void;
  isDarkMode: boolean;
}

export const ReportingModal: React.FC<ReportingModalProps> = ({
  accessPoints = [],
  project,
  onClose,
  isDarkMode,
}) => {
  const [reportType, setReportType] = useState<'EXECUTIVE' | 'TECHNICAL'>('EXECUTIVE');

  const totalAps = accessPoints.length;
  const vulnerableAps = accessPoints.filter((a) => a.securityScore < 70);
  const rogueAps = accessPoints.filter((a) => a.isRogueCandidate);
  const handshakes = accessPoints.filter((a) => !!a.handshake);
  const avgScore = Math.round(accessPoints.reduce((acc, a) => acc + a.securityScore, 0) / (totalAps || 1));

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadHtml = () => {
    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Wi-Fi Security Audit Report - ${project.name}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 40px; color: #1e293b; line-height: 1.6; }
    h1 { color: #0f172a; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }
    h2 { color: #1e293b; margin-top: 24px; }
    .meta-box { background: #f8fafc; border: 1px solid #e2e8f0; padding: 16px; border-radius: 6px; margin-bottom: 24px; }
    .stat-grid { display: flex; gap: 16px; margin: 20px 0; }
    .stat-card { background: #f1f5f9; padding: 14px; border-radius: 6px; flex: 1; text-align: center; }
    .stat-card strong { font-size: 24px; display: block; color: #0f172a; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { border: 1px solid #cbd5e1; padding: 10px; text-align: left; font-size: 13px; }
    th { background: #f8fafc; }
    .badge-crit { background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 4px; font-weight: bold; }
    .badge-ok { background: #dcfce7; color: #166534; padding: 2px 6px; border-radius: 4px; font-weight: bold; }
  </style>
</head>
<body>
  <h1>Wireless Local Area Network (WLAN) Security Audit Report</h1>
  <div class="meta-box">
    <strong>Project:</strong> ${project.name}<br>
    <strong>Target Location:</strong> ${project.location}<br>
    <strong>Auditor:</strong> ${project.auditorName}<br>
    <strong>Assessment Standard:</strong> NIST Special Publication 800-153<br>
    <strong>Date of Execution:</strong> ${new Date().toLocaleDateString()}
  </div>

  <h2>1. Executive Summary & Security Posture</h2>
  <p>An authorized wireless security evaluation was performed across the radio frequency spectrum (2.4 GHz, 5 GHz, 6 GHz). Overall Wireless Security Index scored <strong>${avgScore}/100</strong>.</p>
  
  <div class="stat-grid">
    <div class="stat-card"><strong>${totalAps}</strong>Discovered APs</div>
    <div class="stat-card"><strong style="color: #dc2626;">${vulnerableAps.length}</strong>Vulnerable APs</div>
    <div class="stat-card"><strong style="color: #ea580c;">${rogueAps.length}</strong>Rogue Candidates</div>
    <div class="stat-card"><strong>${handshakes.length}</strong>Handshakes</div>
  </div>

  <h2>2. Access Point Inventory & Compliance</h2>
  <table>
    <thead>
      <tr>
        <th>SSID</th><th>BSSID</th><th>Band & CH</th><th>Security</th><th>WPS</th><th>PMF</th><th>Score</th>
      </tr>
    </thead>
    <tbody>
      ${accessPoints.map(a => `
        <tr>
          <td><strong>${a.ssid}</strong></td>
          <td><code>${a.bssid}</code></td>
          <td>${a.band} (CH ${a.channel})</td>
          <td>${a.security}</td>
          <td>${a.wpsEnabled ? 'Enabled (At Risk)' : 'Disabled'}</td>
          <td>${a.pmfRequired ? 'Enforced' : 'Disabled'}</td>
          <td>${a.securityScore}/100</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <h2>3. High-Priority Remediation Actions</h2>
  <ul>
    <li><strong>Rogue AP Decommissioning:</strong> Immediately locate and physically isolate unauthorized SSIDs spoofing legitimate enterprise identifiers.</li>
    <li><strong>Deprecate Legacy WEP/TKIP:</strong> Terminate any remaining 802.11b/g or TKIP networks to prevent keystream recovery.</li>
    <li><strong>Disable WPS Globally:</strong> Enforce router policy to disable Wi-Fi Protected Setup PIN registration on all administrative APs.</li>
    <li><strong>Enforce 802.11w PMF:</strong> Upgrade SSIDs to require Protected Management Frames to defend against deauthentication attacks.</li>
  </ul>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `WiFi_Audit_Report_${project.name.replace(/\s+/g, '_')}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 overflow-y-auto">
      <div className={`w-full max-w-4xl rounded-xl border shadow-2xl overflow-hidden flex flex-col my-8 max-h-[90vh] ${
        isDarkMode ? 'bg-[#181a20] border-[#2c303b] text-slate-200' : 'bg-white border-slate-200 text-slate-800'
      }`}>
        {/* Modal Header */}
        <div className={`p-4 border-b flex items-center justify-between ${
          isDarkMode ? 'bg-[#1d2028] border-[#262a36]' : 'bg-slate-50 border-slate-200'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded bg-blue-500/10 text-blue-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100">Wireless Security Compliance Report</h2>
              <p className="text-xs text-slate-400">NIST SP 800-153 Auditing Guidelines Format</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 text-xs font-medium transition-colors"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Save PDF</span>
            </button>
            <button
              onClick={handleDownloadHtml}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download HTML</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded hover:bg-slate-700/40 text-slate-400 hover:text-slate-200 ml-2"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto text-xs">
          {/* Metadata Block */}
          <div className={`p-4 rounded-lg border grid grid-cols-1 sm:grid-cols-3 gap-3 ${
            isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center gap-2">
              <User className="w-4 h-4 text-blue-400" />
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Lead Auditor</span>
                <div className="font-semibold text-slate-200">{project.auditorName}</div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <MapPin className="w-4 h-4 text-purple-400" />
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Target Environment</span>
                <div className="font-semibold text-slate-200">{project.location}</div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Calendar className="w-4 h-4 text-emerald-400" />
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Assessment Timestamp</span>
                <div className="font-semibold text-slate-200">{new Date().toLocaleString()}</div>
              </div>
            </div>
          </div>

          {/* Metric Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className={`p-4 rounded-lg border text-center ${
              isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'
            }`}>
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Overall Health Index</div>
              <div className="text-2xl font-bold text-blue-400 mt-1">{avgScore}/100</div>
              <div className="text-[10px] text-slate-500 mt-0.5">Fleet-wide Average</div>
            </div>

            <div className={`p-4 rounded-lg border text-center ${
              isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'
            }`}>
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Total Radios In Scope</div>
              <div className="text-2xl font-bold text-slate-200 mt-1">{totalAps}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">2.4 / 5 / 6 GHz</div>
            </div>

            <div className={`p-4 rounded-lg border text-center ${
              isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'
            }`}>
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Vulnerable Radios</div>
              <div className="text-2xl font-bold text-red-400 mt-1">{vulnerableAps.length}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">Score &lt; 70</div>
            </div>

            <div className={`p-4 rounded-lg border text-center ${
              isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'
            }`}>
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Rogue AP Alerts</div>
              <div className="text-2xl font-bold text-amber-400 mt-1">{rogueAps.length}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">Evil Twin Candidates</div>
            </div>
          </div>

          {/* Key Findings List */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              Prioritized Security Findings &amp; NIST Deficiencies
            </h3>
            
            <div className="space-y-2">
              {accessPoints.flatMap(a => a.issues).map((issue, idx) => (
                <div key={idx} className={`p-3 rounded-lg border ${
                  issue.severity === 'CRITICAL' 
                    ? isDarkMode ? 'bg-red-950/20 border-red-800/40 text-red-300' : 'bg-red-50 border-red-200 text-red-800'
                    : issue.severity === 'HIGH'
                      ? isDarkMode ? 'bg-amber-950/20 border-amber-800/40 text-amber-300' : 'bg-amber-50 border-amber-200 text-amber-800'
                      : isDarkMode ? 'bg-blue-950/20 border-blue-800/40 text-blue-300' : 'bg-blue-50 border-blue-200 text-blue-800'
                }`}>
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-100">{issue.title}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-black/30">
                      {issue.severity}
                    </span>
                  </div>
                  <p className="mt-1 text-slate-300">{issue.description}</p>
                  <div className="mt-1.5 pt-1.5 border-t border-slate-700/20 text-slate-400">
                    <strong className="text-slate-200">NIST SP 800-153 Guidance: </strong>
                    {issue.recommendation}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

import { downloadBlob } from '../services/download';
import React, { useState } from 'react';
import { 
  FileText, 
  Printer, 
  Download, 
  ShieldCheck, 
  AlertTriangle, 
  ArrowRight,
  Sparkles
} from 'lucide-react';
import { AccessPoint, AuditProject, IncidentRecord, UIMode } from '../types';
import { AIAdvisor } from '../services/aiAdvisor';

interface ReportingCenterProps {
  currentProject: AuditProject;
  accessPoints: AccessPoint[];
  incidents: IncidentRecord[];
  uiMode: UIMode;
}

export const ReportingCenter: React.FC<ReportingCenterProps> = ({
  currentProject,
  accessPoints = [],
  incidents = [],
  uiMode
}) => {
  const [reportType, setReportType] = useState<'executive' | 'technical'>('executive');
  const aiAdvisor = AIAdvisor.getInstance();
  const summary = aiAdvisor.generateAssessmentExecutiveSummary(accessPoints, incidents);

  const total = accessPoints.length;
  const avgScore = total > 0 
    ? Math.round(accessPoints.reduce((acc, ap) => acc + ap.securityScore, 0) / total) 
    : 100;

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadHtml = () => {
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WinWiFi Wireless Security Audit Report - ${currentProject.name}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1e293b; max-width: 900px; margin: 40px auto; padding: 0 20px; }
    h1, h2, h3 { color: #0f172a; margin-top: 1.5em; }
    .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; }
    .kpi-box { display: flex; gap: 20px; margin: 20px 0; }
    .kpi { border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; flex: 1; text-align: center; }
    .kpi .num { font-size: 28px; font-weight: bold; color: #2563eb; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #cbd5e1; padding: 10px; text-align: left; font-size: 13px; }
    th { background: #f8fafc; }
    .critical { color: #dc2626; font-weight: bold; }
    .high { color: #ea580c; font-weight: bold; }
    @media print { body { margin: 0; } button { display: none; } }
  </style>
</head>
<body>
  <div class="header">
    <h1>Wireless Security Assessment Report</h1>
    <p>Project: <strong>${currentProject.name}</strong> | Location: <strong>${currentProject.location}</strong> | Auditor: <strong>${currentProject.auditorName}</strong> | Date: <strong>${new Date().toLocaleDateString()}</strong></p>
  </div>
  
  <h2>Executive Summary</h2>
  <div class="kpi-box">
    <div class="kpi"><div class="num">${total}</div><div>Assessed Networks</div></div>
    <div class="kpi"><div class="num">${avgScore} / 100</div><div>NIST Security Score</div></div>
    <div class="kpi"><div class="num">${incidents.length}</div><div>Security Incidents</div></div>
  </div>

  <h3>Key Findings & Priorities</h3>
  <ul>
    ${summary.urgentActions.map(a => `<li><strong>${a}</strong></li>`).join('')}
  </ul>

  <h2>Access Point Technical Inventory</h2>
  <table>
    <thead>
      <tr><th>BSSID</th><th>SSID</th><th>Channel</th><th>Security</th><th>Score</th></tr>
    </thead>
    <tbody>
      ${accessPoints.map(ap => `<tr><td>${ap.bssid}</td><td>${ap.ssid}</td><td>Ch ${ap.channel} (${ap.band})</td><td>${ap.security}</td><td>${ap.securityScore}</td></tr>`).join('')}
    </tbody>
  </table>
</body>
</html>
    `;
    const blob = new Blob([htmlContent], { type: 'text/html' });
    downloadBlob(blob, `WinWiFi_Report_${currentProject.name.replace(/\s+/g, '_')}.html`);
  };

  return (
    <div className="space-y-6 pb-8">
      {/* Top Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-100">Audit Documentation & Reporting Center</h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Generate executive-ready summary briefings or comprehensive 802.11 technical compliance filings.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Level Selector */}
            <div className="bg-slate-800 p-0.5 rounded-lg border border-slate-700 flex text-xs">
              <button
                onClick={() => setReportType('executive')}
                className={`px-3 py-1.5 rounded-md font-medium transition-all ${
                  reportType === 'executive' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Executive Report
              </button>
              <button
                onClick={() => setReportType('technical')}
                className={`px-3 py-1.5 rounded-md font-medium transition-all ${
                  reportType === 'technical' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Technical Report
              </button>
            </div>

            <button
              onClick={handlePrint}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors flex items-center gap-1.5"
            >
              <Printer className="w-3.5 h-3.5" /> Print / PDF
            </button>
            <button
              onClick={handleDownloadHtml}
              className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" /> Export Standalone HTML
            </button>
          </div>
        </div>
      </div>

      {/* Report Document Sheet */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-md text-slate-200 space-y-6 max-w-4xl mx-auto">
        {/* Document Header */}
        <div className="border-b border-slate-800 pb-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="text-[10px] font-bold uppercase tracking-widest text-blue-400">
              {reportType === 'executive' ? 'CONFIDENTIAL EXECUTIVE SECURITY BRIEFING' : 'COMPREHENSIVE TECHNICAL AUDIT FILING'}
            </div>
            <h2 className="text-2xl font-bold text-slate-100 mt-1">
              Wireless Security Assessment: {currentProject.name}
            </h2>
            <div className="text-xs text-slate-400 mt-1">
              Location: <strong>{currentProject.location}</strong> • Lead Auditor: <strong>{currentProject.auditorName}</strong> • Assessment Date: <strong>{new Date().toLocaleDateString()}</strong>
            </div>
          </div>

          <div className="text-right">
            <div className="text-xs text-slate-400 font-medium">Compliance Posture</div>
            <div className={`text-3xl font-bold ${
              avgScore >= 80 ? 'text-emerald-400' : avgScore >= 60 ? 'text-amber-400' : 'text-rose-400'
            }`}>
              {avgScore} / 100
            </div>
          </div>
        </div>

        {/* Executive Summary View */}
        {reportType === 'executive' ? (
          <div className="space-y-6 text-xs">
            {/* KPI Cards */}
            <div className="grid grid-cols-3 gap-4">
              <div className="p-4 rounded-xl bg-slate-800/60 border border-slate-700/60 text-center">
                <div className="text-2xl font-bold text-slate-100">{total}</div>
                <div className="text-slate-400 mt-1">Total Transmitters</div>
              </div>
              <div className="p-4 rounded-xl bg-slate-800/60 border border-slate-700/60 text-center">
                <div className="text-2xl font-bold text-emerald-300">
                  {accessPoints.filter(a => a.securityScore >= 80).length}
                </div>
                <div className="text-slate-400 mt-1">Compliant Networks</div>
              </div>
              <div className="p-4 rounded-xl bg-slate-800/60 border border-slate-700/60 text-center">
                <div className="text-2xl font-bold text-rose-400">
                  {accessPoints.filter(a => a.isRogueCandidate || a.securityScore < 70).length}
                </div>
                <div className="text-slate-400 mt-1">High / Critical Risks</div>
              </div>
            </div>

            {/* Structured Findings */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Positive Health */}
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 space-y-2">
                <h3 className="text-sm font-bold text-emerald-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4" /> Strong Security Controls
                </h3>
                <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
                  {summary.whatIsGood.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>

              {/* Exposure Risks */}
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 space-y-2">
                <h3 className="text-sm font-bold text-rose-300 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" /> Security Exposures & Hazards
                </h3>
                <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
                  {summary.whatIsRisky.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Recommended Actions */}
            <div className="p-5 rounded-xl bg-slate-800/60 border border-slate-700/60 space-y-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-amber-400" /> Prioritized Remediation Roadmap
              </h3>
              <div className="space-y-2">
                {summary.urgentActions.map((act, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 flex items-center gap-2">
                    <ArrowRight className="w-3.5 h-3.5 text-blue-400 flex-shrink-0" />
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          /* Technical Report View */
          <div className="space-y-6 text-xs">
            <h3 className="text-sm font-bold text-slate-100">802.11 Layer Technical Inventory</h3>
            <div className="overflow-x-auto border border-slate-800 rounded-xl">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-800/80 text-slate-400 text-[10px] uppercase">
                  <tr>
                    <th className="p-2.5">BSSID</th>
                    <th className="p-2.5">SSID</th>
                    <th className="p-2.5">Ch / Band</th>
                    <th className="p-2.5">Security Suite</th>
                    <th className="p-2.5">PMF</th>
                    <th className="p-2.5">WPS</th>
                    <th className="p-2.5">Risk contributors</th>
                    <th className="p-2.5 text-right">Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {accessPoints.map(ap => (
                    <tr key={ap.bssid} className="hover:bg-slate-800/30">
                      <td className="p-2.5 text-slate-400">{ap.bssid}</td>
                      <td className="p-2.5 text-slate-100 font-sans font-semibold">{ap.ssid}</td>
                      <td className="p-2.5">Ch {ap.channel} ({ap.band})</td>
                      <td className="p-2.5">{ap.security}</td>
                      <td className="p-2.5">{ap.pmfRequired ? 'Required' : 'Disabled'}</td>
                      <td className="p-2.5">{ap.wpsEnabled ? 'Active' : 'Off'}</td>
                      <td className="p-2.5 font-sans text-[10px] max-w-xs">{(ap.riskFactors || []).length ? (ap.riskFactors || []).map(f => `+${f.points} ${f.name}`).join('; ') : 'None observed'}</td>
                      <td className="p-2.5 text-right font-bold text-emerald-400">{ap.securityScore}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Incidents Reference */}
            {incidents.length > 0 && (
              <div className="space-y-3 pt-4 border-t border-slate-800">
                <h3 className="text-sm font-bold text-slate-100">Active Incident Case Referrals</h3>
                <div className="space-y-2">
                  {incidents.map(inc => (
                    <div key={inc.id} className="p-3 rounded-lg bg-slate-800/40 border border-slate-800 flex items-center justify-between">
                      <div>
                        <span className="font-mono font-bold text-slate-200">{inc.id}</span>: {inc.title}
                        <div className="text-slate-400 text-[11px] mt-0.5">{inc.summary}</div>
                      </div>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase font-bold">
                        {inc.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

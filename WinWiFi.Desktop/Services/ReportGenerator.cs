using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using WinWiFi.Models;

namespace WinWiFi.Services
{
    public class ReportGenerator
    {
        private static string E(string? value) => System.Net.WebUtility.HtmlEncode(value ?? string.Empty);

        public string GenerateHtmlReport(AuditProject project, List<AccessPoint> accessPoints)
        {
            var sb = new StringBuilder();
            int total = accessPoints.Count;
            int highRisk = accessPoints.Count(a => a.SecurityScore < 60);
            int moderateRisk = accessPoints.Count(a => a.SecurityScore >= 60 && a.SecurityScore < 85);
            int compliant = accessPoints.Count(a => a.SecurityScore >= 85);
            int avgScore = total > 0 ? (int)accessPoints.Average(a => a.SecurityScore) : 100;

            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"en\">");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset=\"utf-8\">");
            sb.AppendLine($"<title>Wireless Security Audit - {E(project.Name)}</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0f1115; color: #e2e8f0; }");
            sb.AppendLine(".header { border-bottom: 2px solid #3b82f6; padding-bottom: 20px; margin-bottom: 30px; }");
            sb.AppendLine("h1 { margin: 0; color: #60a5fa; font-size: 26px; }");
            sb.AppendLine(".meta { color: #94a3b8; font-size: 14px; margin-top: 8px; }");
            sb.AppendLine(".metrics { display: flex; gap: 20px; margin-bottom: 30px; }");
            sb.AppendLine(".metric-box { background: #1a1d24; border: 1px solid #2d3340; border-radius: 8px; padding: 16px; flex: 1; }");
            sb.AppendLine(".metric-val { font-size: 28px; font-weight: bold; }");
            sb.AppendLine(".metric-lbl { color: #94a3b8; font-size: 12px; text-transform: uppercase; margin-top: 4px; }");
            sb.AppendLine("table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #161920; border-radius: 8px; overflow: hidden; }");
            sb.AppendLine("th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #252a36; font-size: 13px; }");
            sb.AppendLine("th { background: #1f242e; color: #94a3b8; font-weight: 600; }");
            sb.AppendLine(".score-bad { color: #ef4444; font-weight: bold; }");
            sb.AppendLine(".score-warn { color: #f59e0b; font-weight: bold; }");
            sb.AppendLine(".score-good { color: #10b981; font-weight: bold; }");
            sb.AppendLine(".badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }");
            sb.AppendLine(".badge-rogue { background: #7f1d1d; color: #fca5a5; }");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");

            sb.AppendLine("<div class=\"header\">");
            sb.AppendLine($"<h1>WinWiFi Executive Wireless Audit Report</h1>");
            sb.AppendLine($"<div class=\"meta\">Project: <strong>{E(project.Name)}</strong> | Auditor: <strong>{E(project.AuditorName)}</strong> | Generated: <strong>{DateTime.Now:yyyy-MM-dd HH:mm:ss}</strong></div>");
            sb.AppendLine("</div>");

            sb.AppendLine("<div class=\"metrics\">");
            sb.AppendLine($"<div class=\"metric-box\"><div class=\"metric-val\">{total}</div><div class=\"metric-lbl\">Discovered Networks</div></div>");
            sb.AppendLine($"<div class=\"metric-box\"><div class=\"metric-val score-bad\">{highRisk}</div><div class=\"metric-lbl\">High / Critical Vulnerabilities</div></div>");
            sb.AppendLine($"<div class=\"metric-box\"><div class=\"metric-val score-warn\">{moderateRisk}</div><div class=\"metric-lbl\">Moderate Risk</div></div>");
            sb.AppendLine($"<div class=\"metric-box\"><div class=\"metric-val score-good\">{compliant}</div><div class=\"metric-lbl\">NIST SP 800-153 Compliant</div></div>");
            sb.AppendLine($"<div class=\"metric-box\"><div class=\"metric-val\">{avgScore}/100</div><div class=\"metric-lbl\">Average Health Score</div></div>");
            sb.AppendLine("</div>");

            sb.AppendLine("<h2>Audited Wireless Access Points</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<thead><tr><th>SSID</th><th>BSSID</th><th>Channel / Band</th><th>Signal (RSSI)</th><th>Security & Cipher</th><th>Posture Score</th><th>Findings</th></tr></thead>");
            sb.AppendLine("<tbody>");

            foreach (var ap in accessPoints.OrderBy(a => a.SecurityScore))
            {
                string scoreClass = ap.SecurityScore < 60 ? "score-bad" : (ap.SecurityScore < 85 ? "score-warn" : "score-good");
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td><strong>{System.Net.WebUtility.HtmlEncode(ap.Ssid)}</strong> {(ap.IsRogue ? "<span class=\"badge badge-rogue\">ROGUE</span>" : "")}</td>");
                sb.AppendLine($"<td style=\"font-family:monospace;\">{E(ap.Bssid)}</td>");
                sb.AppendLine($"<td>Ch {ap.Channel} ({E(ap.Band)})</td>");
                sb.AppendLine($"<td>{ap.Rssi} dBm ({ap.SignalQuality}%)</td>");
                sb.AppendLine($"<td>{E(ap.Security)} ({E(ap.Cipher)})</td>");
                sb.AppendLine($"<td class=\"{scoreClass}\">{ap.SecurityScore} / 100</td>");
                sb.AppendLine($"<td>{E(string.Join(", ", ap.SecurityIssues.Select(i => i.Title)))}</td>");
                sb.AppendLine("</tr>");
            }

            sb.AppendLine("</tbody></table>");
            sb.AppendLine("</body></html>");

            return sb.ToString();
        }

        public void SaveReportToFile(string filePath, AuditProject project, List<AccessPoint> accessPoints)
        {
            string html = GenerateHtmlReport(project, accessPoints);
            File.WriteAllText(filePath, html, Encoding.UTF8);
        }

        public string GenerateMarkdownReport(string projectId, string projectName, List<AccessPoint> accessPoints, List<ThreatFinding> findings)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"# WinWiFi Forensic Wireless Security Audit Report");
            sb.AppendLine($"**Project:** {projectName} (`{projectId}`)  ");
            sb.AppendLine($"**Audit Date:** {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC  ");
            sb.AppendLine($"**Discovered Networks:** {accessPoints.Count} | **Threat Findings:** {findings.Count}  \n");

            sb.AppendLine("## 1. Executive Summary & Compliance Posture");
            int highRisk = accessPoints.Count(a => a.SecurityScore < 60);
            int compliant = accessPoints.Count(a => a.SecurityScore >= 85);
            int avgScore = accessPoints.Count > 0 ? (int)accessPoints.Average(a => a.SecurityScore) : 100;
            sb.AppendLine($"- **Average Security Health Score:** {avgScore} / 100");
            sb.AppendLine($"- **NIST SP 800-153 Compliant Networks:** {compliant}");
            sb.AppendLine($"- **High / Critical Risk Networks:** {highRisk}");
            sb.AppendLine($"- **Rogue AP / Evil Twin Alerts:** {findings.Count(f => f.Severity == "CRITICAL" || f.Severity == "HIGH")}\n");

            sb.AppendLine("## 2. Threat Findings & Incidents");
            if (findings.Count == 0)
            {
                sb.AppendLine("No active rogue APs, evil twins, or baseline drifts detected in the monitored airspace.\n");
            }
            else
            {
                foreach (var f in findings)
                {
                    sb.AppendLine($"### [{f.Severity}] {f.Title}");
                    sb.AppendLine($"- **Category:** {f.Category}");
                    sb.AppendLine($"- **Target BSSID:** `{f.RelatedBssid}`");
                    sb.AppendLine($"- **Description:** {f.Explanation}");
                    sb.AppendLine($"- **Evidence:** {f.Evidence}");
                    sb.AppendLine($"- **Recommendation:** {f.Remediation}");
                    sb.AppendLine($"- **Risk Score:** {f.RiskScore}/100 | **Confidence:** {f.Confidence}%\n");
                }
            }

            sb.AppendLine("## 3. Discovered Wireless Networks Catalogue");
            sb.AppendLine("| SSID | BSSID | Channel | Band | Signal (RSSI) | Security | Vendor | Score |");
            sb.AppendLine("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |");
            foreach (var ap in accessPoints.OrderBy(a => a.SecurityScore))
            {
                sb.AppendLine($"| **{ap.Ssid}** | `{ap.Bssid}` | {ap.Channel} | {ap.Band} | {ap.Rssi} dBm | {ap.Security} ({ap.Cipher}) | {ap.Vendor} | {ap.SecurityScore}/100 |");
            }

            return sb.ToString();
        }
    }
}

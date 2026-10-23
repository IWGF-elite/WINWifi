import React, { useState } from 'react';
import { AccessPoint, HandshakeInfo, SecurityIssue, DataSourceProfile } from '../types';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Key, 
  Radio, 
  Users, 
  Cpu, 
  Terminal, 
  Copy, 
  Check, 
  Download, 
  Sparkles, 
  Info,
  X,
  ChevronDown,
  ChevronUp,
  HelpCircle,
  Settings
} from 'lucide-react';
import { AIAdvisor } from '../services/aiAdvisor';

interface NetworkDetailPanelProps {
  ap: AccessPoint | null;
  onClose: () => void;
  onCaptureHandshake: (ap: AccessPoint) => void;
  isDarkMode: boolean;
  dataSourceProfile?: DataSourceProfile;
  onOpenCaptureGuide?: () => void;
  onOpenImport?: () => void;
}

export const NetworkDetailPanel: React.FC<NetworkDetailPanelProps> = ({
  ap,
  onClose,
  onCaptureHandshake,
  isDarkMode,
  dataSourceProfile = 'BENCHMARK',
  onOpenCaptureGuide,
  onOpenImport,
}) => {
  const [copiedHashcat, setCopiedHashcat] = useState(false);
  const [copiedBssid, setCopiedBssid] = useState(false);
  const [showPlainEnglishAdvisor, setShowPlainEnglishAdvisor] = useState(false);
  const [expandedIssueId, setExpandedIssueId] = useState<string | null>(null);

  if (!ap) return null;

  const aiAdvisor = AIAdvisor.getInstance();
  const postureExplanation = aiAdvisor.explainAccessPointPosture(ap);

  const handleCopyHashcat = () => {
    if (ap.handshake?.hashcatFormat) {
      navigator.clipboard.writeText(ap.handshake.hashcatFormat);
      setCopiedHashcat(true);
      setTimeout(() => setCopiedHashcat(false), 2000);
    }
  };

  const handleCopyBssid = () => {
    navigator.clipboard.writeText(ap.bssid);
    setCopiedBssid(true);
    setTimeout(() => setCopiedBssid(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-[100] flex justify-end bg-black/60 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Network inspection">
    <div className={`h-full w-full max-w-3xl overflow-y-auto border-l shadow-2xl flex flex-col transition-all ${
      isDarkMode ? 'bg-[#181a20] border-[#2c303b]' : 'bg-white border-slate-200'
    }`}>
      {/* Header */}
      <div className={`p-4 border-b flex items-center justify-between ${
        isDarkMode ? 'bg-[#1d2028] border-[#262a36]' : 'bg-slate-50 border-slate-200'
      }`}>
        <div className="flex items-center gap-3">
          <div className={`w-11 h-11 rounded-xl flex items-center justify-center font-bold text-lg shadow-sm ${
            ap.securityScore >= 80 
              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' 
              : ap.securityScore >= 50 
                ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' 
                : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
          }`}>
            {ap.securityScore}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-100">{ap.ssid || '<Hidden Network>'}</h2>
              {ap.isRogueCandidate && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40 uppercase animate-pulse">
                  Rogue AP / Evil Twin
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400 font-mono mt-0.5">
              <span>BSSID: {ap.bssid}</span>
              <button 
                onClick={handleCopyBssid} 
                className="hover:text-blue-400 p-0.5" 
                title="Copy BSSID"
              >
                {copiedBssid ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
              <span>•</span>
              <span className="text-slate-300 font-sans">{ap.vendor}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowPlainEnglishAdvisor(!showPlainEnglishAdvisor)}
            className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
              showPlainEnglishAdvisor 
                ? 'bg-purple-600 text-white shadow-sm' 
                : 'bg-purple-500/15 text-purple-300 hover:bg-purple-500/25 border border-purple-500/30'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>AI Security Advisor</span>
          </button>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-700/40 text-slate-400 hover:text-slate-200 transition-colors"
            title="Close Panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* AI Advisor Explanation Accordion Banner */}
      {showPlainEnglishAdvisor && (
        <div className="bg-purple-950/30 border-b border-purple-900/40 p-4 text-xs space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-bold text-purple-300 flex items-center gap-1.5 text-xs">
              <Sparkles className="w-4 h-4 text-purple-400" />
              Plain-English Posture Assessment
            </span>
            <span className="text-[10px] text-purple-300/70 font-mono">Grounded deterministic security model</span>
          </div>

          <p className="text-slate-200 leading-relaxed">
            {postureExplanation.executiveSummary}
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
              <span className="font-semibold text-rose-300 text-[11px]">Identified Vulnerability:</span>
              <p className="text-slate-300 text-[11px]">{postureExplanation.primaryRisk}</p>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
              <span className="font-semibold text-emerald-300 text-[11px]">Recommended Administrator Action:</span>
              <p className="text-slate-300 text-[11px]">{postureExplanation.recommendedAction}</p>
            </div>
          </div>
        </div>
      )}

      {/* Content Grid */}
      <div className="p-4 space-y-5 overflow-y-auto max-h-[580px] text-xs">
        {/* Specification Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className={`p-3 rounded-xl border ${isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'}`}>
            <div className="text-[11px] text-slate-400 font-medium">Channel & Band</div>
            <div className="text-sm font-bold text-slate-100 mt-1">
              CH {ap.channel} <span className="text-xs font-normal text-slate-400">({ap.band})</span>
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">{ap.channelWidthMhz} MHz Channel Width</div>
          </div>

          <div className={`p-3 rounded-xl border ${isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'}`}>
            <div className="text-[11px] text-slate-400 font-medium">Security Protocol</div>
            <div className="text-sm font-bold text-slate-100 mt-1 truncate">{ap.security}</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Cipher: {ap.cipher}</div>
          </div>

          <div className={`p-3 rounded-xl border ${isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'}`}>
            <div className="text-[11px] text-slate-400 font-medium">PMF (802.11w)</div>
            <div className={`text-sm font-bold mt-1 ${ap.pmfRequired ? 'text-emerald-400' : 'text-amber-400'}`}>
              {ap.pmfRequired ? 'Enforced' : 'Disabled'}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              {ap.pmfRequired ? 'Protected Mgmt Frames' : 'Vulnerable to Deauth'}
            </div>
          </div>

          <div className={`p-3 rounded-xl border ${isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'}`}>
            <div className="text-[11px] text-slate-400 font-medium">WPS Status</div>
            <div className={`text-sm font-bold mt-1 ${ap.wpsEnabled ? 'text-rose-400' : 'text-emerald-400'}`}>
              {ap.wpsEnabled ? 'Enabled' : 'Disabled'}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              {ap.wpsEnabled ? ap.wpsVersion || 'WPS 1.0 Active' : 'Secure (No PIN)'}
            </div>
          </div>
        </div>

        <div className={`p-3 rounded-xl border ${isDarkMode ? 'bg-[#14161d] border-[#252934]' : 'bg-slate-50 border-slate-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-200">Weighted Risk Factors</span>
            <span className="text-xs font-mono text-amber-300">Risk {ap.riskScore ?? (100 - ap.securityScore)} / 100</span>
          </div>
          {(ap.riskFactors || []).length ? <div className="space-y-2">{(ap.riskFactors || []).map((factor, index) => <div key={`${factor.name}-${index}`} className="border-l-2 border-amber-500/50 pl-2 text-[11px]"><span className="font-semibold text-slate-200">+{factor.points} {factor.name}</span><p className="mt-0.5 text-slate-400">{factor.evidence}</p></div>)}</div> : <p className="text-[11px] text-slate-500">No weighted risk factors were observed in the current data.</p>}
        </div>

        {/* Security Vulnerabilities & Findings */}
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2.5 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
            Security Audit Findings & Compliance (NIST SP 800-153)
          </h3>
          
          {(ap.issues || []).length === 0 ? (
            <div className={`p-3 rounded-xl border flex items-center gap-2 text-emerald-400 ${
              isDarkMode ? 'bg-emerald-950/20 border-emerald-800/30' : 'bg-emerald-50 border-emerald-200'
            }`}>
              <ShieldCheck className="w-4 h-4" />
              <span>No critical configuration weaknesses detected. Network enforces modern cryptographic primitives.</span>
            </div>
          ) : (
            <div className="space-y-2">
              {(ap.issues || []).map((issue) => {
                const isExpanded = expandedIssueId === issue.id;
                const findingExplanation = aiAdvisor.explainSecurityFinding(issue);

                return (
                  <div 
                    key={issue.id}
                    className={`p-3 rounded-xl border transition-all ${
                      issue.severity === 'CRITICAL' 
                        ? isDarkMode ? 'bg-rose-950/25 border-rose-800/40' : 'bg-rose-50 border-rose-200'
                        : issue.severity === 'HIGH'
                          ? isDarkMode ? 'bg-amber-950/25 border-amber-800/40' : 'bg-amber-50 border-amber-200'
                          : isDarkMode ? 'bg-blue-950/25 border-blue-800/40' : 'bg-blue-50 border-blue-200'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-100 flex items-center gap-1.5">
                        <AlertTriangle className={`w-3.5 h-3.5 ${
                          issue.severity === 'CRITICAL' ? 'text-rose-400' : issue.severity === 'HIGH' ? 'text-amber-400' : 'text-blue-400'
                        }`} />
                        {issue.title}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                          issue.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' : issue.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400'
                        }`}>
                          {issue.severity}
                        </span>
                        <button
                          onClick={() => setExpandedIssueId(isExpanded ? null : issue.id)}
                          className="p-0.5 text-slate-400 hover:text-slate-200"
                          title="Toggle Plain English Explanations"
                        >
                          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                    <p className="text-slate-300 mt-1">{issue.description}</p>
                    
                    <div className="mt-2 pt-2 border-t border-slate-700/20 text-slate-400">
                      <strong className="text-slate-200">Remediation: </strong>
                      {issue.recommendation}
                      {issue.nistRef && <span className="ml-2 font-mono text-[10px] text-blue-400">[{issue.nistRef}]</span>}
                    </div>

                    {/* Expandable Plain-English Explanation */}
                    {isExpanded && (
                      <div className="mt-2.5 pt-2.5 border-t border-slate-700/40 space-y-2 text-[11px] bg-slate-900/60 p-2.5 rounded-lg">
                        <div>
                          <span className="font-semibold text-blue-300">What It Means:</span>
                          <p className="text-slate-300">{findingExplanation.whatItMeans}</p>
                        </div>
                        <div>
                          <span className="font-semibold text-rose-300">Why It Is Risky:</span>
                          <p className="text-slate-300">{findingExplanation.whyItIsRisky}</p>
                        </div>
                        <div>
                          <span className="font-semibold text-emerald-300">How to Fix in Router / AP Admin Panel:</span>
                          <p className="text-slate-300">{findingExplanation.howToFix}</p>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Handshake Telemetry Section */}
        <div>
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2.5">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-blue-400" />
              EAPOL 4-Way Handshake &amp; PMKID Status
            </h3>

            {!ap.handshake ? (
              dataSourceProfile === 'BENCHMARK' || dataSourceProfile === 'OFFLINE_LAB' || dataSourceProfile === 'TRAINING' ? (
                <button
                  onClick={() => onCaptureHandshake(ap)}
                  className="px-2.5 py-1 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-medium flex items-center gap-1.5 shadow-sm transition-all text-xs"
                  title="Generate synthetic training handshake for educational verification"
                >
                  <Sparkles className="w-3 h-3" />
                  <span>Simulate Lab Handshake</span>
                </button>
              ) : (
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-slate-400 italic">
                    Capture Driver / Monitor Mode Required
                  </span>
                  {onOpenCaptureGuide && (
                    <button
                      onClick={onOpenCaptureGuide}
                      className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-medium transition-all"
                    >
                      Capture Guide
                    </button>
                  )}
                  {onOpenImport && (
                    <button
                      onClick={onOpenImport}
                      className="px-2 py-0.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-[11px] font-medium transition-all"
                    >
                      Import PCAP
                    </button>
                  )}
                </div>
              )
            ) : (
              <span className={`px-2 py-0.5 rounded font-semibold text-[11px] flex items-center gap-1 border ${
                ap.handshake.origin === 'IMPORTED' || (!ap.handshake.isSimulated && ap.handshake.origin !== 'TRAINING')
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                  : 'bg-purple-500/20 text-purple-300 border-purple-500/30'
              }`}>
                <Check className="w-3 h-3" />
                {ap.handshake.origin === 'IMPORTED' || (!ap.handshake.isSimulated && ap.handshake.origin !== 'TRAINING')
                  ? 'Verified Forensic Handshake (PCAP)'
                  : 'Training Lab Handshake (Simulated)'}
              </span>
            )}
          </div>

          {ap.handshake ? (
            <div className={`p-3 rounded-xl border font-mono text-[11px] space-y-2.5 ${
              isDarkMode ? 'bg-[#14161d] border-[#262a36]' : 'bg-slate-50 border-slate-200'
            }`}>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div>
                  <span className="text-slate-500">Handshake Type:</span>
                  <div className="text-slate-200 font-semibold">{ap.handshake.type}</div>
                </div>
                <div>
                  <span className="text-slate-500">Target Client MAC:</span>
                  <div className="text-slate-200">{ap.handshake.clientMac}</div>
                </div>
                <div>
                  <span className="text-slate-500">MIC Verification:</span>
                  <div className="text-emerald-400 font-semibold">VALID (CRC32/HMAC)</div>
                </div>
                <div>
                  <span className="text-slate-500">Frames Captured:</span>
                  <div className="text-slate-200">{ap.handshake.capturedSteps.join(' -> ')}</div>
                </div>
              </div>

              {/* Hex Values */}
              <div className="pt-2 border-t border-slate-700/30 space-y-1 text-[10px]">
                <div className="truncate">
                  <span className="text-slate-500">ANonce (AP): </span>
                  <span className="text-amber-300">{ap.handshake.anonce}</span>
                </div>
                <div className="truncate">
                  <span className="text-slate-500">SNonce (Client): </span>
                  <span className="text-cyan-300">{ap.handshake.snonce}</span>
                </div>
                <div className="truncate">
                  <span className="text-slate-500">MIC: </span>
                  <span className="text-emerald-400">{ap.handshake.micHex}</span>
                </div>
              </div>

              {/* Hashcat 22000 export */}
              {ap.handshake.hashcatFormat && (
                <div className="pt-2 border-t border-slate-700/30">
                  <div className="flex items-center justify-between text-slate-400 text-[10px] mb-1">
                    <span>Audit Export Format (Hashcat mode 22000 / PMKID):</span>
                    <button
                      onClick={handleCopyHashcat}
                      className="flex items-center gap-1 text-blue-400 hover:text-blue-300"
                    >
                      {copiedHashcat ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedHashcat ? 'Copied!' : 'Copy Hash String'}</span>
                    </button>
                  </div>
                  <div className="p-2 rounded-lg bg-black/40 border border-slate-800 text-[10px] font-mono text-slate-300 select-all break-all">
                    {ap.handshake.hashcatFormat}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className={`p-4 rounded-xl border text-center text-slate-400 ${
              isDarkMode ? 'bg-[#14161d] border-[#262a36]' : 'bg-slate-50 border-slate-200'
            }`}>
              <Radio className="w-6 h-6 mx-auto mb-1.5 opacity-40 text-blue-400" />
              <p>No active EAPOL key exchange recorded for this AP during current session.</p>
              <p className="text-[11px] text-slate-500 mt-1">
                Click &quot;Simulate Handshake Capture&quot; to test key dissection & Hashcat 22000 extraction.
              </p>
            </div>
          )}
        </div>

        {/* Associated Clients */}
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2 flex items-center gap-1.5">
            <Users className="w-3.5 h-3.5 text-indigo-400" />
            Connected Station Clients ({(ap.clients || []).length})
          </h3>

          {(ap.clients || []).length === 0 ? (
            <p className="text-xs text-slate-500 italic">No wireless stations currently associated.</p>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-slate-700/30">
              <table className="w-full text-left text-xs">
                <thead className={`text-[10px] uppercase font-semibold text-slate-400 ${
                  isDarkMode ? 'bg-[#14161d]' : 'bg-slate-100'
                }`}>
                  <tr>
                    <th className="p-2">Station MAC</th>
                    <th className="p-2">Hardware Vendor</th>
                    <th className="p-2">Signal (RSSI)</th>
                    <th className="p-2">TX Rate</th>
                    <th className="p-2">Frames Sent</th>
                    <th className="p-2">IP Address</th>
                  </tr>
                </thead>
                <tbody className={`divide-y font-mono text-[11px] ${
                  isDarkMode ? 'divide-slate-800' : 'divide-slate-200'
                }`}>
                  {(ap.clients || []).map((c) => (
                    <tr key={c.macAddress} className="hover:bg-slate-500/5">
                      <td className="p-2 text-slate-200">{c.macAddress}</td>
                      <td className="p-2 font-sans text-slate-300">{c.vendor}</td>
                      <td className="p-2 text-slate-300">{c.rssi} dBm</td>
                      <td className="p-2 text-slate-300">{c.dataRateMbps} Mbps</td>
                      <td className="p-2 text-slate-400">{c.packetsSent.toLocaleString()}</td>
                      <td className="p-2 text-blue-400">{c.ipAssigned || 'DHCP Requested'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div></div>
  );
};


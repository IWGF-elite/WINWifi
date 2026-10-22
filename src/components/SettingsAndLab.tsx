import React, { useState } from 'react';
import { 
  Sliders, 
  FlaskConical, 
  ShieldCheck, 
  Layers, 
  Terminal, 
  Cpu, 
  Check, 
  Play, 
  BookOpen, 
  Sparkles,
  ToggleLeft,
  ToggleRight,
  Code
} from 'lucide-react';
import { UIMode, SecurityPolicy, TrainingLabScenario, AccessPoint } from '../types';
import { PolicyEngine } from '../services/policyEngine';
import { TRAINING_SCENARIOS } from '../services/offlineLab';

interface SettingsAndLabProps {
  uiMode: UIMode;
  accessPoints: AccessPoint[];
  onToggleUIMode: (mode: UIMode) => void;
  onLoadLabScenario: (scenario: TrainingLabScenario) => void;
}

export const SettingsAndLab: React.FC<SettingsAndLabProps> = ({
  uiMode,
  accessPoints,
  onToggleUIMode,
  onLoadLabScenario
}) => {
  const policyEngine = PolicyEngine.getInstance();
  const [activePolicyId, setActivePolicyId] = useState(policyEngine.getActivePolicy().id);
  const [selectedLabId, setSelectedLabId] = useState('LAB-01');

  const policies = policyEngine.getPolicies();
  const currentPolicy = policyEngine.getActivePolicy();
  const selectedScenario = TRAINING_SCENARIOS.find(s => s.id === selectedLabId) || TRAINING_SCENARIOS[0];
  const policyResults = policyEngine.evaluateAll(accessPoints);
  const policyFailures = [...policyResults.values()].filter(result => result.status !== 'Compliant').length;

  const handlePolicyChange = (id: string) => {
    setActivePolicyId(id);
    policyEngine.setActivePolicy(id);
  };

  return (
    <div className="space-y-6 pb-8">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-blue-400">
            <Sliders className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-100">Platform Settings, Policies & Offline Lab</h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Customize presentation depth, configure zero-trust wireless security policies, and train in synthetic offline labs.
            </p>
          </div>
        </div>
      </div>

      {/* Section 1: Presentation Experience (Beginner vs Expert) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              Presentation Experience: Beginner vs Expert Mode
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Switches between plain-English guided summaries and deep 802.11 RSN/PMF/hexadecimal forensic inspection.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <span className={`text-xs font-semibold ${uiMode === 'beginner' ? 'text-blue-400 font-bold' : 'text-slate-400'}`}>
              Beginner Friendly
            </span>
            <button
              onClick={() => onToggleUIMode(uiMode === 'beginner' ? 'expert' : 'beginner')}
              className="text-blue-400 hover:text-blue-300 transition-colors"
            >
              {uiMode === 'expert' ? (
                <ToggleRight className="w-8 h-8 fill-current" />
              ) : (
                <ToggleLeft className="w-8 h-8 text-slate-600" />
              )}
            </button>
            <span className={`text-xs font-semibold ${uiMode === 'expert' ? 'text-purple-400 font-bold' : 'text-slate-400'}`}>
              Expert Auditor
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className={`p-3.5 rounded-xl border transition-all ${
            uiMode === 'beginner' ? 'bg-blue-500/10 border-blue-500/40 text-slate-200' : 'bg-slate-800/40 border-slate-800 text-slate-400'
          }`}>
            <div className="font-bold text-slate-100 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-blue-400" />
              Beginner Mode (Simple on the Surface)
            </div>
            <p className="mt-1.5 text-xs text-slate-300 leading-relaxed">
              Focuses on plain-English status indicators ("Safe", "Warning", "Danger"), what each risk means, and clear instructions on what router settings to change. Perfect for non-auditors or initial triage.
            </p>
          </div>

          <div className={`p-3.5 rounded-xl border transition-all ${
            uiMode === 'expert' ? 'bg-purple-500/10 border-purple-500/40 text-slate-200' : 'bg-slate-800/40 border-slate-800 text-slate-400'
          }`}>
            <div className="font-bold text-slate-100 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-purple-400" />
              Expert Mode (Power Under the Hood)
            </div>
            <p className="mt-1.5 text-xs text-slate-300 leading-relaxed">
              Unlocks full 802.11 RSN Tag 48 parsing, AKM cipher suites, Protected Management Frame bitflags, Radiotap antenna measurements, raw hexadecimal packet inspector, and Hashcat Mode 22000 exports.
            </p>
          </div>
        </div>
      </div>

      {/* Section 2: Security Policy Engine */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Configurable Wireless Security Policy Engine
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Every discovered network and capture is continuously audited against this baseline.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          {policies.map(pol => {
            const isSelected = pol.id === activePolicyId;

            return (
              <div
                key={pol.id}
                onClick={() => handlePolicyChange(pol.id)}
                className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                  isSelected 
                    ? 'bg-emerald-500/10 border-emerald-500/50 text-slate-100 ring-1 ring-emerald-500/30' 
                    : 'bg-slate-800/40 border-slate-800 text-slate-400 hover:bg-slate-800/70'
                }`}
              >
                <div className="flex items-center justify-between font-bold">
                  <span>{pol.name}</span>
                  {isSelected && <Check className="w-3.5 h-3.5 text-emerald-400" />}
                </div>
                <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{pol.description}</p>
                <div className="text-[10px] text-slate-500 font-mono mt-2 pt-2 border-t border-slate-800/60">
                  Min: {pol.minSecurity}
                </div>
              </div>
            );
          })}
        </div>

        {/* Current Active Policy Criteria */}
        <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700/60 text-xs space-y-2">
          <div className="font-semibold text-slate-200">Enforced Requirements for {currentPolicy.name}:</div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-slate-300">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>WPS Prohibited: <strong>{currentPolicy.wpsProhibited ? 'Yes' : 'No'}</strong></span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>PMF 802.11w Required: <strong>{currentPolicy.pmfRequired ? 'Yes' : 'No'}</strong></span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>WPA3 Mandated: <strong>{currentPolicy.wpa3Required ? 'Yes' : 'No'}</strong></span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>WEP Prohibited: <strong>{currentPolicy.wepProhibited ? 'Yes' : 'No'}</strong></span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>TKIP Prohibited: <strong>{currentPolicy.tkipProhibited ? 'Yes' : 'No'}</strong></span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Open Prohibited: <strong>{currentPolicy.openProhibited ? 'Yes' : 'No'}</strong></span>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-bold text-slate-100">Current Policy Results</h2>
          <span className="text-xs text-slate-400">{accessPoints.length} observations · {currentPolicy.name}</span>
        </div>
        {accessPoints.length === 0 ? (
          <p className="text-xs text-slate-400">No observations loaded. Connect the Windows bridge, import a capture, or load a Training Lab scenario to evaluate this policy.</p>
        ) : (
          <>
            <p className="text-xs text-slate-300">{policyResults.size - policyFailures} compliant · {policyFailures} require review</p>
            <div className="max-h-72 overflow-y-auto divide-y divide-slate-800">
              {[...policyResults.values()].map(result => (
                <div key={result.apBssid} className="py-2 text-xs">
                  <div className="flex justify-between gap-3"><span className="font-mono text-slate-200">{result.apBssid}</span><span className={result.status === 'Compliant' ? 'text-emerald-400' : result.status === 'Warning' ? 'text-amber-400' : 'text-rose-400'}>{result.status}</span></div>
                  <div className="text-slate-400 mt-1">{result.failedRules.length ? result.failedRules.join(' · ') : 'No policy violations found.'}</div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Section 3: Offline Training & Lab Workbench */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <FlaskConical className="w-4 h-4 text-purple-400" />
              Offline Interactive Laboratory & Training Scenarios
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Simulate enterprise scenarios, vulnerabilities, rogue clones, and handshake dissections without touching a live network.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Left: Scenarios List (5 cols) */}
          <div className="lg:col-span-5 space-y-2 max-h-[300px] overflow-y-auto pr-1">
            {TRAINING_SCENARIOS.map(sc => {
              const isSelected = sc.id === selectedLabId;

              return (
                <div
                  key={sc.id}
                  onClick={() => setSelectedLabId(sc.id)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all text-xs ${
                    isSelected
                      ? 'bg-purple-500/10 border-purple-500/50 text-slate-100'
                      : 'bg-slate-800/40 border-slate-800 text-slate-400 hover:bg-slate-800/70'
                  }`}
                >
                  <div className="flex items-center justify-between font-semibold">
                    <span>{sc.title}</span>
                    <span className="text-[10px] uppercase font-bold px-1.5 py-0.2 rounded bg-slate-800 text-purple-300">
                      {sc.difficulty}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 line-clamp-1">{sc.description}</p>
                </div>
              );
            })}
          </div>

          {/* Right: Selected Scenario Guided Breakdown (7 cols) */}
          <div className="lg:col-span-7 p-4 rounded-xl bg-slate-800/40 border border-slate-700/60 text-xs space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100">{selectedScenario.title}</h3>
              <button
                onClick={() => onLoadLabScenario(selectedScenario)}
                className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold flex items-center gap-1.5 shadow-sm transition-all text-xs"
              >
                <Play className="w-3.5 h-3.5 fill-current" /> Load Lab Scenario
              </button>
            </div>

            <p className="text-slate-300">{selectedScenario.guidedExplanation.overview}</p>

            <div className="space-y-1.5">
              <div className="font-semibold text-purple-300">Why It Matters:</div>
              <p className="text-slate-400 text-[11px]">{selectedScenario.guidedExplanation.whyItMatters}</p>
            </div>

            <div className="space-y-1.5">
              <div className="font-semibold text-blue-300">How to Investigate in WinWiFi:</div>
              <p className="text-slate-400 text-[11px]">{selectedScenario.guidedExplanation.howToInvestigate}</p>
            </div>

            <div className="space-y-1.5">
              <div className="font-semibold text-emerald-300">Defensive Remediation:</div>
              <p className="text-slate-400 text-[11px]">{selectedScenario.guidedExplanation.remediation}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Section 4: Local Administrative Automation & REST API */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
        <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <Code className="w-4 h-4 text-blue-400" />
          Local Administrative Automation & REST API
        </h2>
        <p className="text-xs text-slate-400">
          WinWiFi exposes local-only (loopback) read-only endpoints for SOC integration, SIEM logging, and enterprise orchestration.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs font-mono">
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-emerald-400 font-bold">GET</span> /api/v1/projects
            <div className="text-slate-500 text-[10px] font-sans mt-0.5">Enumerate assessment projects</div>
          </div>
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-emerald-400 font-bold">GET</span> /api/v1/networks
            <div className="text-slate-500 text-[10px] font-sans mt-0.5">Stream live AP inventory & scores</div>
          </div>
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-emerald-400 font-bold">GET</span> /api/v1/threats
            <div className="text-slate-500 text-[10px] font-sans mt-0.5">Retrieve active rogue AP alerts</div>
          </div>
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-emerald-400 font-bold">GET</span> /api/v1/health
            <div className="text-slate-500 text-[10px] font-sans mt-0.5">Check scanner & adapter status</div>
          </div>
        </div>
      </div>
    </div>
  );
};

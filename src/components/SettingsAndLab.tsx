import React, { useState } from 'react';
import {
  Sliders,
  ShieldCheck,
  Check,
  Sparkles,
  GraduationCap,
  SlidersHorizontal,
  Code
} from 'lucide-react';
import { UIMode, AccessPoint, MaintenanceApprovalRecord } from '../types';
import { PolicyEngine, POLICY_CLASSIFICATION_ROUTES } from '../services/policyEngine';
import { MaintenanceApprovalCenter } from './MaintenanceApprovalCenter';
import { AuditTrailCenter } from './AuditTrailCenter';
import { AuditChainState } from '../services/auditChain';
import { OperatorRole, can } from '../services/operatorRoles';

interface SettingsAndLabProps {
  uiMode: UIMode;
  accessPoints: AccessPoint[];
  onToggleUIMode: (mode: UIMode) => void;
  maintenanceApprovals: MaintenanceApprovalRecord[];
  onApproveMaintenance: (id: string, approver: string) => Promise<void>;
  onRejectMaintenance: (id: string, approver: string, note: string) => Promise<void>;
  onRevokeMaintenance: (id: string) => Promise<void>;
  auditChain: AuditChainState;
  operatorName: string;
  operatorRole: OperatorRole;
  onOperatorNameChange: (name: string) => void;
  onOperatorRoleChange: (role: OperatorRole) => void;
  onExportAudit: () => Promise<void>;
  onResetAudit: () => Promise<void>;
  auditError?: string;
}

export const SettingsAndLab: React.FC<SettingsAndLabProps> = ({
  uiMode,
  accessPoints,
  onToggleUIMode,
  maintenanceApprovals,
  onApproveMaintenance,
  onRejectMaintenance,
  onRevokeMaintenance,
  auditChain,
  operatorName,
  operatorRole,
  onOperatorNameChange,
  onOperatorRoleChange,
  onExportAudit,
  onResetAudit,
  auditError
}) => {
  const policyEngine = PolicyEngine.getInstance();
  const [activePolicyId, setActivePolicyId] = useState(policyEngine.getActivePolicy().id);

  const policies = policyEngine.getPolicies();
  const currentPolicy = policyEngine.getActivePolicy();
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
            <h1 className="text-lg font-bold text-slate-100">Platform Settings &amp; Security Policies</h1>
          </div>
        </div>
      </div>

      {/* Section 1: Presentation Experience (Beginner vs Expert) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              Display Mode
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Choose a guided, low-clutter view or show the full technical detail across the workspace.
            </p>
          </div>

          <div role="group" aria-label="Select display mode" className="grid grid-cols-2 gap-1 rounded-xl border border-slate-700 bg-slate-950/70 p-1">
            <button
              type="button"
              onClick={() => onToggleUIMode('beginner')}
              aria-pressed={uiMode === 'beginner'}
              className={`flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition-all ${uiMode === 'beginner' ? 'bg-blue-600 text-white shadow-md shadow-blue-950/40' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'}`}
            >
              <GraduationCap className="h-4 w-4" /> Beginner
            </button>
            <button
              type="button"
              onClick={() => onToggleUIMode('expert')}
              aria-pressed={uiMode === 'expert'}
              className={`flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition-all ${uiMode === 'expert' ? 'bg-blue-600 text-white shadow-md shadow-blue-950/40' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'}`}
            >
              <SlidersHorizontal className="h-4 w-4" /> Expert
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className={`p-3.5 rounded-xl border transition-all ${
            uiMode === 'beginner' ? 'bg-blue-500/10 border-blue-500/40 text-slate-200' : 'bg-slate-800/40 border-slate-800 text-slate-400'
          }`}>
            <div className="font-bold text-slate-100 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-blue-400" />
              Beginner Mode · Guided view
            </div>
            <p className="mt-1.5 text-xs text-slate-300 leading-relaxed">
              Uses plain-language signal and security summaries, fewer table columns, and guided next steps. Full records remain available from Inspect.
            </p>
          </div>

          <div className={`p-3.5 rounded-xl border transition-all ${
            uiMode === 'expert' ? 'bg-purple-500/10 border-purple-500/40 text-slate-200' : 'bg-slate-800/40 border-slate-800 text-slate-400'
          }`}>
            <div className="font-bold text-slate-100 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-purple-400" />
              Expert Mode · Full detail
            </div>
            <p className="mt-1.5 text-xs text-slate-300 leading-relaxed">
              Shows network identifiers, radio measurements, cipher details, capture fields, and diagnostic event logs for deeper review.
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
            Classified assets are routed to the policy assigned to their class. The selected policy is the default for unclassified and Unknown assets.
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

        {/* Classification Routing & Approval Enforcement */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
          <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700/60 space-y-2">
            <div className="font-semibold text-slate-200">Classification Routing</div>
            <p className="text-[11px] text-slate-400">Classified assets are evaluated against their assigned policy, even when another policy is selected as default.</p>
            <div className="space-y-1.5">
              {POLICY_CLASSIFICATION_ROUTES.map(route => {
                const target = policies.find(policy => policy.id === route.policyId);
                return (
                  <div key={route.classification} className="flex items-center justify-between gap-2">
                    <span className="text-slate-300">{route.classification}</span>
                    <span className="text-slate-400 font-medium">{target?.name ?? route.policyId}</span>
                  </div>
                );
              })}
              <div className="flex items-center justify-between gap-2 border-t border-slate-700/60 pt-1.5">
                <span className="text-slate-300">Unknown / unclassified</span>
                <span className="text-slate-400 font-medium">{currentPolicy.name} (default)</span>
              </div>
            </div>
          </div>
          <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700/60 space-y-2">
            <div className="font-semibold text-slate-200">Registry Approval Enforcement</div>
            <p className="text-[11px] text-slate-400">Approval status is evaluated alongside the security baseline for enrolled BSSIDs.</p>
            <div className="space-y-1.5 text-slate-300">
              <div className="flex justify-between gap-2"><span>Approved</span><span className="text-emerald-400">No finding</span></div>
              <div className="flex justify-between gap-2"><span>Pending Review</span><span className="text-amber-400">Warning</span></div>
              <div className="flex justify-between gap-2"><span>Under Investigation</span><span className="text-amber-400">Warning</span></div>
              <div className="flex justify-between gap-2"><span>Unapproved / Decommissioned</span><span className="text-rose-400">Non-Compliant</span></div>
              <div className="flex justify-between gap-2 border-t border-slate-700/60 pt-1.5"><span>Rogue classification</span><span className="text-rose-400">Non-Compliant</span></div>
            </div>
          </div>
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
          <p className="text-xs text-slate-400">No scan data yet. Run a scan or import a capture to evaluate this policy.</p>
        ) : (
          <>
            <p className="text-xs text-slate-300">{policyResults.size - policyFailures} compliant · {policyFailures} require review</p>
            <div className="max-h-72 overflow-y-auto divide-y divide-slate-800">
              {[...policyResults.values()].map(result => (
                <div key={result.apBssid} className="py-2 text-xs">
                  <div className="flex justify-between gap-3"><span className="font-mono text-slate-200">{result.apBssid}</span><span className={result.status === 'Compliant' ? 'text-emerald-400' : result.status === 'Warning' ? 'text-amber-400' : 'text-rose-400'}>{result.status}</span></div>
                  <div className="text-slate-500 mt-0.5">
                    {result.policyName} · {result.classification ?? 'Unclassified'} · {result.approvalStatus ?? 'Not enrolled'}
                  </div>
                  <div className="text-slate-400 mt-1">{result.failedRules.length ? result.failedRules.join(' · ') : 'No policy violations found.'}</div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      <MaintenanceApprovalCenter
        approvals={maintenanceApprovals}
        onApprove={onApproveMaintenance}
        onReject={onRejectMaintenance}
        onRevoke={onRevokeMaintenance}
        canDecide={can(operatorRole, 'approve_maintenance')}
      />

      <AuditTrailCenter
        chain={auditChain}
        operatorName={operatorName}
        operatorRole={operatorRole}
        onOperatorNameChange={onOperatorNameChange}
        onOperatorRoleChange={onOperatorRoleChange}
        onExport={onExportAudit}
        onReset={onResetAudit}
        error={auditError}
      />

      {/* Section 4: Local Administrative Automation & REST API */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
        <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <Code className="w-4 h-4 text-blue-400" />
          Local Administrative Automation & REST API
        </h2>
        <p className="text-xs text-slate-400">
          The Windows bridge exposes local endpoints for network observations, incidents, diagnostics, and health. Scan and import actions are also available through the bridge.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs font-mono">
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-emerald-400 font-bold">GET</span> /api/networks
            <div className="text-slate-500 text-[10px] font-sans mt-0.5">Read current Windows WLAN observations</div>
          </div>
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-emerald-400 font-bold">GET</span> /api/incidents
            <div className="text-slate-500 text-[10px] font-sans mt-0.5">Read locally recorded incidents</div>
          </div>
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-emerald-400 font-bold">GET</span> /api/diagnostics
            <div className="text-slate-500 text-[10px] font-sans mt-0.5">Read adapter and scanner diagnostics</div>
          </div>
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-emerald-400 font-bold">GET</span> /api/health
            <div className="text-slate-500 text-[10px] font-sans mt-0.5">Check scanner & adapter status</div>
          </div>
        </div>
      </div>
    </div>
  );
};

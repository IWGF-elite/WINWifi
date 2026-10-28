import React, { useMemo, useState } from 'react';
import { Download, Hash, RotateCcw, ShieldAlert, ShieldCheck, Users } from 'lucide-react';
import { AuditChainState, headHashOf, verifyAuditChain } from '../services/auditChain';
import { OPERATOR_ROLES, OperatorRole, ROLE_DESCRIPTIONS } from '../services/operatorRoles';

interface AuditTrailCenterProps {
  chain: AuditChainState;
  operatorName: string;
  operatorRole: OperatorRole;
  onOperatorNameChange: (name: string) => void;
  onOperatorRoleChange: (role: OperatorRole) => void;
  onExport: () => Promise<void>;
  onReset: () => Promise<void>;
  error?: string;
}

export const AuditTrailCenter: React.FC<AuditTrailCenterProps> = ({
  chain,
  operatorName,
  operatorRole,
  onOperatorNameChange,
  onOperatorRoleChange,
  onExport,
  onReset,
  error
}) => {
  const [busy, setBusy] = useState(false);
  const [confirmingReset, setConfirmingReset] = useState(false);
  const [message, setMessage] = useState('');

  const verification = useMemo(() => verifyAuditChain(chain), [chain]);
  const recent = useMemo(() => [...chain.records].slice(-25).reverse(), [chain.records]);
  const head = headHashOf(chain);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setMessage('');
    try {
      await action();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Hash className="w-4 h-4 text-cyan-400" />
            Operator Role & Tamper-Evident Audit Trail
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Sensitive actions are appended to a SHA-256 hash chain scoped to this project. Editing, reordering, or deleting a record breaks verification.
          </p>
        </div>
        <span className={`rounded border px-2 py-0.5 text-[11px] font-mono ${
          verification.valid
            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
            : 'border-rose-500/30 bg-rose-500/10 text-rose-300'
        }`}>
          {verification.valid ? 'CHAIN VERIFIED' : 'CHAIN BROKEN'}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        <label className="space-y-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Operator name (recorded locally)</span>
          <input
            value={operatorName}
            onChange={event => onOperatorNameChange(event.target.value)}
            maxLength={80}
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </label>
        <label className="space-y-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Local operator role</span>
          <select
            value={operatorRole}
            onChange={event => onOperatorRoleChange(event.target.value as OperatorRole)}
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100 focus:border-blue-500 focus:outline-none"
          >
            {OPERATOR_ROLES.map(role => (
              <option key={role} value={role}>{role}</option>
            ))}
          </select>
        </label>
      </div>

      <div className="rounded-lg border border-slate-700/60 bg-slate-800/40 p-3 text-[11px] text-slate-300">
        <div className="flex items-center gap-1.5 font-semibold text-slate-200"><Users className="h-3.5 w-3.5" /> {operatorRole}</div>
        <p className="mt-1 text-slate-400">{ROLE_DESCRIPTIONS[operatorRole]}</p>
        <p className="mt-1 text-amber-300/90">
          This is a desktop-local guardrail, not authentication. Anyone with access to this Windows profile can change the role.
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Records</div>
          <div className="mt-1 font-mono text-slate-100">{chain.records.length}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Checked</div>
          <div className="mt-1 font-mono text-slate-100">{verification.checked}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Chain</div>
          <div className="mt-1 truncate font-mono text-slate-100" title={chain.chainId}>{chain.chainId}</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Created</div>
          <div className="mt-1 text-slate-100">{new Date(chain.createdAt).toLocaleDateString()}</div>
        </div>
      </div>

      {!verification.valid && (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200" role="alert">
          <div className="flex items-center gap-1.5 font-semibold"><ShieldAlert className="h-4 w-4" /> Verification failed at record {verification.brokenAt}</div>
          <p className="mt-1">{verification.reason}</p>
          <p className="mt-1 text-rose-300/80">Do not trust this project's audit trail. Export it for investigation, then start a new chain.</p>
        </div>
      )}

      <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5">
        <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-slate-500"><ShieldCheck className="h-3 w-3" /> Head hash</div>
        <div className="mt-1 break-all font-mono text-[10px] text-cyan-300">{head}</div>
      </div>
      <p className="text-[10px] text-slate-500">
        SHA-256 links detect edits, reordering, and gaps inside this chain. Because the chain is stored locally, truncating the newest records cannot be detected without an external anchor — export the chain and store the head hash separately for stronger evidence.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => void run(onExport)}
          disabled={busy}
          className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-40"
        >
          <Download className="h-3.5 w-3.5" /> Export chain JSON
        </button>
        {!confirmingReset ? (
          <button
            type="button"
            onClick={() => setConfirmingReset(true)}
            disabled={busy || operatorRole !== 'Administrator'}
            className="flex items-center gap-1.5 rounded-lg border border-slate-600 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-40"
          >
            <RotateCcw className="h-3.5 w-3.5" /> Start new chain
          </button>
        ) : (
          <span className="flex flex-wrap items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-200">
            Export first. The current head is archived in a CHAIN_RESET record.
            <button
              type="button"
              onClick={() => void run(async () => { await onReset(); setConfirmingReset(false); setMessage('New audit chain started.'); })}
              disabled={busy}
              className="rounded bg-amber-600 px-2 py-1 font-semibold text-white disabled:opacity-40"
            >
              Confirm rotation
            </button>
            <button type="button" onClick={() => setConfirmingReset(false)} className="rounded border border-slate-600 px-2 py-1">Cancel</button>
          </span>
        )}
      </div>

      {(message || error) && (
        <p role={error ? 'alert' : 'status'} className={`text-[11px] ${error ? 'text-rose-300' : 'text-emerald-300'}`}>{error || message}</p>
      )}

      <div>
        <div className="mb-1.5 flex items-center justify-between text-xs">
          <span className="font-semibold text-slate-200">Recent chained events</span>
          <span className="text-slate-500">{chain.records.length} total</span>
        </div>
        {recent.length === 0 ? (
          <p className="rounded-lg border border-dashed border-slate-700 bg-slate-800/30 px-3 py-5 text-center text-xs text-slate-400">
            No chained events yet. Asset edits, project changes, maintenance decisions, and connect attempts will appear here.
          </p>
        ) : (
          <div className="max-h-72 divide-y divide-slate-800 overflow-y-auto rounded-lg border border-slate-800">
            {recent.map(record => (
              <div key={record.hash} className="px-3 py-2 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[10px] text-slate-500">#{record.seq}</span>
                  <span className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300">{record.action}</span>
                  <span className="text-[10px] text-slate-500">{new Date(record.timestamp).toLocaleString()}</span>
                </div>
                <div className="mt-1 text-slate-200">{record.subject}</div>
                <div className="mt-0.5 text-[11px] text-slate-400">{record.details}</div>
                <div className="mt-0.5 text-[10px] text-slate-500">by {record.actor} ({record.role})</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

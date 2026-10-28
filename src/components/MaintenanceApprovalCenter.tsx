import React, { useMemo, useState } from 'react';
import { Ban, CheckCircle2, Clock, KeyRound, ShieldCheck, ShieldX, UserCheck, XCircle } from 'lucide-react';
import { MaintenanceApprovalRecord, MaintenanceApprovalStatus } from '../types';
import { countActiveApprovals } from '../services/maintenanceApproval';

interface MaintenanceApprovalCenterProps {
  approvals: MaintenanceApprovalRecord[];
  onApprove: (id: string, approver: string) => Promise<void>;
  onReject: (id: string, approver: string, note: string) => Promise<void>;
  onRevoke: (id: string) => Promise<void>;
  canDecide?: boolean;
}

const statusStyles: Record<MaintenanceApprovalStatus, string> = {
  Pending: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  Approved: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  Rejected: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  Expired: 'border-slate-600 bg-slate-800/60 text-slate-400',
  Revoked: 'border-slate-600 bg-slate-800/60 text-slate-400'
};

const formatTime = (iso?: string): string => {
  if (!iso) return '—';
  const date = new Date(iso);
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : '—';
};

const effectiveStatus = (record: MaintenanceApprovalRecord): MaintenanceApprovalStatus =>
  (record.status === 'Pending' || record.status === 'Approved') &&
  Date.parse(record.expiresAt) <= Date.now()
    ? 'Expired'
    : record.status;

export const MaintenanceApprovalCenter: React.FC<MaintenanceApprovalCenterProps> = ({
  approvals,
  onApprove,
  onReject,
  onRevoke,
  canDecide = true
}) => {
  const [approverName, setApproverName] = useState('');
  const [decisionNote, setDecisionNote] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState('');

  const sorted = useMemo(
    () => [...approvals].sort((left, right) => Date.parse(right.requestedAt) - Date.parse(left.requestedAt)),
    [approvals]
  );
  const pendingCount = approvals.filter(record => effectiveStatus(record) === 'Pending').length;
  const activeCount = countActiveApprovals(approvals);

  const run = async (id: string, action: () => Promise<void>) => {
    setBusyId(id);
    setError('');
    try {
      await action();
      setDecisionNote('');
    } catch (err: any) {
      setError(err?.message || 'The maintenance decision could not be recorded.');
    } finally {
      setBusyId(null);
    }
  };

  const hasApproverName = approverName.trim().length >= 2;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-amber-400" />
            Maintenance Approvals
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Active actions require a time-boxed, two-person approval. The approver must be a different person from the requester.
          </p>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono">
          <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-amber-300">{pendingCount} pending</span>
          <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-300">{activeCount} active</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
        <label className="space-y-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Acting approver</span>
          <input
            value={approverName}
            onChange={event => setApproverName(event.target.value)}
            placeholder="Name of the person approving or rejecting"
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </label>
        <label className="space-y-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Decision note (optional)</span>
          <input
            value={decisionNote}
            onChange={event => setDecisionNote(event.target.value)}
            placeholder="Reason for rejection or conditions"
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </label>
      </div>

      <p className="text-[11px] text-slate-500">
        Approvals live in this project's local workspace. The native bridge still enforces its own authorization flag and BSSID allow-list when a connection is requested.
      </p>
      {!canDecide && (
        <p className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-300">
          The current local role cannot approve, reject, or revoke maintenance requests. Switch to Administrator in the audit section below.
        </p>
      )}

      {error && <p role="alert" className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">{error}</p>}

      {sorted.length === 0 ? (
        <p className="rounded-lg border border-dashed border-slate-700 bg-slate-800/30 px-3 py-6 text-center text-xs text-slate-400">
          No maintenance requests in this project. Open a network's inspection panel to request one for a connection action.
        </p>
      ) : (
        <div className="max-h-[420px] space-y-2 overflow-y-auto pr-1">
          {sorted.map(record => {
            const status = effectiveStatus(record);
            const busy = busyId === record.id;
            return (
              <div key={record.id} className="rounded-lg border border-slate-800 bg-slate-800/30 p-3 text-xs space-y-2">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${statusStyles[status]}`}>{status}</span>
                      <span className="font-semibold text-slate-100">{record.action}</span>
                    </div>
                    <div className="mt-1 font-mono text-[11px] text-slate-400">
                      {record.ssid || '[No SSID]'} · {record.bssid}
                    </div>
                  </div>
                  <div className="text-right text-[10px] text-slate-500">
                    <div className="flex items-center justify-end gap-1"><Clock className="h-3 w-3" /> expires {formatTime(record.expiresAt)}</div>
                    {record.lastUsedAt && <div>last used {formatTime(record.lastUsedAt)}</div>}
                  </div>
                </div>

                <p className="text-slate-300">{record.justification}</p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-[11px] text-slate-400">
                  <div className="flex items-center gap-1"><UserCheck className="h-3 w-3" /> Requested by <strong className="text-slate-200">{record.requester}</strong> · {formatTime(record.requestedAt)}</div>
                  <div className="flex items-center gap-1">
                    {record.approver ? <ShieldCheck className="h-3 w-3" /> : <ShieldX className="h-3 w-3" />}
                    {record.approver ? <>Decision by <strong className="text-slate-200">{record.approver}</strong></> : 'Awaiting a second person'}
                  </div>
                </div>
                {record.decisionNote && <p className="text-[11px] text-slate-400">Note: {record.decisionNote}</p>}

                {status === 'Pending' && (
                  <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-2">
                    <button
                      type="button"
                      disabled={!hasApproverName || !canDecide || busy}
                      onClick={() => void run(record.id, () => onApprove(record.id, approverName))}
                      className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 font-semibold text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5" /> {busy ? 'Saving…' : 'Approve'}
                    </button>
                    <button
                      type="button"
                      disabled={!hasApproverName || !canDecide || busy}
                      onClick={() => void run(record.id, () => onReject(record.id, approverName, decisionNote))}
                      className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 px-3 py-1.5 font-semibold text-rose-300 hover:bg-rose-500/10 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      <XCircle className="h-3.5 w-3.5" /> Reject
                    </button>
                    {!hasApproverName && <span className="text-[10px] text-slate-500">Enter the acting approver first.</span>}
                  </div>
                )}

                {status === 'Approved' && (
                  <div className="flex items-center justify-between gap-2 border-t border-slate-800 pt-2">
                    <span className="text-[11px] text-emerald-300">Connect actions for this BSSID are unlocked until the window expires.</span>
                    <button
                      type="button"
                      disabled={busy || !canDecide}
                      onClick={() => void run(record.id, () => onRevoke(record.id))}
                      className="flex items-center gap-1.5 rounded-lg border border-slate-600 px-3 py-1.5 text-slate-300 hover:bg-slate-700 disabled:opacity-40"
                    >
                      <Ban className="h-3.5 w-3.5" /> Revoke
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

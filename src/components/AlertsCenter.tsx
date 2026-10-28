import React, { useMemo, useState } from 'react';
import { BellRing, CheckCircle2, Clock, ShieldAlert } from 'lucide-react';
import {
  ALERT_RULES,
  AlertRecord,
  AlertSeverity,
  SEVERITY_ORDER,
  summarizeAlerts
} from '../services/alerts';

interface AlertsCenterProps {
  alerts: AlertRecord[];
  openInvestigationsCount: number;
  operatorName: string;
  canAcknowledge: boolean;
  liveObservationCount: number;
  alertEligibleObservationCount: number;
  onAcknowledge: (id: string) => Promise<void>;
}

const severityStyles: Record<AlertSeverity, string> = {
  Critical: 'border-rose-500/40 bg-rose-500/15 text-rose-300',
  High: 'border-amber-500/40 bg-amber-500/15 text-amber-300',
  Medium: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-300',
  Low: 'border-slate-600 bg-slate-800/60 text-slate-300'
};

const statusStyles: Record<AlertRecord['status'], string> = {
  Open: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  Acknowledged: 'border-blue-500/30 bg-blue-500/10 text-blue-300',
  Resolved: 'border-slate-600 bg-slate-800/60 text-slate-400'
};

const formatTime = (iso: string): string => {
  const date = new Date(iso);
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : '—';
};

export const AlertsCenter: React.FC<AlertsCenterProps> = ({
  alerts,
  openInvestigationsCount,
  operatorName,
  canAcknowledge,
  liveObservationCount,
  alertEligibleObservationCount,
  onAcknowledge
}) => {
  const [statusFilter, setStatusFilter] = useState<'Active' | 'Open' | 'Acknowledged' | 'Resolved' | 'All'>('Active');
  const [severityFilter, setSeverityFilter] = useState<'All' | AlertSeverity>('All');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState('');

  const summary = useMemo(() => summarizeAlerts(alerts), [alerts]);
  const visible = useMemo(() => alerts
    .filter(record => severityFilter === 'All' || record.severity === severityFilter)
    .filter(record => {
      if (statusFilter === 'All') return true;
      if (statusFilter === 'Active') return record.status !== 'Resolved';
      return record.status === statusFilter;
    })
    .sort((left, right) => {
      const severityDelta = SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity];
      if (severityDelta !== 0) return severityDelta;
      return Date.parse(right.lastSeenAt) - Date.parse(left.lastSeenAt);
    }), [alerts, severityFilter, statusFilter]);

  const acknowledge = async (id: string) => {
    setBusyId(id);
    setError('');
    try {
      await onAcknowledge(id);
    } catch (err: any) {
      setError(err?.message || 'The alert could not be acknowledged.');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-4 pb-8">
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-sm">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="flex items-center gap-2 text-lg font-bold text-slate-100">
              <BellRing className="h-5 w-5 text-amber-400" />
              Local Operations Alerts
            </h1>
            <p className="mt-1 text-xs text-slate-400">
              Deduplicated alerts generated from the current observation set. Acknowledging records analyst review; an alert resolves when its condition is absent from the latest scan or capture.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
            <span className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-rose-300">{summary.critical} critical</span>
            <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-amber-300">{summary.high} high</span>
            <span className="rounded border border-yellow-500/30 bg-yellow-500/10 px-2 py-0.5 text-yellow-300">{summary.medium} medium</span>
            <span className="rounded border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 text-blue-300">{summary.acknowledged} acknowledged</span>
          </div>
        </div>
        <p className="mt-3 text-[11px] text-slate-500">
          Alerts are computed from current observations and enrolled assets. Nothing is sent to an external service.
        </p>
        {liveObservationCount > 0 && alertEligibleObservationCount === 0 && alerts.length === 0 && (
          <p className="mt-2 rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-[11px] text-amber-200" role="status">
            {liveObservationCount} live access points are visible, but none are enrolled or classified as trusted/corporate/approved for operational alerting. Review and add authorized networks in Projects &amp; Scope to enable scoped alerts. Unenrolled networks remain visible without being treated as managed assets.
          </p>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Active</div>
          <div className="mt-1 text-xl font-bold text-slate-100">{summary.active}</div>
          <div className="text-[10px] text-slate-500">{summary.open} open · {summary.acknowledged} acknowledged</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Open investigations</div>
          <div className="mt-1 text-xl font-bold text-slate-100">{openInvestigationsCount}</div>
          <div className="text-[10px] text-slate-500">Cases in progress</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Critical</div>
          <div className="mt-1 text-xl font-bold text-rose-300">{summary.critical}</div>
          <div className="text-[10px] text-slate-500">Immediate review</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">High</div>
          <div className="mt-1 text-xl font-bold text-amber-300">{summary.high}</div>
          <div className="text-[10px] text-slate-500">Weak posture or unapproved asset</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Recorded</div>
          <div className="mt-1 text-xl font-bold text-slate-100">{alerts.length}</div>
          <div className="text-[10px] text-slate-500">Including resolved history</div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <label className="flex items-center gap-2">
          <span className="text-slate-400">Status</span>
          <select
            value={statusFilter}
            onChange={event => setStatusFilter(event.target.value as typeof statusFilter)}
            aria-label="Filter alerts by status"
            className="rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-slate-100"
          >
            <option value="Active">Active</option>
            <option value="Open">Open</option>
            <option value="Acknowledged">Acknowledged</option>
            <option value="Resolved">Resolved</option>
            <option value="All">All</option>
          </select>
        </label>
        <label className="flex items-center gap-2">
          <span className="text-slate-400">Severity</span>
          <select
            value={severityFilter}
            onChange={event => setSeverityFilter(event.target.value as typeof severityFilter)}
            aria-label="Filter alerts by severity"
            className="rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-slate-100"
          >
            <option value="All">All</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </label>
        <span className="ml-auto text-slate-500">{visible.length} shown</span>
      </div>

      {!canAcknowledge && (
        <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-300">
          The current local role is read-only for alerts. Switch to Auditor or Administrator in Settings to acknowledge.
        </p>
      )}
      {error && <p role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">{error}</p>}

      {visible.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/60 px-4 py-10 text-center text-xs text-slate-400">
          <ShieldAlert className="mx-auto mb-2 h-6 w-6 text-slate-500" />
          {alerts.length === 0
            ? 'No alerts recorded for this project yet. Alerts appear after a live Windows scan or an imported capture matches a rule.'
            : 'No alerts match the selected filters.'}
        </div>
      ) : (
        <div className="space-y-2">
          {visible.map(record => (
            <div key={record.id} className={`rounded-xl border p-4 ${record.status === 'Resolved' ? 'border-slate-800 bg-slate-900/60' : 'border-slate-800 bg-slate-900'}`}>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${severityStyles[record.severity]}`}>{record.severity}</span>
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${statusStyles[record.status]}`}>{record.status}</span>
                    <span className="text-sm font-semibold text-slate-100">{record.ssid || '[hidden network]'}</span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-slate-400">{record.bssid}</div>
                </div>
                <div className="text-right text-[10px] text-slate-500">
                  <div className="flex items-center justify-end gap-1"><Clock className="h-3 w-3" /> last seen {formatTime(record.lastSeenAt)}</div>
                  <div>first seen {formatTime(record.firstSeenAt)}</div>
                </div>
              </div>

              <div className="mt-2 text-xs font-semibold text-slate-200">{record.title}</div>
              <p className="mt-0.5 text-[11px] text-slate-400">{record.detail}</p>
              <p className="mt-1 text-[10px] text-slate-500">{ALERT_RULES[record.ruleId].description}</p>

              {record.status === 'Acknowledged' && (
                <p className="mt-2 text-[11px] text-blue-300">
                  Acknowledged by {record.acknowledgedBy || 'an analyst'}{record.acknowledgedAt ? ` · ${formatTime(record.acknowledgedAt)}` : ''}. It stays acknowledged until the condition clears.
                </p>
              )}
              {record.status === 'Resolved' && record.resolvedAt && (
                <p className="mt-2 text-[11px] text-slate-500">Resolved when the condition was absent from the latest observation set · {formatTime(record.resolvedAt)}</p>
              )}

              {record.status === 'Open' && (
                <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-slate-800 pt-2">
                  <button
                    type="button"
                    disabled={!canAcknowledge || busyId === record.id}
                    onClick={() => void acknowledge(record.id)}
                    className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" /> {busyId === record.id ? 'Saving…' : 'Acknowledge'}
                  </button>
                  <span className="text-[10px] text-slate-500">Recorded as {operatorName || 'Local operator'}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

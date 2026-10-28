import { AuditLog } from '../types';
import { AlertRecord } from './alerts';

export const LOG_RETENTION_OPTIONS = [7, 30, 90, 180, 365];
export const ALERT_RETENTION_OPTIONS = [30, 90, 180, 365];

export interface RetentionPolicy {
  logDays: number;
  resolvedAlertDays: number;
}

export interface RetentionResult {
  logs: AuditLog[];
  alerts: AlertRecord[];
  logsRemoved: number;
  alertsRemoved: number;
}

const DEFAULT_POLICY: RetentionPolicy = { logDays: 90, resolvedAlertDays: 90 };

function pickDays(value: unknown, options: number[], fallback: number): number {
  const numeric = Number(value);
  return options.includes(numeric) ? numeric : fallback;
}

export function normalizeRetentionPolicy(input: unknown): RetentionPolicy {
  if (!input || typeof input !== 'object') return { ...DEFAULT_POLICY };
  const raw = input as Record<string, unknown>;
  return {
    logDays: pickDays(raw.logDays, LOG_RETENTION_OPTIONS, DEFAULT_POLICY.logDays),
    resolvedAlertDays: pickDays(raw.resolvedAlertDays, ALERT_RETENTION_OPTIONS, DEFAULT_POLICY.resolvedAlertDays)
  };
}

const DAY_MS = 24 * 60 * 60 * 1000;

function isOlderThan(value: string | undefined, cutoff: number): boolean {
  if (!value) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && time < cutoff;
}

/**
 * Diagnostic logs and resolved alerts are prunable. Evidence, incidents, and
 * the audit chain are intentionally excluded: silently deleting case material
 * would undermine an audit trail.
 */
export function applyRetention(
  data: { logs: AuditLog[]; alerts: AlertRecord[] },
  policy: RetentionPolicy,
  now: Date = new Date()
): RetentionResult {
  const normalized = normalizeRetentionPolicy(policy);
  const logCutoff = now.getTime() - normalized.logDays * DAY_MS;
  const alertCutoff = now.getTime() - normalized.resolvedAlertDays * DAY_MS;

  // Logs written before occurredAt existed have no date; keep them rather than
  // deleting records whose age cannot be established.
  const logs = data.logs.filter(log => !log.occurredAt || !isOlderThan(log.occurredAt, logCutoff));
  const alerts = data.alerts.filter(alert => {
    if (alert.status !== 'Resolved') return true;
    return !isOlderThan(alert.resolvedAt, alertCutoff);
  });

  return {
    logs,
    alerts,
    logsRemoved: data.logs.length - logs.length,
    alertsRemoved: data.alerts.length - alerts.length
  };
}

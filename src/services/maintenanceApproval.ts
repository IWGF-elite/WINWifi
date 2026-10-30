import {
  MaintenanceAction,
  MaintenanceApprovalRecord,
  MaintenanceApprovalStatus,
  MaintenanceRequestInput
} from '../types';
import { normalizeMac } from './assetRegistry';

const MAX_RECORDS = 200;
const MAX_ACTIVE_PER_BSSID = 5;
const MIN_DURATION_MINUTES = 15;
const MAX_DURATION_MINUTES = 480;
const MAX_NAME = 80;
const MAX_SSID = 64;
const MAX_ADAPTER = 128;
const MAX_JUSTIFICATION = 400;
const MIN_JUSTIFICATION = 10;
const MAX_DECISION_NOTE = 200;
const TERMINAL_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

export const MAINTENANCE_ACTIONS: MaintenanceAction[] = ['Connect to network'];
export const MAINTENANCE_DURATIONS = [15, 30, 60, 120];

const VALID_STATUSES: MaintenanceApprovalStatus[] = ['Pending', 'Approved', 'Rejected', 'Expired', 'Revoked'];

export interface MaintenanceMutationResult {
  records: MaintenanceApprovalRecord[];
  error?: string;
  record?: MaintenanceApprovalRecord;
}

export function sanitizeMaintenanceText(value: unknown, max: number): string {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

function newApprovalId(): string {
  const buffered = new Uint8Array(4);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(buffered);
  } else {
    for (let index = 0; index < buffered.length; index++) buffered[index] = Math.floor(Math.random() * 256);
  }
  const suffix = Array.from(buffered, byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `MAINT-${Date.now().toString(36).toUpperCase()}-${suffix}`;
}

function parseIso(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
}

const isExpired = (record: MaintenanceApprovalRecord, now: Date): boolean =>
  Date.parse(record.expiresAt) <= now.getTime();

const isActiveStatus = (status: MaintenanceApprovalStatus): boolean =>
  status === 'Pending' || status === 'Approved';

export const isSameMaintenancePerson = (left: string, right: string): boolean =>
  left.trim().toLowerCase() === right.trim().toLowerCase();

/** Accepts untrusted stored JSON and returns bounded, internally consistent records. */
export function normalizeMaintenanceApprovals(input: unknown, now: Date = new Date()): MaintenanceApprovalRecord[] {
  if (!Array.isArray(input)) return [];

  const records: MaintenanceApprovalRecord[] = [];
  const usedIds = new Set<string>();

  for (const raw of input) {
    if (records.length >= MAX_RECORDS) break;
    if (!raw || typeof raw !== 'object') continue;
    const entry = raw as Record<string, unknown>;

    const action: MaintenanceAction | null = entry.action === 'Connect to network' ? 'Connect to network' : null;
    const bssid = normalizeMac(typeof entry.bssid === 'string' ? entry.bssid : '');
    const requester = sanitizeMaintenanceText(entry.requester, MAX_NAME);
    const justification = sanitizeMaintenanceText(entry.justification, MAX_JUSTIFICATION);
    const requestedAt = parseIso(entry.requestedAt);
    const expiresAt = parseIso(entry.expiresAt);
    const status = VALID_STATUSES.includes(entry.status as MaintenanceApprovalStatus)
      ? entry.status as MaintenanceApprovalStatus
      : null;
    if (!action || !bssid || !requester || !justification || !requestedAt || !expiresAt || !status) continue;

    const approver = sanitizeMaintenanceText(entry.approver, MAX_NAME);
    const approvedAt = parseIso(entry.approvedAt) ?? undefined;
    if (status === 'Approved' && (!approver || !approvedAt || isSameMaintenancePerson(approver, requester))) continue;
    if (status === 'Rejected' && !approver) continue;

    let id = typeof entry.id === 'string' ? entry.id.trim().slice(0, 64) : '';
    if (!id || usedIds.has(id)) id = newApprovalId();
    usedIds.add(id);

    const normalizedStatus: MaintenanceApprovalStatus =
      isActiveStatus(status) && Date.parse(expiresAt) <= now.getTime() ? 'Expired' : status;

    records.push({
      id,
      action,
      bssid,
      ssid: sanitizeMaintenanceText(entry.ssid, MAX_SSID),
      adapterId: sanitizeMaintenanceText(entry.adapterId, MAX_ADAPTER),
      requester,
      approver,
      justification,
      requestedAt,
      approvedAt,
      expiresAt,
      status: normalizedStatus,
      decidedAt: parseIso(entry.decidedAt) ?? undefined,
      decisionNote: sanitizeMaintenanceText(entry.decisionNote, MAX_DECISION_NOTE) || undefined,
      lastUsedAt: parseIso(entry.lastUsedAt) ?? undefined
    });
  }

  return records;
}

function pruneTerminal(records: MaintenanceApprovalRecord[], now: Date): MaintenanceApprovalRecord[] {
  return records.filter(record => {
    if (isActiveStatus(record.status)) return true;
    if (record.status === 'Rejected' || record.status === 'Revoked') {
      const decided = record.decidedAt ? Date.parse(record.decidedAt) : Date.parse(record.requestedAt);
      return now.getTime() - decided <= TERMINAL_RETENTION_MS;
    }
    // Expired records remain visible for 30 days past their window.
    return now.getTime() - Date.parse(record.expiresAt) <= TERMINAL_RETENTION_MS;
  });
}

export function createMaintenanceRequest(
  records: MaintenanceApprovalRecord[],
  input: MaintenanceRequestInput,
  now: Date = new Date()
): MaintenanceMutationResult {
  if (!MAINTENANCE_ACTIONS.includes(input.action)) {
    return { records, error: 'That maintenance action is not supported.' };
  }
  const bssid = normalizeMac(input.bssid);
  if (!bssid) return { records, error: 'Enter a valid BSSID for the target access point.' };
  const requester = sanitizeMaintenanceText(input.requester, MAX_NAME);
  if (requester.length < 2) return { records, error: 'Enter the requesting analyst name (at least 2 characters).' };
  const justification = sanitizeMaintenanceText(input.justification, MAX_JUSTIFICATION);
  if (justification.length < MIN_JUSTIFICATION) {
    return { records, error: `Describe why this action is needed (at least ${MIN_JUSTIFICATION} characters).` };
  }
  const duration = Math.trunc(input.durationMinutes);
  if (!Number.isFinite(duration) || duration < MIN_DURATION_MINUTES || duration > MAX_DURATION_MINUTES) {
    return { records, error: `Choose a duration between ${MIN_DURATION_MINUTES} and ${MAX_DURATION_MINUTES} minutes.` };
  }

  const current = pruneTerminal(normalizeMaintenanceApprovals(records, now), now);
  const activeForTarget = current.filter(record =>
    record.bssid === bssid && isActiveStatus(record.status) && !isExpired(record, now)).length;
  if (activeForTarget >= MAX_ACTIVE_PER_BSSID) {
    return { records, error: `This BSSID already has ${MAX_ACTIVE_PER_BSSID} open maintenance requests. Resolve or revoke one first.` };
  }
  if (current.length >= MAX_RECORDS) {
    return { records, error: `This project keeps up to ${MAX_RECORDS} maintenance records. Older resolved entries must be cleared before adding more.` };
  }

  const record: MaintenanceApprovalRecord = {
    id: newApprovalId(),
    action: input.action,
    bssid,
    ssid: sanitizeMaintenanceText(input.ssid, MAX_SSID),
    adapterId: sanitizeMaintenanceText(input.adapterId, MAX_ADAPTER),
    requester,
    approver: '',
    justification,
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + duration * 60_000).toISOString(),
    status: 'Pending'
  };

  return { records: [record, ...current], record };
}

export function approveMaintenance(
  records: MaintenanceApprovalRecord[],
  id: string,
  approverName: string,
  now: Date = new Date()
): MaintenanceMutationResult {
  const record = records.find(candidate => candidate.id === id);
  if (!record) return { records, error: 'That maintenance request no longer exists.' };
  if (record.status !== 'Pending') return { records, error: `This request is already ${record.status.toLowerCase()}.` };
  if (isExpired(record, now)) {
    return { records, error: 'This maintenance window expired before approval. Create a new request.' };
  }
  const approver = sanitizeMaintenanceText(approverName, MAX_NAME);
  if (approver.length < 2) return { records, error: 'Enter the approving analyst name (at least 2 characters).' };
  if (isSameMaintenancePerson(approver, record.requester)) {
    return { records, error: 'The approver must be a different person from the requester.' };
  }

  return {
    records: records.map(candidate => candidate.id === id
      ? { ...candidate, status: 'Approved', approver, approvedAt: now.toISOString(), decidedAt: now.toISOString() }
      : candidate),
    record: { ...record, status: 'Approved', approver, approvedAt: now.toISOString(), decidedAt: now.toISOString() }
  };
}

export function rejectMaintenance(
  records: MaintenanceApprovalRecord[],
  id: string,
  approverName: string,
  note: string,
  now: Date = new Date()
): MaintenanceMutationResult {
  const record = records.find(candidate => candidate.id === id);
  if (!record) return { records, error: 'That maintenance request no longer exists.' };
  if (record.status !== 'Pending') return { records, error: `This request is already ${record.status.toLowerCase()}.` };
  const approver = sanitizeMaintenanceText(approverName, MAX_NAME);
  if (approver.length < 2) return { records, error: 'Enter the rejecting analyst name (at least 2 characters).' };
  if (isSameMaintenancePerson(approver, record.requester)) {
    return { records, error: 'A maintenance decision must be made by a different person from the requester.' };
  }
  const decisionNote = sanitizeMaintenanceText(note, MAX_DECISION_NOTE) || undefined;

  return {
    records: records.map(candidate => candidate.id === id
      ? { ...candidate, status: 'Rejected', approver, decidedAt: now.toISOString(), decisionNote }
      : candidate),
    record: { ...record, status: 'Rejected', approver, decidedAt: now.toISOString(), decisionNote }
  };
}

export function revokeMaintenance(
  records: MaintenanceApprovalRecord[],
  id: string,
  now: Date = new Date()
): MaintenanceMutationResult {
  const record = records.find(candidate => candidate.id === id);
  if (!record) return { records, error: 'That maintenance request no longer exists.' };
  if (record.status === 'Revoked') return { records, error: 'This maintenance request is already revoked.' };
  if (!isActiveStatus(record.status)) return { records, error: `This request is already ${record.status.toLowerCase()}.` };
  if (isExpired(record, now)) return { records, error: 'This maintenance window already expired.' };

  return {
    records: records.map(candidate => candidate.id === id
      ? { ...candidate, status: 'Revoked', decidedAt: now.toISOString() }
      : candidate),
    record: { ...record, status: 'Revoked', decidedAt: now.toISOString() }
  };
}

export function findActiveApproval(
  records: MaintenanceApprovalRecord[],
  bssid: string,
  action: MaintenanceAction = 'Connect to network',
  now: Date = new Date()
): MaintenanceApprovalRecord | null {
  const canonical = normalizeMac(bssid);
  if (!canonical) return null;
  return records.find(record =>
    record.bssid === canonical &&
    record.action === action &&
    record.status === 'Approved' &&
    Date.parse(record.expiresAt) > now.getTime()) ?? null;
}

export function markApprovalUsed(
  records: MaintenanceApprovalRecord[],
  id: string,
  now: Date = new Date()
): MaintenanceMutationResult {
  const record = records.find(candidate => candidate.id === id);
  if (!record) return { records, error: 'That maintenance request no longer exists.' };
  if (record.status !== 'Approved' || isExpired(record, now)) {
    return { records, error: 'The maintenance approval is no longer active.' };
  }
  return {
    records: records.map(candidate => candidate.id === id
      ? { ...candidate, lastUsedAt: now.toISOString() }
      : candidate)
  };
}

export function getApprovalsForBssid(
  records: MaintenanceApprovalRecord[],
  bssid: string
): MaintenanceApprovalRecord[] {
  const canonical = normalizeMac(bssid);
  if (!canonical) return [];
  return records.filter(record => record.bssid === canonical);
}

export function countActiveApprovals(
  records: MaintenanceApprovalRecord[],
  now: Date = new Date()
): number {
  return records.filter(record => isActiveStatus(record.status) && !isExpired(record, now)).length;
}

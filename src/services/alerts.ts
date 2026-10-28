import { AccessPoint, EnterpriseAssetRecord } from '../types';
import { normalizeMac } from './assetRegistry';

export const MAX_ALERTS = 1000;
const RESOLVED_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_TEXT = 300;

export type AlertRuleId =
  | 'ROGUE_AP'
  | 'UNAPPROVED_ASSET'
  | 'WEAK_ENCRYPTION'
  | 'PMF_NOT_REQUIRED'
  | 'WPS_ENABLED';

export type AlertSeverity = 'Critical' | 'High' | 'Medium' | 'Low';
export type AlertStatus = 'Open' | 'Acknowledged' | 'Resolved';

export interface AlertRecord {
  id: string;
  ruleId: AlertRuleId;
  severity: AlertSeverity;
  bssid: string;
  ssid: string;
  title: string;
  detail: string;
  firstSeenAt: string;
  lastSeenAt: string;
  status: AlertStatus;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
  resolvedAt?: string;
}

export interface AlertCandidate {
  ruleId: AlertRuleId;
  severity: AlertSeverity;
  bssid: string;
  ssid: string;
  title: string;
  detail: string;
}

export interface AlertReconcileResult {
  records: AlertRecord[];
  added: number;
  updated: number;
  resolved: number;
}

export interface AlertMutationResult {
  records: AlertRecord[];
  record?: AlertRecord;
  error?: string;
}

export interface AlertSummary {
  open: number;
  acknowledged: number;
  active: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export const ALERT_RULES: Record<AlertRuleId, { title: string; description: string }> = {
  ROGUE_AP: {
    title: 'Rogue or evil-twin behavior',
    description: 'The observation matches rogue/evil-twin indicators, such as a cloned SSID with a different BSSID or vendor.'
  },
  UNAPPROVED_ASSET: {
    title: 'Enrolled asset is not approved',
    description: 'A registry record for this BSSID is marked Unapproved or Decommissioned.'
  },
  WEAK_ENCRYPTION: {
    title: 'Weak or missing encryption',
    description: 'An in-scope network uses WEP, TKIP, or open/unencrypted operation.'
  },
  PMF_NOT_REQUIRED: {
    title: 'Protected Management Frames not enforced',
    description: 'RSN information elements were observed and PMF is not required for an in-scope network.'
  },
  WPS_ENABLED: {
    title: 'Wi-Fi Protected Setup enabled',
    description: 'WPS is broadcast active on an in-scope network, which exposes a PIN registrar attack surface.'
  }
};

const RULE_IDS: AlertRuleId[] = ['ROGUE_AP', 'UNAPPROVED_ASSET', 'WEAK_ENCRYPTION', 'PMF_NOT_REQUIRED', 'WPS_ENABLED'];
const SEVERITIES: AlertSeverity[] = ['Critical', 'High', 'Medium', 'Low'];
const STATUSES: AlertStatus[] = ['Open', 'Acknowledged', 'Resolved'];

export const SEVERITY_ORDER: Record<AlertSeverity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3
};

function sanitize(value: unknown, max: number = MAX_TEXT): string {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

function newAlertId(): string {
  const buffered = new Uint8Array(4);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(buffered);
  } else {
    for (let index = 0; index < buffered.length; index++) buffered[index] = Math.floor(Math.random() * 256);
  }
  const suffix = Array.from(buffered, byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `ALT-${Date.now().toString(36).toUpperCase()}-${suffix}`;
}

function parseIso(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
}

const isActive = (record: AlertRecord): boolean => record.status === 'Open' || record.status === 'Acknowledged';

/** Accepts untrusted stored JSON and returns bounded alert records. */
export function normalizeAlerts(input: unknown, now: Date = new Date()): AlertRecord[] {
  if (!Array.isArray(input)) return [];
  const records: AlertRecord[] = [];
  const usedIds = new Set<string>();

  for (const entry of input) {
    if (records.length >= MAX_ALERTS) break;
    if (!entry || typeof entry !== 'object') continue;
    const item = entry as Record<string, unknown>;
    const bssid = normalizeMac(typeof item.bssid === 'string' ? item.bssid : '');
    const ruleId = RULE_IDS.includes(item.ruleId as AlertRuleId) ? item.ruleId as AlertRuleId : null;
    const severity = SEVERITIES.includes(item.severity as AlertSeverity) ? item.severity as AlertSeverity : null;
    const status = STATUSES.includes(item.status as AlertStatus) ? item.status as AlertStatus : null;
    const firstSeenAt = parseIso(item.firstSeenAt);
    const lastSeenAt = parseIso(item.lastSeenAt);
    if (!bssid || !ruleId || !severity || !status || !firstSeenAt || !lastSeenAt) continue;

    let id = typeof item.id === 'string' ? item.id.trim().slice(0, 64) : '';
    if (!id || usedIds.has(id)) id = newAlertId();
    usedIds.add(id);

    const record: AlertRecord = {
      id,
      ruleId,
      severity,
      bssid,
      ssid: sanitize(item.ssid, 64),
      title: sanitize(item.title) || ALERT_RULES[ruleId].title,
      detail: sanitize(item.detail),
      firstSeenAt,
      lastSeenAt,
      status,
      acknowledgedBy: sanitize(item.acknowledgedBy, 80) || undefined,
      acknowledgedAt: parseIso(item.acknowledgedAt) ?? undefined,
      resolvedAt: parseIso(item.resolvedAt) ?? undefined
    };
    if (record.status === 'Resolved' && record.resolvedAt && now.getTime() - Date.parse(record.resolvedAt) > RESOLVED_RETENTION_MS) {
      continue;
    }
    records.push(record);
  }

  return records;
}

function isRelevant(ap: AccessPoint, asset?: EnterpriseAssetRecord): boolean {
  return Boolean(
    asset ||
    ap.classification === 'Corporate' ||
    ap.classification === 'Trusted' ||
    ap.approvedStatus === 'Approved'
  );
}

/** Count live observations eligible for operational alert rules under project enrollment/classification. */
export function countAlertEligibleAccessPoints(
  accessPoints: AccessPoint[],
  assets: EnterpriseAssetRecord[]
): number {
  const assetsByMac = new Set(assets
    .map(asset => normalizeMac(asset.macAddress))
    .filter((mac): mac is string => Boolean(mac)));
  return accessPoints.filter(ap => {
    const bssid = normalizeMac(ap.bssid);
    return isRelevant(ap) || Boolean(bssid && assetsByMac.has(bssid));
  }).length;
}

/** Evaluates the current observations; alerts never fire on synthetic lab data by themselves. */
export function evaluateAlerts(
  accessPoints: AccessPoint[],
  assets: EnterpriseAssetRecord[]
): AlertCandidate[] {
  const assetsByMac = new Map<string, EnterpriseAssetRecord>();
  for (const asset of assets) {
    const mac = normalizeMac(asset.macAddress);
    if (mac) assetsByMac.set(mac, asset);
  }

  const candidates: AlertCandidate[] = [];
  const seen = new Set<string>();
  const scopedSsids = new Set(accessPoints
    .filter(ap => isRelevant(ap, assetsByMac.get(normalizeMac(ap.bssid) || '')))
    .map(ap => sanitize(ap.ssid, 64).toLocaleLowerCase())
    .filter(Boolean));
  for (const asset of assets) {
    if (asset.ssid && (asset.approvalStatus === 'Approved' || asset.approvalStatus === 'Unapproved' || asset.approvalStatus === 'Decommissioned'))
      scopedSsids.add(sanitize(asset.ssid, 64).toLocaleLowerCase());
  }
  const push = (candidate: AlertCandidate) => {
    const key = `${candidate.ruleId}|${candidate.bssid}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push(candidate);
  };

  for (const ap of accessPoints) {
    const bssid = normalizeMac(ap.bssid);
    if (!bssid) continue;
    const asset = assetsByMac.get(bssid);
    const relevant = isRelevant(ap, asset);
    const ssid = sanitize(ap.ssid, 64) || '[hidden network]';

    const rogueIsInScope = relevant || (ssid !== '[hidden network]' && scopedSsids.has(ssid.toLocaleLowerCase()));
    if (ap.isRogueCandidate && rogueIsInScope) {
      push({
        ruleId: 'ROGUE_AP',
        severity: 'Critical',
        bssid,
        ssid,
        title: ALERT_RULES.ROGUE_AP.title,
        detail: sanitize((ap.rogueEvidence && ap.rogueEvidence[0]) || `Rogue confidence ${ap.rogueConfidence ?? 80}%.`)
      });
    }

    if (asset && (asset.approvalStatus === 'Unapproved' || asset.approvalStatus === 'Decommissioned')) {
      push({
        ruleId: 'UNAPPROVED_ASSET',
        severity: 'High',
        bssid,
        ssid,
        title: ALERT_RULES.UNAPPROVED_ASSET.title,
        detail: `Registry status ${asset.approvalStatus} for ${asset.classification} asset ${asset.macAddress}.`
      });
    }

    const isUnencrypted = /\bopen\b/i.test(ap.security) && !/OWE|Enhanced Open/i.test(ap.security);
    if (relevant && (/WEP/i.test(ap.security) || isUnencrypted)) {
      push({
        ruleId: 'WEAK_ENCRYPTION',
        severity: /WEP/i.test(ap.security) ? 'Critical' : 'High',
        bssid,
        ssid,
        title: ALERT_RULES.WEAK_ENCRYPTION.title,
        detail: `${ap.security} with cipher ${ap.cipher}.`
      });
    } else if (relevant && /TKIP/i.test(`${ap.security} ${ap.cipher}`)) {
      push({
        ruleId: 'WEAK_ENCRYPTION',
        severity: 'High',
        bssid,
        ssid,
        title: ALERT_RULES.WEAK_ENCRYPTION.title,
        detail: `${ap.security} with legacy TKIP cipher.`
      });
    }

    if (relevant && ap.pmfInformationAvailable && !ap.pmfRequired) {
      push({
        ruleId: 'PMF_NOT_REQUIRED',
        severity: 'Medium',
        bssid,
        ssid,
        title: ALERT_RULES.PMF_NOT_REQUIRED.title,
        detail: 'RSN information elements were observed; the PMF-required bit is not set.'
      });
    }

    if (relevant && ap.wpsEnabled) {
      push({
        ruleId: 'WPS_ENABLED',
        severity: 'Medium',
        bssid,
        ssid,
        title: ALERT_RULES.WPS_ENABLED.title,
        detail: ap.wpsLocked ? 'WPS is enabled but reported locked.' : 'WPS is enabled and not locked.'
      });
    }
  }

  return candidates;
}

export function reconcileAlerts(
  existing: AlertRecord[],
  candidates: AlertCandidate[],
  now: Date = new Date()
): AlertReconcileResult {
  const current = normalizeAlerts(existing, now);
  const byKey = new Map<string, AlertRecord>();
  for (const record of current) {
    if (isActive(record)) byKey.set(`${record.ruleId}|${record.bssid}`, record);
  }

  let added = 0;
  let updated = 0;
  let resolved = 0;
  const createdAt = now.toISOString();
  const usedKeys = new Set<string>();
  const newRecords: AlertRecord[] = [];

  for (const candidate of candidates) {
    const key = `${candidate.ruleId}|${candidate.bssid}`;
    if (usedKeys.has(key)) continue;
    usedKeys.add(key);
    const prior = byKey.get(key);
    if (!prior) {
      newRecords.push({
        id: newAlertId(),
        ruleId: candidate.ruleId,
        severity: candidate.severity,
        bssid: candidate.bssid,
        ssid: candidate.ssid,
        title: candidate.title,
        detail: candidate.detail,
        firstSeenAt: createdAt,
        lastSeenAt: createdAt,
        status: 'Open'
      });
      added++;
      continue;
    }
    const material = prior.severity !== candidate.severity || prior.ssid !== candidate.ssid || prior.detail !== candidate.detail || prior.title !== candidate.title;
    byKey.set(key, {
      ...prior,
      severity: candidate.severity,
      ssid: candidate.ssid,
      title: candidate.title,
      detail: candidate.detail,
      lastSeenAt: createdAt
    });
    if (material) updated++;
  }

  const merged: AlertRecord[] = [];
  for (const record of current) {
    if (!isActive(record)) {
      merged.push(record);
      continue;
    }
    const key = `${record.ruleId}|${record.bssid}`;
    if (!usedKeys.has(key)) {
      merged.push({ ...record, status: 'Resolved', resolvedAt: createdAt });
      resolved++;
      continue;
    }
    merged.push(byKey.get(key) ?? record);
  }

  const active = newRecords.concat(merged.filter(isActive));
  const terminal = merged.filter(record => !isActive(record));
  const bounded = active.concat(terminal)
    .sort((left, right) => {
      const activeDelta = Number(!isActive(left)) - Number(!isActive(right));
      if (activeDelta !== 0) return activeDelta;
      return Date.parse(right.lastSeenAt) - Date.parse(left.lastSeenAt);
    })
    .slice(0, MAX_ALERTS);

  return { records: bounded, added, updated, resolved };
}

export function acknowledgeAlert(
  records: AlertRecord[],
  id: string,
  actor: string,
  now: Date = new Date()
): AlertMutationResult {
  const record = records.find(candidate => candidate.id === id);
  if (!record) return { records, error: 'That alert no longer exists.' };
  if (record.status === 'Resolved') return { records, error: 'That alert is already resolved.' };
  if (record.status === 'Acknowledged') return { records, error: 'That alert is already acknowledged.' };
  const acknowledgedBy = actor.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80);
  if (acknowledgedBy.length < 2) return { records, error: 'Enter the acknowledging analyst name (at least 2 characters).' };

  const updated: AlertRecord = { ...record, status: 'Acknowledged', acknowledgedBy, acknowledgedAt: now.toISOString() };
  return {
    records: records.map(candidate => candidate.id === id ? updated : candidate),
    record: updated
  };
}

export function summarizeAlerts(records: AlertRecord[]): AlertSummary {
  const summary: AlertSummary = { open: 0, acknowledged: 0, active: 0, critical: 0, high: 0, medium: 0, low: 0 };
  for (const record of records) {
    if (record.status === 'Resolved') continue;
    summary.active++;
    if (record.status === 'Open') summary.open++;
    else summary.acknowledged++;
    if (record.severity === 'Critical') summary.critical++;
    else if (record.severity === 'High') summary.high++;
    else if (record.severity === 'Medium') summary.medium++;
    else summary.low++;
  }
  return summary;
}

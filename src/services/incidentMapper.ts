import { AccessPoint, IncidentRecord } from '../types';

const SEVERITY_ORDER: Record<IncidentRecord['severity'], number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3
};

const asSeverity = (value: unknown): IncidentRecord['severity'] => {
  const normalized = String(value ?? '').toUpperCase();
  return Object.prototype.hasOwnProperty.call(SEVERITY_ORDER, normalized)
    ? (normalized as IncidentRecord['severity'])
    : 'MEDIUM';
};

const slug = (value: unknown, maxLength = 32): string => {
  const normalized = String(value ?? '')
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized.slice(0, maxLength) || 'UNKNOWN';
};

const fnv1a = (value: string): string => {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index++) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
};

/**
 * Deterministic case identifier. The same source, finding type, and target
 * always produce the same identifier, so a rescan updates a case instead of
 * creating a new one. The trailing digest keeps identifiers distinct even
 * when long labels share a truncated prefix.
 */
export const stableIncidentId = (source: string, type: string, target?: string): string => {
  const normalizedType = String(type ?? '');
  const normalizedTarget = String(target ?? '');
  const digest = fnv1a(`${source}|${normalizedType}|${normalizedTarget}`);
  return `${slug(source, 12)}-${slug(normalizedType)}-${slug(normalizedTarget || 'NO-TARGET', 24)}-${digest}`;
};

export const isNativeIncident = (incident: IncidentRecord): boolean =>
  incident.id.startsWith('NATIVE-');

const deriveFindingType = (finding: any): string => {
  const rawId = String(finding?.id ?? '').trim();
  const structured = /^THR-([A-Z0-9_]+)-/i.exec(rawId);
  if (structured) return structured[1];
  return slug(finding?.ruleId ?? finding?.category ?? finding?.title ?? rawId);
};

const mapFinding = (finding: any): IncidentRecord | null => {
  if (!finding || typeof finding !== 'object' || !finding.title) return null;

  const target = String(finding.relatedBssid ?? finding.bssid ?? '').trim();
  const timestamp = String(finding.detectedAt || finding.timestamp || new Date().toISOString());
  const evidence = String(finding.evidence || finding.explanation || '').trim();

  return {
    id: stableIncidentId('NATIVE', deriveFindingType(finding), target),
    title: String(finding.title),
    severity: asSeverity(finding.severity),
    confidence: Math.max(0, Math.min(100, Number(finding.confidence) || 0)),
    status: finding.status === 'Resolved' ? 'Resolved' : 'Open',
    createdAt: timestamp,
    updatedAt: timestamp,
    assignedTo: 'Windows WLAN Security Analyzer',
    summary: String(finding.explanation || evidence || 'Finding reported by the native Windows WLAN security analyzer.'),
    bssidTarget: target || undefined,
    ssidTarget: finding.relatedSsid ? String(finding.relatedSsid) : undefined,
    evidenceIds: [],
    notes: [{
      timestamp,
      author: 'Native Security Analyzer',
      text: evidence || String(finding.title)
    }],
    resolution: finding.remediation ? String(finding.remediation) : undefined
  };
};

/**
 * Convert native analyzer findings into investigation cases. Findings are
 * deduplicated by source + finding type + BSSID, so repeated scans and the
 * SSE/REST duplicate delivery cannot inflate the incident count.
 */
export const mapNativeFindingsToIncidents = (findings: any[]): IncidentRecord[] => {
  const byId = new Map<string, IncidentRecord>();

  for (const raw of Array.isArray(findings) ? findings : []) {
    const incident = mapFinding(raw);
    if (!incident) continue;

    const existing = byId.get(incident.id);
    if (!existing) {
      byId.set(incident.id, incident);
      continue;
    }

    const existingRank = SEVERITY_ORDER[existing.severity];
    const candidateRank = SEVERITY_ORDER[incident.severity];
    if (candidateRank < existingRank ||
        (candidateRank === existingRank && incident.confidence > existing.confidence)) {
      byId.set(incident.id, incident);
    }
  }

  return sortIncidents([...byId.values()]);
};

// A historical browser record is not a live finding. Retain a manual analyst
// case in the live view only while its BSSID is still observed and classified
// as rogue.
export const isCurrentAnalystCase = (incident: IncidentRecord, aps: AccessPoint[]): boolean => {
  if (isNativeIncident(incident) || !incident.bssidTarget) return false;
  const ap = aps.find(candidate => candidate.bssid.toUpperCase() === incident.bssidTarget?.toUpperCase());
  return Boolean(ap && (ap.classification === 'Rogue' || ap.isRogueCandidate));
};

const mergeNotes = (
  previous: IncidentRecord['notes'] = [],
  fresh: IncidentRecord['notes'] = []
): IncidentRecord['notes'] => {
  const seen = new Set<string>();
  const merged: IncidentRecord['notes'] = [];
  for (const note of [...previous, ...fresh]) {
    if (!note || !note.text) continue;
    const key = `${note.timestamp}|${note.author}|${note.text}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(note);
  }
  return merged;
};

const sortIncidents = (incidents: IncidentRecord[]): IncidentRecord[] =>
  [...incidents].sort((left, right) => {
    const bySeverity = SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity];
    if (bySeverity !== 0) return bySeverity;
    return left.id.localeCompare(right.id);
  });

/**
 * Merge freshly observed native findings with the persisted case list. The
 * stable identifier carries the analyst lifecycle (status, notes, evidence)
 * across scans. Per-AP configuration findings stay on the access point and
 * are intentionally not promoted to incidents.
 */
export const reconcileLiveIncidents = (
  nativeFindings: IncidentRecord[],
  aps: AccessPoint[],
  previous: IncidentRecord[]
): IncidentRecord[] => {
  const priorById = new Map((previous || []).map(incident => [incident.id, incident]));
  const merged = new Map<string, IncidentRecord>();

  for (const fresh of nativeFindings) {
    const prior = priorById.get(fresh.id);
    if (!prior) {
      merged.set(fresh.id, fresh);
      continue;
    }
    merged.set(fresh.id, {
      ...fresh,
      status: prior.status,
      createdAt: prior.createdAt,
      updatedAt: prior.updatedAt,
      assignedTo: prior.assignedTo || fresh.assignedTo,
      evidenceIds: prior.evidenceIds ?? fresh.evidenceIds,
      notes: mergeNotes(prior.notes, fresh.notes),
      resolution: prior.resolution ?? fresh.resolution
    });
  }

  for (const prior of previous || []) {
    if (isNativeIncident(prior) || merged.has(prior.id)) continue;
    if (isCurrentAnalystCase(prior, aps)) merged.set(prior.id, prior);
  }

  return sortIncidents([...merged.values()]);
};

export const countOpenIncidents = (incidents: IncidentRecord[]): number =>
  (incidents || []).filter(incident => incident.status === 'Open' || incident.status === 'Investigating').length;

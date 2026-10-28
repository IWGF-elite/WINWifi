import {
  AccessPoint,
  AuditProject,
  EnterpriseAssetRecord,
  EvidenceItem,
  IncidentRecord
} from '../types';
import { normalizeMac } from './assetRegistry';
import { AlertRecord } from './alerts';

export interface AnonymizedExportInput {
  project: AuditProject;
  accessPoints: AccessPoint[];
  assets: EnterpriseAssetRecord[];
  incidents: IncidentRecord[];
  evidence: EvidenceItem[];
  alerts: AlertRecord[];
}

export interface AnonymizedExport {
  format: 'winwifi-anonymized-export';
  formatVersion: 1;
  generatedAt: string;
  project: { label: string };
  counts: {
    observations: number;
    assets: number;
    incidents: number;
    evidence: number;
    alerts: number;
  };
  observations: Array<{
    mac: string;
    ssid: string;
    origin?: string;
    vendor: string;
    band: string;
    channel: number;
    security: string;
    cipher: string;
    pmfRequired: boolean;
    pmfInformationAvailable: boolean;
    wpsEnabled: boolean;
    riskScore?: number;
    classification?: string;
    approvalStatus?: string;
  }>;
  assets: Array<{
    id: string;
    mac: string;
    ssid: string;
    assetType: string;
    classification: string;
    approvalStatus: string;
    site: string;
    building: string;
    floor: string;
    owner: string;
    vendor: string;
    model: string;
    hasNotes: boolean;
  }>;
  incidents: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    createdAt: string;
    updatedAt: string;
    summary: string;
    mac: string;
    ssid: string;
    evidenceCount: number;
    noteCount: number;
    resolution?: string;
  }>;
  evidence: Array<{
    id: string;
    type: string;
    timestamp: string;
    title: string;
    description: string;
    hasChecksum: boolean;
    hasRawData: boolean;
  }>;
  alerts: Array<{
    ruleId: string;
    severity: string;
    status: string;
    mac: string;
    ssid: string;
    title: string;
    detail: string;
    firstSeenAt: string;
    lastSeenAt: string;
    acknowledged: boolean;
  }>;
  caveats: string[];
}

function unique(values: Array<string | undefined>): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const trimmed = (value || '').trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

function tokenMap(values: string[], prefix: string): Map<string, string> {
  const map = new Map<string, string>();
  values.forEach((value, index) => {
    map.set(value, `${prefix}-${String(index + 1).padStart(3, '0')}`);
  });
  return map;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildRedactor(entries: Array<[string, string]>) {
  const usable = entries
    .filter(([raw]) => raw.trim().length >= 2)
    .sort((left, right) => right[0].length - left[0].length);
  return (value: string | undefined, max = 1000): string => {
    let text = String(value ?? '');
    for (const [raw, token] of usable) {
      // Word boundaries avoid rewriting substrings of unrelated words; values
      // with punctuation (SSIDs, locations) fall back to a plain replacement.
      const isWordy = /^[\w .'-]+$/u.test(raw) && raw.length <= 48;
      const pattern = isWordy
        ? new RegExp(`\\b${escapeRegExp(raw)}\\b`, 'gi')
        : new RegExp(escapeRegExp(raw), 'gi');
      text = text.replace(pattern, token);
    }
    text = text.replace(/\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi, '[MAC]');
    return text.slice(0, max);
  };
}

export function buildAnonymizedExport(
  input: AnonymizedExportInput,
  now: Date = new Date()
): AnonymizedExport {
  const { project, accessPoints, assets, incidents, evidence, alerts } = input;

  const ssids = unique([
    ...accessPoints.map(ap => ap.ssid),
    ...assets.map(asset => asset.ssid),
    ...incidents.map(incident => incident.ssidTarget),
    ...alerts.map(alert => alert.ssid)
  ]);
  const macAliases = unique([
    ...accessPoints.map(ap => ap.bssid),
    ...assets.map(asset => asset.macAddress),
    ...incidents.map(incident => incident.bssidTarget),
    ...alerts.map(alert => alert.bssid)
  ]).map(raw => ({ raw, canonical: normalizeMac(raw) || raw.toUpperCase() }));
  const canonicalMacs = unique(macAliases.map(alias => alias.canonical));
  const sites = unique(assets.map(asset => asset.site));
  const buildings = unique(assets.map(asset => asset.building));
  const floors = unique(assets.map(asset => asset.areaFloor));
  const owners = unique([
    ...assets.map(asset => asset.ownerDepartment),
    ...incidents.map(incident => incident.assignedTo)
  ]);

  const ssidTokens = tokenMap(ssids, 'SSID');
  const macTokens = tokenMap(canonicalMacs, 'MAC');
  const siteTokens = tokenMap(sites, 'SITE');
  const buildingTokens = tokenMap(buildings, 'BUILDING');
  const floorTokens = tokenMap(floors, 'FLOOR');
  const ownerTokens = tokenMap(owners, 'OWNER');
  const assetTokens = tokenMap(assets.map(asset => asset.id), 'ASSET');
  const incidentTokens = tokenMap(incidents.map(incident => incident.id), 'CASE');
  const evidenceTokens = tokenMap(evidence.map(item => item.id), 'EVIDENCE');

  const redactions: Array<[string, string]> = [
    ...ssids.map(ssid => [ssid, ssidTokens.get(ssid)!] as [string, string]),
    ...macAliases.map(alias => [alias.raw, macTokens.get(alias.canonical)!] as [string, string]),
    ...sites.map(site => [site, siteTokens.get(site)!] as [string, string]),
    ...buildings.map(building => [building, buildingTokens.get(building)!] as [string, string]),
    ...floors.map(floor => [floor, floorTokens.get(floor)!] as [string, string]),
    ...owners.map(owner => [owner, ownerTokens.get(owner)!] as [string, string]),
    [project.name, '[PROJECT]'],
    [project.location, '[LOCATION]'],
    [project.auditorName, '[AUDITOR]'],
    [project.scope?.organization || '', '[ORGANIZATION]'],
    [project.scope?.site || '', '[SCOPE-SITE]'],
    [project.scope?.building || '', '[SCOPE-BUILDING]'],
    [project.scope?.area || '', '[SCOPE-AREA]'],
    [project.scope?.assessmentId || '', '[ASSESSMENT]']
  ];
  const redact = buildRedactor(redactions);

  const ssidToken = (ssid?: string): string => {
    const trimmed = (ssid || '').trim();
    return trimmed ? ssidTokens.get(trimmed) || '[unmapped SSID]' : '[hidden network]';
  };
  const macToken = (mac?: string): string => {
    const canonical = normalizeMac(mac || '');
    if (canonical) return macTokens.get(canonical) || '[unmapped MAC]';
    return mac ? '[unmapped MAC]' : '[no MAC]';
  };

  return {
    format: 'winwifi-anonymized-export',
    formatVersion: 1,
    generatedAt: now.toISOString(),
    project: { label: 'Anonymized audit project' },
    counts: {
      observations: accessPoints.length,
      assets: assets.length,
      incidents: incidents.length,
      evidence: evidence.length,
      alerts: alerts.length
    },
    observations: accessPoints.map(ap => ({
      mac: macToken(ap.bssid),
      ssid: ssidToken(ap.ssid),
      origin: ap.dataSourceOrigin,
      vendor: ap.vendor,
      band: ap.band,
      channel: ap.channel,
      security: ap.security,
      cipher: ap.cipher,
      pmfRequired: ap.pmfRequired,
      pmfInformationAvailable: ap.pmfInformationAvailable === true,
      wpsEnabled: ap.wpsEnabled,
      riskScore: ap.riskScore,
      classification: ap.classification,
      approvalStatus: ap.approvedStatus
    })),
    assets: assets.map(asset => ({
      id: assetTokens.get(asset.id) || 'ASSET-UNKNOWN',
      mac: macToken(asset.macAddress),
      ssid: ssidToken(asset.ssid),
      assetType: asset.assetType,
      classification: asset.classification,
      approvalStatus: asset.approvalStatus,
      site: asset.site ? siteTokens.get(asset.site) || '[unmapped site]' : '',
      building: asset.building ? buildingTokens.get(asset.building) || '[unmapped building]' : '',
      floor: asset.areaFloor ? floorTokens.get(asset.areaFloor) || '[unmapped floor]' : '',
      owner: asset.ownerDepartment ? ownerTokens.get(asset.ownerDepartment) || '[unmapped owner]' : '',
      vendor: asset.vendor,
      model: asset.model,
      hasNotes: Boolean(asset.notes && asset.notes.trim())
    })),
    incidents: incidents.map(incident => ({
      id: incidentTokens.get(incident.id) || 'CASE-UNKNOWN',
      title: redact(incident.title, 300),
      severity: incident.severity,
      status: incident.status,
      createdAt: incident.createdAt,
      updatedAt: incident.updatedAt,
      summary: redact(incident.summary, 1000),
      mac: macToken(incident.bssidTarget),
      ssid: ssidToken(incident.ssidTarget),
      evidenceCount: incident.evidenceIds?.length || 0,
      noteCount: incident.notes?.length || 0,
      resolution: incident.resolution ? redact(incident.resolution, 1000) : undefined
    })),
    evidence: evidence.map(item => ({
      id: evidenceTokens.get(item.id) || 'EVIDENCE-UNKNOWN',
      type: item.type,
      timestamp: item.timestamp,
      title: redact(item.title, 300),
      description: redact(item.description, 1000),
      hasChecksum: Boolean(item.checksum),
      hasRawData: Boolean(item.rawData)
    })),
    alerts: alerts.map(alert => ({
      ruleId: alert.ruleId,
      severity: alert.severity,
      status: alert.status,
      mac: macToken(alert.bssid),
      ssid: ssidToken(alert.ssid),
      title: redact(alert.title, 300),
      detail: redact(alert.detail, 1000),
      firstSeenAt: alert.firstSeenAt,
      lastSeenAt: alert.lastSeenAt,
      acknowledged: alert.status === 'Acknowledged' || Boolean(alert.acknowledgedBy)
    })),
    caveats: [
      'BSSIDs, SSIDs, asset identifiers, site names, owners, and project metadata are replaced with tokens that are stable within this file only.',
      'Free text is redacted on a best-effort basis using known values and MAC-address patterns. Unrecognized names or context may remain.',
      'Diagnostic logs, raw packet bytes, and the hash-chained audit trail are intentionally excluded.'
    ]
  };
}

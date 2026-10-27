import {
  AccessPoint,
  EnterpriseAssetApprovalStatus,
  EnterpriseAssetClassification,
  EnterpriseAssetRecord,
  EnterpriseAssetType
} from '../types';

export const ASSET_TYPES: EnterpriseAssetType[] = ['Access Point', 'Client Station', 'IoT Gateway', 'Sensor', 'Other'];
export const ASSET_CLASSIFICATIONS: EnterpriseAssetClassification[] = ['Corporate', 'Guest', 'IoT', 'Unknown', 'Suspicious', 'Rogue'];
export const ASSET_APPROVAL_STATUSES: EnterpriseAssetApprovalStatus[] = ['Approved', 'Unapproved', 'Under Investigation', 'Decommissioned', 'Pending Review'];

export const MAX_ASSET_ROWS = 5000;
const MAX_WARNINGS = 50;

export type AssetField =
  | 'id' | 'macAddress' | 'ssid' | 'assetType' | 'classification' | 'approvalStatus'
  | 'site' | 'building' | 'areaFloor' | 'ownerDepartment' | 'vendor' | 'model'
  | 'lastSeen' | 'notes';

export interface ParsedAssetRow {
  asset: EnterpriseAssetRecord;
  provided: Set<AssetField>;
  rowNumber: number;
}

export interface AssetCsvParseResult {
  rows: ParsedAssetRow[];
  warnings: string[];
  rejected: string[];
  rowsRead: number;
  fatalError?: string;
}

const EXPORT_COLUMNS: AssetField[] = [
  'macAddress', 'ssid', 'assetType', 'classification', 'approvalStatus',
  'site', 'building', 'areaFloor', 'ownerDepartment', 'vendor', 'model', 'lastSeen', 'notes'
];

const HEADER_ALIASES: Record<string, AssetField> = {
  macaddress: 'macAddress', mac: 'macAddress', bssid: 'macAddress', hardwareaddress: 'macAddress', address: 'macAddress',
  assetid: 'id', id: 'id',
  ssid: 'ssid', networkname: 'ssid',
  assettype: 'assetType', type: 'assetType', devicetype: 'assetType',
  classification: 'classification', class: 'classification', category: 'classification',
  approvalstatus: 'approvalStatus', approval: 'approvalStatus', status: 'approvalStatus',
  site: 'site', location: 'site',
  building: 'building',
  areafloor: 'areaFloor', floor: 'areaFloor',
  ownerdepartment: 'ownerDepartment', owner: 'ownerDepartment', department: 'ownerDepartment',
  vendor: 'vendor', manufacturer: 'vendor',
  model: 'model', devicemodel: 'model',
  lastseen: 'lastSeen', lastobserved: 'lastSeen', timestamp: 'lastSeen',
  notes: 'notes', note: 'notes', comment: 'notes'
};

function randomHex(bytes: number): string {
  const buffer = new Uint8Array(bytes);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(buffer);
  } else {
    for (let i = 0; i < buffer.length; i++) buffer[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(buffer, b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

export function newAssetId(): string {
  return `AST-${randomHex(6)}`;
}

/** Returns canonical colon-separated uppercase MAC, or null when invalid. */
export function normalizeMac(input?: string | null): string | null {
  if (!input || !input.trim()) return null;
  const compact = input.replace(/[:\-.\s]/g, '').toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(compact)) return null;
  if (compact === '000000000000' || compact === 'FFFFFFFFFFFF') return null;
  return compact.match(/.{2}/g)!.join(':');
}

export function sanitizeText(value: string | undefined, maxLength: number): string {
  if (!value) return '';
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '?')
    .slice(0, maxLength)
    .trim();
}

export function sanitizeMultilineText(value: string | undefined, maxLength: number): string {
  if (!value) return '';
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '?')
    .slice(0, maxLength)
    .trim();
}

export function formatUtcTimestamp(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

export function normalizeTimestamp(value?: string | null): string {
  if (!value || !value.trim()) return formatUtcTimestamp(new Date());
  const text = value.trim();
  const parsed = new Date(/[zZ]|[+\-]\d{2}:\d{2}$/.test(text) ? text : `${text.replace(' ', 'T')}Z`);
  return Number.isNaN(parsed.getTime()) ? formatUtcTimestamp(new Date()) : formatUtcTimestamp(parsed);
}

function canonicalFrom<T extends string>(list: T[], value: string | undefined, fallback: T): T | null {
  if (!value || !value.trim()) return fallback;
  return list.find(item => item.toLowerCase() === value.trim().toLowerCase()) ?? null;
}

export function normalizeAsset(input: Partial<EnterpriseAssetRecord>): { asset?: EnterpriseAssetRecord; error?: string } {
  const macAddress = normalizeMac(input.macAddress);
  if (!macAddress) {
    return { error: `'${sanitizeText(input.macAddress, 40)}' is not a valid unicast 48-bit MAC address.` };
  }

  const assetType = canonicalFrom(ASSET_TYPES, input.assetType, 'Access Point');
  if (!assetType) return { error: `Asset type '${sanitizeText(input.assetType, 40)}' is not one of: ${ASSET_TYPES.join(', ')}.` };

  const classification = canonicalFrom(ASSET_CLASSIFICATIONS, input.classification, 'Unknown');
  if (!classification) return { error: `Classification '${sanitizeText(input.classification, 40)}' is not one of: ${ASSET_CLASSIFICATIONS.join(', ')}.` };

  const approvalInput = input.approvalStatus?.trim().toLowerCase() === 'investigating'
    ? 'Under Investigation'
    : input.approvalStatus;
  const approvalStatus = canonicalFrom(ASSET_APPROVAL_STATUSES, approvalInput, 'Pending Review');
  if (!approvalStatus) return { error: `Approval status '${sanitizeText(input.approvalStatus, 40)}' is not one of: ${ASSET_APPROVAL_STATUSES.join(', ')}.` };

  return {
    asset: {
      id: sanitizeText(input.id, 64) || newAssetId(),
      macAddress,
      ssid: sanitizeText(input.ssid, 32),
      assetType,
      classification,
      approvalStatus,
      site: sanitizeText(input.site, 120),
      building: sanitizeText(input.building, 120),
      areaFloor: sanitizeText(input.areaFloor, 40),
      ownerDepartment: sanitizeText(input.ownerDepartment, 120),
      vendor: sanitizeText(input.vendor, 120),
      model: sanitizeText(input.model, 120),
      lastSeen: normalizeTimestamp(input.lastSeen),
      notes: sanitizeMultilineText(input.notes, 500)
    }
  };
}

export function escapeCsvCell(value: string | undefined): string {
  let text = value ?? '';
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function unescapeCsvCell(value: string): string {
  if (/^'[=+\-@\t\r]/.test(value)) return value.slice(1);
  return value;
}

function normalizeHeader(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function readRows(text: string, warnings: string[]): { rows: string[][]; limited: boolean } {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;

  const endRow = () => {
    row.push(field);
    field = '';
    if (rows.length === 0 || row.some(cell => cell.trim() !== '')) rows.push(row);
    row = [];
  };

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
      continue;
    }

    if (c === '"') {
      if (field.length === 0) inQuotes = true;
      else field += '"';
    } else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\r' || c === '\n') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      endRow();
      if (rows.length > MAX_ASSET_ROWS + 1) return { rows, limited: true };
    } else {
      field += c;
    }
  }

  if (inQuotes) warnings.push('The CSV ends inside a quoted field; the final row may be incomplete.');
  if (field.length > 0 || row.length > 0) endRow();
  return { rows, limited: false };
}

function addWarning(warnings: string[], message: string): void {
  if (warnings.length < MAX_WARNINGS) warnings.push(message);
  else if (warnings.length === MAX_WARNINGS) warnings.push(`Additional warnings were suppressed after ${MAX_WARNINGS} entries.`);
}

export function parseAssetCsv(csv: string): AssetCsvParseResult {
  const result: AssetCsvParseResult = { rows: [], warnings: [], rejected: [], rowsRead: 0 };
  if (!csv || !csv.trim()) {
    result.fatalError = 'The CSV file is empty.';
    return result;
  }

  const text = csv.replace(/^\uFEFF/, '');
  const { rows, limited } = readRows(text, result.warnings);
  if (limited) addWarning(result.warnings, `Only the first ${MAX_ASSET_ROWS} data rows were imported.`);

  if (rows.length === 0) {
    result.fatalError = 'The CSV file does not contain a header row.';
    return result;
  }

  const header = rows[0];
  const columnMap: (AssetField | null)[] = new Array(header.length).fill(null);
  const unseenHeaders: string[] = [];
  let hasMac = false;
  header.forEach((cell, index) => {
    const key = normalizeHeader(cell);
    if (!key) return;
    const canonical = HEADER_ALIASES[key];
    if (!canonical) {
      unseenHeaders.push(cell.trim());
      return;
    }
    if (columnMap.includes(canonical)) {
      addWarning(result.warnings, `Duplicate column '${cell.trim()}' was ignored.`);
      return;
    }
    columnMap[index] = canonical;
    if (canonical === 'macAddress') hasMac = true;
  });

  if (unseenHeaders.length > 0) {
    addWarning(result.warnings, `Ignored unrecognized column(s): ${unseenHeaders.map(h => `'${sanitizeText(h, 40)}'`).join(', ')}.`);
  }
  if (!hasMac) {
    result.fatalError = "The CSV must contain a MAC/BSSID column (for example 'macAddress').";
    return result;
  }

  const merged = new Map<string, ParsedAssetRow>();
  for (let r = 1; r < rows.length && r <= MAX_ASSET_ROWS; r++) {
    const cells = rows[r];
    if (cells.every(cell => !cell.trim())) continue;
    result.rowsRead++;

    const values = new Map<AssetField, string>();
    for (let c = 0; c < cells.length && c < columnMap.length; c++) {
      const fieldName = columnMap[c];
      if (fieldName) values.set(fieldName, unescapeCsvCell(cells[c]));
    }

    const mac = normalizeMac(values.get('macAddress'));
    if (!mac) {
      result.rejected.push(`Row ${r + 1}: '${sanitizeText(values.get('macAddress'), 40)}' is not a valid unicast 48-bit MAC address.`);
      continue;
    }

    const normalized = normalizeAsset({
      id: values.get('id'),
      macAddress: mac,
      ssid: values.get('ssid'),
      assetType: values.get('assetType') as EnterpriseAssetType | undefined,
      classification: values.get('classification') as EnterpriseAssetClassification | undefined,
      approvalStatus: values.get('approvalStatus') as EnterpriseAssetApprovalStatus | undefined,
      site: values.get('site'),
      building: values.get('building'),
      areaFloor: values.get('areaFloor'),
      ownerDepartment: values.get('ownerDepartment'),
      vendor: values.get('vendor'),
      model: values.get('model'),
      lastSeen: values.get('lastSeen'),
      notes: values.get('notes')
    });
    if (!normalized.asset) {
      result.rejected.push(`Row ${r + 1}: ${normalized.error}`);
      continue;
    }

    if (merged.has(mac)) addWarning(result.warnings, `Row ${r + 1}: duplicate MAC ${mac} replaced the earlier row.`);
    merged.set(mac, {
      asset: normalized.asset,
      provided: new Set(values.keys()),
      rowNumber: r + 1
    });
  }

  result.rows = Array.from(merged.values()).sort((a, b) => a.rowNumber - b.rowNumber);
  return result;
}

export function serializeAssetCsv(assets: EnterpriseAssetRecord[]): string {
  const lines = [EXPORT_COLUMNS.map(escapeCsvCell).join(',')];
  for (const asset of assets) {
    lines.push(EXPORT_COLUMNS.map(column => escapeCsvCell(asset[column])).join(','));
  }
  return `${lines.join('\r\n')}\r\n`;
}

export function mergeMissingFields(existing: EnterpriseAssetRecord, incoming: ParsedAssetRow): EnterpriseAssetRecord {
  const merged: EnterpriseAssetRecord = { ...existing };
  const copyable: AssetField[] = [
    'ssid', 'assetType', 'classification', 'approvalStatus', 'site', 'building',
    'areaFloor', 'ownerDepartment', 'vendor', 'model', 'lastSeen', 'notes'
  ];
  for (const field of copyable) {
    if (incoming.provided.has(field)) {
      (merged as any)[field] = incoming.asset[field];
    }
  }
  return merged;
}

/** Merge incoming records by MAC. Incoming values win; existing ids survive blank ids. */
export function mergeAssetLists(existing: EnterpriseAssetRecord[], incoming: EnterpriseAssetRecord[]): EnterpriseAssetRecord[] {
  const byMac = new Map<string, EnterpriseAssetRecord>();
  for (const asset of existing) {
    const mac = normalizeMac(asset.macAddress);
    if (mac) byMac.set(mac, { ...asset, macAddress: mac });
  }
  for (const asset of incoming) {
    const mac = normalizeMac(asset.macAddress);
    if (!mac) continue;
    const prior = byMac.get(mac);
    byMac.set(mac, { ...asset, macAddress: mac, id: asset.id || prior?.id || newAssetId() });
  }
  return Array.from(byMac.values()).sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
}

function toApClassification(classification: EnterpriseAssetClassification): AccessPoint['classification'] {
  return classification;
}

function toApApproval(status: EnterpriseAssetApprovalStatus): AccessPoint['approvedStatus'] {
  switch (status) {
    case 'Approved': return 'Approved';
    case 'Unapproved':
    case 'Decommissioned': return 'Unapproved';
    case 'Under Investigation': return 'Investigating';
    default: return 'Pending Review';
  }
}

/** Registry records are authoritative for enrolled BSSIDs only; unlisted APs are untouched. */
export function applyAssetsToAccessPoints(accessPoints: AccessPoint[], assets: EnterpriseAssetRecord[]): AccessPoint[] {
  if (!assets.length) return accessPoints;
  const byMac = new Map<string, EnterpriseAssetRecord>();
  for (const asset of assets) {
    const mac = normalizeMac(asset.macAddress);
    if (mac) byMac.set(mac, asset);
  }
  if (!byMac.size) return accessPoints;

  return accessPoints.map(ap => {
    const asset = byMac.get(normalizeMac(ap.bssid) || ap.bssid.toUpperCase());
    if (!asset) return ap;
    return {
      ...ap,
      classification: toApClassification(asset.classification),
      approvedStatus: toApApproval(asset.approvalStatus),
      ownership: asset.ownerDepartment,
      site: asset.site,
      building: asset.building,
      floor: asset.areaFloor,
      notes: asset.notes
    };
  });
}

/** Removes registry-derived metadata from the matching BSSID after a registry delete. */
export function removeAssetFromAccessPoints(accessPoints: AccessPoint[], macAddress: string): AccessPoint[] {
  const target = normalizeMac(macAddress);
  if (!target) return accessPoints;
  return accessPoints.map(ap => {
    if ((normalizeMac(ap.bssid) || ap.bssid.toUpperCase()) !== target) return ap;
    return {
      ...ap,
      classification: 'Unknown',
      approvedStatus: 'Pending Review',
      ownership: '',
      site: '',
      building: '',
      floor: '',
      notes: ''
    };
  });
}

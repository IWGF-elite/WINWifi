import { OperatorRole, OPERATOR_ROLES, sanitizeOperatorName } from './operatorRoles';

export const MAX_AUDIT_RECORDS = 5000;
const MAX_ACTOR = 80;
const MAX_SUBJECT = 200;
const MAX_DETAILS = 500;

export type AuditAction =
  | 'PROJECT_CREATE'
  | 'PROJECT_RENAME'
  | 'PROJECT_DELETE'
  | 'ROLE_CHANGE'
  | 'ASSET_SAVE'
  | 'ASSET_DELETE'
  | 'ASSET_IMPORT'
  | 'ASSET_EXPORT'
  | 'SITE_DIRECTORY'
  | 'MAINTENANCE_REQUEST'
  | 'MAINTENANCE_APPROVE'
  | 'MAINTENANCE_REJECT'
  | 'MAINTENANCE_REVOKE'
  | 'CONNECT_ATTEMPT'
  | 'ALERT_ACK'
  | 'LOG_CLEAR'
  | 'AUDIT_EXPORT'
  | 'AUDIT_RESET'
  | 'UNSUPPORTED';

export const AUDIT_ACTIONS: AuditAction[] = [
  'PROJECT_CREATE',
  'PROJECT_RENAME',
  'PROJECT_DELETE',
  'ROLE_CHANGE',
  'ASSET_SAVE',
  'ASSET_DELETE',
  'ASSET_IMPORT',
  'ASSET_EXPORT',
  'SITE_DIRECTORY',
  'MAINTENANCE_REQUEST',
  'MAINTENANCE_APPROVE',
  'MAINTENANCE_REJECT',
  'MAINTENANCE_REVOKE',
  'CONNECT_ATTEMPT',
  'ALERT_ACK',
  'LOG_CLEAR',
  'AUDIT_EXPORT',
  'AUDIT_RESET'
];

export interface AuditChainRecord {
  seq: number;
  timestamp: string;
  actor: string;
  role: OperatorRole;
  action: AuditAction;
  subject: string;
  details: string;
  prevHash: string;
  hash: string;
}

export interface AuditChainState {
  version: 1;
  chainId: string;
  createdAt: string;
  records: AuditChainRecord[];
}

export interface AuditAppendInput {
  action: AuditAction;
  subject: string;
  details: string;
}

export interface AuditAppendResult {
  state: AuditChainState;
  record?: AuditChainRecord;
  error?: string;
}

export interface AuditVerification {
  valid: boolean;
  checked: number;
  reason?: string;
  brokenAt?: number;
  headHash: string;
}

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function rightRotate(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

/** Synchronous SHA-256 so the audit chain can be appended and verified without async gaps. */
export function sha256Hex(message: string): string {
  const bytes = new TextEncoder().encode(message);
  const bitLength = bytes.length * 8;
  const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
  view.setUint32(paddedLength - 4, bitLength % 0x100000000, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let index = 0; index < 16; index++) {
      w[index] = view.getUint32(offset + index * 4, false);
    }
    for (let index = 16; index < 64; index++) {
      const s0 = rightRotate(w[index - 15], 7) ^ rightRotate(w[index - 15], 18) ^ (w[index - 15] >>> 3);
      const s1 = rightRotate(w[index - 2], 17) ^ rightRotate(w[index - 2], 19) ^ (w[index - 2] >>> 10);
      w[index] = (w[index - 16] + s0 + w[index - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let index = 0; index < 64; index++) {
      const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + K[index] + w[index]) >>> 0;
      const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map(value => value.toString(16).padStart(8, '0'))
    .join('');
}

function newChainId(): string {
  const buffered = new Uint8Array(6);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(buffered);
  } else {
    for (let index = 0; index < buffered.length; index++) buffered[index] = Math.floor(Math.random() * 256);
  }
  const suffix = Array.from(buffered, byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `AUD-${Date.now().toString(36).toUpperCase()}-${suffix}`;
}

export function createAuditChain(now: Date = new Date()): AuditChainState {
  return {
    version: 1,
    chainId: newChainId(),
    createdAt: now.toISOString(),
    records: []
  };
}

export function genesisHash(chainId: string): string {
  return sha256Hex(`winwifi-audit-genesis:${chainId}`);
}

function sanitizeText(value: unknown, max: number): string {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

function canonicalPayload(record: Omit<AuditChainRecord, 'hash'>): string {
  return JSON.stringify([
    record.seq,
    record.timestamp,
    record.actor,
    record.role,
    record.action,
    record.subject,
    record.details,
    record.prevHash
  ]);
}

export function computeAuditHash(record: Omit<AuditChainRecord, 'hash'>): string {
  return sha256Hex(canonicalPayload(record));
}

export function headHashOf(state: AuditChainState): string {
  return state.records.length ? state.records[state.records.length - 1].hash : genesisHash(state.chainId);
}

/** Keeps stored values intact enough that tampering is reported, not silently repaired. */
export function normalizeAuditChain(input: unknown, now: Date = new Date()): AuditChainState {
  if (!input || typeof input !== 'object') return createAuditChain(now);
  const raw = input as Record<string, unknown>;
  const chainId = sanitizeText(raw.chainId, 64);
  const createdAt = typeof raw.createdAt === 'string' && Number.isFinite(Date.parse(raw.createdAt))
    ? new Date(Date.parse(raw.createdAt)).toISOString()
    : now.toISOString();
  if (raw.version !== 1 || !chainId) return createAuditChain(now);

  const rawRecords = Array.isArray(raw.records) ? raw.records : [];
  const records: AuditChainRecord[] = [];
  for (const entry of rawRecords) {
    if (records.length >= MAX_AUDIT_RECORDS) break;
    if (!entry || typeof entry !== 'object') continue;
    const item = entry as Record<string, unknown>;
    const role = OPERATOR_ROLES.includes(item.role as OperatorRole) ? item.role as OperatorRole : 'Viewer';
    const action = AUDIT_ACTIONS.includes(item.action as AuditAction) ? item.action as AuditAction : 'UNSUPPORTED';
    records.push({
      seq: Number.isInteger(item.seq) ? item.seq as number : 0,
      timestamp: sanitizeText(item.timestamp, 40),
      actor: sanitizeText(item.actor, MAX_ACTOR),
      role,
      action,
      subject: sanitizeText(item.subject, MAX_SUBJECT),
      details: sanitizeText(item.details, MAX_DETAILS),
      prevHash: sanitizeText(item.prevHash, 64),
      hash: sanitizeText(item.hash, 64)
    });
  }

  return { version: 1, chainId, createdAt, records };
}

export function appendAuditRecord(
  state: AuditChainState,
  input: AuditAppendInput,
  actor: string,
  role: OperatorRole,
  now: Date = new Date()
): AuditAppendResult {
  if (!AUDIT_ACTIONS.includes(input.action)) {
    return { state, error: 'That audit action is not supported.' };
  }
  if (state.records.length >= MAX_AUDIT_RECORDS) {
    return { state, error: `This audit chain holds ${MAX_AUDIT_RECORDS} records. Export it and start a new chain before recording more events.` };
  }
  const sanitizedActor = sanitizeOperatorName(actor);
  const subject = sanitizeText(input.subject, MAX_SUBJECT);
  if (!subject) return { state, error: 'An audit record needs a subject.' };

  const previous = state.records[state.records.length - 1];
  const prevHash = previous ? previous.hash : genesisHash(state.chainId);
  const base: Omit<AuditChainRecord, 'hash'> = {
    seq: previous ? previous.seq + 1 : 1,
    timestamp: now.toISOString(),
    actor: sanitizedActor,
    role,
    action: input.action,
    subject,
    details: sanitizeText(input.details, MAX_DETAILS),
    prevHash
  };
  const record: AuditChainRecord = { ...base, hash: computeAuditHash(base) };

  return { state: { ...state, records: [...state.records, record] }, record };
}

export function verifyAuditChain(state: AuditChainState): AuditVerification {
  let previousHash = genesisHash(state.chainId);
  for (let index = 0; index < state.records.length; index++) {
    const record = state.records[index];
    const expectedSeq = index + 1;
    if (record.seq !== expectedSeq) {
      return {
        valid: false,
        checked: index,
        brokenAt: expectedSeq,
        reason: `Record ${index + 1} has sequence ${record.seq}; the chain is missing or reordered entries.`,
        headHash: previousHash
      };
    }
    if (record.prevHash !== previousHash) {
      return {
        valid: false,
        checked: index,
        brokenAt: record.seq,
        reason: `Record ${record.seq} does not link to the previous hash.`,
        headHash: previousHash
      };
    }
    if (record.action === 'UNSUPPORTED' || !AUDIT_ACTIONS.includes(record.action)) {
      return {
        valid: false,
        checked: index,
        brokenAt: record.seq,
        reason: `Record ${record.seq} uses an unsupported action.`,
        headHash: previousHash
      };
    }
    if (computeAuditHash(record) !== record.hash) {
      return {
        valid: false,
        checked: index,
        brokenAt: record.seq,
        reason: `Record ${record.seq} was modified after it was written.`,
        headHash: previousHash
      };
    }
    previousHash = record.hash;
  }
  return { valid: true, checked: state.records.length, headHash: previousHash };
}

export function resetAuditChain(
  previous: AuditChainState,
  actor: string,
  role: OperatorRole,
  now: Date = new Date()
): AuditChainState {
  const next = createAuditChain(now);
  const details = `Previous chain ${previous.chainId} ended at ${headHashOf(previous)} with ${previous.records.length} record(s).`;
  const appended = appendAuditRecord(next, { action: 'AUDIT_RESET', subject: 'Audit chain rotation', details }, actor, role, now);
  return appended.state;
}

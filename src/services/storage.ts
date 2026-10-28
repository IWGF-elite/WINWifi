import { AccessPoint, AnalystClassification, AuditProject, AuditLog, EvidenceItem, HandshakeInfo, IncidentRecord, EnterpriseAssetRecord, MaintenanceApprovalRecord, SiteRecord } from '../types';
import { normalizeSiteDirectory } from './siteDirectory';
import { normalizeMaintenanceApprovals } from './maintenanceApproval';
import { AuditChainState, MAX_AUDIT_RECORDS, normalizeAuditChain } from './auditChain';
import { AlertRecord, MAX_ALERTS, normalizeAlerts } from './alerts';

const DB_PREFIX = 'winwifi_sqlite_';

export interface SqlQueryResult {
  columns: string[];
  rows: (string | number | boolean | null)[][];
  rowCount: number;
  executionTimeMs: number;
  tableName?: string;
}

export class SqliteDatabaseService {
  private static instance: SqliteDatabaseService;

  public static getInstance(): SqliteDatabaseService {
    if (!SqliteDatabaseService.instance) {
      SqliteDatabaseService.instance = new SqliteDatabaseService();
    }
    return SqliteDatabaseService.instance;
  }

  // Projects CRUD
  public getProjects(): AuditProject[] {
    const raw = localStorage.getItem(`${DB_PREFIX}projects`);
    if (!raw) {
      const defaultProject: AuditProject = {
        id: 'proj-001',
        name: 'Wireless Security Audit',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        location: 'Not specified',
        auditorName: 'Not assigned',
        notes: '',
        savedNetworksCount: 0,
        capturedHandshakesCount: 0,
      };
      this.saveProjects([defaultProject]);
      return [defaultProject];
    }
    try {
      const projects = JSON.parse(raw) as AuditProject[];
      const starter = projects.find(project => project.id === 'proj-001' && (project.name === 'Corporate HQ Perimeter Audit 2026' || project.name === 'New Wi-Fi Assessment'));
      if (starter) {
        starter.name = 'Wireless Security Audit';
        starter.location = 'Not specified';
        starter.auditorName = 'Not assigned';
        starter.notes = '';
        starter.savedNetworksCount = 0;
        starter.capturedHandshakesCount = 0;
        this.saveProjects(projects);
      }
      return projects;
    } catch {
      return [];
    }
  }

  public saveProjects(projects: AuditProject[]): void {
    localStorage.setItem(`${DB_PREFIX}projects`, JSON.stringify(projects));
  }

  public getCurrentProjectId(): string {
    return localStorage.getItem(`${DB_PREFIX}current_proj_id`) || 'proj-001';
  }

  public setCurrentProjectId(id: string): void {
    localStorage.setItem(`${DB_PREFIX}current_proj_id`, id);
  }

  public deleteProjectData(projectId: string): void {
    localStorage.removeItem(`${DB_PREFIX}access_points_${projectId}`);
    localStorage.removeItem(`${DB_PREFIX}analyst_overrides_${projectId}`);
    for (const kind of ['incidents', 'evidence', 'logs', 'handshakes', 'assets', 'sites', 'maintenance', 'audit_chain', 'alerts']) {
      localStorage.removeItem(this.scopedKey(kind, projectId));
    }
  }

  private scopedKey(kind: string, projectId: string): string {
    return `${DB_PREFIX}${kind}_${projectId}`;
  }

  // Early builds stored cases, evidence, logs, and handshakes globally, which
  // leaked them across projects. Move a legacy global record into the selected
  // project once so history is preserved without cross-project bleed.
  private readScoped<T>(kind: string, projectId: string, fallback: T): T {
    const key = this.scopedKey(kind, projectId);
    let raw = localStorage.getItem(key);
    if (raw === null) {
      const legacyKey = `${DB_PREFIX}${kind}`;
      const legacy = localStorage.getItem(legacyKey);
      if (legacy !== null) {
        localStorage.setItem(key, legacy);
        localStorage.removeItem(legacyKey);
        raw = legacy;
      }
    }
    if (raw === null) return fallback;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return fallback;
    }
  }

  private writeScoped<T>(kind: string, projectId: string, value: T): void {
    localStorage.setItem(this.scopedKey(kind, projectId), JSON.stringify(value));
  }

  public getIncidents(projectId: string = this.getCurrentProjectId()): IncidentRecord[] | null {
    const key = this.scopedKey('incidents', projectId);
    if (localStorage.getItem(key) === null) {
      const legacy = localStorage.getItem(`${DB_PREFIX}incidents`);
      if (legacy === null) return null;
    }
    return this.readScoped<IncidentRecord[] | null>('incidents', projectId, null);
  }

  public saveIncidents(incidents: IncidentRecord[], projectId: string = this.getCurrentProjectId()): void {
    this.writeScoped('incidents', projectId, incidents);
  }

  public getEvidenceItems(projectId: string = this.getCurrentProjectId()): EvidenceItem[] {
    return this.readScoped<EvidenceItem[]>('evidence', projectId, []);
  }

  public saveEvidenceItems(items: EvidenceItem[], projectId: string = this.getCurrentProjectId()): void {
    this.writeScoped('evidence', projectId, items);
  }

  public getAccessPoints(projectId: string): AccessPoint[] {
    const raw = localStorage.getItem(`${DB_PREFIX}access_points_${projectId}`);
    if (!raw) return [];
    try {
      return JSON.parse(raw) as AccessPoint[];
    } catch {
      return [];
    }
  }

  public saveAccessPoints(projectId: string, accessPoints: AccessPoint[]): void {
    localStorage.setItem(`${DB_PREFIX}access_points_${projectId}`, JSON.stringify(accessPoints));
  }

  public getAnalystOverrides(projectId: string): Record<string, AnalystClassification> {
    const raw = localStorage.getItem(`${DB_PREFIX}analyst_overrides_${projectId}`);
    if (!raw) return {};
    try {
      return JSON.parse(raw) as Record<string, AnalystClassification>;
    } catch {
      return {};
    }
  }

  public saveAnalystOverride(projectId: string, bssid: string, classification: AnalystClassification): void {
    const overrides = this.getAnalystOverrides(projectId);
    overrides[bssid.toUpperCase()] = classification;
    localStorage.setItem(`${DB_PREFIX}analyst_overrides_${projectId}`, JSON.stringify(overrides));
  }

  // Logs
  public getLogs(projectId: string = this.getCurrentProjectId()): AuditLog[] {
    return this.readScoped<AuditLog[]>('logs', projectId, []);
  }

  public appendLog(log: Omit<AuditLog, 'id' | 'timestamp'>, projectId: string = this.getCurrentProjectId()): AuditLog {
    const fullLog: AuditLog = {
      ...log,
      id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toLocaleTimeString(),
    };
    const current = this.getLogs(projectId);
    const updated = [fullLog, ...current].slice(0, 300); // keep last 300
    this.writeScoped('logs', projectId, updated);
    return fullLog;
  }

  public clearLogs(projectId: string = this.getCurrentProjectId()): void {
    localStorage.removeItem(this.scopedKey('logs', projectId));
  }

  // Enterprise asset registry (project-scoped local mirror of native SQLite)
  public getSiteDirectory(projectId: string = this.getCurrentProjectId()): SiteRecord[] {
    return normalizeSiteDirectory(this.readScoped<SiteRecord[]>('sites', projectId, []));
  }

  public saveSiteDirectory(sites: SiteRecord[], projectId: string = this.getCurrentProjectId()): void {
    this.writeScoped('sites', projectId, normalizeSiteDirectory(sites));
  }

  public getMaintenanceApprovals(projectId: string = this.getCurrentProjectId()): MaintenanceApprovalRecord[] {
    return normalizeMaintenanceApprovals(this.readScoped<MaintenanceApprovalRecord[]>('maintenance', projectId, []));
  }

  public saveMaintenanceApprovals(records: MaintenanceApprovalRecord[], projectId: string = this.getCurrentProjectId()): void {
    this.writeScoped('maintenance', projectId, normalizeMaintenanceApprovals(records));
  }

  public getAuditChain(projectId: string = this.getCurrentProjectId()): AuditChainState {
    const raw = this.readScoped<unknown>('audit_chain', projectId, null);
    const normalized = normalizeAuditChain(raw);
    if (raw === null) this.writeScoped('audit_chain', projectId, normalized);
    return normalized;
  }

  public saveAuditChain(state: AuditChainState, projectId: string = this.getCurrentProjectId()): void {
    const bounded: AuditChainState = state.records.length > MAX_AUDIT_RECORDS
      ? { ...state, records: state.records.slice(0, MAX_AUDIT_RECORDS) }
      : state;
    this.writeScoped('audit_chain', projectId, bounded);
  }

  public getAlerts(projectId: string = this.getCurrentProjectId()): AlertRecord[] {
    return normalizeAlerts(this.readScoped<unknown>('alerts', projectId, []));
  }

  public saveAlerts(records: AlertRecord[], projectId: string = this.getCurrentProjectId()): void {
    this.writeScoped('alerts', projectId, records.slice(0, MAX_ALERTS));
  }

  public getEnterpriseAssets(projectId: string = this.getCurrentProjectId()): EnterpriseAssetRecord[] {
    return this.readScoped<EnterpriseAssetRecord[]>('assets', projectId, []);
  }

  public saveEnterpriseAssets(projectId: string, assets: EnterpriseAssetRecord[]): void {
    this.writeScoped('assets', projectId, assets);
  }

  // Saved Handshakes in SQLite
  public getSavedHandshakes(projectId: string = this.getCurrentProjectId()): HandshakeInfo[] {
    return this.readScoped<HandshakeInfo[]>('handshakes', projectId, []);
  }

  public saveHandshake(handshake: HandshakeInfo, projectId: string = this.getCurrentProjectId()): void {
    const list = this.getSavedHandshakes(projectId);
    const existingIdx = list.findIndex(h => h.apBssid.toLowerCase() === handshake.apBssid.toLowerCase());
    if (existingIdx >= 0) {
      list[existingIdx] = handshake;
    } else {
      list.unshift(handshake);
    }
    this.writeScoped('handshakes', projectId, list);
  }

  // SQL Query Engine with real filtering, projections, and table support
  public executeQuery(sql: string, liveAps: AccessPoint[]): SqlQueryResult {
    const startTime = performance.now();
    const cleanSql = sql.trim();
    const upper = cleanSql.toUpperCase();

    // SELECT * FROM access_points
    if (upper.includes('FROM ACCESS_POINTS') || upper.includes('FROM "ACCESS_POINTS"')) {
      let filtered = [...liveAps];

      // WHERE conditions
      if (upper.includes('WHERE')) {
        const whereClause = upper.split('WHERE')[1] || '';
        if (whereClause.includes('SCORE <') || whereClause.includes('SECURITY_SCORE <')) {
          const match = whereClause.match(/SCORE\s*<\s*(\d+)/i);
          const threshold = match ? parseInt(match[1], 10) : 50;
          filtered = filtered.filter(a => a.securityScore < threshold);
        }
        if (whereClause.includes('SCORE >=') || whereClause.includes('SECURITY_SCORE >=')) {
          const match = whereClause.match(/SCORE\s*>=\s*(\d+)/i);
          const threshold = match ? parseInt(match[1], 10) : 70;
          filtered = filtered.filter(a => a.securityScore >= threshold);
        }
        if (whereClause.includes('WPS = 1') || whereClause.includes('WPS_ENABLED = 1')) {
          filtered = filtered.filter(a => a.wpsEnabled);
        }
        if (whereClause.includes('BAND = \'5 GHZ\'') || whereClause.includes('BAND = "5 GHZ"')) {
          filtered = filtered.filter(a => a.band === '5 GHz');
        }
        if (whereClause.includes('BAND = \'2.4 GHZ\'') || whereClause.includes('BAND = "2.4 GHZ"')) {
          filtered = filtered.filter(a => a.band === '2.4 GHz');
        }
        if (whereClause.includes('BAND = \'6 GHZ\'') || whereClause.includes('BAND = "6 GHZ"')) {
          filtered = filtered.filter(a => a.band === '6 GHz');
        }
        if (whereClause.includes('ROGUE = 1') || whereClause.includes('IS_ROGUE = 1')) {
          filtered = filtered.filter(a => a.isRogueCandidate);
        }
        if (whereClause.includes('OPEN') || whereClause.includes('WEP')) {
          filtered = filtered.filter(a => a.security.includes('Open') || a.security.includes('WEP'));
        }
      }

      // ORDER BY
      if (upper.includes('ORDER BY')) {
        if (upper.includes('RSSI DESC')) filtered.sort((a, b) => b.rssi - a.rssi);
        else if (upper.includes('RSSI ASC') || upper.includes('RSSI')) filtered.sort((a, b) => a.rssi - b.rssi);
        else if (upper.includes('SCORE DESC')) filtered.sort((a, b) => b.securityScore - a.securityScore);
        else if (upper.includes('SCORE ASC')) filtered.sort((a, b) => a.securityScore - b.securityScore);
        else if (upper.includes('CHANNEL')) filtered.sort((a, b) => a.channel - b.channel);
      }

      // LIMIT
      if (upper.includes('LIMIT')) {
        const limitMatch = upper.match(/LIMIT\s+(\d+)/);
        if (limitMatch) {
          const lim = parseInt(limitMatch[1], 10);
          filtered = filtered.slice(0, lim);
        }
      }

      // Projections
      let columns = ['bssid', 'ssid', 'channel', 'band', 'security', 'cipher', 'rssi', 'clients', 'wps', 'security_score'];
      let selectPart = cleanSql.substring(6, upper.indexOf('FROM')).trim();
      let isSelectAll = selectPart === '*' || selectPart === '';

      let rows: (string | number | boolean | null)[][];
      if (isSelectAll) {
        rows = filtered.map(ap => [
          ap.bssid,
          ap.ssid,
          ap.channel,
          ap.band,
          ap.security,
          ap.cipher,
          `${ap.rssi} dBm`,
          ap.clients.length,
          ap.wpsEnabled ? 'Enabled (1)' : 'Disabled (0)',
          ap.securityScore
        ]);
      } else {
        const requestedCols = selectPart.split(',').map(c => c.trim().toLowerCase());
        columns = requestedCols;
        rows = filtered.map(ap => {
          return requestedCols.map(col => {
            if (col.includes('bssid')) return ap.bssid;
            if (col.includes('ssid')) return ap.ssid;
            if (col.includes('channel')) return ap.channel;
            if (col.includes('band')) return ap.band;
            if (col.includes('security')) return ap.security;
            if (col.includes('cipher')) return ap.cipher;
            if (col.includes('rssi')) return ap.rssi;
            if (col.includes('score')) return ap.securityScore;
            if (col.includes('vendor')) return ap.vendor;
            if (col.includes('client')) return ap.clients.length;
            return null;
          });
        });
      }

      return {
        columns,
        rows,
        rowCount: rows.length,
        executionTimeMs: Math.max(1, Math.round(performance.now() - startTime)),
        tableName: 'access_points'
      };
    }

    // SELECT * FROM captured_handshakes
    if (upper.includes('FROM CAPTURED_HANDSHAKES') || upper.includes('FROM HANDSHAKES')) {
      const handshakes = this.getSavedHandshakes();
      const columns = ['ap_bssid', 'client_mac', 'ssid', 'type', 'captured_steps', 'mic_verified', 'captured_at'];
      const rows = handshakes.map(h => [
        h.apBssid,
        h.clientMac,
        h.ssid,
        h.type,
        h.capturedSteps.join(', '),
        h.micVerified ? 'VALID (1)' : 'INVALID (0)',
        h.capturedAt
      ]);
      return {
        columns,
        rows,
        rowCount: rows.length,
        executionTimeMs: Math.max(1, Math.round(performance.now() - startTime)),
        tableName: 'captured_handshakes'
      };
    }

    // SELECT * FROM projects
    if (upper.includes('FROM PROJECTS')) {
      const projects = this.getProjects();
      const columns = ['id', 'name', 'location', 'auditor_name', 'networks_count', 'handshakes_count', 'updated_at'];
      const rows = projects.map(p => [
        p.id,
        p.name,
        p.location,
        p.auditorName,
        p.savedNetworksCount,
        p.capturedHandshakesCount,
        p.updatedAt
      ]);
      return {
        columns,
        rows,
        rowCount: rows.length,
        executionTimeMs: Math.max(1, Math.round(performance.now() - startTime)),
        tableName: 'projects'
      };
    }

    // SELECT * FROM audit_logs
    if (upper.includes('FROM AUDIT_LOGS') || upper.includes('FROM LOGS')) {
      const logs = this.getLogs();
      const columns = ['id', 'timestamp', 'level', 'source', 'message'];
      const rows = logs.slice(0, 50).map(l => [
        l.id,
        l.timestamp,
        l.level,
        l.source,
        l.message
      ]);
      return {
        columns,
        rows,
        rowCount: rows.length,
        executionTimeMs: Math.max(1, Math.round(performance.now() - startTime)),
        tableName: 'audit_logs'
      };
    }

    // Schema query: SELECT name FROM sqlite_master WHERE type='table'
    if (upper.includes('SQLITE_MASTER')) {
      return {
        columns: ['type', 'name', 'tbl_name', 'sql'],
        rows: [
          ['table', 'projects', 'projects', 'CREATE TABLE projects (id TEXT PRIMARY KEY, name TEXT, location TEXT, auditor TEXT, updated_at TEXT)'],
          ['table', 'access_points', 'access_points', 'CREATE TABLE access_points (bssid TEXT PRIMARY KEY, ssid TEXT, channel INTEGER, band TEXT, security TEXT, cipher TEXT, rssi INTEGER, wps_enabled INTEGER, security_score INTEGER)'],
          ['table', 'captured_handshakes', 'captured_handshakes', 'CREATE TABLE captured_handshakes (id INTEGER PRIMARY KEY, ap_bssid TEXT, client_mac TEXT, ssid TEXT, type TEXT, mic_verified INTEGER, captured_at TEXT)'],
          ['table', 'audit_logs', 'audit_logs', 'CREATE TABLE audit_logs (id TEXT PRIMARY KEY, timestamp TEXT, level TEXT, source TEXT, message TEXT)']
        ],
        rowCount: 4,
        executionTimeMs: Math.max(1, Math.round(performance.now() - startTime)),
        tableName: 'sqlite_master'
      };
    }

    // Fallback notice
    return {
      columns: ['status', 'message'],
      rows: [['SUCCESS', `Query parsed. Try: "SELECT * FROM access_points WHERE score < 50;", "SELECT * FROM captured_handshakes;", or "SELECT * FROM projects;"`]],
      rowCount: 1,
      executionTimeMs: Math.max(1, Math.round(performance.now() - startTime))
    };
  }

  // Export full SQL dump string
  public exportSqlDump(aps: AccessPoint[]): string {
    const projects = this.getProjects();
    const handshakes = this.getSavedHandshakes();
    const logs = this.getLogs();

    let sql = `-- ====================================================================\n`;
    sql += `-- WinWiFi Security Auditor - Relational SQLite 3 Database Dump\n`;
    sql += `-- Standards Reference: NIST SP 800-153 WLAN Security\n`;
    sql += `-- Generated: ${new Date().toISOString()}\n`;
    sql += `-- ====================================================================\n\n`;
    sql += `PRAGMA foreign_keys = ON;\n\n`;

    // Projects DDL & DML
    sql += `-- Table: projects\n`;
    sql += `CREATE TABLE IF NOT EXISTS projects (\n  id TEXT PRIMARY KEY,\n  name TEXT NOT NULL,\n  location TEXT,\n  auditor TEXT,\n  created_at TEXT,\n  updated_at TEXT\n);\n\n`;
    projects.forEach(p => {
      const safeName = p.name.replace(/'/g, "''");
      const safeLoc = p.location.replace(/'/g, "''");
      const safeAud = p.auditorName.replace(/'/g, "''");
      sql += `INSERT OR REPLACE INTO projects VALUES ('${p.id}', '${safeName}', '${safeLoc}', '${safeAud}', '${p.createdAt}', '${p.updatedAt}');\n`;
    });
    sql += `\n`;

    // Access Points DDL & DML
    sql += `-- Table: access_points\n`;
    sql += `CREATE TABLE IF NOT EXISTS access_points (\n  bssid TEXT PRIMARY KEY,\n  ssid TEXT NOT NULL,\n  channel INTEGER,\n  frequency_band TEXT,\n  security TEXT,\n  cipher TEXT,\n  rssi INTEGER,\n  wps_enabled INTEGER,\n  pmf_required INTEGER,\n  security_score INTEGER,\n  first_seen TEXT\n);\n\n`;
    aps.forEach(ap => {
      const safeSsid = (ap.ssid || '<Hidden>').replace(/'/g, "''");
      sql += `INSERT OR REPLACE INTO access_points VALUES ('${ap.bssid}', '${safeSsid}', ${ap.channel}, '${ap.band}', '${ap.security}', '${ap.cipher}', ${ap.rssi}, ${ap.wpsEnabled ? 1 : 0}, ${ap.pmfRequired ? 1 : 0}, ${ap.securityScore}, '${ap.firstSeen}');\n`;
    });
    sql += `\n`;

    // Captured Handshakes DDL & DML
    sql += `-- Table: captured_handshakes\n`;
    sql += `CREATE TABLE IF NOT EXISTS captured_handshakes (\n  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  ap_bssid TEXT,\n  client_mac TEXT,\n  ssid TEXT,\n  type TEXT,\n  anonce TEXT,\n  snonce TEXT,\n  mic_hex TEXT,\n  mic_verified INTEGER,\n  captured_at TEXT\n);\n\n`;
    handshakes.forEach(h => {
      const safeSsid = h.ssid.replace(/'/g, "''");
      sql += `INSERT INTO captured_handshakes (ap_bssid, client_mac, ssid, type, anonce, snonce, mic_hex, mic_verified, captured_at) VALUES ('${h.apBssid}', '${h.clientMac}', '${safeSsid}', '${h.type}', '${h.anonce}', '${h.snonce}', '${h.micHex}', ${h.micVerified ? 1 : 0}, '${h.capturedAt}');\n`;
    });
    sql += `\n`;

    // Audit Logs DDL & DML
    sql += `-- Table: audit_logs\n`;
    sql += `CREATE TABLE IF NOT EXISTS audit_logs (\n  id TEXT PRIMARY KEY,\n  timestamp TEXT,\n  level TEXT,\n  source TEXT,\n  message TEXT\n);\n\n`;
    logs.slice(0, 100).forEach(l => {
      const safeMsg = l.message.replace(/'/g, "''");
      sql += `INSERT OR REPLACE INTO audit_logs VALUES ('${l.id}', '${l.timestamp}', '${l.level}', '${l.source}', '${safeMsg}');\n`;
    });

    return sql;
  }
}

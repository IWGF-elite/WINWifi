import { AccessPoint, AnalystClassification, AuditProject, AuditLog, EvidenceItem, HandshakeInfo, IncidentRecord, EnterpriseAssetRecord, MaintenanceApprovalRecord, SiteRecord } from '../types';
import { normalizeSiteDirectory } from './siteDirectory';
import { normalizeMaintenanceApprovals } from './maintenanceApproval';
import { AuditChainState, MAX_AUDIT_RECORDS, normalizeAuditChain } from './auditChain';
import { AlertRecord, MAX_ALERTS, normalizeAlerts } from './alerts';

const DB_PREFIX = 'winwifi_sqlite_';

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
    const key = this.scopedKey('incidents', projectId);
    let preservedLegacy: IncidentRecord[] = [];
    try {
      const existing = localStorage.getItem(key);
      const records = existing ? JSON.parse(existing) as IncidentRecord[] : [];
      if (Array.isArray(records)) preservedLegacy = records.filter(incident => incident?.id?.startsWith('NATIVE-AP-'));
    } catch {
      // Keep the incoming save usable when a legacy payload is malformed.
    }
    const incomingIds = new Set(incidents.map(incident => incident.id));
    // Old auto-generated per-AP cases are hidden from the current incident
    // view, but preserve them in storage until the operator approves cleanup.
    this.writeScoped('incidents', projectId, [
      ...incidents,
      ...preservedLegacy.filter(incident => !incomingIds.has(incident.id))
    ]);
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
      occurredAt: new Date().toISOString(),
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
}

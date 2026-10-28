import { NativeBridgeClient } from './bridgeClient';

export interface NativeTableDescriptor {
  key: string;
  label: string;
  load: (client: NativeBridgeClient) => Promise<unknown[]>;
}

// Each entry maps to one table in the single native SQLite database and is
// served by an existing read-only bridge endpoint. Nothing here executes SQL.
export const NATIVE_TABLES: NativeTableDescriptor[] = [
  { key: 'projects', label: 'projects', load: client => client.getProjects() },
  { key: 'access_points', label: 'access_points', load: client => client.getProjectAccessPoints() },
  { key: 'enterprise_assets', label: 'enterprise_assets', load: client => client.getEnterpriseAssets() },
  { key: 'incidents', label: 'incidents', load: client => client.getIncidents() },
  { key: 'security_changes', label: 'configuration_drift', load: client => client.getDrifts() },
  { key: 'station_clients', label: 'station_clients', load: client => client.getClients() },
  { key: 'scan_observations', label: 'scan_observations', load: async client => (await client.getObservations()).records }
];

export const MAX_VIEW_ROWS = 200;

export interface NativeTableView {
  columns: string[];
  rows: string[][];
  rowCount: number;
  truncated: boolean;
}

const formatCell = (value: unknown): string => {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (Array.isArray(value) || typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

export const toNativeTableView = (records: unknown[], limit = MAX_VIEW_ROWS): NativeTableView => {
  const objects = records.filter(
    (record): record is Record<string, unknown> =>
      Boolean(record) && typeof record === 'object' && !Array.isArray(record)
  );

  const columns: string[] = [];
  for (const record of objects) {
    for (const key of Object.keys(record)) {
      if (!columns.includes(key)) columns.push(key);
    }
  }

  const visible = objects.slice(0, limit);
  return {
    columns,
    rows: visible.map(record => columns.map(column => formatCell(record[column]))),
    rowCount: objects.length,
    truncated: objects.length > visible.length
  };
};

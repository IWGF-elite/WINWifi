export type OperatorRole = 'Viewer' | 'Auditor' | 'Administrator';

export type OperatorCapability =
  | 'view'
  | 'export_report'
  | 'import_assets'
  | 'edit_assets'
  | 'delete_assets'
  | 'manage_sites'
  | 'request_maintenance'
  | 'approve_maintenance'
  | 'connect_network'
  | 'manage_projects'
  | 'clear_logs'
  | 'manage_roles';

const VIEWER: OperatorCapability[] = ['view'];
const AUDITOR: OperatorCapability[] = [
  ...VIEWER,
  'export_report',
  'import_assets',
  'edit_assets',
  'manage_sites',
  'request_maintenance',
  'connect_network'
];
const ADMINISTRATOR: OperatorCapability[] = [
  ...AUDITOR,
  'delete_assets',
  'approve_maintenance',
  'manage_projects',
  'clear_logs',
  'manage_roles'
];

export const OPERATOR_ROLES: OperatorRole[] = ['Viewer', 'Auditor', 'Administrator'];

export const ROLE_CAPABILITIES: Record<OperatorRole, OperatorCapability[]> = {
  Viewer: VIEWER,
  Auditor: AUDITOR,
  Administrator: ADMINISTRATOR
};

export const ROLE_DESCRIPTIONS: Record<OperatorRole, string> = {
  Viewer: 'Read-only: inspect networks, policies, sites, and evidence in this project.',
  Auditor: 'Analysis plus capture import, asset metadata edits, site edits, maintenance requests, and authorized connect attempts.',
  Administrator: 'Everything an Auditor can do, plus asset/project deletion, maintenance decisions, log clearing, and role changes.'
};

// This is a desktop-local guardrail, not authentication. It stops accidental
// destructive clicks; anyone with access to this profile can change the role.
export function normalizeOperatorRole(value: unknown): OperatorRole {
  return OPERATOR_ROLES.includes(value as OperatorRole) ? value as OperatorRole : 'Administrator';
}

export function can(role: OperatorRole, capability: OperatorCapability): boolean {
  return ROLE_CAPABILITIES[role]?.includes(capability) ?? false;
}

export function requireCapability(role: OperatorRole, capability: OperatorCapability, actionLabel: string): void {
  if (!can(role, capability)) {
    throw new Error(`${actionLabel} is not allowed by the current local role (${role}). Switch to a role that includes this capability in Settings.`);
  }
}

export function sanitizeOperatorName(value: unknown): string {
  const name = String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
  return name || 'Local operator';
}

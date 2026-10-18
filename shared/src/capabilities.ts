// =============================================================================
// Capabilities — the one vocabulary of the permission model
// =============================================================================
//
// Two stores, one list each:
//   - tenant capabilities: WHAT a member may do in a tenant. The member's
//     tenant role (user_tenants.role) is a permission set slug, and the set's
//     capabilities (permission_sets.capabilities) are checked by the server's
//     requireTenantCapability. A tenant administrator holds them all.
//   - device capabilities: held per team permission row (team_permissions: a
//     group, a device or the ungrouped devices), on the devices the row
//     covers (the server's permissionService.canUseCapability).
//
// A stored list may hold values outside this vocabulary (features removed
// since, older installs): readers keep only the known ones, so such a value
// is never an error and never grants anything. A removed key is never reused
// for a new capability, as stored lists may still carry it.

/** Tenant capabilities, in the order of the permission set matrix. */
export const TENANT_CAPABILITIES = [
  'supervision:read',
  'agent_config:keys',
  'agent_config:approval',
  'devices.manage',
  'groups.manage',
  'reports',
  'settings',
  'users.manage',
  // Read the tenant's audit log (audit-durci §9.1): the admin set shows it, the
  // client sets approver and auditor (the DPO) hold it.
  'audit.read',
  // Review the approval requests of the tenant (audit-durci §10.4, lot A7).
  'approvals.review',
  // Write the policies and their assignments (modele-donnees-mdm §10.7, lot B5b); reading them needs none.
  'mdm.policies.manage',
  // Manage the enrollment profiles, links, invitations and sessions (integration-apple-edge §10.9, lot C1).
  'mdm.enrollment.manage',
  // Connect and renew the Apple integrations: push certificate, ADE servers, deadlines (integration-apple-edge §11.6,
  // lot C3); reading them needs 'settings' or this one.
  'mdm.integrations.manage',
] as const;

export type TenantCapability = typeof TENANT_CAPABILITIES[number];

/** English labels of the permission set matrix (the client translates them). */
export const TENANT_CAPABILITY_LABELS: Record<TenantCapability, string> = {
  'supervision:read':      'Supervision · Reports',
  'agent_config:keys':     'Agent config · API keys',
  'agent_config:approval': 'Agent config · Approve / refuse agents',
  'devices.manage':        'Device Management',
  'groups.manage':         'Group Management',
  'reports':               'Reports',
  'settings':              'Settings',
  'users.manage':          'User Management',
  'audit.read':            "Audit · Read the tenant's log",
  'approvals.review':      'Approvals · Review requests',
  'mdm.policies.manage':   'Policies · Edit, assign and publish',
  'mdm.enrollment.manage': 'Enrollment · Profiles, links and invitations',
  'mdm.integrations.manage': 'Apple integrations · Push certificate, ADE servers',
};

/** Device capabilities. 'monitor' is the baseline every team permission row
 *  holds (the row's RO / RW level decides read or write access; it covers the
 *  record, the command queue and the timeline of a device). The MDM actions
 *  (integration-apple-edge §8.11) each need their own, on a row with write
 *  access: none is part of the defaults, so a team gets no MDM action
 *  without a decision of an administrator. */
export const DEVICE_CAPABILITIES = [
  'monitor',
  'mdm:inventory',
  'mdm:profiles',
  'mdm:apps',
  'mdm:restart',
  'mdm:lock',
  'mdm:lost_mode',
  'mdm:passcode',
  'mdm:wipe',
  'mdm:remove',
] as const;

export type DeviceCapability = typeof DEVICE_CAPABILITIES[number];

/** English labels of the team permission editor (the client translates them: capabilities.device.<key>). */
export const DEVICE_CAPABILITY_LABELS: Record<DeviceCapability, string> = {
  'monitor':       'Monitor',
  'mdm:inventory': 'MDM · Refresh the inventory',
  'mdm:profiles':  'MDM · Profiles and settings',
  'mdm:apps':      'MDM · Install and remove apps',
  'mdm:restart':   'MDM · Restart and shut down',
  'mdm:lock':      'MDM · Lock',
  'mdm:lost_mode': 'MDM · Lost mode',
  'mdm:passcode':  'MDM · Clear the passcode',
  'mdm:wipe':      'MDM · Erase',
  'mdm:remove':    'MDM · Remove from management',
};

/** Capabilities of a new team permission row, and of a row stored without any. */
export const DEFAULT_DEVICE_CAPABILITIES: readonly DeviceCapability[] = ['monitor'];

const TENANT_CAPABILITY_SET: ReadonlySet<string> = new Set<string>(TENANT_CAPABILITIES);
const DEVICE_CAPABILITY_SET: ReadonlySet<string> = new Set<string>(DEVICE_CAPABILITIES);

export function isTenantCapability(value: unknown): value is TenantCapability {
  return typeof value === 'string' && TENANT_CAPABILITY_SET.has(value);
}

export function isDeviceCapability(value: unknown): value is DeviceCapability {
  return typeof value === 'string' && DEVICE_CAPABILITY_SET.has(value);
}

/** A stored capability list (a jsonb array, or its JSON text) as an array;
 *  anything else, unreadable JSON included, is an empty list. */
function storedList(stored: unknown): unknown[] {
  let value = stored;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return []; }
  }
  return Array.isArray(value) ? value : [];
}

/** The tenant capabilities of a stored list, in order, without duplicates:
 *  any other value is dropped. */
export function knownTenantCapabilities(stored: unknown): TenantCapability[] {
  return [...new Set(storedList(stored).filter(isTenantCapability))];
}

/** The device capabilities of a stored list, in order, without duplicates:
 *  any other value is dropped. */
export function knownDeviceCapabilities(stored: unknown): DeviceCapability[] {
  return [...new Set(storedList(stored).filter(isDeviceCapability))];
}

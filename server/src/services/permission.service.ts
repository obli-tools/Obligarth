import { db } from '../db';
import type { DeviceCapability, PermissionLevel, TenantCapability, UserPermissions } from '@obligarth/shared';
import { knownDeviceCapabilities, knownTenantCapabilities, TENANT_CAPABILITIES } from '@obligarth/shared';
import { normaliseTenantRole } from './userScope.service';

export const permissionService = {
  /**
   * Get all team IDs a user belongs to.
   */
  async getUserTeamIds(userId: number): Promise<number[]> {
    const rows = await db('team_memberships')
      .where({ user_id: userId })
      .select('team_id');
    return rows.map((r) => r.team_id);
  },

  /**
   * Check if user (via any of their teams) has canCreate permission. With
   * `tenantId`, only the teams of that tenant count (teams are mono-tenant:
   * a team of another tenant grants nothing here).
   */
  async canCreate(userId: number, isAdmin: boolean, tenantId?: number): Promise<boolean> {
    if (isAdmin) return true;
    const q = db('user_teams')
      .join('team_memberships', 'user_teams.id', 'team_memberships.team_id')
      .where('team_memberships.user_id', userId)
      .where('user_teams.can_create', true);
    if (tenantId !== undefined) q.where('user_teams.tenant_id', Number.isInteger(tenantId) ? tenantId : -1);
    const row = await q.first('user_teams.id');
    return !!row;
  },

  /**
   * Get the effective permission level for a user on a specific device.
   * Returns 'rw', 'ro', or null (no access).
   *
   * Resolution order (highest level wins):
   *  - Direct device permission (scope='device', scope_id=deviceId)
   *  - Group permission via closure table on devices.group_id
   *  - **Ungrouped scope**: when devices.group_id IS NULL, a
   *    team_permissions row with scope='ungrouped' of a team of the
   *    device's tenant grants access.
   * A device receives its group at enrollment (its enrollment profile:
   * modele-donnees-mdm §4.5); the claim of the removed agent's API keys
   * is gone with them.
   */
  async getDevicePermission(
    userId: number,
    deviceId: number,
    isAdmin: boolean,
  ): Promise<PermissionLevel | null> {
    if (isAdmin) return 'rw';

    const deviceRow = await db('devices')
      .where({ id: deviceId })
      .select('group_id', 'tenant_id')
      .first();
    if (!deviceRow) return null;

    // Direct device permission
    const directLevel = await this._getHighestPermission(userId, 'device', deviceId);

    let groupLevel: PermissionLevel | null = null;
    if (deviceRow.group_id) {
      // Group permission (inherited via closure table)
      groupLevel = await this._getGroupPermissionViaClosure(userId, deviceRow.group_id);
    } else {
      // SECURITY: only an 'ungrouped' grant of a team of the DEVICE's
      // tenant (teams are mono-tenant) — the same rule as
      // getVisibleDeviceIds. Without it, a user with an 'ungrouped' grant
      // in tenant A passed the single-device check on the ungrouped
      // devices of every other tenant they could name.
      groupLevel = await this._getHighestPermission(userId, 'ungrouped', 0, Number(deviceRow.tenant_id));
    }

    // Return highest: rw > ro > null
    return this._highest(directLevel, groupLevel);
  },

  /**
   * Check if user can read a device.
   */
  async canReadDevice(userId: number, deviceId: number, isAdmin: boolean): Promise<boolean> {
    const perm = await this.getDevicePermission(userId, deviceId, isAdmin);
    return perm !== null;
  },

  /**
   * Check if user can write (edit/delete) a device.
   */
  async canWriteDevice(userId: number, deviceId: number, isAdmin: boolean): Promise<boolean> {
    const perm = await this.getDevicePermission(userId, deviceId, isAdmin);
    return perm === 'rw';
  },

  /**
   * Tenant-wide capability check — resolves the user's per-tenant role
   * (`user_tenants.role`, now a permission_set slug) and looks up the
   * matching `permission_sets.capabilities`. Tenant admins bypass the
   * check entirely. Tenant role drives WHAT the user can do; team
   * membership (handled by canUseCapability) drives WHERE they can
   * do it. Stored values outside the shared vocabulary never match.
   * The pre-091 role 'member' is the 'user' set (normaliseTenantRole, as
   * for the user-management scope).
   */
  async userHasTenantCapability(userId: number, tenantId: number, capability: TenantCapability): Promise<boolean> {
    const ut = await db('user_tenants')
      .where({ user_id: userId, tenant_id: tenantId })
      .first() as { role: string } | undefined;
    if (!ut) return false;
    const role = normaliseTenantRole(ut.role);
    if (role === 'admin') return true;
    const set = await db('permission_sets').where({ slug: role }).first() as { capabilities: unknown } | undefined;
    if (!set) return false;
    return knownTenantCapabilities(set.capabilities).includes(capability);
  },

  /**
   * Bulk variant — returns every capability granted to the user on a
   * given tenant via their permission_set. Used by /auth/me so the
   * client can render gates without round-trips. A tenant administrator
   * gets the whole vocabulary: userHasTenantCapability above grants them
   * every capability by their role, and what is announced must be what is
   * enforced (a capability held by no stored set, like mdm.policies.manage,
   * was missing from the union of the sets: modele-donnees-mdm, lot B6).
   * Only the shared vocabulary's capabilities are returned.
   */
  async listUserTenantCapabilities(userId: number, tenantId: number): Promise<TenantCapability[]> {
    const ut = await db('user_tenants')
      .where({ user_id: userId, tenant_id: tenantId })
      .first() as { role: string } | undefined;
    if (!ut) return [];
    const role = normaliseTenantRole(ut.role);
    if (role === 'admin') return [...TENANT_CAPABILITIES];
    const set = await db('permission_sets').where({ slug: role }).first() as { capabilities: unknown } | undefined;
    if (!set) return [];
    return knownTenantCapabilities(set.capabilities);
  },

  /**
   * Check if user has a specific capability on a device.
   * Admins always have all capabilities.
   * Checks both direct device permissions and inherited group permissions.
   * Stored values outside the shared vocabulary never match.
   */
  async canUseCapability(userId: number, deviceId: number, isAdmin: boolean, capability: DeviceCapability): Promise<boolean> {
    if (isAdmin) return true;

    const deviceRow = await db('devices').where({ id: deviceId }).select('group_id').first();
    if (!deviceRow) return false;

    // Check direct device permissions
    const directPerms = await db('team_permissions as tp')
      .join('team_memberships as tm', 'tm.team_id', 'tp.team_id')
      .where({ 'tm.user_id': userId, 'tp.scope': 'device', 'tp.scope_id': deviceId })
      .select('tp.capabilities');

    for (const row of directPerms) {
      if (knownDeviceCapabilities(row.capabilities).includes(capability)) return true;
    }

    // Check group permissions (via closure table)
    if (deviceRow.group_id) {
      const groupPerms = await db('team_permissions as tp')
        .join('team_memberships as tm', 'tm.team_id', 'tp.team_id')
        .join('device_group_closure as dgc', 'dgc.ancestor_id', 'tp.scope_id')
        .where({ 'tm.user_id': userId, 'tp.scope': 'group', 'dgc.descendant_id': deviceRow.group_id })
        .select('tp.capabilities');

      for (const row of groupPerms) {
        if (knownDeviceCapabilities(row.capabilities).includes(capability)) return true;
      }
    }

    return false;
  },

  /**
   * Batch form of canUseCapability (same rules: a direct device-scope grant,
   * or a group-scope grant on the device's group or one of its ancestors,
   * whose capabilities include `capability`). Returns the ids — in input
   * order, deduplicated — the user may NOT use the capability on (unknown
   * devices included). Callers handle the admin bypass themselves, exactly
   * as with canUseCapability(…, isAdmin=false, …). A constant number of
   * queries per chunk instead of 1-3 per device, so a fleet-wide target
   * set stays cheap.
   */
  async devicesLackingCapability(userId: number, deviceIds: number[], capability: DeviceCapability): Promise<number[]> {
    const ids = [...new Set(deviceIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
    if (ids.length === 0) return [];
    const hasCap = (raw: unknown): boolean => knownDeviceCapabilities(raw).includes(capability);
    const granted = new Set<number>();
    const CHUNK = 5000;
    for (let i = 0; i < ids.length; i += CHUNK) {
      const chunk = ids.slice(i, i + CHUNK);
      const devices = await db('devices').whereIn('id', chunk).select('id', 'group_id') as Array<{ id: number; group_id: number | null }>;

      const direct = await db('team_permissions as tp')
        .join('team_memberships as tm', 'tm.team_id', 'tp.team_id')
        .where({ 'tm.user_id': userId, 'tp.scope': 'device' })
        .whereIn('tp.scope_id', chunk)
        .select('tp.scope_id', 'tp.capabilities') as Array<{ scope_id: number; capabilities: unknown }>;
      for (const row of direct) if (hasCap(row.capabilities)) granted.add(Number(row.scope_id));

      const groupIds = [...new Set(devices.map((d) => d.group_id).filter((g): g is number => g != null))];
      const grantedGroups = new Set<number>();
      if (groupIds.length) {
        const groupRows = await db('team_permissions as tp')
          .join('team_memberships as tm', 'tm.team_id', 'tp.team_id')
          .join('device_group_closure as dgc', 'dgc.ancestor_id', 'tp.scope_id')
          .where({ 'tm.user_id': userId, 'tp.scope': 'group' })
          .whereIn('dgc.descendant_id', groupIds)
          .select('dgc.descendant_id', 'tp.capabilities') as Array<{ descendant_id: number; capabilities: unknown }>;
        for (const row of groupRows) if (hasCap(row.capabilities)) grantedGroups.add(Number(row.descendant_id));
      }
      for (const d of devices) {
        if (d.group_id != null && grantedGroups.has(Number(d.group_id))) granted.add(Number(d.id));
      }
      // A device granted directly but deleted since is still "lacking".
      const existing = new Set(devices.map((d) => Number(d.id)));
      for (const id of chunk) if (!existing.has(id)) granted.delete(id);
    }
    return ids.filter((id) => !granted.has(id));
  },

  /**
   * Does the user hold `capability` on at least one team permission row with write access, through a team of
   * `tenantId` (the scopes offered to an MCP access key, and what its `whoami` reports)? A capability of the
   * device actions is only ever used on a row with write access, so a read-only row never counts. Callers handle
   * the platform administrator bypass themselves. Stored values outside the shared vocabulary never match.
   */
  async userHoldsDeviceCapabilityAnywhere(userId: number, tenantId: number, capability: DeviceCapability): Promise<boolean> {
    const rows = await db('team_permissions as tp')
      .join('team_memberships as tm', 'tm.team_id', 'tp.team_id')
      .join('user_teams as ut', 'ut.id', 'tp.team_id')
      .where('tm.user_id', userId)
      .where('ut.tenant_id', Number.isInteger(tenantId) ? tenantId : -1)
      .where('tp.level', 'rw')
      .select('tp.capabilities') as Array<{ capabilities: unknown }>;
    return rows.some((r) => knownDeviceCapabilities(r.capabilities).includes(capability));
  },

  /**
   * Get effective permission for a user on a group.
   * Checks direct group permissions + ancestor permissions via closure table.
   */
  async getGroupPermission(
    userId: number,
    groupId: number,
    isAdmin: boolean,
  ): Promise<PermissionLevel | null> {
    if (isAdmin) return 'rw';
    return this._getGroupPermissionViaClosure(userId, groupId);
  },

  async canReadGroup(userId: number, groupId: number, isAdmin: boolean): Promise<boolean> {
    const perm = await this.getGroupPermission(userId, groupId, isAdmin);
    return perm !== null;
  },

  async canWriteGroup(userId: number, groupId: number, isAdmin: boolean): Promise<boolean> {
    const perm = await this.getGroupPermission(userId, groupId, isAdmin);
    return perm === 'rw';
  },

  /**
   * Get all device IDs visible to a user.
   * Returns 'all' for admins.
   */
  async getVisibleDeviceIds(userId: number, isAdmin: boolean): Promise<number[] | 'all'> {
    if (isAdmin) return 'all';

    const teamIds = await this.getUserTeamIds(userId);
    if (teamIds.length === 0) return [];

    // Devices via group permissions (inherited through closure table)
    const groupDevices = await db('devices')
      .join('device_group_closure', 'device_group_closure.descendant_id', 'devices.group_id')
      .join('team_permissions', function () {
        this.on('team_permissions.scope_id', 'device_group_closure.ancestor_id')
          .andOn(db.raw("team_permissions.scope = 'group'"));
      })
      .whereIn('team_permissions.team_id', teamIds)
      .select('devices.id');

    // Devices via direct device permissions
    const directDevices = await db('team_permissions')
      .whereIn('team_id', teamIds)
      .where('scope', 'device')
      .select('scope_id as id');

    // Devices in the catch-all "Ungrouped" bucket — group_id IS NULL —
    // visible to teams that hold an explicit scope='ungrouped' permission. SECURITY: only the
    // ungrouped devices of the tenants of those teams (teams are
    // mono-tenant): without that, a master-tenant caller that drops its
    // tenant filter (god view) got every tenant's ungrouped machines.
    const ungroupedScopeRows = await db('team_permissions as tp')
      .join('user_teams as ut', 'ut.id', 'tp.team_id')
      .whereIn('tp.team_id', teamIds)
      .where('tp.scope', 'ungrouped')
      .select('ut.tenant_id') as Array<{ tenant_id: number }>;
    const ungroupedTenants = [...new Set(ungroupedScopeRows.map((r) => r.tenant_id))];
    let ungroupedDevices: Array<{ id: number }> = [];
    if (ungroupedTenants.length > 0) {
      ungroupedDevices = await db('devices')
        .whereNull('group_id')
        .whereIn('tenant_id', ungroupedTenants)
        .select('id');
    }

    const ids = new Set<number>();
    for (const r of groupDevices) ids.add(r.id);
    for (const r of directDevices) ids.add(r.id);
    for (const r of ungroupedDevices) ids.add(r.id);

    return [...ids];
  },

  /**
   * Get all group IDs visible to a user.
   * A group is visible if the user has any permission on it, any ancestor has permission,
   * or any device inside it has a direct permission.
   * Returns 'all' for admins.
   */
  async getVisibleGroupIds(userId: number, isAdmin: boolean): Promise<number[] | 'all'> {
    if (isAdmin) return 'all';

    const teamIds = await this.getUserTeamIds(userId);
    if (teamIds.length === 0) return [];

    // Groups with direct or ancestor group permissions → includes descendants
    const groupPerms = await db('team_permissions')
      .whereIn('team_id', teamIds)
      .where('scope', 'group')
      .select('scope_id');
    const permGroupIds = groupPerms.map((r) => r.scope_id);

    // All descendants of those groups
    let descendantIds: number[] = [];
    if (permGroupIds.length > 0) {
      const descRows = await db('device_group_closure')
        .whereIn('ancestor_id', permGroupIds)
        .select('descendant_id');
      descendantIds = descRows.map((r) => r.descendant_id);
    }

    // Groups that contain devices with direct device permissions
    const devicePerms = await db('team_permissions')
      .whereIn('team_id', teamIds)
      .where('scope', 'device')
      .select('scope_id');
    const deviceIds = devicePerms.map((r) => r.scope_id);

    let deviceGroupIds: number[] = [];
    if (deviceIds.length > 0) {
      const dgRows = await db('devices')
        .whereIn('id', deviceIds)
        .whereNotNull('group_id')
        .select('group_id');
      deviceGroupIds = dgRows.map((r) => r.group_id);
    }

    // Ancestor groups of deviceGroupIds (for tree navigation)
    let ancestorIds: number[] = [];
    if (deviceGroupIds.length > 0) {
      const ancRows = await db('device_group_closure')
        .whereIn('descendant_id', deviceGroupIds)
        .select('ancestor_id');
      ancestorIds = ancRows.map((r) => r.ancestor_id);
    }

    // Also ancestor groups of permGroupIds (for tree navigation)
    if (permGroupIds.length > 0) {
      const ancRows = await db('device_group_closure')
        .whereIn('descendant_id', permGroupIds)
        .select('ancestor_id');
      ancestorIds = [...ancestorIds, ...ancRows.map((r) => r.ancestor_id)];
    }

    const ids = new Set<number>();
    for (const id of descendantIds) ids.add(id);
    for (const id of deviceGroupIds) ids.add(id);
    for (const id of ancestorIds) ids.add(id);

    return [...ids];
  },

  /**
   * Build the full UserPermissions object for the current user.
   * Sent to the client on login/session check so the UI can adapt.
   */
  async getUserPermissions(userId: number, isAdmin: boolean, tenantId?: number): Promise<UserPermissions> {
    if (isAdmin) {
      return { canCreate: true, teams: [], permissions: {}, tenantCapabilities: [] };
    }

    const teamIds = await this.getUserTeamIds(userId);
    // Only the teams of the active tenant open the "create" gates there.
    const canCreate = await this.canCreate(userId, false, tenantId);

    const perms = await db('team_permissions')
      .whereIn('team_id', teamIds)
      .select('scope', 'scope_id', 'level');

    const permissions: Record<string, PermissionLevel> = {};
    for (const p of perms) {
      const key = `${p.scope}:${p.scope_id}`;
      const existing = permissions[key];
      if (!existing || (existing === 'ro' && p.level === 'rw')) {
        permissions[key] = p.level;
      }
    }

    // tenantCapabilities now resolves via permission_sets (slug = the
    // user's user_tenants.role). Requires a tenant context; callers
    // hitting /auth/me / /auth/login pass the active tenant id. Empty
    // when no tenant has been resolved yet (very early session repair
    // path).
    const tenantCapabilities = tenantId != null
      ? await this.listUserTenantCapabilities(userId, tenantId)
      : [];

    return { canCreate, teams: teamIds, permissions, tenantCapabilities };
  },

  /**
   * Get user IDs that have at least read access to a specific device.
   * Used for Socket.io broadcasts.
   */
  async getUsersWithDeviceAccess(deviceId: number): Promise<number[]> {
    const deviceRow = await db('devices').where({ id: deviceId }).select('group_id').first();
    if (!deviceRow) return [];

    // Users via direct device permission
    const directUsers = await db('team_memberships')
      .join('team_permissions', 'team_memberships.team_id', 'team_permissions.team_id')
      .where('team_permissions.scope', 'device')
      .where('team_permissions.scope_id', deviceId)
      .select('team_memberships.user_id');

    const userIds = new Set<number>(directUsers.map((r) => r.user_id));

    // Users via group permission (inherited)
    if (deviceRow.group_id) {
      const groupUsers = await db('team_memberships')
        .join('team_permissions', 'team_memberships.team_id', 'team_permissions.team_id')
        .join('device_group_closure', 'device_group_closure.ancestor_id', 'team_permissions.scope_id')
        .where('team_permissions.scope', 'group')
        .where('device_group_closure.descendant_id', deviceRow.group_id)
        .select('team_memberships.user_id');
      for (const r of groupUsers) userIds.add(r.user_id);
    }

    return [...userIds];
  },

  // ── Private helpers ──

  /**
   * Get the highest permission level from all teams for a specific scope+scopeId.
   */
  async _getHighestPermission(
    userId: number,
    scope: string,
    scopeId: number,
    /** Only the grants of teams of this tenant (the 'ungrouped' scope). */
    teamTenantId?: number,
  ): Promise<PermissionLevel | null> {
    const q = db('team_permissions')
      .join('team_memberships', 'team_permissions.team_id', 'team_memberships.team_id')
      .where('team_memberships.user_id', userId)
      .where('team_permissions.scope', scope)
      .where('team_permissions.scope_id', scopeId);
    if (teamTenantId !== undefined) {
      q.join('user_teams', 'user_teams.id', 'team_permissions.team_id')
        .where('user_teams.tenant_id', Number.isInteger(teamTenantId) ? teamTenantId : -1);
    }
    const rows = await q.select('team_permissions.level');

    if (rows.length === 0) return null;
    return rows.some((r) => r.level === 'rw') ? 'rw' : 'ro';
  },

  /**
   * Get the highest group permission for a user on a group,
   * checking all ancestors via closure table.
   */
  async _getGroupPermissionViaClosure(
    userId: number,
    groupId: number,
  ): Promise<PermissionLevel | null> {
    const rows = await db('team_permissions')
      .join('team_memberships', 'team_permissions.team_id', 'team_memberships.team_id')
      .join('device_group_closure', 'device_group_closure.ancestor_id', 'team_permissions.scope_id')
      .where('team_memberships.user_id', userId)
      .where('team_permissions.scope', 'group')
      .where('device_group_closure.descendant_id', groupId)
      .select('team_permissions.level');

    if (rows.length === 0) return null;
    return rows.some((r) => r.level === 'rw') ? 'rw' : 'ro';
  },

  _highest(a: PermissionLevel | null, b: PermissionLevel | null): PermissionLevel | null {
    if (a === 'rw' || b === 'rw') return 'rw';
    if (a === 'ro' || b === 'ro') return 'ro';
    return null;
  },
};

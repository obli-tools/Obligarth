import type { Knex } from 'knex';
import { db } from '../db';
import type { UserTeam, TeamPermission, DeviceCapability } from '@obligarth/shared';
import { DEFAULT_DEVICE_CAPABILITIES, knownDeviceCapabilities } from '@obligarth/shared';
import { AppError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';

interface TeamRow {
  id: number;
  uuid: string;
  name: string;
  description: string | null;
  can_create: boolean;
  tenant_id: number;
  tenant_name?: string; // populated by JOIN when fetching all tenants
  created_at: Date;
  updated_at: Date;
}

interface PermissionRow {
  id: number;
  team_id: number;
  tenant_id: number;
  scope: 'group' | 'device' | 'ungrouped';
  scope_id: number;
  level: 'ro' | 'rw';
}

function rowToTeam(row: TeamRow): UserTeam {
  return {
    id: row.id,
    uuid: row.uuid,
    name: row.name,
    canCreate: row.can_create,
    tenantId: row.tenant_id,
    // Always exposed when the row was joined with `tenants` (the
    // god-view query does this). The /admin/users page renders it
    // both in the team-list rows and in the create-team selector
    // so admins see "ACME" / "CONTOSO" instead of "Tenant 2".
    tenantName: row.tenant_name ?? undefined,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

// Rows may hold values outside the shared device capabilities (removed
// capabilities, older installs): they are dropped on read, so the team
// editor's GET → edit → PUT round trip never sends them back. A row stored
// without capabilities holds the defaults.
function rowToPermission(row: any): TeamPermission {
  const caps = row.capabilities
    ? knownDeviceCapabilities(row.capabilities)
    : [...DEFAULT_DEVICE_CAPABILITIES];
  return {
    id: row.id,
    tenantId: row.tenant_id,
    teamId: row.team_id,
    scope: row.scope,
    scopeId: row.scope_id,
    level: row.level,
    capabilities: caps,
  };
}

type TeamScope = 'group' | 'device' | 'ungrouped';

/**
 * Teams are mono-tenant: a team's scopes name groups and devices of the
 * team's own tenant only, whoever edits it (a platform admin on the master
 * tenant edits the teams of every tenant). Refuses (400) a group or a device
 * of another tenant (or that does not exist), an 'ungrouped' scope whose id
 * is not 0 (its convention), and the same scope twice.
 */
async function assertScopesInTenant(
  tenantId: number,
  permissions: ReadonlyArray<{ scope: TeamScope; scopeId: number }>,
  conn: Knex = db,
): Promise<void> {
  const seen = new Set<string>();
  const ids: Record<'group' | 'device', Set<number>> = { group: new Set(), device: new Set() };
  for (const p of permissions) {
    const key = `${p.scope}:${p.scopeId}`;
    if (seen.has(key)) throw new AppError(400, `Duplicate scope: ${key}`);
    seen.add(key);
    if (p.scope === 'ungrouped') {
      if (p.scopeId !== 0) throw new AppError(400, "The 'ungrouped' scope has the id 0");
    } else if (p.scope === 'group' || p.scope === 'device') {
      ids[p.scope].add(Number(p.scopeId));
    } else {
      throw new AppError(400, `Unknown scope: ${String(p.scope)}`);
    }
  }
  for (const [scope, table] of [['group', 'device_groups'], ['device', 'devices']] as const) {
    const wanted = [...ids[scope]];
    if (wanted.length === 0) continue;
    const found = new Set((await conn(table).whereIn('id', wanted).where({ tenant_id: tenantId }).pluck('id') as number[]).map(Number));
    const outside = wanted.filter((id) => !found.has(id));
    if (outside.length > 0) {
      throw new AppError(400, `${scope === 'group' ? 'Group' : 'Device'} not found in the team's tenant: ${outside.join(', ')}`);
    }
  }
}

async function teamTenantId(teamId: number, conn: Knex = db): Promise<number | null> {
  const row = await conn('user_teams').where({ id: teamId }).first('tenant_id') as { tenant_id: number } | undefined;
  return row ? Number(row.tenant_id) : null;
}

export const teamService = {
  /**
   * Returns teams scoped to a tenant.
   * If tenantId is null (platform admin cross-tenant view), returns ALL teams across
   * all tenants, joined with tenant name.
   */
  async getAll(tenantId: number | null): Promise<UserTeam[]> {
    const query = db('user_teams')
      .join('tenants', 'user_teams.tenant_id', 'tenants.id')
      .select('user_teams.*', 'tenants.name as tenant_name')
      .orderBy('user_teams.name');
    if (tenantId !== null) {
      query.where('user_teams.tenant_id', tenantId);
    }
    const rows = await query;
    return rows.map(rowToTeam);
  },

  /** UNSAFE without tenant scope — callers MUST pair this with a
   *  `team.tenantId === req.tenantId`, or platform admin on the master
   *  tenant, check before exposing the row to the user (see `teamInScope`
   *  in teams.controller.ts for the canonical pattern). The helper is left
   *  tenant-agnostic on purpose because internal jobs (e.g. group cascade)
   *  need cross-tenant access. */
  async getById(id: number): Promise<UserTeam | null> {
    const row = await db<TeamRow>('user_teams').where({ id }).first();
    return row ? rowToTeam(row) : null;
  },

  async create(data: { name: string; description?: string | null; canCreate?: boolean }, tenantId: number): Promise<UserTeam> {
    const [row] = await db<TeamRow>('user_teams')
      .insert({
        name: data.name,
        description: data.description ?? null,
        can_create: data.canCreate ?? false,
        tenant_id: tenantId,
      })
      .returning('*');
    return rowToTeam(row);
  },

  async update(
    id: number,
    data: { name?: string; description?: string | null; canCreate?: boolean },
  ): Promise<UserTeam | null> {
    const updateData: Record<string, unknown> = { updated_at: new Date() };
    if (data.name !== undefined) updateData.name = data.name;
    if (data.description !== undefined) updateData.description = data.description;
    if (data.canCreate !== undefined) updateData.can_create = data.canCreate;

    const [row] = await db<TeamRow>('user_teams')
      .where({ id })
      .update(updateData)
      .returning('*');
    return row ? rowToTeam(row) : null;
  },

  async delete(id: number): Promise<boolean> {
    const count = await db('user_teams').where({ id }).del();
    return count > 0;
  },

  // ── Members ──

  async getMembers(teamId: number): Promise<number[]> {
    const rows = await db('team_memberships')
      .where({ team_id: teamId })
      .select('user_id');
    return rows.map((r) => r.user_id);
  },

  /** Refuses (400) members that do not belong to the tenant `tenantId`: a
   *  removal from a tenant purges the user's teams there, so a team never
   *  grants anything to a non-member of its tenant. */
  async assertMembersInTenant(tenantId: number, userIds: ReadonlyArray<number>): Promise<void> {
    const ids = [...new Set(userIds.map(Number))];
    if (ids.length === 0) return;
    const members = new Set((await db('user_tenants')
      .where({ tenant_id: tenantId })
      .whereIn('user_id', ids)
      .pluck('user_id') as number[]).map(Number));
    const outside = ids.filter((id) => !members.has(id));
    if (outside.length > 0) {
      throw new AppError(400, `Not a member of the team's tenant: user ${outside.join(', ')}`);
    }
  },

  /** Replaces the members of a team: members of the team's tenant only
   *  (assertMembersInTenant). */
  async setMembers(teamId: number, userIds: number[]): Promise<void> {
    const tenantId = await teamTenantId(teamId);
    if (tenantId === null) throw new AppError(404, 'Team not found');
    const ids = [...new Set(userIds.map(Number))];
    await this.assertMembersInTenant(tenantId, ids);
    await db.transaction(async (trx) => {
      await trx('team_memberships').where({ team_id: teamId }).del();
      if (ids.length > 0) {
        await trx('team_memberships').insert(
          ids.map((uid) => ({ team_id: teamId, user_id: uid })),
        );
      }
    });
  },

  /** The user's teams; with `tenantId`, only that tenant's. */
  async getUserTeams(userId: number, tenantId?: number): Promise<UserTeam[]> {
    const q = db<TeamRow>('user_teams')
      .join('team_memberships', 'user_teams.id', 'team_memberships.team_id')
      .where('team_memberships.user_id', userId)
      .select('user_teams.*')
      .orderBy('user_teams.name');
    if (tenantId !== undefined) q.where('user_teams.tenant_id', Number.isInteger(tenantId) ? tenantId : -1);
    const rows = await q;
    return rows.map(rowToTeam);
  },

  // ── Permissions ──

  async getPermissions(teamId: number): Promise<TeamPermission[]> {
    const rows = await db<PermissionRow>('team_permissions')
      .where({ team_id: teamId })
      .orderBy('scope')
      .orderBy('scope_id');
    return rows.map(rowToPermission);
  },

  /** Refuses (400) scopes a team of `tenantId` may not hold (see
   *  assertScopesInTenant): lets a route refuse a request before it waits
   *  for an approval. setPermissions checks them again. */
  async assertScopesInTenant(
    tenantId: number,
    permissions: ReadonlyArray<{ scope: TeamScope; scopeId: number }>,
  ): Promise<void> {
    await assertScopesInTenant(tenantId, permissions);
  },

  /** Replaces the scopes of a team: groups and devices of the team's tenant
   *  only (400 otherwise). */
  async setPermissions(
    teamId: number,
    permissions: Array<{ scope: 'group' | 'device' | 'ungrouped'; scopeId: number; level: 'ro' | 'rw'; capabilities?: DeviceCapability[] }>,
  ): Promise<TeamPermission[]> {
    // Resolve tenant_id from the team
    const tenantId = await teamTenantId(teamId);
    if (tenantId === null) throw new AppError(404, 'Team not found');
    await assertScopesInTenant(tenantId, permissions);

    return db.transaction(async (trx) => {
      await trx('team_permissions').where({ team_id: teamId }).del();
      if (permissions.length > 0) {
        await trx('team_permissions').insert(
          permissions.map((p) => ({
            team_id: teamId,
            tenant_id: tenantId,
            scope: p.scope,
            scope_id: p.scopeId,
            level: p.level,
            capabilities: JSON.stringify(p.capabilities ?? DEFAULT_DEVICE_CAPABILITIES),
          })),
        );
      }
      const rows = await trx<PermissionRow>('team_permissions')
        .where({ team_id: teamId })
        .orderBy('scope')
        .orderBy('scope_id');
      return rows.map(rowToPermission);
    });
  },

  /**
   * Adds one scope to a team, or changes its level (group creation grants
   * the creator's can_create teams the new group). The row is written in
   * the team's tenant (`tenant_id`, NOT NULL). A scope outside that tenant
   * is never written: logged, and null is returned. The ON CONFLICT relies
   * on the unique constraint on (team_id, scope, scope_id). `conn`: a
   * transaction of the caller, if any.
   */
  async addPermission(
    teamId: number,
    scope: 'group' | 'device' | 'ungrouped',
    scopeId: number,
    level: 'ro' | 'rw',
    conn: Knex = db,
  ): Promise<TeamPermission | null> {
    const tenantId = await teamTenantId(teamId, conn);
    if (tenantId === null) return null;
    try {
      await assertScopesInTenant(tenantId, [{ scope, scopeId }], conn);
    } catch (err) {
      if (!(err instanceof AppError)) throw err;
      logger.warn({ teamId, tenantId, scope, scopeId }, `team scope not added: ${err.message}`);
      return null;
    }
    const [row] = await conn<PermissionRow>('team_permissions')
      .insert({ team_id: teamId, tenant_id: tenantId, scope, scope_id: scopeId, level })
      .onConflict(['team_id', 'scope', 'scope_id'])
      .merge({ level })
      .returning('*');
    return rowToPermission(row);
  },

  /** Removes one scope of this team; false when the team has no such scope
   *  (a scope of another team is never touched). */
  async removePermission(teamId: number, permissionId: number): Promise<boolean> {
    const count = await db('team_permissions').where({ id: permissionId, team_id: teamId }).del();
    return count > 0;
  },
};

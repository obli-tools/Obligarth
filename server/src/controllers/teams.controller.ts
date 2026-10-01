import type { Request, Response, NextFunction } from 'express';
import { teamService } from '../services/team.service';
import { AppError } from '../middleware/errorHandler';
import { asTargetTenant, globalViewRead } from '../middleware/dbContext';
import { isMasterTenant } from '@obligarth/shared';
import type { UserTeam } from '@obligarth/shared';
import type {
  CreateTeamInput,
  UpdateTeamInput,
  SetTeamMembersInput,
  SetTeamPermissionsInput,
} from '../validators/team.schema';

/** The god view over teams: a platform admin on the master tenant. */
function teamGodView(req: Request): boolean {
  return req.session.role === 'admin' && isMasterTenant(req.tenantId);
}

/**
 * The team of `/:id`, if the request may act on it: a team of the request's
 * tenant, or any team in the god view. Every `/:id` route goes through it —
 * `teamService.getById` is tenant-agnostic — BEFORE any restriction envelope
 * (no approval is ever filed for another tenant's team). Anything else
 * answers like an unknown team (404: a sibling tenant's team's existence is
 * not leaked). Database context (rls-tenant §6.3): read across tenants in the
 * god view (context 'platform'); the writes then run in the team's tenant
 * (asTargetTenant).
 */
async function teamInScope(req: Request): Promise<UserTeam> {
  const id = Number(req.params.id);
  const team = Number.isInteger(id) && id > 0 ? await globalViewRead(req, () => teamService.getById(id)) : null;
  if (!team || (!teamGodView(req) && Number(team.tenantId) !== Number(req.tenantId))) {
    throw new AppError(404, 'Team not found');
  }
  return team;
}

/**
 * What an approved team request will do (tenant.manage_teams /
 * tenant.manage_permissions at the 'restricted' level): built from the
 * validated body the executor replays (approvalDescribe.ts).
 */
async function describeTeamRequest(req: Request, action: string): Promise<string> {
  // What the reviewer reads names the team, its members and scopes, possibly
  // of another tenant in the god view: read there.
  return globalViewRead(req, () => describeTeamRequestIn(req, action));
}

async function describeTeamRequestIn(req: Request, action: string): Promise<string> {
  const d = await import('../services/approvalDescribe');
  const body = (req.body ?? {}) as Record<string, any>;
  if (action === 'team_create') {
    const where = isMasterTenant(req.tenantId) && body.tenantId ? ` in ${await d.tenantLabel(body.tenantId)}` : '';
    return `Create team "${body.name}"${where}${body.description ? ` — description: ${d.short(body.description)}` : ''}${body.canCreate ? ' — members may create' : ''}`;
  }
  const id = parseInt(req.params.id, 10);
  const team = Number.isInteger(id) ? await teamService.getById(id) : null;
  const label = team ? `team "${team.name}" (#${id})` : `team #${req.params.id}`;
  const teamTenant = Number(team?.tenantId ?? req.tenantId);
  switch (action) {
    case 'team_update': {
      const t = team as unknown as Record<string, unknown> | null;
      const parts = [
        'name' in body ? d.change('name', t?.name ?? null, body.name) : null,
        'description' in body ? d.change('description', t?.description ?? null, body.description) : null,
        'canCreate' in body ? d.change('members may create', t?.canCreate ?? null, body.canCreate) : null,
      ].filter(Boolean);
      return `Update ${label} — ${parts.join('; ') || 'no change'}`;
    }
    case 'team_delete':
      return `Delete ${label} (its members lose the access it grants)`;
    case 'team_members_set': {
      const next: number[] = Array.isArray(body.memberIds) ? body.memberIds.map(Number) : [];
      const prev: number[] = team ? (await teamService.getMembers(id)).map(Number) : [];
      const added = next.filter((u) => !prev.includes(u));
      const removed = prev.filter((u) => !next.includes(u));
      return `Members of ${label} → ${await d.userList(next)}`
        + (added.length ? ` — added: ${await d.userList(added)}` : '')
        + (removed.length ? ` — removed: ${await d.userList(removed)}` : '');
    }
    case 'team_permissions_set':
      return `Permissions of ${label} → ${await d.permissionList(teamTenant, body.permissions)}`;
    default:
      return `${action} on ${label}`;
  }
}

/** Audit of a team action, filed in the team's tenant: a god-view action on
 *  another tenant's team leaves its trace in that tenant's own log (as
 *  logReqAs does for devices), where the team's name resolves. */
async function auditTeam(req: Request, teamTenantId: number, action: string, teamId: number, details?: Record<string, unknown>): Promise<void> {
  try {
    const { auditService } = await import('../services/audit.service');
    await auditService.logReqAs(req, teamTenantId, action, { resourceType: 'team', resourcePath: String(teamId), details });
  } catch {}
}

export const teamsController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // The god view (platform admin on the master tenant) can request all
      // teams across tenants via ?scope=all. Otherwise scope to the current
      // tenant from session
      const scopeAll = teamGodView(req) && req.query.scope === 'all';
      const teams = await teamService.getAll(scopeAll ? null : req.tenantId);
      res.json({ success: true, data: teams });
    } catch (err) {
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const team = await teamInScope(req);
      const [members, permissions] = await Promise.all([
        teamService.getMembers(team.id),
        teamService.getPermissions(team.id),
      ]);

      res.json({ success: true, data: { ...team, memberIds: members, permissions } });
    } catch (err) {
      next(err);
    }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_teams',
        approvalRequestType: 'batch_command',
        approvalDescription: await describeTeamRequest(req, 'team_create'),
        approvalPayload: { action: 'team_create', body: req.body },
      });
      if (!gated) return;

      const data = req.body as CreateTeamInput & { tenantId?: number };

      // Teams are strictly mono-tenant: the row's tenant_id determines
      // which devices the team can be granted permissions on, and a
      // user joining a team only gains access INSIDE that one tenant.
      // To give a user access to N tenants the admin must create N
      // separate teams and assign them all.
      //
      //   - From the master tenant the admin MUST specify a target
      //     tenantId in the body (it can be MASTER_TENANT_ID itself,
      //     in which case the team only grants rights on devices
      //     genuinely owned by Default).
      //   - From any other tenant the body's tenantId is ignored — a
      //     child-tenant admin cannot create teams in another tenant.
      const isPlatformAdmin = req.session.role === 'admin';
      let targetTenantId: number;
      if (isMasterTenant(req.tenantId)) {
        if (!isPlatformAdmin) throw new AppError(403, 'Only platform admins can create teams from the master tenant');
        if (!data.tenantId || !Number.isFinite(data.tenantId)) {
          throw new AppError(400, 'tenantId is required when creating a team from the master tenant. Pick the tenant the team will operate in.');
        }
        const { tenantService } = await import('../services/tenant.service');
        if (!(await tenantService.getById(data.tenantId))) throw new AppError(400, 'Target tenant not found');
        targetTenantId = data.tenantId;
      } else {
        // Body tenantId is ignored from child tenants (security).
        targetTenantId = req.tenantId;
      }
      const team = await asTargetTenant(req, targetTenantId, () => teamService.create(data, targetTenantId));
      await auditTeam(req, targetTenantId, 'team.created', team.id, { name: team.name });
      res.status(201).json({ success: true, data: team });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('unique')) {
        next(new AppError(409, 'Team name already exists'));
      } else {
        next(err);
      }
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const current = await teamInScope(req);
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_teams',
        approvalRequestType: 'batch_command',
        approvalDescription: await describeTeamRequest(req, 'team_update'),
        approvalPayload: { action: 'team_update', teamId: current.id, body: req.body },
      });
      if (!gated) return;

      const data = req.body as UpdateTeamInput;
      const team = await asTargetTenant(req, Number(current.tenantId), () => teamService.update(current.id, data));
      if (!team) throw new AppError(404, 'Team not found');
      await auditTeam(req, Number(current.tenantId), 'team.updated', current.id, { name: team.name });
      res.json({ success: true, data: team });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('unique')) {
        next(new AppError(409, 'Team name already exists'));
      } else {
        next(err);
      }
    }
  },

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const current = await teamInScope(req);
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_teams',
        approvalRequestType: 'batch_command',
        approvalDescription: await describeTeamRequest(req, 'team_delete'),
        approvalPayload: { action: 'team_delete', teamId: current.id },
      });
      if (!gated) return;

      const deleted = await asTargetTenant(req, Number(current.tenantId), () => teamService.delete(current.id));
      if (!deleted) throw new AppError(404, 'Team not found');
      await auditTeam(req, Number(current.tenantId), 'team.deleted', current.id, { name: current.name });
      res.json({ success: true, message: 'Team deleted' });
    } catch (err) {
      next(err);
    }
  },

  // ── Members ──

  async getMembers(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const team = await teamInScope(req);
      const members = await teamService.getMembers(team.id);
      res.json({ success: true, data: members });
    } catch (err) {
      next(err);
    }
  },

  async setMembers(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const team = await teamInScope(req);
      const { memberIds } = req.body as SetTeamMembersInput;
      // Members of the team's tenant only: refused now rather than after a
      // second administrator approved it (setMembers checks it again).
      await asTargetTenant(req, Number(team.tenantId), () => teamService.assertMembersInTenant(Number(team.tenantId), memberIds));
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_permissions',
        approvalRequestType: 'batch_command',
        approvalDescription: await describeTeamRequest(req, 'team_members_set'),
        approvalPayload: { action: 'team_members_set', teamId: team.id, memberIds },
      });
      if (!gated) return;

      await asTargetTenant(req, Number(team.tenantId), () => teamService.setMembers(team.id, memberIds));
      await auditTeam(req, Number(team.tenantId), 'team.members_changed', team.id, { userCount: memberIds.length, memberIds });
      res.json({ success: true, data: memberIds });
    } catch (err) {
      next(err);
    }
  },

  // ── Permissions ──

  async getPermissions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const team = await teamInScope(req);
      const permissions = await teamService.getPermissions(team.id);
      res.json({ success: true, data: permissions });
    } catch (err) {
      next(err);
    }
  },

  async setPermissions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // Tenant ownership check — a request from tenant A may not edit a
      // team owned by tenant B (only the god view reaches every team) —
      // and the scopes must name groups and devices of the TEAM's tenant:
      // both refused before any approval is filed (setPermissions checks
      // the scopes again).
      const team = await teamInScope(req);
      const { permissions } = req.body as SetTeamPermissionsInput;
      await asTargetTenant(req, Number(team.tenantId), () => teamService.assertScopesInTenant(Number(team.tenantId), permissions));

      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_permissions',
        approvalRequestType: 'batch_command',
        approvalDescription: await describeTeamRequest(req, 'team_permissions_set'),
        approvalPayload: { action: 'team_permissions_set', teamId: team.id, permissions },
      });
      if (!gated) return;

      const result = await asTargetTenant(req, Number(team.tenantId), () => teamService.setPermissions(team.id, permissions));
      await auditTeam(req, Number(team.tenantId), 'team.permissions_changed', team.id, { permissionCount: permissions.length });
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  async removePermission(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // The team's tenant first, then a scope of THAT team only.
      const team = await teamInScope(req);
      const permId = Number(req.params.permId);
      if (!Number.isInteger(permId) || permId <= 0) throw new AppError(404, 'Permission not found');
      const deleted = await asTargetTenant(req, Number(team.tenantId), () => teamService.removePermission(team.id, permId));
      if (!deleted) throw new AppError(404, 'Permission not found');
      await auditTeam(req, Number(team.tenantId), 'team.permission_removed', team.id, { permissionId: permId });
      res.json({ success: true, message: 'Permission removed' });
    } catch (err) {
      next(err);
    }
  },
};

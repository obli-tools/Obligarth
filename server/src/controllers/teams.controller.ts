import type { Request, Response, NextFunction } from 'express';
import { teamService } from '../services/team.service';
import { AppError } from '../middleware/errorHandler';
import { isMasterTenant } from '@obliance/shared';
import type {
  CreateTeamInput,
  UpdateTeamInput,
  SetTeamMembersInput,
  SetTeamPermissionsInput,
} from '../validators/team.schema';

/**
 * What an approved team request will do (tenant.manage_teams /
 * tenant.manage_permissions at the 'restricted' level): built from the
 * validated body the executor replays (approvalDescribe.ts).
 */
async function describeTeamRequest(req: Request, action: string): Promise<string> {
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

export const teamsController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // Platform admins can request all teams across tenants via ?scope=all
      // Otherwise scope to the current tenant from session
      const isPlatformAdmin = req.session.role === 'admin';
      const scopeAll = isPlatformAdmin && req.query.scope === 'all';
      const teams = await teamService.getAll(scopeAll ? null : req.tenantId);
      res.json({ success: true, data: teams });
    } catch (err) {
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const team = await teamService.getById(id);
      if (!team) throw new AppError(404, 'Team not found');
      // Tenant ownership gate — `teamService.getById` is intentionally
      // tenant-agnostic (background jobs read across tenants), so the
      // controller MUST gate the response. Same 404 shape as
      // "doesn't exist" so a sibling tenant's team's existence isn't
      // leaked.
      if (!isMasterTenant(req.tenantId) && team.tenantId !== req.tenantId) {
        throw new AppError(404, 'Team not found');
      }

      const [members, permissions] = await Promise.all([
        teamService.getMembers(id),
        teamService.getPermissions(id),
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
        targetTenantId = data.tenantId;
      } else {
        // Body tenantId is ignored from child tenants (security).
        targetTenantId = req.tenantId;
      }
      const team = await teamService.create(data, targetTenantId);
      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'team.created', {
          resourceType: 'team', resourcePath: String(team.id),
          details: { name: team.name },
        });
      } catch {}
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
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_teams',
        approvalRequestType: 'batch_command',
        approvalDescription: await describeTeamRequest(req, 'team_update'),
        approvalPayload: { action: 'team_update', teamId: parseInt(req.params.id, 10), body: req.body },
      });
      if (!gated) return;

      const id = parseInt(req.params.id, 10);
      const data = req.body as UpdateTeamInput;
      const team = await teamService.update(id, data);
      if (!team) throw new AppError(404, 'Team not found');
      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'team.updated', {
          resourceType: 'team', resourcePath: String(id), details: { name: team.name },
        });
      } catch {}
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
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_teams',
        approvalRequestType: 'batch_command',
        approvalDescription: await describeTeamRequest(req, 'team_delete'),
        approvalPayload: { action: 'team_delete', teamId: parseInt(req.params.id, 10) },
      });
      if (!gated) return;

      const id = parseInt(req.params.id, 10);
      const deleted = await teamService.delete(id);
      if (!deleted) throw new AppError(404, 'Team not found');
      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'team.deleted', { resourceType: 'team', resourcePath: String(id) });
      } catch {}
      res.json({ success: true, message: 'Team deleted' });
    } catch (err) {
      next(err);
    }
  },

  // ── Members ──

  async getMembers(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const members = await teamService.getMembers(id);
      res.json({ success: true, data: members });
    } catch (err) {
      next(err);
    }
  },

  async setMembers(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_permissions',
        approvalRequestType: 'batch_command',
        approvalDescription: await describeTeamRequest(req, 'team_members_set'),
        approvalPayload: { action: 'team_members_set', teamId: parseInt(req.params.id, 10), memberIds: (req.body as SetTeamMembersInput)?.memberIds },
      });
      if (!gated) return;

      const id = parseInt(req.params.id, 10);
      const { memberIds } = req.body as SetTeamMembersInput;
      await teamService.setMembers(id, memberIds);
      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'team.members_changed', {
          resourceType: 'team', resourcePath: String(id),
          details: { userCount: memberIds.length, memberIds },
        });
      } catch {}
      res.json({ success: true, data: memberIds });
    } catch (err) {
      next(err);
    }
  },

  // ── Permissions ──

  async getPermissions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const permissions = await teamService.getPermissions(id);
      res.json({ success: true, data: permissions });
    } catch (err) {
      next(err);
    }
  },

  async setPermissions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);

      // Tenant ownership check — a request from tenant A may not edit a
      // team owned by tenant B. The default tenant (id=1) is the
      // platform-admin "god view" and bypasses the check by design.
      const team = await teamService.getById(id);
      if (!team) throw new AppError(404, 'Team not found');
      if (req.tenantId !== 1 && team.tenantId !== req.tenantId) {
        throw new AppError(403, 'Team belongs to another tenant');
      }

      const { applyRestriction } = await import('../services/restriction.service');
      const gated = await applyRestriction(res, {
        req, actionKey: 'tenant.manage_permissions',
        approvalRequestType: 'batch_command',
        approvalDescription: await describeTeamRequest(req, 'team_permissions_set'),
        approvalPayload: { action: 'team_permissions_set', teamId: id, permissions: (req.body as SetTeamPermissionsInput)?.permissions },
      });
      if (!gated) return;

      const { permissions } = req.body as SetTeamPermissionsInput;
      const result = await teamService.setPermissions(id, permissions);
      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'team.permissions_changed', {
          resourceType: 'team', resourcePath: String(id),
          details: { permissionCount: permissions.length },
        });
      } catch {}
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  async removePermission(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const permId = parseInt(req.params.permId, 10);
      const deleted = await teamService.removePermission(permId);
      if (!deleted) throw new AppError(404, 'Permission not found');
      res.json({ success: true, message: 'Permission removed' });
    } catch (err) {
      next(err);
    }
  },
};

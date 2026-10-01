import type { Request, Response, NextFunction } from 'express';
import type { DeviceGroup } from '@obligarth/shared';
import { groupService } from '../services/group.service';
import { permissionService } from '../services/permission.service';
import { teamService } from '../services/team.service';
import { groupNotificationService } from '../services/groupNotification.service';
import { hasGlobalView } from '../services/deviceScope.service';
import { AppError } from '../middleware/errorHandler';
import { asTargetTenant, globalViewRead } from '../middleware/dbContext';
import { db } from '../db';
import type { CreateGroupInput, UpdateGroupInput, MoveGroupInput } from '../validators/group.schema';

/**
 * Tenant ownership gate of the /:id routes: a group of the session's
 * tenant, or of any tenant for the master tenant's global view (platform
 * administrators only, hasGlobalView). Anything else answers like an
 * unknown group (404 over 403, so that a guessed id does not reveal that
 * the group exists). Database context (rls-tenant §6.3): the group is read
 * across tenants in the global view (context 'platform'); a write then runs
 * in the context of the group's tenant (asTargetTenant).
 */
async function groupInReach(req: Request, id: number): Promise<DeviceGroup> {
  const group = Number.isSafeInteger(id) && id > 0 ? await globalViewRead(req, () => groupService.getById(id)) : null;
  if (!group || (group.tenantId !== req.tenantId && !hasGlobalView(req))) {
    throw new AppError(404, 'Group not found');
  }
  return group;
}

export const groupsController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const isAdmin = req.session.role === 'admin';
      const allGroups = await groupService.getAll(req.tenantId, { globalView: hasGlobalView(req) });

      if (isAdmin) {
        res.json({ success: true, data: allGroups });
        return;
      }

      const visibleIds = await permissionService.getVisibleGroupIds(req.session.userId!, false);
      if (visibleIds === 'all') {
        res.json({ success: true, data: allGroups });
        return;
      }

      const visibleSet = new Set(visibleIds);
      const filtered = allGroups.filter((g) => visibleSet.has(g.id));
      res.json({ success: true, data: filtered });
    } catch (err) {
      next(err);
    }
  },

  async tree(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const isAdmin = req.session.role === 'admin';
      const tree = await groupService.getTree(req.tenantId, { globalView: hasGlobalView(req) });

      if (isAdmin) {
        res.json({ success: true, data: tree });
        return;
      }

      const visibleIds = await permissionService.getVisibleGroupIds(req.session.userId!, false);
      if (visibleIds === 'all') {
        res.json({ success: true, data: tree });
        return;
      }

      // Filter tree to only include visible groups
      const visibleSet = new Set(visibleIds);
      function filterTree(nodes: typeof tree): typeof tree {
        return nodes
          .filter((n) => visibleSet.has(n.id))
          .map((n) => ({ ...n, children: filterTree(n.children) }));
      }
      res.json({ success: true, data: filterTree(tree) });
    } catch (err) {
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const group = await groupInReach(req, id);

      const isAdmin = req.session.role === 'admin';
      if (!isAdmin) {
        const canRead = await permissionService.canReadGroup(req.session.userId!, id, false);
        if (!canRead) throw new AppError(403, 'Access denied');
      }

      res.json({ success: true, data: group });
    } catch (err) {
      next(err);
    }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as CreateGroupInput;
      const isAdmin = req.session.role === 'admin';

      // The new group belongs to the session's tenant. Under a parent, to
      // the parent's tenant — which must be the session's, except for the
      // global view (a tree never spans two tenants). Another tenant's
      // parent answers like an unknown one; a non-administrator must also
      // be able to write the parent, as for a move.
      let tenantId = req.tenantId;
      if (data.parentId) {
        const parentId = data.parentId;
        const parent = await globalViewRead(req, () => groupService.getById(parentId));
        if (!parent || (parent.tenantId !== req.tenantId && !hasGlobalView(req))) {
          throw new AppError(400, 'Parent group not found');
        }
        tenantId = parent.tenantId;
        if (!isAdmin && !(await permissionService.canWriteGroup(req.session.userId!, parent.id, false))) {
          throw new AppError(403, 'No write permission on target group');
        }
      }

      // A non-administrator creates through a can_create team of THIS
      // tenant (the rule of requireCanCreate), of which it is still a
      // member, and only those teams receive the rw scope on the new group.
      const creatorTeamIds = isAdmin ? [] : await groupService.creatorTeamIds(req.session.userId!, tenantId);
      if (!isAdmin && creatorTeamIds.length === 0) throw new AppError(403, 'Insufficient permissions');

      // Written in the group's tenant (the parent's, from the global view).
      const group = await asTargetTenant(req, tenantId, async () => {
        const created = await groupService.create(data, tenantId);

        // Auto-assign RW to the creator's can_create teams of the tenant. A
        // failure undoes the creation: never a group its creator cannot reach.
        try {
          for (const teamId of creatorTeamIds) {
            await teamService.addPermission(teamId, 'group', created.id, 'rw');
          }
        } catch (err) {
          await groupService.delete(created.id).catch(() => {});
          throw err;
        }
        return created;
      });

      try {
        const { auditService } = await import('../services/audit.service');
        // Filed in the group's tenant (from the global view: the client's log,
        // rls-tenant EX-08), from asTargetTenant.
        await auditService.logReqAs(req, tenantId, 'group.created', {
          resourceType: 'group', resourcePath: String(group.id),
          details: { name: group.name, parentId: group.parentId ?? null },
        });
      } catch {}

      res.status(201).json({ success: true, data: group });
    } catch (err) {
      next(err);
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      // Tenant ownership gate before any write.
      const current = await groupInReach(req, id);
      const data = req.body as UpdateGroupInput;
      const group = await asTargetTenant(req, current.tenantId, () => groupService.update(id, data));

      if (!group) throw new AppError(404, 'Group not found');

      if (data.groupNotifications !== undefined) {
        groupNotificationService.removeGroup(id);
      }

      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReqAs(req, current.tenantId, 'group.updated', {
          resourceType: 'group', resourcePath: String(id),
          details: { name: group.name },
        });
      } catch {}

      res.json({ success: true, data: group });
    } catch (err) {
      next(err);
    }
  },

  async move(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const { newParentId } = req.body as MoveGroupInput;

      // Tenant ownership gate — and the target parent must belong to the
      // group's own tenant, so that a group is never reparented into
      // another tenant's tree. Another tenant's parent answers like an
      // unknown one.
      const existing = await groupInReach(req, id);
      if (newParentId !== null) {
        const parent = await globalViewRead(req, () => groupService.getById(newParentId));
        if (!parent || parent.tenantId !== existing.tenantId) {
          throw new AppError(400, 'Parent group not found');
        }
      }

      // Also check write permission on target parent if non-admin
      const isAdmin = req.session.role === 'admin';
      if (!isAdmin && newParentId !== null) {
        const canWriteTarget = await permissionService.canWriteGroup(req.session.userId!, newParentId, false);
        if (!canWriteTarget) throw new AppError(403, 'No write permission on target group');
      }

      const group = await asTargetTenant(req, existing.tenantId, () => groupService.move(id, newParentId));
      if (!group) throw new AppError(404, 'Group not found');

      res.json({ success: true, data: group });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('circular')) {
        next(new AppError(400, err.message));
      } else {
        next(err);
      }
    }
  },

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);

      // Same tenant gate as update.
      const current = await groupInReach(req, id);

      groupNotificationService.removeGroup(id);

      const deleted = await asTargetTenant(req, current.tenantId, () => groupService.delete(id));
      if (!deleted) throw new AppError(404, 'Group not found');

      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReqAs(req, current.tenantId, 'group.deleted', {
          resourceType: 'group', resourcePath: String(id),
        });
      } catch {}

      res.json({ success: true, message: 'Group deleted' });
    } catch (err) {
      next(err);
    }
  },

  async stats(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: {} });
    } catch (err) {
      next(err);
    }
  },

  async reorder(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const raw = req.body?.items as unknown;
      if (!Array.isArray(raw) || raw.length === 0) {
        throw new AppError(400, 'items array is required');
      }
      const items = raw.map((it) => ({ id: Number(it?.id), sortOrder: Number(it?.sortOrder) }));
      if (items.some((it) => !Number.isSafeInteger(it.id) || it.id <= 0 || !Number.isSafeInteger(it.sortOrder))) {
        throw new AppError(400, 'Invalid items');
      }
      // Groups of the session's tenant only (any tenant for the global
      // view): one id out of reach and nothing is reordered. From the global
      // view, the groups of ONE tenant only (409 otherwise: a request never
      // writes to several clients), written in that tenant's context.
      const view = { globalView: hasGlobalView(req) };
      let targetTenantId = req.tenantId;
      if (view.globalView) {
        const ids = [...new Set(items.map((i) => i.id))];
        const tenants = await globalViewRead(req, () => db('device_groups').whereIn('id', ids).distinct('tenant_id').pluck('tenant_id')) as number[];
        if (tenants.length > 1) throw new AppError(409, 'One request acts on one tenant only', 'crossTenantBatch');
        if (tenants.length === 1) targetTenantId = Number(tenants[0]);
      }
      const done = await asTargetTenant(req, targetTenantId, () => groupService.reorder(items, req.tenantId, view));
      if (!done) throw new AppError(404, 'Group not found');

      res.json({ success: true, message: 'Groups reordered' });
    } catch (err) {
      next(err);
    }
  },

};

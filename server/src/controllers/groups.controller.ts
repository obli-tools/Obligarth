import type { Request, Response, NextFunction } from 'express';
import type { DeviceGroup } from '@obligarth/shared';
import { groupService } from '../services/group.service';
import { permissionService } from '../services/permission.service';
import { teamService } from '../services/team.service';
import { groupNotificationService } from '../services/groupNotification.service';
import { hasGlobalView } from '../services/deviceScope.service';
import { AppError } from '../middleware/errorHandler';
import type { CreateGroupInput, UpdateGroupInput, MoveGroupInput } from '../validators/group.schema';

/**
 * Tenant ownership gate of the /:id routes: a group of the session's
 * tenant, or of any tenant for the master tenant's global view (platform
 * administrators only, hasGlobalView). Anything else answers like an
 * unknown group (404 over 403, so that a guessed id does not reveal that
 * the group exists).
 */
async function groupInReach(req: Request, id: number): Promise<DeviceGroup> {
  const group = Number.isSafeInteger(id) && id > 0 ? await groupService.getById(id) : null;
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
        const parent = await groupService.getById(data.parentId);
        if (!parent || (parent.tenantId !== req.tenantId && !hasGlobalView(req))) {
          throw new AppError(400, 'Parent group not found');
        }
        tenantId = parent.tenantId;
        if (!isAdmin && !(await permissionService.canWriteGroup(req.session.userId!, parent.id, false))) {
          throw new AppError(403, 'No write permission on target group');
        }
      }

      // A non-administrator creates through a can_create team of THIS
      // tenant (requireCanCreate looks at the teams of every tenant), and
      // only those teams receive the rw scope on the new group.
      const creatorTeamIds = isAdmin ? [] : await groupService.creatorTeamIds(req.session.userId!, tenantId);
      if (!isAdmin && creatorTeamIds.length === 0) throw new AppError(403, 'Insufficient permissions');

      const group = await groupService.create(data, tenantId);

      // Auto-assign RW to the creator's can_create teams of the tenant. A
      // failure undoes the creation: never a group its creator cannot reach.
      try {
        for (const teamId of creatorTeamIds) {
          await teamService.addPermission(teamId, 'group', group.id, 'rw');
        }
      } catch (err) {
        await groupService.delete(group.id).catch(() => {});
        throw err;
      }

      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'group.created', {
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
      await groupInReach(req, id);
      const data = req.body as UpdateGroupInput;
      const group = await groupService.update(id, data);

      if (!group) throw new AppError(404, 'Group not found');

      if (data.groupNotifications !== undefined) {
        groupNotificationService.removeGroup(id);
      }

      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'group.updated', {
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
        const parent = await groupService.getById(newParentId);
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

      const group = await groupService.move(id, newParentId);
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
      await groupInReach(req, id);

      groupNotificationService.removeGroup(id);

      const deleted = await groupService.delete(id);
      if (!deleted) throw new AppError(404, 'Group not found');

      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'group.deleted', {
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
      // view): one id out of reach and nothing is reordered.
      const done = await groupService.reorder(items, req.tenantId, { globalView: hasGlobalView(req) });
      if (!done) throw new AppError(404, 'Group not found');

      res.json({ success: true, message: 'Groups reordered' });
    } catch (err) {
      next(err);
    }
  },

};

import type { Request, Response, NextFunction } from 'express';
import { settingsService } from '../services/settings.service';
import { hasGlobalView } from '../services/deviceScope.service';
import type { SettingScope } from '@obligarth/shared';
import type { SettingKey } from '@obligarth/shared';
import { AppError } from '../middleware/errorHandler';
import { asTargetTenant, globalViewRead } from '../middleware/dbContext';
import type { SetSettingInput, SetSettingsBulkInput } from '../validators/settings.schema';

function parseScope(req: Request): { scope: SettingScope; scopeId: number | null } {
  const { scope, scopeId } = req.params;

  if (scope === 'global') return { scope: 'global', scopeId: null };
  if (scope === 'group' || scope === 'device') {
    const id = parseInt(scopeId, 10);
    if (isNaN(id)) throw new AppError(400, 'Invalid scope ID');
    return { scope, scopeId: id };
  }
  throw new AppError(400, 'Invalid scope. Must be global, group, or device');
}

/**
 * The tenant whose settings rows this request reads or writes: a group or a
 * device of the session's tenant (a group of any tenant for the master
 * tenant's global view, whose rows then live in the group's tenant).
 * Anything else answers like an unknown id (404). Database context
 * (rls-tenant §6.3): resolved and read across tenants in the global view
 * (context 'platform'), written in the context of the rows' tenant
 * (asTargetTenant).
 */
async function scopeTenantId(req: Request, scope: SettingScope, scopeId: number | null): Promise<number> {
  const tenantId = await globalViewRead(req,
    () => settingsService.scopeTenantId(req.tenantId!, scope, scopeId, { globalView: hasGlobalView(req) }));
  if (tenantId === null) throw new AppError(404, scope === 'device' ? 'Device not found' : 'Group not found');
  return tenantId;
}

export const settingsController = {
  // GET /api/settings/global/resolved
  async getGlobalResolved(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const result = await settingsService.resolveGlobal(req.tenantId!);
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/settings/group/:scopeId/resolved
  async getGroupResolved(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const groupId = parseInt(req.params.scopeId, 10);
      if (isNaN(groupId)) throw new AppError(400, 'Invalid group ID');
      const tenantId = await scopeTenantId(req, 'group', groupId);
      const result = await globalViewRead(req, () => settingsService.resolveForGroup(tenantId, groupId));
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/settings/device/:scopeId/resolved
  async getDeviceResolved(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseInt(req.params.scopeId, 10);
      if (isNaN(deviceId)) throw new AppError(400, 'Invalid device ID');

      // Need the device's group_id
      const { db: database } = await import('../db');
      const device = await database('devices').where({ id: deviceId, tenant_id: req.tenantId! }).first();
      if (!device) throw new AppError(404, 'Device not found');

      const resolved = await settingsService.resolveForDevice(req.tenantId!, deviceId, device.group_id);

      // Also get device-level overrides specifically
      const overrides = await settingsService.getByScope(req.tenantId!, 'device', deviceId);

      res.json({ success: true, data: { resolved, overrides } });
    } catch (err) {
      next(err);
    }
  },

  // PUT /api/settings/:scope/:scopeId
  async set(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      const { key, value } = req.body as SetSettingInput;
      const tenantId = await scopeTenantId(req, scope, scopeId);

      await asTargetTenant(req, tenantId, () => settingsService.set(tenantId, scope, scopeId, key as SettingKey, value));

      res.json({ success: true, message: 'Setting saved' });
    } catch (err: unknown) {
      if (err instanceof Error && (err.message.includes('must be between') || err.message.includes('Unknown setting'))) {
        next(new AppError(400, err.message));
      } else {
        next(err);
      }
    }
  },

  // PUT /api/settings/:scope/:scopeId/bulk
  async setBulk(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      const { overrides } = req.body as SetSettingsBulkInput;
      const tenantId = await scopeTenantId(req, scope, scopeId);

      await asTargetTenant(req, tenantId, () => settingsService.setBulk(
        tenantId,
        scope,
        scopeId,
        overrides.map((o) => ({ key: o.key as SettingKey, value: o.value })),
      ));

      res.json({ success: true, message: 'Settings saved' });
    } catch (err) {
      next(err);
    }
  },

  // DELETE /api/settings/:scope/:scopeId/:key  (reset to inherited)
  async remove(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      const { key } = req.params;
      const tenantId = await scopeTenantId(req, scope, scopeId);

      const deleted = await asTargetTenant(req, tenantId, () => settingsService.remove(tenantId, scope, scopeId, key as SettingKey));

      res.json({ success: true, message: deleted ? 'Setting reset to inherited' : 'No override found' });
    } catch (err) {
      next(err);
    }
  },
};

import type { Request, Response, NextFunction } from 'express';
import { isPlatformOnlyAlertKind, liveAlertService } from '../services/liveAlert.service';
import { db } from '../db';
import { asMember, asTenant, userActor } from '../db/context';

/** An alert of one of the user's tenants (read in the context 'member'),
 *  or undefined; an alert of the platform for its administrators only. */
async function alertOfUser(userId: number, id: number, platformAdmin = false): Promise<{ id: number; tenant_id: number } | undefined> {
  return asMember(userId, async () => {
    const userTenantIds = await db('user_tenants')
      .where('user_id', userId)
      .pluck('tenant_id') as number[];
    const row = await db('live_alerts')
      .where({ id })
      .whereIn('tenant_id', userTenantIds)
      .first('id', 'tenant_id', 'kind') as { id: number; tenant_id: number; kind: string | null } | undefined;
    if (!row || (!platformAdmin && isPlatformOnlyAlertKind(row.kind))) return undefined;
    return { id: row.id, tenant_id: row.tenant_id };
  });
}

/** GET /api/live-alerts — current tenant */
export async function getAlerts(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const alerts = await liveAlertService.getForTenant(req.tenantId, 100, { platformAdmin: req.session.role === 'admin' });
    res.json(alerts);
  } catch (err) { next(err); }
}

/**
 * GET /api/live-alerts/all — all tenants accessible by this user.
 * Returns { alerts, tenants, activeIds } where alerts are enriched with
 * tenantName (newest 200 active) and activeIds lists every active alert id
 * of the same tenants (the Android app withdraws notifications with it).
 */
export async function getAllTenantAlerts(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const tenants = await db('user_tenants')
      .join('tenants', 'user_tenants.tenant_id', 'tenants.id')
      .where('user_tenants.user_id', req.session.userId!)
      .select('tenants.id', 'tenants.name') as { id: number; name: string }[];

    const tenantIds = tenants.map((t) => t.id);
    const [alerts, activeIds] = await Promise.all([
      liveAlertService.getForTenants(tenantIds, 200),
      liveAlertService.getActiveIds(tenantIds),
    ]);
    res.json({ alerts, tenants, activeIds });
  } catch (err) { next(err); }
}

/** PATCH /api/live-alerts/:id/read — mark one alert as read (cross-tenant) */
export async function markRead(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const id = parseInt(req.params.id, 10);
    // Verify the alert belongs to a tenant the user can access
    const userId = Number(req.session.userId);
    const alert = Number.isSafeInteger(id) && id > 0 ? await alertOfUser(userId, id, req.session.role === 'admin') : undefined;
    if (!alert) { res.status(404).json({ error: 'Alert not found' }); return; }

    await asTenant(Number(alert.tenant_id), userActor(userId), () => liveAlertService.markRead(id, alert.tenant_id));
    res.json({ ok: true });
  } catch (err) { next(err); }
}

/** POST /api/live-alerts/read-all — mark all as read for current tenant */
export async function markAllRead(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await liveAlertService.markAllRead(req.tenantId, { platformAdmin: req.session.role === 'admin' });
    res.json({ ok: true });
  } catch (err) { next(err); }
}

/** DELETE /api/live-alerts/:id — delete one alert (cross-tenant) */
export async function deleteAlert(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const id = parseInt(req.params.id, 10);
    const userId = Number(req.session.userId);
    const alert = Number.isSafeInteger(id) && id > 0 ? await alertOfUser(userId, id, req.session.role === 'admin') : undefined;
    if (!alert) { res.status(404).json({ error: 'Alert not found' }); return; }

    await asTenant(Number(alert.tenant_id), userActor(userId), () => liveAlertService.deleteAlert(id, Number(alert.tenant_id)));
    res.json({ ok: true });
  } catch (err) { next(err); }
}

/** DELETE /api/live-alerts — clear all for current tenant */
export async function clearAll(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await liveAlertService.clearAll(req.tenantId, { platformAdmin: req.session.role === 'admin' });
    res.json({ ok: true });
  } catch (err) { next(err); }
}

import type { Request } from 'express';
import { isMasterTenant } from '@obliance/shared';
import type { DeviceCapability } from '@obliance/shared';
import { db } from '../db';
import { permissionService } from './permission.service';

/**
 * The device a REST request may act on, with the REST rules every
 * tenant-scoped route follows (master tenant + isolation rules):
 *   - the device must be in the session's tenant (req.tenantId), except for a
 *     platform admin on the master tenant (god view: any tenant);
 *   - a non-admin must also be a member of that tenant (requireTenant does
 *     not check it: a user removed from a tenant keeps a session on it until
 *     it switches), see the device through one of their teams (the same rule
 *     as the device list, permissionService.canReadDevice) and, when
 *     `capability` is given, hold it on the device.
 * Admins (users.role 'admin') bypass the team checks, as everywhere.
 *
 * A device the caller may not see answers like an unknown one (404, no
 * existence leak); a visible device without the capability answers 403.
 */
export type RequestDevice = {
  id: number;
  tenant_id: number;
  hostname: string | null;
  approval_status: string | null;
};

export type RequestDeviceOutcome =
  | { ok: true; device: RequestDevice; isAdmin: boolean }
  | { ok: false; status: 400 | 403 | 404; error: string };

/** A device id as a route or a body carries it (a number, or a digit string). */
export function parseRequestDeviceId(raw: unknown): number | null {
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' && /^[1-9][0-9]{0,9}$/.test(raw) ? Number(raw) : NaN;
  return Number.isSafeInteger(n) && n > 0 && n <= 2147483647 ? n : null;
}

export async function resolveRequestDevice(
  req: Request,
  rawDeviceId: unknown,
  opts: { capability?: DeviceCapability; capabilityError?: string } = {},
): Promise<RequestDeviceOutcome> {
  const notFound = { ok: false as const, status: 404 as const, error: 'Device not found' };
  const deviceId = parseRequestDeviceId(rawDeviceId);
  if (deviceId === null) return notFound;
  const tenantId = Number(req.tenantId);
  const userId = Number(req.session?.userId);
  if (!Number.isInteger(tenantId) || tenantId <= 0 || !Number.isInteger(userId) || userId <= 0) return notFound;
  const isAdmin = req.session?.role === 'admin';

  const q = db('devices').where({ id: deviceId });
  if (!(isAdmin && isMasterTenant(tenantId))) q.where({ tenant_id: tenantId });
  const device = await q.first('id', 'tenant_id', 'hostname', 'approval_status') as RequestDevice | undefined;
  if (!device) return notFound;
  if (isAdmin) return { ok: true, device, isAdmin };

  const member = await db('user_tenants').where({ user_id: userId, tenant_id: device.tenant_id }).first('user_id');
  if (!member) return notFound;
  if (!(await permissionService.canReadDevice(userId, device.id, false))) return notFound;
  if (opts.capability && !(await permissionService.canUseCapability(userId, device.id, false, opts.capability))) {
    return { ok: false, status: 403, error: opts.capabilityError ?? `Capability '${opts.capability}' not permitted for your team` };
  }
  return { ok: true, device, isAdmin };
}

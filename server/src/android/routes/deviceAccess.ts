// The device of an Android route, as the Apple routes of the queue reach it (apple/commands/routes.ts deviceOf and
// requireCapability; review AN-A2): a device of the request's tenant the caller sees (team scopes), else 404 whatever
// the request says; with a capability, that capability of the device's team scope and write access to it, else 403
// capabilityMissing. A platform administrator passes the scopes, never the tenant (the global view of the master
// tenant names no device of another tenant here). Capabilities per command: android-amapi §22.8 (AN41).
import type { Request } from 'express';
import type { DeviceCapability } from '@obligarth/shared';
import { AppError } from '../../middleware/errorHandler';
import { permissionService } from '../../services/permission.service';
import { resolveRequestDevice } from '../../services/deviceScope.service';

/** The capability and the restriction of each command type (§22.8, §11.2): android/commands/console.ts. */
export { ANDROID_COMMAND_CAPABILITY, ANDROID_COMMAND_RESTRICTION } from '../commands/console';

/** The device of a route (its id in `raw`): seen by the caller in the request's tenant, else 404; with `capability`,
 *  that capability on it and write access, else 403. */
export async function androidDeviceOf(req: Request, raw: unknown, capability?: DeviceCapability): Promise<number> {
  const outcome = await resolveRequestDevice(req, raw);
  if (!outcome.ok || Number(outcome.device.tenant_id) !== Number(req.tenantId)) throw new AppError(404, 'Not found', 'notFound');
  const id = Number(outcome.device.id);
  if (capability && !outcome.isAdmin) {
    const userId = Number(req.session.userId);
    if (!(await permissionService.canUseCapability(userId, id, false, capability)) || !(await permissionService.canWriteDevice(userId, id, false))) {
      throw new AppError(403, `Capability '${capability}' not permitted for your team`, 'capabilityMissing');
    }
  }
  return id;
}

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
import type { AndroidCommandType } from '../commands/catalog';

/** The capability of the device's team scope each command type needs (§22.8). */
export const ANDROID_COMMAND_CAPABILITY: Readonly<Record<AndroidCommandType, DeviceCapability>> = Object.freeze({
  LOCK: 'mdm:lock',
  RESET_PASSWORD: 'mdm:passcode',
  REBOOT: 'mdm:restart',
  START_LOST_MODE: 'mdm:lost_mode',
  STOP_LOST_MODE: 'mdm:lost_mode',
  WIPE: 'mdm:wipe',
  RELINQUISH_OWNERSHIP: 'mdm:remove',
  CLEAR_APP_DATA: 'mdm:apps',
});

/** The restriction of the tenant's matrix each command of the console route takes: the keys of the Apple commands
 *  of the same nature (one matrix entry for both platforms, as the common queue of lot AN-P will have it). */
export const ANDROID_COMMAND_RESTRICTION: Readonly<Partial<Record<AndroidCommandType, string>>> = Object.freeze({
  REBOOT: 'mdm.restart',
  STOP_LOST_MODE: 'mdm.lost_mode',
  CLEAR_APP_DATA: 'mdm.apps',
});

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

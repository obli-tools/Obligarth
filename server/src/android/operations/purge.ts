// Retention purge of the Android devices (lot AN-H1; android-amapi §4.8, COH-10): the generic purge of the retention
// (privacy.retention-tenant, modules/privacy.ts) deletes the records of devices past their retention; for the channel
// amapi it calls this purger first (registerDevicePurger('amapi', …), lot AN-P: modules/privacy.ts is an existing
// file), which, per device released from management:
//   1. deletes its own policy d-<uuid> at Google (absent: fine);
//   2. checks the device is gone at Google (getDevice → null): a resource still there is never purged under it (the
//      reconciliation, the forget or the operator clear it first), the device is kept for the next pass;
//   3. deletes the satellite android_devices (the generic purge then deletes the record of devices and its children).
// A tenant without an mdm_key is not skipped for its amapi records (COH-10): nothing here reads that key.
// Tenant context; identifiers and counts only.
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import { parseOwnedName } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { deleteDevicePolicy } from './forget';

export const PURGE_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'privacy.retention-tenant' }) as DbActor;

export interface PurgeResult { purged: number[]; kept: number[] }

/**
 * The purger of the channel amapi for `deviceIds` of `tenantId` (the generic purge chose them). Returns the devices
 * whose satellite is gone (purged) and those kept (still managed, or still present at Google, or Google unreachable).
 */
export async function purgeAndroidDevices(tenantId: number, deviceIds: number[], o: { gateway?: AndroidGateway; actor?: DbActor } = {}): Promise<PurgeResult> {
  const gw = o.gateway ?? androidGateway();
  const out: PurgeResult = { purged: [], kept: [] };
  if (!deviceIds.length) return out;
  return asTenant(tenantId, o.actor ?? PURGE_ACTOR, async () => {
    const rows = await db('android_devices as a').join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .where('a.tenant_id', tenantId).whereIn('a.device_id', deviceIds)
      .select('a.device_id', 'a.amapi_name', 'a.released_at', 'a.enterprise_id', 'd.uuid') as
      Array<{ device_id: number; amapi_name: string; released_at: Date | null; enterprise_id: number; uuid: string }>;
    const byId = new Map(rows.map((r) => [Number(r.device_id), r]));
    const e = await readEnterprise();
    for (const id of deviceIds) {
      const r = byId.get(id);
      if (!r) { out.purged.push(id); continue; }                      // no satellite: nothing Android to purge
      if (!r.released_at) { out.kept.push(id); continue; }            // still managed: never purged
      // Google side, only while the enterprise of the device is the tenant's current one and reachable.
      if (e && e.id === Number(r.enterprise_id) && (e.state === 'linked' || e.state === 'unlinking')) {
        try {
          await deleteDevicePolicy(gw, e, r.uuid);
          const p = parseOwnedName(e, r.amapi_name);
          const still = p.kind === 'device' ? await gw.getDevice(e, p.deviceId) : null;
          if (still) { out.kept.push(id); continue; }
        } catch (err) {
          if (!(err instanceof AndroidError && (err.kind === 'not_found' || err.kind === 'access_lost'))) { out.kept.push(id); continue; }
        }
      }
      await db('android_devices').where({ tenant_id: tenantId, device_id: id }).whereNotNull('released_at').delete();
      out.purged.push(id);
    }
    return out;
  });
}

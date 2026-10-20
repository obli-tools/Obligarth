// Devices gone at Google (lot AN-H1; android-amapi §6.5 step 2, §13.1, §22.5): one rule for the daily reconciliation
// and for the offboarding that waits for the managed devices of a client.
//   - devices.list is read whole (class background of the limiter; bounded): a list cut short marks nothing gone;
//   - a managed device absent from a complete list leaves management, removed_by_command when a WIPE or a
//     RELINQUISH_OWNERSHIP of the instance was sent to it, otherwise missing_in_provider;
//   - race guard (review AN-H1, R1): only a record created and enrolled before the listing started (one second of
//     margin) may be declared gone; a device enrolled or renewed while the list is read is left to the next pass.
// Runs in the tenant context of the caller, never inside an open transaction (G-A1). No device datum in a log.
import type { AmapiDevice } from '@obligarth/shared';
import { db } from '../../db';
import type { AndroidEnterpriseRef } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { exitManagement } from './exit';
import { commands } from '../commands/store';

/** 200 pages of 100 devices: 20 000 devices per enterprise at most in one run. */
export const MAX_LIST_PAGES = 200;

/** Lists every device of the enterprise at Google (bounded); `complete` false when the bound cut the list. */
export async function listAllDevices(gw: AndroidGateway, e: AndroidEnterpriseRef): Promise<{ devices: AmapiDevice[]; complete: boolean }> {
  const devices: AmapiDevice[] = [];
  let token: string | undefined;
  for (let page = 0; page < MAX_LIST_PAGES; page++) {
    const r = await gw.listDevices(e, token);
    devices.push(...r.items);
    token = r.nextPageToken;
    if (!token) return { devices, complete: true };
  }
  return { devices, complete: false };
}

/** Was the record written (created or enrolled again) after the listing started? It is then never declared gone. */
export function writtenDuringListing(k: { created_at: Date | string | null; enrolled_at: Date | string | null }, listStartedAt: number): boolean {
  return [k.created_at, k.enrolled_at].some((t) => t !== null && t !== undefined && new Date(t).getTime() >= listStartedAt);
}

/** A device absent at Google leaves management with the reason its commands give; true when it left now. */
export async function releaseGoneDevice(tenantId: number, deviceId: number): Promise<boolean> {
  const removed = await commands(db).where({ 'c.tenant_id': tenantId, 't.device_id': deviceId })
    .whereIn('c.request_type', ['WIPE', 'RELINQUISH_OWNERSHIP']).whereIn('t.state', ['sent', 'acknowledged']).first('c.id');
  return db.transaction((trx) => exitManagement(trx, tenantId, deviceId, removed ? 'removed_by_command' : 'missing_in_provider'));
}

/**
 * The managed devices of the enterprise that a complete devices.list no longer shows leave management (offboarding,
 * §6.5 step 2: a device erased while the procedure waits). `complete` false: the list was cut, nothing released.
 */
export async function releaseDevicesGoneAtGoogle(gw: AndroidGateway, e: AndroidEnterpriseRef, tenantId: number):
  Promise<{ released: number; complete: boolean }> {
  const listStartedAt = Date.now() - 1000;
  const listed = await listAllDevices(gw, e);
  if (!listed.complete) return { released: 0, complete: false };
  const atGoogle = new Set(listed.devices.map((d) => d.name));
  const known = await db('android_devices').where({ tenant_id: tenantId, enterprise_id: e.id }).whereNull('released_at')
    .select('device_id', 'amapi_name', 'created_at', 'enrolled_at') as Array<{ device_id: number; amapi_name: string | null; created_at: Date; enrolled_at: Date | null }>;
  let released = 0;
  for (const k of known) {
    if (!k.amapi_name || atGoogle.has(k.amapi_name)) continue;
    if (writtenDuringListing(k, listStartedAt)) continue;
    if (await releaseGoneDevice(tenantId, Number(k.device_id))) released += 1;
  }
  return { released, complete: true };
}

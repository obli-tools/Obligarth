import type { Knex } from 'knex';
import { audit } from '../audit';
import { requestDeviceResolution } from '../mdm/policies/triggers';
import { LEGACY_AGENT_ACTOR } from './actor';
import { cancelOpenOfDevice } from './commands';

// =============================================================================
// The record of a device the agent erased (review F032). The agent sends the
// acknowledgement of a device.wipe BEFORE erasing (RS-4: flushed, then the
// erase), so the acknowledgement alone does not prove the erase: an erase that
// failed after it leaves an agent that keeps interrogating, or a phone that
// stays off (stolen, a night) and interrogates later. A silence is therefore
// never a proof: a satellite revoked on a silence would answer agentRevoked to
// a phone whose erase failed, and the agent would then lift its protections
// (policy, kiosk, device owner) and forget its identity.
// The proof is a new enrollment carrying the serial number or one of the IMEIs
// of a record whose wipe was acknowledged and that has not interrogated since
// (WIPE_FLUSH_SECONDS of margin for the flush of the acknowledgement): the phone
// was erased and enrolled again with a new key (enroll.ts). Then, like a
// revocation: the old satellite revoked (revoke_reason 'wiped'), its open
// commands closed, the old record unenrolled (unenroll_reason 'wiped': its
// serial number free for the new enrollment, its site archivable), audited
// legacy_agent.device_wiped, its resolution requested.
// Without a new enrollment the record stays enrolled, as any silent device
// (alert legacy_agent.silent), until an operator revokes it.
// =============================================================================

/** The interrogations right after the acknowledgement (the flush before the erase) are part of it. */
export const WIPE_FLUSH_SECONDS = 120;

/** The SQL condition (alias a: legacy_agent_devices) of a device whose acknowledged wipe no interrogation followed. A
 *  constant: no value interpolated. */
const WIPED_SQL = `EXISTS (SELECT 1 FROM obligarth.legacy_agent_commands c
  WHERE c.tenant_id = a.tenant_id AND c.device_id = a.device_id AND c.request_type = 'device.wipe' AND c.state = 'acknowledged'
    AND c.completed_at IS NOT NULL AND coalesce(a.last_poll_at, c.completed_at) <= c.completed_at + make_interval(secs => ${WIPE_FLUSH_SECONDS}))`;

/**
 * Retires the erased devices among `deviceIds` (the records a new enrollment of the same phone names), in the caller's
 * transaction of the tenant. Returns the devices retired.
 */
export async function retireWipedInTx(trx: Knex.Transaction, tenantId: number, deviceIds: number[]): Promise<number[]> {
  if (deviceIds.length === 0) return [];
  const ids = (await trx('legacy_agent_devices as a')
    .join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where('a.tenant_id', tenantId).whereNull('a.revoked_at').whereNot('d.enrollment_state', 'unenrolled')
    .whereRaw(WIPED_SQL)
    .whereRaw('a.device_id = ANY (?::int[])', [deviceIds])
    .orderBy('a.device_id').forUpdate('a').pluck('a.device_id') as number[]).map(Number);
  if (ids.length === 0) return [];
  const now = new Date();
  const ctx = await audit.fromDbActor(LEGACY_AGENT_ACTOR, tenantId);
  for (const deviceId of ids) {
    await trx('legacy_agent_devices').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('revoked_at')
      .update({ revoked_at: now, revoke_reason: 'wiped', updated_at: now });
    const cancelled = await cancelOpenOfDevice(trx, tenantId, deviceId);
    await trx('devices').where({ tenant_id: tenantId, id: deviceId }).whereNot('enrollment_state', 'unenrolled')
      .update({ enrollment_state: 'unenrolled', enrollment_state_at: now, unenrolled_at: now, unenroll_reason: 'wiped', updated_at: now });
    await audit.appendInTx(trx, {
      tenantId, action: 'legacy_agent.device_wiped', target: { type: 'device', id: String(deviceId), device: deviceId },
      details: { cancelledCommands: cancelled, proof: 'reenrollment' },
    }, ctx, { onFailure: 'spool' });
  }
  await requestDeviceResolution(trx, tenantId, ids);
  return ids;
}

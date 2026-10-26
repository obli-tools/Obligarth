import type { Knex } from 'knex';
import { lostModeLocationAllowed } from '../../privacy/profiles';
import { lostModePurgeAt } from '../../privacy/retention';
import { locationOf } from './location';
import { registerCommandResultIngestor, type ResultIngestContext } from './results';

// =============================================================================
// Ingestion of the results of the lost-mode commands (docs: integration-apple-edge
// §7.6, SEC-05), inline in the event's savepoint (one row each):
//   DeviceLocation    the position the device answered, kept the lost_mode_location_days
//                     of the tenant (P0-13 T4, CNF-04; 30 by default) in lost_mode_locations with the id of its command; never
//                     for a personal device (read first: the table's trigger
//                     lost_mode_locations_guard would raise and fail the savepoint),
//                     nor when the tenant's privacy profile of the ownership refuses
//                     the location (P0-13, CNF-02: an answer to a request sent
//                     before the profile changed)
//   EnableLostMode    acknowledged: lost_mode_state 'on'
//   DisableLostMode   acknowledged: lost_mode_state 'off'
// The state follows the acknowledgement only when it is not older than the last
// change (lost_mode_changed_at: the device's word in DeviceInformation, §4.4, may
// have come first), and never for a personal device. The bus and the state
// 'enabling' at the submission are not touched. The target's final state already
// announces MDM_COMMAND_CHANGED with the device (outbox handler, after commit).
// Never a coordinate in the logs.
// =============================================================================

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function ownershipOf(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<string | null> {
  const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('ownership') as { ownership: string } | undefined;
  return d?.ownership ?? null;
}

/** DeviceLocation acknowledged: one row of lost_mode_locations (company devices whose profile allows it only). */
async function ingestDeviceLocation(c: ResultIngestContext): Promise<void> {
  const ownership = await ownershipOf(c.trx, c.tenantId, c.deviceId);
  if (ownership === null || ownership === 'personal') return;
  if (!(await lostModeLocationAllowed(c.trx, c.tenantId, ownership))) return;
  const p = locationOf(c.result ?? {}, c.occurredAt);
  if (!p) return;
  // The command of the answer (mdm_commands.id: the target was found by it); null if it is not there any more.
  const commandId = UUID_RE.test(c.commandId)
    && await c.trx('mdm_commands').where({ tenant_id: c.tenantId, id: c.commandId.toLowerCase() }).first('id')
    ? c.commandId.toLowerCase() : null;
  await c.trx('lost_mode_locations').insert({
    tenant_id: c.tenantId, device_id: c.deviceId, latitude: p.latitude, longitude: p.longitude,
    horizontal_accuracy: p.horizontalAccuracy, vertical_accuracy: p.verticalAccuracy, altitude: p.altitude, speed: p.speed,
    course: p.course, observed_at: p.observedAt, command_id: commandId,
    purge_at: lostModePurgeAt(c.trx, c.tenantId),
  });
}

/** EnableLostMode / DisableLostMode acknowledged: the lost mode takes the state the device confirmed. */
function lostModeAck(to: 'on' | 'off') {
  return async (c: ResultIngestContext): Promise<void> => {
    await c.trx('devices').where({ tenant_id: c.tenantId, id: c.deviceId }).whereNot('ownership', 'personal')
      .whereNot('lost_mode_state', to)
      .where((q) => q.whereNull('lost_mode_changed_at').orWhere('lost_mode_changed_at', '<=', c.occurredAt))
      .update({ lost_mode_state: to, lost_mode_changed_at: c.occurredAt });
  };
}

let registered = false;

/** The ingestors of the lost mode (registerAppleModule, after the MVP ones). */
export function registerLostModeResultIngestors(): void {
  if (registered) return;
  registered = true;
  registerCommandResultIngestor({ requestType: 'DeviceLocation', mode: 'inline', apply: ingestDeviceLocation });
  registerCommandResultIngestor({ requestType: 'EnableLostMode', mode: 'inline', apply: lostModeAck('on') });
  registerCommandResultIngestor({ requestType: 'DisableLostMode', mode: 'inline', apply: lostModeAck('off') });
}

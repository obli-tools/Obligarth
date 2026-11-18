import type { Knex } from 'knex';
import { logger } from '../../utils/logger';

// =============================================================================
// The change marker of the devices read by Obliwatch (devices.signal_updated_at, migration
// 20261118100100_devices_signal_marker; owner decision Q-L2a). The trigger of devices marks the changes of the columns
// of devices the read API exposes, in the row being written. What it exposes from OTHER tables is marked here, by the
// writer, inside its own transaction:
//   - signalMark(trx): the value to put in an UPDATE of devices the writer already does (no extra write): AMAPI
//     posture and security patch (android/inventory/statusReport.ts), bridge agent's inventory (legacyAgent/inventory.ts);
//   - touchSignalInTx / touchEndUserDevicesInTx: an UPDATE of its own where the writer has none (first inventory of
//     the apps, the e-mail of an end user), under a savepoint: a failure is logged and swallowed, NEVER the failure of
//     the caller's report or change.
// =============================================================================

/** The value of devices.signal_updated_at for an UPDATE of devices in progress (the trigger's clock). */
export function signalMark(q: Knex | Knex.Transaction): Knex.Raw {
  return q.raw('clock_timestamp()');
}

async function guarded(trx: Knex.Transaction, what: string, fn: (sp: Knex.Transaction) => Promise<unknown>): Promise<void> {
  try {
    await trx.transaction(async (sp) => { await fn(sp); });
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, what }, 'obliwatch marker: not written (the caller goes on)');
  }
}

/** Marks devices of `tenantId` as changed for the read API (a datum of a satellite changed). Never throws. */
export async function touchSignalInTx(trx: Knex.Transaction, tenantId: number, deviceIds: number[]): Promise<void> {
  const ids = [...new Set(deviceIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  if (ids.length === 0) return;
  await guarded(trx, 'devices', (sp) => sp('devices').where({ tenant_id: tenantId }).whereIn('id', ids)
    .update({ signal_updated_at: signalMark(sp) }));
}

/** Marks the devices of end users of `tenantId` whose e-mail (primaryUpn of the read API) may have changed. Never throws. */
export async function touchEndUserDevicesInTx(trx: Knex.Transaction, tenantId: number, endUserIds: number[]): Promise<void> {
  const ids = [...new Set(endUserIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  if (ids.length === 0) return;
  await guarded(trx, 'end_user_devices', (sp) => sp('devices').where({ tenant_id: tenantId }).whereIn('end_user_id', ids)
    .update({ signal_updated_at: signalMark(sp) }));
}

// The sealed newPassword the migration android_commands_move could not open (its AAD names android_commands): sealed
// again for mdm_commands.secret_enc by the boot backfill of the vault (legacy source 'custom' of that column,
// modules/android.ts), before any job runs. Only for a RESET_PASSWORD still pending and never issued; a seal that does
// not open any more is dropped, and the submission then rejects its command (secret_lost): never a RESET_PASSWORD
// without its password, which would clear the password. Idempotent: the rows leave android_command_moved_secrets.
import { db } from '../../db';
import { asNone, asTenant, type DbActor } from '../../db/context';
import { allTenantIds } from '../../db/tenantContext';
import { logger } from '../../utils/logger';
import { isVaultError, vault } from '../../vault';
import { COMMAND_SECRET_COLUMN, MOVED_SECRET_COLUMN, patchCommand, readCommand } from './store';

const ACTOR: DbActor = Object.freeze({ type: 'job', name: 'vault.backfill' }) as DbActor;

export async function resealMovedCommandSecrets(): Promise<{ moved: number; conflicts: number; skipped: number }> {
  const out = { moved: 0, conflicts: 0, skipped: 0 };
  const r = await asNone(ACTOR, () => db.raw("SELECT to_regclass('obligarth.android_command_moved_secrets') IS NOT NULL AS present")) as
    { rows: Array<{ present: boolean }> };
  if (!r.rows[0]?.present) return out;
  for (const tenantId of await asNone(ACTOR, () => allTenantIds())) {
    await asTenant(tenantId, ACTOR, () => db.transaction(async (trx) => {
      const rows = await trx('android_command_moved_secrets').where({ tenant_id: tenantId }).forUpdate()
        .select('command_id', 'secret_enc') as Array<{ command_id: string; secret_enc: string }>;
      for (const row of rows) {
        const id = String(row.command_id).toLowerCase();
        const cmd = await readCommand(trx, tenantId, id, true);
        if (cmd && cmd.request_type === 'RESET_PASSWORD' && cmd.state === 'pending' && !cmd.amapi_operation && !cmd.secret_enc) {
          try {
            const sealed = await vault.reseal({ ...MOVED_SECRET_COLUMN, pk: id, tenantId }, { ...COMMAND_SECRET_COLUMN, pk: id, tenantId },
              row.secret_enc, { trx, requestTenantId: tenantId });
            await patchCommand(trx, tenantId, id, { secret_enc: sealed });
            out.moved += 1;
          } catch (err) {
            if (!isVaultError(err)) throw err;
            // coordinates and code only (the vault already logged and alerted)
            logger.warn({ android: { command: id, tenantId, code: err.code } }, 'android: a moved reset-password seal does not open; the command will be rejected');
            out.conflicts += 1;
          }
        }
        await trx('android_command_moved_secrets').where({ tenant_id: tenantId, command_id: id }).delete();
      }
    }));
  }
  return out;
}

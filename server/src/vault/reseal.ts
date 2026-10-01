// Reseal of the sealed values (docs: coffre-secrets §6.6): the online
// rotation of a DEK, run by the durable job vault.reencrypt-tenant (or the
// CLI's dek-rotate), and the reseal flag of the users trigger.
//
//   1. one transaction: the tenant's DEKs locked, the active one retired, a
//      new one (version + 1) active, the operation running; from then on,
//      every seal takes the new DEK (its id is re-read at each seal);
//   2. for each registered column (transient ones excepted), in the scope of
//      the DEK (scopes.ts), by slices of 500 rows, each in its own
//      transaction: SELECT … WHERE <col> LIKE 'v1:<retired id>:%' … FOR
//      UPDATE SKIP LOCKED, then reseal and compare-and-set UPDATE;
//   3. a pass without rows, a wait (60 s: requests that read the old id just
//      before step 1), a second pass without rows, and no value left under
//      the retired DEK (a plain read: the passes skip the rows another
//      transaction holds, which would otherwise be lost): the retired DEK is
//      destroyed, the operation done, vault.dek_rotated audited;
//   4. a failure: the operation 'failed' (code and coordinates), the retired
//      DEK kept (everything stays readable), an alert; the operation resumes
//      from the database (never from a cursor in memory) when the job is
//      retried or the CLI runs it again.
import { setTimeout as sleepFor } from 'node:timers/promises';
import type { Knex } from 'knex';
import { db } from '../db';
import { asNone, type DbActor } from '../db/context';
import { logger } from '../utils/logger';
import { VaultError } from './errors';
import { masterEntry, vaultAlert, writeVaultAuditInTx } from './events';
import { operationError, vaultOperations } from './operations';
import { secretColumns } from './registry';
import { scopesOf } from './scopes';
import { vault, vaultInternals, type SecretLocator } from './vault';

/** SET LOCAL obligarth.vault_reseal = 'on' (users_bump_credential_version):
 *  the TOTP secret's ciphertext changes, never its value, so the phone keys
 *  survive. The only statement of the server that sets this flag. */
export async function setResealFlag(trx: Knex.Transaction): Promise<void> {
  await trx.raw("SET LOCAL obligarth.vault_reseal = 'on'");
}

const SLICE = 500;
const SETTLE_MS = 60_000;

export interface RotationOptions {
  /** Database actor of the work (j:vault.reencrypt-tenant, j:vault.cli). */
  actor: DbActor;
  signal?: AbortSignal;
  /** Wait between the two empty passes (60 s; tests use less). */
  settleMs?: number;
}

export interface RotationResult {
  tenantId: number | null;
  retiredDekId: string;
  newDekId: string;
  resealed: Record<string, number>;
}

type Rows<T> = { rows: T[] };

function tenantOf(params: Record<string, unknown>): number | null {
  const t = params.tenantId;
  return typeof t === 'number' && Number.isSafeInteger(t) && t > 0 ? t : null;
}

/** Step 1, for an authorized operation: the new DEK becomes active. */
async function startRotation(operationId: string, actor: DbActor): Promise<void> {
  const { keyring } = vaultInternals;
  const made: { fresh?: Awaited<ReturnType<typeof keyring.newWrappedDek>>; retiredId?: string } = {};
  try {
    await asNone(actor, () => db.transaction(async (trx) => {
      const op = await vaultOperations.get(trx, operationId, { forUpdate: true });
      if (!op || op.kind !== 'dek_rotation') throw new VaultError('operation_not_authorized', null, 'unknown DEK rotation');
      if (op.state !== 'authorized') return;   // started meanwhile
      const tenantId = tenantOf(op.params);
      const keys = await trx.raw(
        `SELECT id, version, state, destroy_after FROM data_keys
          WHERE coalesce(tenant_id, 0) = coalesce(?::int, 0) ORDER BY version FOR UPDATE`, [tenantId],
      ) as Rows<{ id: string; version: number; state: string; destroy_after: Date | null }>;
      const active = keys.rows.find((k) => k.state === 'active');
      if (!active) throw new VaultError('dek_destroyed', null, 'no active data key to rotate');
      if (active.destroy_after) throw new VaultError('tenant_retiring', null, 'the tenant is being deleted');
      const version = Math.max(...keys.rows.map((k) => Number(k.version))) + 1;
      await trx('data_keys').where({ id: active.id }).update({ state: 'retired', retired_at: trx.fn.now() });
      const fresh = await keyring.newWrappedDek(tenantId, version);
      made.fresh = fresh;
      await trx('data_keys').insert({
        id: fresh.id, tenant_id: tenantId, version, kek_id: fresh.kek_id, dek_wrapped: fresh.dek_wrapped, state: 'active',
      });
      made.retiredId = active.id;
      await vaultOperations.update(trx, operationId, {
        state: 'running', startedAt: new Date(), error: null,
        params: { ...op.params, tenantId, retiredDekId: active.id, newDekId: fresh.id, newVersion: version },
      });
    }));
    made.fresh?.cache();
  } catch (err) {
    made.fresh?.discard();
    throw err;
  }
  if (made.retiredId) keyring.invalidate({ ids: [made.retiredId] });
}

/** One pass over the registry: every value still sealed under the retired
 *  DEK is resealed under the active one. Returns the count per column. */
async function pass(tenantId: number | null, retiredDekId: string, o: RotationOptions): Promise<Record<string, number>> {
  const counts: Record<string, number> = {};
  for (const def of secretColumns()) {
    if (def.transient) continue;
    const label = `${def.table}.${def.column}`;
    for (const scope of await scopesOf(def, o.actor, tenantId)) {
      for (;;) {
        o.signal?.throwIfAborted();
        const n = await scope.run(() => db.transaction(async (trx) => {
          if (def.resealFlag) await setResealFlag(trx);
          const cols = [def.pk, def.column, ...(def.tenantColumn ? [def.tenantColumn] : [])];
          const rows = await scope.filter(trx(def.table).select(cols)
            .where(def.column, 'like', `v1:${retiredDekId}:%`))
            .orderBy(def.pk).limit(SLICE).forUpdate().skipLocked() as Array<Record<string, unknown>>;
          for (const r of rows) {
            const loc: SecretLocator = {
              table: def.table, column: def.column, pk: r[def.pk] as string | number,
              tenantId: def.tenantColumn && r[def.tenantColumn] != null ? Number(r[def.tenantColumn]) : null,
            };
            const before = String(r[def.column]);
            const after = await vault.reseal(loc, loc, before, { trx });
            await trx(def.table).where(def.pk, r[def.pk] as string | number).where(def.column, before).update({ [def.column]: after });
          }
          return rows.length;
        }));
        if (n) counts[label] = (counts[label] ?? 0) + n;
        if (n < SLICE) break;
      }
    }
  }
  return counts;
}

/** Is a value of the registry (transient ones excepted) still sealed under
 *  the retired DEK? A plain read, which no row lock hides: a row another
 *  transaction held during both passes (FOR UPDATE SKIP LOCKED skips it) is
 *  still sealed under that DEK, which must not be destroyed yet (review of
 *  lot A4: the value would be lost for good). */
async function stillSealedUnder(tenantId: number | null, retiredDekId: string, o: RotationOptions): Promise<boolean> {
  for (const def of secretColumns()) {
    if (def.transient) continue;
    for (const scope of await scopesOf(def, o.actor, tenantId)) {
      o.signal?.throwIfAborted();
      const row = await scope.run(() => scope.filter(db(def.table)
        .where(def.column, 'like', `v1:${retiredDekId}:%`)).first(def.pk));
      if (row) return true;
    }
  }
  return false;
}

/** Runs (or resumes) a DEK rotation. Throws on failure, the operation then
 *  being 'failed' (resumable). */
export async function runDekRotation(operationId: string, o: RotationOptions): Promise<RotationResult> {
  vaultInternals.requireReady();
  const opBefore = await asNone(o.actor, () => vaultOperations.get(db, operationId));
  if (!opBefore || opBefore.kind !== 'dek_rotation' || !['authorized', 'running', 'failed'].includes(opBefore.state)) {
    throw new VaultError('operation_not_authorized', null, 'no authorized or running DEK rotation with this id');
  }
  try {
    if (opBefore.state === 'authorized') await startRotation(operationId, o.actor);
    const op = await asNone(o.actor, () => vaultOperations.get(db, operationId));
    if (!op || !['running', 'failed'].includes(op.state)) throw new VaultError('operation_not_authorized', null, 'the rotation is not running');
    if (op.state === 'failed') {
      await asNone(o.actor, () => vaultOperations.update(db, operationId, { state: 'running', error: null }, { fromStates: ['failed'] }));
    }
    const tenantId = tenantOf(op.params);
    const retiredDekId = String(op.params.retiredDekId ?? '');
    const newDekId = String(op.params.newDekId ?? '');
    if (!/^[0-9a-f-]{36}$/.test(retiredDekId)) throw new VaultError('format', null, 'rotation without its retired key');

    const resealed: Record<string, number> = { ...((op.progress.resealed as Record<string, number> | undefined) ?? {}) };
    const add = (c: Record<string, number>) => { for (const [k, n] of Object.entries(c)) resealed[k] = (resealed[k] ?? 0) + n; };
    for (;;) {
      const first = await pass(tenantId, retiredDekId, o);
      add(first);
      await asNone(o.actor, () => vaultOperations.update(db, operationId, { progress: { resealed } }));
      if (Object.keys(first).length) continue;
      await sleepFor(o.settleMs ?? SETTLE_MS, undefined, o.signal ? { signal: o.signal } : undefined);
      const second = await pass(tenantId, retiredDekId, o);
      add(second);
      if (Object.keys(second).length) continue;
      // Rows held by other transactions were skipped: wait for them (the
      // next passes reseal them) rather than destroy the DEK under them.
      if (!(await stillSealedUnder(tenantId, retiredDekId, o))) break;
    }

    // Step 3: the retired DEK is destroyed; nothing is sealed under it any
    // more. The entries in the same transaction (P1, critical).
    const details = { operationId, tenantId, retiredDekId, newDekId, version: op.params.newVersion ?? null, resealed, reason: op.reason };
    await asNone(o.actor, () => db.transaction(async (trx) => {
      await trx('data_keys').where({ id: retiredDekId, state: 'retired' })
        .update({ state: 'destroyed', dek_wrapped: null, destroyed_at: trx.fn.now() });
      await vaultOperations.update(trx, operationId, { state: 'done', finishedAt: new Date(), progress: { resealed }, error: null });
      await writeVaultAuditInTx(trx, [
        ...(tenantId !== null ? [{ tenantId, action: 'vault.dek_rotated', resourceType: 'vault', details }] : []),
        masterEntry('vault.dek_rotated', details, { resourceType: 'vault_operation', resourcePath: operationId }),
      ]);
    }));
    vaultInternals.keyring.invalidate({ ids: [retiredDekId] });
    logger.info({ operationId, tenantId, resealed }, 'vault: DEK rotation done');
    return { tenantId, retiredDekId, newDekId, resealed };
  } catch (err) {
    const aborted = (err as { name?: string })?.name === 'AbortError' || o.signal?.aborted;
    await asNone(o.actor, () => vaultOperations.update(db, operationId, {
      state: 'failed', error: aborted ? 'aborted' : operationError(err),
    }, { fromStates: ['authorized', 'running'] })).catch(() => undefined);
    if (!aborted) {
      logger.error({ operationId, code: (err as { code?: string })?.code ?? 'error' }, 'vault: DEK rotation failed');
      vaultAlert('vault:dek-rotation-failed', 'Vault: a key rotation failed',
        'A data key rotation failed: the old key is kept and everything stays readable. See the vault operations.');
    }
    throw err;
  }
}

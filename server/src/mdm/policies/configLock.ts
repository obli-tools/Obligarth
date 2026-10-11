import { AsyncLocalStorage } from 'node:async_hooks';
import type { Knex } from 'knex';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';

// =============================================================================
// One writer of the configuration of a tenant at a time (docs:
// modele-donnees-mdm §7.11, §7.12; review of lot B5b, MDM-B5b-C1). A change
// of the effective configuration (a version published, a batch of assignment
// changes, a policy archived, a group moved in the tree or deleted) is decided
// on a preview: the devices it touches say whether a second factor is enough
// or a second approver is required (DM23). Two changes of the same tenant made
// at the same time would each be previewed on the state before the other. So
// every writer takes this lock first, in the transaction that writes, and
// decides there, on a preview computed after the lock: what the other wrote is
// then committed and read.
//   - lockTenantConfiguration(trx, tenantId): the transaction lock itself
//     (released at the commit or the rollback), taken again without harm by a
//     function called in a transaction that holds it;
//   - withConfigurationLock(tenantId, fn): a transaction that holds the lock.
//     The writers of one process wait for each other in memory, without a
//     connection: a burst of requests on one tenant never drains the pool that
//     serves every tenant. The transaction lock then orders the processes.
// Order of the locks, everywhere: this one, then the row of a policy, then the
// row of its version.
// =============================================================================

/** Namespace of the lock (two-key advisory locks, as the resolution's 'MDPR'). */
const CONFIGURATION_LOCK_SPACE = 0x4d445043;   // 'MDPC'

/** Writers of one tenant in line in this process, the one at work included. */
const MAX_IN_LINE = 32;

interface Held { readonly tenantId: number; active: boolean }

const tails = new Map<number, Promise<void>>();
const inLine = new Map<number, number>();
const holding = new AsyncLocalStorage<readonly Held[]>();

/** The lock of the configuration of a tenant, held until the end of `trx`. */
export async function lockTenantConfiguration(trx: Knex.Transaction, tenantId: number): Promise<void> {
  await trx.raw('SELECT pg_advisory_xact_lock(?::integer, ?::integer)', [CONFIGURATION_LOCK_SPACE, tenantId]);
}

/**
 * Runs `fn` in a transaction that holds the lock of the configuration of `tenantId`, in the caller's database
 * context. Never called by a function that already runs under it for the same tenant (its transaction is passed
 * instead): a second transaction would wait for the first one for ever, so this is refused at once.
 */
export async function withConfigurationLock<T>(tenantId: number, fn: (trx: Knex.Transaction) => Promise<T>): Promise<T> {
  if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new Error('withConfigurationLock: invalid tenant');
  const outer = holding.getStore() ?? [];
  if (outer.some((h) => h.active && h.tenantId === tenantId)) {
    throw new Error('withConfigurationLock: already held for this tenant (pass the open transaction)');
  }
  const count = inLine.get(tenantId) ?? 0;
  if (count >= MAX_IN_LINE) {
    throw new AppError(429, 'Too many changes of the configuration of this tenant are waiting: try again', 'configurationBusy');
  }
  inLine.set(tenantId, count + 1);
  const previous = tails.get(tenantId) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((resolve) => { release = resolve; });
  const tail = previous.then(() => mine);
  tails.set(tenantId, tail);
  const held: Held = { tenantId, active: true };
  try {
    await previous;
    return await holding.run([...outer, held], () => db.transaction(async (trx) => {
      await lockTenantConfiguration(trx, tenantId);
      return fn(trx);
    }));
  } finally {
    held.active = false;
    release();
    const left = (inLine.get(tenantId) ?? 1) - 1;
    if (left > 0) inLine.set(tenantId, left); else inLine.delete(tenantId);
    if (tails.get(tenantId) === tail) tails.delete(tenantId);
  }
}

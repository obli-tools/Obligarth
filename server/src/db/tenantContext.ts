import type { Knex } from 'knex';
import { db } from './index';
import {
  DbContextDeniedError, DbContextMissingError, LEASE_SEARCH_PATH, actorToken, asNone, asTenant, assertValidContext, currentDbContext,
  encodeContext, leaseKey, runWithDbContext, type DbActor, type DbContext,
} from './context';
import type { PgConnection } from './contextPgClient';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';

// =============================================================================
// Tenant contexts of background work (rls-tenant §4.5, §7.6; file-durable §5.8)
// =============================================================================

/** A transaction in one tenant: what FND-04's ctx.withTenant(fn) calls. The
 *  lease itself carries the tenant (the ALS context is set before
 *  db.transaction acquires its connection). */
export function withTenantTransaction<T>(
  tenantId: number, actor: DbActor, fn: (trx: Knex.Transaction) => Promise<T>,
): Promise<T> {
  return asTenant(tenantId, actor, () => db.transaction((trx) => fn(trx)));
}

// Transaction-local switch of the context (rls-tenant §4.5). Lot A8: the role
// and the search_path are set again with it, so that what an injected
// statement left in the transaction (SET LOCAL ROLE, SET LOCAL search_path
// towards pgboss) does not reach the next event of the same transaction.
const SET_LOCAL_WITH_ROLE_SQL =
  "SELECT set_config('role', ?, true), set_config('obligarth.ctx', ?, true), set_config('obligarth.ctx_sig', ?, true), " +
  "set_config('search_path', ?, true)";

/** Alphabet of the values of a context (role, context text, signature,
 *  search_path): what encodeContext produces from a valid context. */
const CONTEXT_LITERAL_RE = /^[A-Za-z0-9_.:|, -]*$/;

/** The statement applyTenantContext sends, its values written as literals,
 *  for a transaction that switches its context once per event in a single
 *  round trip joined to the event's SAVEPOINT (outbox consumer,
 *  jobs/outbox/apply.ts: file-durable L2). The values are the context's own
 *  (role name, context text, HMAC signature, search_path), built here from a
 *  checked context and refused outside their alphabet before being quoted:
 *  no caller value reaches the SQL. tenantId null: no tenant. */
export function tenantContextStatement(tenantId: number | null, actor: DbActor): string {
  const ctx: DbContext = tenantId === null
    ? { kind: 'none', tenantId: null, actor, grantId: null, origin: 'job' }
    : { kind: 'tenant', tenantId, actor, grantId: null, origin: 'job' };
  assertValidContext(ctx);
  const enc = encodeContext(ctx);
  const lit = (v: string): string => {
    if (!CONTEXT_LITERAL_RE.test(v)) throw new DbContextDeniedError('context value outside its alphabet');
    return `'${v}'`;
  };
  return `SELECT set_config('role', ${lit(enc.role)}, true), set_config('obligarth.ctx', ${lit(enc.ctx)}, true), `
    + `set_config('obligarth.ctx_sig', ${lit(enc.sig)}, true), set_config('search_path', ${lit(LEASE_SEARCH_PATH)}, true)`;
}

/** Low level, for a transaction that serves several tenants one after the
 *  other (outbox consumer, inside its SAVEPOINT per event): transaction-local
 *  context, reverted by ROLLBACK TO SAVEPOINT. The Node context is not
 *  changed: the work must go through trx (a db(...) call would open a new
 *  lease in the consumer's context, 'none', and see no tenant row).
 *  tenantId null: no tenant. */
export async function applyTenantContext(trx: Knex.Transaction, tenantId: number | null, actor: DbActor): Promise<void> {
  const ctx: DbContext = tenantId === null
    ? { kind: 'none', tenantId: null, actor, grantId: null, origin: 'job' }
    : { kind: 'tenant', tenantId, actor, grantId: null, origin: 'job' };
  assertValidContext(ctx);
  const enc = encodeContext(ctx);
  await trx.raw(SET_LOCAL_WITH_ROLE_SQL, [enc.role, enc.ctx, enc.sig, LEASE_SEARCH_PATH]);
}

/** The connection of a transaction (Knex 3.3.0: its client lends it). */
async function connectionOf(trx: Knex.Transaction): Promise<PgConnection> {
  return (trx as unknown as { client: { acquireConnection(): Promise<PgConnection> } }).client.acquireConnection();
}

const SAVEPOINT = 'obligarth_tenant_switch';

/** Same, with its own SAVEPOINT, the Node context switched for fn (lease key
 *  updated for the consistency check) and the outer context restored after
 *  RELEASE (rls-tenant §4.5). On failure: ROLLBACK TO SAVEPOINT, which also
 *  reverts the transaction-local context, and the error is rethrown. */
export async function withTenantInTransaction<T>(
  trx: Knex.Transaction, tenantId: number, actor: DbActor, fn: () => Promise<T>,
): Promise<T> {
  const outer = currentDbContext();
  if (!outer) throw new DbContextMissingError();
  const inner: DbContext = { kind: 'tenant', tenantId, actor, grantId: null, origin: outer.origin, requestId: outer.requestId };
  assertValidContext(inner);
  const conn = await connectionOf(trx);
  const outerLease = conn.__obligarthLease;
  await trx.raw(`SAVEPOINT ${SAVEPOINT}`);
  const encIn = encodeContext(inner);
  await trx.raw(SET_LOCAL_WITH_ROLE_SQL, [encIn.role, encIn.ctx, encIn.sig, LEASE_SEARCH_PATH]);
  conn.__obligarthLease = leaseKey(inner);
  let result: T;
  try {
    result = await runWithDbContext(inner, fn);
  } catch (err) {
    conn.__obligarthLease = outerLease;
    await trx.raw(`ROLLBACK TO SAVEPOINT ${SAVEPOINT}`);
    throw err;
  }
  conn.__obligarthLease = outerLease;
  await trx.raw(`RELEASE SAVEPOINT ${SAVEPOINT}`);
  const encOut = encodeContext(outer);
  await trx.raw(SET_LOCAL_WITH_ROLE_SQL, [encOut.role, encOut.ctx, encOut.sig, LEASE_SEARCH_PATH]);
  return result;
}

// ── Platform jobs that work tenant by tenant (jobs/, rls-tenant §7.6) ──────
// A durable job runs in its own context ('none', actor j:<queue>: the
// execution envelope, jobs/wrapper.ts); one that visits every tenant lists
// them, then works in each tenant's context in turn.

/** The ids of every tenant (obligarth.tenant_ids_all(), callable in any
 *  context: ids only). */
export async function allTenantIds(): Promise<number[]> {
  const res = await db.raw('SELECT obligarth.tenant_ids_all() AS ids') as { rows: Array<{ ids: number[] | null }> };
  return (res.rows[0]?.ids ?? []).map(Number);
}

/** Runs fn once per tenant, each run in the tenant's own context (its
 *  statements are leases of that tenant only); failures are counted and
 *  logged, never stopping the other tenants. */
export async function forEachTenant(
  actor: DbActor, fn: (tenantId: number) => Promise<void>,
): Promise<{ ok: number; failed: number }> {
  const ids = await asNone(actor, () => allTenantIds());
  let ok = 0;
  let failed = 0;
  for (const tenantId of ids) {
    try {
      await asTenant(tenantId, actor, () => fn(tenantId));
      ok++;
    } catch (err) {
      failed++;
      logger.warn({ err: safeErr(err), tenantId, actor: actorToken(actor) }, 'per-tenant job step failed');
    }
  }
  return { ok, failed };
}

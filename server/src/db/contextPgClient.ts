import ClientPG from 'knex/lib/dialects/postgres';
import {
  DbContextMismatchError, DbContextMissingError, contextAssertMode, contextMode, countContextMismatch,
  countContextMissing, currentDbContext, encodeContext, leaseKey, type DbContext,
} from './context';
import { logger } from '../utils/logger';

// =============================================================================
// Knex client that sets the database context at every lease (rls-tenant §4.4)
// =============================================================================
//
// A lease is a Knex transaction (its connection is acquired once, before
// BEGIN) or one statement in autocommit. At each acquisition, before any
// statement of the lease, one round trip sets the role and the context of
// the current AsyncLocalStorage context (bound parameters: never in
// pg_stat_activity nor in the server logs). No cache, no reset on release:
// every lease writes all three values (R4), so a connection back in the pool
// with the context of another request is never used without being rewritten.
//
// Knex 3.3.0 is pinned: these overrides rely on its internals
// (acquireConnection, releaseConnection, _query, _stream).

/** A pg.Client as Knex lends it, with Knex's and our markers. */
export interface PgConnection {
  query(config: { text: string; values: unknown[] }, cb: (err: Error | null) => void): void;
  __knex__disposed?: unknown;
  __obligarthLease?: string;
}

const SET_CONTEXT_SQL =
  "SELECT set_config('role', $1, false), set_config('obligarth.ctx', $2, false), set_config('obligarth.ctx_sig', $3, false)";

/** Context of a query issued without one while DB_CONTEXT_MODE=audit: run
 *  in 'none' (catalogs and own rows only once the RLS is active). */
const UNSCOPED: DbContext = {
  kind: 'none', tenantId: null, actor: { type: 'anonymous', name: 'unscoped' }, grantId: null, origin: 'request',
};

function exec(conn: PgConnection, text: string, values: unknown[]): Promise<void> {
  return new Promise((resolve, reject) => conn.query({ text, values }, (err) => (err ? reject(err) : resolve())));
}

// ── Queries without context (DB_CONTEXT_MODE=audit) ─────────────────────────
// Every one is logged (the site's first occurrences, then one in a hundred):
// the conversion of a code path is complete when none is left. A Knex
// builder runs when it is awaited, from a microtask: the stack at that time
// no longer shows the code that built it. In audit mode only, the builders,
// raw statements and transactions record where they were created, and the
// lease reports that site.

const missingBySite = new Map<string, number>();

function callSite(stack: string): string {
  const frames = stack.split('\n').slice(1).map((l) => l.trim())
    .filter((l) => !l.includes('node_modules') && !l.includes('contextPgClient') && !l.includes('node:internal')
      && !l.startsWith('at async Promise.all'));
  return frames.slice(0, 4).join(' | ') || 'unknown';
}

/** Creation site of the builder whose lease is being acquired (audit mode). */
let pendingSite: string | undefined;

function captureSite(): string {
  return callSite(new Error('created').stack ?? '');
}

function reportMissingContext(): void {
  countContextMissing();
  const stack = new Error('database query without context').stack ?? '';
  const site = pendingSite ?? callSite(stack);
  const n = (missingBySite.get(site) ?? 0) + 1;
  if (missingBySite.size < 1000 || missingBySite.has(site)) missingBySite.set(site, n);
  if (n <= 3 || n % 100 === 0) {
    logger.warn({ code: 'DB_CONTEXT_MISSING', occurrences: n, site, stack }, 'database query without context');
  }
}

type WithSite = { __obligarthSite?: string };

/** Runs a synchronous call with the creation site of `site` pending (the
 *  lease is acquired synchronously at the start of the call). */
function withPendingSite<T>(site: string | undefined, call: () => T): T {
  if (!site) return call();
  const previous = pendingSite;
  pendingSite = site;
  try {
    return call();
  } finally {
    pendingSite = previous;
  }
}

// ── Lease consistency ───────────────────────────────────────────────────────
// A statement on a lease opened in another context (code that reuses a trx
// across contexts): DB_CONTEXT_MISMATCH, thrown in test and development,
// logged in production (rate limited by call site).

const mismatchLogged = new Map<string, number>();

function checkLease(conn: PgConnection): void {
  // Raw connections opened by Knex itself (query cancellation) carry no lease.
  if (contextAssertMode() === 'off' || conn.__obligarthLease === undefined) return;
  const ctx = currentDbContext() ?? (contextMode() === 'audit' ? UNSCOPED : undefined);
  if (ctx && conn.__obligarthLease === leaseKey(ctx)) return;
  countContextMismatch();
  const err = new DbContextMismatchError(conn.__obligarthLease, ctx ? leaseKey(ctx) : undefined);
  if (contextAssertMode() === 'throw') throw err;
  const site = callSite(err.stack ?? '');
  const n = (mismatchLogged.get(site) ?? 0) + 1;
  if (mismatchLogged.size < 1000 || mismatchLogged.has(site)) mismatchLogged.set(site, n);
  if (n <= 3 || n % 100 === 0) logger.warn({ err, occurrences: n }, 'database context mismatch');
}

export class ContextAwarePgClient extends ClientPG {
  // Audit mode only: where builders, raw statements and transactions are
  // created (see "Queries without context" above).
  queryBuilder(): any {
    const builder = super.queryBuilder() as unknown as WithSite;
    if (contextMode() === 'audit') builder.__obligarthSite = captureSite();
    return builder;
  }

  raw(...args: any[]): any {
    const raw = super.raw(...args) as WithSite;
    if (contextMode() === 'audit') raw.__obligarthSite = captureSite();
    return raw;
  }

  runner(builder: any): any {
    const runner = super.runner(builder);
    const site = (builder as WithSite | undefined)?.__obligarthSite;
    if (site) {
      const ensure = runner.ensureConnection.bind(runner);
      runner.ensureConnection = (cb: unknown, params: unknown) => withPendingSite(site, () => ensure(cb, params));
    }
    return runner;
  }

  transaction(container: any, config: any, outerTx: any): any {
    const trx = super.transaction(container, config, outerTx) as any;
    if (contextMode() === 'audit' && trx && typeof trx.acquireConnection === 'function') {
      const site = captureSite();
      const acquire = trx.acquireConnection.bind(trx);
      trx.acquireConnection = (cfg: unknown, cb: unknown) => withPendingSite(site, () => acquire(cfg, cb));
    }
    return trx;
  }

  async acquireConnection(): Promise<PgConnection> {
    let ctx = currentDbContext();                                  // read before any await
    if (!ctx) {
      if (contextMode() !== 'audit') {
        countContextMissing();
        throw new DbContextMissingError();
      }
      reportMissingContext();
      ctx = UNSCOPED;
    }
    const enc = encodeContext(ctx);
    const lease = leaseKey(ctx);
    const conn: PgConnection = await super.acquireConnection();
    try {
      await exec(conn, SET_CONTEXT_SQL, [enc.role, enc.ctx, enc.sig]);
    } catch (err) {
      conn.__knex__disposed = err;                                 // the pool drops it at the next validation
      await super.releaseConnection(conn);
      throw err;
    }
    conn.__obligarthLease = lease;
    return conn;
  }

  releaseConnection(conn: PgConnection): Promise<void> {
    conn.__obligarthLease = undefined;
    return super.releaseConnection(conn);
  }

  // Every statement of this Knex instance, transactions included (their
  // client is created from this prototype), runs through one of these two.
  _query(conn: PgConnection, obj: unknown): Promise<unknown> {
    checkLease(conn);
    return super._query(conn, obj);
  }

  _stream(conn: PgConnection, obj: unknown, stream: unknown, options: unknown): Promise<unknown> {
    checkLease(conn);
    return super._stream(conn, obj, stream, options);
  }
}

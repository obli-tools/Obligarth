import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, createHmac } from 'node:crypto';
import { closeSync, constants as fsConstants, existsSync, fstatSync, openSync, readSync } from 'node:fs';
import { config } from '../config';

// =============================================================================
// Database context (row level security, docs: rls-tenant §4, §7.3)
// =============================================================================
//
// Every lease of a pooled connection (a transaction, or one statement in
// autocommit) runs in a context carried by AsyncLocalStorage: the derived
// Knex client (contextPgClient.ts) writes it into the session variable
// `obligarth.ctx` (and the role) before the lease starts, the policies read
// it through the obligarth.ctx_* functions. A query issued without a context
// fails (DB_CONTEXT_MISSING) instead of running unscoped.
//
// Kinds:
//   tenant    one tenant, read and write (role obligarth);
//   member    read of the tenants the user is a member of (obligarth_reader);
//   platform  read of every tenant, with a journaled grant (obligarth_reader);
//   identity  accounts and platform settings, no tenant data;
//   none      catalogs and the actor's own rows only.
//
// Signed mode (rls-tenant §4.6, R12; migration D): the context carries an
// expiry and travels with its HMAC-SHA256 (obligarth.ctx_sig) under the key
// of RLS_CONTEXT_KEY_FILE, which server-migrate deposits in the database;
// obligarth.ctx_raw() refuses a context whose signature, key or expiry does
// not hold, so an injected set_config no longer opens another tenant.
//
// Only this file, contextPgClient.ts and tenantContext.ts set obligarth.ctx,
// the role or the search_path: application code never runs SET, RESET,
// DISCARD, SET ROLE nor set_config (one exception, vault/reseal.ts: SET
// LOCAL obligarth.vault_reseal; checked by the testbed, essai 118).

export type DbContextKind = 'tenant' | 'member' | 'platform' | 'identity' | 'none';

export type DbActor =
  | { readonly type: 'user'; readonly userId: number }
  | { readonly type: 'job'; readonly name: string }          // 'devices.fleetDaily'
  | { readonly type: 'integration'; readonly name: string }  // 'obligate', 'apple-edge'
  | { readonly type: 'enrollment'; readonly name: string }   // 'enroll', 'ade-web'
  | { readonly type: 'anonymous'; readonly name: string };   // 'http', 'login', 'repo'

export interface DbContext {
  readonly kind: DbContextKind;
  readonly tenantId: number | null;            // kind 'tenant' only
  readonly actor: DbActor;
  readonly grantId: string | null;             // kind 'platform' only
  readonly origin: 'request' | 'socket' | 'job' | 'integration' | 'boot' | 'test';
  readonly requestId?: string;
}

export interface EncodedContext {
  readonly role: 'none' | 'obligarth_reader';
  readonly ctx: string;
  readonly sig: string;                        // '' in plain mode
}

export class DbContextMissingError extends Error {
  readonly code = 'DB_CONTEXT_MISSING';
  constructor(message = 'database query without a database context (DB_CONTEXT_MISSING)') {
    super(message);
    this.name = 'DbContextMissingError';
  }
}

export class DbContextMismatchError extends Error {
  readonly code = 'DB_CONTEXT_MISMATCH';
  constructor(readonly lease: string | undefined, readonly current: string | undefined) {
    super(`database statement on a lease of another context (lease ${lease ?? 'none'}, current ${current ?? 'none'})`);
    this.name = 'DbContextMismatchError';
  }
}

export class DbContextDeniedError extends Error {
  readonly code = 'DB_CONTEXT_DENIED';
  constructor(message = 'database context denied') {
    super(message);
    this.name = 'DbContextDeniedError';
  }
}

const ACTOR_PREFIX = { user: 'u', job: 'j', integration: 'i', enrollment: 'e', anonymous: 'a' } as const;
const NAME_RE = /^[A-Za-z0-9._:-]{1,62}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KINDS: ReadonlySet<string> = new Set(['tenant', 'member', 'platform', 'identity', 'none']);
const ORIGINS: ReadonlySet<string> = new Set(['request', 'socket', 'job', 'integration', 'boot', 'test']);
/** Lifetime of a signed context (signed mode only): no transaction of the
 *  server lasts that long (idle_in_transaction_session_timeout is 60 s). */
const CONTEXT_TTL_SECONDS = 30 * 60;
/** Largest tenant id the SQL format accepts ([0-9]{0,10}) and an integer
 *  column holds. */
const MAX_INT = 2147483647;

const als = new AsyncLocalStorage<DbContext>();

/** `u:<id>`, `j:<name>`, `i:<name>`, `e:<name>`, `a:<name>`; throws
 *  DbContextDeniedError for an invalid actor. */
export function actorToken(actor: DbActor): string {
  if (!actor || typeof actor !== 'object' || !Object.prototype.hasOwnProperty.call(ACTOR_PREFIX, actor.type)) {
    throw new DbContextDeniedError('invalid actor');
  }
  if (actor.type === 'user') {
    if (!(Number.isSafeInteger(actor.userId) && actor.userId > 0 && actor.userId <= MAX_INT)) {
      throw new DbContextDeniedError('invalid actor user');
    }
    return `u:${actor.userId}`;
  }
  if (typeof actor.name !== 'string' || !NAME_RE.test(actor.name)) {
    throw new DbContextDeniedError(`invalid actor ${actor.type}`);
  }
  return `${ACTOR_PREFIX[actor.type]}:${actor.name}`;
}

/** Validation of the invariants of a context (kind ↔ tenant ↔ grant ↔
 *  actor); throws DbContextDeniedError. */
export function assertValidContext(ctx: DbContext): void {
  if (!ctx || typeof ctx !== 'object' || !KINDS.has(ctx.kind)) throw new DbContextDeniedError('invalid context kind');
  if (!ORIGINS.has(ctx.origin)) throw new DbContextDeniedError('invalid context origin');
  actorToken(ctx.actor);
  if (ctx.kind === 'tenant') {
    if (!(Number.isSafeInteger(ctx.tenantId) && (ctx.tenantId as number) > 0 && (ctx.tenantId as number) <= MAX_INT)) {
      throw new DbContextDeniedError('a tenant context needs a positive tenant id');
    }
  } else if (ctx.tenantId !== null) {
    throw new DbContextDeniedError(`a ${ctx.kind} context has no tenant`);
  }
  if (ctx.kind === 'platform') {
    if (typeof ctx.grantId !== 'string' || !UUID_RE.test(ctx.grantId)) {
      throw new DbContextDeniedError('a platform context needs a grant');
    }
    if (ctx.actor.type !== 'user' && ctx.actor.type !== 'job' && ctx.actor.type !== 'integration') {
      throw new DbContextDeniedError('a platform context is opened by a user, a job or an integration');
    }
  } else if (ctx.grantId !== null) {
    throw new DbContextDeniedError(`a ${ctx.kind} context has no grant`);
  }
  if (ctx.kind === 'member' && ctx.actor.type !== 'user') {
    throw new DbContextDeniedError('a member context is a user\'s');
  }
}

/** What a lease is: two statements may share a lease only in the same
 *  context (contextPgClient.ts, DB_CONTEXT_MISMATCH). */
export function leaseKey(ctx: DbContext): string {
  return [ctx.kind, ctx.tenantId ?? '', actorToken(ctx.actor), ctx.grantId ?? ''].join('|');
}

// ── Signing (rls-tenant §4.6, R12) ──────────────────────────────────────────

let signingKey: { kid: string; key: Buffer } | null = null;

/** The key id of a signing key: 16 first hex characters of SHA-256(key). */
export function contextKeyId(key: Buffer): string {
  return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

/** At start (index.ts, the CLIs), from RLS_CONTEXT_KEY_FILE; null: plain
 *  mode (refused by the boot guard once migration D is applied). */
export function configureContextSigning(key: Buffer | null): void {
  if (key !== null && key.length < 32) throw new Error('the database context key must be at least 32 bytes long');
  signingKey = key ? { kid: contextKeyId(key), key } : null;
}

export function contextSigningEnabled(): boolean {
  return signingKey !== null;
}

/** The kid of the configured signing key (null: plain mode), for messages:
 *  never the key. */
export function contextSigningKeyId(): string | null {
  return signingKey?.kid ?? null;
}

/** Largest context key file read (a key is 32 bytes, 44 in base64). */
const CONTEXT_KEY_FILE_MAX_BYTES = 1024;

/** Does a setting that should name a key file hold a key instead (64+ hex
 *  characters, or base64 of 32 bytes or more)? Such a value is never used as
 *  a file name nor repeated in a message (hardening, lot A8: the vault's KEK
 *  setting got the same rule at the review of lot A2). */
export function looksLikeContextKey(value: string): boolean {
  if (typeof value !== 'string') return false;
  const compact = value.replace(/\s+/g, '');
  if (/^[0-9A-Fa-f]{64,}$/.test(compact)) return true;
  return /^[A-Za-z0-9+/_-]{43,}={0,2}$/.test(compact) && Buffer.from(compact, 'base64').length >= 32;
}

/** A key file (RLS_CONTEXT_KEY_FILE, Docker secret rls_context_key): 64+
 *  hex characters or base64 text are decoded, anything else is taken as
 *  raw bytes; at least 32 bytes. No file name: null. The messages never
 *  carry the file's content, nor the setting when it holds a key instead of
 *  a path; a file that is not a regular one (a named pipe would block the
 *  start) is refused. `setting`: the variable named in the messages. */
export function loadContextKeyFile(file: string | undefined | null, setting = 'RLS_CONTEXT_KEY_FILE'): Buffer | null {
  if (!file) return null;
  if (!existsSync(file) && looksLikeContextKey(file)) {
    throw new Error(`${setting} names no file and looks like a key (value not shown): give the path of the key file`);
  }
  let fd: number;
  try {
    // O_NONBLOCK: a named pipe is refused below (not a regular file) instead of blocking the start.
    fd = openSync(file, fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0));
  } catch (err) {
    const code = (err as { code?: string }).code;
    throw new Error(`${setting} ${file}: ${code === 'ENOENT' ? 'no such file' : code === 'EISDIR' ? 'not a regular file'
      : code === 'EACCES' || code === 'EPERM' ? 'permission denied' : 'unreadable'}`);
  }
  const buf = Buffer.alloc(CONTEXT_KEY_FILE_MAX_BYTES + 1);
  let size = 0;
  try {
    if (!fstatSync(fd).isFile()) throw new Error(`${setting} ${file}: not a regular file`);
    for (;;) {
      const n = readSync(fd, buf, size, buf.length - size, null);
      if (n === 0) break;
      size += n;
      if (size > CONTEXT_KEY_FILE_MAX_BYTES) throw new Error(`${setting} ${file}: too large for a context key file`);
    }
  } finally {
    closeSync(fd);
  }
  const raw = Buffer.from(buf.subarray(0, size));
  buf.fill(0);
  const text = raw.toString('utf8').trim();
  let key: Buffer;
  if (/^[0-9a-fA-F]{64,}$/.test(text) && text.length % 2 === 0) key = Buffer.from(text, 'hex');
  else if (/^[A-Za-z0-9+/]{43,}={0,2}$/.test(text)) key = Buffer.from(text, 'base64');
  else key = raw;
  if (key !== raw) raw.fill(0);
  if (key.length < 32) {
    key.fill(0);
    throw new Error(`${setting} ${file}: the database context key must be at least 32 bytes long`);
  }
  return key;
}

/** The signing of index.ts and of the commands that query as the runtime
 *  role (vault and audit CLIs): the key of RLS_CONTEXT_KEY_FILE, or plain
 *  mode without one (refused by the boot guard once migration D is applied).
 *  Returns the kid configured (null: plain mode); throws a message that
 *  never carries a key. */
export function configureContextSigningFromFile(file: string | undefined | null): string | null {
  const key = loadContextKeyFile(file);
  configureContextSigning(key);
  return key ? contextKeyId(key) : null;
}

/** search_path of every lease (rls-tenant §4.4, lot A8): the schema of the
 *  brain, then the session's temporary schema, last, so that a temporary
 *  table never stands for a table of the brain; set again at every lease, so
 *  that a search_path changed by an injected statement never reaches the
 *  next lease of the same pooled connection. */
export const LEASE_SEARCH_PATH = 'obligarth, pg_temp';

/** DB_CONTEXT_ASSERT: 'throw' in test and development, 'log' in production. */
export const contextAssertMode = (): 'throw' | 'log' | 'off' => config.dbContextAssert;

/** DB_CONTEXT_MODE: 'strict' (a query without a context fails) or 'audit'
 *  (logged, then run in the context 'none'), see contextPgClient.ts. */
export const contextMode = (): 'strict' | 'audit' => (config.dbContextMode === 'audit' ? 'audit' : 'strict');

/** The three values a lease sets: role, context, signature. */
export function encodeContext(ctx: DbContext, now = Math.floor(Date.now() / 1000)): EncodedContext {
  const exp = signingKey ? now + CONTEXT_TTL_SECONDS : 0;
  const ctxText = ['v1', ctx.kind, ctx.kind === 'tenant' ? String(ctx.tenantId) : '', actorToken(ctx.actor),
    ctx.kind === 'platform' ? ctx.grantId : '', String(exp)].join('|');
  const sig = signingKey ? `${signingKey.kid}.${createHmac('sha256', signingKey.key).update(ctxText).digest('hex')}` : '';
  return { role: ctx.kind === 'member' || ctx.kind === 'platform' ? 'obligarth_reader' : 'none', ctx: ctxText, sig };
}

// ── Current context ─────────────────────────────────────────────────────────

export const currentDbContext = (): DbContext | undefined => als.getStore();

/** The actor of the current context; DbContextMissingError without one. */
export function currentActor(): DbActor {
  const ctx = als.getStore();
  if (!ctx) throw new DbContextMissingError('no database context: no actor');
  return ctx.actor;
}

export const userActor = (userId: number): DbActor => ({ type: 'user', userId: Number(userId) });

const originOf = (actor: DbActor): DbContext['origin'] =>
  actor.type === 'job' ? 'job' : actor.type === 'integration' ? 'integration' : 'request';

/** Runs fn in ctx. The await happens inside the scope: Knex builders are
 *  lazy thenables (a builder returned unawaited would run outside it). An
 *  invalid context rejects (DbContextDeniedError), never throws: callers
 *  outside an async function (socket events) only see promises. */
export function runWithDbContext<T>(ctx: DbContext, fn: () => T | PromiseLike<T>): Promise<T> {
  try {
    assertValidContext(ctx);
  } catch (err) {
    return Promise.reject(err);
  }
  return als.run(ctx, async () => await fn());
}

/** Express and Socket.io middlewares: the rest of the chain runs in ctx. */
export function enterDbContext(ctx: DbContext, next: () => void): void {
  assertValidContext(ctx);
  als.run(ctx, next);
}

/** Origin and request id of the current context, kept when the kind changes. */
function inherited(actor: DbActor): Pick<DbContext, 'origin' | 'requestId'> {
  const cur = als.getStore();
  return cur && leaseActorEquals(cur.actor, actor)
    ? { origin: cur.origin, requestId: cur.requestId }
    : { origin: originOf(actor) };
}

function leaseActorEquals(a: DbActor, b: DbActor): boolean {
  try { return actorToken(a) === actorToken(b); } catch { return false; }
}

export const asTenant = <T>(tenantId: number, actor: DbActor, fn: () => T | PromiseLike<T>): Promise<T> =>
  runWithDbContext({ kind: 'tenant', tenantId, actor, grantId: null, ...inherited(actor) }, fn);
export const asIdentity = <T>(actor: DbActor, fn: () => T | PromiseLike<T>): Promise<T> =>
  runWithDbContext({ kind: 'identity', tenantId: null, actor, grantId: null, ...inherited(actor) }, fn);
export const asNone = <T>(actor: DbActor, fn: () => T | PromiseLike<T>): Promise<T> =>
  runWithDbContext({ kind: 'none', tenantId: null, actor, grantId: null, ...inherited(actor) }, fn);
export const asMember = <T>(userId: number, fn: () => T | PromiseLike<T>): Promise<T> => {
  const actor = userActor(userId);
  return runWithDbContext({ kind: 'member', tenantId: null, actor, grantId: null, ...inherited(actor) }, fn);
};
export const asPlatform = <T>(grant: { id: string; actor: DbActor }, fn: () => T | PromiseLike<T>): Promise<T> =>
  runWithDbContext({ kind: 'platform', tenantId: null, actor: grant.actor, grantId: grant.id, ...inherited(grant.actor) }, fn);

// Same actor, another kind: the current context's actor carries over (a
// service that must write an account, or a tenant's row, on behalf of the
// caller of the current context). DbContextMissingError without a context.
export const switchToTenant = <T>(tenantId: number, fn: () => T | PromiseLike<T>): Promise<T> =>
  asTenant(tenantId, currentActor(), fn);
export const switchToIdentity = <T>(fn: () => T | PromiseLike<T>): Promise<T> => asIdentity(currentActor(), fn);
export const switchToNone = <T>(fn: () => T | PromiseLike<T>): Promise<T> => asNone(currentActor(), fn);

// ── Counters (instant view for FND-14) ──────────────────────────────────────

const counters = { missing: 0, mismatch: 0, rlsDenied: new Map<string, number>() };

export function countContextMissing(): void { counters.missing++; }
export function countContextMismatch(): void { counters.mismatch++; }
export function countRlsDenied(table: string): void {
  const key = /^[a-z_][a-z0-9_]{0,62}$/.test(table) ? table : 'unknown';
  counters.rlsDenied.set(key, (counters.rlsDenied.get(key) ?? 0) + 1);
}

/** obligarth_db_context_missing_total, obligarth_db_context_mismatch_total,
 *  obligarth_rls_denied_total{table}. */
export function dbContextMetrics(): { missing: number; mismatch: number; rlsDenied: Record<string, number> } {
  return { missing: counters.missing, mismatch: counters.mismatch, rlsDenied: Object.fromEntries(counters.rlsDenied) };
}

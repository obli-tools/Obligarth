// API of the server's vault (docs: coffre-secrets §5.6, §6): every secret the
// server stores is sealed under the data key (DEK) of the tenant that owns its
// row, or under the instance DEK, with an AAD that binds it to its table,
// column, row and tenant. The DEKs are wrapped by the KEK (kek.ts), never
// stored in clear.
//
// Rules for the callers (normative, coffre-secrets §5.6):
//   R1 the tenant of a locator comes from the row in the database, read in
//      the same transaction (FOR UPDATE before a write), never from the
//      session or the body of a request; in a request, pass requestTenantId
//      (and globalView for the master tenant's global view);
//   R2 a secret leaves the server only towards its technical recipient, never
//      towards the browser;
//   R3 never a secret nor a sealed value in a log, an error, the audit
//      journal, an approval's payload, an event, a job, an alert, a metric
//      or an API answer;
//   R4 open at the last moment, keep no clear secret in a cache;
//   R5 a write that moves a row to another tenant reseals in the same
//      transaction;
//   R6 the mappers never expose a column *_enc;
//   R7 a new secret table: server-generated UUID or serial with allocateId,
//      column <name>_enc with its _sealed constraint, registered;
//   R8 a write of a secret is audited by the function that makes it, without
//      the value; the vault audits only its own operations.
//
// Database contexts: the vault's own tables (data_keys, instance_secrets,
// vault_operations) are technical (no row level security) and are used on
// the caller's transaction, else in the current context, else (a read-only
// context: member, platform, whose reader role has no access to them) in the
// context 'none' of the same actor. The tables of the callers are read and
// written by the callers, in their contexts.
import crypto from 'node:crypto';
import type { Knex } from 'knex';
import { MASTER_TENANT_ID, type VaultStatus } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import { asNone, currentDbContext } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
import * as envelope from './envelope';
import { VAULT_NAMESPACE } from './envelope';
import { VaultError, toVaultError, type VaultErrorCode } from './errors';
import { interruptedRotationRefusal, kekMismatchRefusal, readVaultConfig, type VaultConfig } from './config';
import { loadKekProvider } from './kek';
import { Keyring, UUID_RE, type Dek, type DekRow } from './keyring';
import { OnlineLock } from './lock';
import { vaultMetrics } from './metrics';
import { isInstanceSecretName, secretColumn, secretColumns, type SecretColumnDef } from './registry';
import { auditAfterCommit, currentUserId, masterEntry, vaultAlert, writeVaultAudit, type VaultAuditEntry } from './events';

export { VAULT_NAMESPACE };

/** Where a sealed value lives: the AAD is built from it. */
export interface SecretLocator {
  table: string;
  column: string;
  pk: string | number;
  /** tenants.id of the tenant that owns the ROW (read from the row), null for
   *  an instance secret. */
  tenantId: number | null;
}

export interface VaultCallOptions {
  /** The caller's transaction (required while the tenant row itself is not
   *  committed). */
  trx?: Knex | Knex.Transaction;
  /** Tenant of the request, when there is one: a row of another tenant is
   *  refused (tenant_mismatch), unless the locator is an instance secret or
   *  globalView is set. */
  requestTenantId?: number;
  globalView?: boolean;
}

export interface ActorRef {
  userId: number | null;
}

/** Refusal to start (messages A and B of coffre-secrets §6.1, and the other
 *  start-up failures of the vault): `refusal` is the line for the operator. */
export class VaultStartupError extends Error {
  constructor(readonly refusal: string, readonly code: VaultErrorCode) {
    super(refusal);
    this.name = 'VaultStartupError';
  }
}

// ── State ───────────────────────────────────────────────────────────────────

const keyring = new Keyring();
const lock = new OnlineLock();
let cfg: VaultConfig | null = null;
let ready = false;
let lastBackfill: { at: Date; remaining: Record<string, number> } | null = null;

const IDENT_RE = /^[a-z_][a-z0-9_]{0,62}$/;
const PK_INT_RE = /^[1-9][0-9]{0,15}$/;
const PURPOSE_RE = /^[a-z][a-z0-9_.]{1,63}$/;
/** Codes that hint at tampering or at an isolation defect: logged as errors,
 *  counted and raised as a live alert of the master tenant. */
const INTEGRITY_CODES: ReadonlySet<string> = new Set(['decrypt_failed', 'tenant_mismatch', 'key_id_mismatch', 'format']);

function requireReady(): void {
  if (!ready) throw new VaultError('kek_unavailable', null, 'the vault is not initialized');
}

/** The vault's own tables: on the caller's transaction, else in the current
 *  context (a read-only one becomes 'none' with the same actor). */
function withVaultDb<T>(o: VaultCallOptions | undefined, fn: (q: Knex | Knex.Transaction) => Promise<T>): Promise<T> {
  if (o?.trx) return fn(o.trx);
  const cur = currentDbContext();
  if (cur && (cur.kind === 'member' || cur.kind === 'platform')) return asNone(cur.actor, () => fn(db));
  return fn(db);
}

function isTransaction(q: unknown): q is Knex.Transaction {
  return !!q && typeof (q as Knex.Transaction).isCompleted === 'function';
}

// ── Locators ────────────────────────────────────────────────────────────────

function pkIsValid(def: SecretColumnDef, pk: unknown): boolean {
  switch (def.pkType) {
    case 'integer':
      return typeof pk === 'number'
        ? Number.isSafeInteger(pk) && pk > 0
        : typeof pk === 'string' && PK_INT_RE.test(pk) && Number.isSafeInteger(Number(pk));
    case 'uuid':
      return typeof pk === 'string' && UUID_RE.test(pk);
    case 'name':
      return isInstanceSecretName(pk);
    default:
      return false;
  }
}

/**
 * The registered definition of a locator, its coordinates checked BEFORE any
 * AAD is built or any error carries them (review of lot A2): a registered
 * table and column (not_registered), a tenant id that is a positive safe
 * integer or null as the column allows, a primary key of the column's form
 * (decimal, lower-case UUID, registered instance secret name).
 */
export function locatorDef(loc: SecretLocator): SecretColumnDef {
  if (!loc || typeof loc !== 'object') throw new VaultError('format', null, 'invalid locator');
  const named = typeof loc.table === 'string' && typeof loc.column === 'string'
    && IDENT_RE.test(loc.table) && IDENT_RE.test(loc.column);
  const def = named ? secretColumn(loc.table, loc.column) : undefined;
  if (!def) {
    throw new VaultError('not_registered', null, named ? `${loc.table}.${loc.column} is not a registered secret column` : 'invalid table or column');
  }
  const t = loc.tenantId;
  if (t !== null && !(typeof t === 'number' && Number.isSafeInteger(t) && t > 0)) {
    throw new VaultError('format', null, `${def.table}.${def.column}: invalid tenant id`);
  }
  if (def.tenantColumn === null && t !== null) throw new VaultError('format', null, `${def.table}.${def.column}: an instance secret has no tenant`);
  if (def.tenantColumn !== null && !def.tenantNullable && t === null) {
    throw new VaultError('format', null, `${def.table}.${def.column}: the tenant of the row is required`);
  }
  if (!pkIsValid(def, loc.pk)) throw new VaultError('format', null, `${def.table}.${def.column}: invalid primary key`);
  return def;
}

/** "obligarth.<table>:<column>:<pk>:<tenant or ->" of a checked locator. */
export function locatorAad(loc: SecretLocator): Buffer {
  return envelope.aad(`${VAULT_NAMESPACE}.${loc.table}`, loc.column, String(loc.pk),
    loc.tenantId === null ? null : String(loc.tenantId));
}

function checkRequestTenant(loc: SecretLocator, o: VaultCallOptions): void {
  if (o.requestTenantId === undefined || o.globalView || loc.tenantId === null) return;
  if (loc.tenantId !== o.requestTenantId) throw new VaultError('tenant_mismatch', loc);
}

/** The coordinates a log line names: the error's, else those of the locator
 *  (checked again): the keyring's refusals (tenant_mismatch, dek_not_found,
 *  dek_destroyed, kek_mismatch) carry none, and coffre-secrets §5.7 logs
 *  them with the code and the coordinates (review of lot A4). */
function coordinatesOf(e: VaultError, loc: SecretLocator | null): { table: string; column: string; pk: string; tenantId: number | null } | undefined {
  if (e.where) return { table: e.where.table, column: e.where.column, pk: e.where.pk, tenantId: e.where.tenantId };
  if (!loc) return undefined;
  try {
    locatorDef(loc);
  } catch {
    return undefined;
  }
  return { table: loc.table, column: loc.column, pk: String(loc.pk), tenantId: loc.tenantId };
}

/** Logs, counts and alerts a failure, as coffre-secrets §5.7 says; returns
 *  the error to throw (a VaultError with the coordinates). */
function failure(err: unknown, loc: SecretLocator | null, op: 'seal' | 'open'): unknown {
  const e = toVaultError(err, loc);
  if (!(e instanceof VaultError)) return e;
  const table = loc && IDENT_RE.test(String(loc.table)) ? loc.table : 'unknown';
  if (op === 'open') vaultMetrics.openFailed(table, e.code);
  if (op === 'seal') vaultMetrics.sealed(table, e.code);
  else vaultMetrics.opened(table, e.code);
  const where = coordinatesOf(e, loc);
  if (INTEGRITY_CODES.has(e.code)) {
    logger.error({ vault: { code: e.code, op, ...where } }, `vault: sealed value refused (${e.code})`);
    vaultAlert(`vault:refused:${table}`, 'Vault: a sealed value was refused',
      `${op === 'open' ? 'Opening' : 'Sealing'} a value of ${table} failed (${e.code}): possible tampering or isolation defect.`);
  } else if (e.code === 'tenant_retiring') {
    logger.info({ vault: { code: e.code, op, ...where } }, 'vault: tenant being deleted, write refused');
  } else if (e.code === 'dek_not_found' || e.code === 'dek_destroyed') {
    logger.warn({ vault: { code: e.code, op, ...where } }, `vault: ${e.code}`);
  } else {
    logger.error({ vault: { code: e.code, op, ...where } }, `vault: ${e.code}`);
  }
  return e;
}

// ── Seal / open ─────────────────────────────────────────────────────────────

async function sealBytes(loc: SecretLocator, bytes: Buffer, o: VaultCallOptions): Promise<string> {
  requireReady();
  locatorDef(loc);
  let dek: Dek | null = null;
  try {
    checkRequestTenant(loc, o);
    if (bytes.length > (cfg?.maxPlaintextBytes ?? 1024 * 1024)) throw new VaultError('too_large', loc);
    lock.check();
    dek = await withVaultDb(o, (q) => keyring.activeDekFor(loc.tenantId, q));
    const sealed = envelope.seal(dek.key, dek.id, locatorAad(loc), bytes);
    vaultMetrics.sealed(loc.table, 'ok');
    return sealed;
  } catch (err) {
    throw failure(err, loc, 'seal');
  } finally {
    dek?.key.fill(0);
  }
}

async function openBytes(loc: SecretLocator, sealed: string, o: VaultCallOptions): Promise<Buffer> {
  requireReady();
  locatorDef(loc);
  let dek: Dek | null = null;
  try {
    checkRequestTenant(loc, o);
    const kid = envelope.keyIdOf(sealed);
    lock.check();
    dek = await withVaultDb(o, (q) => keyring.dekById(kid, loc.tenantId, q));
    const out = envelope.open(dek.key, dek.id, locatorAad(loc), sealed);
    vaultMetrics.opened(loc.table, 'ok');
    return out;
  } catch (err) {
    throw failure(err, loc, 'open');
  } finally {
    dek?.key.fill(0);
  }
}

function toBytes(plaintext: string | Buffer): { bytes: Buffer; own: boolean } {
  if (Buffer.isBuffer(plaintext)) return { bytes: plaintext, own: false };
  if (typeof plaintext !== 'string') throw new VaultError('format', null, 'a secret is a string or bytes');
  return { bytes: Buffer.from(plaintext, 'utf8'), own: true };
}

// ── Status helpers ──────────────────────────────────────────────────────────

type Rows<T> = { rows: T[] };

async function escrowCovers(q: Knex | Knex.Transaction, kekId: string): Promise<boolean> {
  const res = await q.raw(
    `SELECT 1 FROM vault_operations
      WHERE kind IN ('escrow_confirmation', 'escrow_test') AND state = 'done'
        AND params -> 'kekIds' ->> 'server' = ? LIMIT 1`, [kekId]) as Rows<unknown>;
  return res.rows.length > 0;
}

function iso(d: Date | string | null | undefined): string | null {
  if (!d) return null;
  const t = d instanceof Date ? d : new Date(d);
  return Number.isNaN(t.getTime()) ? null : t.toISOString();
}

// ── Start-up (coffre-secrets §6.1) ──────────────────────────────────────────

async function canary(provider: { id: string }): Promise<void> {
  // A fresh database: the instance DEK is created (no instance DEK at all,
  // not even a destroyed one).
  const instance = await db('data_keys').whereNull('tenant_id').count<{ n: string }[]>({ n: '*' });
  if (Number(instance[0]?.n ?? 0) === 0) {
    const out: { created?: DekRow } = {};
    await keyring.createFirstDek(null, db, out);
    if (out.created) {
      logger.info({ dekId: out.created.id, kekId: provider.id }, 'vault: instance data key created (new database)');
      await writeVaultAudit([masterEntry('vault.dek_created', { scope: 'instance', dekId: out.created.id, version: 1, kekId: provider.id })]);
    }
  }
  const live = await db('data_keys').whereNotNull('dek_wrapped')
    .select('id', 'tenant_id', 'version', 'kek_id', 'state') as Array<Pick<DekRow, 'id' | 'tenant_id' | 'version' | 'kek_id' | 'state'>>;
  const active = await keyring.selectActive(null, db);
  if (!active || !active.dek_wrapped) {
    throw new VaultStartupError('The vault has no active instance data key: restore the backup of this database, '
      + 'or recover with "vault recover-lost-kek". Refusing to start.', 'dek_destroyed');
  }
  if (active.kek_id !== provider.id) {
    // Some keys already under the loaded KEK: a rotation stopped half-way.
    if (live.some((r) => r.kek_id === provider.id)) {
      throw new VaultStartupError(interruptedRotationRefusal(active.kek_id), 'kek_mismatch');
    }
    throw new VaultStartupError(kekMismatchRefusal(provider.id, active.kek_id), 'kek_mismatch');
  }
  try {
    const key = await keyring.unwrapUncached({ ...active, dek_wrapped: active.dek_wrapped });
    key.fill(0);
  } catch {
    throw new VaultStartupError(kekMismatchRefusal(provider.id, active.kek_id), 'decrypt_failed');
  }
  const foreign = live.find((r) => r.kek_id !== provider.id);
  if (foreign) throw new VaultStartupError(interruptedRotationRefusal(foreign.kek_id), 'kek_mismatch');
}

/** The first DEK of every tenant that never had one (tenants created by SQL),
 *  by batches of 200. */
async function createMissingTenantKeys(): Promise<number> {
  let created = 0;
  for (;;) {
    const res = await db.raw(`SELECT t.id FROM tenants t
       WHERE NOT EXISTS (SELECT 1 FROM data_keys d WHERE d.tenant_id = t.id)
       ORDER BY t.id LIMIT 200`) as Rows<{ id: number }>;
    if (!res.rows.length) break;
    const fresh = await Promise.all(res.rows.map((r) => keyring.newWrappedDek(Number(r.id), 1)));
    let inserted: Rows<{ id: string; tenant_id: number }>;
    try {
      const values = fresh.map(() => "(?, ?, 1, ?, ?, 'active')").join(', ');
      inserted = await db.raw(
        `INSERT INTO data_keys (id, tenant_id, version, kek_id, dek_wrapped, state) VALUES ${values}
         ON CONFLICT DO NOTHING RETURNING id, tenant_id`,
        fresh.flatMap((d) => [d.id, d.tenant_id, d.kek_id, d.dek_wrapped]),
      ) as Rows<{ id: string; tenant_id: number }>;
    } catch (err) {
      for (const d of fresh) d.discard();
      throw err;
    }
    const ok = new Set(inserted.rows.map((r) => r.id));
    for (const d of fresh) (ok.has(d.id) ? d.cache : d.discard)();
    created += ok.size;
    await writeVaultAudit(inserted.rows.map((r) => ({
      tenantId: Number(r.tenant_id), action: 'vault.dek_created', resourceType: 'vault',
      details: { scope: 'tenant', dekId: r.id, version: 1, kekId: keyring.provider().id, origin: 'init' },
    })));
    if (inserted.rows.length === 0) break;   // created meanwhile by another instance
  }
  return created;
}

// ── The API ─────────────────────────────────────────────────────────────────

export const vault = {
  /**
   * Boot (coffre-secrets §6.1), in the context 'none' of the job actor
   * vault.init: KEK provider, online lock, canary (message A), interrupted
   * rotation (message B), DEKs of the tenants that have none, escrow check.
   * Throws VaultStartupError (refusal to start) or VaultError.
   */
  async init(opts: { config?: VaultConfig } = {}): Promise<VaultStatus> {
    if (ready) return this.status();
    const c = opts.config ?? readVaultConfig();
    const provider = loadKekProvider(c);
    try {
      keyring.configure(provider, c.dekCacheTtlSeconds);
      await lock.acquireShared(config.databaseUrl, (msg, extra) => logger.warn(extra ?? {}, msg));
      await canary(provider);
      const created = await createMissingTenantKeys();
      if (created) logger.info({ created }, 'vault: first data key of the tenants that had none');
      cfg = c;
      ready = true;
      vaultMetrics.setReady(true);
      const status = await this.status();
      if (!c.allowUnescrowed && process.env.NODE_ENV !== 'development' && !status.escrow.coversCurrentKek) {
        logger.warn({ kekId: provider.id }, 'vault: no escrow confirmation covers the current KEK; Apple secrets stay refused '
          + 'until the vault keys are escrowed (vault escrow split) and the confirmation is recorded');
        vaultAlert('vault:escrow-missing', 'Vault keys not escrowed',
          'No escrow confirmation covers the current key-encryption key: escrow it and record the confirmation.', 'warning');
      }
      logger.info({ kekId: provider.id, provider: provider.kind }, 'vault ready');
      return status;
    } catch (err) {
      ready = false;
      cfg = null;
      vaultMetrics.setReady(false);
      keyring.reset();
      provider.dispose();
      await lock.release();
      throw err;
    }
  },

  /** Shutdown: the KEK is zeroed, the cache emptied, the online lock released. */
  async close(): Promise<void> {
    const wasReady = ready;
    ready = false;
    vaultMetrics.setReady(false);
    if (keyring.hasProvider()) keyring.provider().dispose();
    keyring.reset();
    cfg = null;
    await lock.release();
    if (wasReady) logger.info('vault closed');
  },

  isReady(): boolean {
    return ready;
  },

  /** kek_id of the loaded KEK. */
  kekId(): string {
    requireReady();
    return keyring.provider().id;
  },

  seal(loc: SecretLocator, plaintext: string | Buffer, o: VaultCallOptions = {}): Promise<string> {
    const { bytes, own } = toBytes(plaintext);
    return sealBytes(loc, bytes, o).finally(() => { if (own) bytes.fill(0); });
  },

  sealJson(loc: SecretLocator, value: unknown, o: VaultCallOptions = {}): Promise<string> {
    const text = JSON.stringify(value);
    if (text === undefined) return Promise.reject(new VaultError('format', null, 'a JSON secret cannot be undefined'));
    return this.seal(loc, text, o);
  },

  /** The clear bytes: the caller's (fill(0) once used). */
  open(loc: SecretLocator, sealed: string, o: VaultCallOptions = {}): Promise<Buffer> {
    return openBytes(loc, sealed, o);
  },

  async openString(loc: SecretLocator, sealed: string, o: VaultCallOptions = {}): Promise<string> {
    const bytes = await openBytes(loc, sealed, o);
    try {
      return bytes.toString('utf8');
    } finally {
      bytes.fill(0);
    }
  },

  async openJson<T = unknown>(loc: SecretLocator, sealed: string, o: VaultCallOptions = {}): Promise<T> {
    const text = await this.openString(loc, sealed, o);
    try {
      return JSON.parse(text) as T;
    } catch {
      throw failure(new VaultError('format', loc, 'the sealed value is not JSON'), loc, 'open');
    }
  },

  /** Moves a sealed value to new coordinates (tenant change of a row, DEK
   *  rotation): opened at `from`, sealed at `to` under the active DEK. */
  async reseal(from: SecretLocator, to: SecretLocator, sealed: string, o: VaultCallOptions = {}): Promise<string> {
    const bytes = await openBytes(from, sealed, o);
    try {
      return await sealBytes(to, bytes, o);
    } finally {
      bytes.fill(0);
    }
  },

  /** Next value of a registered table's serial id, to build the AAD before
   *  the INSERT (R7). */
  async allocateId(table: string, o: VaultCallOptions = {}): Promise<number> {
    const def = typeof table === 'string' && IDENT_RE.test(table)
      ? secretColumns().find((c) => c.table === table && !c.transient) : undefined;
    if (!def || def.pkType !== 'integer') throw new VaultError('not_registered', null, 'allocateId: not a registered table with a serial key');
    const run = async (q: Knex | Knex.Transaction) => {
      const res = await q.raw('SELECT nextval(pg_get_serial_sequence(?, ?)) AS id', [`obligarth.${def.table}`, def.pk]) as Rows<{ id: string | number }>;
      const id = Number(res.rows[0]?.id);
      if (!Number.isSafeInteger(id) || id <= 0) throw new VaultError('format', null, 'allocateId: no serial sequence');
      return id;
    };
    return o.trx ? run(o.trx) : run(db);
  },

  // ── Instance secrets ──────────────────────────────────────────────────────

  /** Is the secret set? (a flag for an API: the value is not opened) */
  async hasInstanceSecret(name: string, o: VaultCallOptions = {}): Promise<boolean> {
    if (!isInstanceSecretName(name)) throw new VaultError('not_registered', null, 'unknown instance secret name');
    const row = await withVaultDb(o, (q) => q('instance_secrets').where({ name }).first('name'));
    return !!row;
  },

  async getInstanceSecret(name: string, o: VaultCallOptions = {}): Promise<string | null> {
    if (!isInstanceSecretName(name)) throw new VaultError('not_registered', null, 'unknown instance secret name');
    requireReady();
    const row = await withVaultDb(o, (q) => q('instance_secrets').where({ name }).first('value_enc')) as { value_enc: string } | undefined;
    if (!row) return null;
    return this.openString({ table: 'instance_secrets', column: 'value_enc', pk: name, tenantId: null }, row.value_enc, o);
  },

  /** null deletes the secret. Audited (vault.instance_secret_changed, master
   *  tenant) once the change commits. Returns whether something changed. */
  async setInstanceSecret(name: string, value: string | null, actor: ActorRef, o: VaultCallOptions = {}): Promise<boolean> {
    if (!isInstanceSecretName(name)) throw new VaultError('not_registered', null, 'unknown instance secret name');
    requireReady();
    const loc: SecretLocator = { table: 'instance_secrets', column: 'value_enc', pk: name, tenantId: null };
    const userId = actor?.userId ?? null;
    const run = async (q: Knex | Knex.Transaction): Promise<{ changed: boolean; version: number | null }> => {
      if (value === null) {
        const n = await q('instance_secrets').where({ name }).delete();
        return { changed: n > 0, version: null };
      }
      const sealed = await this.seal(loc, value, { ...o, trx: q });
      const res = await q.raw(
        `INSERT INTO instance_secrets (name, value_enc, version, updated_by, updated_at) VALUES (?, ?, 1, ?, now())
         ON CONFLICT (name) DO UPDATE SET value_enc = EXCLUDED.value_enc, version = instance_secrets.version + 1,
           updated_by = EXCLUDED.updated_by, updated_at = now()
         RETURNING version`, [name, sealed, userId]) as Rows<{ version: number }>;
      return { changed: true, version: Number(res.rows[0]?.version ?? 1) };
    };
    const out = await withVaultDb(o, (q) => (isTransaction(q) ? run(q) : q.transaction((trx) => run(trx))));
    if (out.changed) {
      void auditAfterCommit(o.trx, [masterEntry('vault.instance_secret_changed',
        { name, version: out.version, deleted: value === null }, { userId: userId ?? undefined, resourceType: 'instance_secret', resourcePath: name })]);
    }
    return out.changed;
  },

  // ── Secrets referenced from documents (coffre-secrets §6.4) ────────────────

  /** Returns the id to embed as {"$secret": "<id>"}. A value never changes in
   *  place: a new secret is a new row. In the tenant's context (row level
   *  security): the caller's. */
  async createTenantSecret(tenantId: number, purpose: string, value: string | Buffer, actor: ActorRef, o: VaultCallOptions = {}): Promise<string> {
    if (typeof purpose !== 'string' || !PURPOSE_RE.test(purpose)) throw new VaultError('format', null, 'invalid purpose');
    const id = crypto.randomUUID();
    const loc: SecretLocator = { table: 'tenant_secrets', column: 'value_enc', pk: id, tenantId };
    const sealed = await this.seal(loc, value, o);
    await (o.trx ?? db)('tenant_secrets').insert({
      id, tenant_id: tenantId, purpose, value_enc: sealed, created_by: actor?.userId ?? null,
    });
    void auditAfterCommit(o.trx, [{
      tenantId, userId: actor?.userId ?? undefined, action: 'vault.tenant_secret_created',
      resourceType: 'tenant_secret', resourcePath: id, details: { purpose, id },
    }]);
    return id;
  },

  /** The value of a tenant secret: the caller's bytes (fill(0) once used). A
   *  row of another tenant is refused (tenant_mismatch), unless globalView
   *  (the master tenant's library served to a client's devices). */
  async readTenantSecret(tenantId: number, id: string, o: VaultCallOptions = {}): Promise<Buffer> {
    if (typeof id !== 'string' || !UUID_RE.test(id)) throw new VaultError('format', null, 'invalid secret id');
    requireReady();
    const row = await (o.trx ?? db)('tenant_secrets').where({ id }).first('id', 'tenant_id', 'value_enc') as
      { id: string; tenant_id: number; value_enc: string } | undefined;
    if (!row) throw new VaultError('dek_not_found', null, 'no such tenant secret');
    const loc: SecretLocator = { table: 'tenant_secrets', column: 'value_enc', pk: row.id, tenantId: Number(row.tenant_id) };
    if (loc.tenantId !== tenantId && !o.globalView) throw failure(new VaultError('tenant_mismatch', loc), loc, 'open');
    return this.open(loc, row.value_enc, { ...o, requestTenantId: undefined });
  },

  // ── Tenant keys (coffre-secrets §6.2, §6.5) ───────────────────────────────

  /** The first DEK of a new tenant, in the transaction that creates it.
   *  Audited (vault.dek_created, the tenant's log) once it commits. */
  async createTenantKey(trx: Knex.Transaction, tenantId: number): Promise<{ id: string; version: number; kekId: string }> {
    requireReady();
    const out: { created?: DekRow } = {};
    const row = await keyring.createFirstDek(tenantId, trx, out);
    const info = { id: row.id, version: Number(row.version), kekId: row.kek_id };
    if (out.created) {
      void auditAfterCommit(trx, [{
        tenantId, userId: currentUserId(), action: 'vault.dek_created', resourceType: 'vault',
        details: { scope: 'tenant', dekId: info.id, version: info.version, kekId: info.kekId, origin: 'tenant_created' },
      }]);
    }
    return info;
  },

  /**
   * Crypto-shredding of a deleted tenant (V7: immediate while the 30-day soft
   * deletion does not exist): its data_keys rows are locked and deleted (the
   * foreign key is RESTRICT: tenant_delete fails without this), the cache is
   * dropped, and the entry vault.dek_destroyed (master tenant) is written
   * once the transaction commits — or returned (audit 'return', review
   * COF-RC2) for the caller to write after tenant_delete.
   */
  async shredTenantKeys(trx: Knex.Transaction, tenantId: number, actor: ActorRef,
    o: { audit?: 'write' | 'return' } = {}): Promise<{ count: number; auditEntry: VaultAuditEntry | null }> {
    if (!(Number.isSafeInteger(tenantId) && tenantId > 0)) throw new VaultError('format', null, 'invalid tenant id');
    const tenant = await trx('tenants').where({ id: tenantId }).first('id', 'slug') as { id: number; slug: string } | undefined;
    const rows = await trx('data_keys').where({ tenant_id: tenantId }).forUpdate()
      .select('id', 'version', 'kek_id', 'state') as Array<{ id: string; version: number; kek_id: string; state: string }>;
    await trx('data_keys').where({ tenant_id: tenantId }).delete();
    keyring.invalidate({ tenantId });
    const entry = masterEntry('vault.dek_destroyed', {
      tenantId, slug: tenant?.slug ?? null, reason: 'tenant_deleted',
      keys: rows.map((r) => ({ id: r.id, version: Number(r.version), state: r.state })),
      kekIds: [...new Set(rows.map((r) => r.kek_id))],
    }, { userId: actor?.userId ?? undefined, resourceType: 'tenant', resourcePath: String(tenantId) });
    if ((o.audit ?? 'write') === 'write') {
      void auditAfterCommit(trx, [entry]);
      return { count: rows.length, auditEntry: null };
    }
    return { count: rows.length, auditEntry: entry };
  },

  /** Soft deletion (PLT-11): the tenant's DEKs are destroyed at `at`; new
   *  seals are refused meanwhile (tenant_retiring), opening still works. */
  async scheduleTenantShred(trx: Knex.Transaction, tenantId: number, at: Date): Promise<void> {
    if (!(at instanceof Date) || Number.isNaN(at.getTime())) throw new VaultError('format', null, 'invalid destruction date');
    const n = await trx('data_keys').where({ tenant_id: tenantId }).whereNot({ state: 'destroyed' })
      .update({ destroy_after: at });
    keyring.invalidate({ tenantId });
    const details = { tenantId, destroyAfter: at.toISOString(), keys: n };
    void auditAfterCommit(trx, [
      { tenantId, userId: currentUserId(), action: 'vault.dek_destruction_scheduled', resourceType: 'vault', details },
      masterEntry('vault.dek_destruction_scheduled', details, { resourceType: 'tenant', resourcePath: String(tenantId) }),
    ]);
  },

  async cancelTenantShred(trx: Knex.Transaction, tenantId: number): Promise<void> {
    const n = await trx('data_keys').where({ tenant_id: tenantId }).whereNot({ state: 'destroyed' })
      .whereNotNull('destroy_after').update({ destroy_after: null });
    keyring.invalidate({ tenantId });
    if (n > 0) {
      const details = { tenantId, keys: n };
      void auditAfterCommit(trx, [
        { tenantId, userId: currentUserId(), action: 'vault.dek_destruction_cancelled', resourceType: 'vault', details },
        masterEntry('vault.dek_destruction_cancelled', details, { resourceType: 'tenant', resourcePath: String(tenantId) }),
      ]);
    }
  },

  /** Destroys the tenant's DEKs whose destroy_after has passed (called by
   *  tenants.retire-due before it purges the tenant). Returns how many. */
  async destroyDueKeys(tenantId: number): Promise<number> {
    if (!(Number.isSafeInteger(tenantId) && tenantId > 0)) throw new VaultError('format', null, 'invalid tenant id');
    const res = await withVaultDb({}, (q) => q.raw(
      `UPDATE data_keys SET dek_wrapped = NULL, state = 'destroyed', destroyed_at = now()
        WHERE tenant_id = ? AND destroy_after IS NOT NULL AND destroy_after <= now() AND state <> 'destroyed'
        RETURNING id, version, kek_id`, [tenantId])) as Rows<{ id: string; version: number; kek_id: string }>;
    keyring.invalidate({ tenantId });
    if (res.rows.length) {
      await writeVaultAudit([masterEntry('vault.dek_destroyed', {
        tenantId, reason: 'retired', keys: res.rows.map((r) => ({ id: r.id, version: Number(r.version) })),
        kekIds: [...new Set(res.rows.map((r) => r.kek_id))],
      }, { resourceType: 'tenant', resourcePath: String(tenantId) })]);
    }
    return res.rows.length;
  },

  // ── Escrow guard (V14) ────────────────────────────────────────────────────

  /** Throws AppError(409, …, 'escrowRequired') when no escrow confirmation
   *  covers the current kek_id, unless VAULT_ALLOW_UNESCROWED. */
  async requireEscrow(): Promise<void> {
    requireReady();
    if (cfg?.allowUnescrowed) return;
    const kekId = keyring.provider().id;
    if (await withVaultDb({}, (q) => escrowCovers(q, kekId))) return;
    throw new AppError(409, 'Escrow the vault keys before connecting Apple: record the escrow confirmation of the current '
      + 'key-encryption key in the vault panel.', 'escrowRequired');
  },

  // ── State ─────────────────────────────────────────────────────────────────

  async status(): Promise<VaultStatus> {
    requireReady();
    const provider = keyring.provider();
    return withVaultDb({}, async (q) => {
      const keys = (await q.raw(`SELECT
          count(*) FILTER (WHERE tenant_id IS NOT NULL AND state = 'active')::int AS active,
          count(*) FILTER (WHERE tenant_id IS NOT NULL AND state = 'retired')::int AS retired,
          count(*) FILTER (WHERE tenant_id IS NOT NULL AND state = 'destroyed')::int AS destroyed,
          count(*) FILTER (WHERE destroy_after IS NOT NULL AND state <> 'destroyed')::int AS scheduled
        FROM data_keys`) as Rows<{ active: number; retired: number; destroyed: number; scheduled: number }>).rows[0];
      const without = (await q.raw(`SELECT count(*)::int AS n FROM unnest(obligarth.tenant_ids_all()) AS t(id)
          WHERE NOT EXISTS (SELECT 1 FROM data_keys d WHERE d.tenant_id = t.id)`) as Rows<{ n: number }>).rows[0];
      const inst = await keyring.selectActive(null, q);
      const instRow = inst ? await q('data_keys').where({ id: inst.id }).first('created_at') as { created_at: Date } | undefined : undefined;
      const ops = (await q.raw(`SELECT
          (SELECT max(created_at) FROM vault_operations WHERE kind = 'escrow_confirmation' AND state = 'done') AS confirmed_at,
          (SELECT max(created_at) FROM vault_operations WHERE kind = 'escrow_test' AND state = 'done') AS tested_at,
          (SELECT max(finished_at) FROM vault_operations WHERE kind = 'kek_rotation' AND state = 'done') AS rotated_at,
          (SELECT max(finished_at) FROM vault_operations WHERE kind = 'backfill' AND state = 'done') AS backfill_at,
          (SELECT count(*)::int FROM vault_operations WHERE state = 'running') AS running,
          (SELECT count(*)::int FROM vault_operations WHERE state = 'failed') AS failed`) as Rows<{
          confirmed_at: Date | null; tested_at: Date | null; rotated_at: Date | null; backfill_at: Date | null; running: number; failed: number;
        }>).rows[0];
      const remaining = lastBackfill?.remaining ?? {};
      return {
        provider: provider.kind,
        kekId: provider.id,
        edgeKekId: null,
        instanceDek: inst ? { id: inst.id, version: Number(inst.version), createdAt: iso(instRow?.created_at) ?? '' } : null,
        tenantKeys: {
          active: Number(keys?.active ?? 0), retired: Number(keys?.retired ?? 0), destroyed: Number(keys?.destroyed ?? 0),
          scheduled: Number(keys?.scheduled ?? 0), tenantsWithoutKey: Number(without?.n ?? 0),
        },
        backfill: {
          complete: Object.values(remaining).every((n) => n === 0),
          remaining: { ...remaining },
          lastRunAt: iso(lastBackfill?.at) ?? iso(ops?.backfill_at),
        },
        escrow: {
          confirmedAt: iso(ops?.confirmed_at),
          lastTestAt: iso(ops?.tested_at),
          coversCurrentKek: await escrowCovers(q, provider.id),
        },
        lastKekRotationAt: iso(ops?.rotated_at),
        operations: { running: Number(ops?.running ?? 0), failed: Number(ops?.failed ?? 0) },
      };
    });
  },

  /** Values for the observability work (FND-14): counters, never a value. */
  metricsSnapshot() {
    return {
      ...vaultMetrics.snapshot(),
      dekCacheEntries: keyring.cacheSize(),
      dekUnwrap: { ok: keyring.counters.unwrapOk, failed: keyring.counters.unwrapFailed },
      dekCreated: keyring.counters.created,
    };
  },
};

/** For the vault's own modules (backfill, rotation, verification, CLI):
 *  never imported elsewhere. */
export const vaultInternals = {
  keyring,
  lock,
  withVaultDb,
  requireReady,
  config: (): VaultConfig | null => cfg,
  setBackfillReport(remaining: Record<string, number>): void {
    lastBackfill = { at: new Date(), remaining: { ...remaining } };
    vaultMetrics.setBackfillRemaining(remaining);
  },
  masterTenantId: MASTER_TENANT_ID,
};

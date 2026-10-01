// Keyring of the data keys (docs: coffre-secrets §5.4): the table data_keys
// (one active DEK per tenant, plus the instance DEK, wrapped by the KEK), its
// lazy creation (V6), and a cache of the unwrapped key material.
//
//   - Sealing re-reads the id of the active DEK every time (one indexed
//     query; sealing is rare): a rotation made by another process is taken
//     at once. Only the key material is cached.
//   - A DEK is handed to its caller as a COPY of the cached key: the caller
//     zeroes it once used (never a buffer the cache may zero meanwhile).
//   - Cache: VAULT_DEK_CACHE_TTL seconds (0: no cache), 10 000 entries at
//     most, the oldest evicted first; every evicted buffer is zeroed (at
//     best: Node does not guarantee that internal copies are erased).
//
// The queries run on the connection the caller gives (its transaction, or
// the server's pool in the current context): data_keys is a technical table
// (no row level security), readable and writable by the runtime role in the
// contexts tenant, identity and none.
import crypto from 'node:crypto';
import type { Knex } from 'knex';
import { KEY_BYTES, newKey } from './envelope';
import { VaultError } from './errors';
import type { KekProvider } from './kek';

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CACHE_MAX_ENTRIES = 10_000;

export interface DekRow {
  id: string;
  tenant_id: number | null;
  version: number;
  kek_id: string;
  dek_wrapped: string | null;
  state: 'active' | 'retired' | 'destroyed';
  destroy_after: Date | null;
  created_at?: Date;
}

/** An unwrapped DEK: `key` is the caller's copy (fill(0) once used). */
export interface Dek {
  id: string;
  tenantId: number | null;
  version: number;
  key: Buffer;
}

interface CacheEntry {
  key: Buffer;
  tenantId: number | null;
  version: number;
  expiresAt: number;
}

const ACTIVE_COLUMNS = ['id', 'tenant_id', 'version', 'kek_id', 'dek_wrapped', 'state', 'destroy_after'] as const;

/** A tenant id as a DEK names it: a positive safe integer, or null (instance). */
function checkTenant(tenantId: number | null): void {
  if (tenantId !== null && !(Number.isSafeInteger(tenantId) && tenantId > 0)) throw new VaultError('format', null, 'invalid tenant id');
}

export class Keyring {
  #provider: KekProvider | null = null;
  #ttlMs = 300_000;
  readonly #cache = new Map<string, CacheEntry>();
  /** Counters for the metrics (obligarth_vault_dek_unwrap_total{outcome}). */
  readonly counters = { unwrapOk: 0, unwrapFailed: 0, created: 0 };

  configure(provider: KekProvider, cacheTtlSeconds: number): void {
    this.#provider = provider;
    this.#ttlMs = Math.max(0, Math.floor(cacheTtlSeconds)) * 1000;
  }

  /** The KEK provider; kek_unavailable before init() or after close(). */
  provider(): KekProvider {
    if (!this.#provider) throw new VaultError('kek_unavailable', null, 'the vault is not initialized');
    return this.#provider;
  }

  hasProvider(): boolean {
    return this.#provider !== null;
  }

  /** Forgets the provider and the cache (close, tests). */
  reset(): void {
    this.clear();
    this.#provider = null;
  }

  cacheSize(): number {
    return this.#cache.size;
  }

  // ── Cache ─────────────────────────────────────────────────────────────────

  #get(id: string): CacheEntry | undefined {
    const e = this.#cache.get(id);
    if (!e) return undefined;
    if (e.expiresAt <= Date.now()) {
      e.key.fill(0);
      this.#cache.delete(id);
      return undefined;
    }
    return e;
  }

  #put(id: string, tenantId: number | null, version: number, key: Buffer): void {
    if (this.#ttlMs <= 0) return;
    const own = Buffer.alloc(KEY_BYTES);
    key.copy(own);
    const old = this.#cache.get(id);
    if (old) {
      old.key.fill(0);
      this.#cache.delete(id);
    }
    this.#cache.set(id, { key: own, tenantId, version, expiresAt: Date.now() + this.#ttlMs });
    while (this.#cache.size > CACHE_MAX_ENTRIES) {
      const oldest = this.#cache.keys().next().value as string;
      this.#cache.get(oldest)?.key.fill(0);
      this.#cache.delete(oldest);
    }
  }

  #copy(id: string, e: { key: Buffer; tenantId: number | null; version: number }): Dek {
    const key = Buffer.alloc(KEY_BYTES);
    e.key.copy(key);
    return { id, tenantId: e.tenantId, version: e.version, key };
  }

  /** Drops cached DEKs: these ids, or every DEK of a tenant (null: the
   *  instance's), or everything. Safe if the change is rolled back: the
   *  cache fills again at the next miss. */
  invalidate(sel?: { ids?: readonly string[]; tenantId?: number | null }): void {
    if (!sel) { this.clear(); return; }
    for (const [id, e] of [...this.#cache]) {
      const byId = sel.ids?.includes(id) ?? false;
      const byTenant = sel.tenantId !== undefined && e.tenantId === sel.tenantId;
      if (byId || byTenant) {
        e.key.fill(0);
        this.#cache.delete(id);
      }
    }
  }

  clear(): void {
    for (const e of this.#cache.values()) e.key.fill(0);
    this.#cache.clear();
  }

  // ── Unwrap ────────────────────────────────────────────────────────────────

  async #unwrapRow(row: { id: string; tenant_id: number | null; version: number; kek_id: string; dek_wrapped: string }): Promise<Dek> {
    const provider = this.provider();
    let key: Buffer;
    try {
      key = await provider.unwrap(row.id, row.tenant_id, row.dek_wrapped, row.kek_id);
    } catch (err) {
      this.counters.unwrapFailed++;
      throw err;
    }
    this.counters.unwrapOk++;
    try {
      this.#put(row.id, row.tenant_id, row.version, key);
      return this.#copy(row.id, { key, tenantId: row.tenant_id, version: row.version });
    } finally {
      key.fill(0);
    }
  }

  /** Unwraps a DEK row without the cache (verification, KEK rotation). The
   *  returned key is the caller's (fill(0) once used). */
  async unwrapUncached(row: { id: string; tenant_id: number | null; version: number; kek_id: string; dek_wrapped: string }): Promise<Buffer> {
    const key = await this.provider().unwrap(row.id, row.tenant_id, row.dek_wrapped, row.kek_id);
    this.counters.unwrapOk++;
    return key;
  }

  // ── Active DEK (sealing) ──────────────────────────────────────────────────

  async selectActive(tenantId: number | null, q: Knex | Knex.Transaction): Promise<DekRow | undefined> {
    checkTenant(tenantId);
    const res = await q.raw(
      `SELECT ${ACTIVE_COLUMNS.join(', ')} FROM data_keys WHERE coalesce(tenant_id, 0) = coalesce(?::int, 0) AND state = 'active'`,
      [tenantId],
    ) as { rows: DekRow[] };
    return res.rows[0];
  }

  /**
   * The active DEK of a tenant (null: the instance), for sealing. A tenant
   * that never had a DEK gets its first one now (V6: tenants created by SQL),
   * in the caller's transaction when given; a tenant whose DEKs were all
   * retired or destroyed gets none (dek_destroyed). A DEK scheduled for
   * destruction refuses new seals (tenant_retiring). The instance DEK is
   * created by vault.init(), never here.
   */
  async activeDekFor(tenantId: number | null, q: Knex | Knex.Transaction): Promise<Dek> {
    let row = await this.selectActive(tenantId, q);
    if (!row) {
      if (tenantId === null) throw new VaultError('kek_unavailable', null, 'no active instance data key: the vault is not initialized');
      row = await this.createFirstDek(tenantId, q);
    }
    if (row.destroy_after) throw new VaultError('tenant_retiring');
    if (!row.dek_wrapped) throw new VaultError('dek_destroyed');
    const hit = this.#get(row.id);
    if (hit && hit.tenantId === row.tenant_id) return this.#copy(row.id, hit);
    if (row.kek_id !== this.provider().id) throw new VaultError('kek_mismatch');
    return this.#unwrapRow({ ...row, dek_wrapped: row.dek_wrapped });
  }

  /**
   * First DEK of a tenant (version 1), race-safe: INSERT … WHERE NOT EXISTS
   * (no DEK at all for the tenant, even destroyed) … ON CONFLICT DO NOTHING,
   * every unique index being an arbiter; then the active row again. Returns
   * the active row, or throws dek_destroyed when the tenant had DEKs but has
   * no active one. `created` tells whether this call inserted it.
   */
  async createFirstDek(tenantId: number | null, q: Knex | Knex.Transaction, out?: { created?: DekRow }): Promise<DekRow> {
    checkTenant(tenantId);
    const provider = this.provider();
    const id = crypto.randomUUID();
    const key = newKey();
    try {
      const wrapped = await provider.wrap(id, tenantId, key);
      const res = await q.raw(
        `INSERT INTO data_keys (id, tenant_id, version, kek_id, dek_wrapped, state)
         SELECT ?, ?, 1, ?, ?, 'active'
          WHERE NOT EXISTS (SELECT 1 FROM data_keys WHERE coalesce(tenant_id, 0) = coalesce(?::int, 0))
         ON CONFLICT DO NOTHING
         RETURNING ${ACTIVE_COLUMNS.join(', ')}`,
        [id, tenantId, provider.id, wrapped, tenantId],
      ) as { rows: DekRow[] };
      if (res.rows[0]) {
        this.counters.created++;
        this.#put(id, tenantId, 1, key);
        if (out) out.created = res.rows[0];
        return res.rows[0];
      }
    } finally {
      key.fill(0);
    }
    const row = await this.selectActive(tenantId, q);
    if (!row) throw new VaultError('dek_destroyed');
    return row;
  }

  // ── DEK by id (opening) ───────────────────────────────────────────────────

  /**
   * The DEK named by a sealed value's kid, for opening. Checks, in this
   * order (as apple-edge's DEKByID): the row exists (dek_not_found); it
   * belongs to the tenant of the locator (tenant_mismatch, before any GCM
   * computation); it is not destroyed (dek_destroyed); it is wrapped by the
   * loaded KEK (kek_mismatch); then it is unwrapped (or taken from the
   * cache, with the same tenant check).
   */
  async dekById(kid: string, tenantId: number | null, q: Knex | Knex.Transaction): Promise<Dek> {
    checkTenant(tenantId);
    if (typeof kid !== 'string' || !UUID_RE.test(kid)) throw new VaultError('format');
    const hit = this.#get(kid);
    if (hit) {
      if (hit.tenantId !== tenantId) throw new VaultError('tenant_mismatch');
      return this.#copy(kid, hit);
    }
    const row = await q('data_keys').where({ id: kid })
      .first('id', 'tenant_id', 'version', 'kek_id', 'dek_wrapped', 'state') as Omit<DekRow, 'destroy_after'> | undefined;
    if (!row) throw new VaultError('dek_not_found');
    if ((row.tenant_id ?? null) !== tenantId) throw new VaultError('tenant_mismatch');
    if (!row.dek_wrapped) throw new VaultError('dek_destroyed');
    if (row.kek_id !== this.provider().id) throw new VaultError('kek_mismatch');
    return this.#unwrapRow({ ...row, tenant_id: row.tenant_id ?? null, dek_wrapped: row.dek_wrapped });
  }

  // ── New DEK under the current KEK (init, rotation, recovery) ─────────────

  /** A new DEK row to insert: id, version, wrapped key. The key is cached
   *  (once the row exists, the caller commits) and zeroed here. */
  async newWrappedDek(tenantId: number | null, version: number): Promise<{ id: string; tenant_id: number | null; version: number; kek_id: string; dek_wrapped: string; cache: () => void; discard: () => void }> {
    checkTenant(tenantId);
    const provider = this.provider();
    const id = crypto.randomUUID();
    const key = newKey();
    let wrapped: string;
    try {
      wrapped = await provider.wrap(id, tenantId, key);
    } catch (err) {
      key.fill(0);
      throw err;
    }
    return {
      id, tenant_id: tenantId, version, kek_id: provider.id, dek_wrapped: wrapped,
      cache: () => { this.#put(id, tenantId, version, key); key.fill(0); this.counters.created++; },
      discard: () => { key.fill(0); },
    };
  }
}

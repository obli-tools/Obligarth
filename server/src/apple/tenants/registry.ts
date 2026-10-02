import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import { config } from '../../config';
import { db } from '../../db';
import { asNone, asTenant, type DbActor } from '../../db/context';
import { withTenantTransaction } from '../../db/tenantContext';
import { AppError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { edgeActorOf } from '../actors';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import type { EdgeCa, EdgeCaRotation, EdgeEnrollmentConfig } from '../edge/wire';
import { isMdmKey } from './key';

// =============================================================================
// Registry of the tenants at apple-edge (docs: integration-apple-edge §6):
//   - tenants.uuid is the external reference given to apple-edge (never in a
//     URL); tenants.mdm_key the key apple-edge generated, written once by
//     obligarth.tenant_set_mdm_key (a job or a platform administrator), never
//     changed after, the only tenant reference in the devices' URLs;
//   - tenant_apple_edge mirrors the tenant's state at apple-edge (state,
//     commands freeze, CA, cached enrollment configuration);
//   - provisioning: a durable job sent in the transaction that creates the
//     tenant (tenants/jobs.ts), idempotent on external_ref;
//   - every call to apple-edge happens outside a database transaction (T-1):
//     read, close, call, then write in a new transaction.
// The state of a tenant is read in that tenant's context (or the platform
// context of an administrator's grant); the key also in the context 'none' of
// a job or an integration (the registry is readable there).
// =============================================================================

export type EdgeMirrorState = 'unprovisioned' | 'provisioning' | 'active' | 'suspended' | 'retiring' | 'retired'
  | 'load_failed' | 'missing' | 'error';

export interface TenantAppleState {
  tenantId: number;
  mdmKey: string | null;
  edgeState: EdgeMirrorState;
  commandsFrozen: boolean;
  ca: { id: string; sha256: string; notAfter: string } | null;
  verifyOnly: Array<{ id: string; sha256: string | null; notAfter: string | null }>;
  provisionAttempts: number;
  lastErrorCode: string | null;
  lastSyncedAt: string | null;
}

export { MDM_KEY_RE } from './key';
/** Lifetime of the cached enrollment configuration. */
export const ENROLLMENT_CONFIG_TTL_MS = 10 * 60_000;
/** Lifetime of a key → tenant lookup in memory (device surface). */
const KEY_CACHE_TTL_MS = 60_000;
const KEY_CACHE_MAX = 10_000;

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);

/** The provisioning job's handle, set by tenants/jobs.ts at registration. */
let provisionSender: ((trx: Knex.Transaction, tenantId: number) => Promise<string | null>) | null = null;

export function setProvisionSender(fn: (trx: Knex.Transaction, tenantId: number) => Promise<string | null>): void {
  provisionSender = fn;
}

// ── Mirror and deadlines (in the tenant's context, inside the caller's transaction) ──

export interface MirrorPatch {
  edge_state?: EdgeMirrorState;
  edge_state_at?: Date;
  commands_frozen?: boolean;
  ca?: EdgeCa | null;
  verify_only?: Array<{ id: string; sha256: string | null; not_after: string | null }>;
  enrollment_config?: EdgeEnrollmentConfig | null;
  last_error_code?: string | null;
  last_synced_at?: Date;
}

/** Inserts or updates the mirror row of `tenantId` (the transaction's context is that tenant's). */
export async function upsertMirror(trx: Knex.Transaction, tenantId: number, p: MirrorPatch): Promise<void> {
  const row: Record<string, unknown> = { tenant_id: tenantId, updated_at: new Date() };
  if (p.edge_state !== undefined) row.edge_state = p.edge_state;
  if (p.edge_state_at !== undefined) row.edge_state_at = p.edge_state_at;
  if (p.commands_frozen !== undefined) row.commands_frozen = p.commands_frozen;
  if (p.ca !== undefined) {
    row.ca_id = p.ca?.id ?? null;
    row.ca_sha256 = p.ca?.sha256 ?? null;
    row.ca_not_after = p.ca?.not_after ? new Date(p.ca.not_after) : null;
  }
  if (p.verify_only !== undefined) row.ca_verify_only = JSON.stringify(p.verify_only);
  if (p.enrollment_config !== undefined) {
    row.enrollment_config = p.enrollment_config === null ? null : JSON.stringify(p.enrollment_config);
    row.enrollment_config_at = p.enrollment_config === null ? null : new Date();
  }
  if (p.last_error_code !== undefined) row.last_error_code = p.last_error_code;
  if (p.last_synced_at !== undefined) row.last_synced_at = p.last_synced_at;
  const { tenant_id: _t, ...updates } = row;
  await trx('tenant_apple_edge').insert(row).onConflict('tenant_id').merge(Object.keys(updates));
}

/** The deadline of the tenant's device CA (INT-05, §11.4): the active CA's, the previous ones retired. */
export async function recordDeviceCaDeadline(trx: Knex.Transaction, tenantId: number, ca: EdgeCa): Promise<void> {
  await trx.raw(`
    INSERT INTO obligarth.integration_deadline_items (id, tenant_id, kind, subject_ref, label, not_after, source, updated_at)
    VALUES (?, ?, 'device_ca', ?, 'Device identity CA', ?, 'apple-edge', now())
    ON CONFLICT ((coalesce(tenant_id, 0)), kind, subject_ref)
    DO UPDATE SET not_after = EXCLUDED.not_after, retired_at = NULL, updated_at = now()`,
  [randomUUID(), tenantId, String(ca.id).slice(0, 100), new Date(ca.not_after)]);
  await trx('integration_deadline_items')
    .where({ tenant_id: tenantId, kind: 'device_ca' })
    .whereNot('subject_ref', String(ca.id).slice(0, 100))
    .whereNull('retired_at')
    .update({ retired_at: new Date(), updated_at: new Date() });
}

function mapState(row: Record<string, unknown> | undefined, tenantId: number, mdmKey: string | null): TenantAppleState {
  const caId = (row?.ca_id as string | null | undefined) ?? null;
  const verify = Array.isArray(row?.ca_verify_only) ? row?.ca_verify_only as Array<Record<string, unknown>> : [];
  return {
    tenantId,
    mdmKey,
    edgeState: ((row?.edge_state as EdgeMirrorState | undefined) ?? 'unprovisioned'),
    commandsFrozen: row?.commands_frozen === true,
    ca: caId ? { id: caId, sha256: String(row?.ca_sha256 ?? ''), notAfter: iso(row?.ca_not_after) ?? '' } : null,
    verifyOnly: verify.map((v) => ({ id: String(v.id), sha256: (v.sha256 as string | null) ?? null, notAfter: (v.not_after as string | null) ?? null })),
    provisionAttempts: Number(row?.provision_attempts ?? 0),
    lastErrorCode: (row?.last_error_code as string | null | undefined) ?? null,
    lastSyncedAt: iso(row?.last_synced_at),
  };
}

// ── Key lookup cache (device surface: a key of a URL → its tenant) ─────────────

const keyCache = new Map<string, { tenantId: number; at: number }>();

function forgetKey(key: string | null | undefined): void {
  if (key) keyCache.delete(key);
}

export const appleTenants = {
  /** Enqueues the provisioning in the caller's transaction (tenant creation, P1). APPLE_EDGE_MODE=off: nothing
   *  (apple-edge.provision-all provisions every tenant without key once the integration is turned on). */
  async scheduleProvisioning(trx: Knex.Transaction, tenantId: number): Promise<void> {
    if (config.apple.mode !== 'on') return;
    if (!provisionSender) {
      logger.warn({ tenantId }, 'apple-edge provisioning not scheduled: the Apple module is not registered');
      return;
    }
    await provisionSender(trx, tenantId);
  },

  /** The tenant's MDM key, read in the caller's context; AppError 409 appleTenantNotProvisioned while it has none. */
  async keyOf(tenantId: number, trx?: Knex.Transaction): Promise<string> {
    const row = await (trx ?? db)('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
    if (!row) throw new AppError(404, 'Tenant not found');
    if (!row.mdm_key) throw new AppError(409, 'This tenant is not provisioned at the device service yet', 'appleTenantNotProvisioned');
    return row.mdm_key;
  },

  /** The key, or null while the tenant has none (read in the caller's context). */
  async keyOrNull(tenantId: number, trx?: Knex.Transaction): Promise<string | null> {
    const row = await (trx ?? db)('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
    return row?.mdm_key ?? null;
  },

  /** The tenant of an MDM key (obligarth.tenant_lookup_by_mdm_key, context 'none' of `actor`), cached 60 s;
   *  null for an unknown or malformed key (never cached). */
  async tenantOfKey(key: string, actor: DbActor): Promise<number | null> {
    if (!isMdmKey(key)) return null;
    const hit = keyCache.get(key);
    if (hit && Date.now() - hit.at < KEY_CACHE_TTL_MS) return hit.tenantId;
    const res = await asNone(actor, () => db.raw('SELECT obligarth.tenant_lookup_by_mdm_key(?) AS id', [key])) as { rows: Array<{ id: number | null }> };
    const id = res.rows[0]?.id ?? null;
    if (id === null) return null;
    if (keyCache.size >= KEY_CACHE_MAX) keyCache.clear();
    keyCache.set(key, { tenantId: Number(id), at: Date.now() });
    return Number(id);
  },

  /** The tenant's state at apple-edge (mirror), read in the caller's context (the tenant's). */
  async state(tenantId: number, trx?: Knex.Transaction): Promise<TenantAppleState> {
    const q = trx ?? db;
    const t = await q('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
    if (!t) throw new AppError(404, 'Tenant not found');
    const row = await q('tenant_apple_edge').where({ tenant_id: tenantId }).first() as Record<string, unknown> | undefined;
    return mapState(row, tenantId, t.mdm_key ?? null);
  },

  /** Suspends or resumes the tenant at apple-edge (§6.3); the mirror follows the answer (the event confirms). */
  async setState(tenantId: number, state: 'active' | 'suspended', actor: DbActor): Promise<void> {
    const key = await asTenant(tenantId, actor, () => appleTenants.keyOf(tenantId));
    await appleEdge.setTenantState(key, state, { actor: edgeActorOf(actor) });
    await withTenantTransaction(tenantId, actor, (trx) => upsertMirror(trx, tenantId, { edge_state: state, edge_state_at: new Date() }));
  },

  /** The emergency freeze of the commands at apple-edge (called by the guard engine's job
   *  actions.edge-freeze-sync, never by a route of the integration). 'no_edge_tenant': apple-edge does not
   *  know the tenant yet (its provisioning carries the freeze over: INT-RC10). */
  async setCommandsFrozen(tenantId: number, frozen: boolean, actor: DbActor): Promise<'done' | 'no_edge_tenant'> {
    if (config.apple.mode !== 'on') return 'no_edge_tenant';
    const key = await asTenant(tenantId, actor, () => appleTenants.keyOrNull(tenantId));
    if (!key) return 'no_edge_tenant';
    try {
      await appleEdge.setCommandsFrozen(key, frozen, { actor: edgeActorOf(actor) });
    } catch (err) {
      if (isAppleEdgeError(err) && err.code === 'tenant_not_found') {
        await withTenantTransaction(tenantId, actor, (trx) => upsertMirror(trx, tenantId, { edge_state: 'missing', last_error_code: 'tenant_not_found' }));
        return 'no_edge_tenant';
      }
      throw err;
    }
    await withTenantTransaction(tenantId, actor, (trx) => upsertMirror(trx, tenantId, { commands_frozen: frozen }));
    return 'done';
  },

  /** Starts the retirement at apple-edge (30-day soft deletion there); 409 tenant_has_active_enrollments or
   *  tenant_has_ade_tokens passed on as they are. 'no_edge_tenant' when the tenant has no key. */
  async retire(tenantId: number, actor: DbActor): Promise<'retiring' | 'no_edge_tenant'> {
    const key = await appleTenants.keyOrNull(tenantId);
    if (!key) return 'no_edge_tenant';
    await appleEdge.retireTenant(key, { actor: edgeActorOf(actor) });
    await withTenantTransaction(tenantId, actor, (trx) => upsertMirror(trx, tenantId, { edge_state: 'retiring', edge_state_at: new Date() }))
      .catch((err) => { logger.warn({ tenantId, code: (err as { code?: unknown })?.code }, 'apple-edge mirror not updated after the retirement'); });
    return 'retiring';
  },

  /** Cancels the retirement at apple-edge (within its 30 days). */
  async restore(tenantId: number, actor: DbActor): Promise<void> {
    const key = await appleTenants.keyOf(tenantId);
    await appleEdge.restoreTenant(key, { actor: edgeActorOf(actor) });
    await withTenantTransaction(tenantId, actor, (trx) => upsertMirror(trx, tenantId, { edge_state: 'active', edge_state_at: new Date() }));
  },

  /** The enrollment configuration (§6.4), cached 10 minutes in the mirror; refresh forces a call. Throws the
   *  AppleEdgeError of apple-edge (409 tenant_not_live for a tenant being retired). */
  async enrollmentConfig(tenantId: number, actor: DbActor, opts: { refresh?: boolean } = {}): Promise<EdgeEnrollmentConfig> {
    const cached = await asTenant(tenantId, actor, async () => {
      const t = await db('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
      const m = await db('tenant_apple_edge').where({ tenant_id: tenantId }).first('enrollment_config', 'enrollment_config_at') as
        { enrollment_config: EdgeEnrollmentConfig | null; enrollment_config_at: Date | null } | undefined;
      return { key: t?.mdm_key ?? null, config: m?.enrollment_config ?? null, at: m?.enrollment_config_at ?? null };
    });
    if (!cached.key) throw new AppError(409, 'This tenant is not provisioned at the device service yet', 'appleTenantNotProvisioned');
    if (!opts.refresh && cached.config && cached.at && Date.now() - new Date(cached.at).getTime() < ENROLLMENT_CONFIG_TTL_MS) {
      return cached.config;
    }
    const fresh = await appleEdge.enrollmentConfig(cached.key, { actor: edgeActorOf(actor) });
    await withTenantTransaction(tenantId, actor, (trx) => upsertMirror(trx, tenantId, { enrollment_config: fresh }));
    return fresh;
  },

  /** Rotation of the tenant's CA (§6.5): the mirror and the device_ca deadline follow the answer, then the
   *  event tenant.ca_rotated; the audit entry is the caller's (apple.tenant_ca_rotated, P2). */
  async rotateCa(tenantId: number, actor: DbActor): Promise<EdgeCaRotation> {
    const key = await asTenant(tenantId, actor, () => appleTenants.keyOf(tenantId));
    const rotation = await appleEdge.rotateCa(key, { actor: edgeActorOf(actor) });
    await withTenantTransaction(tenantId, actor, async (trx) => {
      const current = await trx('tenant_apple_edge').where({ tenant_id: tenantId }).first('ca_verify_only') as { ca_verify_only: unknown } | undefined;
      const kept = (Array.isArray(current?.ca_verify_only) ? current?.ca_verify_only as Array<{ id: string; sha256: string | null; not_after: string | null }> : []);
      const verify = new Map(kept.map((v) => [v.id, v]));
      for (const v of rotation.verify_only) verify.set(v.id, { id: v.id, sha256: v.sha256, not_after: v.not_after });
      verify.delete(rotation.ca.id);
      await upsertMirror(trx, tenantId, { ca: rotation.ca, verify_only: [...verify.values()], enrollment_config: null, last_synced_at: new Date() });
      await recordDeviceCaDeadline(trx, tenantId, rotation.ca);
    });
    return rotation;
  },

  /** README §5, temporary measure: before the hard deletion of a tenant, its retirement at apple-edge.
   *  APPLE_EDGE_MODE=off with a key: refused (the tenant would stay active at apple-edge, without reference).
   *  Unknown to apple-edge, or already retired there: nothing left to retire, the deletion goes on. */
  async retireBeforeDeletion(tenantId: number, actor: DbActor): Promise<'retiring' | 'no_edge_tenant'> {
    const key = await appleTenants.keyOrNull(tenantId);
    if (!key) return 'no_edge_tenant';
    if (config.apple.mode !== 'on') {
      throw new AppError(503, 'This tenant has devices service data at apple-edge and the Apple integration is turned off: turn it on to delete the tenant', 'appleIntegrationDisabled');
    }
    try {
      return await appleTenants.retire(tenantId, actor);
    } catch (err) {
      if (isAppleEdgeError(err)) {
        // apple-edge's Retire answers 409 tenant_not_live for a retired tenant only (a retiring one: 200), e.g.
        // a tenant brought back by the restore of an older backup of the brain: otherwise never deletable here.
        if (err.code === 'tenant_not_found' || err.code === 'tenant_not_live') return 'no_edge_tenant';
        const { edgeErrorResponse } = await import('../edge/errors');
        const r = edgeErrorResponse(err, 'console');
        throw new AppError(r.status, r.message, r.code);
      }
      throw err;
    } finally {
      forgetKey(key);
    }
  },
};

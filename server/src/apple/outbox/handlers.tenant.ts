import type { Knex } from 'knex';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { applyTenantContext } from '../../db/tenantContext';
import { registerOutboxHandler, type OutboxHandlerContext } from '../../jobs';
import { raiseMasterInTx, resolveMasterInTx } from '../alerts/service';
import { appleTenants, recordDeviceCaDeadline, upsertMirror } from '../tenants/registry';
import { P } from './schemas';

// =============================================================================
// Handlers of the tenant events of apple-edge (docs: integration-apple-edge
// §6.2, §6.3, §7.4; rules G-1 to G-9 of §7.2). Writes through ctx.trx only, no
// network call; monotone by occurred_at (edge_state_at of the mirror; for the
// CA, its expiry: a newer CA expires later).
//   tenant.created        platform: tenant by external_ref; key written once
//                         (tenant_set_mdm_key) when absent, with
//                         apple.tenant_provisioned at the first key; mirror;
//                         provisioning job when the CA or the enrollment
//                         configuration is still missing; unknown
//                         external_ref: platform.edge_orphan; another key
//                         than the tenant's, or a key another tenant holds:
//                         tenant.mdm_key_conflict, nothing written
//   tenant.state_changed  platform: tenant by key; mirror; audit in the
//                         tenant's chain; retired: platform.tenant_retired
//   tenant.load_failed    platform: mirror load_failed, platform.tenant_load_failed
//   tenant.ca_rotated     tenant: mirror of the CA, enrollment configuration
//                         invalidated, device_ca deadline replaced
// A platform event sets the tenant's context itself (G-6) and writes the
// platform alerts in the master tenant's context (raiseMasterInTx). Before
// writing, a handler locks the tenant's row (FOR KEY SHARE, FOR UPDATE for
// tenant.created): a deletion of the tenant running meanwhile waits for the
// batch, and one that already committed makes the event moot (no write).
// =============================================================================

type TenantRow = { id: number; name: string; mdm_key: string | null };
type Payload<K extends keyof typeof P> = (typeof P)[K]['_output'];

async function tenantByKey(trx: Knex.Transaction, key: string): Promise<TenantRow | undefined> {
  return trx('tenants').where({ mdm_key: key }).first('id', 'name', 'mdm_key') as Promise<TenantRow | undefined>;
}

/** In the tenant's context: its row locked (FOR KEY SHARE) until the batch commits, so that a deletion
 *  running meanwhile waits for the mirror's write; false when the deletion already committed (the event is
 *  then moot). */
async function lockTenant(trx: Knex.Transaction, tenantId: number): Promise<boolean> {
  const res = await trx.raw('SELECT 1 FROM obligarth.tenants WHERE id = ? FOR KEY SHARE', [tenantId]) as { rows: unknown[] };
  return res.rows.length > 0;
}

/** Updates the mirror's state when the event is newer than the state it holds (monotone, G-3). */
async function mirrorStateAt(trx: Knex.Transaction, tenantId: number, state: string, at: Date): Promise<boolean> {
  const res = await trx.raw(`
    INSERT INTO obligarth.tenant_apple_edge AS m (tenant_id, edge_state, edge_state_at, last_synced_at)
    VALUES (?, ?, ?, now())
    ON CONFLICT (tenant_id) DO UPDATE
       SET edge_state = EXCLUDED.edge_state, edge_state_at = EXCLUDED.edge_state_at, last_synced_at = now(), updated_at = now()
     WHERE m.edge_state_at IS NULL OR m.edge_state_at < EXCLUDED.edge_state_at`, [tenantId, state, at]) as { rowCount?: number };
  return Number(res.rowCount ?? 0) > 0;
}

async function onTenantCreated(ctx: OutboxHandlerContext<Payload<'tenant.created'>>): Promise<void> {
  const { trx, event } = ctx;
  const p = event.payload;
  const t = await trx('tenants').where({ uuid: p.external_ref }).first('id', 'name', 'mdm_key') as TenantRow | undefined;
  if (!t) {
    // A tenant of apple-edge that no tenant of the brain references (deleted here, or another brain).
    await raiseMasterInTx(trx, 'platform.edge_orphan', { discriminant: p.key, params: { key: p.key } }, ctx.actor, null);
    return;
  }
  await applyTenantContext(trx, t.id, ctx.actor);
  // The key, once: the provisioning job may set it first (same key: no effect), never another one. The row
  // lock serialises with the job, so that one of them only journals the first key.
  const current = await trx('tenants').where({ id: t.id }).forUpdate().first('mdm_key') as { mdm_key: string | null } | undefined;
  if (!current) return;                                 // deleted meanwhile: nothing to provision
  if (current.mdm_key !== null && current.mdm_key !== p.key) {
    await raiseMasterInTx(trx, 'tenant.mdm_key_conflict', { discriminant: t.id, params: { tenantName: t.name } }, ctx.actor, t.id);
    return;
  }
  if (current.mdm_key === null) {
    // A key another tenant of the brain already holds: the two bases disagree (partial restore). As the
    // provisioning job does (§6.2): the critical alert, the key never written, no retry (waiting cannot heal).
    const holder = await trx('tenants').where({ mdm_key: p.key }).whereNot({ id: t.id }).first('id') as { id: number } | undefined;
    if (holder) {
      await raiseMasterInTx(trx, 'tenant.mdm_key_conflict', { discriminant: t.id, params: { tenantName: t.name } }, ctx.actor, t.id);
      return;
    }
    await trx.raw('SELECT obligarth.tenant_set_mdm_key(?, ?)', [t.id, p.key]);
    ctx.audit({
      tenantId: t.id, action: 'apple.tenant_provisioned', target: { type: 'tenant', id: String(t.id) },
      details: { created: true, state: p.state, source: 'event' },
    });
  }
  await mirrorStateAt(trx, t.id, p.state === 'suspended' ? 'suspended' : 'active', event.occurredAt);
  const m = await trx('tenant_apple_edge').where({ tenant_id: t.id }).first('enrollment_config', 'ca_id') as
    { enrollment_config: unknown; ca_id: string | null } | undefined;
  if (!m?.enrollment_config || !m.ca_id) await appleTenants.scheduleProvisioning(trx, t.id);
}

async function onTenantStateChanged(ctx: OutboxHandlerContext<Payload<'tenant.state_changed'>>): Promise<void> {
  const { trx, event } = ctx;
  const p = event.payload;
  const t = await tenantByKey(trx, p.key);
  if (!t) return;                                       // deleted in the brain meanwhile: nothing to mirror
  await applyTenantContext(trx, t.id, ctx.actor);
  if (!(await lockTenant(trx, t.id))) return;           // its deletion committed during the batch
  if (!(await mirrorStateAt(trx, t.id, p.state, event.occurredAt))) return;   // an older event consumed late
  ctx.audit({
    tenantId: t.id, action: 'apple.tenant_state_changed', target: { type: 'tenant', id: String(t.id) },
    details: { state: p.state, source: 'apple-edge' },
  });
  await resolveMasterInTx(trx, 'platform.tenant_load_failed', t.id, ctx.actor, t.id);
  if (p.state === 'retired') {
    await raiseMasterInTx(trx, 'platform.tenant_retired', { discriminant: t.id, params: { tenantName: t.name } }, ctx.actor, t.id);
  }
}

async function onTenantLoadFailed(ctx: OutboxHandlerContext<Payload<'tenant.load_failed'>>): Promise<void> {
  const { trx, event } = ctx;
  const t = await tenantByKey(trx, event.payload.key);
  if (!t) return;
  await applyTenantContext(trx, t.id, ctx.actor);
  if (!(await lockTenant(trx, t.id))) return;
  if (!(await mirrorStateAt(trx, t.id, 'load_failed', event.occurredAt))) return;
  ctx.audit({
    tenantId: MASTER_TENANT_ID, onBehalfOf: t.id, action: 'apple.tenant_state_changed', target: { type: 'tenant', id: String(t.id) },
    details: { state: 'load_failed', source: 'apple-edge' },
  });
  await raiseMasterInTx(trx, 'platform.tenant_load_failed', { discriminant: t.id, params: { tenantName: t.name } }, ctx.actor, t.id);
}

async function onTenantCaRotated(ctx: OutboxHandlerContext<Payload<'tenant.ca_rotated'>>): Promise<void> {
  const { trx, event } = ctx;
  const tenantId = ctx.tenantId as number;
  const p = event.payload;
  if (!(await lockTenant(trx, tenantId))) return;
  const m = await trx('tenant_apple_edge').where({ tenant_id: tenantId }).first('ca_id', 'ca_sha256', 'ca_not_after', 'ca_verify_only') as
    { ca_id: string | null; ca_sha256: string | null; ca_not_after: Date | null; ca_verify_only: unknown } | undefined;
  const notAfter = new Date(p.not_after);
  if (m?.ca_id === p.ca_id) return;                     // already mirrored (the rotation's answer, or a replay)
  if (m?.ca_not_after && new Date(m.ca_not_after).getTime() >= notAfter.getTime()) return;   // an older rotation
  const previous = Array.isArray(m?.ca_verify_only)
    ? m?.ca_verify_only as Array<{ id: string; sha256: string | null; not_after: string | null }> : [];
  const verify = new Map(previous.filter((v) => p.verify_only.includes(v.id)).map((v) => [v.id, v]));
  if (m?.ca_id && p.verify_only.includes(m.ca_id)) {
    verify.set(m.ca_id, { id: m.ca_id, sha256: m.ca_sha256, not_after: m.ca_not_after ? new Date(m.ca_not_after).toISOString() : null });
  }
  for (const id of p.verify_only) if (!verify.has(id)) verify.set(id, { id, sha256: null, not_after: null });
  const ca = { id: p.ca_id, sha256: p.sha256, not_after: notAfter.toISOString() };
  await upsertMirror(trx, tenantId, { ca, verify_only: [...verify.values()], enrollment_config: null });
  await recordDeviceCaDeadline(trx, tenantId, ca);
}

let registered = false;

export function registerTenantHandlers(): void {
  if (registered) return;
  registered = true;
  registerOutboxHandler({ type: 'tenant.created', scope: 'platform', module: 'apple', payload: P['tenant.created'], handle: onTenantCreated });
  registerOutboxHandler({ type: 'tenant.state_changed', scope: 'platform', module: 'apple', payload: P['tenant.state_changed'], handle: onTenantStateChanged });
  registerOutboxHandler({ type: 'tenant.load_failed', scope: 'platform', module: 'apple', payload: P['tenant.load_failed'], handle: onTenantLoadFailed });
  registerOutboxHandler({ type: 'tenant.ca_rotated', scope: 'tenant', module: 'apple', payload: P['tenant.ca_rotated'], handle: onTenantCaRotated });
}

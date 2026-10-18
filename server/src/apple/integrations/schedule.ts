import { connect as tlsConnect } from 'node:tls';
import type { Knex } from 'knex';
import { z } from 'zod';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { asIdentity, type DbActor } from '../../db/context';
import { forEachTenant } from '../../db/tenantContext';
import { JobError, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { logger } from '../../utils/logger';
import { vault } from '../../vault';
import { raiseAlert, raiseInTx, resolveAlert, resolveInTx } from '../alerts/service';
import type { AppleAlertKind } from '../alerts/catalog';
import { edgeHealth } from '../edge/health';
import { realtime } from '../realtime';
import { appleTenants } from '../tenants/registry';
import { reconcileAdeServers } from './ade';
import { recordInstanceDeadline, retireInstanceDeadlines } from './deadlines';
import { decide, OLD_SHARES_DAYS, severityOfThreshold, type ItemState } from './deadlineRules';
import { abandonStaleRequests } from './push';

// =============================================================================
// The échéancier of the integrations (docs: integration-apple-edge §11.4,
// INT-05; coffre-secrets §11.5) and the other periodic jobs of the lot C3
// (annex B):
//   integrations.deadlines-all     platform, 0 6 * * * UTC: the producers of
//                                  the instance (vault, signing identity of
//                                  apple-edge), the items of the instance
//                                  (alerts in the master tenant), then
//                                  integrations.deadlines-tenant for each tenant
//                                  that has items
//   integrations.deadlines-tenant  tenant, exclusive t:<id>: its items
//   integrations.tls-check         platform, 30 5 * * *: TLS handshake with the
//                                  host of MDM_PUBLIC_BASE, the certificate's expiry
//   integrations.ade-reconcile     platform, 25 * * * *: the ADE mirror against
//                                  apple-edge's list (ade.ts)
//   integrations.push-abandon      platform, 45 5 * * *: push requests open for
//                                  more than 30 days are abandoned
// Thresholds J-60, 30, 14, 7, 3, 1 and 0 (expired) by default (the vault's own
// lists for its kinds); a threshold crossed and not yet alerted for this expiry
// (last_alert_threshold, last_alerted_not_after) raises deadline.<kind>
// (warning at J-60 and J-30, critical from J-14), in the tenant concerned or in
// the master tenant for an item of the instance; a new expiry (a renewal)
// resolves the open alert and starts again. Exactly once per threshold and
// expiry: for a tenant item, the alert and the mark are written in one
// transaction (the delivery job is sent in it); for an item of the instance,
// the alert is raised first (deduplicated on its open row), the mark written
// after: a crash between the two raises nothing new the next day.
// =============================================================================

const DAY = 86_400_000;
const ESCROW_TEST_DAYS = 365;
const KEK_ROTATION_DAYS = 730;
/** A retired item is kept this long (the view shows it), then deleted. */
const RETIRED_KEEP_DAYS = 30;

interface ItemRow extends ItemState {
  id: string;
  tenant_id: number | null;
  label: string;
}

const alertKindOf = (kind: string): AppleAlertKind => `deadline.${kind}` as AppleAlertKind;
const paramsOf = (r: ItemRow, daysLeft: number) => ({ label: r.label, daysLeft, notAfter: new Date(r.not_after as Date).toISOString().slice(0, 10) });
const ITEM_COLS = ['id', 'tenant_id', 'kind', 'label', 'not_after', 'retired_at', 'last_alert_threshold', 'last_alerted_not_after'];

/** One tenant item, in its own transaction (tenant context). True when something changed. */
async function processTenantItem(tenantId: number, id: string, now: Date): Promise<boolean> {
  return db.transaction(async (trx) => {
    const r = await trx('integration_deadline_items').where({ tenant_id: tenantId, id }).forUpdate().first(ITEM_COLS) as ItemRow | undefined;
    if (!r) return false;
    const d = decide(r, now);
    if (d.action === 'none') return false;
    const kind = alertKindOf(r.kind);
    if (d.action === 'resolve' || d.resolveFirst) await resolveInTx(trx, tenantId, kind, r.id);
    if (d.action === 'resolve') {
      await trx('integration_deadline_items').where({ tenant_id: tenantId, id }).update({ last_alert_threshold: null, last_alerted_not_after: null });
      return true;
    }
    await raiseInTx(trx, tenantId, kind, { discriminant: r.id, params: paramsOf(r, d.daysLeft), severity: severityOfThreshold(d.threshold), navigateTo: '/integrations' });
    await trx('integration_deadline_items').where({ tenant_id: tenantId, id })
      .update({ last_alert_threshold: d.threshold, last_alerted_not_after: r.not_after });
    return true;
  });
}

/** integrations.deadlines-tenant. */
async function deadlinesTenant(ctx: JobContext<{ tenantId: number }>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const now = new Date();
  let changed = 0;
  const ids = await ctx.inTenant(async () => {
    await db('integration_deadline_items').where({ tenant_id: tenantId }).whereNotNull('retired_at')
      .where('retired_at', '<', new Date(now.getTime() - RETIRED_KEEP_DAYS * DAY)).whereNull('last_alert_threshold').del();
    return db('integration_deadline_items').where({ tenant_id: tenantId })
      .where((q) => q.whereNull('retired_at').orWhereNotNull('last_alert_threshold')).pluck('id') as Promise<string[]>;
  });
  for (const id of ids) {
    ctx.throwIfAborted();
    if (await ctx.inTenant(() => processTenantItem(tenantId, String(id), now))) changed += 1;
  }
  if (changed) realtime.integrationChanged(tenantId, 'deadlines');
  return { output: { items: ids.length, changed } };
}

/** One instance item: the alert in the master tenant first (deduplicated), then the mark (identity context). */
async function processInstanceItem(actor: DbActor, r: ItemRow, now: Date): Promise<boolean> {
  const d = decide(r, now);
  if (d.action === 'none') return false;
  const kind = alertKindOf(r.kind);
  if (d.action === 'resolve' || d.resolveFirst) await resolveAlert(actor, MASTER_TENANT_ID, kind, r.id);
  if (d.action === 'resolve') {
    await asIdentity(actor, () => db('integration_deadline_items').whereNull('tenant_id').where({ id: r.id })
      .update({ last_alert_threshold: null, last_alerted_not_after: null }));
    return true;
  }
  await raiseAlert(actor, MASTER_TENANT_ID, kind, { discriminant: r.id, params: paramsOf(r, d.daysLeft), severity: severityOfThreshold(d.threshold), navigateTo: '/integrations' });
  await asIdentity(actor, () => db('integration_deadline_items').whereNull('tenant_id').where({ id: r.id })
    .update({ last_alert_threshold: d.threshold, last_alerted_not_after: r.not_after }));
  return true;
}

/** The vault's deadlines (coffre-secrets §11.5), as items of the instance. Skipped while the vault is not ready. */
async function refreshVaultItems(actor: DbActor): Promise<boolean> {
  let f: Awaited<ReturnType<typeof vault.deadlineFacts>>;
  try {
    f = await vault.deadlineFacts();
  } catch (err) {
    logger.warn({ code: (err as { code?: unknown })?.code ?? null }, 'deadlines: the vault is not ready, its deadlines are skipped');
    return false;
  }
  await asIdentity(actor, () => db.transaction(async (trx) => {
    if (f.escrowedAt) {
      await recordInstanceDeadline(trx, { kind: 'vault_escrow_test', subjectRef: 'escrow', label: 'Escrow test of the vault keys',
        notAfter: new Date(f.escrowedAt.getTime() + ESCROW_TEST_DAYS * DAY), source: 'vault', replace: true });
    }
    const since = f.rotatedAt ?? f.installedAt;
    if (since) {
      await recordInstanceDeadline(trx, { kind: 'vault_kek_rotation', subjectRef: f.kekId, label: `Rotation of the key-encryption key ${f.kekId}`,
        notAfter: new Date(since.getTime() + KEK_ROTATION_DAYS * DAY), source: 'vault', replace: true });
      await retireInstanceDeadlines(trx, 'vault_kek_rotation', f.kekId);
    }
    if (f.rotatedAt && !(f.oldSharesDestroyedAt && f.oldSharesDestroyedAt.getTime() >= f.rotatedAt.getTime())) {
      await recordInstanceDeadline(trx, { kind: 'vault_old_shares', subjectRef: 'old-shares', label: 'Destruction of the escrow shares of the previous key',
        notAfter: new Date(f.rotatedAt.getTime() + OLD_SHARES_DAYS * DAY), source: 'vault', replace: true });
    } else {
      await retireInstanceDeadlines(trx, 'vault_old_shares');
    }
    if (f.nextDekDestruction) {
      await recordInstanceDeadline(trx, { kind: 'vault_dek_destruction', subjectRef: 'dek', label: 'Scheduled destruction of data keys',
        notAfter: f.nextDekDestruction, source: 'vault', replace: true });
    } else {
      await retireInstanceDeadlines(trx, 'vault_dek_destruction');
    }
  }));
  return true;
}

/** The signing identity apple-edge announces (its status), as the item profile_signing_identity of source apple-edge
 *  (a manual entry stays, it is the administrator's). */
async function refreshSigningItem(actor: DbActor): Promise<void> {
  if (config.apple.mode !== 'on') return;
  const s = edgeHealth().signingIdentity;
  await asIdentity(actor, () => db.transaction(async (trx) => {
    if (s && /^[0-9a-f]{64}$/i.test(s.sha256) && !Number.isNaN(Date.parse(s.notAfter))) {
      await recordInstanceDeadline(trx, { kind: 'profile_signing_identity', subjectRef: s.sha256.toLowerCase(), label: 'Profile signing identity',
        notAfter: new Date(s.notAfter), source: 'apple-edge', replace: true });
    }
    let q = trx('integration_deadline_items').whereNull('tenant_id').where({ kind: 'profile_signing_identity', source: 'apple-edge' }).whereNull('retired_at');
    if (s) q = q.whereNot('subject_ref', s.sha256.toLowerCase());
    await q.update({ retired_at: new Date(), updated_at: new Date() });
  }));
}

let tenantJob: JobHandle<{ tenantId: number }> | null = null;

/** integrations.deadlines-all. */
async function deadlinesAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  const now = new Date();
  const vaultDone = await refreshVaultItems(ctx.dbActor);
  await refreshSigningItem(ctx.dbActor);
  const items = await asIdentity(ctx.dbActor, async () => {
    await db('integration_deadline_items').whereNull('tenant_id').whereNotNull('retired_at')
      .where('retired_at', '<', new Date(now.getTime() - RETIRED_KEEP_DAYS * DAY)).whereNull('last_alert_threshold').del();
    return db('integration_deadline_items').whereNull('tenant_id')
      .where((q) => q.whereNull('retired_at').orWhereNotNull('last_alert_threshold')).select(ITEM_COLS) as Promise<ItemRow[]>;
  });
  let instanceChanged = 0;
  for (const r of items) {
    ctx.throwIfAborted();
    if (await processInstanceItem(ctx.dbActor, r, now)) instanceChanged += 1;
  }
  if (instanceChanged) realtime.integrationChanged(MASTER_TENANT_ID, 'deadlines');
  let tenants = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const any = await db('integration_deadline_items').where({ tenant_id: tenantId })
      .where((q) => q.whereNull('retired_at').orWhereNotNull('last_alert_threshold')).first('id');
    if (!any) return;
    await (tenantJob as JobHandle<{ tenantId: number }>).send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
    tenants += 1;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { instanceItems: items.length, instanceChanged, tenants, vault: vaultDone } };
}

/** The certificate an HTTPS host presents: its expiry and fingerprint (no trust decision: what is read is the date). */
export function tlsExpiry(host: string, port: number, timeoutMs = 10_000): Promise<{ notAfter: Date; sha256: string }> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({ host, port, servername: /^[\d.]+$/.test(host) ? undefined : host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const c = socket.getPeerCertificate();
      socket.end();
      if (!c || !c.valid_to) { reject(new Error('no certificate')); return; }
      resolve({ notAfter: new Date(c.valid_to), sha256: String(c.fingerprint256 ?? '').replace(/:/g, '').toLowerCase() });
    });
    socket.on('timeout', () => { socket.destroy(); reject(new Error('timeout')); });
    socket.on('error', (err) => reject(err));
  });
}

/** integrations.tls-check. */
async function tlsCheck(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  if (config.apple.mode !== 'on' || !config.apple.mdmPublicBase) return { output: { skipped: 'apple_edge_off' } };
  const u = new URL(config.apple.mdmPublicBase);
  if (u.protocol !== 'https:') return { output: { skipped: 'not_https' } };
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const port = Number(u.port || 443);
  let r: { notAfter: Date; sha256: string };
  try {
    r = await tlsExpiry(host, port);
  } catch (err) {
    throw new JobError('tls_unreachable', `TLS handshake with the device service host failed (${(err as { code?: string }).code ?? 'error'})`, true);
  }
  await asIdentity(ctx.dbActor, () => db.transaction((trx) => recordInstanceDeadline(trx, {
    kind: 'mdm_tls_certificate', subjectRef: u.host.slice(0, 100), label: `TLS certificate of ${u.host}`, notAfter: r.notAfter, source: 'brain', replace: true,
  })));
  return { output: { notAfter: r.notAfter.toISOString() } };
}

/** integrations.ade-reconcile. */
async function adeReconcile(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  let updated = 0;
  let tenants = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const key = await appleTenants.keyOrNull(tenantId);
    if (!key) return;
    const mirrored = await db('tenant_apple_ade_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed').first('id');
    const edgeKnows = await db('tenant_apple_edge').where({ tenant_id: tenantId, edge_state: 'active' }).first('tenant_id');
    if (!mirrored && !edgeKnows) return;
    const r = await reconcileAdeServers(tenantId, key, ctx.dbActor);
    updated += r.updated + r.added + r.removed;
    tenants += 1;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { tenants, changed: updated } };
}

/** integrations.push-abandon. */
async function pushAbandon(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let abandoned = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const n = await db.transaction((trx: Knex.Transaction) => abandonStaleRequests(trx, tenantId, 30));
    if (n) realtime.integrationChanged(tenantId, 'push');
    abandoned += n;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { abandoned } };
}

const Empty = z.object({}).strict();
const SWEEP = { deadLetter: false, trackStatus: 'queue', manualRun: true, keepFinishedSeconds: 172_800, keepPendingSeconds: 86_400 } as const;

let registered = false;

export function registerIntegrationJobs(): void {
  if (registered) return;
  registered = true;
  const on = config.apple.mode === 'on';
  tenantJob = registerJob({
    name: 'integrations.deadlines-tenant',
    scope: 'tenant',
    description: 'The deadlines of a tenant (push certificate, ADE tokens, content tokens, device CA): alerts at their thresholds',
    payload: z.object({ tenantId: z.number().int().positive() }).strict(),
    policy: 'exclusive',
    retry: { limit: 2, delaySeconds: 300, backoff: true },
    timeoutSeconds: 300,
    pollSeconds: 300,
    handler: deadlinesTenant,
  });
  // The deadlines of the instance include the vault's: scheduled whatever APPLE_EDGE_MODE says.
  registerJob({
    name: 'integrations.deadlines-all',
    scope: 'platform',
    description: 'Every day at 06:00 UTC: the deadlines of the instance (vault, vendor certificate, TLS, domain, signing identity) and of every tenant',
    payload: Empty,
    policy: 'exclusive',
    schedule: { cron: '0 6 * * *' },
    retry: { limit: 2, delaySeconds: 600, backoff: true },
    timeoutSeconds: 900,
    handler: deadlinesAll,
  });
  registerJob({
    name: 'integrations.tls-check',
    scope: 'platform',
    description: 'Every day at 05:30 UTC: the expiry of the TLS certificate the device service host presents',
    payload: Empty,
    policy: 'exclusive',
    ...(on ? { schedule: { cron: '30 5 * * *' } } : {}),
    retry: { limit: 2, delaySeconds: 600, backoff: true },
    timeoutSeconds: 120,
    pollSeconds: 300,
    ...SWEEP,
    handler: tlsCheck,
  });
  registerJob({
    name: 'integrations.ade-reconcile',
    scope: 'platform',
    description: 'Every hour: the ADE servers of every tenant compared with the device service',
    payload: Empty,
    policy: 'exclusive',
    ...(on ? { schedule: { cron: '25 * * * *' } } : {}),
    retry: { limit: 2, delaySeconds: 300, backoff: true },
    timeoutSeconds: 900,
    pollSeconds: 300,
    ...SWEEP,
    handler: adeReconcile,
  });
  registerJob({
    name: 'integrations.push-abandon',
    scope: 'platform',
    description: 'Every day at 05:45 UTC: push certificate requests open for more than 30 days are abandoned',
    payload: Empty,
    policy: 'exclusive',
    ...(on ? { schedule: { cron: '45 5 * * *' } } : {}),
    retry: { limit: 2, delaySeconds: 600, backoff: true },
    timeoutSeconds: 300,
    pollSeconds: 300,
    ...SWEEP,
    handler: pushAbandon,
  });
}

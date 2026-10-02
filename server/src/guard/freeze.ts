// Emergency freeze of a tenant (docs: audit-durci §10.7): open to the
// platform administrators, the tenant's administrators and its designated
// approvers of both sides, under a step-up (trusted IP accepted: speed
// matters); automatic on anomaly (§10.9). The freeze is protective: it never
// depends on the journal (entries written after the commit, P4). Scheduled
// actions are paused (never resumed by themselves: 24 h, then expired).
// apple-edge stops delivering the tenant's commands (lot B handler; without
// one the freeze stays in the brain). Unfreezing goes through an approval
// (guard.unfreeze, floor 'restricted', the examination policy of §10.4).
import { audit, type AuditWriteContext } from '../audit';
import { db } from '../db';
import { asTenant, type DbActor } from '../db/context';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';
import { edgeFreezeOf } from './catalog';
import { cancelJob, edgeFreezeSyncJob } from './jobs';
import { guardMetrics } from './metrics';
import { alertTenantAndMsp, emitState, notifyAction } from './notify';
import { readSettings } from './settings';
import { ACTION_COLUMNS, normaliseRow, toDtos, type PendingActionRow } from './store';

const ANOMALY_ACTOR: DbActor = { type: 'job', name: 'guard.anomalies' };

export interface FreezeResult {
  frozen: boolean;
  frozenAt: string | null;
  /** false: it was frozen already (nothing changed). */
  changed: boolean;
  paused: number;
}

/**
 * Freezes the tenant (in its database context). One transaction: the
 * settings and the scheduled actions paused; then, after the commit, the
 * entries (guard.action_paused per action, guard.tenant_frozen), the jobs
 * cancelled, apple-edge, the alerts and the events.
 */
export async function freezeTenant(tenantId: number, by: { userId: number | null; source: 'manual' | 'anomaly'; reason: string; anomaly?: string },
  ctx: AuditWriteContext): Promise<FreezeResult> {
  const { changed, frozenAt, paused } = await db.transaction(async (trx) => {
    const s = await readSettings(tenantId, trx, { forUpdate: true });
    if (s.frozen_at) return { changed: false, frozenAt: s.frozen_at, paused: [] as PendingActionRow[] };
    const now = new Date();
    await trx('tenant_guard_settings').where({ tenant_id: tenantId }).update({
      frozen_at: now, frozen_by: by.userId, frozen_source: by.source, frozen_reason: by.reason.slice(0, 500), updated_at: now,
    });
    const rows = await trx('pending_actions').where({ tenant_id: tenantId, state: 'scheduled' })
      .update({ state: 'paused', paused_at: now, updated_at: now }).returning(ACTION_COLUMNS);
    return { changed: true, frozenAt: now, paused: (rows as Array<Record<string, unknown>>).map(normaliseRow) };
  });
  if (!changed) return { frozen: true, frozenAt: frozenAt ? frozenAt.toISOString() : null, changed: false, paused: 0 };

  guardMetrics.inc('obligarth_guard_freezes_total', { source: by.source });
  // P4: the freeze stands whatever the journal says.
  for (const row of paused) {
    await audit.append({
      tenantId, action: 'guard.action_paused', outcome: 'success', links: { action: row.uuid },
      details: { actionKey: row.action_key, family: row.family, code: 'frozen' },
    }, ctx);
    if (row.job_id) await cancelJob(row.job_id);
  }
  await audit.append({
    tenantId, action: 'guard.tenant_frozen', outcome: 'success', reason: by.reason,
    details: { source: by.source, paused: paused.length, ...(by.anomaly ? { anomaly: by.anomaly } : {}) },
  }, ctx);
  await syncEdge(tenantId, true);
  emitState({ tenantId, frozen: true, frozenAt: frozenAt ? frozenAt.toISOString() : null, source: by.source });
  for (const dto of await toDtos(paused)) await notifyAction(dto, { code: 'frozen' });
  await alertTenantAndMsp(tenantId, {
    severity: 'critical',
    title: by.source === 'anomaly' ? 'Tenant frozen automatically (anomaly)' : 'Tenant frozen',
    message: `Guarded actions and MDM commands are stopped${by.anomaly ? ` (rule ${by.anomaly})` : ''}. Unfreezing needs a second approver.`,
    stableKey: `guard:freeze:${tenantId}:${frozenAt ? frozenAt.getTime() : 0}`,
  });
  return { frozen: true, frozenAt: frozenAt ? frozenAt.toISOString() : null, changed: true, paused: paused.length };
}

/** The automatic freeze of an anomaly (frozen_by null, source 'anomaly'):
 *  entry guard.anomaly_detected then the freeze. Never throws. */
export async function autoFreeze(tenantId: number, rule: 'A1' | 'A2'): Promise<void> {
  try {
    await asTenant(tenantId, ANOMALY_ACTOR, async () => {
      if ((await readSettings(tenantId)).frozen_at) return;
      const ctx = audit.fromJob({ name: ANOMALY_ACTOR.type === 'job' ? ANOMALY_ACTOR.name : 'guard.anomalies', requestId: `anomaly-${rule}` });
      guardMetrics.inc('obligarth_guard_anomalies_total', { rule });
      await audit.append({ tenantId, action: 'guard.anomaly_detected', outcome: 'success', details: { rule } }, ctx);
      await freezeTenant(tenantId, {
        userId: null, source: 'anomaly', anomaly: rule,
        reason: rule === 'A1' ? 'Automatic freeze: the hourly cap was exceeded twice in 24 hours'
          : 'Automatic freeze: three refusals for cooldown in 24 hours',
      }, ctx);
    });
  } catch (err) {
    logger.error({ err: safeErr(err), tenantId, rule }, 'guard: automatic freeze failed');
  }
}

/**
 * Lifts the freeze (the approved guard_unfreeze, in the tenant's context, as
 * the requester): settings and guard.tenant_unfrozen in one transaction (P1),
 * then apple-edge and the events. Paused actions stay paused.
 */
export async function unfreezeTenant(tenantId: number, ctx: AuditWriteContext, o: { approvalIds: number[]; reason: string; userId: number }): Promise<boolean> {
  const changed = await db.transaction(async (trx) => {
    const s = await readSettings(tenantId, trx, { forUpdate: true });
    if (!s.frozen_at) return false;
    await trx('tenant_guard_settings').where({ tenant_id: tenantId }).update({
      frozen_at: null, frozen_by: null, frozen_source: null, frozen_reason: null, updated_by: o.userId, updated_at: new Date(),
    });
    await audit.appendInTx(trx, {
      tenantId, action: 'guard.tenant_unfrozen', outcome: 'success', reason: o.reason, approvalIds: o.approvalIds,
      details: { frozenSince: s.frozen_at.toISOString(), source: s.frozen_source },
    }, ctx);
    return true;
  });
  if (!changed) return false;
  await syncEdge(tenantId, false);
  emitState({ tenantId, frozen: false, frozenAt: null, source: null });
  await alertTenantAndMsp(tenantId, {
    severity: 'critical',
    title: 'Tenant unfrozen',
    message: 'Guarded actions are possible again; paused actions stay paused until resumed or cancelled.',
    stableKey: `guard:unfreeze:${tenantId}:${Date.now()}`,
  });
  return true;
}

/**
 * The freeze at apple-edge (§10.7; review AUD-RC3): the handler of the
 * integration (lot B), called after the commit; on a failure, the job
 * actions.edge-freeze-sync retries every minute and alerts. No handler
 * (lot A, APPLE_EDGE_MODE=off) or a tenant apple-edge does not know yet: no
 * alert, its provisioning carries the freeze over.
 */
export async function syncEdge(tenantId: number, frozen: boolean): Promise<'done' | 'no_edge_tenant' | 'apple_edge_off' | 'queued'> {
  const handler = edgeFreezeOf();
  if (!handler) return 'apple_edge_off';
  try {
    return await handler(tenantId, frozen);
  } catch (err) {
    logger.warn({ err: safeErr(err), tenantId, frozen }, 'guard: apple-edge freeze failed, retried by actions.edge-freeze-sync');
    try {
      await edgeFreezeSyncJob().send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
    } catch (sendErr) {
      logger.error({ err: safeErr(sendErr), tenantId }, 'guard: actions.edge-freeze-sync not queued');
      await alertTenantAndMsp(tenantId, {
        severity: 'critical',
        title: 'Freeze not applied at apple-edge',
        message: 'The freeze of the commands could not be sent to apple-edge and could not be retried: check the job runtime.',
        stableKey: `guard:edge-freeze:${tenantId}`,
      });
    }
    return 'queued';
  }
}

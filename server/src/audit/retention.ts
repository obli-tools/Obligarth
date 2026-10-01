// Retention of the journal (docs: audit-durci §7, D25): 12 months by
// default, 6 to 36 with a justification (database constraints); a decrease
// takes effect 30 days later; legal hold. Changes are made by the SQL
// functions obligarth.audit_set_retention / audit_set_legal_hold, which
// refuse any other actor than a platform administrator in the tenant's
// context and write the prepared event in the same transaction. The purge
// (job audit.retention-all) removes only an expired prefix of a chain that
// is already sealed and received by every required destination, keeps the
// anchor, and writes audit.retention_purged (obligarth.audit_purge).
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { db } from '../db';
import { asNone, asTenant, userActor, type DbActor } from '../db/context';
import { logger } from '../utils/logger';
import { auditMetrics } from './metrics';
import { fromDbActor } from './actor';
import { prepare } from './writer';

/** The actor the database admits for the purge and the housekeeping. */
export const RETENTION_ACTOR: DbActor = { type: 'job', name: 'audit.retention' };
const PURGE_BATCH = 10_000;
const PURGE_ROUNDS = 50;
const BLOCKED_ALERT_DAYS = 7;

export interface RetentionChange { tenantId: number; months: number; justification: string | null }

/** Retention in force of a tenant (months). */
export async function retentionMonths(tenantId: number): Promise<number> {
  const res = await db.raw('SELECT obligarth.audit_retention_months(?) AS m', [tenantId]) as { rows: Array<{ m: number }> };
  return Number(res.rows[0]?.m ?? 12);
}

/**
 * Applies a retention change as `requesterId` (a platform administrator: the
 * approval's executor), in the tenant's context: the event is prepared here
 * and written by the SQL function, which checks that it describes this change.
 */
export async function applyRetentionChange(change: RetentionChange, requesterId: number, origin: { requestId?: string } = {}): Promise<{
  months: number; effectiveMonths: number; pendingEffectiveAt: string | null;
}> {
  const actor = userActor(requesterId);
  return asTenant(change.tenantId, actor, async () => {
    const previous = await retentionMonths(change.tenantId);
    const effectiveAt = change.months >= previous ? new Date() : new Date(Date.now() + 30 * 86_400_000);
    const ctx = await fromDbActor(actor, change.tenantId, origin);
    const body = prepare({
      tenantId: change.tenantId, action: 'audit.retention_changed', target: { type: 'tenant', id: String(change.tenantId) },
      onBehalfOf: change.tenantId === MASTER_TENANT_ID ? undefined : change.tenantId,
      details: { months: change.months, previousMonths: previous, effectiveAt: effectiveAt.toISOString(), justification: change.justification },
    }, ctx, { criticality: 'critical' });
    const res = await db.raw('SELECT months, effective_months, pending_effective_at FROM obligarth.audit_set_retention(?, ?, ?, ?)',
      [change.tenantId, change.months, change.justification, body.text]) as {
      rows: Array<{ months: number; effective_months: number; pending_effective_at: Date | null }>;
    };
    const r = res.rows[0];
    return {
      months: Number(r.months),
      effectiveMonths: Number(r.effective_months),
      pendingEffectiveAt: r.pending_effective_at ? new Date(r.pending_effective_at).toISOString() : null,
    };
  });
}

/** Sets, extends or lifts (until null) a legal hold, as a platform
 *  administrator in the tenant's context. */
export async function applyLegalHold(tenantId: number, until: Date | null, reason: string | null, requesterId: number,
  origin: { requestId?: string } = {}): Promise<void> {
  const actor = userActor(requesterId);
  await asTenant(tenantId, actor, async () => {
    const ctx = await fromDbActor(actor, tenantId, origin);
    const body = prepare({
      tenantId, action: 'audit.legal_hold_changed', target: { type: 'tenant', id: String(tenantId) },
      onBehalfOf: tenantId === MASTER_TENANT_ID ? undefined : tenantId,
      details: { until: until ? until.toISOString() : null, reason: until ? reason : null, released: until === null },
    }, ctx, { criticality: 'critical' });
    await db.raw('SELECT obligarth.audit_set_legal_hold(?, ?::timestamptz, ?, ?)', [tenantId, until ? until.toISOString() : null, reason, body.text]);
  });
}

/** The current legal hold of a tenant (null: none). */
export async function legalHoldOf(tenantId: number): Promise<{ until: Date; reason: string } | null> {
  return asTenant(tenantId, RETENTION_ACTOR, async () => {
    const r = await db('audit_retention').where({ tenant_id: tenantId }).first('legal_hold_until', 'legal_hold_reason') as
      { legal_hold_until: Date | null; legal_hold_reason: string | null } | undefined;
    return r?.legal_hold_until ? { until: new Date(r.legal_hold_until), reason: String(r.legal_hold_reason ?? '') } : null;
  });
}

export interface PurgeReport { chains: number; purged: number; blocked: Record<string, number> }

/** The job audit.retention-all (§7.3): every chain, purge rounds of 10,000
 *  entries (50 at most), then the housekeeping. */
export async function runRetention(signal?: AbortSignal): Promise<PurgeReport & { leaves: number; verifications: number }> {
  return asNone(RETENTION_ACTOR, async () => {
    const chains = (await db.raw('SELECT tenant_id, last_seq, anchor_seq, tenant_exists FROM obligarth.audit_chains()') as {
      rows: Array<{ tenant_id: number; last_seq: string | number; anchor_seq: string | number; tenant_exists: boolean }>;
    }).rows;
    const report: PurgeReport = { chains: chains.length, purged: 0, blocked: {} };
    const blockedNow: Record<string, number> = { legal_hold: 0, not_sealed: 0, not_exported: 0, nothing_due: 0 };
    for (const c of chains) {
      if (signal?.aborted) break;
      const tenantId = Number(c.tenant_id);
      let lastBlock: string | null = null;
      for (let round = 0; round < PURGE_ROUNDS; round++) {
        const res = await db.raw('SELECT purged, through_seq, blocked_by FROM obligarth.audit_purge(?, ?)', [tenantId, PURGE_BATCH]) as {
          rows: Array<{ purged: string | number; through_seq: string | number | null; blocked_by: string | null }>;
        };
        const r = res.rows[0];
        const n = Number(r?.purged ?? 0);
        report.purged += n;
        if (n > 0) auditMetrics.inc('obligarth_audit_retention_purged_total', {}, n);
        if (!n) { lastBlock = r?.blocked_by ?? 'nothing_due'; break; }
      }
      if (lastBlock) {
        blockedNow[lastBlock] = (blockedNow[lastBlock] ?? 0) + 1;
        if (lastBlock === 'not_sealed' || lastBlock === 'not_exported') await alertIfBlockedLong(tenantId, lastBlock);
      }
    }
    for (const [reason, n] of Object.entries(blockedNow)) auditMetrics.set('obligarth_audit_retention_blocked', n, { reason });
    report.blocked = blockedNow;
    const hk = (await db.raw('SELECT seal_leaves, verifications FROM obligarth.audit_housekeeping()') as {
      rows: Array<{ seal_leaves: string | number; verifications: string | number }>;
    }).rows[0];
    logger.info({ chains: report.chains, purged: report.purged, blocked: blockedNow }, 'audit: retention run');
    return { ...report, leaves: Number(hk?.seal_leaves ?? 0), verifications: Number(hk?.verifications ?? 0) };
  });
}

/** A chain whose oldest due entry waits for a seal or an export for more than
 *  7 days: alert of the master tenant. */
async function alertIfBlockedLong(tenantId: number, reason: string): Promise<void> {
  try {
    const months = await retentionMonths(tenantId);
    const oldest = await asTenant(tenantId, RETENTION_ACTOR, () => db('audit_logs').where({ tenant_id: tenantId })
      .min({ at: 'created_at' }).first()) as { at: Date | null } | undefined;
    if (!oldest?.at) return;
    const due = new Date(oldest.at);
    due.setUTCMonth(due.getUTCMonth() + months);
    if (Date.now() - due.getTime() < BLOCKED_ALERT_DAYS * 86_400_000) return;
    const { raiseJobAlert } = await import('../jobs/alerts');
    await raiseJobAlert(RETENTION_ACTOR, {
      stableKey: `audit:retention-blocked:${tenantId}`, severity: 'warning',
      title: 'Audit retention blocked',
      message: `Expired audit entries of tenant ${tenantId} wait for ${reason === 'not_sealed' ? 'a seal' : 'a SIEM export'} for more than 7 days.`,
    });
  } catch (err) {
    logger.warn({ tenantId, err: { name: (err as Error).name } }, 'audit: retention block not checked');
  }
}

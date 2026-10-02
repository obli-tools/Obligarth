// Refusals of the guard engine (docs: audit-durci §10.3, §10.9): a refusal
// of the steps 3 to 9 (freeze, cooldown, ownership, whole fleet, hourly cap,
// confirmation), or of a re-check at approval, is journaled in class
// standard (guard.action_refused, details.code) and counted; the anomalies
// are counted in the journal right after, and may freeze the tenant.
import type { Request } from 'express';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../audit';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';
import { anomalyOf } from './anomalies';
import { guardMetrics } from './metrics';
import { alertTenants } from './notify';
import type { PersonFacts } from './people';
import type { GuardedActionDef } from './types';

export interface RefusalInput {
  tenantId: number;
  def: GuardedActionDef<any>;
  code: string;
  deviceIds: number[];
  reason?: string;
  ticket?: string | null;
  requester?: PersonFacts;
  details?: Record<string, unknown>;
  /** The pending action, when the refusal closes one (approval, execution). */
  actionUuid?: string;
  approvalIds?: number[];
}

/** The refusal entry, the counters, then the anomalies (never throws). */
export async function recordRefusal(req: Request | null, r: RefusalInput, ctx?: AuditWriteContext): Promise<void> {
  guardMetrics.inc('obligarth_guard_refusals_total', { code: r.code });
  guardMetrics.inc('obligarth_guard_requests_total', { action: r.def.key, outcome: 'refused' });
  try {
    const writeCtx = ctx ?? (req ? await audit.fromRequest(req, r.tenantId) : undefined);
    if (writeCtx) {
      const onBehalfOf = r.requester?.side === 'msp' && r.tenantId !== MASTER_TENANT_ID ? r.tenantId : undefined;
      await audit.append({
        tenantId: r.tenantId, action: 'guard.action_refused', outcome: 'denied', onBehalfOf,
        reason: r.reason || undefined, ticket: r.ticket ?? undefined,
        ...(r.actionUuid ? { links: { action: r.actionUuid } } : {}),
        ...(r.approvalIds?.length ? { approvalIds: r.approvalIds } : {}),
        ...(r.deviceIds.length ? { targets: { deviceIds: r.deviceIds } } : {}),
        details: { actionKey: r.def.key, family: r.def.family, code: r.code, ...(r.details ?? {}) },
      }, writeCtx);
    }
  } catch (err) {
    logger.warn({ err: safeErr(err), code: r.code }, 'guard: refusal entry not written');
  }
  if (r.code === 'privilegeCooldown') {
    // A new administrator attempts a destructive action (11 §3.1).
    await alertTenants([MASTER_TENANT_ID], {
      severity: 'warning',
      title: 'A new administrator attempted a destructive action',
      message: `${r.def.key} refused: the account's administrator rights are less than 72 hours old.`,
      stableKey: `guard:cooldown:${r.tenantId}:${r.requester?.userId ?? 'unknown'}`,
      navigateTo: '/admin/security?tab=guard',
    });
  }
  await checkAnomalies(r.tenantId);
}

/** A1 or A2 broken: the tenant is frozen (source 'anomaly'). Never throws. */
export async function checkAnomalies(tenantId: number): Promise<void> {
  try {
    const rule = await anomalyOf(tenantId);
    if (!rule) return;
    const { autoFreeze } = await import('./freeze');
    await autoFreeze(tenantId, rule);
  } catch (err) {
    logger.error({ err: safeErr(err), tenantId }, 'guard: anomaly freeze failed');
  }
}

// Rows of pending_actions and their console shape (docs: audit-durci §10.5,
// §10.11). Read and written in the database context of the action's tenant
// (the global view lists every tenant's through the context 'platform').
import type { Knex } from 'knex';
import type { GuardSide, PendingActionDto, PendingActionState } from '@obligarth/shared';
import { db } from '../db';
import { userLabels } from '../services/userLabels.service';
import { guardedActionDef } from './catalog';
import { lateCancelOf, type GuardResultSummary } from './types';

export interface PendingActionRow {
  id: number;
  uuid: string;
  tenant_id: number;
  action_key: string;
  family: string;
  state: PendingActionState;
  requested_by: number;
  requester_side: GuardSide;
  approval_id: number | null;
  approved_by: number | null;
  approver_side: GuardSide | null;
  approver_fallback: boolean;
  selection: Record<string, unknown>;
  target_device_ids: number[];
  target_count: number;
  params: Record<string, unknown>;
  reason: string;
  ticket: string | null;
  delay_seconds: number;
  execute_after: Date | null;
  job_id: string | null;
  paused_at: Date | null;
  cancelled_by: number | null;
  cancelled_at: Date | null;
  cancel_reason: string | null;
  executed_at: Date | null;
  result: GuardResultSummary | null;
  created_at: Date;
  updated_at: Date;
}

/** Explicit columns (never select('*')). */
export const ACTION_COLUMNS = [
  'id', 'uuid', 'tenant_id', 'action_key', 'family', 'state', 'requested_by', 'requester_side', 'approval_id',
  'approved_by', 'approver_side', 'approver_fallback', 'selection', 'target_device_ids', 'target_count', 'params',
  'reason', 'ticket', 'delay_seconds', 'execute_after', 'job_id', 'paused_at', 'cancelled_by', 'cancelled_at',
  'cancel_reason', 'executed_at', 'result', 'created_at', 'updated_at',
] as const;

const asJson = <T>(v: unknown, fallback: T): T => {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'string') {
    try { return JSON.parse(v) as T; } catch { return fallback; }
  }
  return v as T;
};

export function normaliseRow(r: Record<string, unknown>): PendingActionRow {
  const date = (v: unknown): Date | null => (v ? new Date(v as string | Date) : null);
  const int = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));
  return {
    id: Number(r.id),
    uuid: String(r.uuid),
    tenant_id: Number(r.tenant_id),
    action_key: String(r.action_key),
    family: String(r.family),
    state: r.state as PendingActionState,
    requested_by: Number(r.requested_by),
    requester_side: r.requester_side === 'client' ? 'client' : 'msp',
    approval_id: int(r.approval_id),
    approved_by: int(r.approved_by),
    approver_side: r.approver_side === 'client' || r.approver_side === 'msp' ? r.approver_side : null,
    approver_fallback: r.approver_fallback === true,
    selection: asJson<Record<string, unknown>>(r.selection, {}),
    target_device_ids: (Array.isArray(r.target_device_ids) ? r.target_device_ids : []).map(Number),
    target_count: Number(r.target_count),
    params: asJson<Record<string, unknown>>(r.params, {}),
    reason: String(r.reason ?? ''),
    ticket: typeof r.ticket === 'string' ? r.ticket : null,
    delay_seconds: Number(r.delay_seconds),
    execute_after: date(r.execute_after),
    job_id: typeof r.job_id === 'string' ? r.job_id : null,
    paused_at: date(r.paused_at),
    cancelled_by: int(r.cancelled_by),
    cancelled_at: date(r.cancelled_at),
    cancel_reason: typeof r.cancel_reason === 'string' ? r.cancel_reason : null,
    executed_at: date(r.executed_at),
    result: asJson<GuardResultSummary | null>(r.result, null),
    created_at: date(r.created_at) as Date,
    updated_at: date(r.updated_at) as Date,
  };
}

/** One action of the current context's tenant (by uuid), or undefined. */
export async function findAction(uuid: string, o: { trx?: Knex.Transaction; forUpdate?: boolean; tenantId?: number } = {}):
  Promise<PendingActionRow | undefined> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) return undefined;
  const q = (o.trx ?? db)('pending_actions').where({ uuid: uuid.toLowerCase() });
  if (o.tenantId !== undefined) q.andWhere({ tenant_id: o.tenantId });
  if (o.forUpdate) q.forUpdate();
  const row = await q.first(ACTION_COLUMNS);
  return row ? normaliseRow(row) : undefined;
}

/** The action of an approval request (guarded_action, guard_resume). */
export async function findActionByApproval(approvalId: number, trx?: Knex.Transaction): Promise<PendingActionRow | undefined> {
  const row = await (trx ?? db)('pending_actions').where({ approval_id: approvalId }).first(ACTION_COLUMNS);
  return row ? normaliseRow(row) : undefined;
}

const MAX_DTO_TARGETS = 1000;

/** May what the action dispatched still be withdrawn (the console offers the late cancellation)? An action that
 *  defines the withdrawal, being executed or executed, not withdrawn yet, within the life of what it dispatched. */
function lateCancellable(r: PendingActionRow): boolean {
  if (r.state !== 'executing' && r.state !== 'done' && r.state !== 'partial') return false;
  const def = guardedActionDef(r.action_key);
  if (!def?.cancelAfterDispatch || Array.isArray(r.result?.cancellation)) return false;
  if (r.state === 'executing' || def.cancelWindowSeconds === undefined || !r.executed_at) return true;
  return Date.now() <= r.executed_at.getTime() + def.cancelWindowSeconds * 1000;
}

/** The console shape of rows (names through obligarth.user_labels). */
export async function toDtos(rows: PendingActionRow[]): Promise<PendingActionDto[]> {
  const labels = await userLabels(rows.flatMap((r) => [r.requested_by, r.approved_by]).filter((v) => v !== null));
  return rows.map((r) => {
    const summary = r.result;
    return {
      uuid: r.uuid,
      tenantId: r.tenant_id,
      actionKey: r.action_key,
      family: r.family,
      state: r.state,
      requestedBy: { id: r.requested_by, label: labels.get(r.requested_by)?.username ?? null, side: r.requester_side },
      approvalId: r.approval_id,
      approvedBy: r.approved_by !== null
        ? { id: r.approved_by, label: labels.get(r.approved_by)?.username ?? null, side: r.approver_side ?? 'msp' }
        : null,
      approverFallback: r.approver_fallback,
      targetCount: r.target_count,
      targetDeviceIds: r.target_device_ids.slice(0, MAX_DTO_TARGETS),
      reason: r.reason,
      ticket: r.ticket,
      delaySeconds: r.delay_seconds,
      executeAfter: r.execute_after ? r.execute_after.toISOString() : null,
      pausedAt: r.paused_at ? r.paused_at.toISOString() : null,
      cancelledAt: r.cancelled_at ? r.cancelled_at.toISOString() : null,
      executedAt: r.executed_at ? r.executed_at.toISOString() : null,
      result: summary ? { done: Number(summary.done) || 0, failed: Number(summary.failed) || 0, skipped: Number(summary.skipped) || 0 } : null,
      createdAt: r.created_at.toISOString(),
      lateCancellable: lateCancellable(r),
      lateCancelledAt: lateCancelOf(summary)?.at ?? null,
    };
  });
}

export async function toDto(row: PendingActionRow): Promise<PendingActionDto> {
  return (await toDtos([row]))[0];
}

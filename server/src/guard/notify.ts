// Notifications of the guard engine (docs: audit-durci §10.10): live alerts
// in the tenant and in the master tenant (the MSP), Socket.io events to the
// tenant's room. Never thrown: a notification that fails is logged, the
// action stands. English titles; the console translates them by their
// stable key (guard:<uuid>:<state> → guard.alerts.<state>).
import { MASTER_TENANT_ID, SocketEvents, type GuardStateChanged, type PendingActionDto } from '@obligarth/shared';
import { asTenant, currentDbContext, type DbActor } from '../db/context';
import { getIO } from '../socket';
import { liveAlertService, type LiveAlertSeverity } from '../services/liveAlert.service';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';

export interface GuardAlert {
  severity: LiveAlertSeverity;
  title: string;
  message: string;
  stableKey: string;
  navigateTo?: string;
}

const actorOrSystem = (): DbActor => currentDbContext()?.actor ?? { type: 'job', name: 'guard.notify' };

/** A live alert in each of these tenants (deduplicated: one tenant once). */
export async function alertTenants(tenantIds: number[], alert: GuardAlert): Promise<void> {
  const actor = actorOrSystem();
  for (const tenantId of [...new Set(tenantIds.filter((t) => Number.isSafeInteger(t) && t > 0))]) {
    try {
      await asTenant(tenantId, actor, () => liveAlertService.add(tenantId, {
        severity: alert.severity,
        title: alert.title.slice(0, 200),
        message: alert.message.slice(0, 500),
        navigateTo: alert.navigateTo ?? '/admin/security?tab=guard',
        stableKey: alert.stableKey.slice(0, 200),
      }));
    } catch (err) {
      logger.warn({ err: safeErr(err), tenantId, alert: alert.stableKey }, 'guard: live alert not written');
    }
  }
}

/** The tenant and the master tenant. */
export function alertTenantAndMsp(tenantId: number, alert: GuardAlert): Promise<void> {
  return alertTenants([tenantId, MASTER_TENANT_ID], alert);
}

const linkOf = (uuid: string): string => `/admin/security?tab=guard&action=${uuid}`;

const STATE_TEXT: Record<string, { severity: LiveAlertSeverity; title: string }> = {
  awaiting_approval: { severity: 'warning', title: 'Guarded action awaiting approval' },
  scheduled: { severity: 'warning', title: 'Guarded action scheduled' },
  executing: { severity: 'info', title: 'Guarded action running' },
  done: { severity: 'info', title: 'Guarded action done' },
  partial: { severity: 'warning', title: 'Guarded action done in part' },
  failed: { severity: 'critical', title: 'Guarded action failed' },
  cancelled: { severity: 'info', title: 'Guarded action cancelled' },
  paused: { severity: 'warning', title: 'Guarded action paused' },
  expired: { severity: 'info', title: 'Guarded action expired' },
  refused: { severity: 'warning', title: 'Guarded action refused' },
};

/** The live alert of an action's new state, then GUARD_ACTION_UPDATED. */
export async function notifyAction(dto: PendingActionDto, extra: { code?: string } = {}): Promise<void> {
  emitAction(dto);
  const text = STATE_TEXT[dto.state];
  if (!text) return;
  const when = dto.executeAfter && dto.state === 'scheduled' ? ` at ${dto.executeAfter}` : '';
  const why = extra.code ? ` (${extra.code})` : '';
  await alertTenantAndMsp(dto.tenantId, {
    severity: text.severity,
    title: text.title,
    message: `${dto.actionKey} on ${dto.targetCount} device(s)${when}${why}.`,
    stableKey: `guard:${dto.uuid}:${dto.state}`,
    navigateTo: linkOf(dto.uuid),
  });
}

/** The live alert of a late cancellation (the state of the action does not change: guard:<uuid>:withdrawn), then
 *  GUARD_ACTION_UPDATED. A warning when a device had already received what was dispatched. */
export async function notifyLateCancel(dto: PendingActionDto, n: { cancelled: number; tooLate: number }): Promise<void> {
  emitAction(dto);
  await alertTenantAndMsp(dto.tenantId, {
    severity: n.tooLate > 0 ? 'warning' : 'info',
    title: 'Guarded action withdrawn',
    message: `${dto.actionKey}: withdrawn for ${n.cancelled} device(s)${n.tooLate > 0 ? `, too late for ${n.tooLate}` : ''}.`,
    stableKey: `guard:${dto.uuid}:withdrawn`,
    navigateTo: linkOf(dto.uuid),
  });
}

export function emitAction(dto: PendingActionDto): void {
  try { getIO().to(`tenant:${dto.tenantId}`).emit(SocketEvents.GUARD_ACTION_UPDATED, dto); } catch { /* no Socket.io */ }
}

export function emitState(state: GuardStateChanged): void {
  try { getIO().to(`tenant:${state.tenantId}`).emit(SocketEvents.GUARD_STATE_CHANGED, state); } catch { /* no Socket.io */ }
  if (state.tenantId !== MASTER_TENANT_ID) {
    try { getIO().to(`tenant:${MASTER_TENANT_ID}:admin`).emit(SocketEvents.GUARD_STATE_CHANGED, state); } catch { /* no Socket.io */ }
  }
}

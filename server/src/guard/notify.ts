// Notifications of the guard engine (docs: audit-durci §10.10): live alerts
// in the tenant and in the master tenant (the MSP), Socket.io events to the
// tenant's guard readers. Never thrown: a notification that fails is logged, the
// action stands. English titles; the console translates them by their
// stable key (guard:<uuid>:<state> → guard.alerts.<state>).
import { MASTER_TENANT_ID, SocketEvents, type GuardStateChanged, type PendingActionDto } from '@obligarth/shared';
import { asTenant, currentDbContext, type DbActor } from '../db/context';
import { getIO, guardReadersRoom } from '../socket';
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

/** Is the copy filed in the master tenant an alert of the platform (read by the platform administrators only, kind
 *  'platform')? Yes when the alert also goes to another tenant (the MSP copy of a tenant's event) or when the caller
 *  says the alert is about the platform or about another tenant (`platform`); no for an event of the master tenant
 *  itself, which its members read like those of any tenant. */
export function masterCopyIsPlatformOnly(tenantIds: readonly number[], platform?: boolean): boolean {
  return platform === true || tenantIds.some((t) => Number.isSafeInteger(t) && t > 0 && t !== MASTER_TENANT_ID);
}

/** A live alert in each of these tenants (deduplicated: one tenant once). The copy of the master tenant is an alert
 *  of the platform when masterCopyIsPlatformOnly says so (F109/F111). */
export async function alertTenants(tenantIds: number[], alert: GuardAlert, opts: { platform?: boolean } = {}): Promise<void> {
  const actor = actorOrSystem();
  const platformCopy = masterCopyIsPlatformOnly(tenantIds, opts.platform);
  for (const tenantId of [...new Set(tenantIds.filter((t) => Number.isSafeInteger(t) && t > 0))]) {
    try {
      await asTenant(tenantId, actor, () => liveAlertService.add(tenantId, {
        severity: alert.severity,
        title: alert.title.slice(0, 200),
        message: alert.message.slice(0, 500),
        navigateTo: alert.navigateTo ?? '/admin/security?tab=guard',
        stableKey: alert.stableKey.slice(0, 200),
        ...(tenantId === MASTER_TENANT_ID && platformCopy ? { platformOnly: true } : {}),
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

/** Rooms of GUARD_ACTION_UPDATED: the guard readers of the tenant (the rule of guard/routes.ts requireGuardReader,
 *  socket.ts guardReadersRoom) and the requester's own sockets, never every member of the tenant (F110/F119). */
export function actionRooms(dto: Pick<PendingActionDto, 'tenantId' | 'requestedBy'>): string[] {
  const rooms = [guardReadersRoom(dto.tenantId)];
  const requester = Number(dto.requestedBy?.id);
  if (Number.isSafeInteger(requester) && requester > 0) rooms.push(`user:${requester}`);
  return rooms;
}

export function emitAction(dto: PendingActionDto): void {
  try { getIO().to(actionRooms(dto)).emit(SocketEvents.GUARD_ACTION_UPDATED, dto); } catch { /* no Socket.io */ }
}

export function emitState(state: GuardStateChanged): void {
  try { getIO().to(`tenant:${state.tenantId}`).emit(SocketEvents.GUARD_STATE_CHANGED, state); } catch { /* no Socket.io */ }
  if (state.tenantId !== MASTER_TENANT_ID) {
    try { getIO().to(`tenant:${MASTER_TENANT_ID}:admin`).emit(SocketEvents.GUARD_STATE_CHANGED, state); } catch { /* no Socket.io */ }
  }
}

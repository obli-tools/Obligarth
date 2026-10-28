import { MASTER_TENANT_ID, type GuardApproverSide } from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { asTenant, userActor, type DbActor } from '../db/context';
import { requiredSideFor, refuseHeldFallback } from '../guard/approvals';
import { activeClientApprovers, personFacts } from '../guard/people';
import { AppError } from '../middleware/errorHandler';
import {
  activeRequester, refuse, requireTenantCapability, type ApprovalClosed, type ApprovalExecution,
} from '../services/approval.service';
import { RemoteEffects, approveSession, endSession, flushRemoteEffects, lockSession } from './sessions';
import { RemoteSettingsInputSchema, readRemoteSettings, settingsChanges, writeRemoteSettings } from './settings';

// =============================================================================
// The approvals of the remote assistance (P0-15 §4.6, §0.1 rule 4: the matrix may still raise a session to
// 'restricted', and mspSessionsNeedClientApproval stays an option of the tenant, false by default), examined by the guard's policy (guardReviewerPolicy: the
// requester never reviews, no account in its 72-hour cooldown, the side the payload requires; a strict step-up of the
// reviewer):
//   remote_session          a session the matrix holds at 'restricted' (remote.view, remote.control), or any session
//                           of the MSP when the tenant set mspSessionsNeedClientApproval (requiredSide 'client', no
//                           fallback on the MSP side). The executor (as the requester) reads the conditions again and
//                           queues the session; a denial, a withdrawal or the expiry closes it.
//   remote_settings_change  a change of the settings (floor 'restricted'); a request of the MSP that touches
//                           mspSessionsNeedClientApproval is reviewed by a client approver only.
// requiredSide and approverFallback in the payload, as the other guarded types (without them the policy would admit
// either side).
// =============================================================================

export const REMOTE_SESSION_REQUEST_TYPE = 'remote_session';
export const REMOTE_SETTINGS_REQUEST_TYPE = 'remote_settings_change';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface RequiredSide { side: GuardApproverSide; fallback: boolean }

/**
 * The side a request of `userId` requires. `clientOnly`: a client approver of the tenant, never the MSP side (the
 * tenant's setting, or the setting itself changed by the MSP): 409 clientApproverRequired when the tenant has none —
 * the master tenant aside (no client: its own rule). Otherwise the guard's rule (requiredSideFor: the client side by
 * default for a request of the MSP, its fallback held after the loss of a client approver: 409 approverFallbackHeld).
 */
export async function remoteRequiredSide(tenantId: number, userId: number, clientOnly: boolean): Promise<RequiredSide> {
  const facts = await personFacts(userId, tenantId);
  if (clientOnly && facts.side === 'msp' && tenantId !== MASTER_TENANT_ID) {
    if ((await activeClientApprovers(tenantId)) === 0) {
      throw new AppError(409, 'A designated client approver of the tenant must review this request, never the MSP side: designate one first',
        'clientApproverRequired');
    }
    return { side: 'client', fallback: false };
  }
  const required = await requiredSideFor(facts, tenantId);
  refuseHeldFallback(required);
  return { side: required.side, fallback: required.fallback };
}

// ── remote_session ───────────────────────────────────────────────────────────

/** The executor of an approved session, as the requester (the approval's tenant context). */
export async function executeRemoteSession(x: ApprovalExecution): Promise<string | void> {
  const p = (x.payload ?? {}) as { sessionId?: unknown };
  if (typeof p.sessionId !== 'string' || !UUID_RE.test(p.sessionId) || !x.approvalId) refuse('Malformed request');
  await activeRequester(x.requesterId);
  const auditCtx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  const fx = new RemoteEffects();
  const t = await db.transaction(async (trx) => {
    const r = await lockSession(trx, x.tenantId, String(p.sessionId).toLowerCase());
    return r ? approveSession(trx, fx, r, x.approvalId as number, auditCtx) : null;
  });
  await flushRemoteEffects(fx, userActor(x.requesterId), auditCtx);
  if (!t) refuse('The remote session no longer exists');
  if (!t!.ok) {
    const why = t!.code === 'remoteUnavailable' ? `remoteUnavailable (${String(t!.details?.reason ?? '')})` : `${t!.code} (${t!.row.state})`;
    refuse(`${why}: the remote session was not opened — it is ${t!.row.state}`);
  }
  return undefined;
}

/** A request closed without execution: its session awaiting the approval is closed (denied: cancelled
 *  approval_denied; withdrawn by its requester: cancelled operator; expired: expired approval_expired). */
export async function onRemoteSessionApprovalClosed(x: ApprovalClosed): Promise<void> {
  const p = (x.payload ?? {}) as { sessionId?: unknown };
  if (typeof p.sessionId !== 'string' || !UUID_RE.test(p.sessionId)) return;
  const actor: DbActor = x.byUserId ? userActor(x.byUserId) : { type: 'job', name: 'core.approvals.expire' };
  const auditCtx = x.byUserId ? await audit.fromDbActor(actor, x.tenantId) : audit.fromJob({ name: 'core.approvals.expire', requestId: 'job' });
  const fx = new RemoteEffects();
  await asTenant(x.tenantId, actor, () => db.transaction(async (trx) => {
    const r = await lockSession(trx, x.tenantId, String(p.sessionId).toLowerCase());
    if (!r || r.state !== 'awaiting_approval' || Number(r.approval_id) !== x.approvalId) return;
    await endSession(trx, fx, r, x.status === 'denied'
      ? { reason: 'approval_denied', by: 'operator', byUserId: x.byUserId, auditCtx }
      : x.status === 'cancelled'
        ? { reason: 'operator', by: 'operator', byUserId: x.byUserId, auditCtx }
        : { reason: 'approval_expired', by: 'system', auditCtx });
  }));
  await flushRemoteEffects(fx, actor, auditCtx);
}

// ── remote_settings_change ───────────────────────────────────────────────────

/** The executor of an approved change of the settings, as the requester (who still holds 'settings'): the keys of the
 *  request written, remote.settings_changed in the same transaction. */
export async function executeRemoteSettingsChange(x: ApprovalExecution): Promise<string | void> {
  const p = (x.payload ?? {}) as { settings?: unknown };
  const parsed = RemoteSettingsInputSchema.safeParse(p.settings ?? null);
  if (!parsed.success) refuse('Malformed request');
  await requireTenantCapability(x.requesterId, x.tenantId, 'settings');
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await db.transaction(async (trx) => {
    const before = await readRemoteSettings(trx, x.tenantId, { forUpdate: true });
    const changes = settingsChanges(before, parsed.data!);
    if (Object.keys(changes).length === 0) return;
    await writeRemoteSettings(trx, x.tenantId, parsed.data!, x.requesterId);
    await audit.appendInTx(trx, {
      tenantId: x.tenantId, action: 'remote.settings_changed', target: { type: 'tenant', id: String(x.tenantId) }, details: { changes },
    }, ctx);
  });
  return undefined;
}

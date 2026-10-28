import { randomBytes, randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import {
  REMOTE_LIMITS, SocketEvents, isRemoteFinalState, remoteEffectiveMode,
  type RemoteAgentCapabilities, type RemoteChannel, type RemoteEndReason, type RemoteEndedBy, type RemoteFinalState,
  type RemoteMode, type RemoteRequesterSide, type RemoteServerToAgentMessage, type RemoteSessionChanged,
  type RemoteUnavailableReason,
} from '@obligarth/shared';
import { audit, type AuditEntryInput, type AuditWriteContext } from '../audit';
import { asTenant, type DbActor } from '../db/context';
import { safeErr } from '../jobs/errors';
import { AppError } from '../middleware/errorHandler';
import { approvalService, type PendingApproval } from '../services/approval.service';
import type { StepUpVia } from '../services/deviceKey/stepUpProof';
import { getIO } from '../socket';
import { logger } from '../utils/logger';
import { remoteChannel, type RemoteChannelSession } from './channels';
import { checkOpenable } from './guard';
import { remoteMetrics } from './metrics';
import { readRemoteSettings } from './settings';

// =============================================================================
// The state machine of the remote assistance sessions (P0-15 §2, §0.1 of the spec: the MSP model of the owners'
// decision of 27/10): the only writer of remote_sessions. Every transition runs in the tenant's transaction, on the row
// locked (SELECT … FOR UPDATE), and checks the deadline of the state first (a session past it ends there, with the
// reason of its state, and the transition answers remoteSessionState: the sweep « at each transition »). What follows
// the commit (Socket.io, metrics, the wake of the device, the withdrawal of an approval, the relay's end) is collected
// in RemoteEffects and run by flushRemoteEffects once the transaction committed.
//   awaiting_approval  → queued (approved), cancelled (denied, withdrawn, the operator), expired (30 min)
//   queued             → awaiting_consent (delivered: onDelivered), expired (10 min), cancelled
//   awaiting_consent   → connecting (onAccepted), failed (the system dialog of the capture refused or left 60 s
//                        unanswered: projection_denied; an agent's error), expired (60 s + margin), cancelled
//   connecting         → live (onAttached), failed (60 s without stream), cancelled
//   live               → ended (any reason)
// Nothing is asked of the user of the device (§0.1 rule 1): /accept carries the mode the agent took (the mode asked,
// view when it cannot inject; never above the request). Effective mode: min(mode, consented_mode). The control during
// a session is granted by the server (escalate: the conditions of a control session, the technician's strict step-up
// taken by the route) and released by the technician (release); the agent applies the frame mode it receives.
// =============================================================================

import { VIEWER_TOKEN_UNISSUED, dueReason, finalStateOf, sessionDto, sha256Hex, type SessionRow } from './machine';

export { VIEWER_TOKEN_UNISSUED, dueReason, finalStateOf, sessionDto, sha256Hex, type SessionRow };

// ── Effects after the commit ─────────────────────────────────────────────────

export interface RemoteSessionEnded { tenantId: number; sessionId: string; deviceId: number; state: RemoteFinalState; reason: RemoteEndReason }
type EndedListener = (e: RemoteSessionEnded) => void;
const endedListeners: Array<{ name: string; fn: EndedListener }> = [];

/** Told once a session ended and its transaction committed (the relay closes both ends, T5). Never throws out. */
export function onRemoteSessionEnded(name: string, fn: EndedListener): void {
  if (endedListeners.some((l) => l.name === name)) throw new Error(`remote session listener ${name} registered twice`);
  endedListeners.push({ name, fn });
}

/** What a transaction of the state machine leaves to do once it committed. */
export class RemoteEffects {
  readonly changed: Array<RemoteSessionChanged & { tenantId: number; requestedBy: number | null }> = [];
  readonly ended: RemoteSessionEnded[] = [];
  readonly wake: Array<{ tenantId: number; deviceId: number; channel: RemoteChannel }> = [];
  readonly withdraw: Array<{ tenantId: number; approvalId: number; byUserId: number | null; reason: string }> = [];
  readonly announce: PendingApproval[] = [];
  /** The frames mode for the agent's end of the relay (the control granted or released), sent once committed. */
  readonly control: Array<{ channel: RemoteChannel; sessionId: string; message: RemoteServerToAgentMessage }> = [];
}

/** What the relay counted of a live session (T5): its totals so far, written at its end and every 60 s. */
export interface RemoteCounters { bytesDown: number; bytesUp: number; inputEvents: number }
type CountersSource = (sessionId: string) => RemoteCounters | null;
let countersSource: CountersSource | null = null;

/** The relay's counters of its tunnels (remote/relay.ts): endSession writes them with the end. */
export function setRemoteCountersSource(fn: CountersSource | null): void {
  countersSource = fn;
}

const countersColumns = (c: RemoteCounters): Record<string, number> => ({
  bytes_down: Math.max(0, Math.floor(c.bytesDown)), bytes_up: Math.max(0, Math.floor(c.bytesUp)),
  input_events: Math.min(2_147_483_647, Math.max(0, Math.floor(c.inputEvents))),
});

/** Runs the effects of a committed transaction (never throws: each failure is logged). `actor`: the database actor of
 *  the withdrawals of approvals (the tenant's context). */
export async function flushRemoteEffects(fx: RemoteEffects, actor: DbActor, auditCtx: AuditWriteContext): Promise<void> {
  // The mode first: the agent applies the control (or its release) as soon as it is committed.
  for (const c of fx.control) {
    try {
      if (!remoteChannel(c.channel)?.deliverControl(c.sessionId, c.message)) {
        logger.warn({ sessionId: c.sessionId, type: c.message.type }, 'remote: control message not delivered (the agent left)');
      }
    } catch (err) {
      logger.warn({ err: safeErr(err), sessionId: c.sessionId }, 'remote: control message not delivered');
    }
  }
  for (const w of fx.withdraw) {
    try {
      await asTenant(w.tenantId, actor, () => approvalService.withdraw({ tenantId: w.tenantId, approvalId: w.approvalId, byUserId: w.byUserId, auditCtx, reason: w.reason }));
    } catch (err) {
      logger.warn({ err: safeErr(err), approvalId: w.approvalId }, 'remote: approval of an ended session not withdrawn');
    }
  }
  for (const a of fx.announce) approvalService.announceCreated(a);
  for (const c of fx.changed) {
    const event: RemoteSessionChanged = { sessionId: c.sessionId, deviceId: c.deviceId, state: c.state, ...(c.endReason ? { endReason: c.endReason } : {}) };
    try {
      const io = getIO();
      if (c.requestedBy) io.to(`user:${c.requestedBy}`).emit(SocketEvents.REMOTE_SESSION_CHANGED, event);
      io.to(`tenant:${c.tenantId}:admin`).emit(SocketEvents.REMOTE_SESSION_CHANGED, event);
    } catch { /* no Socket.io (tests, jobs process) */ }
  }
  for (const e of fx.ended) {
    remoteMetrics.closed(e.state);
    for (const l of endedListeners) {
      try { l.fn(e); } catch (err) { logger.warn({ err: safeErr(err), listener: l.name }, 'remote: listener of an ended session failed'); }
    }
  }
  for (const w of fx.wake) remoteChannel(w.channel)?.wake(w.tenantId, w.deviceId);
}

// ── Rows ─────────────────────────────────────────────────────────────────────

/** The row of a session of the tenant, locked for its transition (null: unknown in this tenant). */
export async function lockSession(trx: Knex.Transaction, tenantId: number, sessionId: string): Promise<SessionRow | null> {
  const r = await trx('remote_sessions').where({ tenant_id: tenantId, id: sessionId }).forUpdate().first() as SessionRow | undefined;
  return r ?? null;
}

const stateError = (row: SessionRow): AppError => new AppError(409, `The session is ${row.state}`, 'remoteSessionState', { state: row.state });

function channelSession(r: SessionRow, maxMinutes: number): RemoteChannelSession {
  return {
    id: String(r.id).toLowerCase(), tenantId: Number(r.tenant_id), deviceId: Number(r.device_id), mode: r.mode,
    requestedBy: r.requested_by === null ? null : Number(r.requested_by), requestedByName: r.requested_by_name, operatorOrg: r.operator_org,
    controllerName: r.controller_name, reason: r.reason ?? null, approvalId: r.approval_id === null ? null : Number(r.approval_id),
    commandId: r.command_id ? String(r.command_id).toLowerCase() : null, maxMinutes,
  };
}

function changed(fx: RemoteEffects, r: SessionRow): void {
  fx.changed.push({
    tenantId: Number(r.tenant_id), requestedBy: r.requested_by === null ? null : Number(r.requested_by), sessionId: String(r.id).toLowerCase(),
    deviceId: Number(r.device_id), state: r.state, ...(r.end_reason ? { endReason: r.end_reason } : {}),
  });
}

async function update(trx: Knex.Transaction, r: SessionRow, values: Record<string, unknown>): Promise<SessionRow> {
  const [row] = await trx('remote_sessions').where({ tenant_id: r.tenant_id, id: r.id }).update(values).returning('*') as SessionRow[];
  return row;
}

const target = (r: SessionRow) => ({ type: 'remote_session', id: String(r.id).toLowerCase(), device: Number(r.device_id) });

/** The reason and the ticket of a session for an audit entry (both optional, §0.1 rule 3). */
const why = (r: SessionRow): Pick<AuditEntryInput, 'reason' | 'ticket'> => ({
  ...(r.reason ? { reason: r.reason } : {}), ...(r.ticket ? { ticket: r.ticket } : {}),
});

// ── End ──────────────────────────────────────────────────────────────────────

export interface EndInput {
  reason: RemoteEndReason;
  by: RemoteEndedBy;
  byUserId?: number | null;
  auditCtx: AuditWriteContext;
  /** Extra details of the audit entry (the codes of a refusal). */
  details?: Record<string, unknown>;
}

/** Ends an open session (a final one is left as it is and returned). The request still waiting in the device's queue
 *  is withdrawn, a request of approval still pending is withdrawn after the commit; audited (protective entries,
 *  never blocked by the journal: the end of a session is never held). */
export async function endSession(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, e: EndInput): Promise<SessionRow> {
  if (isRemoteFinalState(r.state)) return r;
  const now = new Date();
  const state = finalStateOf(r.state, e.reason);
  const settings = await readRemoteSettings(trx, Number(r.tenant_id));
  if (r.command_id && (r.state === 'queued' || r.state === 'awaiting_consent')) {
    await remoteChannel(r.channel)?.cancel(trx, channelSession(r, settings.maxMinutes));
  }
  const counted = countersSource?.(String(r.id).toLowerCase()) ?? null;
  const row = await update(trx, r, {
    state, ended_at: now, end_reason: e.reason, ended_by: e.by, ended_by_user_id: e.byUserId ?? null, stream_token_sha256: null,
    ...(counted ? countersColumns(counted) : {}),
  });
  if (r.state === 'awaiting_approval' && r.approval_id) {
    fx.withdraw.push({ tenantId: Number(r.tenant_id), approvalId: Number(r.approval_id), byUserId: e.byUserId ?? null, reason: `remote session ${e.reason}` });
  }
  const dto = sessionDto(row, now);
  const base: Omit<AuditEntryInput, 'action'> = {
    tenantId: Number(r.tenant_id), target: target(row), ...why(r),
    ...(r.approval_id ? { approvalIds: [Number(r.approval_id)] } : {}), ...(r.command_id ? { links: { command: String(r.command_id).toLowerCase() } } : {}),
    details: {
      deviceId: dto.deviceId, channel: r.channel, mode: r.mode, effectiveMode: dto.effectiveMode, state, from: r.state, endReason: e.reason,
      endedBy: e.by, ...(e.byUserId ? { endedByUserId: e.byUserId } : {}), requestedBy: dto.requestedBy, requesterSide: r.requester_side,
      startedAt: dto.startedAt, durationSeconds: dto.durationSeconds ?? 0, bytesDown: dto.bytesDown, bytesUp: dto.bytesUp, inputEvents: dto.inputEvents,
      ...(r.escalated_at ? { controlGrantedAt: new Date(r.escalated_at).toISOString() } : {}),
      ...(e.details ?? {}),
    },
  };
  await audit.appendInTx(trx, { ...base, action: state === 'cancelled' ? 'remote.session_cancelled' : 'remote.session_ended' }, e.auditCtx,
    { onFailure: 'spool' });
  changed(fx, row);
  fx.ended.push({ tenantId: Number(r.tenant_id), sessionId: dto.id, deviceId: dto.deviceId, state, reason: e.reason });
  return row;
}

/** A transition's answer: the row as it now is; not ok when the session could not take it (its state, its deadline
 *  passed — it ended there —, a condition lost — it ended —). The caller commits, flushes, then answers `code`. */
export type Transition =
  | { ok: true; row: SessionRow }
  | { ok: false; row: SessionRow; code: string; status: number; details?: Record<string, unknown> };

const notOk = (row: SessionRow, code: string, status: number, details?: Record<string, unknown>): Transition => ({ ok: false, row, code, status, details });

/** The session ended at once when its deadline passed (the sweep at each transition); its answer otherwise null. */
async function endIfDue(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, auditCtx: AuditWriteContext): Promise<Transition | null> {
  const due = dueReason(r, new Date());
  if (!due) return null;
  const row = await endSession(trx, fx, r, { reason: due, by: 'system', auditCtx });
  return notOk(row, 'remoteSessionState', 409, { state: row.state });
}

/** The end of a session whose conditions no longer hold (revalidation): freeze for a frozen tenant, revoked otherwise. */
async function endUnavailable(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, reason: RemoteUnavailableReason,
  auditCtx: AuditWriteContext, details?: Record<string, unknown>): Promise<Transition> {
  const row = await endSession(trx, fx, r, { reason: reason === 'frozen' ? 'freeze' : 'revoked', by: 'system', auditCtx, details: { unavailable: reason } });
  return notOk(row, 'remoteUnavailable', 409, { reason, ...(details ?? {}) });
}

// ── Request ──────────────────────────────────────────────────────────────────

export interface SessionRequest {
  tenantId: number;
  userId: number;
  deviceId: number;
  channel: RemoteChannel;
  mode: RemoteMode;
  /** Optional (§0.1 rule 3). */
  reason: string | null;
  ticket: string | null;
  requesterSide: RemoteRequesterSide;
  requestedByName: string;
  operatorOrg: string;
  controllerName: string;
  /** How the technician proved the second factor of this request (strict step-up, §0.1 rule 3). */
  stepUpVia: StepUpVia | null;
  /** The address of the console (its trusted proxies resolved). */
  consoleIp: string | null;
  /** The console session of the request (SHA-256 of its express session id): the viewer's token handed now is bound to
   *  it (§0.1 rule 3). */
  consoleSession: string | null;
  /** Held for approval: the request filed in the same transaction (its payload gets the session's id). */
  approval: { description: string; payload: Record<string, unknown> } | null;
  auditCtx: AuditWriteContext;
}

export interface SessionRequested { row: SessionRow; viewerToken: string | null; approval: PendingApproval | null }

/** A new session: awaiting its approval (the request filed in this transaction), or queued (its request in the
 *  device's queue, in this transaction). The caller ran checkOpenable in this transaction, the device row locked.
 *  remote.session_requested (critical: who, the console's address, the step-up, the device, the mode) is written in the
 *  transaction, before the dispatch. */
export async function requestSession(trx: Knex.Transaction, fx: RemoteEffects, q: SessionRequest): Promise<SessionRequested> {
  const id = randomUUID();
  const now = new Date();
  const settings = await readRemoteSettings(trx, q.tenantId);
  const viewerToken = q.approval ? null : randomBytes(32).toString('hex');
  let approval: PendingApproval | null = null;
  if (q.approval) {
    approval = await approvalService.createInTx(trx, {
      tenantId: q.tenantId, userId: q.userId, requestType: 'remote_session', description: q.approval.description,
      payload: { ...q.approval.payload, sessionId: id }, auditCtx: q.auditCtx,
    });
    fx.announce.push(approval);
  }
  let row: SessionRow;
  try {
    [row] = await trx('remote_sessions').insert({
      id, tenant_id: q.tenantId, device_id: q.deviceId, channel: q.channel, mode: q.mode,
      state: approval ? 'awaiting_approval' : 'queued', requested_by: q.userId, requested_by_name: q.requestedByName,
      requester_side: q.requesterSide, operator_org: q.operatorOrg, controller_name: q.controllerName, approval_id: approval ? approval.id : null,
      reason: q.reason, ticket: q.ticket, step_up_via: q.stepUpVia, viewer_token_sha256: viewerToken ? sha256Hex(viewerToken) : VIEWER_TOKEN_UNISSUED,
      viewer_session_sha256: viewerToken ? q.consoleSession : null,
      created_at: now, expires_at: new Date(now.getTime() + (approval ? REMOTE_LIMITS.approvalMinutes * 60 : REMOTE_LIMITS.deliverySeconds) * 1000),
    }).returning('*') as SessionRow[];
  } catch (err) {
    if ((err as { code?: string; constraint?: string }).constraint === 'remote_sessions_open_per_device') {
      throw new AppError(409, 'A remote session is already open on this device', 'remoteSessionOpen');
    }
    throw err;
  }
  await audit.appendInTx(trx, {
    tenantId: q.tenantId, action: 'remote.session_requested', target: target(row), ...why(row),
    ...(approval ? { approvalIds: [approval.id] } : {}),
    details: {
      deviceId: q.deviceId, mode: q.mode, channel: q.channel, requesterSide: q.requesterSide, operatorOrg: q.operatorOrg,
      consoleIp: q.consoleIp, stepUp: q.stepUpVia, stepUpStrict: true, heldForApproval: approval !== null,
      ...(approval ? { requiredSide: q.approval?.payload.requiredSide ?? null } : {}),
    },
  }, q.auditCtx);
  if (!approval) row = await dispatch(trx, fx, row, settings.maxMinutes, q.auditCtx);
  else changed(fx, row);
  return { row, viewerToken, approval };
}

/** The request of the session sent to its device (queued): the channel's dispatch, in this transaction. */
async function dispatch(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, maxMinutes: number, auditCtx: AuditWriteContext): Promise<SessionRow> {
  const impl = remoteChannel(r.channel);
  if (!impl) throw new AppError(409, 'No channel serves this device', 'remoteUnavailable', { reason: 'platformUnsupported' });
  const commandId = await impl.dispatchOpen(trx, channelSession(r, maxMinutes), auditCtx);
  const row = await update(trx, r, {
    state: 'queued', command_id: commandId, expires_at: new Date(Date.now() + REMOTE_LIMITS.deliverySeconds * 1000),
  });
  changed(fx, row);
  fx.wake.push({ tenantId: Number(row.tenant_id), deviceId: Number(row.device_id), channel: row.channel });
  return row;
}

/** The approval of a session held for it (the executor of 'remote_session', as the requester): the conditions read
 *  again (checkOpenable, phase approval), then queued. A condition lost ends the session (revoked or freeze). */
export async function approveSession(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, approvalId: number,
  auditCtx: AuditWriteContext): Promise<Transition> {
  if (r.state !== 'awaiting_approval' || Number(r.approval_id) !== approvalId) return notOk(r, 'remoteSessionState', 409, { state: r.state });
  const due = await endIfDue(trx, fx, r, auditCtx);
  if (due) return due;
  if (r.requested_by === null) return endUnavailable(trx, fx, r, 'capabilityMissing', auditCtx);
  const check = await checkOpenable(trx, {
    tenantId: Number(r.tenant_id), userId: Number(r.requested_by), deviceId: Number(r.device_id), mode: r.mode, phase: 'approval', sessionId: r.id,
  });
  if (!check.ok) return endUnavailable(trx, fx, r, check.reason, auditCtx, check.details);
  const settings = await readRemoteSettings(trx, Number(r.tenant_id));
  return { ok: true, row: await dispatch(trx, fx, r, settings.maxMinutes, auditCtx) };
}

// ── The device's side (T4: /poll, /accept, results; T5: the relay) ───────────

/** The request of the session delivered to its device (in the transaction of /poll): awaiting /accept, which only the
 *  system dialog of the screen capture holds (§0.1 rule 8). */
export async function onDelivered(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, auditCtx: AuditWriteContext): Promise<Transition> {
  const due = await endIfDue(trx, fx, r, auditCtx);
  if (due) return due;
  if (r.state !== 'queued') return notOk(r, 'remoteSessionState', 409, { state: r.state });
  const now = Date.now();
  const row = await update(trx, r, {
    state: 'awaiting_consent', delivered_at: new Date(now),
    expires_at: new Date(now + (REMOTE_LIMITS.projectionDialogSeconds + REMOTE_LIMITS.consentMarginSeconds) * 1000),
  });
  changed(fx, row);
  return { ok: true, row };
}

export interface AcceptInput {
  /** The mode the agent took: the mode asked, view when it cannot inject (never above the request). */
  consentedMode: RemoteMode;
  /** What the agent measured; notificationsEnabled is informative (§0.1 rule 2), never a refusal. */
  capabilities: RemoteAgentCapabilities;
  /** SHA-256 (hex) of the one-use stream token handed in the signed answer. */
  streamTokenSha256: string;
  auditCtx: AuditWriteContext;
}

/** The device took the session (/accept, T4; nothing asked of its user, §0.1 rule 1): the mode bounded by the request
 *  (a control taken on a view request: consentExceedsRequest, the session closed agent_error), the conditions read
 *  again; then connecting, with the stream token, for streamTokenSeconds, and the maximum duration of the tenant. */
export async function onAccepted(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, a: AcceptInput): Promise<Transition> {
  const due = await endIfDue(trx, fx, r, a.auditCtx);
  if (due) return due;
  if (r.state !== 'awaiting_consent') return notOk(r, 'remoteSessionState', 409, { state: r.state });
  if (a.consentedMode === 'control' && r.mode === 'view') {
    const row = await endSession(trx, fx, r, { reason: 'agent_error', by: 'system', auditCtx: a.auditCtx, details: { code: 'consentExceedsRequest' } });
    return notOk(row, 'consentExceedsRequest', 400);
  }
  if (r.requested_by === null) return endUnavailable(trx, fx, r, 'capabilityMissing', a.auditCtx);
  const effective = remoteEffectiveMode(r.mode, a.consentedMode);
  const check = await checkOpenable(trx, {
    tenantId: Number(r.tenant_id), userId: Number(r.requested_by), deviceId: Number(r.device_id), mode: effective, phase: 'accept', sessionId: r.id,
  });
  if (!check.ok) return endUnavailable(trx, fx, r, check.reason, a.auditCtx, check.details);
  const settings = await readRemoteSettings(trx, Number(r.tenant_id));
  const now = Date.now();
  const row = await update(trx, r, {
    state: 'connecting', consented_mode: a.consentedMode, consented_at: new Date(now), agent_capabilities: JSON.stringify(a.capabilities),
    stream_token_sha256: a.streamTokenSha256, stream_token_expires_at: new Date(now + REMOTE_LIMITS.streamTokenSeconds * 1000), stream_token_used_at: null,
    expires_at: new Date(now + REMOTE_LIMITS.connectingSeconds * 1000), max_ends_at: new Date(now + settings.maxMinutes * 60_000),
  });
  await audit.appendInTx(trx, {
    tenantId: Number(r.tenant_id), action: 'remote.session_consented', target: target(row),
    details: {
      mode: r.mode, consentedMode: a.consentedMode, effectiveMode: effective, downgraded: effective !== r.mode,
      notificationsEnabled: a.capabilities.notificationsEnabled === true,
    },
  }, a.auditCtx, { onFailure: 'spool' });
  changed(fx, row);
  return { ok: true, row };
}

/** Both ends attached to the relay (T5): live, until the maximum duration; the conditions read again.
 *  remote.session_started (critical) names the console's address and the step-up of the opening. */
export async function onAttached(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, auditCtx: AuditWriteContext,
  origin: { ip?: string | null } = {}): Promise<Transition> {
  const due = await endIfDue(trx, fx, r, auditCtx);
  if (due) return due;
  if (r.state !== 'connecting') return notOk(r, 'remoteSessionState', 409, { state: r.state });
  if (r.requested_by === null) return endUnavailable(trx, fx, r, 'capabilityMissing', auditCtx);
  const effective = remoteEffectiveMode(r.mode, r.consented_mode);
  const check = await checkOpenable(trx, {
    tenantId: Number(r.tenant_id), userId: Number(r.requested_by), deviceId: Number(r.device_id), mode: effective, phase: 'attach', sessionId: r.id,
  });
  if (!check.ok) return endUnavailable(trx, fx, r, check.reason, auditCtx, check.details);
  const now = new Date();
  const maxEnds = r.max_ends_at ? new Date(r.max_ends_at) : new Date(now.getTime() + REMOTE_LIMITS.maxMinutesDefault * 60_000);
  const row = await update(trx, r, { state: 'live', started_at: now, expires_at: maxEnds, max_ends_at: maxEnds });
  await audit.appendInTx(trx, {
    tenantId: Number(r.tenant_id), action: 'remote.session_started', target: target(row), ...why(r),
    details: {
      deviceId: Number(r.device_id), mode: r.mode, effectiveMode: effective, channel: r.channel, consoleIp: origin.ip ?? null,
      stepUp: r.step_up_via ?? null, stepUpStrict: true,
    },
  }, auditCtx);
  changed(fx, row);
  return { ok: true, row };
}

/** The codes of the agent's result of remote.open (§4.3) → the end of a session that has not reached connecting. No
 *  refusal by the user any more (§0.1 rule 1): the system dialog of the capture refused or left unanswered
 *  (projection_denied), anything else an agent's error. */
const RESULT_ENDS: Record<string, { reason: RemoteEndReason; by: RemoteEndedBy }> = {
  projection_denied: { reason: 'projection_denied', by: 'user' },
};

/** The result of the remote.open of a session (in the transaction of /poll, T4): it closes a session that has not
 *  reached connecting (a result after it changes nothing). */
export async function onCommandResult(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, code: string, auditCtx: AuditWriteContext): Promise<SessionRow> {
  if (r.state !== 'queued' && r.state !== 'awaiting_consent') return r;
  if (code === 'session_gone') return r;
  const end = RESULT_ENDS[code] ?? { reason: 'agent_error' as const, by: 'system' as const };
  return endSession(trx, fx, r, { ...end, auditCtx, details: { resultCode: code } });
}

// ── Control during a session (§0.1 rule 1) ───────────────────────────────────

export interface ControlChange {
  userId: number;
  auditCtx: AuditWriteContext;
  /** escalate: the strict step-up the route took (§0.1 rule 3). */
  stepUpVia?: StepUpVia | null;
  consoleIp?: string | null;
}

/** The frame mode for the agent's end of the relay, sent once the transaction committed (flushRemoteEffects): the
 *  control is never granted to an agent that is not attached (409, nothing written), the audit of the grant always
 *  precedes it. */
function requireAttached(r: SessionRow): void {
  if (!remoteChannel(r.channel)?.attached(String(r.id).toLowerCase())) {
    throw new AppError(409, 'The device is not attached to the session', 'remoteSessionState', { state: r.state, attached: false });
  }
}

const sendMode = (fx: RemoteEffects, r: SessionRow, effective: RemoteMode): void => {
  fx.control.push({ channel: r.channel, sessionId: String(r.id).toLowerCase(), message: { type: 'mode', effective } });
};

/** View → control granted by the server to the requester of a live session in effective view: the conditions of a
 *  control session (checkOpenable in control: capability, the measured injection…), the restriction remote.control and
 *  the technician's strict step-up being the route's. Nothing is asked of the device: the frame mode { effective:
 *  'control' } tells the agent, which applies it. Audited remote.session_escalation_granted (critical: who, the step-up,
 *  the console's address). */
export async function escalate(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, c: ControlChange): Promise<Transition> {
  const due = await endIfDue(trx, fx, r, c.auditCtx);
  if (due) return due;
  if (r.state !== 'live' || remoteEffectiveMode(r.mode, r.consented_mode) !== 'view') {
    return notOk(r, 'remoteSessionState', 409, { state: r.state, effectiveMode: remoteEffectiveMode(r.mode, r.consented_mode) });
  }
  const check = await checkOpenable(trx, {
    tenantId: Number(r.tenant_id), userId: c.userId, deviceId: Number(r.device_id), mode: 'control', phase: 'revalidate', sessionId: r.id,
  });
  if (!check.ok) return notOk(r, 'remoteUnavailable', 409, { reason: check.reason, ...(check.details ?? {}) });
  requireAttached(r);
  const row = await update(trx, r, {
    mode: 'control', consented_mode: 'control', escalation_state: 'granted', escalated_at: new Date(), step_up_via: c.stepUpVia ?? null,
  });
  await audit.appendInTx(trx, {
    tenantId: Number(r.tenant_id), action: 'remote.session_escalation_granted', target: target(row), ...why(r),
    details: { deviceId: Number(r.device_id), from: 'view', to: 'control', stepUp: c.stepUpVia ?? null, stepUpStrict: true, consoleIp: c.consoleIp ?? null },
  }, c.auditCtx);
  sendMode(fx, row, 'control');
  changed(fx, row);
  return { ok: true, row };
}

/** Control → view by the requester of a live session in effective control (no second factor: the rights go down):
 *  the frame mode { effective: 'view' } to the agent, attached or not (the relay drops the inputs at once). */
export async function releaseControl(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, c: ControlChange): Promise<Transition> {
  const due = await endIfDue(trx, fx, r, c.auditCtx);
  if (due) return due;
  if (r.state !== 'live' || remoteEffectiveMode(r.mode, r.consented_mode) !== 'control') {
    return notOk(r, 'remoteSessionState', 409, { state: r.state, effectiveMode: remoteEffectiveMode(r.mode, r.consented_mode) });
  }
  const row = await update(trx, r, { mode: 'view', consented_mode: 'view', escalation_state: 'released' });
  await audit.appendInTx(trx, {
    tenantId: Number(r.tenant_id), action: 'remote.session_control_released', target: target(row),
    details: { deviceId: Number(r.device_id), from: 'control', to: 'view' },
  }, c.auditCtx, { onFailure: 'spool' });
  sendMode(fx, row, 'view');
  changed(fx, row);
  return { ok: true, row };
}

// ── The relay (T5) ───────────────────────────────────────────────────────────

/** The conditions of an end attaching to the relay (§4.4): the session's deadline, its state (the agent: connecting, its
 *  one-use stream token consumed; the viewer: connecting or live), its requester, then checkOpenable in its effective mode
 *  (a condition lost ends it: revoked or freeze). A viewer that replaces the one attached is audited
 *  (remote.session_viewer_reattached). */
export async function onEndAttaching(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow,
  x: { end: 'agent' | 'viewer'; reattach?: boolean; auditCtx: AuditWriteContext }): Promise<Transition> {
  const due = await endIfDue(trx, fx, r, x.auditCtx);
  if (due) return due;
  const states = x.end === 'agent' ? ['connecting'] : ['connecting', 'live'];
  if (!states.includes(r.state)) return notOk(r, 'remoteSessionState', 409, { state: r.state });
  if (r.requested_by === null) return endUnavailable(trx, fx, r, 'capabilityMissing', x.auditCtx);
  const check = await checkOpenable(trx, {
    tenantId: Number(r.tenant_id), userId: Number(r.requested_by), deviceId: Number(r.device_id),
    mode: remoteEffectiveMode(r.mode, r.consented_mode), phase: 'attach', sessionId: r.id,
  });
  if (!check.ok) return endUnavailable(trx, fx, r, check.reason, x.auditCtx, check.details);
  if (x.end === 'viewer' && x.reattach) {
    await audit.appendInTx(trx, {
      tenantId: Number(r.tenant_id), action: 'remote.session_viewer_reattached', target: target(r),
      details: { deviceId: Number(r.device_id), state: r.state },
    }, x.auditCtx, { onFailure: 'spool' });
  }
  return { ok: true, row: r };
}

export interface RevalidateInput {
  /** The relay's counters of the session, written first. */
  counters: RemoteCounters | null;
  /** The console session of its viewer still valid; null: no viewer attached (not read). */
  consoleSession: boolean | null;
  auditCtx: AuditWriteContext;
}

/** The revalidation of a session the relay holds (§2, every 60 s, §0.1 rule 3: the console session revalidated): its
 *  counters written, its deadline (the maximum duration, the 60 s to attach), the console session of its viewer
 *  (revoked otherwise), then the conditions for its requester in its effective mode (checkOpenable: revoked or
 *  freeze). Not ok: the session ended (or was final already). */
export async function revalidateSession(trx: Knex.Transaction, fx: RemoteEffects, r: SessionRow, x: RevalidateInput): Promise<Transition> {
  if (isRemoteFinalState(r.state)) return notOk(r, 'remoteSessionState', 409, { state: r.state });
  const row = x.counters ? await update(trx, r, countersColumns(x.counters)) : r;
  const due = await endIfDue(trx, fx, row, x.auditCtx);
  if (due) return due;
  if (row.requested_by === null) return endUnavailable(trx, fx, row, 'capabilityMissing', x.auditCtx);
  if (x.consoleSession === false) {
    const ended = await endSession(trx, fx, row, { reason: 'revoked', by: 'system', auditCtx: x.auditCtx, details: { consoleSession: 'gone' } });
    return notOk(ended, 'remoteUnavailable', 409, { reason: 'revoked' });
  }
  const check = await checkOpenable(trx, {
    tenantId: Number(row.tenant_id), userId: Number(row.requested_by), deviceId: Number(row.device_id),
    mode: remoteEffectiveMode(row.mode, row.consented_mode), phase: 'revalidate', sessionId: row.id,
  });
  if (!check.ok) return endUnavailable(trx, fx, row, check.reason, x.auditCtx, check.details);
  return { ok: true, row };
}

// ── Viewer's token ───────────────────────────────────────────────────────────

/** The viewer's token of a session approved later (POST /:id/viewer-token): once, before the attachment, to its
 *  requester (whose strict step-up the route took), bound to the console session that asks it. Returned in clear here
 *  only; its SHA-256 kept. */
export async function issueViewerToken(trx: Knex.Transaction, r: SessionRow, userId: number, stepUpVia: StepUpVia | null = null,
  consoleSession: string | null = null): Promise<{ row: SessionRow; token: string }> {
  if (Number(r.requested_by) !== userId) throw new AppError(404, 'Session not found');
  if (!['queued', 'awaiting_consent', 'connecting'].includes(r.state)) throw stateError(r);
  if (r.viewer_token_sha256 !== VIEWER_TOKEN_UNISSUED) throw new AppError(409, 'The viewer token of this session was already handed', 'viewerTokenIssued');
  const token = randomBytes(32).toString('hex');
  const row = await update(trx, r, { viewer_token_sha256: sha256Hex(token), viewer_session_sha256: consoleSession, ...(stepUpVia ? { step_up_via: stepUpVia } : {}) });
  return { row, token };
}

// ── Sweep (§4.1 sweep.ts) ────────────────────────────────────────────────────

/** The open sessions of a tenant past a deadline: their state's (ended with its reason), their maximum duration
 *  (max_duration). In the tenant's transaction, `limit` rows at most, those locked by a transition skipped (taken at
 *  the next run). */
export async function sweepTenant(trx: Knex.Transaction, fx: RemoteEffects, tenantId: number, auditCtx: AuditWriteContext,
  limit = 200): Promise<{ ended: number }> {
  const now = new Date();
  const rows = await trx('remote_sessions').where({ tenant_id: tenantId }).whereNull('ended_at')
    .where((w) => { w.where('expires_at', '<=', now).orWhere('max_ends_at', '<=', now); })
    .orderBy('expires_at').limit(limit).forUpdate().skipLocked().select('*') as SessionRow[];
  let ended = 0;
  for (const r of rows) {
    const due = dueReason(r, now);
    if (due) {
      await endSession(trx, fx, r, { reason: due, by: 'system', auditCtx });
      ended++;
    }
  }
  return { ended };
}

/** The sessions a restart orphaned (§4.1): the relay pairs in memory, so a live or connecting session of before the
 *  start has lost its ends: ended server_restart. */
export async function closeOrphanedOfTenant(trx: Knex.Transaction, fx: RemoteEffects, tenantId: number, auditCtx: AuditWriteContext): Promise<number> {
  const rows = await trx('remote_sessions').where({ tenant_id: tenantId }).whereNull('ended_at').whereIn('state', ['live', 'connecting'])
    .forUpdate().select('*') as SessionRow[];
  for (const r of rows) await endSession(trx, fx, r, { reason: 'server_restart', by: 'system', auditCtx });
  return rows.length;
}

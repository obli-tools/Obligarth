import { createHash, randomBytes } from 'node:crypto';
import type { Knex } from 'knex';
import type { z } from 'zod';
import {
  REMOTE_LIMITS, isRemoteFinalState,
  type LegacyAgentErrorCode, type LegacyAgentRemoteConfig, type RemoteEndedBy,
} from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../audit';
import { LEGACY_AGENT_ACTOR } from '../legacyAgent/actor';
import type { LegacyAgentRemote, LegacyAgentRemoteBatch } from '../legacyAgent/remoteBridge';
import { RemoteAcceptBody, RemoteEndBody } from '../legacyAgent/schemas';
import { withAgentTransaction } from '../legacyAgent/session';
import { errorReply, type AgentIdentity, type Exchange, type Reply } from '../legacyAgent/surface';
import { remoteAssistanceAllowed } from '../privacy/profiles';
import { remoteAvailability } from './guard';
import {
  RemoteEffects, endSession, flushRemoteEffects, lockSession, onAccepted, onCommandResult, onDelivered, type SessionRow, type Transition,
} from './sessions';
import { readRemoteSettings } from './settings';
import { holdWait, wakeDevice } from './wake';

// =============================================================================
// The bridge agent's side of the remote sessions (P0-15 §4.3, T4; §0.1: nothing is asked of the user of the device),
// registered into the agent surface by modules/remote.ts (legacyAgent/remoteBridge.ts):
//   /poll       the open session of the device locked after the device; its remote.open delivered only while the
//               session awaits it (queued → awaiting_consent: the system dialog of the screen capture, 60 s + margin),
//               withdrawn when the session ended or passed its deadline; the agent's error or refusal of it
//               (projection_denied, agent_busy, unsupported…) closes a session that has not reached connecting
//   /accept     consentedMode = the mode asked (view when the agent cannot inject; never above: 400
//               consentExceedsRequest, the session closed), notificationsEnabled informative; the conditions read again;
//               the answer, signed: a one-use stream token (32 bytes, base64url; its SHA-256 over the 32 bytes kept),
//               its path, 60 s to attach, the end at the latest, the inactivity, the uplink bitrate (kbit/s)
//   /end        the end from the device's side: projection_denied, screen_off_timeout, agent_error; a final session
//               answers 200 as it is (the agent may tell both the result and /end)
//   /wait       remote/wake.ts
//   config      config.remote: the rule remoteAssistance of the corporate profile, the permanent wait of the tenant, the
//               armed window 15 min after the end of a session the device took
// The refusals of /accept that close the session (the agent then tells nothing more, session_gone): 404 notFound,
// 409 remoteSessionState, 400 consentExceedsRequest, 409 remoteUnavailable. Any other (400 badRequest, 401, 409
// seqReplay, 429, 503) leaves it awaiting /accept: the agent ends it with /end agent_error.
// =============================================================================

const streamPath = (sessionId: string): string => `/agent/v1/remote/${sessionId}/stream`;
const unix = (d: Date | string | null): number | null => (d ? Math.floor(new Date(d).getTime() / 1000) : null);

/** The hash of a stream token kept in remote_sessions.stream_token_sha256: SHA-256 (hex) of its 32 bytes (the agent
 *  sends them back in Obl-Stream-Token, base64url, at the attachment, T5). */
export const streamTokenSha256 = (token: Buffer): string => createHash('sha256').update(token).digest('hex');

const MESSAGES: Record<string, string> = {
  remoteSessionState: 'The session cannot take this in its state',
  consentExceedsRequest: 'The mode taken exceeds the mode asked: the session is closed',
  remoteUnavailable: 'The session is no longer possible on this device: it is closed',
};

/** The agent's answer of a transition refused (its session closed, or not in a state to take it). */
function refusal(t: Extract<Transition, { ok: false }>): Reply {
  return errorReply(t.status, t.code as LegacyAgentErrorCode, MESSAGES[t.code] ?? 'Refused', { ...(t.details ?? {}), state: t.row.state });
}

/** The body of a request in its strict schema, or the 400 of the surface. */
function parse<S extends z.ZodTypeAny>(raw: Buffer, schema: S): { ok: true; data: z.infer<S> } | { ok: false; reply: Reply } {
  let json: unknown;
  try { json = JSON.parse(raw.toString('utf8')); } catch { return { ok: false, reply: errorReply(400, 'badRequest', 'Malformed JSON') }; }
  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    return { ok: false, reply: errorReply(400, 'badRequest', `Invalid body: ${parsed.error.issues[0]?.path.join('.') ?? ''}`.slice(0, 200)) };
  }
  return { ok: true, data: parsed.data };
}

/** The session of the route, of this agent's device only (another device's, another tenant's: unknown). */
async function sessionOfAgent(trx: Knex.Transaction, who: AgentIdentity, sessionId: string): Promise<SessionRow | null> {
  const r = await lockSession(trx, who.tenantId, sessionId);
  return r && Number(r.device_id) === who.deviceId && r.channel === 'legacy_agent' ? r : null;
}

const notFound = (): Reply => errorReply(404, 'notFound', 'Session not found');

// ── /poll ────────────────────────────────────────────────────────────────────

class PollBatch implements LegacyAgentRemoteBatch {
  private open: SessionRow | null = null;
  private readonly fx = new RemoteEffects();
  private ctx: AuditWriteContext | null = null;

  constructor(private readonly who: AgentIdentity) {}

  private async auditCtx(): Promise<AuditWriteContext> {
    this.ctx ??= await audit.fromDbActor(LEGACY_AGENT_ACTOR, this.who.tenantId);
    return this.ctx;
  }

  /** The open session of this device whose request is `commandId`. */
  private of(commandId: string): SessionRow | null {
    const r = this.open;
    return r && !isRemoteFinalState(r.state) && r.command_id && String(r.command_id).toLowerCase() === commandId.toLowerCase() ? r : null;
  }

  async lock(trx: Knex.Transaction): Promise<void> {
    const r = await trx('remote_sessions').where({ tenant_id: this.who.tenantId, device_id: this.who.deviceId }).whereNull('ended_at')
      .forUpdate().first() as SessionRow | undefined;
    this.open = r ?? null;
  }

  async delivering(trx: Knex.Transaction, commandIds: string[]): Promise<{ withdraw: Set<string>; defer: Set<string> }> {
    const withdraw = new Set<string>();
    const defer = new Set<string>();
    for (const id of commandIds) {
      const r = this.of(id);
      if (!r) { withdraw.add(id); continue; }
      // Delivered before and not answered (a delivery again): it still awaits /accept.
      if (r.state === 'awaiting_consent') continue;
      // Already taken (connecting, live): the agent holds it, nothing to hand again.
      if (r.state !== 'queued') { defer.add(id); continue; }
      const t = await onDelivered(trx, this.fx, r, await this.auditCtx());
      this.open = t.row;
      if (!t.ok) withdraw.add(id);
    }
    return { withdraw, defer };
  }

  async resulted(trx: Knex.Transaction, x: { commandId: string; status: string; code: string }): Promise<void> {
    // acknowledged (done, remote_injection_unavailable): the session goes on through /accept.
    if (x.status === 'acknowledged') return;
    const r = this.of(x.commandId);
    if (!r) return;
    this.open = await onCommandResult(trx, this.fx, r, x.code, await this.auditCtx());
  }

  async flush(): Promise<void> {
    if (this.ctx) await flushRemoteEffects(this.fx, LEGACY_AGENT_ACTOR, this.ctx);
  }
}

// ── /accept, /end ────────────────────────────────────────────────────────────

async function accept(who: AgentIdentity, ex: Exchange, sessionId: string, raw: Buffer): Promise<Reply> {
  const p = parse(raw, RemoteAcceptBody);
  if (!p.ok) return p.reply;
  const body = p.data;
  if (Buffer.byteLength(JSON.stringify(body.capabilities), 'utf8') > REMOTE_LIMITS.agentCapabilitiesMaxBytes) {
    return errorReply(400, 'badRequest', 'Invalid body: capabilities');
  }
  const token = randomBytes(32);
  const fx = new RemoteEffects();
  const held: { ctx: AuditWriteContext | null } = { ctx: null };
  const reply = await withAgentTransaction(who, ex, async (trx) => {
    const r = await sessionOfAgent(trx, who, sessionId);
    if (!r) return notFound();
    held.ctx = await audit.fromDbActor(LEGACY_AGENT_ACTOR, who.tenantId);
    const t = await onAccepted(trx, fx, r, {
      consentedMode: body.consentedMode, capabilities: body.capabilities, streamTokenSha256: streamTokenSha256(token), auditCtx: held.ctx,
    });
    if (!t.ok) return refusal(t);
    return {
      status: 200,
      body: {
        success: true, streamToken: token.toString('base64url'), streamPath: streamPath(String(t.row.id).toLowerCase()),
        expiresIn: REMOTE_LIMITS.streamTokenSeconds, maxEndsAt: unix(t.row.max_ends_at), idleSeconds: REMOTE_LIMITS.idleSeconds,
        bitrateMax: REMOTE_LIMITS.agentUplinkKbps,
      },
    };
  });
  token.fill(0);
  if (held.ctx) await flushRemoteEffects(fx, LEGACY_AGENT_ACTOR, held.ctx);
  return reply;
}

/** The states in which the device may end a session: once it took its request. */
const DEVICE_SIDE_STATES = new Set(['awaiting_consent', 'connecting', 'live']);

async function end(who: AgentIdentity, ex: Exchange, sessionId: string, raw: Buffer): Promise<Reply> {
  const p = parse(raw, RemoteEndBody);
  if (!p.ok) return p.reply;
  const body = p.data;
  const fx = new RemoteEffects();
  const held: { ctx: AuditWriteContext | null } = { ctx: null };
  const reply = await withAgentTransaction(who, ex, async (trx) => {
    const r = await sessionOfAgent(trx, who, sessionId);
    if (!r) return notFound();
    if (isRemoteFinalState(r.state)) return { status: 200, body: { success: true, state: r.state, endReason: r.end_reason } };
    if (!DEVICE_SIDE_STATES.has(r.state)) return errorReply(409, 'remoteSessionState', MESSAGES.remoteSessionState, { state: r.state });
    held.ctx = await audit.fromDbActor(LEGACY_AGENT_ACTOR, who.tenantId);
    // The system dialog refused or unanswered, the screen off too long: the device's side; its error: the system.
    const by: RemoteEndedBy = body.reason === 'agent_error' ? 'system' : 'user';
    const row = await endSession(trx, fx, r, { reason: body.reason, by, auditCtx: held.ctx, details: { endedFrom: 'agent' } });
    return { status: 200, body: { success: true, state: row.state, endReason: row.end_reason } };
  });
  if (held.ctx) await flushRemoteEffects(fx, LEGACY_AGENT_ACTOR, held.ctx);
  return reply;
}

// ── /wait ────────────────────────────────────────────────────────────────────

async function wait(who: AgentIdentity, _ex: Exchange, nonce: string, onClose: (fn: () => void) => void): Promise<Reply> {
  const held = holdWait(who, onClose);
  if (held === null) return errorReply(429, 'rateLimited', 'Too many waits on this server', {}, { 'Retry-After': '60' });
  const wake = await held;
  return { status: 200, body: { success: true, wake, nonce } };
}

// ── Configuration ────────────────────────────────────────────────────────────

/** config.remote of an agent of the device (§4.3). armedUntil: 15 min after the end of the last session its device took
 *  (delivered), while it is ahead; a value fixed by that end (the configuration's version changes twice: when it arms,
 *  when it passes). */
async function config(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<LegacyAgentRemoteConfig> {
  const enabled = await remoteAssistanceAllowed(trx, tenantId, 'corporate');
  const settings = await readRemoteSettings(trx, tenantId);
  let armedUntil: number | null = null;
  if (enabled) {
    const windowMs = REMOTE_LIMITS.armedWindowMinutes * 60_000;
    const last = await trx('remote_sessions').where({ tenant_id: tenantId, device_id: deviceId }).whereNotNull('delivered_at')
      .where('ended_at', '>', new Date(Date.now() - windowMs)).max('ended_at as at').first() as { at: Date | string | null } | undefined;
    const until = last?.at ? unix(new Date(new Date(last.at).getTime() + windowMs)) : null;
    if (until !== null && until > Math.floor(Date.now() / 1000)) armedUntil = until;
  }
  return { enabled, waitChannel: enabled && settings.waitChannel, armedUntil, minAgentVersion: REMOTE_LIMITS.minAgentVersion };
}

export const legacyAgentRemoteBridge: LegacyAgentRemote = {
  batch: (who) => new PollBatch(who),
  config,
  accept,
  end,
  wait,
  wake(tenantId, deviceIds) {
    for (const d of deviceIds) {
      try { wakeDevice(tenantId, d); } catch { /* a wake never fails a request */ }
    }
  },
  availability: (tenantId, userId, deviceId, mode) => remoteAvailability(tenantId, userId, deviceId, mode),
};

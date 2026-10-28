import type { RemoteServerToAgentMessage } from '@obligarth/shared';
import { AppError } from '../../middleware/errorHandler';
import { legacyAgentCommands, REMOTE_OPEN } from '../../legacyAgent/commands';
import type { RemoteChannelImpl } from '../channels';
import { legacyAgentEligible, remoteOpenParams } from './legacyAgentRules';

export { agentVersionNameOf, remoteOpenParams, versionAtLeast } from './legacyAgentRules';

// =============================================================================
// The channel legacy_agent of the remote assistance (P0-15 §4.1, §4.3; parc of the Android bridge agent, first):
//   eligible       the agent enrolled and not revoked, version 1.1.0 at least (agentTooOld); the control
//                  (mode 'control') refused on Android 15 and later (platformUnsupported, KBA Samsung 1674: the Knox
//                  control is kept to the Android Enterprise modes) and while the measured capability remoteInject of
//                  the agent (status item agent.remote.inject, §8) is not true: knoxRequired without a licensed Knox,
//                  injectUnavailable otherwise, whatever knox_state says;
//   dispatchOpen   remote.open in the queue of the device (origin 'remote', actor u:<requester>, the session's id as
//                  the idempotency key), in the session's transaction; its params are filled by the server (operator,
//                  organisation, data controller; the reason when given) and hold no secret; the agent opens the
//                  session without asking its user, who is told by its notifications (§0.1 rules 1, 2);
//   cancel         the remote.open still pending withdrawn (one delivered stays: the agent learns the end at /accept);
//   wake           the long wait of the agent (remote/wake.ts, set by modules/remote.ts): answered at once when held
//                  (armed window); otherwise the agent takes the request at its next interrogation (« Demander de
//                  l'aide », or its period);
//   attached,      through the relay (remote/relay.ts, T5), which registers its sink (setRemoteControlSink): is the
//   deliverControl agent's end attached; the frames mode (the control granted or released by the server, sent once
//                  committed) and session_end.
// =============================================================================

export interface ControlSink {
  attached(sessionId: string): boolean;
  deliver(sessionId: string, message: RemoteServerToAgentMessage): boolean;
}
let controlSink: ControlSink | null = null;

/** The relay's way to a session's agent end (remote/relay.ts, T5); without it no agent is attached, no control
 *  message leaves. */
export function setRemoteControlSink(sink: ControlSink | null): void {
  controlSink = sink;
}

type WakeHook = (tenantId: number, deviceId: number) => void;
let wakeHook: WakeHook | null = null;

/** The long waits of the bridge agents (remote/wake.ts, T4). */
export function setLegacyAgentWakeHook(hook: WakeHook | null): void {
  wakeHook = hook;
}

const REFUSAL_REASONS: Record<string, 'revoked' | 'notEnrolled' | 'platformUnsupported'> = {
  revoked: 'revoked', not_enrolled: 'notEnrolled', not_agent: 'platformUnsupported',
};

export const legacyAgentRemoteChannel: RemoteChannelImpl = {
  eligible: legacyAgentEligible,

  async dispatchOpen(trx, session, auditCtx) {
    const o = await legacyAgentCommands.enqueue(trx, {
      tenantId: session.tenantId, requestType: REMOTE_OPEN, deviceIds: [session.deviceId], params: remoteOpenParams(session),
      origin: 'remote', actor: session.requestedBy ? `u:${session.requestedBy}` : 'j:remote.sessions', ...(session.requestedBy ? { requestedBy: session.requestedBy } : {}),
      ...(session.reason ? { reason: session.reason } : {}), ...(session.approvalId ? { approvalId: session.approvalId } : {}), idempotencyKey: `remote:${session.id}`, auditCtx,
    });
    if (o.targets === 0 || !o.commandIds[0]) {
      const reason = REFUSAL_REASONS[o.refused[0]?.code ?? ''] ?? 'platformUnsupported';
      throw new AppError(409, 'The device cannot take a remote session now', 'remoteUnavailable', { reason });
    }
    return o.commandIds[0];
  },

  wake(tenantId, deviceId) {
    try { wakeHook?.(tenantId, deviceId); } catch { /* a wake never fails a request */ }
  },

  async cancel(trx, session) {
    if (!session.commandId) return;
    const actor = session.requestedBy ? `u:${session.requestedBy}` : 'j:remote.sessions';
    try {
      await legacyAgentCommands.cancel(trx, session.tenantId, session.commandId, actor, { silent: true });
    } catch (err) {
      // The command purged meanwhile (its retention): nothing to withdraw.
      if (!(err instanceof AppError && err.statusCode === 404)) throw err;
    }
  },

  attached(sessionId) {
    return controlSink ? controlSink.attached(sessionId) : false;
  },

  deliverControl(sessionId, message) {
    return controlSink ? controlSink.deliver(sessionId, message) : false;
  },
};

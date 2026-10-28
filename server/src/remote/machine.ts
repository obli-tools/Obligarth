import { createHash } from 'node:crypto';
import {
  isRemoteFinalState, remoteEffectiveMode,
  type RemoteChannel, type RemoteEndReason, type RemoteEndedBy, type RemoteEscalationState, type RemoteFinalState, type RemoteMode,
  type RemoteRequesterSide, type RemoteSessionDto, type RemoteSessionState,
} from '@obligarth/shared';

// =============================================================================
// The pure part of the state machine of the remote assistance sessions (P0-15 §2), without a database: the row, the
// console's view, the final state of an end, the deadline of each state. server/src/remote/sessions.ts runs the
// transitions; the unit tests load this file alone.
// =============================================================================

/** The hash a session holds while its viewer's token was never handed (a session approved later: POST
 *  /:id/viewer-token, once). No token hashes to it (a token is 64 hex characters, its SHA-256 is never all zeros). */
export const VIEWER_TOKEN_UNISSUED = '0'.repeat(64);

export const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

export interface SessionRow {
  id: string;
  tenant_id: number;
  device_id: number;
  channel: RemoteChannel;
  mode: RemoteMode;
  state: RemoteSessionState;
  requested_by: number | null;
  requested_by_name: string;
  requester_side: RemoteRequesterSide;
  operator_org: string;
  controller_name: string;
  approval_id: number | null;
  reason: string | null;
  ticket: string | null;
  step_up_via: string | null;
  command_id: string | null;
  viewer_token_sha256: string;
  /** The console session (SHA-256 of its express session id) the viewer's token was handed to. */
  viewer_session_sha256: string | null;
  stream_token_sha256: string | null;
  stream_token_expires_at: Date | null;
  stream_token_used_at: Date | null;
  created_at: Date;
  delivered_at: Date | null;
  consented_at: Date | null;
  started_at: Date | null;
  ended_at: Date | null;
  expires_at: Date;
  max_ends_at: Date | null;
  consented_mode: RemoteMode | null;
  escalated_at: Date | null;
  escalation_state: RemoteEscalationState | null;
  end_reason: RemoteEndReason | null;
  ended_by: RemoteEndedBy | null;
  ended_by_user_id: number | null;
  bytes_down: string | number;
  bytes_up: string | number;
  input_events: number;
  agent_capabilities: unknown;
}

const iso = (v: Date | string | null | undefined): string | null => (v ? new Date(v).toISOString() : null);

/** The console's view of a session (never a token, nor its hash). */
export function sessionDto(r: SessionRow, now: Date = new Date()): RemoteSessionDto {
  const started = r.started_at ? new Date(r.started_at).getTime() : null;
  const end = r.ended_at ? new Date(r.ended_at).getTime() : now.getTime();
  return {
    id: String(r.id).toLowerCase(), deviceId: Number(r.device_id), channel: r.channel, mode: r.mode, consentedMode: r.consented_mode ?? null,
    effectiveMode: remoteEffectiveMode(r.mode, r.consented_mode ?? null), state: r.state,
    requestedBy: r.requested_by === null ? null : Number(r.requested_by), requestedByName: r.requested_by_name, requesterSide: r.requester_side,
    operatorOrg: r.operator_org, reason: r.reason ?? null, ticket: r.ticket ?? null, approvalId: r.approval_id === null ? null : Number(r.approval_id),
    createdAt: iso(r.created_at) as string, deliveredAt: iso(r.delivered_at), consentedAt: iso(r.consented_at), startedAt: iso(r.started_at),
    endedAt: iso(r.ended_at), expiresAt: iso(r.expires_at) as string, maxEndsAt: iso(r.max_ends_at), escalationState: r.escalation_state ?? null,
    endReason: r.end_reason ?? null, endedBy: r.ended_by ?? null, bytesDown: Number(r.bytes_down ?? 0), bytesUp: Number(r.bytes_up ?? 0),
    inputEvents: Number(r.input_events ?? 0), durationSeconds: started === null ? null : Math.max(0, Math.round((end - started) / 1000)),
  };
}

/** The final state of a session ended in `state` for `reason` (§2, §0.1: no refusal by the user; the system dialog of
 *  the capture refused or left unanswered is a failure of the opening). */
export function finalStateOf(state: RemoteSessionState, reason: RemoteEndReason): RemoteFinalState {
  if (state === 'live') return 'ended';
  switch (reason) {
    case 'device_timeout': case 'approval_expired': return state === 'connecting' ? 'failed' : 'expired';
    case 'projection_denied': case 'agent_error': case 'server_restart': return 'failed';
    default: return 'cancelled';
  }
}

/** The reason a session past the deadline of its state ends with (null: not due). */
export function dueReason(r: SessionRow, now: Date): RemoteEndReason | null {
  if (isRemoteFinalState(r.state)) return null;
  const expired = new Date(r.expires_at).getTime() <= now.getTime();
  if (r.state === 'live') return expired || (r.max_ends_at && new Date(r.max_ends_at).getTime() <= now.getTime()) ? 'max_duration' : null;
  if (!expired) return null;
  return r.state === 'awaiting_approval' ? 'approval_expired' : 'device_timeout';
}

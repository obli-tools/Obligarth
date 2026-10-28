import type { Knex } from 'knex';
import type {
  RemoteChannel, RemoteMode, RemoteServerToAgentMessage, RemoteUnavailableReason,
} from '@obligarth/shared';
import type { AuditWriteContext } from '../audit';

// =============================================================================
// The channels of the remote assistance (P0-15 §4.1): what a fleet does for a session. server/src/remote is the only
// writer of remote_sessions; a channel answers for its devices: are they eligible (its own conditions, after the
// common ones of guard.ts), how the request of a session reaches the device (dispatchOpen, in the transaction of the
// session), how the device is woken, what is withdrawn when the session ends before the device took it, and how a
// control message reaches the agent's end of the relay. T3 registers legacy_agent (channels/legacyAgent.ts:
// dispatchOpen = remote.open in the queue of the bridge agent); android waits for T10 (after P0-9), apple for T11.
// Registered before anything starts (modules/remote.ts), no I/O.
// =============================================================================

/** What a channel reads of a device to decide (the row of the session's device, in the tenant's transaction). */
export interface RemoteDeviceFacts {
  deviceId: number;
  managementChannel: string;
  ownership: string | null;
  enrollmentState: string;
  platform: string | null;
}

/** The session as a channel sees it at its dispatch or its cancellation. */
export interface RemoteChannelSession {
  id: string;
  tenantId: number;
  deviceId: number;
  mode: RemoteMode;
  requestedBy: number | null;
  requestedByName: string;
  operatorOrg: string;
  controllerName: string;
  /** Optional (§0.1 rule 3). */
  reason: string | null;
  approvalId: number | null;
  commandId: string | null;
  maxMinutes: number;
}

export type RemoteEligibility = { ok: true } | { ok: false; reason: RemoteUnavailableReason; details?: Record<string, unknown> };

export interface RemoteChannelImpl {
  /** The channel's own conditions of a session on this device in this mode (the agent's version, Knox, the measured
   *  injection, the Android version…), in the caller's transaction (the tenant's context). */
  eligible(trx: Knex.Transaction, tenantId: number, device: RemoteDeviceFacts, mode: RemoteMode): Promise<RemoteEligibility>;
  /** Sends the request of the session to the device, in the session's transaction; returns the id of the command (the
   *  row remote_sessions.command_id), or null when the channel has none. Throws (AppError) when the device cannot take
   *  it: the transaction is rolled back, no session is left. */
  dispatchOpen(trx: Knex.Transaction, session: RemoteChannelSession, auditCtx: AuditWriteContext): Promise<string | null>;
  /** Wakes the device after the commit (a long wait, a push…): never throws, never awaited by the request. */
  wake(tenantId: number, deviceId: number): void;
  /** The session ended before the device took its request: the request is withdrawn, in the session's transaction. */
  cancel(trx: Knex.Transaction, session: RemoteChannelSession): Promise<void>;
  /** Is the agent's end of this session attached to the relay now (the control is granted only then)? */
  attached(sessionId: string): boolean;
  /** A control message to the agent's end of the relay (mode, session_end), once its transaction committed: false
   *  when the agent is not attached. */
  deliverControl(sessionId: string, message: RemoteServerToAgentMessage): boolean;
}

const channels = new Map<RemoteChannel, RemoteChannelImpl>();

/** The implementation of a channel (one per channel). */
export function registerRemoteChannel(channel: RemoteChannel, impl: RemoteChannelImpl): void {
  if (channels.has(channel)) throw new Error(`remote channel ${channel}: registered twice`);
  for (const k of ['eligible', 'dispatchOpen', 'wake', 'cancel', 'attached', 'deliverControl'] as const) {
    if (typeof impl[k] !== 'function') throw new Error(`remote channel ${channel}: ${k} is required`);
  }
  channels.set(channel, Object.freeze({ ...impl }));
}

/** The channel of a session (undefined: no channel registered, the platform is unsupported). */
export function remoteChannel(channel: string): RemoteChannelImpl | undefined {
  return channels.get(channel as RemoteChannel);
}

/** The channel of the remote assistance of a device's management channel. */
export function remoteChannelOfManagement(managementChannel: string): RemoteChannel | null {
  if (managementChannel === 'legacy_agent') return 'legacy_agent';
  if (managementChannel === 'amapi') return 'android';
  if (managementChannel === 'apple_mdm') return 'apple';
  return null;
}

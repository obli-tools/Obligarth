import type { Knex } from 'knex';
import type { LegacyAgentRemoteConfig, RemoteMode, RemoteUnavailableReason } from '@obligarth/shared';
import type { AgentIdentity, Exchange, Reply } from './surface';

// =============================================================================
// The remote assistance seen from the bridge agent (P0-15 §4.3): what the queue, the interrogation, the configuration,
// the menu of a device and the routes of the surface ask of server/src/remote, without importing it (the module of
// the remote assistance depends on the bridge agent, never the reverse). modules/remote.ts registers it before
// anything starts; without it the agent surface has no remote route (404), a remote.open is delivered as any command,
// the configuration has no remote object and the menu no remote action.
// =============================================================================

/** What one transaction of /poll does for the remote session of its device, then after its commit. */
export interface LegacyAgentRemoteBatch {
  /** First in the transaction, after the state of the device (the order of the locks: the satellite, the device, the
   *  session, then the commands, as the console's transitions take the session then its command). */
  lock(trx: Knex.Transaction): Promise<void>;
  /** The remote.open among `commandIds` the delivery is about to hand: those whose session takes it (queued →
   *  awaiting_consent, or already awaiting it: a delivery again) are delivered; `withdraw` the others (the session
   *  ended, or past its deadline: it ends there); `defer` those the agent already took (connecting, live: kept, not
   *  handed again). */
  delivering(trx: Knex.Transaction, commandIds: string[]): Promise<{ withdraw: Set<string>; defer: Set<string> }>;
  /** The agent's result of a remote.open (an error or a refusal closes a session that has not reached connecting). */
  resulted(trx: Knex.Transaction, r: { commandId: string; status: string; code: string }): Promise<void>;
  /** After the commit (never throws). */
  flush(): Promise<void>;
}

export interface LegacyAgentRemote {
  batch(who: AgentIdentity): LegacyAgentRemoteBatch;
  /** config.remote of an agent of the device (§4.3), in the tenant's transaction. */
  config(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<LegacyAgentRemoteConfig>;
  /** POST /agent/v1/remote/<id>/accept, the request authenticated (signature, revocation, clock); seq consumed. */
  accept(who: AgentIdentity, ex: Exchange, sessionId: string, body: Buffer): Promise<Reply>;
  /** POST /agent/v1/remote/<id>/end, the same. */
  end(who: AgentIdentity, ex: Exchange, sessionId: string, body: Buffer): Promise<Reply>;
  /** POST /agent/v1/wait, authenticated with Obl-Seq 0 (no sequence read nor consumed): held up to 50 s. `onClose` tells
   *  when the connection of the agent closes. */
  wait(who: AgentIdentity, ex: Exchange, nonce: string, onClose: (fn: () => void) => void): Promise<Reply>;
  /** Wakes the long waits of these devices (a command that cannot wait: lock, erase), after the commit. Never throws. */
  wake(tenantId: number, deviceIds: number[]): void;
  /** The reason a remote action of the device is unavailable to the caller, null when it is available. */
  availability(tenantId: number, userId: number, deviceId: number, mode: RemoteMode): Promise<RemoteUnavailableReason | null>;
}

let remote: LegacyAgentRemote | null = null;

/** Registered once, before anything starts (modules/remote.ts). */
export function registerLegacyAgentRemote(impl: LegacyAgentRemote): void {
  if (remote && remote !== impl) throw new Error('legacy agent remote registered twice');
  remote = impl;
}

export function legacyAgentRemote(): LegacyAgentRemote | null {
  return remote;
}

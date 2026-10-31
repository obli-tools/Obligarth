import type { Knex } from 'knex';
import { db } from '../db';
import { asTenant } from '../db/context';
import { LEGACY_AGENT_ACTOR } from './actor';
import type { AgentIdentity, Exchange, Reply } from './surface';

// =============================================================================
// The transaction of a signed request (docs: agent-pont-android §4.2 (5)): in
// the tenant's context, the satellite locked (requests of one agent are
// serialised), revocation read again, the sequence number strictly above the
// last one (409 seqReplay with lastSeq, RC-6), then the processing and
// last_seq = seq in the SAME transaction: a processing that fails does not
// consume the number.
// =============================================================================

export interface Satellite {
  device_id: number;
  tenant_id: number;
  agent_id: string;
  last_seq: string | number;
  agent_version_code: number;
  admin_active: boolean;
  knox_state: string;
  poll_seconds: number | null;
  last_inventory_at: Date | null;
  inventory_requested_at: Date | null;
  security_patch: string | null;
  revoked_at: Date | null;
  /** Lot BANC: the agent owns the device (as last reported). */
  device_owner: boolean;
  adb_enabled: boolean | null;
}

export function withAgentTransaction(who: AgentIdentity, _ex: Exchange,
  fn: (trx: Knex.Transaction, sat: Satellite) => Promise<Reply>): Promise<Reply> {
  return asTenant(who.tenantId, LEGACY_AGENT_ACTOR, () => db.transaction(async (trx) => {
    const sat = await trx('legacy_agent_devices').where({ tenant_id: who.tenantId, device_id: who.deviceId }).forUpdate().first() as Satellite | undefined;
    if (!sat || String(sat.agent_id).toLowerCase() !== who.agentId) {
      return { status: 401, body: { success: false, error: 'Unknown agent', code: 'unknownAgent' }, signed: false };
    }
    if (sat.revoked_at) return { status: 403, body: { success: false, error: 'This device was removed from management', code: 'agentRevoked' } };
    const last = Number(sat.last_seq);
    if (!(who.seq > last)) {
      return { status: 409, body: { success: false, error: 'Sequence number already used', code: 'seqReplay', lastSeq: last } };
    }
    const reply = await fn(trx, sat);
    await trx('legacy_agent_devices').where({ tenant_id: who.tenantId, device_id: who.deviceId }).update({ last_seq: who.seq, updated_at: new Date() });
    return reply;
  }));
}

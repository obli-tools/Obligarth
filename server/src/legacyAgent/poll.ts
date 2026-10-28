import type { Knex } from 'knex';
import { REMOTE_LEGACY_INJECT_ITEM } from '@obligarth/shared';
import { audit } from '../audit';
import { raiseInTx, resolveInTx } from '../apple/alerts/service';
import { tenantFrozen as frozenFor } from '../guard/frozen';
import { LEGACY_AGENT_ACTOR } from './actor';
import { agentConfigFor } from './agentConfig';
import { acknowledgeUpdates, applyResults, deliver, REMOTE_OPEN } from './commands';
import { instanceSettings } from './config';
import { legacyAgentRemote } from './remoteBridge';
import { PollBody } from './schemas';
import { withAgentTransaction, type Satellite } from './session';
import { errorReply, type AgentIdentity, type Exchange, type Reply } from './surface';
import { writeStatusItems } from './status';

/** The freeze of the queue of the bridge agent: the engine's, and apple-edge's mirror (decision PONT-R; guard/frozen.ts). */
const tenantFrozen = (trx: Knex.Transaction, tenantId: number): Promise<boolean> => frozenFor(trx, tenantId, 'legacy_agent');

// =============================================================================
// POST /agent/v1/poll (docs: agent-pont-android §4.5, RS-2, RS-3): in one
// transaction of the tenant, the satellite locked and the sequence checked
// (session.ts): the state of the device (satellite, last contact, status
// items), the results (by rank), the events (audit, alerts), then the
// commands to deliver (commands.ts: nothing while the tenant is frozen). The
// remote session of the device (P0-15 §4.3, remoteBridge.ts): its row locked
// after the device's, its remote.open delivered only while it awaits it, the
// agent's result of it applied; the configuration follows the agent's version.
// An agent below legacy_agent_min_version_code gets 426 agentTooOld with the
// same body, whose commands are agent.update and inventory.refresh only.
// =============================================================================

const TOO_OLD_TYPES = ['agent.update', 'inventory.refresh'] as const;

async function applyEvents(trx: Knex.Transaction, who: AgentIdentity, body: PollBody, sat: Satellite): Promise<void> {
  const ctx = await audit.fromDbActor(LEGACY_AGENT_ACTOR, who.tenantId);
  const target = { type: 'device', id: String(who.deviceId), device: who.deviceId };
  const disabled = body.events.some((e) => e.type === 'admin_disabled' || e.type === 'admin_disable_requested')
    || (sat.admin_active === true && body.status.adminActive === false);
  if (disabled) {
    await audit.appendInTx(trx, {
      tenantId: who.tenantId, action: 'legacy_agent.admin_disabled', target,
      details: { events: body.events.filter((e) => e.type.startsWith('admin_')).map((e) => e.type).slice(0, 5), adminActive: body.status.adminActive },
    }, ctx, { onFailure: 'spool' });
    if (!body.status.adminActive) {
      await raiseInTx(trx, who.tenantId, 'legacy_agent.admin_disabled', { discriminant: who.deviceId, navigateTo: `/legacy-agent?device=${who.deviceId}` });
    }
  }
  if (body.status.adminActive && sat.admin_active === false) {
    await resolveInTx(trx, who.tenantId, 'legacy_agent.admin_disabled', who.deviceId);
  }
  if (body.status.knoxState === 'license_error' && sat.knox_state !== 'license_error') {
    await raiseInTx(trx, who.tenantId, 'legacy_agent.license_error', { discriminant: who.deviceId, navigateTo: `/legacy-agent?device=${who.deviceId}` });
  } else if (body.status.knoxState === 'licensed' && sat.knox_state === 'license_error') {
    await resolveInTx(trx, who.tenantId, 'legacy_agent.license_error', who.deviceId);
  }
}

export async function handlePoll(who: AgentIdentity, ex: Exchange, raw: Buffer): Promise<Reply> {
  let json: unknown;
  try { json = JSON.parse(raw.toString('utf8')); } catch { return errorReply(400, 'badRequest', 'Malformed JSON'); }
  const parsed = PollBody.safeParse(json);
  if (!parsed.success) return errorReply(400, 'badRequest', `Invalid body: ${parsed.error.issues[0]?.path.join('.') ?? ''}`.slice(0, 200));
  const body = parsed.data;
  const settings = await instanceSettings();
  // The remote session of the device (P0-15 §4.3): its remote.open delivered (awaiting /accept), its result applied;
  // the effects (console events, metrics) once the transaction committed.
  const remote = legacyAgentRemote()?.batch(who) ?? null;

  const reply = await withAgentTransaction(who, ex, async (trx, sat) => {
    const now = new Date();
    const serverTime = Math.floor(now.getTime() / 1000);
    const pollSeconds = sat.poll_seconds ?? settings.pollSeconds;
    const s = body.status;

    // 1. The state.
    await trx('legacy_agent_devices').where({ tenant_id: who.tenantId, device_id: who.deviceId }).update({
      last_poll_at: now, clock_offset_s: Math.max(-2_000_000_000, Math.min(2_000_000_000, serverTime - ex.ts)),
      admin_active: s.adminActive, knox_state: s.knoxState, agent_version_code: body.agent.versionCode, updated_at: now,
    });
    await trx('devices').where({ tenant_id: who.tenantId, id: who.deviceId }).update({ last_checkin_at: now, updated_at: now });
    await writeStatusItems(trx, who.tenantId, who.deviceId, now, {
      'agent.battery.level': s.batteryLevel ?? null,
      'agent.battery.charging': s.charging ?? null,
      'agent.storage.free': s.storageFreeBytes ?? null,
      'agent.network.type': s.network?.type ?? null,
      'agent.network.ip': s.network?.ip ?? null,
      'agent.admin.active': s.adminActive,
      'agent.knox.state': s.knoxState,
      // P0-15 §8: the measured capability of the control (agent 1.1.0 and later), only when the agent tells it.
      ...(typeof s.remoteInject === 'boolean' ? { [REMOTE_LEGACY_INJECT_ITEM]: s.remoteInject } : {}),
    });
    await remote?.lock(trx);

    // 2. The results, then the events.
    const results = await applyResults(trx, who.tenantId, who.deviceId, body.results.map((r) => ({ ...r, detail: r.detail as Record<string, unknown> | undefined })));
    if (remote) for (const r of results.applied_rows) if (r.type === REMOTE_OPEN) await remote.resulted(trx, { commandId: r.id, status: r.status, code: r.code });
    await acknowledgeUpdates(trx, who.tenantId, who.deviceId, body.agent.versionCode);
    await applyEvents(trx, who, body, sat);

    // 3. The commands.
    const tooOld = settings.minVersionCode > 0 && body.agent.versionCode < settings.minVersionCode;
    const frozen = await tenantFrozen(trx, who.tenantId);
    const commands = await deliver(trx, who.tenantId, who.deviceId, {
      pollSeconds, frozen, ...(tooOld ? { onlyTypes: TOO_OLD_TYPES } : {}),
      ...(remote ? { admitRemote: (ids: string[]) => remote.delivering(trx, ids) } : {}),
    });
    const inventoryDue = !sat.last_inventory_at || sat.inventory_requested_at !== null
      || now.getTime() - new Date(sat.last_inventory_at).getTime() > settings.inventorySeconds * 1000;
    const config = await agentConfigFor(trx, who.tenantId, { deviceId: who.deviceId, versionCode: body.agent.versionCode });
    const out = {
      serverTime, pollSeconds, resultsAccepted: results.accepted, inventoryDue, commands,
      config: body.agent.configVersion === config.version ? null : config,
    };
    if (tooOld) return { status: 426, body: { success: false, error: 'This version of the agent is too old: update it', code: 'agentTooOld', ...out } };
    return { status: 200, body: out };
  });
  await remote?.flush();
  return reply;
}

import { audit } from '../audit';
import { db } from '../db';
import { asNone, currentDbContext, type DbActor } from '../db/context';
import { withTenantTransaction } from '../db/tenantContext';
import { guardReviewerPolicy } from '../guard/approvals';
import { registerFreezeHandler } from '../guard/catalog';
import { registerLegacyAgentMinuteStep } from '../legacyAgent/jobs';
import { registerLegacyAgentRemote } from '../legacyAgent/remoteBridge';
import { registerBootTask, registerStopTask, registerUpgradeHandler } from '../lifecycle';
import { registerMetricsCollector } from '../ops/metrics';
import { registerApprovalRequestType } from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { onSessionsKilled } from '../services/userSessions.service';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';
import {
  REMOTE_SESSION_REQUEST_TYPE, REMOTE_SETTINGS_REQUEST_TYPE, executeRemoteSession, executeRemoteSettingsChange, onRemoteSessionApprovalClosed,
} from '../remote/approvals';
import { legacyAgentRemoteBridge } from '../remote/agentSurface';
import { registerRemoteAuditActions } from '../remote/audit';
import { registerRemoteChannel } from '../remote/channels';
import { legacyAgentRemoteChannel, setLegacyAgentWakeHook, setRemoteControlSink } from '../remote/channels/legacyAgent';
import { remoteMetrics } from '../remote/metrics';
import {
  closeTunnel, endTunnelsOfConsoleSessions, endTunnelsOfUser, relayControlSink, relayStats, stopRelay, tunnelCounters,
} from '../remote/relay';
import { RemoteEffects, endSession, flushRemoteEffects, onRemoteSessionEnded, setRemoteCountersSource, type SessionRow } from '../remote/sessions';
import { closeOrphanedAtBoot, sweepRemoteSessions } from '../remote/sweep';
import { agentUpgrade, viewerUpgrade } from '../remote/upgrade';
import { releaseAllWaits, wakeDevice } from '../remote/wake';

// =============================================================================
// REMOTE ASSISTANCE (P0-15): its hooks into the core's registries, registered here and only here; index.ts calls
// registerRemoteModule() right after registerLegacyAgentModule() (its first channel), before anything starts. No I/O
// but the boot task. The console routes are mounted by routes/index.ts (/api/remote-sessions); the retention of the
// journal (remote_sessions_months) by modules/privacy.ts (remote/retention.ts, T1).
//   audit            remote/audit.ts
//   restrictions     remote.view and remote.control: floor 'sensitive' and strict step-up, never lowered by the matrix
//                    (§0.1 rule 3: the technician strongly authenticated at each opening and each move to the control;
//                    the matrix may raise them to 'restricted', an approval); remote.settings_change ('restricted'
//                    floor)
//   approvals        remote_session (30 min), remote_settings_change: the guard's examination policy, strict step-up
//   freeze           the open sessions of a frozen tenant end (freeze)
//   channel          legacy_agent (remote/channels/legacyAgent.ts), and its agent's side: the queue, /accept, /end,
//                    /wait, config.remote, the menu of a device (remote/agentSurface.ts, remote/wake.ts), the long
//                    waits answered at the stop
//   relay            remote/relay.ts and its two upgrades (remote/upgrade.ts: the viewer's tunnel, the agent's
//                    stream), the control messages of the state machine, its counters written with each end, the
//                    tunnel closed at each end of its session, the revocation of a console session or of its user
//                    (onSessionsKilled: forUser, forSessions; userSessions.service.ts unchanged), the relayed sessions
//                    ended at the stop (server_restart)
//   deadlines        a step of the minute job legacy-agent.commands-expire (C5), the orphans at boot
//   metrics          the collector 'remote'
// =============================================================================

/** The restrictable actions of the remote assistance (§4.6, §0.1 rules 3 and 4). */
export const REMOTE_RESTRICTABLE_ACTIONS = [
  { key: 'remote.view', label: 'See the screen of a device (remote assistance)', category: 'Remote assistance' },
  { key: 'remote.control', label: 'Take control of a device (remote assistance)', category: 'Remote assistance' },
  { key: 'remote.settings_change', label: 'Change the remote assistance settings', category: 'Remote assistance' },
] as const;

const METRICS_ACTOR = { type: 'job', name: 'ops.metrics' } as const;
const METRICS_CACHE_MS = 60_000;
const ORPHANS_TASK = 'remote.orphans';
const WAITS_TASK = 'remote.waits';
const RELAY_TASK = 'remote.relay';

let registered = false;

export function registerRemoteModule(): void {
  if (registered) return;
  registered = true;

  registerRemoteAuditActions();
  registerRestrictableActions(REMOTE_RESTRICTABLE_ACTIONS, {}, {
    'remote.view': { level: 'sensitive', strictStepUp: true },
    'remote.control': { level: 'sensitive', strictStepUp: true },
    'remote.settings_change': { level: 'restricted' },
  });
  registerApprovalRequestType(REMOTE_SESSION_REQUEST_TYPE, executeRemoteSession, {
    expiryMinutes: 30, reviewerPolicy: guardReviewerPolicy, reviewerStepUp: 'strict', onClosed: onRemoteSessionApprovalClosed,
  });
  registerApprovalRequestType(REMOTE_SETTINGS_REQUEST_TYPE, executeRemoteSettingsChange, {
    expiryMinutes: 240, reviewerPolicy: guardReviewerPolicy, reviewerStepUp: 'strict',
  });

  registerRemoteChannel('legacy_agent', legacyAgentRemoteChannel);

  // The bridge agent's side (T4): /poll (delivery, results), /accept, /end, /wait, config.remote, the menu of a device;
  // its long waits woken by a session, a lock or an erase, answered at the stop of the server.
  registerLegacyAgentRemote(legacyAgentRemoteBridge);
  setLegacyAgentWakeHook(wakeDevice);
  registerStopTask(WAITS_TASK, () => {
    const n = releaseAllWaits();
    if (n > 0) logger.info({ waits: n }, 'remote: long waits of the agents answered at the stop');
  });

  // The relay (T5): its ends upgraded before Socket.io, the frames mode of the state machine, its counters, the tunnel
  // of each ended session closed, the revoked console sessions and users, the relayed sessions ended at the stop.
  registerUpgradeHandler('remote.viewer', viewerUpgrade);
  registerUpgradeHandler('remote.agent', agentUpgrade);
  setRemoteControlSink(relayControlSink);
  setRemoteCountersSource(tunnelCounters);
  onRemoteSessionEnded('relay', (e) => closeTunnel(e.sessionId, e.reason));
  onSessionsKilled({
    name: 'remote', label: 'remote sessions',
    forUser: (userId, reason) => endTunnelsOfUser(userId, reason),
    forSessions: (hashes, reason) => endTunnelsOfConsoleSessions(hashes, reason),
  });
  remoteMetrics.attachedFrom(() => { const s = relayStats(); return { agent: s.agent, viewer: s.viewer }; });
  registerStopTask(RELAY_TASK, async () => {
    const n = await stopRelay();
    if (n > 0) logger.info({ sessions: n }, 'remote: relayed sessions ended at the stop');
  });

  // A freeze ends every open session of the tenant (freeze); an unfreeze reopens nothing.
  registerFreezeHandler('remote', async (tenantId, frozen) => {
    if (!frozen) return 'nothing';
    const actor: DbActor = currentDbContext()?.actor ?? { type: 'job', name: 'actions.edge-freeze-sync' };
    const auditCtx = actor.type === 'user' ? await audit.fromDbActor(actor, tenantId) : audit.fromJob({ name: 'actions.edge-freeze-sync', requestId: 'freeze' });
    const fx = new RemoteEffects();
    const n = await withTenantTransaction(tenantId, actor, async (trx) => {
      const rows = await trx('remote_sessions').where({ tenant_id: tenantId }).whereNull('ended_at').forUpdate().select('*') as SessionRow[];
      for (const r of rows) await endSession(trx, fx, r, { reason: 'freeze', by: 'system', auditCtx });
      return rows.length;
    });
    await flushRemoteEffects(fx, actor, auditCtx);
    return n > 0 ? 'done' : 'nothing';
  });

  // The deadlines, every minute, in the bridge agent's minute job (no new minute job, C5).
  registerLegacyAgentMinuteStep('remote.sweep', async (ctx) => {
    const actor = ctx.dbActor.type === 'job' ? ctx.dbActor : { type: 'job' as const, name: 'legacy-agent.commands-expire' };
    return sweepRemoteSessions(actor, ctx.requestId, ctx.signal);
  });

  // The live and connecting sessions of before a restart: ended server_restart (the relay pairs in memory).
  registerBootTask(ORPHANS_TASK, async () => {
    try {
      const n = await closeOrphanedAtBoot({ type: 'job', name: ORPHANS_TASK });
      if (n > 0) logger.info({ closed: n }, 'remote: sessions orphaned by the restart closed');
    } catch (err) {
      logger.error({ err: safeErr(err) }, 'remote: orphaned sessions not closed at start');
    }
  });

  registerMetricsCollector('remote', async () => {
    const r = await asNone(METRICS_ACTOR, () => db.raw('SELECT state, sessions FROM obligarth.remote_sessions_open_summary()')) as
      { rows: Array<{ state: string; sessions: string | number }> };
    return remoteMetrics.families(r.rows.map((x) => ({ state: String(x.state), sessions: Number(x.sessions) || 0 })));
  }, { cacheMs: METRICS_CACHE_MS });
}

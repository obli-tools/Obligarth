import { audit } from '../audit';
import { db } from '../db';
import { asNone, type DbActor } from '../db/context';
import { allTenantIds, withTenantTransaction } from '../db/tenantContext';
import { safeErr } from '../jobs/errors';
import { logger } from '../utils/logger';
import { RemoteEffects, closeOrphanedOfTenant, flushRemoteEffects, sweepTenant } from './sessions';

// =============================================================================
// The deadlines of the remote assistance sessions (P0-15 §4.1 sweep.ts): run every minute by the existing minute job
// of the bridge agent (legacy-agent.commands-expire, registerLegacyAgentMinuteStep: no new minute job, C5) and at each
// transition (sessions.ts endIfDue). The tenants holding a session past a deadline are read once
// (obligarth.remote_sessions_due_tenants: ids only), so an instance without such a session costs one statement a
// minute; each tenant then in its own transaction. At the start (boot task remote.orphans), the live and connecting
// sessions of before the restart are ended server_restart (the relay pairs in memory).
// =============================================================================

/** The tenants with an open session past a deadline (context none of a platform job). */
async function dueTenants(): Promise<number[]> {
  const r = await db.raw('SELECT obligarth.remote_sessions_due_tenants() AS ids') as { rows: Array<{ ids: number[] | null }> };
  return (r.rows[0]?.ids ?? []).map(Number);
}

/** One run of the sweep, as the job `actor` (its context none): ends the sessions past their deadline. */
export async function sweepRemoteSessions(actor: DbActor & { type: 'job' }, requestId: string, signal?: AbortSignal):
  Promise<{ remoteEnded: number; remoteFailed: number }> {
  const out = { remoteEnded: 0, remoteFailed: 0 };
  const tenants = await asNone(actor, dueTenants);
  for (const tenantId of tenants) {
    if (signal?.aborted) break;
    const fx = new RemoteEffects();
    const auditCtx = audit.fromJob({ name: actor.name, requestId });
    try {
      const r = await withTenantTransaction(tenantId, actor, (trx) => sweepTenant(trx, fx, tenantId, auditCtx));
      out.remoteEnded += r.ended;
    } catch (err) {
      out.remoteFailed++;
      logger.warn({ err: safeErr(err), tenantId }, 'remote: sweep of a tenant failed');
    }
    await flushRemoteEffects(fx, actor, auditCtx);
  }
  return out;
}

/** The sessions a restart orphaned (boot task remote.orphans, context none of j:remote.orphans). */
export async function closeOrphanedAtBoot(actor: DbActor & { type: 'job' }): Promise<number> {
  const summary = await db.raw('SELECT state, sessions FROM obligarth.remote_sessions_open_summary()') as
    { rows: Array<{ state: string; sessions: string | number }> };
  if (!summary.rows.some((r) => (r.state === 'live' || r.state === 'connecting') && Number(r.sessions) > 0)) return 0;
  let closed = 0;
  for (const tenantId of await allTenantIds()) {
    const fx = new RemoteEffects();
    const auditCtx = audit.fromJob({ name: actor.name, requestId: 'boot' });
    try {
      closed += await withTenantTransaction(tenantId, actor, (trx) => closeOrphanedOfTenant(trx, fx, tenantId, auditCtx));
    } catch (err) {
      logger.warn({ err: safeErr(err), tenantId }, 'remote: orphaned sessions of a tenant not closed');
    }
    await flushRemoteEffects(fx, actor, auditCtx);
  }
  return closed;
}

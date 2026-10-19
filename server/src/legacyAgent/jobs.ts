import { z } from 'zod';
import { db } from '../db';
import { forEachTenant } from '../db/tenantContext';
import { JobError, registerJob, type JobContext, type JobResult } from '../jobs';
import { raiseInTx, resolveInTx } from '../apple/alerts/service';
import { expireDue } from './commands';

// =============================================================================
// Jobs of the bridge agent (docs: agent-pont-android §6):
//   legacy-agent.commands-expire  every minute: the open commands past their
//                                 lifetime become 'expired'
//   legacy-agent.silence-check    every hour: per tenant, the agents enrolled
//                                 and not revoked that have not interrogated
//                                 for 24 hours (alert legacy_agent.silent,
//                                 resolved when none is left)
// The packages-gc and retention jobs are v1 (§15.4).
// =============================================================================

async function expireCommands(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let expired = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const any = await db('legacy_agent_commands').where({ tenant_id: tenantId }).whereIn('state', ['pending', 'sent'])
      .where('expires_at', '<=', new Date()).first('id');
    if (!any) return;
    expired += await db.transaction((trx) => expireDue(trx, tenantId));
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { expired } };
}

async function silenceCheck(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let silent = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const cutoff = new Date(Date.now() - 24 * 3_600_000);
    const row = await db('legacy_agent_devices as a')
      .join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .where('a.tenant_id', tenantId).whereNull('a.revoked_at').where('d.enrollment_state', 'enrolled')
      .where((w) => w.whereNull('a.last_poll_at').orWhere('a.last_poll_at', '<', cutoff))
      .count<{ n: string }[]>('a.device_id as n').first();
    const n = Number(row?.n ?? 0);
    silent += n;
    await db.transaction(async (trx) => {
      if (n > 0) await raiseInTx(trx, tenantId, 'legacy_agent.silent', { params: { count: n }, navigateTo: '/legacy-agent' });
      else await resolveInTx(trx, tenantId, 'legacy_agent.silent');
    });
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { silent } };
}

let registered = false;

export function registerLegacyAgentJobs(): void {
  if (registered) return;
  registered = true;
  registerJob({
    name: 'legacy-agent.commands-expire',
    scope: 'platform',
    description: 'Every minute: the Android agent commands past their lifetime expire',
    payload: z.object({}).strict(),
    policy: 'exclusive',
    schedule: { cron: '* * * * *' },
    retry: { limit: 0, delaySeconds: 0, backoff: false },
    timeoutSeconds: 50,
    pollSeconds: 60,
    deadLetter: false, trackStatus: 'queue', manualRun: true, keepFinishedSeconds: 86_400, keepPendingSeconds: 3_600,
    handler: expireCommands,
  });
  registerJob({
    name: 'legacy-agent.silence-check',
    scope: 'platform',
    description: 'Every hour: alert on the Android agents silent for 24 hours, per tenant',
    payload: z.object({}).strict(),
    policy: 'exclusive',
    schedule: { cron: '17 * * * *' },
    retry: { limit: 1, delaySeconds: 120, backoff: false },
    timeoutSeconds: 600,
    pollSeconds: 300,
    deadLetter: false, trackStatus: 'queue', manualRun: true, keepFinishedSeconds: 172_800, keepPendingSeconds: 86_400,
    handler: silenceCheck,
  });
}

import { z } from 'zod';
import { config } from '../../config';
import { db } from '../../db';
import { forEachTenant } from '../../db/tenantContext';
import { JobError, registerJob, type JobContext, type JobResult } from '../../jobs';
import { realtime } from '../realtime';
import { CERTIFIED_GRACE_MS } from '../../mdm/registry/authenticateRules';
import { endSession } from './flow';

// =============================================================================
// enrollment.sessions-expire (docs: integration-apple-edge §10.3 step 5,
// annex B): every 5 minutes, the sessions not enrolled after their lifetime
// (one hour for OTA) expire and give the use of their link back. A session
// whose device got its identity (certificate_issued) is left one hour more:
// its Authenticate may still be waiting in the outbox (an expired session
// revived by an Authenticate that occurred before its expiry takes its use
// again, refused when the use served another device: devices/lifecycle.ts).
// Sessions that reached a device (authenticated) never expire here.
// =============================================================================

const EXPIRABLE = ['started', 'acknowledged', 'profile_issued'] as const;
// The grace of a certified session is the one findSessionForAuthenticate honours (review of lot C1, INT-C1-R1).
const SLICE = 500;

async function expireSessions(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let expired = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const now = Date.now();
    const due = await db('enrollment_sessions').where({ tenant_id: tenantId })
      .where((q) => {
        q.where((a) => a.whereIn('state', EXPIRABLE as unknown as string[]).where('expires_at', '<=', new Date(now)))
          .orWhere((b) => b.where('state', 'certificate_issued').where('expires_at', '<=', new Date(now - CERTIFIED_GRACE_MS)));
      })
      .orderBy('expires_at').limit(SLICE).pluck('id') as string[];
    if (!due.length) return;
    const ended: string[] = [];
    await db.transaction(async (trx) => {
      for (const id of due) {
        if (await endSession(trx, tenantId, id, 'expired', null, [...EXPIRABLE, 'certificate_issued'])) ended.push(id);
      }
    });
    expired += ended.length;
    if (ended.length) realtime.sessionChanged(tenantId, ...ended);
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { expired } };
}

let registered = false;

export function registerEnrollmentJobs(): void {
  if (registered) return;
  registered = true;
  registerJob({
    name: 'enrollment.sessions-expire',
    scope: 'platform',
    description: 'Every 5 minutes: the enrollment sessions not enrolled in time expire and give their link\'s use back',
    payload: z.object({}).strict(),
    policy: 'exclusive',
    // APPLE_EDGE_MODE=off: no session is opened (the device surface answers 404), the sweep is not scheduled.
    ...(config.apple.mode === 'on' ? { schedule: { cron: '*/5 * * * *' } } : {}),
    retry: { limit: 0, delaySeconds: 0, backoff: false },
    timeoutSeconds: 240,
    pollSeconds: 120,
    deadLetter: false, trackStatus: 'queue', manualRun: true, keepFinishedSeconds: 172_800, keepPendingSeconds: 86_400,
    handler: expireSessions,
  });
}

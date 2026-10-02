import { z } from 'zod';
import { config } from '../../config';
import { raiseJobAlert } from '../alerts';
import { registerJob } from '../index';
import type { JobContext, JobResult } from '../types';
import { registerOutboxApprovals } from './admin.routes';
import { outboxConsumer } from './consumer';
import { deadLettersSince, outboxLag, purgeDeadLetters } from './deadLetters';
import { outboxMetrics } from './metrics';

// =============================================================================
// Jobs of the outbox (docs: file-durable §7.8, §8.4, annex B):
//   apple-edge.outbox-monitor       * * * * *, exclusive, no retry: lag, new
//                                   dead letters, consumer degraded; alerts
//                                   outbox:lag, outbox:dead-letters,
//                                   outbox:consumer-degraded (master tenant);
//                                   nothing while apple_edge.outbox is absent,
//                                   but the lag alert also fires when the
//                                   table exists and the consumer is off;
//                                   not scheduled when OUTBOX_CONSUMER and
//                                   APPLE_EDGE_MODE are both off (no event
//                                   written nor read: file-durable L3);
//   apple-edge.dead-letters-purge   55 3 * * *: dead letters past
//                                   OUTBOX_DEAD_LETTER_RETENTION_DAYS.
// And the approval executor of the outbox administration ('outbox_manage').
// index.ts calls registerOutboxJobs() with the other modules, before the start.
// =============================================================================

const empty = z.object({}).strict();
/** A consumer degraded for longer than this raises outbox:consumer-degraded. */
const DEGRADED_ALERT_MS = 5 * 60_000;

/** Start of the previous check of this process (new dead letters since). */
let previousCheckAt: Date | null = null;

async function monitor(ctx: JobContext<unknown>): Promise<JobResult> {
  const startedAt = new Date();
  const lag = await outboxLag(ctx.dbActor);
  if (!lag.table) {
    previousCheckAt = startedAt;
    return { output: { table: false } };
  }
  outboxMetrics.lag(lag);
  if (lag.oldestPendingSeconds !== null && lag.oldestPendingSeconds > config.outbox.lagAlertSeconds) {
    const consumer = outboxConsumer.status().state;
    await raiseJobAlert(ctx.dbActor, {
      stableKey: 'outbox:lag',
      severity: 'critical',
      title: 'apple-edge events waiting',
      message: `The oldest event of apple-edge not consumed is ${lag.oldestPendingSeconds} s old (${lag.pending} waiting; consumer ${consumer}).`,
    });
  }
  const since = previousCheckAt ?? new Date(startedAt.getTime() - 2 * 60_000);
  previousCheckAt = startedAt;
  const fresh = await deadLettersSince(since, ctx.dbActor);
  if (fresh > 0) {
    await raiseJobAlert(ctx.dbActor, {
      stableKey: 'outbox:dead-letters',
      severity: 'warning',
      title: 'apple-edge events moved to the dead letters',
      message: `${fresh} new dead letter(s) of the outbox: see the outbox administration API.`,
    });
  }
  const st = outboxConsumer.status();
  if (st.state === 'degraded' && st.degradedSince !== null && Date.now() - st.degradedSince > DEGRADED_ALERT_MS) {
    await raiseJobAlert(ctx.dbActor, {
      stableKey: 'outbox:consumer-degraded',
      severity: 'critical',
      title: 'apple-edge event consumer failing',
      message: `The outbox consumer has failed its batches for ${Math.round((Date.now() - st.degradedSince) / 60_000)} min.`,
    });
  }
  return { output: { pending: lag.pending, retrying: lag.retrying, oldestPendingSeconds: lag.oldestPendingSeconds, newDeadLetters: fresh } };
}

let registered = false;

export function registerOutboxJobs(): void {
  if (registered) return;
  registered = true;
  registerOutboxApprovals();

  registerJob({
    name: 'apple-edge.outbox-monitor',
    scope: 'platform',
    description: 'Lag of the apple-edge outbox, new dead letters, consumer state: alerts of the master tenant',
    payload: empty,
    // Nothing to watch with OUTBOX_CONSUMER=off and APPLE_EDGE_MODE=off (no event written, none read)
    ...(config.outbox.consumer !== 'off' || config.apple.mode === 'on' ? { schedule: { cron: '* * * * *' } } : {}),
    notify: true,
    pollSeconds: 30,
    retry: { limit: 0 },
    timeoutSeconds: 60,
    handler: monitor,
  });

  registerJob({
    name: 'apple-edge.dead-letters-purge',
    scope: 'platform',
    description: 'Delete the outbox dead letters older than OUTBOX_DEAD_LETTER_RETENTION_DAYS',
    payload: empty,
    schedule: { cron: '55 3 * * *' },
    pollSeconds: 60,
    timeoutSeconds: 300,
    handler: async (ctx) => ({ output: { deleted: await purgeDeadLetters(config.outbox.deadLetterRetentionDays, ctx.signal) } }),
  });
}

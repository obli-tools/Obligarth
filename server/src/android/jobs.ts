// Durable jobs of the Android integration (section 22.7, AN39), registered only when ANDROID_MODE is not off (an
// instance without Android adds no queue and no statement at rest): no batching window (pattern M5: stately, woken by
// NOTIFY), per-tenant sweeps folded into the platform job android.maintenance.
import { z } from 'zod';
import { registerJob } from '../jobs';
import { setupEnterprise, checkTestMessage, setTestCheckSender } from './enterprises/setup';
import { setSetupSender } from './enterprises/signup';
import { drainTenantInbox } from './inbox/drain';
import { setDrainSender } from './link/pull';
import { runAndroidMaintenance, setMaintenanceDrainWaker } from './maintenance';

const tenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();

let registered = false;
let bind: (() => void) | null = null;

/** (Re)binds the senders of the pull loop, the signup, the setup and the maintenance to the durable jobs. */
export function bindAndroidSenders(): void {
  bind?.();
}

export function registerAndroidJobs(): void {
  if (registered) return;
  registered = true;

  const drain = registerJob({
    name: 'android.inbox-drain',
    scope: 'tenant',
    description: 'Applies the Android notifications of a tenant (inbox)',
    payload: tenantPayload,
    policy: 'stately',
    notify: true,
    retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) {
      const r = await drainTenantInbox(ctx.payload.tenantId, { requestId: ctx.requestId });
      if (r.remaining) await drain.send({ tenantId: ctx.payload.tenantId }, { singletonKey: `t:${ctx.payload.tenantId}`, tenantId: ctx.payload.tenantId });
      return { output: { applied: r.applied, skipped: r.skipped, retried: r.retried, dead: r.dead } };
    },
  });

  const setup = registerJob({
    name: 'android.enterprise-setup',
    scope: 'tenant',
    description: 'Sets the Pub/Sub topic, the display name and the default policy of an Android enterprise',
    payload: tenantPayload,
    policy: 'stately',
    notify: true,
    async handler(ctx) {
      const r = await setupEnterprise(ctx.payload.tenantId);
      return { output: { result: r } };
    },
  });

  const testCheck = registerJob({
    name: 'android.pubsub-test-check',
    scope: 'tenant',
    description: 'Checks that the Pub/Sub test message arrived after the topic was set',
    payload: tenantPayload,
    policy: 'stately',
    async handler(ctx) {
      return { output: { result: await checkTestMessage(ctx.payload.tenantId) } };
    },
  });
  bind = () => {
    setDrainSender((trx, tenantId) => drain.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    setMaintenanceDrainWaker((tenantId) => drain.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    setSetupSender((trx, tenantId) => setup.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    setTestCheckSender((trx, tenantId) => testCheck.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId, startAfter: 900 }));
  };
  bind();

  registerJob({
    name: 'android.maintenance',
    scope: 'platform',
    description: 'Android sweeps: inbox retries, stale signups, purges, weekly check of the project enterprises',
    payload: z.object({}).strict(),
    policy: 'exclusive',
    schedule: { cron: '* * * * *' },
    async handler() {
      const r = await runAndroidMaintenance();
      return { output: { drains: r.drains, interrupted: r.interrupted, expired: r.expired, purged: r.purged, orphans: r.orphans } };
    },
  });
}

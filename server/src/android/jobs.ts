// Durable jobs of the Android integration (section 22.7, AN39), registered only when ANDROID_MODE is not off (an
// instance without Android adds no queue and no statement at rest): no batching window (pattern M5: stately, woken by
// NOTIFY), per-tenant sweeps folded into the platform job android.maintenance.
import { z } from 'zod';
import { registerJob } from '../jobs';
import { setupEnterprise, checkTestMessage, setTestCheckSender } from './enterprises/setup';
import { setSetupSender } from './enterprises/signup';
import { drainTenantInbox } from './inbox/drain';
import { setDrainSender } from './link/pull';
import { cleanupSupersededDevice, holdDevice, quarantineDevice, rejectDevice } from './enrollment/decisions';
import { setAndroidSenders } from './enrollment/senders';
import { recoverEnrollmentTokens } from './enrollment/tokens';
import { runAndroidMaintenance, setMaintenanceDrainWaker, setTokenRecoverySender } from './maintenance';
import { pushDevicePolicy, pushEnrollmentPolicy } from './policies/push';
import { setCommandSenders } from './commands/bus';
import { pollAndroidOperations, submitAndroidCommand } from './commands/submit';
import { setOperationsPollSender, setAppMetadataSender } from './maintenance';
import { refreshDueAndroidApps } from './apps/catalog';

const tenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();
const devicePayload = z.object({ tenantId: z.number().int().positive(), deviceId: z.number().int().positive() }).strict();
const quarantinePayload = z.object({ tenantId: z.number().int().positive(), quarantineId: z.number().int().positive() }).strict();
const profilePayload = z.object({ tenantId: z.number().int().positive(), profileId: z.string().uuid() }).strict();
const commandPayload = z.object({ tenantId: z.number().int().positive(), commandId: z.string().uuid() }).strict();

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
  // ── Enrollment, policies (lot AN-C1b, section 22.7) ─────────────────────────
  const devKey = (p: { tenantId: number; deviceId: number }) => `t:${p.tenantId}:d:${p.deviceId}`;
  const onboard = registerJob({
    name: 'android.device-onboard', scope: 'tenant', description: 'First push of the own policy of an enrolled Android device',
    payload: devicePayload, policy: 'stately', notify: true, retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) { return { output: { result: await pushDevicePolicy(ctx.payload.tenantId, ctx.payload.deviceId) } }; },
  });
  const push = registerJob({
    name: 'android.policies.push-device', scope: 'tenant', description: 'Pushes the own policy of an Android device',
    payload: devicePayload, policy: 'stately', notify: true, retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) { return { output: { result: await pushDevicePolicy(ctx.payload.tenantId, ctx.payload.deviceId) } }; },
  });
  const enrollmentPolicy = registerJob({
    name: 'android.policies.enrollment-policy', scope: 'tenant', description: 'Pushes the enrollment policy of an Android profile',
    payload: profilePayload, policy: 'stately', notify: true, retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) { return { output: { result: await pushEnrollmentPolicy(ctx.payload.tenantId, ctx.payload.profileId) } }; },
  });
  const hold = registerJob({
    name: 'android.device-hold', scope: 'tenant', description: 'Disables an Android device waiting for its approval',
    payload: devicePayload, policy: 'stately', retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) { return { output: { result: await holdDevice(ctx.payload.tenantId, ctx.payload.deviceId) } }; },
  });
  const quarantine = registerJob({
    name: 'android.device-quarantine', scope: 'tenant', description: 'Disables an Android device not accepted at its enrollment',
    payload: quarantinePayload, policy: 'stately', retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) { return { output: { result: await quarantineDevice(ctx.payload.tenantId, ctx.payload.quarantineId) } }; },
  });
  const reject = registerJob({
    name: 'android.device-reject', scope: 'tenant', description: 'Deletes an Android device refused within the window of its enrollment',
    payload: quarantinePayload, policy: 'stately', redrivable: false, retry: { limit: 3, delaySeconds: 10, backoff: true, maxDelaySeconds: 120 },
    async handler(ctx) { return { output: { result: await rejectDevice(ctx.payload.tenantId, ctx.payload.quarantineId) } }; },
  });
  const cleanup = registerJob({
    name: 'android.device-cleanup', scope: 'tenant', description: 'Deletes the AMAPI resource a re-enrollment replaced',
    payload: devicePayload, policy: 'stately', redrivable: false, retry: { limit: 5, delaySeconds: 60, backoff: true, maxDelaySeconds: 3600 },
    async handler(ctx) { return { output: { result: await cleanupSupersededDevice(ctx.payload.tenantId, ctx.payload.deviceId) } }; },
  });
  const tokensRecover = registerJob({
    name: 'android.tokens-recover', scope: 'tenant', description: 'Recovers interrupted Android enrollment tokens and collects orphans',
    payload: tenantPayload, policy: 'stately',
    async handler(ctx) { return { output: { ...(await recoverEnrollmentTokens(ctx.payload.tenantId)) } }; },
  });
  const bindEnrollment = () => {
    setAndroidSenders({
      onboard: (trx, p) => onboard.sendInTx(trx, p, { singletonKey: devKey(p), tenantId: p.tenantId }),
      push: (trx, p) => push.sendInTx(trx, p, { singletonKey: devKey(p), tenantId: p.tenantId }),
      hold: (trx, p) => hold.sendInTx(trx, p, { singletonKey: devKey(p), tenantId: p.tenantId }),
      cleanup: (trx, p) => cleanup.sendInTx(trx, p, { singletonKey: devKey(p), tenantId: p.tenantId }),
      quarantine: (trx, p) => quarantine.sendInTx(trx, p, { singletonKey: `t:${p.tenantId}:q:${p.quarantineId}`, tenantId: p.tenantId }),
      reject: (trx, p) => reject.sendInTx(trx, p, { singletonKey: `t:${p.tenantId}:q:${p.quarantineId}`, tenantId: p.tenantId }),
      enrollmentPolicy: (trx, p) => enrollmentPolicy.sendInTx(trx, p, { singletonKey: `t:${p.tenantId}:p:${p.profileId}`, tenantId: p.tenantId }),
    });
    setTokenRecoverySender((tenantId) => tokensRecover.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
  };

  // ── Commands (lot AN-D1, section 11.3) ─────────────────────────────────────
  // One submission per command (stately t:<tenant>:c:<command>): never a blind retry of issueCommand, the AN50
  // recovery runs on every attempt after the first call; the polling of a tenant's operations (stately t:<tenant>).
  const submit = registerJob({
    name: 'android.commands.submit', scope: 'tenant', description: 'Submits an Android command to Google (AN50 recovery)',
    payload: commandPayload, policy: 'stately', notify: true, retry: { limit: 8, delaySeconds: 15, backoff: true, maxDelaySeconds: 900 },
    async handler(ctx) { return { output: { result: await submitAndroidCommand(ctx.payload.tenantId, ctx.payload.commandId) } }; },
  });
  const poll = registerJob({
    name: 'android.operations-poll', scope: 'tenant', description: 'Polls the Android operations sent and expires the commands past their end',
    payload: tenantPayload, policy: 'stately', retry: { limit: 3, delaySeconds: 30, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) { return { output: { ...(await pollAndroidOperations(ctx.payload.tenantId)) } }; },
  });
  const bindCommands = () => {
    setCommandSenders({ submit: (trx, p) => submit.sendInTx(trx, p, { singletonKey: `t:${p.tenantId}:c:${p.commandId}`, tenantId: p.tenantId }) });
    setOperationsPollSender((tenantId) => poll.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
  };

  // ── Apps (lot AN-E1, section 9.6) ───────────────────────────────────────────
  // The metadata of a tenant's Android apps, once a day at most per app (stately t:<tenant>), 50 apps a run.
  const appMetadata = registerJob({
    name: 'android.app-metadata', scope: 'tenant', description: 'Reads the metadata of the Android apps of a tenant at Google again',
    payload: tenantPayload, policy: 'stately', retry: { limit: 3, delaySeconds: 60, backoff: true, maxDelaySeconds: 3600 },
    async handler(ctx) {
      const r = await refreshDueAndroidApps(ctx.payload.tenantId);
      if (r.remaining) await appMetadata.send({ tenantId: ctx.payload.tenantId }, { singletonKey: `t:${ctx.payload.tenantId}`, tenantId: ctx.payload.tenantId });
      return { output: { refreshed: r.refreshed, unavailable: r.unavailable, failed: r.failed, remaining: r.remaining } };
    },
  });
  const bindApps = () => {
    setAppMetadataSender((tenantId) => appMetadata.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
  };

  bind = () => {
    setDrainSender((trx, tenantId) => drain.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    setMaintenanceDrainWaker((tenantId) => drain.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    setSetupSender((trx, tenantId) => setup.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    setTestCheckSender((trx, tenantId) => testCheck.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId, startAfter: 900 }));
    bindEnrollment();
    bindCommands();
    bindApps();
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
      return { output: { drains: r.drains, interrupted: r.interrupted, expired: r.expired, purged: r.purged, orphans: r.orphans, tokensExpired: r.tokensExpired, commands: r.commands, apps: r.apps } };
    },
  });
}

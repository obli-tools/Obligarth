// Durable jobs of the Android integration (section 22.7, AN39), registered only when ANDROID_MODE is not off (an
// instance without Android adds no queue and no statement at rest): no batching window (pattern M5: stately, woken by
// NOTIFY), per-tenant sweeps folded into the platform job android.maintenance.
// Lot AN-A2 (file-durable L3): ten queues. pg-boss supervises the queues of its table by chunks of 100 names, each
// chunk a monitor and a maintenance of its own at every pass; the 90 queues of the instance without Android plus these
// ten make one chunk (a second chunk costs about 0.5 statement a second at rest). The first push of a device and its
// later pushes share android.policies.push-device; the decisions of an enrollment (hold, quarantine, reject) and the cleanup of a replaced
// resource share android.device-decision; the tenant sweeps sent by the maintenance or by a delayed start (recovery of
// the tokens, metadata of the apps, check of the test message, end of the kiosk exits, polling of the operations)
// share android.tenant-sweep. Each keeps its own singleton key (its kind in front).
import { z } from 'zod';
import { registerJob } from '../jobs';
import type { JobResult } from '../jobs/types';
import { SCHEDULED_POLL_SECONDS } from '../jobs/registry';
import { setupEnterprise, checkTestMessage, setTestCheckSender } from './enterprises/setup';
import { setSetupSender } from './enterprises/signup';
import { drainTenantInbox } from './inbox/drain';
import { setDrainSender } from './link/pull';
import { cleanupSupersededDevice, holdDevice, quarantineDevice, rejectDevice } from './enrollment/decisions';
import { setAndroidSenders } from './enrollment/senders';
import { recoverEnrollmentTokens } from './enrollment/tokens';
import { runAndroidMaintenance, setMaintenanceDrainWaker, setTokenRecoverySender } from './maintenance';
import { pushDevicePolicy, pushEnrollmentPolicy } from './policies/push';
import { awaitsOnboarding } from './policies/channel';
import { runOnboardSteps } from '../mdm/registry/onboard';
import { db } from '../db';
import { setCommandSenders } from './commands/bus';
import { pollAndroidOperations, submitAndroidCommand } from './commands/submit';
import { setOperationsPollSender, setAppMetadataSender } from './maintenance';
import { refreshDueAndroidApps } from './apps/catalog';
import { expireKioskExits, setKioskExitEndSender } from './kiosk/exits';
import { setOffboardingSender, setReconcileSender } from './maintenance';
import { runOffboarding, setOffboardSender } from './operations/offboarding';
import { reconcileTenant } from './operations/reconcile';

const tenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();
const devicePayload = z.object({ tenantId: z.number().int().positive(), deviceId: z.number().int().positive() }).strict();
const profilePayload = z.object({ tenantId: z.number().int().positive(), profileId: z.string().uuid() }).strict();
const commandPayload = z.object({ tenantId: z.number().int().positive(), commandId: z.string().uuid() }).strict();
const DECISIONS = ['hold', 'quarantine', 'reject', 'cleanup'] as const;
const decisionPayload = z.object({
  kind: z.enum(DECISIONS), tenantId: z.number().int().positive(),
  deviceId: z.number().int().positive().optional(), quarantineId: z.number().int().positive().optional(),
}).strict();
const SWEEPS = ['tokens_recover', 'app_metadata', 'test_check', 'kiosk_exit_end', 'operations_poll'] as const;
const sweepPayload = z.object({ kind: z.enum(SWEEPS), tenantId: z.number().int().positive(), exitId: z.string().uuid().optional() }).strict();

/**
 * Polling of the queues (file-durable L3, lot AN-A2): every queue is woken by NOTIFY when a job is sent; the poll only
 * picks up the delayed starts and the retries, every 5 minutes (as the idle queues of the Apple integration). What
 * waits longer is sent again by android.maintenance every minute (inbox due, submissions lost, kiosk exits past their
 * end, operations to poll). Measured at rest in fake mode with three linked tenants (scripts/l3-android.mjs).
 */
const IDLE_POLL_SECONDS = 300;

let registered = false;
let bind: (() => void) | null = null;

/** (Re)binds the senders of the pull loop, the signup, the setup and the maintenance to the durable jobs. */
export function bindAndroidSenders(): void {
  bind?.();
}

/** The id a kind of job needs; a payload without it is refused (never run on a guess). */
function required<T>(v: T | undefined, what: string): T {
  if (v === undefined) throw new Error(`android job: ${what} missing`);
  return v;
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
    notify: true, pollSeconds: IDLE_POLL_SECONDS,
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
    notify: true, pollSeconds: IDLE_POLL_SECONDS,
    async handler(ctx) {
      const r = await setupEnterprise(ctx.payload.tenantId);
      return { output: { result: r } };
    },
  });

  // ── Tenant sweeps (lots AN-A1, AN-C1b, AN-D1, AN-E1, AN-G1): one queue, a kind each ───────────────────────────
  const sweep = registerJob({
    name: 'android.tenant-sweep', scope: 'tenant',
    description: 'Android sweeps of a tenant: tokens to recover, metadata of the apps, test message, kiosk exits past their end, operations to poll',
    payload: sweepPayload, policy: 'stately', notify: true, pollSeconds: IDLE_POLL_SECONDS,
    retry: { limit: 5, delaySeconds: 30, backoff: true, maxDelaySeconds: 1800 },
    async handler(ctx): Promise<JobResult> {
      const { kind, tenantId } = ctx.payload;
      switch (kind) {
        case 'tokens_recover':
          return { output: { kind, ...(await recoverEnrollmentTokens(tenantId)) } };
        case 'app_metadata': {
          const r = await refreshDueAndroidApps(tenantId);
          if (r.remaining) await sendSweep('app_metadata', tenantId);
          return { output: { kind, refreshed: r.refreshed, unavailable: r.unavailable, failed: r.failed, remaining: r.remaining } };
        }
        case 'test_check':
          return { output: { kind, result: await checkTestMessage(tenantId) } };
        case 'kiosk_exit_end':
          required(ctx.payload.exitId, 'exitId');
          return { output: { kind, ...(await expireKioskExits(tenantId)) } };
        case 'operations_poll':
          return { output: { kind, ...(await pollAndroidOperations(tenantId)) } };
        default:
          throw new Error('android.tenant-sweep: unknown kind');
      }
    },
  });
  const sendSweep = (kind: typeof SWEEPS[number], tenantId: number) =>
    sweep.send({ kind, tenantId }, { singletonKey: `${kind}:t:${tenantId}`, tenantId });

  // ── Enrollment, policies (lot AN-C1b, section 22.7) ─────────────────────────
  const devKey = (p: { tenantId: number; deviceId: number }) => `t:${p.tenantId}:d:${p.deviceId}`;
  // The first push of an enrolled device (onboarding) and every later push are the same job (pushDevicePolicy compiles,
  // pushes the own policy and, the first time, points the device at it): one queue, one singleton key per device. Until
  // the device is attached to its own policy, the onboarding steps of the channel amapi run first (registry by channel,
  // lot AN-P: the resolution of its policies), instead of a queue of their own.
  const push = registerJob({
    name: 'android.policies.push-device', scope: 'tenant', description: 'Pushes the own policy of an Android device',
    payload: devicePayload, policy: 'stately', notify: true, pollSeconds: IDLE_POLL_SECONDS, retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) {
      const { tenantId, deviceId } = ctx.payload;
      if (await ctx.inTenant(() => awaitsOnboarding(db, tenantId, deviceId))) await runOnboardSteps('amapi', { job: ctx, tenantId, deviceId });
      return { output: { result: await pushDevicePolicy(tenantId, deviceId) } };
    },
  });
  const enrollmentPolicy = registerJob({
    name: 'android.policies.enrollment-policy', scope: 'tenant', description: 'Pushes the enrollment policy of an Android profile',
    payload: profilePayload, policy: 'stately', notify: true, pollSeconds: IDLE_POLL_SECONDS, retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) { return { output: { result: await pushEnrollmentPolicy(ctx.payload.tenantId, ctx.payload.profileId) } }; },
  });
  // The decisions of an enrollment and the cleanup of a replaced resource (section 10.4): never redriven by hand
  // (a reject or a cleanup deletes a resource at Google; each checks its conditions again when it runs).
  const decision = registerJob({
    name: 'android.device-decision', scope: 'tenant',
    description: 'Decision on an Android device at its enrollment (hold, quarantine, reject) or deletion of the resource a re-enrollment replaced',
    payload: decisionPayload, policy: 'stately', notify: true, pollSeconds: IDLE_POLL_SECONDS, redrivable: false,
    retry: { limit: 5, delaySeconds: 10, backoff: true, maxDelaySeconds: 600 },
    async handler(ctx) {
      const { kind, tenantId } = ctx.payload;
      switch (kind) {
        case 'hold': return { output: { kind, result: await holdDevice(tenantId, required(ctx.payload.deviceId, 'deviceId')) } };
        case 'quarantine': return { output: { kind, result: await quarantineDevice(tenantId, required(ctx.payload.quarantineId, 'quarantineId')) } };
        case 'reject': return { output: { kind, result: await rejectDevice(tenantId, required(ctx.payload.quarantineId, 'quarantineId')) } };
        case 'cleanup': return { output: { kind, result: await cleanupSupersededDevice(tenantId, required(ctx.payload.deviceId, 'deviceId')) } };
        default: throw new Error('android.device-decision: unknown kind');
      }
    },
  });
  const bindEnrollment = () => {
    setAndroidSenders({
      onboard: (trx, p) => push.sendInTx(trx, p, { singletonKey: devKey(p), tenantId: p.tenantId }),
      push: (trx, p) => push.sendInTx(trx, p, { singletonKey: devKey(p), tenantId: p.tenantId }),
      hold: (trx, p) => decision.sendInTx(trx, { kind: 'hold', ...p }, { singletonKey: `hold:${devKey(p)}`, tenantId: p.tenantId }),
      cleanup: (trx, p) => decision.sendInTx(trx, { kind: 'cleanup', ...p }, { singletonKey: `cleanup:${devKey(p)}`, tenantId: p.tenantId }),
      quarantine: (trx, p) => decision.sendInTx(trx, { kind: 'quarantine', ...p },
        { singletonKey: `quarantine:t:${p.tenantId}:q:${p.quarantineId}`, tenantId: p.tenantId }),
      reject: (trx, p) => decision.sendInTx(trx, { kind: 'reject', ...p }, { singletonKey: `reject:t:${p.tenantId}:q:${p.quarantineId}`, tenantId: p.tenantId }),
      enrollmentPolicy: (trx, p) => enrollmentPolicy.sendInTx(trx, p, { singletonKey: `t:${p.tenantId}:p:${p.profileId}`, tenantId: p.tenantId }),
    });
    setTokenRecoverySender((tenantId) => sendSweep('tokens_recover', tenantId));
  };

  // ── Commands (lot AN-D1, section 11.3) ─────────────────────────────────────
  // One submission per command (stately t:<tenant>:c:<command>): never a blind retry of issueCommand, the AN50
  // recovery runs on every attempt after the first call; the polling of a tenant's operations (a tenant sweep).
  const submit = registerJob({
    name: 'android.commands.submit', scope: 'tenant', description: 'Submits an Android command to Google (AN50 recovery)',
    payload: commandPayload, policy: 'stately', notify: true, pollSeconds: IDLE_POLL_SECONDS, retry: { limit: 8, delaySeconds: 15, backoff: true, maxDelaySeconds: 900 },
    async handler(ctx) { return { output: { result: await submitAndroidCommand(ctx.payload.tenantId, ctx.payload.commandId) } }; },
  });
  const bindCommands = () => {
    setCommandSenders({ submit: (trx, p) => submit.sendInTx(trx, p, { singletonKey: `t:${p.tenantId}:c:${p.commandId}`, tenantId: p.tenantId }) });
    setOperationsPollSender((tenantId) => sendSweep('operations_poll', tenantId));
  };

  // ── Apps (lot AN-E1, section 9.6) ───────────────────────────────────────────
  // The metadata of a tenant's Android apps, once a day at most per app (a tenant sweep), 50 apps a run.
  const bindApps = () => {
    setAppMetadataSender((tenantId) => sendSweep('app_metadata', tenantId));
  };

  // ── Kiosk exits (lot AN-G1, section 9.7) ────────────────────────────────────
  // The end of a kiosk exit at its expiry (one job per exit, started at expires_at); android.maintenance ends the
  // exits whose job was lost.
  const bindKiosk = () => {
    setKioskExitEndSender((trx, p) => sweep.sendInTx(trx, { kind: 'kiosk_exit_end', tenantId: p.tenantId, exitId: p.exitId },
      { singletonKey: `kiosk:t:${p.tenantId}:k:${p.exitId}`, tenantId: p.tenantId, startAfter: p.expiresAt }));
  };

  // ── Operation (lot AN-H1, sections 6.5 and 13.1) ────────────────────────────
  // The reconciliation of a tenant (stately t:<tenant>: one at a time, never two passes of devices.list at once) and
  // the offboarding of a client (stately t:<tenant>; android.maintenance sends it again while a step waits).
  const reconcile = registerJob({
    name: 'android.reconcile-tenant', scope: 'tenant', description: 'Reconciles the Android devices of a tenant with Google (silent disappearances, quota)',
    payload: tenantPayload, policy: 'stately', notify: true, pollSeconds: IDLE_POLL_SECONDS, retry: { limit: 3, delaySeconds: 60, backoff: true, maxDelaySeconds: 1800 },
    async handler(ctx) {
      const r = await reconcileTenant(ctx.payload.tenantId);
      const output: Record<string, string | number> = typeof r === 'string' ? { result: r }
        : { listed: r.listed, missing: r.missing, presumedGone: r.presumedGone, forgotten: r.forgotten, unknown: r.unknown };
      return { output };
    },
  });
  const offboard = registerJob({
    name: 'android.offboard-tenant', scope: 'tenant', description: 'Offboards the Android enterprise of a tenant, step by step',
    payload: tenantPayload, policy: 'stately', notify: true, pollSeconds: IDLE_POLL_SECONDS, retry: { limit: 3, delaySeconds: 60, backoff: true, maxDelaySeconds: 900 },
    async handler(ctx) { return { output: { result: await runOffboarding(ctx.payload.tenantId) } }; },
  });
  const bindOperations = () => {
    setReconcileSender((tenantId) => reconcile.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    const sendOffboard = (tenantId: number) => offboard.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
    setOffboardingSender(sendOffboard);
    setOffboardSender(sendOffboard);
  };

  bind = () => {
    setDrainSender((trx, tenantId) => drain.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    setMaintenanceDrainWaker((tenantId) => drain.send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    setSetupSender((trx, tenantId) => setup.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId }));
    setTestCheckSender((trx, tenantId) => sweep.sendInTx(trx, { kind: 'test_check', tenantId },
      { singletonKey: `test_check:t:${tenantId}`, tenantId, startAfter: 900 }));
    bindEnrollment();
    bindCommands();
    bindApps();
    bindKiosk();
    bindOperations();
  };
  bind();

  registerJob({
    name: 'android.maintenance',
    scope: 'platform',
    description: 'Android sweeps: inbox retries, stale signups, purges, weekly check of the project enterprises',
    payload: z.object({}).strict(),
    policy: 'exclusive',
    schedule: { cron: '* * * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    async handler() {
      const r = await runAndroidMaintenance();
      return { output: { drains: r.drains, interrupted: r.interrupted, expired: r.expired, purged: r.purged, orphans: r.orphans, tokensExpired: r.tokensExpired, commands: r.commands, apps: r.apps, kiosk: r.kiosk,
        reconciles: r.reconciles, offboardings: r.offboardings, quota: r.quota, key: r.key } };
    },
  });
}

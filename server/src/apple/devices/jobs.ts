import { createHash, X509Certificate } from 'node:crypto';
import type { Knex } from 'knex';
import { z } from 'zod';
import { config } from '../../config';
import { jobIdFor, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { unenrollCleanup } from '../../mdm/registry/unenroll';
import { resolveInTx } from '../alerts/service';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import { realtime } from '../realtime';

// =============================================================================
// Follow-up jobs of the enrollment cycles (docs: integration-apple-edge §7.4,
// annex B; §8.9, §8.10, §13.3), sent by the outbox handlers in the event's
// savepoint (the job exists only if the event is consumed; its id or key
// makes a replay add none). Payloads: internal identifiers only.
//   apple.device-onboard       first TokenUpdate of a cycle (I3), id per event, 5 retries: the public identity
//                              certificate of the device (GET …/enrollments/{id}, outside any transaction:
//                              identity_cert_pem, used to encrypt the profiles that carry a secret, §8.8), then
//                              the onboarding steps the other lots register (registerOnboardStep: the initial
//                              inventory of the command queue, §8.10; the first DDM synchronisation, §9.4; the
//                              resolution of the policies, modele §10.4)
//   apple.await-configuration  TokenUpdate awaiting the configuration (ADE), stately d:<id>, 3 retries: the setup
//                              plan (running, deadline APPLE_SETUP_TIMEOUT_S), then the setup runner of the command
//                              queue (registerSetupRunner, §8.9: contributors, DeviceConfigured)
//   devices.unenroll-cleanup   a departure from management, id per departure, 5 retries: retention date, effective
//                              state and artifacts (modele §5.5), DDM set, status and inboxes of the device, setup
//                              plan, the device's alerts of an ongoing problem (§13.3)
// =============================================================================

const DevicePayload = z.object({ tenantId: z.number().int().positive(), deviceId: z.number().int().positive() }).strict();
type DeviceJob = z.infer<typeof DevicePayload>;

export interface OnboardStepContext {
  job: JobContext<DeviceJob>;
  tenantId: number;
  deviceId: number;
}
type OnboardStep = (ctx: OnboardStepContext) => Promise<void>;
type SetupRunner = (ctx: OnboardStepContext & { deadlineAt: Date }) => Promise<void>;

const onboardSteps: Array<{ name: string; fn: OnboardStep }> = [];
let setupRunner: SetupRunner | null = null;

/** A step of the onboarding of a device (after its identity certificate), run in registration order; registered
 *  before jobs.start() by the command queue (initial inventory), the DDM engine and the policies. A step that
 *  fails fails the job (retried): steps are idempotent. */
export function registerOnboardStep(name: string, fn: OnboardStep): void {
  if (!/^[a-z][a-z0-9_.-]{0,40}$/.test(name)) throw new Error('onboard step: invalid name');
  if (onboardSteps.some((s) => s.name === name)) throw new Error(`onboard step ${name}: registered twice`);
  onboardSteps.push({ name, fn });
}

/** The command queue's runner of the setup plan of an ADE device awaiting its configuration (§8.9). */
export function registerSetupRunner(fn: SetupRunner): void {
  if (setupRunner) throw new Error('setup runner: registered twice');
  setupRunner = fn;
}

let onboardJob: JobHandle<DeviceJob> | null = null;
let awaitJob: JobHandle<DeviceJob> | null = null;
let cleanupJob: JobHandle<DeviceJob> | null = null;

function handle(job: JobHandle<DeviceJob> | null, name: string): JobHandle<DeviceJob> {
  if (!job) throw new Error(`${name} is not registered (registerAppleModule)`);
  return job;
}

/** devices.unenroll-cleanup of a departure, in the caller's transaction: id derived from the device and the time it
 *  left (the checkout and the release of the same departure send one job). */
export async function sendUnenrollCleanup(trx: Knex.Transaction, tenantId: number, deviceId: number, unenrolledAt: Date | null): Promise<void> {
  const at = unenrolledAt ? unenrolledAt.getTime() : 0;
  await handle(cleanupJob, 'devices.unenroll-cleanup').sendInTx(trx, { tenantId, deviceId },
    { id: jobIdFor('devices.unenroll-cleanup', `${deviceId}:${at}`), tenantId });
}

/** The handles the outbox handlers send in the event's savepoint. */
export const deviceJobs = {
  onboard: (): JobHandle<DeviceJob> => handle(onboardJob, 'apple.device-onboard'),
  awaitConfiguration: (): JobHandle<DeviceJob> => handle(awaitJob, 'apple.await-configuration'),
  unenrollCleanup: (): JobHandle<DeviceJob> => handle(cleanupJob, 'devices.unenroll-cleanup'),
};

interface OnboardFacts {
  key: string | null;
  enrollmentId: string;
  certSha256: string | null;
  identityCertPem: string | null;
  state: string;
}

/** SHA-256 of the DER of a PEM certificate, or null when unreadable. */
function pemSha256(pem: string): string | null {
  try {
    return createHash('sha256').update(new X509Certificate(pem).raw).digest('hex');
  } catch {
    return null;
  }
}

/** apple.device-onboard (§8.10, §8.8). */
async function onboard(ctx: JobContext<DeviceJob>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const deviceId = ctx.payload.deviceId;
  const facts = await ctx.withTenant(async (trx) => {
    const r = await trx('apple_devices as a')
      .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .join('tenants as t', 't.id', 'd.tenant_id')
      .where({ 'a.tenant_id': tenantId, 'a.device_id': deviceId })
      .first('t.mdm_key', 'a.enrollment_id', 'a.cert_sha256', 'a.identity_cert_pem', 'd.enrollment_state') as
      { mdm_key: string | null; enrollment_id: string; cert_sha256: string | null; identity_cert_pem: string | null; enrollment_state: string } | undefined;
    return r ? { key: r.mdm_key, enrollmentId: r.enrollment_id, certSha256: r.cert_sha256 ? String(r.cert_sha256).trim() : null,
      identityCertPem: r.identity_cert_pem, state: r.enrollment_state } as OnboardFacts : null;
  });
  if (!facts) return { output: { skipped: 'no_record' } };
  if (facts.state === 'unenrolled' || facts.state === 'unenrolling') return { output: { skipped: 'not_enrolled' } };

  // 1. The public identity certificate, read from apple-edge outside any transaction (T-1), kept only when it is
  //    the certificate of the current cycle (a newer cycle may have started meanwhile).
  let identity: string = 'apple_edge_off';
  if (config.apple.mode === 'on') {
    if (facts.identityCertPem) {
      identity = 'present';
    } else if (!facts.key || !facts.enrollmentId.startsWith(`${facts.key}_`)) {
      identity = 'tenant_mismatch';                     // T-3: never ask apple-edge about another tenant's enrollment
    } else {
      try {
        const detail = await appleEdge.getEnrollment(facts.key, facts.enrollmentId, { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal });
        const pem = detail.certificate_pem;
        const sha = pem ? pemSha256(pem) : null;
        if (!pem || !sha) {
          identity = 'unavailable';
        } else if (sha !== facts.certSha256) {
          identity = 'other_cycle';
        } else {
          const stored = await ctx.withTenant((trx) => trx('apple_devices')
            .where({ tenant_id: tenantId, device_id: deviceId, cert_sha256: sha }).whereNull('identity_cert_pem')
            .update({ identity_cert_pem: pem, updated_at: new Date() }));
          identity = stored ? 'stored' : 'present';
        }
      } catch (err) {
        if (isAppleEdgeError(err) && (err.code === 'enrollment_not_found' || err.status === 404)) identity = 'not_in_edge';
        else throw err;
      }
    }
  }

  // 2. The steps of the other lots (inventory, DDM, policies).
  for (const s of onboardSteps) await s.fn({ job: ctx, tenantId, deviceId });
  ctx.log.debug({ identity, steps: onboardSteps.length }, 'device onboarded');
  return { output: { identity, steps: onboardSteps.length } };
}

/** apple.await-configuration (§8.9, I22): the plan of the setup, then the runner of the command queue. */
async function awaitConfiguration(ctx: JobContext<DeviceJob>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const deviceId = ctx.payload.deviceId;
  const plan = await ctx.withTenant(async (trx) => {
    const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).forUpdate().first('enrollment_state') as
      { enrollment_state: string } | undefined;
    if (!d || d.enrollment_state !== 'awaiting_configuration') return null;
    const deadlineAt = new Date(Date.now() + config.apple.setupTimeoutS * 1000);
    // A plan of this cycle already running stays (a retry, a replayed TokenUpdate); an ended one starts again.
    const res = await trx.raw(`
      INSERT INTO obligarth.apple_setup_plans AS p (device_id, tenant_id, state, command_ids, started_at, deadline_at)
      VALUES (?, ?, 'running', '{}', now(), ?)
      ON CONFLICT (device_id) DO UPDATE
         SET state = 'running', command_ids = '{}', device_configured_command_id = NULL, started_at = now(),
             deadline_at = EXCLUDED.deadline_at, completed_at = NULL, outcome_code = NULL
       WHERE p.state <> 'running'
      RETURNING p.deadline_at`, [deviceId, tenantId, deadlineAt]) as { rows: Array<{ deadline_at: Date }> };
    if (res.rows.length > 0) return { started: true, deadlineAt: new Date(res.rows[0].deadline_at) };
    const running = await trx('apple_setup_plans').where({ tenant_id: tenantId, device_id: deviceId }).first('deadline_at') as
      { deadline_at: Date } | undefined;
    return { started: false, deadlineAt: running ? new Date(running.deadline_at) : deadlineAt };
  });
  if (!plan) return { output: { skipped: 'not_awaiting_configuration' } };
  if (setupRunner) await setupRunner({ job: ctx, tenantId, deviceId, deadlineAt: plan.deadlineAt });
  return { output: { plan: plan.started ? 'started' : 'running', runner: setupRunner !== null } };
}

/** The alerts of a device that tell an ongoing problem of its management (resolved when it leaves). */
const DEVICE_PROBLEM_ALERTS = ['enrollment.setup_timeout', 'device.serial_changed', 'security.identity_mismatch',
  'enrollment.reenrolled_without_proof', 'enrollment.reenroll_refused'] as const;

/** What another module does at the cleanup of a departure, in its transaction (the licences of Apps and Books given
 *  back, lot C4). */
export type UnenrollCleanupStep = (trx: Knex.Transaction, tenantId: number, deviceId: number) => Promise<void>;
const cleanupSteps: UnenrollCleanupStep[] = [];
export function onUnenrollCleanup(fn: UnenrollCleanupStep): void { if (!cleanupSteps.includes(fn)) cleanupSteps.push(fn); }

/** devices.unenroll-cleanup (§13.3; modele §5.5, §10.4). */
async function cleanup(ctx: JobContext<DeviceJob>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const deviceId = ctx.payload.deviceId;
  const done = await ctx.withTenant(async (trx: Knex.Transaction) => {
    const r = await unenrollCleanup(trx, tenantId, deviceId);
    if (!r) return null;                                // enrolled again meanwhile, or gone
    await trx('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId }).del();
    await trx('apple_declaration_status').where({ tenant_id: tenantId, device_id: deviceId }).del();
    await trx('apple_ddm_status_inbox').where({ tenant_id: tenantId, device_id: deviceId }).del();
    await trx('apple_command_results_inbox').where({ tenant_id: tenantId, device_id: deviceId }).del();
    await trx('apple_setup_plans').where({ tenant_id: tenantId, device_id: deviceId, state: 'running' })
      .update({ state: 'cancelled', completed_at: new Date(), outcome_code: 'unenrolled' });
    for (const kind of DEVICE_PROBLEM_ALERTS) await resolveInTx(trx, tenantId, kind, deviceId);
    for (const step of cleanupSteps) await step(trx, tenantId, deviceId);
    return r;
  });
  if (!done) return { output: { skipped: 'not_unenrolled' } };
  realtime.deviceChanged(tenantId, deviceId);
  return { output: { retentionUntil: done.retentionUntil.toISOString() } };
}

let registered = false;

/**
 * Polling interval of a follow-up queue no one waits for (file-durable L3: 5 queries a second at most for the whole
 * server at rest; a queue polled every minute costs about three queries a minute). These queues are woken by NOTIFY
 * when a job is sent: the poll only picks up a retry that became due, at most this long after its delay.
 */
export const IDLE_POLL_SECONDS = 300;

/** The follow-up jobs of the enrollment cycles (registerAppleModule). */
export function registerDeviceJobs(): void {
  if (registered) return;
  registered = true;
  onboardJob = registerJob({
    name: 'apple.device-onboard',
    scope: 'tenant',
    description: 'Onboard a device at the end of its enrollment: identity certificate, then initial inventory, DDM and policies',
    payload: DevicePayload,
    policy: 'standard',
    retry: { limit: 5, delaySeconds: 30, backoff: true, maxDelaySeconds: 1800 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: onboard,
  });
  awaitJob = registerJob({
    name: 'apple.await-configuration',
    scope: 'tenant',
    description: 'Start the setup plan of an ADE device awaiting its configuration in the setup assistant',
    payload: DevicePayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 15, backoff: true, maxDelaySeconds: 300 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: 60,                                   // a device waits in the setup assistant: its retries within the minute
    handler: awaitConfiguration,
  });
  cleanupJob = registerJob({
    name: 'devices.unenroll-cleanup',
    scope: 'tenant',
    description: 'Clean up after a device left management: retention date, effective state, DDM set, inboxes, alerts',
    payload: DevicePayload,
    policy: 'standard',
    retry: { limit: 5, delaySeconds: 30, backoff: true, maxDelaySeconds: 1800 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: IDLE_POLL_SECONDS,
    handler: cleanup,
  });
}

import type { Knex } from 'knex';
import { z } from 'zod';
import type { Ownership } from '@obligarth/shared';
import { jobIdFor, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { raiseInTx } from '../alerts/service';
import { registerSetupRunner } from '../devices/jobs';
import { mdmCommands } from './bus';
import { onTargetFinal } from './targets';

// =============================================================================
// Setup sequence of an ADE device awaiting its configuration (docs:
// integration-apple-edge §8.9, I22): the device stays in the setup assistant
// until DeviceConfigured. apple.await-configuration opens the plan
// (apple_setup_plans, 'running', deadline APPLE_SETUP_TIMEOUT_S) and calls the
// runner registered here:
//   1. the contributors, in registration order, give the commands of the
//      plan (core: DeviceInformation, SecurityInfo, and for a company device
//      the activation lock of the organisation; the policies and the
//      mandatory apps register theirs); each one the bus accepts is enqueued
//      (origin 'setup') and listed in command_ids; apple.setup-timeout is
//      sent for the deadline;
//   2. when every command of the plan has a final target (rank 3 or more),
//      the hook enqueues DeviceConfigured; with no command at all, at once;
//   3. DeviceConfigured acknowledged: the plan is 'configured' (its ingestor);
//   4. the deadline with the plan still running: DeviceConfigured anyway, the
//      plan 'timed_out', the alert enrollment.setup_timeout.
// A device that leaves management meanwhile has its plan cancelled and its
// open targets closed (the lifecycle).
// =============================================================================

export interface SetupCommand {
  requestType: string;
  params?: Record<string, unknown>;
}

export interface SetupContributor {
  /** 'core', 'policies', 'apps'. */
  name: string;
  contribute(trx: Knex.Transaction, ctx: {
    tenantId: number; deviceId: number; profileId: string | null; ownership: Ownership | null; platform: string | null; supervised: boolean;
  }): Promise<SetupCommand[]>;
}

const contributors: SetupContributor[] = [];

/** A contributor of the setup plan; registered before anything starts, a name once. */
export function registerSetupContributor(c: SetupContributor): void {
  if (!/^[a-z][a-z0-9_.-]{0,40}$/.test(String(c?.name ?? ''))) throw new Error('setup contributor: invalid name');
  if (contributors.some((x) => x.name === c.name)) throw new Error(`setup contributor ${c.name}: registered twice`);
  contributors.push(c);
}

const ACTOR = 'j:apple.await-configuration';
const TimeoutPayload = z.object({ tenantId: z.number().int().positive(), deviceId: z.number().int().positive(), startedAt: z.string().datetime() }).strict();
type Timeout = z.infer<typeof TimeoutPayload>;
let timeoutJob: JobHandle<Timeout> | null = null;

interface PlanRow {
  state: string;
  command_ids: string[];
  device_configured_command_id: string | null;
  started_at: Date;
  deadline_at: Date;
}

const planOf = (trx: Knex.Transaction, tenantId: number, deviceId: number) => trx('apple_setup_plans')
  .where({ tenant_id: tenantId, device_id: deviceId }).forUpdate()
  .first('state', 'command_ids', 'device_configured_command_id', 'started_at', 'deadline_at') as Promise<PlanRow | undefined>;

/** DeviceConfigured of a plan, once (the bus keeps one open per device). */
async function sendDeviceConfigured(trx: Knex.Transaction, tenantId: number, deviceId: number, actor: string): Promise<string | null> {
  const o = await mdmCommands.enqueue(trx, { tenantId, requestType: 'DeviceConfigured', deviceIds: [deviceId], origin: 'setup', actor, push: true });
  const id = o.commandIds[0] ?? null;
  if (id) await trx('apple_setup_plans').where({ tenant_id: tenantId, device_id: deviceId }).update({ device_configured_command_id: id });
  return id;
}

/** The runner of apple.await-configuration: the commands of the plan, its deadline. */
async function runSetup(ctx: { job: JobContext<{ tenantId: number; deviceId: number }>; tenantId: number; deviceId: number; deadlineAt: Date }): Promise<void> {
  const { tenantId, deviceId } = ctx;
  await ctx.job.withTenant(async (trx) => {
    const plan = await planOf(trx, tenantId, deviceId);
    if (!plan || plan.state !== 'running') return;
    // A retry of the job, a replayed TokenUpdate: the plan already has its commands.
    if ((plan.command_ids ?? []).length > 0 || plan.device_configured_command_id) return;
    const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('ownership', 'platform', 'supervised', 'enrollment_profile_id', 'enrollment_state') as
      { ownership: Ownership; platform: string | null; supervised: boolean; enrollment_profile_id: string | null; enrollment_state: string } | undefined;
    if (!d || d.enrollment_state !== 'awaiting_configuration') return;
    const commandIds: string[] = [];
    for (const c of contributors) {
      const wanted = await c.contribute(trx, { tenantId, deviceId, profileId: d.enrollment_profile_id, ownership: d.ownership, platform: d.platform, supervised: d.supervised === true });
      for (const w of wanted) {
        // A command the bus refuses (a prerequisite) is not part of the plan.
        const o = await mdmCommands.enqueue(trx, { tenantId, requestType: w.requestType, deviceIds: [deviceId], params: w.params ?? {}, origin: 'setup', actor: ACTOR, push: true });
        commandIds.push(...o.commandIds);
      }
    }
    await trx('apple_setup_plans').where({ tenant_id: tenantId, device_id: deviceId })
      .update({ command_ids: trx.raw('?::uuid[]', [commandIds]) });
    await (timeoutJob as JobHandle<Timeout>).sendInTx(trx, { tenantId, deviceId, startedAt: new Date(plan.started_at).toISOString() },
      { id: jobIdFor('apple.setup-timeout', `${deviceId}:${new Date(plan.started_at).getTime()}`), tenantId, startAfter: new Date(plan.deadline_at) });
    if (commandIds.length === 0) await sendDeviceConfigured(trx, tenantId, deviceId, ACTOR);
  });
}

/** apple.setup-timeout: the plan of this start still running at its deadline. */
async function setupTimeout(ctx: JobContext<Timeout>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const deviceId = ctx.payload.deviceId;
  const outcome = await ctx.withTenant(async (trx) => {
    const plan = await planOf(trx, tenantId, deviceId);
    if (!plan || plan.state !== 'running') return plan?.state ?? 'no_plan';
    if (new Date(plan.started_at).getTime() !== new Date(ctx.payload.startedAt).getTime()) return 'another_plan';
    if (new Date(plan.deadline_at).getTime() > Date.now() + 1000) return 'not_due';
    if (!plan.device_configured_command_id) await sendDeviceConfigured(trx, tenantId, deviceId, `j:${ctx.name}`);
    await trx('apple_setup_plans').where({ tenant_id: tenantId, device_id: deviceId })
      .update({ state: 'timed_out', completed_at: new Date(), outcome_code: 'timeout' });
    await raiseInTx(trx, tenantId, 'enrollment.setup_timeout', { discriminant: deviceId, navigateTo: `/devices/${deviceId}` });
    return 'timed_out';
  });
  return { output: { plan: outcome } };
}

/**
 * The name the enrollment profile gives the device (settings.deviceNameTemplate, §10.1, §8.9): {serial} its
 * serial number, {model} its model, {n} the number of its record; null without template. Control characters
 * removed, 255 characters at most.
 */
export async function deviceNameOf(trx: Knex.Transaction, tenantId: number, deviceId: number, profileId: string | null): Promise<string | null> {
  if (!profileId) return null;
  const p = await trx('enrollment_profiles').where({ tenant_id: tenantId, id: profileId }).first('settings') as { settings: Record<string, unknown> | null } | undefined;
  const tpl = typeof p?.settings?.deviceNameTemplate === 'string' ? p.settings.deviceNameTemplate : '';
  if (!tpl.trim()) return null;
  const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('serial_number', 'model_name', 'model') as
    { serial_number: string | null; model_name: string | null; model: string | null } | undefined;
  const values: Record<string, string> = { serial: d?.serial_number ?? '', model: d?.model_name ?? d?.model ?? '', n: String(deviceId) };
  const name = tpl.replace(/\{(serial|model|n)\}/g, (_m, k: string) => values[k] ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 255);
  return name || null;
}

let registered = false;

/** The setup plan's runner, its hook, its core contributor and its timeout job (registerAppleModule). */
export function registerSetup(): void {
  if (registered) return;
  registered = true;
  registerSetupRunner(runSetup);
  // Core: the inventory the console shows first, and for a company device the activation lock of the organisation
  // (conception §5.4.2: allowed while supervised, then its bypass code), with the device name of the enrollment
  // profile (lot C2); the first DDM synchronisation is the DDM engine's contributor.
  registerSetupContributor({
    name: 'core',
    async contribute(trx, c) {
      const out: SetupCommand[] = [{ requestType: 'DeviceInformation' }, { requestType: 'SecurityInfo' }];
      const company = c.ownership === 'corporate' || c.ownership === 'corporate_personal';
      // One Settings command (the bus keeps one open per type and device): the device name of the enrollment
      // profile's template (lot C2: {serial}, {model}, {n}, never a value of the employee), then the activation
      // lock of the organisation.
      const items: Array<Record<string, unknown>> = [];
      if (c.supervised && company) {
        const name = await deviceNameOf(trx, c.tenantId, c.deviceId, c.profileId);
        if (name) items.push({ item: 'DeviceName', deviceName: name });
        items.push({ item: 'MDMOptions', activationLockAllowedWhileSupervised: true });
      }
      if (items.length > 0) out.push({ requestType: 'Settings', params: { items } });
      if (c.supervised && company) out.push({ requestType: 'ActivationLockBypassCode' });
      return out;
    },
  });
  // A final target of a command of a running plan: once they all are, the device may leave the setup assistant.
  onTargetFinal('setup.plan', async ({ trx, tenantId, deviceId, commandId }) => {
    const plan = await trx('apple_setup_plans').where({ tenant_id: tenantId, device_id: deviceId, state: 'running' })
      .whereRaw('?::uuid = ANY (command_ids)', [commandId]).forUpdate().first('command_ids', 'device_configured_command_id') as
      { command_ids: string[]; device_configured_command_id: string | null } | undefined;
    if (!plan || plan.device_configured_command_id) return;
    const open = await trx('mdm_command_targets').where({ tenant_id: tenantId, device_id: deviceId })
      .whereRaw('command_id = ANY (?::uuid[])', [plan.command_ids]).whereIn('state', ['pending', 'queued', 'sent', 'notnow']).first('command_id');
    if (open) return;
    await sendDeviceConfigured(trx, tenantId, deviceId, ACTOR);
  });
  timeoutJob = registerJob({
    name: 'apple.setup-timeout',
    scope: 'tenant',
    description: 'Release from the setup assistant a device whose configuration did not finish in time',
    payload: TimeoutPayload,
    policy: 'standard',
    retry: { limit: 3, delaySeconds: 15, backoff: true, maxDelaySeconds: 300 },
    timeoutSeconds: 120,
    notify: true,
    // The job is dated at the deadline of the plan: only the poll starts it (a device waits in the setup assistant).
    pollSeconds: 120,
    handler: setupTimeout,
  });
}

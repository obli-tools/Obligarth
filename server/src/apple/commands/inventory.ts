import type { Knex } from 'knex';
import { z } from 'zod';
import { config } from '../../config';
import { db } from '../../db';
import { forEachTenant } from '../../db/tenantContext';
import { JobError, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { AppError } from '../../middleware/errorHandler';
import { registerOnboardStep } from '../../mdm/registry/onboard';
import type { AuditWriteContext } from '../../audit';
import { mdmCommands, type EnqueueOutcome } from './bus';
import { setAfterDeviceInformation } from './results';

// =============================================================================
// Inventory through the command queue (docs: integration-apple-edge §8.10;
// modele-donnees-mdm §5.1, §5.2): what is asked follows the privacy rules of
// each device's ownership (the catalogue builds the queries from them).
//   initial    a step of apple.device-onboard, once the device opened to
//              management: DeviceInformation, SecurityInfo, the application,
//              profile and certificate lists, and the bypass code of the
//              activation lock of a supervised company device
//   periodic   apple.inventory.refresh-all (daily, 02:30 UTC) fans out
//              apple.inventory.refresh-tenant: DeviceInformation and
//              SecurityInfo of the devices whose last answer is older than a
//              day, the lists every week; 2 000 devices per run at most; the
//              wake-ups spread over 6 hours (slots of 15 minutes); devices
//              whose push cannot reach them left out
//   on demand  the console's « Refresh the inventory », once per device and
//              per 5 minutes
// One command of a type open per device (the bus sets a device aside:
// already_open): a run repeated, or a device that does not answer, adds none.
// =============================================================================

const DAILY = ['DeviceInformation', 'SecurityInfo'] as const;
const WEEKLY = ['InstalledApplicationList', 'ProfileList', 'CertificateList'] as const;
const INITIAL = [...DAILY, ...WEEKLY] as const;
const MAX_DEVICES_PER_RUN = 2_000;
/** The wake-ups of a periodic run are spread over this long, in slots. */
const SPREAD_SECONDS = 6 * 3600;
const SLOT_SECONDS = 900;
const REFRESH_GAP_MS = 5 * 60_000;

const TenantPayload = z.object({ tenantId: z.number().int().positive() }).strict();
type Tenant = z.infer<typeof TenantPayload>;
let tenantJob: JobHandle<Tenant> | null = null;

/** The bypass code of the activation lock is asked of a supervised company device that has none recorded. */
async function wantsBypassCode(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<boolean> {
  const r = await trx('devices as d')
    .join('apple_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where({ 'd.tenant_id': tenantId, 'd.id': deviceId })
    .first('d.ownership', 'd.supervised', 'd.enrollment_state', 'a.activation_lock_bypass_ref') as
    { ownership: string; supervised: boolean; enrollment_state: string; activation_lock_bypass_ref: string | null } | undefined;
  return !!r && r.supervised === true && r.activation_lock_bypass_ref === null
    && (r.ownership === 'corporate' || r.ownership === 'corporate_personal')
    && (r.enrollment_state === 'enrolled' || r.enrollment_state === 'awaiting_configuration');
}

/** The initial inventory of a device (in the tenant's transaction): the types the device takes, in one go. */
export async function enqueueInitialInventory(trx: Knex.Transaction, tenantId: number, deviceId: number, actor: string, auditCtx?: AuditWriteContext): Promise<number> {
  let commands = 0;
  for (const requestType of INITIAL) {
    const o = await mdmCommands.enqueue(trx, { tenantId, requestType, deviceIds: [deviceId], origin: 'inventory', actor, auditCtx });
    commands += o.commandIds.length;
  }
  if (await wantsBypassCode(trx, tenantId, deviceId)) {
    const o = await mdmCommands.enqueue(trx, { tenantId, requestType: 'ActivationLockBypassCode', deviceIds: [deviceId], origin: 'inventory', actor, auditCtx });
    commands += o.commandIds.length;
  }
  return commands;
}

/**
 * « Refresh the inventory » of the console (§8.12): the five inventory commands of the device, once per 5 minutes
 * (429 otherwise). In the tenant's transaction.
 */
export async function refreshInventoryNow(trx: Knex.Transaction, tenantId: number, deviceId: number, userId: number, auditCtx: AuditWriteContext):
  Promise<{ batchIds: string[]; commandIds: string[]; refused: EnqueueOutcome['refused'] }> {
  const recent = await trx('mdm_command_targets as t')
    .join('mdm_commands as c', function joinCommand() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
    .where({ 't.tenant_id': tenantId, 't.device_id': deviceId, 'c.origin': 'console' }).whereIn('c.request_type', INITIAL as unknown as string[])
    .where('c.created_at', '>', new Date(Date.now() - REFRESH_GAP_MS)).first('c.id');
  if (recent) throw new AppError(429, 'The inventory of this device was refreshed less than 5 minutes ago', 'inventoryRefreshTooSoon');
  const out = { batchIds: [] as string[], commandIds: [] as string[], refused: [] as EnqueueOutcome['refused'] };
  for (const requestType of INITIAL) {
    const o = await mdmCommands.enqueue(trx, { tenantId, requestType, deviceIds: [deviceId], origin: 'console', actor: `u:${userId}`, requestedBy: userId, auditCtx });
    if (o.commandIds.length > 0) out.batchIds.push(o.batchId);
    out.commandIds.push(...o.commandIds);
    for (const r of o.refused) if (!out.refused.some((x) => x.code === r.code)) out.refused.push(r);
  }
  return out;
}

/** apple.inventory.refresh-tenant. */
async function refreshTenant(ctx: JobContext<Tenant>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const day = new Date(Date.now() - 24 * 3600_000);
  const week = new Date(Date.now() - 7 * 24 * 3600_000);
  const actor = `j:${ctx.name}`;
  let commands = 0;
  let devices = 0;
  await ctx.withTenant(async (trx) => {
    const rows = await trx('devices as d')
      .join('apple_devices as a', function joinSatellite() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
      .where({ 'd.tenant_id': tenantId, 'd.management_channel': 'apple_mdm', 'd.enrollment_state': 'enrolled' })
      .whereNotIn('a.push_state', ['invalid_token', 'inactive', 'disabled'])
      .where((q) => q.whereNull('a.last_device_info_at').orWhere('a.last_device_info_at', '<', day)
        .orWhereNull('a.last_apps_at').orWhere('a.last_apps_at', '<', week))
      .orderByRaw('a.last_device_info_at ASC NULLS FIRST').limit(MAX_DEVICES_PER_RUN)
      .select('d.id', 'a.last_device_info_at', 'a.last_security_info_at', 'a.last_apps_at', 'a.last_profiles_at', 'a.last_certificates_at') as
      Array<{ id: number; last_device_info_at: Date | null; last_security_info_at: Date | null; last_apps_at: Date | null;
        last_profiles_at: Date | null; last_certificates_at: Date | null }>;
    devices = rows.length;
    if (rows.length === 0) return;
    const old = (v: Date | null, limit: Date): boolean => v === null || new Date(v).getTime() < limit.getTime();
    const due: Record<string, number[]> = {
      DeviceInformation: rows.filter((r) => old(r.last_device_info_at, day)).map((r) => Number(r.id)),
      SecurityInfo: rows.filter((r) => old(r.last_security_info_at, day)).map((r) => Number(r.id)),
      InstalledApplicationList: rows.filter((r) => old(r.last_apps_at, week)).map((r) => Number(r.id)),
      ProfileList: rows.filter((r) => old(r.last_profiles_at, week)).map((r) => Number(r.id)),
      CertificateList: rows.filter((r) => old(r.last_certificates_at, week)).map((r) => Number(r.id)),
    };
    // A device keeps its slot for all its commands of the run: one wake-up serves them all.
    const slots = Math.max(1, Math.min(SPREAD_SECONDS / SLOT_SECONDS, Math.ceil(rows.length / 20)));
    const slotOf = new Map(rows.map((r) => [Number(r.id), Math.floor(Math.random() * slots)]));
    for (const [requestType, ids] of Object.entries(due)) {
      for (let slot = 0; slot < slots; slot++) {
        const deviceIds = ids.filter((id) => slotOf.get(id) === slot);
        if (deviceIds.length === 0) continue;
        ctx.throwIfAborted();
        const o = await mdmCommands.enqueue(trx, { tenantId, requestType, deviceIds, origin: 'inventory', actor, delaySeconds: slot * SLOT_SECONDS });
        commands += o.commandIds.length;
      }
    }
  });
  return { output: { devices, commands } };
}

/** apple.inventory.refresh-all. */
async function refreshAll(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let tenants = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const any = await db('devices').where({ tenant_id: tenantId, management_channel: 'apple_mdm', enrollment_state: 'enrolled' }).first('id');
    if (!any) return;
    await (tenantJob as JobHandle<Tenant>).send({ tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
    tenants++;
  });
  if (failed > 0) throw new JobError('partial_failure', `${failed} tenant(s) failed`);
  return { output: { tenants } };
}

let registered = false;

/** The inventory's hooks into the onboarding, the ingestion and the durable jobs (registerAppleModule). */
export function registerInventory(): void {
  if (registered) return;
  registered = true;
  // §8.10: the initial inventory, a step of apple.device-onboard (after the identity certificate).
  registerOnboardStep('apple_mdm', { name: 'inventory.initial', run: async ({ job, tenantId, deviceId }) => {
    await job.withTenant((trx) => enqueueInitialInventory(trx, tenantId, deviceId, `j:${job.name}`));
  } });
  // The ingestor of DeviceInformation learns that a company device without a bypass reference is supervised.
  setAfterDeviceInformation(async (c) => {
    if (await wantsBypassCode(c.trx, c.tenantId, c.deviceId)) {
      // One open command of the type per device (the bus sets the device aside otherwise): a replay adds none.
      await mdmCommands.enqueue(c.trx, { tenantId: c.tenantId, requestType: 'ActivationLockBypassCode', deviceIds: [c.deviceId], origin: 'inventory',
        actor: 'j:apple.command-result-ingest' });
    }
  });
  tenantJob = registerJob({
    name: 'apple.inventory.refresh-tenant',
    scope: 'tenant',
    description: 'Ask the devices of a tenant for their inventory again (daily information, weekly lists), spread over 6 hours',
    payload: TenantPayload,
    policy: 'exclusive',
    retry: { limit: 2, delaySeconds: 300, backoff: true, maxDelaySeconds: 3600 },
    timeoutSeconds: 900,
    heartbeatSeconds: 60,
    notify: true,
    pollSeconds: 300,
    handler: refreshTenant,
  });
  registerJob({
    name: 'apple.inventory.refresh-all',
    scope: 'platform',
    description: 'Daily: the tenants whose devices are asked for their inventory again',
    payload: z.object({}).strict(),
    policy: 'exclusive',
    // APPLE_EDGE_MODE=off: no device answers, the daily refresh is not scheduled (file-durable L3).
    ...(config.apple.mode === 'on' ? { schedule: { cron: '30 2 * * *' } } : {}),
    retry: { limit: 2, delaySeconds: 300, backoff: true, maxDelaySeconds: 3600 },
    timeoutSeconds: 600,
    pollSeconds: 300,
    deadLetter: false, trackStatus: 'queue', manualRun: true, keepFinishedSeconds: 172_800, keepPendingSeconds: 86_400,
    handler: refreshAll,
  });
}

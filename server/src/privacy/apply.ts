import type { Knex } from 'knex';
import { z } from 'zod';
import { OWNERSHIPS, type Ownership } from '@obligarth/shared';
import { audit } from '../audit';
import { config } from '../config';
import { db } from '../db';
import { requestEnrollmentPolicies } from '../android/enrollment/policyRequests';
import { androidSenders } from '../android/enrollment/senders';
import { mdmCommands } from '../apple/commands/bus';
import { requestDdmRecompute } from '../apple/ddm/engine';
import { SERIAL_STATUS_ITEMS } from '../apple/devices/privacy';
import { registerJob, type JobContext, type JobHandle, type JobResult } from '../jobs';
import { applyCollectionRules } from '../mdm/inventory/ingestors';
import { resolveApplyRules, type ApplyRules } from './applyRules';

// =============================================================================
// privacy.apply-profile (P0-13 T3, CNF-02): what a new version of a privacy profile does to the fleet of its
// ownership, once published by the executor of its approval (privacy/approvals.ts).
//   - Cleaning (motif M8): what the new rules collect no longer leaves the records, by slices of devices (each slice its
//     own tenant transaction, abort checked between two: the job is cancellable, and idempotent: a run starts again
//     from the base). Only the keys narrowed since the version in force before (`fromVersion`, the defaults when
//     null) are cleaned, as each channel's ingestion now refuses them:
//       Apple (apple_mdm)       applyCollectionRules (the unmanaged apps, the device name, the IMEI, the keys of the
//                               last DeviceInformation answer: serial number, hardware ids, phone, network), the
//                               serial number of the record and its status item, the certificates of the
//                               CertificateList not issued by the MDM (a CertificateList ManagedOnly is asked again);
//       Android (amapi)         network_info (whole, or its IMEI), the apps outside the tenant's catalog;
//       bridge agent            the IMEIs (and the one of the MobiControl hints), the apps no app.install put there;
//       every channel           the positions in lost mode when the profile no longer locates;
//       Apple Business          the hardware ids of the devices not enrolled yet (rules of corporate_personal, the
//                               strictest ADE allows: apple/outbox/handlers.ade.ts).
//     device_apps (columns of the migration app_icons: is_system, launchable, installer, dates) loses whole rows only;
//     app_icons (one icon per tenant and identifier, the pipeline of the Applications tab) is left alone.
//   - Recompilation, whatever changed: the Android policies of the devices of the ownership and the enrollment
//     policies (statusReportingSettings: networkInfo), the DDM sets of the tenant (status items). The next Apple
//     inventory commands follow the new rules by themselves (the catalogue builds the queries from them).
//   - Audit privacy.data_scrubbed (standard, counters only).
// Sent by the executor in the transaction of the publication, 45 seconds later: the profiles are cached 30 seconds per
// process (privacy/profiles.ts), an ingestion of another process sees the new rules before the cleaning starts.
// Policy stately, key t:<tenant>:<ownership>: a publication while a run is active queues the next one; a third while one
// waits is folded into it (the waiting one, not started, reads the rules in force and still carries the oldest
// fromVersion: the net narrowing of both).
// =============================================================================

/** Devices per slice (motif M8). */
const DEVICE_SLICE = 100;
/** Rows of apple_ade_devices per slice. */
const ROW_SLICE = 500;
/** After the 30-second cache of the profiles (privacy/profiles.ts CACHE_TTL_MS). */
export const APPLY_DELAY_SECONDS = 45;
const JOB_NAME = 'privacy.apply-profile';

const ApplyPayload = z.object({
  tenantId: z.number().int().positive(),
  ownership: z.enum(OWNERSHIPS),
  /** The version in force before the publication (null: none, the defaults). */
  fromVersion: z.number().int().positive().nullable(),
}).strict();
type Apply = z.infer<typeof ApplyPayload>;

let applyJob: JobHandle<Apply> | null = null;

/** Queues the application of the profile of `ownership` in `trx` (the transaction of its publication). */
export async function requestProfileApplication(trx: Knex.Transaction, tenantId: number, ownership: Ownership, fromVersion: number | null):
  Promise<string | null> {
  if (!applyJob) throw new Error(`${JOB_NAME} is not registered (registerPrivacyModule)`);
  return applyJob.sendInTx(trx, { tenantId, ownership, fromVersion },
    { singletonKey: `t:${tenantId}:${ownership}`, tenantId, startAfter: APPLY_DELAY_SECONDS });
}

/** What a slice removed. */
export interface ScrubCounts {
  devices: number;
  records: number;
  apps: number;
  certificates: number;
  locations: number;
  adeDevices: number;
  androidPushes: number;
}

const zero = (): ScrubCounts => ({ devices: 0, records: 0, apps: 0, certificates: 0, locations: 0, adeDevices: 0, androidPushes: 0 });

interface SliceDevice { id: number; channel: string; enrolled: boolean }

/** The next slice of devices of the ownership after `afterId` (records under management or not: an unenrolled record
 *  still holds its data until its retention ends). */
async function nextSlice(trx: Knex.Transaction, tenantId: number, ownership: Ownership, afterId: number): Promise<SliceDevice[]> {
  const rows = await trx('devices').where({ tenant_id: tenantId, ownership }).where('id', '>', afterId).orderBy('id').limit(DEVICE_SLICE)
    .select('id', 'management_channel', 'enrollment_state') as Array<{ id: number; management_channel: string; enrollment_state: string }>;
  return rows.map((r) => ({ id: Number(r.id), channel: r.management_channel, enrolled: r.enrollment_state !== 'unenrolled' && r.enrollment_state !== 'unenrolling' }));
}

/** Cleans and recompiles one slice of devices, in `trx` (the tenant's context). */
export async function applyToSlice(trx: Knex.Transaction, tenantId: number, r: ApplyRules, devices: readonly SliceDevice[],
  o: { actor: string; requestCertificates: boolean }): Promise<ScrubCounts> {
  const out = zero();
  out.devices = devices.length;
  const n = r.narrowed;
  const apple = devices.filter((d) => d.channel === 'apple_mdm').map((d) => d.id);
  const amapi = devices.filter((d) => d.channel === 'amapi');
  const agent = devices.filter((d) => d.channel === 'legacy_agent').map((d) => d.id);
  const all = devices.map((d) => d.id);
  const now = new Date();

  // ── Apple ────────────────────────────────────────────────────────────────
  if (apple.length) {
    if (n.has('installedApps') || n.has('deviceName') || n.has('hardwareIds') || n.has('serialNumber') || n.has('phoneNumber') || n.has('network')) {
      for (const id of apple) out.apps += (await applyCollectionRules(trx, tenantId, id, r.apple)).purgedApps;
    }
    if (n.has('serialNumber') && !r.apple.storeSerialNumber) {
      out.records += await trx('devices').where({ tenant_id: tenantId }).whereIn('id', apple).whereNotNull('serial_number')
        .update({ serial_number: null, updated_at: now });
      await trx('device_status_items').where({ tenant_id: tenantId }).whereIn('device_id', apple).whereIn('item', SERIAL_STATUS_ITEMS).delete();
    }
    if (n.has('certificates') && r.apple.certificates === 'managed_only') {
      const gone = await trx('device_certificates').where({ tenant_id: tenantId, source: 'certificate_list', is_mdm_identity: false })
        .whereIn('device_id', apple).delete().returning('device_id') as Array<{ device_id: number }>;
      out.certificates += gone.length;
      const touched = [...new Set(gone.map((g) => Number(g.device_id)))];
      if (touched.length) {
        await trx('apple_devices').where({ tenant_id: tenantId }).whereIn('device_id', touched).update({ last_certificates_at: null, updated_at: now });
        // The managed certificates come back with the next list, asked now (ManagedOnly: the catalogue follows the rules).
        const enrolled = devices.filter((d) => d.enrolled && touched.includes(d.id)).map((d) => d.id);
        if (o.requestCertificates && enrolled.length) {
          await mdmCommands.enqueue(trx, { tenantId, requestType: 'CertificateList', deviceIds: enrolled, origin: 'inventory', actor: o.actor });
        }
      }
    }
  }

  // ── Android AMAPI ─────────────────────────────────────────────────────────
  if (amapi.length) {
    const ids = amapi.map((d) => d.id);
    if ((n.has('network') || n.has('hardwareIds')) && !r.android.networkInfo) {
      out.records += await trx('android_devices').where({ tenant_id: tenantId }).whereIn('device_id', ids).whereNotNull('network_info')
        .update({ network_info: null, updated_at: now });
    } else if (n.has('hardwareIds') && !r.android.imei) {
      out.records += await trx('android_devices').where({ tenant_id: tenantId }).whereIn('device_id', ids).whereRaw("network_info ->> 'imei' IS NOT NULL")
        .update({ network_info: trx.raw("network_info - 'imei'"), updated_at: now });
    }
    if (n.has('installedApps') && r.android.installedApps === 'managed_only') {
      out.apps += await trx('device_apps').where({ tenant_id: tenantId }).whereIn('device_id', ids)
        .whereNotIn('identifier', trx('apps').where({ tenant_id: tenantId, platform_family: 'android' }).whereNull('archived_at').select('identifier'))
        .delete();
    }
    // The policy of each device compiled again (statusReportingSettings), pushed when it changed.
    for (const d of amapi) {
      if (!d.enrolled) continue;
      await androidSenders.push(trx, { tenantId, deviceId: d.id });
      out.androidPushes++;
    }
  }

  // ── Bridge agent ──────────────────────────────────────────────────────────
  if (agent.length) {
    if (n.has('hardwareIds') && !r.agent.imei) {
      out.records += await trx('legacy_agent_devices').where({ tenant_id: tenantId }).whereIn('device_id', agent)
        .where((q) => q.whereRaw('cardinality(imeis) > 0').orWhereRaw("hints ->> 'imei' IS NOT NULL"))
        .update({
          imeis: trx.raw("'{}'::text[]"),
          hints: trx.raw("CASE WHEN hints ->> 'imei' IS NULL THEN hints ELSE jsonb_set(hints, '{imei}', 'null'::jsonb) END"),
          updated_at: now,
        });
    }
    if (n.has('installedApps') && r.agent.installedApps === 'managed_only') {
      out.apps += await trx('device_apps').where({ tenant_id: tenantId, source: 'agent_report', managed: false }).whereIn('device_id', agent).delete();
    }
  }

  // ── Every channel: the positions in lost mode ─────────────────────────────
  if (n.has('lostModeLocation') && !r.locate && all.length) {
    out.locations += await trx('lost_mode_locations').where({ tenant_id: tenantId }).whereIn('device_id', all).delete();
  }
  return out;
}

/** The hardware ids of the devices of Apple Business not enrolled yet (kept under the rules of corporate_personal):
 *  one slice, in `trx`. */
export async function scrubAdeSlice(trx: Knex.Transaction, tenantId: number): Promise<number> {
  return trx('apple_ade_devices').where({ tenant_id: tenantId })
    .whereIn('id', trx('apple_ade_devices').where({ tenant_id: tenantId }).whereRaw("hardware_ids <> '{}'::jsonb").limit(ROW_SLICE).select('id'))
    .update({ hardware_ids: trx.raw("'{}'::jsonb"), updated_at: new Date() });
}

const add = (a: ScrubCounts, b: ScrubCounts): void => {
  for (const k of Object.keys(a) as Array<keyof ScrubCounts>) a[k] += b[k];
};

async function applyProfile(ctx: JobContext<Apply>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const { ownership, fromVersion } = ctx.payload;
  const rules = await ctx.inTenant(() => resolveApplyRules(db, tenantId, ownership, fromVersion));
  if (!rules) return { output: { applied: false } };
  const total = zero();
  let afterId = 0;
  for (;;) {
    ctx.throwIfAborted();
    const cursor = afterId;
    const slice = await ctx.withTenant(async (trx) => {
      const devices = await nextSlice(trx, tenantId, ownership, cursor);
      if (!devices.length) return { devices, counts: zero() };
      return { devices, counts: await applyToSlice(trx, tenantId, rules, devices, { actor: `j:${ctx.name}`, requestCertificates: config.apple.mode === 'on' }) };
    });
    add(total, slice.counts);
    if (slice.devices.length < DEVICE_SLICE) break;
    afterId = slice.devices[slice.devices.length - 1].id;
  }
  if (ownership === 'corporate_personal' && rules.narrowed.has('hardwareIds') && !rules.apple.storeHardwareIds) {
    for (;;) {
      ctx.throwIfAborted();
      const n = await ctx.withTenant((trx) => scrubAdeSlice(trx, tenantId));
      total.adeDevices += n;
      if (n < ROW_SLICE) break;
    }
  }
  // The enrollment policies of Android (their statusReportingSettings follow the profile of their ownership) and the
  // DDM sets of the tenant (the status items follow the rules).
  await ctx.withTenant(async (trx) => {
    await requestEnrollmentPolicies(trx, tenantId);
    await requestDdmRecompute(trx, tenantId, { all: true });
  });
  const narrowed = [...rules.narrowed].sort();
  await audit.append({
    tenantId, action: 'privacy.data_scrubbed', target: { type: 'privacy_profile', id: ownership },
    details: { ownership, fromVersion, narrowed, ...total },
  }, audit.fromJob({ name: ctx.name, requestId: ctx.requestId }));
  return { output: { applied: true, narrowed: narrowed.join(',') || null, ...total } };
}

let registered = false;

/** Registers privacy.apply-profile (registerPrivacyModule, before anything starts). */
export function registerProfileApplicationJob(): void {
  if (registered) return;
  registered = true;
  applyJob = registerJob({
    name: JOB_NAME,
    scope: 'tenant',
    description: 'Apply a new version of a privacy profile: clean the data it no longer collects, compile the policies again',
    payload: ApplyPayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 60, backoff: true, maxDelaySeconds: 1_800 },
    timeoutSeconds: 3_600,
    heartbeatSeconds: 60,
    // Rare (an approved change of a profile) and delayed: picked up by the poll of an idle queue (file-durable L3).
    notify: true,
    pollSeconds: 300,
    handler: applyProfile,
  });
}

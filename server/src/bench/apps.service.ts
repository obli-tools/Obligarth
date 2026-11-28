import path from 'node:path';
import type { Knex } from 'knex';
import { z } from 'zod';
import { MASTER_TENANT_ID, truncateSerial, type BenchAppsPlanAnswer, type BenchRequiredAppView } from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { asNone, asTenant } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { apkDir } from '../legacyAgent/config';
import { WindowLimiter } from '../legacyAgent/limits';
import { benchRequiredApps } from '../legacyAgent/requiredApps';
import { stationActor, stationAuditContext } from './actor';
import { comparableSerial } from './enrollment';
import {
  PlanBody, groupWithin, sessionUser, stationTargets, targetIn, technicianMayOperate, withProvisioning, type Origin,
} from './provisioning.service';
import type { StationLookup } from './stations.service';

// =============================================================================
// The required apps installed on the bench by ADB (lot BANC-A, spec banc-apps). The list is the one the server already
// decides for the bridge agent policies (legacyAgent/requiredApps.ts: benchRequiredApps, what sets them aside applied);
// the bench only installs it where a remote install would wait for a person at the screen (a device administrator
// without Knox). One source of truth: afterwards the inventory shows the apps and the job sends nothing.
//   provisioningApps   the apps of a provisioning ENROLLED of this station (its device known): 409 not_enrolled
//                      otherwise; for a conversion and a completion an open bench session too (409 no_session): their
//                      device was found by its identity, not by a single-use token; the device still enrolled, a bridge
//                      device not revoked, inside the target of the provisioning (422 device_outside_target), and the
//                      technician of the session holding mdm.bench.operate in its tenant, checked again on every call
//                      (422 target_refused); an open provisioning expires after 120 minutes (bench_expire_open)
//   packageFile        the file of one of THOSE apps (by its SHA-256), nothing else of the store
//   planAppsCompletion « compléter les apps »: a device already enrolled brought back to the bench. The proof of its
//                      identity is described at the function; a kind 'apps' provisioning, enrolled, is created for it.
// =============================================================================

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** The Android ID is comparable below Android 8 (API 26): from 8 on, an app reads a value of its own signing key and the
 *  shell another one. */
export const ANDROID_ID_COMPARABLE_BELOW_SDK = 26;
/** « compléter les apps » per station (the route's): each one searches the station's targets for a serial. */
export const completionLimiter = new WindowLimiter(30, 3_600_000);

export const AppsPlanBody = z.object({
  /** The facts read by ADB, as for a plan (getprop: ro.serialno, ril.serialnumber, the model, the API level). */
  device: PlanBody.shape.device,
  /** `settings get secure android_id` read by ADB (hexadecimal); null when the shell reads none. */
  androidId: z.string().regex(/^[0-9a-fA-F]{1,32}$/).transform((s) => s.toLowerCase()).nullable(),
  /** What the bench channel of the agent answers (content call … --method state), null when it does not answer (an
   *  agent older than 1.4.0). An answer must say the agent is enrolled. */
  agent: z.object({
    phase: z.literal('ENROLLED'),
    role: z.enum(['NONE', 'ADMIN', 'OWNER']),
    versionCode: z.number().int().min(1).max(2_147_483_647),
  }).strict().nullable(),
}).strict();
export type AppsPlanBody = z.infer<typeof AppsPlanBody>;

// ── The apps of a provisioning ───────────────────────────────────────────────

/** The device of a provisioning ready for its apps (its tenant), checked in the provisioning's transaction. */
async function appsDevice(station: StationLookup, id: string): Promise<{ tenantId: number; deviceId: number }> {
  return withProvisioning(station, id, async (trx, p, tenantId) => {
    if (p.state !== 'enrolled' || !p.device_id) throw new AppError(409, 'The device of this provisioning is not enrolled', 'not_enrolled');
    if (p.kind !== 'new') {
      if (sessionUser(station) === null) throw new AppError(409, 'No bench session is open for this station', 'no_session');
      // Its technician answers for it on every call (the session may have changed since the plan, or the right gone):
      // mdm.bench.operate in the provisioning's tenant, which the plan of a conversion or a completion checked once.
      if (!(await technicianMayOperate(station, tenantId))) {
        throw new AppError(422, 'The technician of the session may not enroll into this tenant', 'target_refused');
      }
    }
    const dev = await trx('devices as d')
      .join('legacy_agent_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
      .where({ 'd.tenant_id': tenantId, 'd.id': p.device_id }).first('d.group_id', 'd.enrollment_state', 'd.management_channel', 'a.revoked_at') as
      Record<string, any> | undefined;
    if (!dev || dev.enrollment_state !== 'enrolled' || dev.management_channel !== 'legacy_agent' || dev.revoked_at) {
      throw new AppError(409, 'The device of this provisioning is not enrolled', 'not_enrolled');
    }
    if (dev.group_id === null || !(await groupWithin(trx, tenantId, Number(dev.group_id), Number(p.group_id)))) {
      throw new AppError(422, 'This device is managed outside the target group', 'device_outside_target');
    }
    return { tenantId, deviceId: Number(p.device_id) };
  });
}

/** GET /v1/provisionings/:id/apps: the required apps the bench installs on the device of this provisioning. */
export async function provisioningApps(station: StationLookup, id: string): Promise<{ tenantId: number; deviceId: number; items: BenchRequiredAppView[] }> {
  const { tenantId, deviceId } = await appsDevice(station, id);
  const { items } = await asTenant(tenantId, stationActor(station.id), () => benchRequiredApps(tenantId, deviceId));
  return { tenantId, deviceId, items };
}

/** The file of an app of the list of this provisioning (null: not one of them). */
export async function packageFile(station: StationLookup, id: string, sha256: string): Promise<{ tenantId: number; deviceId: number; app: BenchRequiredAppView; file: string } | null> {
  const { tenantId, deviceId, items } = await provisioningApps(station, id);
  const app = items.find((a) => a.sha256 === sha256);
  return app ? { tenantId, deviceId, app, file: path.join(apkDir(), `${app.sha256}.apk`) } : null;
}

// ── « Compléter les apps » ───────────────────────────────────────────────────

interface Candidate {
  tenantId: number; tenantName: string; groupId: number; deviceId: number; uuid: string; label: string | null; siteId: string | null;
  androidId: string | null; apiLevel: number | null; deviceOwner: boolean; serialPairs: number;
}

/** The serial pairs of the bench against the record of a bridge device, by nature, as benchIdentity (enrollment.ts):
 *  the ADB serial (ro.serialno) against Build.SERIAL the agent declared, ril.serialnumber against the samsungSerial the
 *  agent declared. Never devices.serial_number: it holds samsungSerial ?? Build.SERIAL (legacyAgent/enroll.ts), so
 *  without a samsungSerial it is a ro.serialno, which would be compared with a ril.serialnumber. The count of comparable
 *  pairs that agree, -1 when a comparable pair differs. The configuration's hints are not a proof (they come from a
 *  bench or a console, not from the device). */
export function serialPairsAgreeing(bench: { adb: string | null; hw: string | null },
  record: { claimedSerial: string | null; samsungSerial: string | null }): number {
  const pairs: Array<[string | null, string | null]> = [
    [bench.adb, comparableSerial(record.claimedSerial)],
    [bench.hw, comparableSerial(record.samsungSerial)],
  ];
  const comparable = pairs.filter(([a, b]) => a !== null && b !== null);
  if (comparable.some(([a, b]) => a !== b)) return -1;
  return comparable.length;
}

/** The bridge devices of one tenant of the station that agree with the serials, each inside one of its targets. */
async function candidatesIn(trx: Knex.Transaction, tenantId: number, tenantName: string, targetGroups: number[],
  adb: string | null, hw: string | null): Promise<Candidate[]> {
  const rows = await trx('devices as d')
    .join('legacy_agent_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).where('d.enrollment_state', 'enrolled').where('d.management_channel', 'legacy_agent').whereNull('a.revoked_at')
    .where((w) => {
      if (adb) w.orWhereRaw('upper(a.claimed_serial) = ?', [adb]);
      if (hw) w.orWhereRaw('upper(a.samsung_serial) = ?', [hw]);
    })
    .limit(10)
    .select('d.id', 'd.uuid', 'd.group_id', 'd.label', 'd.site_id', 'a.claimed_serial', 'a.samsung_serial', 'a.android_id',
      'a.api_level', 'a.device_owner') as Array<Record<string, any>>;
  const out: Candidate[] = [];
  for (const r of rows) {
    const serialPairs = serialPairsAgreeing({ adb, hw }, { claimedSerial: r.claimed_serial ?? null, samsungSerial: r.samsung_serial ?? null });
    if (serialPairs < 1 || r.group_id === null) continue;
    // Inside a target: its group itself first, else the first target above the device's group.
    let groupId: number | null = targetGroups.includes(Number(r.group_id)) ? Number(r.group_id) : null;
    for (const g of targetGroups) {
      if (groupId !== null) break;
      if (await groupWithin(trx, tenantId, Number(r.group_id), g)) groupId = g;
    }
    if (groupId === null) continue;
    out.push({
      tenantId, tenantName, groupId, deviceId: Number(r.id), uuid: String(r.uuid), label: r.label ?? null, siteId: r.site_id ? String(r.site_id) : null,
      androidId: r.android_id ? String(r.android_id).toLowerCase() : null, apiLevel: r.api_level === null || r.api_level === undefined ? null : Number(r.api_level),
      deviceOwner: r.device_owner === true, serialPairs,
    });
  }
  return out;
}

/** The verdict of the Android ID and of the API level on the one device found (pure). */
export function completionProof(c: { androidId: string | null; apiLevel: number | null }, b: { androidId: string | null; sdkInt: number }):
  { ok: true; androidId: 'matched' | 'not_comparable' } | { ok: false; reason: 'android_id' | 'sdk' } {
  // The API level the server knows decides (never the one the station claims): an OS is never downgraded.
  if (c.apiLevel !== null && b.sdkInt < c.apiLevel) return { ok: false, reason: 'sdk' };
  if (!c.androidId) return { ok: true, androidId: 'not_comparable' };
  const matched = b.androidId !== null && b.androidId === c.androidId;
  // An Android ID known without an API level (an agent that never sent one): fail closed, the station's sdkInt never
  // decides that the value is not comparable. It must match (refused otherwise, even on Android 8 or later).
  if (c.apiLevel === null || c.apiLevel < ANDROID_ID_COMPARABLE_BELOW_SDK) {
    return matched ? { ok: true, androidId: 'matched' } : { ok: false, reason: 'android_id' };
  }
  return { ok: true, androidId: 'not_comparable' };
}

/**
 * POST /v1/provisionings/apps: « compléter les apps » of a device already enrolled. The proof of its identity, each
 * condition necessary:
 *   1. an open bench session (its technician, signed in with a second factor, answers for it) whose technician may
 *      enroll into the tenant found (mdm.bench.operate); 30 completions per hour and station;
 *   2. the serials read by ADB (ro.serialno, ril.serialnumber) against what THE AGENT declared of the device (Build.SERIAL,
 *      ril.serialnumber, never a hint of a configuration), by pairs of the same nature: at least one comparable pair
 *      agrees, none differs;
 *   3. the device searched only in the tenants of the station's targets (tenant context each, never another tenant's
 *      rows), enrolled, a bridge device not revoked, inside a target group; exactly one (two: 409 identity_ambiguous);
 *   4. below Android 8 (the API level the SERVER knows; unknown with an Android ID known: compared too), the Android ID the shell reads (settings get secure android_id)
 *      equals the one the agent reported: a value seen only by ADB on an authorised computer or by an app of the device,
 *      never printed; from Android 8 it is not comparable (said in the answer) and 1 to 3 carry the proof;
 *   5. the API level read is not below the server's.
 * Anything else answers 404 device_not_found, the same for a serial unknown, outside the targets or held in another
 * tenant (that one goes to the audit of the platform only): no answer tells another tenant's device. A device found in a
 * tenant where the technician may not operate answers the same 404 (no oracle of what is enrolled there), audited in
 * that tenant (bench.identity_probe_refused). A contradiction of
 * 4 or 5 is 409 identity_mismatch, audited in the tenant (protective). The bench channel of the agent (phase ENROLLED,
 * its role and version) is required when it answers but proves nothing by itself: the shell can fake no device, but a
 * station could fake its words.
 */
export async function planAppsCompletion(station: StationLookup, b: AppsPlanBody, origin: Origin): Promise<BenchAppsPlanAnswer> {
  const technician = sessionUser(station);
  if (technician === null) throw new AppError(409, 'No bench session is open for this station', 'no_session');
  const adbRaw = b.device.adbSerial;
  const open = await asNone(stationActor(station.id), () => db.raw('SELECT id FROM obligarth.bench_open_provisioning_of(?::uuid, ?)', [station.id, adbRaw])) as
    { rows: Array<{ id: string }> };
  if (open.rows[0]) {
    throw new AppError(409, 'This device has an open provisioning on this station', 'open_provisioning', { provisioningId: String(open.rows[0].id) });
  }
  const adb = comparableSerial(adbRaw);
  const hw = comparableSerial(b.device.hwSerial ?? null);
  const notFound = (): AppError => new AppError(404, 'No device of the station targets answers this identity', 'device_not_found');

  const targets = await stationTargets(station.id);
  const byTenant = new Map<number, { name: string; groups: number[] }>();
  for (const t of targets) {
    const e = byTenant.get(t.tenantId) ?? { name: t.tenantName, groups: [] };
    e.groups.push(t.groupId);
    byTenant.set(t.tenantId, e);
  }
  const candidates: Candidate[] = [];
  if (adb || hw) {
    for (const [tenantId, t] of byTenant) {
      candidates.push(...await asTenant(tenantId, stationActor(station.id), () => db.transaction((trx) => candidatesIn(trx, tenantId, t.name, t.groups, adb, hw))));
    }
  }
  if (candidates.length === 0) {
    // A serial held elsewhere: the audit of the platform only (p_tenant 0: every tenant), never the station's answer.
    const serials = [adb, hw].filter((s): s is string => !!s);
    if (serials.length > 0) {
      const cross = await asNone(stationActor(station.id), () => db.raw('SELECT obligarth.bench_identity_conflict(?::uuid, 0, ?::text[]) AS c',
        [station.id, serials])) as { rows: Array<{ c: boolean }> };
      if (cross.rows[0]?.c === true) {
        await audit.append({
          tenantId: MASTER_TENANT_ID, action: 'bench.identity_conflict_cross_tenant', target: { type: 'bench_station', id: station.id },
          details: { stationId: station.id, kind: 'apps', adbSerial: truncateSerial(adbRaw), hwSerial: truncateSerial(b.device.hwSerial ?? null) },
        }, await stationAuditContext(station.id, station.name, MASTER_TENANT_ID, origin));
      }
    }
    throw notFound();
  }
  if (candidates.length > 1) throw new AppError(409, 'Several devices of the station targets answer this identity', 'identity_ambiguous');
  const c = candidates[0];
  if (!(await technicianMayOperate(station, c.tenantId))) {
    // The same answer as an unknown device (never tell what is enrolled in a tenant the technician has no right in),
    // the probe written to that tenant's audit.
    await audit.append({
      tenantId: c.tenantId, action: 'bench.identity_probe_refused', target: { type: 'bench_station', id: station.id, device: c.deviceId },
      details: {
        kind: 'apps', stationId: station.id, technicianUserId: technician, benchAdbSerial: truncateSerial(adbRaw),
        benchHwSerial: truncateSerial(b.device.hwSerial ?? null),
      },
    }, await stationAuditContext(station.id, station.name, c.tenantId, origin));
    throw notFound();
  }
  const proof = completionProof(c, { androidId: b.androidId, sdkInt: b.device.sdkInt });
  if (!proof.ok) {
    await audit.append({
      tenantId: c.tenantId, action: 'bench.identity_mismatch', target: { type: 'bench_station', id: station.id, device: c.deviceId },
      details: {
        kind: 'apps', reason: proof.reason, stationId: station.id, technicianUserId: technician, benchAdbSerial: truncateSerial(adbRaw),
        benchHwSerial: truncateSerial(b.device.hwSerial ?? null), sdk: b.device.sdkInt,
      },
    }, await stationAuditContext(station.id, station.name, c.tenantId, origin));
    throw new AppError(409, 'The identity read on the bench contradicts the device found', 'identity_mismatch');
  }

  return asTenant(c.tenantId, stationActor(station.id), () => db.transaction(async (trx): Promise<BenchAppsPlanAnswer> => {
    if (!(await targetIn(trx, station.id, c.tenantId, c.groupId))) throw notFound();
    const site = c.siteId ? await trx('sites').where({ tenant_id: c.tenantId, id: c.siteId }).first('id', 'code', 'name') as
      { id: string; code: string; name: string } | undefined : undefined;
    const roleTarget = c.deviceOwner ? 'device_owner' : 'device_admin';
    const deviceName = c.label ? c.label.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 100) || null : null;
    const [row] = await trx('bench_provisionings').insert({
      tenant_id: c.tenantId, group_id: c.groupId, station_id: station.id, session_id: station.session!.id, kind: 'apps', state: 'enrolled',
      adb_serial: adbRaw, hw_serial: b.device.hwSerial ?? null, model: b.device.model, manufacturer: b.device.manufacturer, sdk_int: b.device.sdkInt,
      os_release: b.device.osRelease ?? null, one_ui: b.device.oneUi ?? null, device_name: deviceName, role_target: roleTarget,
      preflight: JSON.stringify({}), device_id: c.deviceId, site_id: site ? String(site.id) : null,
    }).returning(['id']) as Array<{ id: string }>;
    const id = String(row.id).toLowerCase();
    // Written before the answer, in the provisioning's transaction: no completion without its trace.
    await audit.appendInTx(trx, {
      tenantId: c.tenantId, action: 'bench.provisioning_planned', target: { type: 'bench_provisioning', id, device: c.deviceId },
      details: {
        provisioningId: id, stationId: station.id, kind: 'apps', adbSerial: truncateSerial(adbRaw), hwSerial: truncateSerial(b.device.hwSerial ?? null),
        model: b.device.model, sdk: b.device.sdkInt, roleTarget, groupId: c.groupId, warnings: [], ...(site ? { siteId: String(site.id) } : {}),
        proof: { serialPairs: c.serialPairs, androidId: proof.androidId, agentChannel: b.agent ? b.agent.role : null }, technicianUserId: technician,
      },
    }, await stationAuditContext(station.id, station.name, c.tenantId, origin));
    return {
      provisioningId: id, kind: 'apps', tenantId: c.tenantId, tenantName: c.tenantName, groupId: c.groupId, deviceUuid: c.uuid, deviceName,
      site: site ? { id: String(site.id), code: String(site.code), name: String(site.name) } : null, roleTarget,
      proof: { serialPairs: c.serialPairs, androidId: proof.androidId },
    };
  })).catch((err) => {
    if ((err as { code?: string; constraint?: string })?.code === '23505' && /bench_provisionings_open/.test(String((err as { constraint?: string }).constraint ?? ''))) {
      throw new AppError(409, 'This device has an open provisioning on this station', 'open_provisioning');
    }
    throw err;
  });
}

export const isProvisioningId = (s: string): boolean => UUID_RE.test(s);

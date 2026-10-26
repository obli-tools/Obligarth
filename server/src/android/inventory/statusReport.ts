// Handler of the STATUS_REPORT notifications (amapi.status_report, sections 8.1 to 8.4, 9.4 step 5; criterion 6).
// Monotonic: a report older than the last one applied only moves last_checkin_at (maximum). Otherwise: the satellite
// (state, applied policy, posture, normalised non-compliance, API level, patch level, filtered inventory), the columns
// of devices that changed, the apps (the set of the report: upserted, the absent ones deleted; Google reports the work
// profile only; managed when the effective settings deliver them), the state of the
// device's policy (applied when the applied version reaches the pushed one without a non-compliance of the policy;
// error with <reason>:<setting> otherwise; PENDING stays delivering), then the compliance. A report of a device the
// instance does not know yet waits for its ENROLLMENT (MissingPrerequisite); one of a quarantined device is ignored.
// §8.3 (lot AN-C1): a report that changes the Android version or the API level asks for the resolution of the device
// (mdm.policies.resolve-device: the availability of its settings) and for the push of its own policy (the compiler
// checks each field against the API level: a field that becomes available is pushed, nothing when the policy is
// unchanged); the management mode of an AMAPI device never changes.
// No network call (G-A3); identifiers only in the real-time events and the alerts (G-A4).
import type { z } from 'zod';
import { raiseAndroidTenantAlert } from '../alerts';
import { MissingPrerequisite, registerAndroidEventHandler, type AndroidEventContext } from '../inbox/handlers';
import { DeviceSchema } from '../inbox/schemas';
import { evaluateAndroidDevices } from './compliance';
import { filterInventory } from './privacy';
import { byodApps } from '../byod/policy';
import { policyArtifactHash, syncPolicyArtifact } from '../policies/channel';
import { appsMerge } from '../../mdm/inventory/appMerge';
import { rollupConfigState } from '../../mdm/policies/artifacts';
import { requestDeviceResolution } from '../../mdm/policies/triggers';
import { androidSenders } from '../enrollment/senders';

type Device = z.infer<typeof DeviceSchema>;
type Ctx = AndroidEventContext<Device>;

const MAX_NON_COMPLIANCE = 50;
const str = (v: unknown, max: number): string | undefined => (typeof v === 'string' && v ? v.slice(0, max) : undefined);

/** nonComplianceDetails normalised (section 8.4): { settingName, nonComplianceReason, packageName?, fieldPath?, specificReason? }. */
export function normaliseNonCompliance(list: unknown): Array<Record<string, string>> {
  if (!Array.isArray(list)) return [];
  const out: Array<Record<string, string>> = [];
  for (const x of list) {
    if (!x || typeof x !== 'object') continue;
    const o = x as Record<string, unknown>;
    const e: Record<string, string> = {};
    const s = str(o.settingName, 120); if (s) e.settingName = s;
    const r = str(o.nonComplianceReason, 60); if (r) e.nonComplianceReason = r;
    const p = str(o.packageName, 255); if (p) e.packageName = p;
    const f = str(o.fieldPath, 200); if (f) e.fieldPath = f;
    const sr = str(o.specificNonComplianceReason, 80); if (sr) e.specificReason = sr;
    if (Object.keys(e).length) out.push(e);
    if (out.length >= MAX_NON_COMPLIANCE) break;
  }
  return out;
}

/** securityPosture reduced to { devicePosture, risks[] } (the risk types only). */
export function reducePosture(p: unknown): { devicePosture: string; risks: string[] } | null {
  if (!p || typeof p !== 'object') return null;
  const o = p as Record<string, unknown>;
  const posture = str(o.devicePosture, 40);
  if (!posture) return null;
  const risks = Array.isArray(o.postureDetails)
    ? [...new Set(o.postureDetails.map((d) => str((d as Record<string, unknown>)?.securityRisk, 60)).filter((x): x is string => !!x))].slice(0, 20)
    : [];
  return { devicePosture: posture, risks };
}

const time = (v: unknown): Date | null => (typeof v === 'string' && Number.isFinite(Date.parse(v)) ? new Date(v) : null);

export async function onStatusReport(ctx: Ctx): Promise<'applied' | 'stale' | 'ignored'> {
  const { trx, tenantId } = ctx;
  const d = ctx.event.payload;
  const row = await trx('android_devices as a').join('devices as dv', function j() { this.on('dv.id', '=', 'a.device_id').andOn('dv.tenant_id', '=', 'a.tenant_id'); })
    .where('a.amapi_name', d.name).whereNull('a.released_at')
    .first('a.device_id', 'a.last_status_report_at', 'a.pushed_policy_version', 'a.policy_state', 'a.policy_name', 'a.api_level', 'a.approval_state',
      'dv.ownership', 'dv.serial_number', 'dv.last_checkin_at', 'dv.os_version') as
    Record<string, any> | undefined;
  if (!row) {
    const q = await trx('android_quarantine').where({ amapi_name: d.name }).first('id');
    if (q) return 'ignored';
    throw new MissingPrerequisite('device not enrolled yet');
  }
  const deviceId = Number(row.device_id);
  const reportAt = time(d.lastStatusReportTime) ?? ctx.event.occurredAt;
  const checkin = (prev: unknown) => (!prev || new Date(prev as string).getTime() < reportAt.getTime() ? { last_checkin_at: reportAt } : {});
  if (row.last_status_report_at && new Date(row.last_status_report_at).getTime() >= reportAt.getTime()) {
    const c = checkin(row.last_checkin_at);
    if (Object.keys(c).length) await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update(c);
    return 'stale';
  }
  const ownership = String(row.ownership);
  const inv = filterInventory(d as Record<string, unknown>, ownership);
  const nonCompliance = normaliseNonCompliance(d.nonComplianceDetails);
  const posture = reducePosture((d as Record<string, unknown>).securityPosture);
  const applied = d.appliedPolicyVersion !== undefined && Number.isFinite(Number(d.appliedPolicyVersion)) ? Number(d.appliedPolicyVersion) : null;
  const pushed = row.pushed_policy_version === null ? null : Number(row.pushed_policy_version);
  // State of the device's policy (section 9.4 step 5).
  let policyState: string = row.policy_state;
  let reasons: string[] | null = null;
  const policyIssues = nonCompliance.filter((n) => n.nonComplianceReason && n.nonComplianceReason !== 'PENDING');
  const appliedName = typeof d.appliedPolicyName === 'string' ? d.appliedPolicyName.split('/').pop() : undefined;
  if (pushed !== null && row.policy_state !== 'error') {
    if (policyIssues.length) {
      policyState = 'error';
      reasons = policyIssues.map((n) => `${n.nonComplianceReason}:${n.settingName ?? ''}`).slice(0, 20);
    } else if (applied !== null && applied >= pushed && (!appliedName || appliedName === row.policy_name)) {
      policyState = 'applied';
      reasons = [];
    }
  } else if (pushed !== null && row.policy_state === 'error' && applied !== null && applied >= pushed && !policyIssues.length) {
    policyState = 'applied';
    reasons = [];
  }
  await trx('android_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({
    state: str(d.state, 32) ?? null, applied_state: str(d.appliedState, 32) ?? null, applied_policy_version: applied,
    security_posture: posture ? JSON.stringify(posture) : null, non_compliance: JSON.stringify(nonCompliance),
    policy_compliant: typeof (d as Record<string, unknown>).policyCompliant === 'boolean' ? (d as Record<string, unknown>).policyCompliant : null,
    api_level: inv.apiLevel, security_patch_level: inv.securityPatchLevel, last_status_report_at: reportAt,
    last_policy_sync_at: time(d.lastPolicySyncTime), previous_device_names: (d.previousDeviceNames ?? []).slice(0, 100),
    hardware_info: inv.hardwareInfo ? JSON.stringify(inv.hardwareInfo) : null, software_info: JSON.stringify(inv.softwareInfo),
    network_info: inv.networkInfo ? JSON.stringify(inv.networkInfo) : null, policy_state: policyState,
    ...(reasons !== null ? { policy_state_reasons: JSON.stringify(reasons) } : {}), updated_at: trx.fn.now(),
  });
  const cols: Record<string, unknown> = { ...checkin(row.last_checkin_at) };
  if (inv.model) cols.model = inv.model;
  if (inv.brand && inv.model) cols.model_name = `${inv.brand} ${inv.model}`.slice(0, 128);
  if (inv.osVersion) cols.os_version = inv.osVersion;
  if (inv.osBuild) cols.os_build = inv.osBuild;
  if (ownership !== 'personal') {
    if (inv.storageTotal !== null) cols.storage_capacity_bytes = inv.storageTotal;
    if (inv.storageAvailable !== null) cols.storage_available_bytes = inv.storageAvailable;
  }
  cols.config_state = policyState === 'applied' ? 'applied' : policyState === 'error' ? 'error' : 'pending';
  await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update(cols);
  // Lot AN-P: the state of the policy on the artifact amapi:policy when the version pushed is the one desired; the
  // aggregate state then follows the artifacts of the device (a desired version not pushed yet keeps it pending).
  if (await policyArtifactHash(trx, tenantId, deviceId)) {
    await syncPolicyArtifact(trx, tenantId, deviceId, { delivered: true });
    await rollupConfigState(trx, [deviceId]);
  }
  // Apps: the set of the report (source amapi_report); Google reports the work profile only (AMAPI-R20). A personal
  // device keeps the apps of the tenant's catalog only (lot AN-F1, criterion 6): never a personal app, whatever the
  // report carries. A COPE device (work profile on a company device) too (lot AN-F2, section 10.5: « apps
  // personnelles jamais inventoriées »): its personal profile is the employee's.
  let apps = inv.apps;
  if ((ownership === 'personal' || ownership === 'corporate_personal') && apps.length) {
    const catalog = new Set(await trx('apps').where({ tenant_id: tenantId, platform_family: 'android' }).whereNull('archived_at')
      .whereIn('identifier', apps.map((a) => a.identifier)).pluck('identifier') as string[]);
    apps = byodApps(apps, catalog);
  }
  // Upserted (first_seen_at and version_changed_at survive a report), the absent ones deleted. Managed: an app the
  // device's effective settings deliver (android:app[<package>], available: a setting not applicable never reaches the
  // policy, mdm/android/compile.ts), not every app Google reports.
  const keep = apps.map((a) => a.identifier);
  const gone = trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId });
  if (keep.length) gone.whereNotIn('identifier', keep);
  await gone.delete();
  if (apps.length) {
    const delivered = new Set((await trx('device_effective_settings').where({ tenant_id: tenantId, device_id: deviceId, removed: false, availability: 'available' })
      .where('setting_key', 'like', 'android:app[%').pluck('setting_key') as string[]).map((k) => k.slice('android:app['.length, -1)));
    const at = new Date();
    for (let i = 0; i < apps.length; i += 500) {
      await trx('device_apps').insert(apps.slice(i, i + 500).map((a) => ({
        tenant_id: tenantId, device_id: deviceId, identifier: a.identifier, name: a.name, version: a.version, short_version: a.shortVersion,
        managed: delivered.has(a.identifier), management_status: a.state, is_system: a.isSystem, installer: a.installer, source: 'amapi_report',
        first_seen_at: at, last_seen_at: at,
      }))).onConflict(['tenant_id', 'device_id', 'identifier'])
        .merge(appsMerge(trx, ['name', 'version', 'short_version', 'managed', 'management_status', 'is_system', 'installer', 'source', 'last_seen_at']));
    }
  }
  // §8.3: the facts the availability depends on changed (an upgrade): resolution of the device and push of its policy.
  const apiChanged = inv.apiLevel !== null && inv.apiLevel !== undefined && row.api_level !== null && Number(row.api_level) !== Number(inv.apiLevel);
  const osChanged = !!inv.osVersion && !!row.os_version && String(row.os_version) !== String(inv.osVersion);
  if (apiChanged || osChanged) {
    await requestDeviceResolution(trx, tenantId, [deviceId]);
    if (row.policy_name && row.approval_state !== 'pending') await androidSenders.push(trx, { tenantId, deviceId });
  }
  const evaluation = await evaluateAndroidDevices(trx, tenantId, [deviceId]);
  for (const id of evaluation.atRisk) ctx.afterCommit(() => raiseAndroidTenantAlert(tenantId, 'android.integrity_compromised', { deviceId: id }));
  return 'applied';
}

let registered = false;

export function registerStatusReportHandler(): void {
  if (registered) return;
  registered = true;
  registerAndroidEventHandler({
    type: 'amapi.status_report',
    payload: DeviceSchema,
    async handle(ctx) { await onStatusReport(ctx); },
  });
}

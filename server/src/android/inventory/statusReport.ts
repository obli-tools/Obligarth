// Handler of the STATUS_REPORT notifications (amapi.status_report, sections 8.1 to 8.4, 9.4 step 5; criterion 6).
// Monotonic: a report older than the last one applied only moves last_checkin_at (maximum). Otherwise: the satellite
// (state, applied policy, posture, normalised non-compliance, API level, patch level, filtered inventory), the columns
// of devices that changed, the apps (the whole set replaced; Google reports the work profile only), the state of the
// device's policy (applied when the applied version reaches the pushed one without a non-compliance of the policy;
// error with <reason>:<setting> otherwise; PENDING stays delivering), then the compliance. A report of a device the
// instance does not know yet waits for its ENROLLMENT (MissingPrerequisite); one of a quarantined device is ignored.
// No network call (G-A3); identifiers only in the real-time events and the alerts (G-A4).
import type { z } from 'zod';
import { raiseAndroidTenantAlert } from '../alerts';
import { MissingPrerequisite, registerAndroidEventHandler, type AndroidEventContext } from '../inbox/handlers';
import { DeviceSchema } from '../inbox/schemas';
import { evaluateAndroidDevices } from './compliance';
import { filterInventory } from './privacy';

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
    .first('a.device_id', 'a.last_status_report_at', 'a.pushed_policy_version', 'a.policy_state', 'a.policy_name', 'dv.ownership', 'dv.serial_number', 'dv.last_checkin_at') as
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
  // Apps: the whole set replaced (source amapi_report); Google reports the work profile only (AMAPI-R20).
  await trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId }).delete();
  if (inv.apps.length) {
    await trx('device_apps').insert(inv.apps.map((a) => ({
      tenant_id: tenantId, device_id: deviceId, identifier: a.identifier, name: a.name, version: a.version, short_version: a.shortVersion,
      managed: true, management_status: a.state, source: 'amapi_report',
    })));
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

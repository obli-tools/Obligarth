// Compliance of an Android device (section 8.4, AN20): the reasons of the channel amapi, written in
// devices.compliance_state and compliance_reasons like the common minimal evaluator writes them for Apple
// (mdm/compliance/evaluate.ts, an existing file: at the junction AN-A2, evaluateDevices sends the devices of the
// channel amapi here instead of evaluating them with the Apple facts, and 'mdm.compliance.evaluate-all' covers them).
//   os_outdated          security patch level older than the tenant's threshold (in days; null: not checked)
//   amapi_noncompliant   nonComplianceDetails, out of PENDING and of the tolerated reasons (APP_NOT_INSTALLED of an
//                        app offered as AVAILABLE)
//   integrity_at_risk    securityPosture.devicePosture AT_RISK or POTENTIALLY_COMPROMISED (tenant alert)
//   no_contact           no status report beyond mdmStaleAfterDays (none at all 24 h after the enrollment)
//   policy_not_applied   appliedPolicyVersion below the pushed version for more than 24 hours
//   management_disabled  Device.state DISABLED
// The reasons carry codes, setting names and counters only: never an inventory value nor a personal datum.
import type { Knex } from 'knex';
import { MDM_STALE_AFTER_DAYS_DEFAULT, SETTINGS_KEYS } from '@obligarth/shared';

export type AndroidComplianceCode = 'os_outdated' | 'amapi_noncompliant' | 'integrity_at_risk' | 'no_contact' | 'policy_not_applied'
  | 'management_disabled';

export interface AndroidComplianceReason { code: AndroidComplianceCode; detail?: Record<string, string | number | null> }

export interface AndroidComplianceFacts {
  state: string | null;
  enrolledAt: Date | null;
  lastStatusReportAt: Date | null;
  lastCheckinAt: Date | null;
  securityPatchLevel: string | null;
  nonCompliance: Array<{ settingName?: string; nonComplianceReason?: string; packageName?: string }>;
  devicePosture: string | null;
  pushedVersion: number | null;
  appliedVersion: number | null;
  pushedAt: Date | null;
  staleAfterDays: number;
  /** Patch level age in days beyond which the device is outdated; null: no threshold. */
  patchMaxAgeDays: number | null;
  /** Packages offered as AVAILABLE (APP_NOT_INSTALLED tolerated for them). */
  availablePackages: ReadonlySet<string>;
}

export interface AndroidComplianceVerdict { state: 'unknown' | 'compliant' | 'non_compliant'; reasons: AndroidComplianceReason[] }

const DAY_MS = 86_400_000;
const RISKY = new Set(['AT_RISK', 'POTENTIALLY_COMPROMISED']);

/** Pure verdict of one device. */
export function evaluateAndroidCompliance(f: AndroidComplianceFacts, now: Date): AndroidComplianceVerdict {
  const reasons: AndroidComplianceReason[] = [];
  if (f.patchMaxAgeDays !== null && f.securityPatchLevel) {
    const t = Date.parse(`${f.securityPatchLevel}T00:00:00Z`);
    if (Number.isFinite(t) && now.getTime() - t > f.patchMaxAgeDays * DAY_MS) {
      reasons.push({ code: 'os_outdated', detail: { securityPatchLevel: f.securityPatchLevel } });
    }
  }
  const relevant = f.nonCompliance.filter((n) => n.nonComplianceReason !== 'PENDING'
    && !(n.nonComplianceReason === 'APP_NOT_INSTALLED' && n.packageName && f.availablePackages.has(n.packageName)));
  if (relevant.length) {
    const names = [...new Set(relevant.map((n) => String(n.settingName ?? '')).filter(Boolean))].sort();
    reasons.push({ code: 'amapi_noncompliant', detail: { count: relevant.length, settings: names.slice(0, 5).join(', ').slice(0, 300) } });
  }
  if (f.devicePosture && RISKY.has(f.devicePosture)) reasons.push({ code: 'integrity_at_risk', detail: { posture: f.devicePosture } });
  const last = f.lastStatusReportAt ?? f.lastCheckinAt;
  if (last ? now.getTime() - last.getTime() > f.staleAfterDays * DAY_MS : (f.enrolledAt !== null && now.getTime() - f.enrolledAt.getTime() > DAY_MS)) {
    reasons.push({ code: 'no_contact', detail: { lastStatusReportAt: last ? last.toISOString() : null } });
  }
  if (f.pushedVersion !== null && f.pushedAt !== null && (f.appliedVersion === null || f.appliedVersion < f.pushedVersion)
    && now.getTime() - f.pushedAt.getTime() > DAY_MS) {
    reasons.push({ code: 'policy_not_applied', detail: { pushed: f.pushedVersion, applied: f.appliedVersion } });
  }
  if (f.state === 'DISABLED') reasons.push({ code: 'management_disabled' });
  if (reasons.length) return { state: 'non_compliant', reasons };
  return { state: f.lastStatusReportAt ? 'compliant' : 'unknown', reasons: [] };
}

async function staleDays(trx: Knex.Transaction, tenantId: number): Promise<number> {
  const row = await trx('settings').where({ tenant_id: tenantId, scope: 'global', key: SETTINGS_KEYS.MDM_STALE_AFTER_DAYS }).whereNull('scope_id')
    .first('value') as { value: unknown } | undefined;
  const n = typeof row?.value === 'number' ? row.value : typeof row?.value === 'string' ? Number(row.value) : NaN;
  return Number.isInteger(n) && n >= 1 && n <= 90 ? n : MDM_STALE_AFTER_DAYS_DEFAULT;
}

const date = (v: unknown): Date | null => (v ? new Date(v as string) : null);
const num = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));

export interface AndroidEvaluation { changed: number[]; atRisk: number[] }

/**
 * Evaluates the Android devices of the tenant (caller's transaction, tenant context) and writes what changed. A device
 * out of management or exempt is left alone. Returns the devices that changed and those newly at risk (alert).
 */
export async function evaluateAndroidDevices(trx: Knex.Transaction, tenantId: number, deviceIds: number[], o: { now?: Date; patchMaxAgeDays?: number | null } = {}): Promise<AndroidEvaluation> {
  const now = o.now ?? new Date();
  const out: AndroidEvaluation = { changed: [], atRisk: [] };
  const ids = [...new Set(deviceIds.filter((n) => Number.isSafeInteger(n) && n > 0))];
  if (!ids.length) return out;
  const rows = await trx('devices as d').join('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereIn('d.id', ids).whereIn('d.enrollment_state', ['enrolled', 'awaiting_configuration']).whereNull('a.released_at')
    .select('d.id', 'd.compliance_state', 'd.compliance_reasons', 'd.enrolled_at', 'd.last_checkin_at', 'a.state', 'a.last_status_report_at',
      'a.security_patch_level', 'a.non_compliance', 'a.security_posture', 'a.pushed_policy_version', 'a.applied_policy_version', 'a.pushed_at') as
    Array<Record<string, any>>;
  const stale = await staleDays(trx, tenantId);
  for (const r of rows) {
    if (r.compliance_state === 'exempt') continue;
    const posture = r.security_posture && typeof r.security_posture === 'object' ? String(r.security_posture.devicePosture ?? '') || null : null;
    const patch = r.security_patch_level ? new Date(r.security_patch_level).toISOString().slice(0, 10) : null;
    const v = evaluateAndroidCompliance({
      state: r.state ?? null, enrolledAt: date(r.enrolled_at), lastStatusReportAt: date(r.last_status_report_at), lastCheckinAt: date(r.last_checkin_at),
      securityPatchLevel: patch, nonCompliance: Array.isArray(r.non_compliance) ? r.non_compliance : [], devicePosture: posture,
      pushedVersion: num(r.pushed_policy_version), appliedVersion: num(r.applied_policy_version), pushedAt: date(r.pushed_at),
      staleAfterDays: stale, patchMaxAgeDays: o.patchMaxAgeDays ?? null, availablePackages: new Set(),
    }, now);
    const before = JSON.stringify(Array.isArray(r.compliance_reasons) ? r.compliance_reasons : []);
    const after = JSON.stringify(v.reasons);
    if (r.compliance_state === v.state && before === after) continue;
    await trx('devices').where({ tenant_id: tenantId, id: r.id }).update({
      compliance_state: v.state, compliance_reasons: after, compliance_evaluated_at: now,
    });
    out.changed.push(Number(r.id));
    const wasAtRisk = before.includes('"integrity_at_risk"');
    if (!wasAtRisk && v.reasons.some((x) => x.code === 'integrity_at_risk')) out.atRisk.push(Number(r.id));
  }
  return out;
}

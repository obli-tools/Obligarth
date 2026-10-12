import type { Knex } from 'knex';
import {
  MDM_STALE_AFTER_DAYS_DEFAULT, SETTINGS_KEYS, contactState, versionNum,
  type ComplianceReason, type ComplianceState,
} from '@obligarth/shared';
import { canonicalJson } from '../../audit/canonical';

// =============================================================================
// Minimal compliance (docs: modele-donnees-mdm §4.4; the compliance engine is
// v1, SEC-09): built-in reasons, without escalation nor action, that serve the
// lists of the console.
//   config_error          an artifact of the device is in error
//   passcode              a passcode policy is applied, and the device reports
//                         no passcode, or one that does not comply
//   os_update_overdue     an enforced update whose deadline passed more than
//                         24 hours ago, the OS still below its target
//   stale                 no contact beyond the tenant's threshold, or none at
//                         all 24 hours after the enrollment
//   supervision_required  a company device with personal use (COPE) found not
//                         supervised by its inventory
// non_compliant with one reason at least; compliant with none and an
// inventory; unknown otherwise. 'exempt' (a manual exemption, v1) is never
// touched. The reasons carry identifiers of artifacts, versions and dates:
// never a value of the inventory nor a personal datum.
// evaluateCompliance is pure; evaluateDevices reads the facts of devices in
// bulk and writes what changed, in the caller's transaction (the tenant's).
// =============================================================================

export interface ComplianceFacts {
  enrollmentState: string;
  ownership: string;
  supervised: boolean;
  osVersion: string | null;
  lastCheckinAt: Date | null;
  enrolledAt: Date | null;
  configState: string;
  /** apple_devices.last_device_info_at: null until a first DeviceInformation. */
  lastDeviceInfoAt: Date | null;
  staleAfterDays: number;
  /** Artifact keys in error. */
  errorArtifacts: string[];
  /** A passcode policy (declaration or payload) is applied on the device. */
  passcodePolicyApplied: boolean;
  /** passcode.is-present and passcode.is-compliant as the device reports them; null: not reported. */
  passcodeIsPresent: boolean | null;
  passcodeIsCompliant: boolean | null;
  /** The enforced updates of the device (softwareupdate.enforcement.specific). */
  enforcements: Array<{ targetOsVersion: string; targetLocalDateTime: string }>;
}

export interface ComplianceVerdict { state: ComplianceState; reasons: ComplianceReason[] }

const DAY_MS = 86_400_000;

/** A deadline of an enforced update (the device's local time, without zone): read as UTC; the 24 hours of the
 *  rule cover any time zone. null when unreadable. */
function deadlineOf(s: string): number | null {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?/.test(s)) return null;
  const t = Date.parse(/(Z|[+-]\d{2}:\d{2})$/.test(s) ? s : `${s}Z`);
  return Number.isFinite(t) ? t : null;
}

/** The compliance of a device from its facts (section 4.4). */
export function evaluateCompliance(f: ComplianceFacts, now: Date): ComplianceVerdict {
  if (f.enrollmentState !== 'enrolled' && f.enrollmentState !== 'awaiting_configuration') return { state: 'unknown', reasons: [] };
  const reasons: ComplianceReason[] = [];
  if (f.configState === 'error') {
    const keys = [...f.errorArtifacts].sort();
    reasons.push({ code: 'config_error', detail: { count: keys.length, artifacts: keys.slice(0, 5).join(', ').slice(0, 400) } });
  }
  if (f.passcodePolicyApplied && (f.passcodeIsPresent === false || f.passcodeIsCompliant === false)) {
    reasons.push({ code: 'passcode', detail: { isPresent: f.passcodeIsPresent, isCompliant: f.passcodeIsCompliant } });
  }
  const os = versionNum(f.osVersion);
  const overdue = f.enforcements
    .map((e) => ({ e, deadline: deadlineOf(e.targetLocalDateTime), target: versionNum(e.targetOsVersion) }))
    .filter((x) => x.deadline !== null && x.target !== null && now.getTime() - x.deadline > DAY_MS && os !== null && os < x.target)
    .sort((a, b) => (a.deadline as number) - (b.deadline as number))[0];
  if (overdue) {
    reasons.push({ code: 'os_update_overdue', detail: { target: overdue.e.targetOsVersion.slice(0, 32), deadline: overdue.e.targetLocalDateTime.slice(0, 32) } });
  }
  const contact = contactState(f.lastCheckinAt, now, f.staleAfterDays);
  if (contact === 'stale' || (contact === 'never' && f.enrolledAt !== null && now.getTime() - f.enrolledAt.getTime() > DAY_MS)) {
    reasons.push({ code: 'stale', detail: { lastCheckinAt: f.lastCheckinAt ? f.lastCheckinAt.toISOString() : null } });
  }
  if (f.ownership === 'corporate_personal' && !f.supervised && f.lastDeviceInfoAt !== null) reasons.push({ code: 'supervision_required' });
  if (reasons.length > 0) return { state: 'non_compliant', reasons };
  return { state: f.lastDeviceInfoAt !== null ? 'compliant' : 'unknown', reasons: [] };
}

const PASSCODE_ARTIFACTS = ['ddm:obg.cfg.pol-passcode.settings', 'profile:tools.obli.obligarth.p.mobiledevice.passwordpolicy'];
const ENFORCEMENT_PREFIX = 'ddm:obg.cfg.pol-softwareupdate.enforcement.specific';

const parse = <T>(v: unknown, fallback: T): T => {
  if (v === null || v === undefined) return fallback;
  if (typeof v !== 'string') return v as T;
  try { return JSON.parse(v) as T; } catch { return fallback; }
};
const date = (v: unknown): Date | null => (v ? new Date(v as string) : null);

/** mdmStaleAfterDays of the tenant (1 to 90 days; the default without a value). */
async function staleDays(trx: Knex.Transaction, tenantId: number): Promise<number> {
  const row = await trx('settings').where({ tenant_id: tenantId, scope: 'global', key: SETTINGS_KEYS.MDM_STALE_AFTER_DAYS }).whereNull('scope_id')
    .first('value') as { value: unknown } | undefined;
  const n = typeof row?.value === 'number' ? row.value : typeof row?.value === 'string' ? Number(row.value) : NaN;
  return Number.isInteger(n) && n >= 1 && n <= 90 ? n : MDM_STALE_AFTER_DAYS_DEFAULT;
}

export interface EvaluationSummary { evaluated: number; changed: number[] }

/**
 * Evaluates the compliance of devices of the tenant and writes the state and the reasons of those that changed
 * (compliance_evaluated_at dates the last change). In the caller's transaction and the tenant's context. A device
 * out of management, or exempt, is left as it is.
 */
export async function evaluateDevices(trx: Knex.Transaction, tenantId: number, deviceIds: number[], now = new Date()): Promise<EvaluationSummary> {
  const ids = [...new Set(deviceIds.filter((n) => Number.isSafeInteger(n) && n > 0))].sort((a, b) => a - b);
  const out: EvaluationSummary = { evaluated: 0, changed: [] };
  if (ids.length === 0) return out;
  const devices = await trx('devices as d')
    .leftJoin('apple_devices as a', function joinSat() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where('d.tenant_id', tenantId).whereRaw('d.id = ANY (?::int[])', [ids]).whereIn('d.enrollment_state', ['enrolled', 'awaiting_configuration'])
    .select('d.id', 'd.enrollment_state', 'd.ownership', 'd.supervised', 'd.os_version', 'd.last_checkin_at', 'd.enrolled_at', 'd.config_state',
      'd.compliance_state', 'd.compliance_reasons', 'a.last_device_info_at') as Array<Record<string, any>>;
  if (devices.length === 0) return out;
  const live = devices.map((d) => Number(d.id));
  const staleAfterDays = await staleDays(trx, tenantId);
  const status = await trx('device_status_items').where({ tenant_id: tenantId }).whereRaw('device_id = ANY (?::int[])', [live])
    .whereIn('item', ['passcode.is-present', 'passcode.is-compliant']).select('device_id', 'item', 'value') as
    Array<{ device_id: number; item: string; value: unknown }>;
  const artifacts = await trx('device_artifacts').where({ tenant_id: tenantId }).whereRaw('device_id = ANY (?::int[])', [live])
    .where((w) => w.where('state', 'error').orWhereIn('artifact_key', PASSCODE_ARTIFACTS).orWhere('artifact_key', 'like', `${ENFORCEMENT_PREFIX}%`))
    .select('device_id', 'artifact_key', 'state', 'desired_hash') as
    Array<{ device_id: number; artifact_key: string; state: string; desired_hash: string | null }>;
  // The bodies of the enforced updates still desired (their target version and their deadline).
  const enforced = [...new Set(artifacts.filter((a) => a.artifact_key.startsWith(ENFORCEMENT_PREFIX) && a.desired_hash !== null
    && a.state !== 'removing' && a.state !== 'removed').map((a) => String(a.desired_hash).trim()))];
  const bodies = new Map<string, unknown>(enforced.length
    ? (await trx('mdm_artifacts').where({ tenant_id: tenantId }).whereIn('hash', enforced).select('hash', 'body') as Array<{ hash: string; body: unknown }>)
      .map((b) => [b.hash.trim(), b.body])
    : []);
  const byDevice = new Map<number, typeof artifacts>();
  for (const a of artifacts) {
    const list = byDevice.get(Number(a.device_id));
    if (list) list.push(a); else byDevice.set(Number(a.device_id), [a]);
  }
  const statusOf = new Map<string, unknown>(status.map((s) => [`${Number(s.device_id)}|${s.item}`, parse<unknown>(s.value, null)]));
  const bool = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
  for (const d of devices) {
    const id = Number(d.id);
    out.evaluated++;
    if (d.compliance_state === 'exempt') continue;
    const mine = byDevice.get(id) ?? [];
    const enforcements = mine
      .filter((a) => a.artifact_key.startsWith(ENFORCEMENT_PREFIX) && a.desired_hash !== null && a.state !== 'removing' && a.state !== 'removed')
      .map((a) => (parse<{ Payload?: Record<string, unknown> }>(bodies.get(String(a.desired_hash).trim()), {}).Payload ?? {}))
      .filter((p) => typeof p.TargetOSVersion === 'string' && typeof p.TargetLocalDateTime === 'string')
      .map((p) => ({ targetOsVersion: p.TargetOSVersion as string, targetLocalDateTime: p.TargetLocalDateTime as string }));
    const verdict = evaluateCompliance({
      enrollmentState: d.enrollment_state, ownership: d.ownership, supervised: !!d.supervised, osVersion: d.os_version ?? null,
      lastCheckinAt: date(d.last_checkin_at), enrolledAt: date(d.enrolled_at), configState: d.config_state,
      lastDeviceInfoAt: date(d.last_device_info_at), staleAfterDays,
      errorArtifacts: mine.filter((a) => a.state === 'error').map((a) => a.artifact_key),
      passcodePolicyApplied: mine.some((a) => PASSCODE_ARTIFACTS.includes(a.artifact_key) && a.state === 'applied'),
      passcodeIsPresent: bool(statusOf.get(`${id}|passcode.is-present`)),
      passcodeIsCompliant: bool(statusOf.get(`${id}|passcode.is-compliant`)),
      enforcements,
    }, now);
    const before = canonicalJson(parse<unknown>(d.compliance_reasons, []) ?? []);
    if (d.compliance_state === verdict.state && before === canonicalJson(verdict.reasons)) continue;
    await trx('devices').where({ tenant_id: tenantId, id }).whereNot('compliance_state', 'exempt').update({
      compliance_state: verdict.state, compliance_reasons: JSON.stringify(verdict.reasons), compliance_evaluated_at: now, updated_at: new Date(),
    });
    out.changed.push(id);
  }
  return out;
}

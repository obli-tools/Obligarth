import {
  ANDROID_KIOSK_LOCK_TYPE, ANDROID_KIOSK_UPDATE_WINDOW, ANDROID_SYSTEM_UPDATE_LIMITS, type AndroidKioskForm,
  type AndroidKioskLock, isAndroidPackage, type JsonValue, parseAndroidSettingKey,
} from '@obligarth/shared';
import { policyHasWipeSettings, RESERVED_PACKAGES } from './overlay';
import { defaultApplicationDomain, preferredDomains } from './validate';

// =============================================================================
// Dedicated devices and kiosks (android-amapi §9.7; lot AN-G1), pure:
//   - the kiosk lock of a policy: one form among three (an app installed as
//     KIOSK, Google's launcher, an app holding the KIOSK role), never two; the
//     KIOSK role only on an app REQUIRED_FOR_SETUP (CUSTOM is refused in v1);
//     a role held once; no default home of another app beside a kiosk (an
//     escape from the lock by the home intent);
//   - the rules the compilation applies to a kiosk device: the app of its
//     enrollment profile becomes the single-app kiosk when its policies give
//     no form (only when it is a live app of the tenant's catalog), a kiosk
//     without form is not delivered, the Settings app is blocked unless a
//     policy allows it (Google allows it by default: a way out of the
//     kiosk), and a kiosk without system update policy is updated in a
//     window (MAJ-04);
//   - the temporary exit of a kiosk (guarded action mdm.android_kiosk_exit):
//     the device's own policy is compiled without the lock while it lasts;
//   - the system updates: a window of 0 to 1439 minutes, freeze periods of 90
//     days at most and 60 days apart, a type set when a freeze is set;
//   - the kiosk lock of the settings a resolution retained, for the impact
//     preview (kioskLockChanges, DM23).
// No database, no logger: the unit tests load it.
// =============================================================================

type Json = Record<string, JsonValue>;
const isObject = (v: unknown): v is Json => !!v && typeof v === 'object' && !Array.isArray(v);
const byKey = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

export interface KioskIssue { path: string; code: KioskValidationCode }
export type KioskValidationCode =
  | 'kiosk_form_ambiguous' | 'kiosk_role_install_type' | 'role_duplicate' | 'kiosk_home_conflict'
  | 'system_update_window_invalid' | 'freeze_period_invalid' | 'freeze_period_too_long' | 'freeze_period_gap_too_short'
  | 'freeze_period_overlap' | 'freeze_period_without_type' | 'too_many_freeze_periods';

export const isKioskInstall = (a: unknown): boolean => isObject(a) && a.installType === 'KIOSK';
export const hasKioskRole = (a: unknown): boolean => isObject(a) && Array.isArray(a.roles) && a.roles.some((r) => isObject(r) && r.roleType === 'KIOSK');
/** Holds a kiosk lock (installType KIOSK or the KIOSK role). */
export const isKioskApp = (a: unknown): boolean => isKioskInstall(a) || hasKioskRole(a);

interface FormFound { form: AndroidKioskForm; packageName: string | null }

/** The kiosk forms a set of apps and fields holds (one per app or launcher), in a stable order. */
function formsOf(apps: unknown[], launcher: unknown): FormFound[] {
  const out: FormFound[] = [];
  for (const a of apps) {
    if (!isObject(a)) continue;
    const pkg = typeof a.packageName === 'string' ? a.packageName : null;
    if (isKioskInstall(a)) out.push({ form: 'single_app', packageName: pkg });
    if (hasKioskRole(a)) out.push({ form: 'custom', packageName: pkg });
  }
  if (launcher === true) out.push({ form: 'launcher', packageName: null });
  return out;
}

/** The kiosk lock of a compiled body; ambiguous when it holds two forms (the compilation refuses it). */
export function kioskLockOf(body: Json): { lock: AndroidKioskLock | null; ambiguous: boolean } {
  const apps = Array.isArray(body.applications) ? body.applications : [];
  const forms = formsOf(apps, body.kioskCustomLauncherEnabled);
  if (forms.length === 0) return { lock: null, ambiguous: false };
  return { lock: { form: forms[0].form, packageName: forms[0].packageName }, ambiguous: forms.length > 1 };
}

/** The package of a persistent preferred activity's receiver ('com.example.app/.Main' → 'com.example.app'). */
export function receiverPackage(activity: unknown): string | null {
  if (!isObject(activity) || typeof activity.receiverActivity !== 'string') return null;
  const pkg = activity.receiverActivity.split('/')[0];
  return isAndroidPackage(pkg) ? pkg : null;
}

/** The home-intent claims that would take the device out of its kiosk: a persistent preferred activity on HOME for
 *  another app than the kiosk's (any, for Google's launcher), a default application of type DEFAULT_HOME. Paths. */
export function homeConflicts(fragment: Json, lock: AndroidKioskLock, base = 'fragment'): string[] {
  const out: string[] = [];
  const ppa = fragment.persistentPreferredActivities;
  if (Array.isArray(ppa)) {
    ppa.forEach((a, i) => {
      if (!preferredDomains(a).has('DEFAULT_HOME')) return;
      if (lock.form === 'launcher' || receiverPackage(a) !== lock.packageName) out.push(`${base}.persistentPreferredActivities[${i}]`);
    });
  }
  const das = fragment.defaultApplicationSettings;
  if (Array.isArray(das)) {
    das.forEach((s, i) => { if (defaultApplicationDomain(s) === 'DEFAULT_HOME') out.push(`${base}.defaultApplicationSettings[${i}]`); });
  }
  return out;
}

/** The roles held twice: by one app (two roles of a type) or by two apps (Google: « multiple apps cannot hold a role
 *  with the same roleType »). Paths of the second holder. */
export function duplicateRoles(apps: Array<{ entry: unknown; path: string }>): string[] {
  const out: string[] = [];
  const holders = new Set<string>();
  for (const { entry, path } of apps) {
    if (!isObject(entry) || !Array.isArray(entry.roles)) continue;
    const own = new Set<string>();
    entry.roles.forEach((r, i) => {
      const t = isObject(r) && typeof r.roleType === 'string' ? r.roleType : null;
      if (t === null) return;
      if (own.has(t) || holders.has(t)) out.push(`${path}.roles[${i}]`);
      own.add(t);
    });
    for (const t of own) holders.add(t);
  }
  return out;
}

/**
 * The kiosk rules of ONE section (the validation at each write of a draft): one form at most, the KIOSK role on an
 * app REQUIRED_FOR_SETUP only, roles held once, no other home beside the section's kiosk. Between two policies the
 * compilation applies the same rules to the merged policy (problems).
 */
export function validateKioskSection(fragment: Json, apps: Array<{ entry: unknown; path: string }>): KioskIssue[] {
  const issues: KioskIssue[] = [];
  const forms = formsOf(apps.map((a) => a.entry), fragment.kioskCustomLauncherEnabled);
  if (forms.length > 1) issues.push({ path: fragment.kioskCustomLauncherEnabled === true ? 'fragment.kioskCustomLauncherEnabled' : 'applications', code: 'kiosk_form_ambiguous' });
  for (const { entry, path } of apps) {
    if (hasKioskRole(entry) && (entry as Json).installType !== 'REQUIRED_FOR_SETUP') issues.push({ path: `${path}.installType`, code: 'kiosk_role_install_type' });
  }
  for (const p of duplicateRoles(apps)) issues.push({ path: p, code: 'role_duplicate' });
  if (forms.length === 1) for (const p of homeConflicts(fragment, forms[0])) issues.push({ path: p, code: 'kiosk_home_conflict' });
  return issues;
}

// ── System updates ─────────────────────────────────────────────────────────

const MONTH_DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const YEAR_DAYS = 365;

/** The day of a 365-day year (1 to 365) of a FreezePeriod date, or null when invalid. Google ignores leap years:
 *  February 29th counts as February 28th. A year is refused (Google ignores it: the period repeats every year). */
export function freezeDay(d: unknown): number | null {
  if (!isObject(d)) return null;
  const { month, day, year } = d;
  if (year !== undefined && year !== 0) return null;
  if (typeof month !== 'number' || typeof day !== 'number' || !Number.isInteger(month) || !Number.isInteger(day)) return null;
  if (month < 1 || month > 12 || day < 1) return null;
  const max = month === 2 ? 29 : MONTH_DAYS[month - 1];
  if (day > max) return null;
  let n = Math.min(day, MONTH_DAYS[month - 1]);
  for (let m = 0; m < month - 1; m++) n += MONTH_DAYS[m];
  return n;
}

/** The days of a freeze period (inclusive; an end before the start wraps the year end). */
export function freezeLength(start: number, end: number): number {
  return end >= start ? end - start + 1 : YEAR_DAYS - start + 1 + end;
}

const daysOf = (start: number, end: number): Set<number> => {
  const out = new Set<number>();
  for (let i = 0, d = start; i < freezeLength(start, end); i++, d = d === YEAR_DAYS ? 1 : d + 1) out.add(d);
  return out;
};

/**
 * Policy.systemUpdate (revision 20261014): WINDOWED needs a window of 0 to 1439 minutes (start and end), the other
 * types none; a freeze period is a valid month and day without year, 90 days at most; two periods never overlap and
 * are 60 days apart at least (counted between the end of one and the start of the next, around the year); a freeze
 * needs a type (« freeze periods require a defined policy »); four periods at most.
 */
export function validateSystemUpdate(value: unknown, path = 'fragment.systemUpdate'): KioskIssue[] {
  const issues: KioskIssue[] = [];
  if (!isObject(value)) return issues;                       // the schema check reports the type
  const L = ANDROID_SYSTEM_UPDATE_LIMITS;
  const type = value.type;
  const minutes = (v: unknown): boolean => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= L.maxMinutes;
  if (type === 'WINDOWED') {
    if (!minutes(value.startMinutes)) issues.push({ path: `${path}.startMinutes`, code: 'system_update_window_invalid' });
    if (!minutes(value.endMinutes)) issues.push({ path: `${path}.endMinutes`, code: 'system_update_window_invalid' });
  } else {
    for (const k of ['startMinutes', 'endMinutes']) if (value[k] !== undefined) issues.push({ path: `${path}.${k}`, code: 'system_update_window_invalid' });
  }
  const periods = value.freezePeriods;
  if (periods === undefined) return issues;
  if (!Array.isArray(periods)) return issues;
  if (periods.length > 0 && (type === undefined || type === 'SYSTEM_UPDATE_TYPE_UNSPECIFIED')) issues.push({ path: `${path}.type`, code: 'freeze_period_without_type' });
  if (periods.length > L.maxFreezePeriods) { issues.push({ path: `${path}.freezePeriods`, code: 'too_many_freeze_periods' }); return issues; }
  const ok: Array<{ start: number; end: number; i: number }> = [];
  periods.forEach((p, i) => {
    const at = `${path}.freezePeriods[${i}]`;
    const start = isObject(p) ? freezeDay(p.startDate) : null;
    const end = isObject(p) ? freezeDay(p.endDate) : null;
    if (start === null || end === null) { issues.push({ path: at, code: 'freeze_period_invalid' }); return; }
    if (freezeLength(start, end) > L.maxFreezeDays) { issues.push({ path: at, code: 'freeze_period_too_long' }); return; }
    ok.push({ start, end, i });
  });
  if (ok.length < 2) return issues;
  const sets = ok.map((p) => daysOf(p.start, p.end));
  for (let a = 0; a < ok.length; a++) {
    for (let b = a + 1; b < ok.length; b++) {
      if ([...sets[a]].some((d) => sets[b].has(d))) issues.push({ path: `${path}.freezePeriods[${ok[b].i}]`, code: 'freeze_period_overlap' });
    }
  }
  if (issues.some((x) => x.code === 'freeze_period_overlap')) return issues;
  const sorted = [...ok].sort((x, y) => x.start - y.start);
  for (let k = 0; k < sorted.length; k++) {
    const prev = sorted[k];
    const next = sorted[(k + 1) % sorted.length];
    const gap = ((next.start - prev.end + YEAR_DAYS) % YEAR_DAYS) - 1;
    if (gap < L.minFreezeGapDays) issues.push({ path: `${path}.freezePeriods[${next.i}]`, code: 'freeze_period_gap_too_short' });
  }
  return issues;
}

// ── Compilation ────────────────────────────────────────────────────────────

export interface KioskCompileOptions {
  purpose: 'device' | 'enrollment';
  /** settings.kioskApp of the device's enrollment profile (the single-app kiosk when its policies give no form). */
  app?: string | null;
  /** The profile's app is a live app of the tenant's catalog (read by the caller); otherwise never set. */
  appInCatalog?: boolean;
  /** A kiosk exit of the device is running (the device's own policy only). */
  exit?: boolean;
}

export interface KioskCompileResult {
  lock: AndroidKioskLock | null;
  /** The lock was lifted for a kiosk exit. */
  exitApplied: boolean;
  /** A kiosk exit runs but the lock was kept: the policy carries a wipe-capable setting (review AN-G1, G1-R1). Under a
   *  freeze the gateway refuses any policies.patch with such a setting (AN15), so an unlocked policy pushed with one
   *  could not be locked again before the tenant is unfrozen: it is never pushed. The caller ends the exit. */
  exitWithheld: boolean;
  /** The profile's app was set as the single-app kiosk. */
  injected: boolean;
  problems: string[];
}

/** Lifts the kiosk lock of a body (kiosk exit): the kiosk app stays installed (FORCE_INSTALLED), the KIOSK role is
 *  removed, Google's launcher and the kiosk customization go. Everything else is kept. */
export function stripKioskLock(body: Json): void {
  if (Array.isArray(body.applications)) {
    body.applications = body.applications.map((a) => {
      if (!isObject(a)) return a;
      const out: Json = { ...a };
      if (out.installType === 'KIOSK') out.installType = 'FORCE_INSTALLED';
      if (Array.isArray(out.roles)) {
        const roles = out.roles.filter((r) => !(isObject(r) && r.roleType === 'KIOSK'));
        if (roles.length) out.roles = roles; else delete out.roles;
      }
      return out;
    });
  }
  delete body.kioskCustomLauncherEnabled;
  delete body.kioskCustomization;
}

/**
 * The kiosk rules of the compilation (step 4 of section 9.3) for a device of use 'kiosk' (dedicated), applied to the
 * merged body in place. A device that is not a kiosk is left as is (the compiler already keeps kiosk apps and the
 * dedicated-only fields away from it).
 */
export function applyKioskRules(body: Json, usage: string, o: KioskCompileOptions): KioskCompileResult {
  const out: KioskCompileResult = { lock: null, exitApplied: false, exitWithheld: false, injected: false, problems: [] };
  if (usage !== 'kiosk') return out;
  let apps = Array.isArray(body.applications) ? body.applications.filter(isObject) : [];
  for (const a of apps) {
    if (hasKioskRole(a) && a.installType !== 'REQUIRED_FOR_SETUP') out.problems.push('compile:kiosk_role_install_type');
  }
  let forms = formsOf(apps, body.kioskCustomLauncherEnabled);
  if (forms.length > 1) out.problems.push('compile:kiosk_form_ambiguous');
  if (forms.length === 0 && typeof o.app === 'string' && o.app) {
    const pkg = o.app;
    const entry = apps.find((a) => a.packageName === pkg);
    if (!isAndroidPackage(pkg) || RESERVED_PACKAGES.has(pkg)) out.problems.push('compile:kiosk_app_invalid');
    else if (o.appInCatalog !== true) out.problems.push('compile:kiosk_app_not_in_catalog');
    else if (entry && entry.installType === 'BLOCKED') out.problems.push('compile:kiosk_app_blocked');
    else {
      if (entry) entry.installType = 'KIOSK';
      else apps = [...apps, { packageName: pkg, installType: 'KIOSK' }];
      apps.sort((x, y) => byKey(String(x.packageName), String(y.packageName)));
      body.applications = apps;
      out.injected = true;
      forms = [{ form: 'single_app', packageName: pkg }];
    }
  }
  if (forms.length === 0) {
    if (o.purpose === 'device') out.problems.push('compile:kiosk_form_missing');
  } else {
    out.lock = { form: forms[0].form, packageName: forms[0].packageName };
    if (forms.length === 1 && homeConflicts(body, out.lock).length > 0) out.problems.push('compile:kiosk_home_conflict');
  }
  if (out.lock && o.exit === true && o.purpose === 'device' && policyHasWipeSettings(body)) out.exitWithheld = true;
  if (out.lock && o.exit === true && o.purpose === 'device' && !out.exitWithheld) {
    stripKioskLock(body);
    out.exitApplied = true;
  } else if (out.lock) {
    // Google allows the Settings app in a kiosk by default: a way out of the lock. Blocked unless a policy says so.
    const custom = isObject(body.kioskCustomization) ? { ...body.kioskCustomization } : {};
    if (custom.deviceSettings === undefined || custom.deviceSettings === 'DEVICE_SETTINGS_UNSPECIFIED') custom.deviceSettings = 'SETTINGS_ACCESS_BLOCKED';
    body.kioskCustomization = custom;
  }
  if (body.systemUpdate === undefined) body.systemUpdate = { ...ANDROID_KIOSK_UPDATE_WINDOW };
  out.problems = [...new Set(out.problems)];
  return out;
}

// ── Impact preview (DM23) ──────────────────────────────────────────────────

/** A setting retained by a resolution, as the preview sees it. */
export interface KioskPreviewSetting {
  settingKey: string;
  removed?: boolean;
  value?: JsonValue;
  availability?: { status: string };
}

/**
 * The kiosk lock artifact of the settings a resolution retained for a device (the impact preview counts a change of
 * its signature in kioskLockChanges, DM23): the apps installed as KIOSK or holding the KIOSK role, Google's launcher,
 * the kiosk customization. null: no kiosk lock.
 */
export function androidKioskLockArtifact(settings: readonly KioskPreviewSetting[]): { key: string; type: string; sig: string } | null {
  const forms: string[] = [];
  let custom: JsonValue | undefined;
  for (const s of settings) {
    if (s.removed || s.value === undefined || (s.availability && s.availability.status !== 'available')) continue;
    const k = parseAndroidSettingKey(s.settingKey);
    if (!k) continue;
    if (k.kind === 'app' && isObject(s.value)) {
      if (isKioskInstall(s.value)) forms.push(`single_app:${k.packageName}`);
      if (hasKioskRole(s.value)) forms.push(`custom:${k.packageName}`);
    } else if (k.kind === 'field' && k.field === 'kioskCustomLauncherEnabled' && s.value === true) forms.push('launcher');
    else if (k.kind === 'field' && k.field === 'kioskCustomization') custom = s.value;
  }
  if (forms.length === 0) return null;
  return { key: 'android:kiosk', type: ANDROID_KIOSK_LOCK_TYPE, sig: JSON.stringify({ forms: forms.sort(), custom: custom ?? null }) };
}

/** Does a change of the retained settings change a device's kiosk lock (kioskLockChanges)? */
export function androidKioskLockChanged(before: readonly KioskPreviewSetting[], after: readonly KioskPreviewSetting[]): boolean {
  return (androidKioskLockArtifact(before)?.sig ?? null) !== (androidKioskLockArtifact(after)?.sig ?? null);
}

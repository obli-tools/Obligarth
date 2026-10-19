// What a personal device (work profile on a personal device, BYOD) may receive (lot AN-F1, section 10.5, EX-A7,
// criterion 6), pure: the instance never erases a personal device entirely, never locates it, never inventories it
// outside the work profile. Three barriers share these rules:
//   - the own policy of a BYOD device and the enrollment policy of a BYOD profile (« politique propre au BYOD »):
//     byodPolicy() withholds every setting that acts on the whole device (wipe flags, factory reset protection,
//     setup actions, the device-scope wipe after failed passwords, personal usage policies of COPE, usage logs),
//     forces the minimised status reporting of a personal device (no hardware, memory, network, display, power nor
//     system properties report) and forces a separate challenge of the work profile
//     (passwordPolicies[SCOPE_PROFILE].unifiedLockSettings = REQUIRE_SEPARATE_WORK_LOCK, decision of the owners of
//     19/10/2026 on F1R-3: a LOCK then locks the work profile only, never the personal device, as the notice the
//     employee acknowledges says); policies/push.ts applies it, the gateway refuses a body that still carries one
//     (byodPolicyViolations) for a policy of a personal device or profile;
//   - the commands: byodCommandRefusal() admits on a personal device only LOCK (the work profile, which always has
//     its own challenge since 19/10/2026 [AR]), CLEAR_APP_DATA of managed apps and WIPE without any wipe data flag (the removal of the work
//     profile: AMAPI never resets a personally-owned device [AR]); the bus refuses the rest at the request, the
//     submission refuses it again before each issue (recovery included), the gateway once more before the call;
//   - the inventory: only the apps of the tenant's catalog are kept for a personal device (byodApps), whatever the
//     report carries (Google reports the work profile only: a second barrier, AMAPI-R20).

type Json = unknown;
const isObj = (v: Json): v is Record<string, Json> => !!v && typeof v === 'object' && !Array.isArray(v);

/** Top-level fields that act on the whole device, never in a policy of a personal device. */
export const BYOD_FORBIDDEN_FIELDS: readonly string[] = [
  'wipeDataFlags', 'frpAdminEmails', 'setupActions', 'factoryResetDisabled', 'personalUsagePolicies', 'usageLog',
];

/** The status reporting of a personal device (section 8.2, AN19): the work profile's apps, software, settings. */
export const BYOD_STATUS_REPORTING: Readonly<Record<string, Json>> = Object.freeze({
  applicationReportsEnabled: true,
  applicationReportingSettings: { includeRemovedApps: false },
  deviceSettingsEnabled: true,
  softwareInfoEnabled: true,
  memoryInfoEnabled: false,
  networkInfoEnabled: false,
  displayInfoEnabled: false,
  powerManagementEventsEnabled: false,
  systemPropertiesEnabled: false,
  hardwareStatusEnabled: false,
  commonCriteriaModeEnabled: false,
});

/** Reports a personal device never sends (anything else than false is a violation). */
const REPORTS_OFF = ['memoryInfoEnabled', 'networkInfoEnabled', 'displayInfoEnabled', 'powerManagementEventsEnabled',
  'systemPropertiesEnabled', 'hardwareStatusEnabled'] as const;

/** The separate challenge of the work profile a personal device always gets (F1R-3, decision of 19/10/2026). */
export const BYOD_WORK_LOCK = 'REQUIRE_SEPARATE_WORK_LOCK';
/** The path byodPolicyViolations gives when the separate challenge of the work profile is not required. */
export const BYOD_WORK_LOCK_PATH = 'passwordPolicies[SCOPE_PROFILE].unifiedLockSettings';
const profileScope = (r: Json): boolean => isObj(r) && r.passwordScope === 'SCOPE_PROFILE';
/** Does the body require a separate challenge of the work profile (a SCOPE_PROFILE entry, none allowing the unified lock)? */
const separateWorkLock = (pp: Json): boolean => Array.isArray(pp) && pp.some((r) => profileScope(r) && (r as Record<string, Json>).unifiedLockSettings === BYOD_WORK_LOCK)
  && !pp.some((r) => profileScope(r) && (r as Record<string, Json>).unifiedLockSettings !== BYOD_WORK_LOCK);

/** The path byodPolicyViolations gives when an entry other than SCOPE_PROFILE carries unifiedLockSettings. */
export const BYOD_FOREIGN_LOCK_PATH = 'passwordPolicies[not SCOPE_PROFILE].unifiedLockSettings';
/** An entry of another scope that asks for a lock setting (AMAPI admits unifiedLockSettings under SCOPE_PROFILE only;
 *  an entry of unspecified scope designates the work profile of a personal device): never (review of lot D-1910). */
const foreignLockSetting = (r: Json): boolean => isObj(r) && !profileScope(r) && r.unifiedLockSettings !== undefined;

/** A password policy whose failed attempts wipe the whole device (scope device, or the deprecated requirements). */
const deviceScopeWipe = (r: Json): boolean => isObj(r) && r.maximumFailedPasswordsForWipe !== undefined && r.passwordScope === 'SCOPE_DEVICE';

/**
 * The paths of a policy body that a personal device must never receive (empty: admitted). The gateway refuses a
 * putPolicy of a personal device or profile whose body gives one.
 */
export function byodPolicyViolations(body: Record<string, Json>): string[] {
  const out: string[] = [];
  for (const f of BYOD_FORBIDDEN_FIELDS) if (body[f] !== undefined) out.push(f);
  const pp = body.passwordPolicies;
  if (Array.isArray(pp) && pp.some(deviceScopeWipe)) out.push('passwordPolicies[SCOPE_DEVICE].maximumFailedPasswordsForWipe');
  const pr = body.passwordRequirements;
  if (isObj(pr) && pr.maximumFailedPasswordsForWipe !== undefined) out.push('passwordRequirements.maximumFailedPasswordsForWipe');
  if (!separateWorkLock(pp)) out.push(BYOD_WORK_LOCK_PATH);
  if (Array.isArray(pp) && pp.some(foreignLockSetting)) out.push(BYOD_FOREIGN_LOCK_PATH);
  const srs = body.statusReportingSettings;
  if (isObj(srs)) {
    for (const k of REPORTS_OFF) if (srs[k] !== undefined && srs[k] !== false) out.push(`statusReportingSettings.${k}`);
    const ars = srs.applicationReportingSettings;
    if (isObj(ars) && ars.includeRemovedApps === true) out.push('statusReportingSettings.applicationReportingSettings.includeRemovedApps');
  }
  return out;
}

/**
 * The policy of a personal device: the forbidden settings withheld (their paths returned, never their values), the
 * status reporting of a personal device forced. Idempotent; the result has no violation.
 */
export function byodPolicy(body: Record<string, Json>): { body: Record<string, Json>; withheld: string[] } {
  // Forced, not withheld: the status reporting and the separate challenge of the work profile.
  const withheld = byodPolicyViolations(body).filter((p) => !p.startsWith('statusReportingSettings.') && p !== BYOD_WORK_LOCK_PATH);
  const out: Record<string, Json> = { ...body };
  for (const f of BYOD_FORBIDDEN_FIELDS) delete out[f];
  const pp = out.passwordPolicies;
  const kept = Array.isArray(pp)
    ? pp.map((r) => {
      let e = r;
      if (deviceScopeWipe(e)) {
        const { maximumFailedPasswordsForWipe: _m, ...rest } = e as Record<string, Json>;
        e = rest;
      }
      if (foreignLockSetting(e)) {
        const { unifiedLockSettings: _u, ...rest } = e as Record<string, Json>;
        e = rest;
      }
      return e;
    })
    : [];
  // F1R-3: every SCOPE_PROFILE entry requires the separate challenge of the work profile (AMAPI admits
  // unifiedLockSettings under SCOPE_PROFILE only). Without one, the first entry of unspecified scope (the work profile
  // on a personal device) is made SCOPE_PROFILE; without either, an entry is added.
  const unspecified = (r: Json): boolean => isObj(r) && (r.passwordScope === undefined || r.passwordScope === 'SCOPE_UNSPECIFIED');
  const promote = !kept.some(profileScope) ? kept.findIndex(unspecified) : -1;
  const forced = kept.map((r, i) => (profileScope(r) || i === promote
    ? { ...(r as Record<string, Json>), passwordScope: 'SCOPE_PROFILE', unifiedLockSettings: BYOD_WORK_LOCK } : r));
  if (!forced.some(profileScope)) forced.push({ passwordScope: 'SCOPE_PROFILE', unifiedLockSettings: BYOD_WORK_LOCK });
  out.passwordPolicies = forced;
  const pr = out.passwordRequirements;
  if (isObj(pr) && pr.maximumFailedPasswordsForWipe !== undefined) {
    const { maximumFailedPasswordsForWipe: _m, ...rest } = pr;
    out.passwordRequirements = rest;
  }
  out.statusReportingSettings = JSON.parse(JSON.stringify(BYOD_STATUS_REPORTING));
  return { body: out, withheld };
}

/** Command types a personal device may take (everything else is refused at every barrier). */
export const BYOD_COMMAND_TYPES: ReadonlySet<string> = new Set(['LOCK', 'WIPE', 'CLEAR_APP_DATA']);

/**
 * Why a command body must never reach a personal device, or null. `body` is the AMAPI Command (type, wipeParams…).
 * A WIPE is the removal of the work profile only: no wipe data flag (WIPE_EXTERNAL_STORAGE, WIPE_ESIMS,
 * PRESERVE_RESET_PROTECTION_DATA act on the whole device).
 */
export function byodCommandRefusal(body: { type?: unknown; [k: string]: unknown }): 'personal_command' | 'personal_full_wipe' | null {
  const type = typeof body?.type === 'string' ? body.type : '';
  if (!BYOD_COMMAND_TYPES.has(type)) return 'personal_command';
  if (type === 'WIPE') {
    // Any value other than an empty list is a flag (a scalar or an object as well: review of lot AN-F1).
    const flagged = (v: unknown): boolean => v !== undefined && v !== null && !(Array.isArray(v) && v.length === 0);
    const wp = body.wipeParams;
    if (wp !== undefined && wp !== null && !isObj(wp)) return 'personal_full_wipe';
    if (isObj(wp) && flagged(wp.wipeDataFlags)) return 'personal_full_wipe';
    if (flagged(body.wipeDataFlags)) return 'personal_full_wipe';
  }
  return null;
}

/** The apps of a personal device kept by the instance: those of the tenant's catalog only (never a personal app). */
export function byodApps<T extends { identifier: string }>(apps: readonly T[], catalog: ReadonlySet<string>): T[] {
  return apps.filter((a) => catalog.has(a.identifier));
}

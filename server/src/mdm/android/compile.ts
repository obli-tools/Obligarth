import { createHash } from 'node:crypto';
import { variablesOf, type JsonValue, type UnavailableReason } from '@obligarth/shared';
import type { AndroidAvailabilityFacts, AndroidUnavailableReason } from '@obligarth/shared/dist/android/availability.js';
import {
  AMAPI_ARTIFACT_KEY, AMAPI_CHANNEL, devicePolicyId, enrollmentPolicyId, parseAndroidSettingKey,
} from '@obligarth/shared/dist/android/policy.js';
import { CanonicalJsonError, canonicalize } from '../../apple/ddm/canonical';
import { secretRefsOf } from '../apple/compile';
import type { VariableValues } from '../apple/variables';
import type { AndroidKioskLock } from '@obligarth/shared/dist/android/kiosk.js';
import { androidKeyAvailability } from './availability';
import { androidCatalog, type AndroidCatalogView } from './catalog';
import { FAILED_PASSWORDS_FOR_WIPE, POLICY_LIMITS, RESERVED_FIELDS, RESERVED_PACKAGES, RESERVED_ROLES } from './overlay';
import { applyKioskRules, isKioskApp } from './kiosk';
import { defaultApplicationDomain, preferredActivityConflicts, preferredDomains } from './validate';

// =============================================================================
// The Android compilation: the settings a resolution retained for one device
// become ONE AMAPI Policy, the artifact 'amapi:policy' of the channel 'amapi'.
//   1. Obligarth's base: statusReportingSettings derived from the ownership
//      and the privacy rules (never from a policy), playStoreMode WHITELIST
//      unless a setting says otherwise, the enterprise's name visible;
//   2. the retained and available keys, in the order of the keys;
//   3. applications[]: one entry per package (android:app[…]), sorted, never
//      the reserved package nor a reserved role;
//   4. usage rules (kiosk.ts, lot AN-G1): a device that is not a kiosk never
//      receives a kiosk app; a kiosk device needs ONE kiosk form (an app
//      installed as KIOSK, an app holding the KIOSK role, or Google's
//      launcher), the app of its enrollment profile when its policies give
//      none (a live app of the tenant's catalog only), no other home beside
//      it, the Settings app blocked unless a policy allows it, a windowed
//      system update unless a policy sets one; a running kiosk exit lifts
//      the lock of the device's own policy;
//   5. ownership rules (through the availability: ownership_forbidden);
//   6. conflicts between two keys (persistentPreferredActivities and
//      defaultApplicationSettings on one intent domain, from two policies):
//      broken by the rule of the resolution (the first of rank, priority,
//      resource wins), the loser's entries on the domain left out and the
//      conflict listed; without the provenance of both keys, a problem;
//   7. the guards known at the compilation (enterprise domain of the FRP
//      administrators, the tenant's floor of failed passwords): a policy
//      written before a change of either is not delivered (problems);
//   8. canonical JSON (RFC 8785, the function of the DDM engine) and hash.
// The secret references and the variables stay in the body: a secret and a
// device's values exist at rendering only (render.ts). The hash addresses the
// body, not the device: SHA-256 of the canonical { channel, policyId: null,
// body }. The enrollment policy of a profile ('e-<uuid>') is compiled for a
// fictitious device of the profile's mode and ownership, without the device's
// variables and without any secret: the settings that carry one are deferred
// to the device's own policy, applied once it is accepted; a secret left in
// the body is refused (AndroidCompileError enrollmentPolicySecret).
// Pure: no database, no logger; the unit tests load it.
// =============================================================================

/** Bumped when the form of the compiled body changes: every tenant is then resolved again. */
export const ANDROID_COMPILER_VERSION = 2;

export type AndroidNotApplicableReason = AndroidUnavailableReason | UnavailableReason;

export interface CompiledAndroidPolicy {
  artifactKey: typeof AMAPI_ARTIFACT_KEY;
  channel: typeof AMAPI_CHANNEL;
  /** 'd-<device uuid>' (per device) | 'e-<profile uuid>' (enrollment). */
  policyId: string;
  /** AMAPI Policy with $secret references and variables. */
  body: Record<string, JsonValue>;
  /** SHA-256 of the canonical { channel, policyId: null, body }. */
  hash: string;
  secretRefs: string[];
  hasVariables: boolean;
  /** Setting keys that produced it. */
  sources: string[];
  notApplicable: Array<{ settingKey: string; reason: AndroidNotApplicableReason; detail?: string }>;
  /** Enrollment policy: setting keys left to the device's own policy (they carry a secret). */
  deferred: string[];
  /** Why the policy cannot be delivered as compiled (codes, never a value); empty: deliverable. */
  problems: string[];
  /** Conflicts between two keys broken here: the loser's entries on the domains were left out. */
  conflicts: AndroidKeyConflict[];
  /** The kiosk lock of the policy (a kiosk device; null otherwise), even while a kiosk exit lifts it. */
  kioskLock: AndroidKioskLock | null;
  /** A kiosk exit lifted the lock of this compilation. */
  kioskExit: boolean;
}

/** Provenance of a retained setting (the resolver's ResolvedSetting.source). */
export interface AndroidSettingSource {
  type: 'policy' | 'app';
  id: number;
  tenantId?: number;
  assignmentId?: number;
  rank: number;
  priority: number;
}

export interface AndroidKeyConflict {
  /** The key whose entries were left out, and the key that kept the domains. */
  settingKey: string;
  winner: string;
  domains: string[];
  /** Same rank and priority (a conflict the write refuses; broken here by the resource order). */
  sameRank: boolean;
  source: AndroidSettingSource;
}

/** A setting retained by the resolution (the resolver's ResolvedSetting has this shape). */
export interface AndroidEffectiveSetting {
  settingKey: string;
  removed: boolean;
  availability: { status: 'available' } | { status: 'not_applicable'; reason: string; detail?: string };
  value?: JsonValue;
  /** Provenance (needed to break a conflict between two keys). */
  source?: AndroidSettingSource;
}

export interface AndroidDeviceFacts extends AndroidAvailabilityFacts {
  /** devices.uuid (random, no personal data): the name of the device's policy. */
  uuid: string;
  /** Declared use ('standard', 'kiosk', 'shared'). */
  usage: string;
}

export interface AndroidCompileContext {
  purpose: 'device' | 'enrollment';
  /** Enrollment policy: the profile's uuid. */
  profileUuid?: string;
  /** What the privacy rules let the device report (network information: IMEI, operator…). */
  privacy?: { networkInfo?: boolean };
  /** The values of the variables known for the device; absent: the resolution decided (variable_unresolved). An
   *  enrollment policy has the tenant's only. */
  variables?: VariableValues;
  /** Guards re-checked at the compilation (the validation checked them at the write, against the values then). */
  guards?: { adminDomain?: string | null; minFailedPasswordsForWipe?: number };
  catalog?: AndroidCatalogView;
  /** Kiosk of a dedicated device (lot AN-G1): the app of its enrollment profile, whether it is a live app of the
   *  tenant's catalog, and whether a kiosk exit runs (the device's own policy only). */
  kiosk?: { app?: string | null; appInCatalog?: boolean; exit?: boolean };
}

export class AndroidCompileError extends Error {
  readonly code: 'enrollmentPolicySecret' | 'invalid_value' | 'invalid_context';
  constructor(code: AndroidCompileError['code']) {
    super(code);
    this.name = 'AndroidCompileError';
    this.code = code;
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const isObject = (v: unknown): v is Record<string, JsonValue> => !!v && typeof v === 'object' && !Array.isArray(v);
const byKey = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
/** The order of the resolution (resolver.ts compareCandidates): the first wins. */
const bySource = (x: AndroidSettingSource, y: AndroidSettingSource): number =>
  x.rank - y.rank || x.priority - y.priority || byKey(x.type, y.type) || (x.tenantId ?? 0) - (y.tenantId ?? 0) || x.id - y.id
  || (x.assignmentId ?? 0) - (y.assignmentId ?? 0);
const PPA = 'persistentPreferredActivities';
const DAS = 'defaultApplicationSettings';
const EMAIL_DOMAIN_RE = /^[^\s@{}]{1,64}@([A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+)$/;

/** statusReportingSettings of an ownership: the inventory is minimised at the source. */
export function statusReportingSettings(ownership: string, privacy: AndroidCompileContext['privacy'] = {}): Record<string, JsonValue> {
  const personal = ownership !== 'corporate' && ownership !== 'corporate_personal';
  const networkInfo = personal ? false : (privacy.networkInfo ?? ownership === 'corporate');
  return {
    applicationReportsEnabled: true,
    applicationReportingSettings: { includeRemovedApps: false },
    deviceSettingsEnabled: true,
    softwareInfoEnabled: true,
    memoryInfoEnabled: !personal,
    networkInfoEnabled: networkInfo,
    displayInfoEnabled: false,
    powerManagementEventsEnabled: false,
    systemPropertiesEnabled: false,
    hardwareStatusEnabled: false,
    commonCriteriaModeEnabled: false,
  };
}

/** The hash of a compiled policy: its body, nothing of a device nor of its name. */
export function androidPolicyHash(body: Record<string, JsonValue>): string {
  return createHash('sha256').update(canonicalize({ channel: AMAPI_CHANNEL, policyId: null, body }), 'utf8').digest('hex');
}

/**
 * compileAndroid(effective, device, ctx): the AMAPI policy of the settings retained for one device. The settings
 * that are not Android's are ignored (the resolution already found them platform_unsupported).
 */
export function compileAndroid(effective: AndroidEffectiveSetting[], device: AndroidDeviceFacts, ctx: AndroidCompileContext): CompiledAndroidPolicy {
  const catalog = ctx.catalog ?? androidCatalog();
  const enrollment = ctx.purpose === 'enrollment';
  let policyId: string;
  if (enrollment) {
    if (typeof ctx.profileUuid !== 'string' || !UUID_RE.test(ctx.profileUuid)) throw new AndroidCompileError('invalid_context');
    policyId = enrollmentPolicyId(ctx.profileUuid);
  } else {
    if (typeof device.uuid !== 'string' || !UUID_RE.test(device.uuid)) throw new AndroidCompileError('invalid_context');
    policyId = devicePolicyId(device.uuid);
  }
  const variables: VariableValues | undefined = enrollment ? (ctx.variables ?? {}) : ctx.variables;

  const body: Record<string, JsonValue> = {
    statusReportingSettings: statusReportingSettings(device.ownership, ctx.privacy),
    playStoreMode: 'WHITELIST',
    enterpriseDisplayNameVisibility: 'ENTERPRISE_DISPLAY_NAME_VISIBLE',
  };
  const sources: string[] = [];
  const notApplicable: CompiledAndroidPolicy['notApplicable'] = [];
  const deferred: string[] = [];
  const problems: string[] = [];
  const conflicts: AndroidKeyConflict[] = [];
  const fieldSettings = new Map<string, AndroidEffectiveSetting>();
  const apps = new Map<string, { key: string; entry: Record<string, JsonValue> }>();
  const networks = new Map<string, { key: string; entry: Record<string, JsonValue> }>();
  let oncRest: { key: string; value: Record<string, JsonValue> } | null = null;

  for (const s of [...effective].sort((a, b) => byKey(a.settingKey, b.settingKey))) {
    const k = parseAndroidSettingKey(s.settingKey);
    if (!k || s.removed || s.value === undefined) continue;
    if (s.availability.status !== 'available') {
      notApplicable.push({ settingKey: s.settingKey, reason: s.availability.reason as AndroidNotApplicableReason,
        ...(s.availability.detail ? { detail: s.availability.detail } : {}) });
      continue;
    }
    const unresolved = variables ? variablesOf(s.value).find((v) => typeof variables[v] !== 'string' || variables[v] === '') ?? null : null;
    const a = androidKeyAvailability(s.settingKey, s.value, device, { unresolvedVariable: unresolved }, catalog);
    if (a.status !== 'available') {
      notApplicable.push({ settingKey: s.settingKey, reason: a.reason, ...(a.detail ? { detail: a.detail } : {}) });
      continue;
    }
    if (enrollment && secretRefsOf(s.value).size > 0) { deferred.push(s.settingKey); continue; }
    if (k.kind === 'field') {
      if (RESERVED_FIELDS.has(k.field) || k.field === 'applications') { problems.push(`compile:reserved:${k.field}`.slice(0, 120)); continue; }
      if (k.field === 'openNetworkConfiguration') {
        if (isObject(s.value)) oncRest = { key: s.settingKey, value: s.value };
        continue;
      }
      body[k.field] = s.value;
      fieldSettings.set(k.field, s);
      sources.push(s.settingKey);
    } else if (k.kind === 'app') {
      if (!isObject(s.value)) continue;
      if (RESERVED_PACKAGES.has(k.packageName)) { problems.push('compile:reserved_package'); continue; }
      const entry: Record<string, JsonValue> = { ...s.value, packageName: k.packageName };
      if (Array.isArray(entry.roles) && entry.roles.some((r) => isObject(r) && typeof r.roleType === 'string' && RESERVED_ROLES.has(r.roleType))) {
        problems.push('compile:reserved_role');
        continue;
      }
      // 4. A device that is not a kiosk never receives a kiosk app.
      if (device.usage !== 'kiosk' && isKioskApp(entry)) {
        notApplicable.push({ settingKey: s.settingKey, reason: 'management_mode_unsupported', detail: 'kiosk' });
        continue;
      }
      apps.set(k.packageName, { key: s.settingKey, entry });
    } else {
      if (!isObject(s.value)) continue;
      networks.set(k.guid, { key: s.settingKey, entry: { ...s.value, GUID: k.guid } });
    }
  }

  // ONC: the rest of the field, then the networks by GUID.
  if (oncRest || networks.size > 0) {
    const value: Record<string, JsonValue> = { ...(oncRest?.value ?? {}) };
    if (oncRest) sources.push(oncRest.key);
    if (networks.size > 0) {
      const guids = [...networks.keys()].sort(byKey);
      value.NetworkConfigurations = guids.map((g) => networks.get(g)!.entry);
      for (const g of guids) sources.push(networks.get(g)!.key);
    }
    body.openNetworkConfiguration = value;
  }
  // 3. Apps, sorted by package.
  if (apps.size > 0) {
    const pkgs = [...apps.keys()].sort(byKey);
    const list = pkgs.map((p) => apps.get(p)!.entry);
    body.applications = list;
    for (const p of pkgs) sources.push(apps.get(p)!.key);
    if (list.filter((a) => a.installType === 'REQUIRED_FOR_SETUP').length > POLICY_LIMITS.requiredForSetupApps) problems.push('compile:limit:required_for_setup');
    if (list.filter((a) => a.minimumVersionCode !== undefined).length > POLICY_LIMITS.minimumVersionCodeApps) problems.push('compile:limit:minimum_version_code');
    if (list.filter((a) => a.installType === 'KIOSK').length > POLICY_LIMITS.kioskApps) problems.push('compile:limit:kiosk');
  }
  // 4. The kiosk of a dedicated device (kiosk.ts).
  const kiosk = applyKioskRules(body, device.usage, {
    purpose: ctx.purpose, app: ctx.kiosk?.app ?? null, appInCatalog: ctx.kiosk?.appInCatalog === true, exit: ctx.kiosk?.exit === true,
  });
  problems.push(...kiosk.problems);
  if (Array.isArray(body.setupActions) && body.setupActions.length > POLICY_LIMITS.setupActions) problems.push('compile:limit:setup_actions');

  // 6. Preferred activities against default applications, from two keys.
  const domains = preferredActivityConflicts(body[PPA], body[DAS]);
  if (domains.length > 0) {
    const ppa = fieldSettings.get(PPA)!;
    const das = fieldSettings.get(DAS)!;
    if (!ppa.source || !das.source || (ppa.source.type === das.source.type && ppa.source.id === das.source.id)) {
      problems.push('compile:conflict:preferred_activities');
    } else {
      const ppaWins = bySource(ppa.source, das.source) < 0;
      const [winner, loser] = ppaWins ? [ppa, das] : [das, ppa];
      const field = ppaWins ? DAS : PPA;
      const lost = new Set(domains);
      const kept = (body[field] as JsonValue[]).filter((e) => (ppaWins
        ? !lost.has(defaultApplicationDomain(e) ?? '')
        : ![...preferredDomains(e)].some((d) => lost.has(d))));
      if (kept.length > 0) body[field] = kept;
      else {
        delete body[field];
        sources.splice(sources.indexOf(loser.settingKey), 1);
      }
      conflicts.push({ settingKey: loser.settingKey, winner: winner.settingKey, domains, source: loser.source!,
        sameRank: winner.source!.rank === loser.source!.rank && winner.source!.priority === loser.source!.priority });
    }
  }
  // 7. Guards re-checked against today's values.
  if (ctx.guards) {
    if (Array.isArray(body.frpAdminEmails) && body.frpAdminEmails.length > 0) {
      const domain = typeof ctx.guards.adminDomain === 'string' && ctx.guards.adminDomain ? ctx.guards.adminDomain.toLowerCase() : null;
      if (body.frpAdminEmails.some((e) => {
        const m = typeof e === 'string' ? EMAIL_DOMAIN_RE.exec(e) : null;
        return !m || domain === null || m[1].toLowerCase() !== domain;
      })) problems.push('compile:frp_email_outside_domain');
    }
    if (Array.isArray(body.passwordPolicies) && ctx.guards.minFailedPasswordsForWipe !== undefined) {
      const floor = Math.max(FAILED_PASSWORDS_FOR_WIPE.min, Number.isInteger(ctx.guards.minFailedPasswordsForWipe)
        ? ctx.guards.minFailedPasswordsForWipe : FAILED_PASSWORDS_FOR_WIPE.defaultFloor);
      if (body.passwordPolicies.some((pp) => isObject(pp) && typeof pp.maximumFailedPasswordsForWipe === 'number'
        && pp.maximumFailedPasswordsForWipe !== 0 && pp.maximumFailedPasswordsForWipe < floor)) problems.push('compile:wipe_threshold_too_low');
    }
  }

  const secretRefs = [...secretRefsOf(body)].sort();
  if (enrollment && secretRefs.length > 0) throw new AndroidCompileError('enrollmentPolicySecret');
  let hash: string;
  try {
    hash = androidPolicyHash(body);
  } catch (err) {
    // A value no canonical JSON holds (the validation refuses it at the write).
    if (err instanceof CanonicalJsonError) throw new AndroidCompileError('invalid_value');
    throw err;
  }
  sources.sort(byKey);
  return {
    artifactKey: AMAPI_ARTIFACT_KEY, channel: AMAPI_CHANNEL, policyId, body, hash, secretRefs,
    hasVariables: variablesOf(body).length > 0, sources, notApplicable, deferred, problems, conflicts,
    kioskLock: kiosk.lock, kioskExit: kiosk.exitApplied,
  };
}

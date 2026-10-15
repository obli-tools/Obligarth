import { createHash } from 'node:crypto';
import { variablesOf, type JsonValue, type UnavailableReason } from '@obligarth/shared';
import type { AndroidAvailabilityFacts, AndroidUnavailableReason } from '@obligarth/shared/dist/android/availability.js';
import {
  AMAPI_ARTIFACT_KEY, AMAPI_CHANNEL, devicePolicyId, enrollmentPolicyId, parseAndroidSettingKey,
} from '@obligarth/shared/dist/android/policy.js';
import { CanonicalJsonError, canonicalize } from '../../apple/ddm/canonical';
import { secretRefsOf } from '../apple/compile';
import type { VariableValues } from '../apple/variables';
import { androidKeyAvailability } from './availability';
import { androidCatalog, type AndroidCatalogView } from './catalog';
import { POLICY_LIMITS, RESERVED_FIELDS, RESERVED_PACKAGES, RESERVED_ROLES } from './overlay';

// =============================================================================
// The Android compilation: the settings a resolution retained for one device
// become ONE AMAPI Policy, the artifact 'amapi:policy' of the channel 'amapi'.
//   1. Obligarth's base: statusReportingSettings derived from the ownership
//      and the privacy rules (never from a policy), playStoreMode WHITELIST
//      unless a setting says otherwise, the enterprise's name visible;
//   2. the retained and available keys, in the order of the keys;
//   3. applications[]: one entry per package (android:app[…]), sorted, never
//      the reserved package nor a reserved role;
//   4. usage rules: a kiosk device needs a kiosk form (an app installed as
//      KIOSK or holding the KIOSK role, or the custom launcher); a device that
//      is not a kiosk never receives one;
//   5. ownership rules (through the availability: ownership_forbidden);
//   6. canonical JSON (RFC 8785, the function of the DDM engine) and hash.
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
export const ANDROID_COMPILER_VERSION = 1;

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
}

/** A setting retained by the resolution (the resolver's ResolvedSetting has this shape). */
export interface AndroidEffectiveSetting {
  settingKey: string;
  removed: boolean;
  availability: { status: 'available' } | { status: 'not_applicable'; reason: string; detail?: string };
  value?: JsonValue;
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
  catalog?: AndroidCatalogView;
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

const isKioskApp = (a: Record<string, JsonValue>): boolean => a.installType === 'KIOSK'
  || (Array.isArray(a.roles) && a.roles.some((r) => isObject(r) && r.roleType === 'KIOSK'));

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
  // 4. A kiosk device needs a kiosk form.
  if (device.usage === 'kiosk' && !enrollment) {
    const list = Array.isArray(body.applications) ? body.applications.filter(isObject) : [];
    if (!list.some(isKioskApp) && body.kioskCustomLauncherEnabled !== true) problems.push('compile:kiosk_form_missing');
  }
  if (Array.isArray(body.setupActions) && body.setupActions.length > POLICY_LIMITS.setupActions) problems.push('compile:limit:setup_actions');

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
    hasVariables: variablesOf(body).length > 0, sources, notApplicable, deferred, problems,
  };
}

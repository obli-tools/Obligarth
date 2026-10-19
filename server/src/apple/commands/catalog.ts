import { z } from 'zod';
import type { DeviceCapability, NanoEnrollType, Ownership } from '@obligarth/shared';
import { POLICY_PROFILE_PREFIXES } from '@obligarth/shared';
import type { PrivacyRules } from '../devices/privacy';
import { PlistData, plistFromJson, plistFromTypedJson, type PlistDict, type PlistValue } from './plist';
import { UNLOCK_PLACEHOLDER } from './sensitive';

// =============================================================================
// Catalogue of the MDM commands (docs: integration-apple-edge §8.3;
// modele-donnees-mdm §6.2): one CommandSpec per Apple RequestType, registered
// before anything starts; the sister specifications add theirs
// (registerCommandSpec). The bus refuses any type that is not registered.
// A spec says who may ask for the command (capability, restriction key,
// guarded action), on which devices (ownership, supervision, enrollment
// state), and how its Command dictionary is built from validated parameters
// (camelCase, never a secret) and the facts of the device (privacy rules of
// its ownership). `build` is pure: no I/O.
// Ownerships: corporate (E), corporate with personal use (C), personal (B: a
// User Enrollment). The ownership of a record is never unknown (DM25).
// =============================================================================

export type { Ownership };

export interface CommandDeviceContext {
  deviceId: number;
  enrollmentId: string;
  enrollmentType: NanoEnrollType;
  ownership: Ownership | null;
  supervised: boolean | null;
  platform: string | null;
  osVersion: string | null;
  privacy: PrivacyRules;                     // §10.7
  identityCertPem: string | null;            // §8.8
}

export type EnrollmentStateAllowed = 'awaiting_configuration' | 'enrolled';

export interface CommandSpec<P extends z.ZodTypeAny = z.ZodTypeAny> {
  /** Apple RequestType, exact case. */
  requestType: string;
  /** z.object({...}).strict(): validated parameters, never a secret. */
  params: P;
  /** Restriction key (§8.11); null: not restrictable. */
  restrictionKey: string | null;
  /** Device capability required from a console user; null: no console route (system origins only). */
  capability: DeviceCapability | null;
  supervised: 'required' | 'no';
  /** Ownerships allowed; 'personal' means a User Enrollment. */
  ownership: readonly Ownership[];
  enrollmentStates: readonly EnrollmentStateAllowed[];
  /** One command per device (the plist depends on the device). Otherwise the devices whose Command
   *  dictionaries are equal share one command, by slices of 5 000 targets. */
  perDevice: boolean;
  maxTargets: number;
  expiresInSeconds: number;
  /** Key of the guarded action (audit-durci §10.2) this type belongs to: the bus enqueues it only from that
   *  action's execution (origin 'guard', pending_actions row 'executing'). null: not guarded. */
  guardedBy: string | null;
  reasonRequired: boolean;
  /** One open command of this type per device (inventory, DeclarativeManagement, DeviceConfigured): a device
   *  with one already open is set aside (already_open). */
  singleOpen?: boolean;
  /** True when these parameters are reserved to the system origins (a policy, a setup plan…): the bus refuses
   *  them from a user's request (console, bulk, approval). Absent: any origin. */
  systemOnly?(params: z.infer<P>): boolean;
  /** The Command dictionary without RequestType (added by the bus). Pure: no I/O. */
  build(params: z.infer<P>, device: CommandDeviceContext): PlistDict;
  /** Non-personal summary of an Acknowledged result (≤ 4 KiB), e.g. { count: 42 }. */
  summarize?(result: Record<string, unknown>): Record<string, string | number | boolean> | null;
}

const specs = new Map<string, CommandSpec<any>>();
const REQUEST_TYPE_RE = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
const OWNERSHIP_SET = new Set(['corporate', 'corporate_personal', 'personal']);

/** Registers a command type (before jobs.start()); throws on a duplicate or an invalid definition. */
export function registerCommandSpec<P extends z.ZodTypeAny>(spec: CommandSpec<P>): void {
  const t = String(spec?.requestType ?? '');
  const fail = (m: string): never => { throw new Error(`command spec ${JSON.stringify(t)}: ${m}`); };
  if (!REQUEST_TYPE_RE.test(t)) fail('invalid request type');
  if (specs.has(t)) fail('registered twice');
  if (!(spec.params instanceof z.ZodObject) && !(spec.params instanceof z.ZodEffects)) fail('params must be a zod object');
  if (spec.supervised !== 'required' && spec.supervised !== 'no') fail('supervised is required or no');
  if (!spec.ownership.length || !spec.ownership.every((o) => OWNERSHIP_SET.has(o))) fail('invalid ownership list');
  if (!spec.enrollmentStates.length) fail('enrollmentStates is empty');
  if (!Number.isInteger(spec.maxTargets) || spec.maxTargets < 1 || spec.maxTargets > 10_000) fail('maxTargets is 1 to 10 000');
  if (!Number.isInteger(spec.expiresInSeconds) || spec.expiresInSeconds < 60 || spec.expiresInSeconds > 90 * 86_400) fail('expiresInSeconds is 60 s to 90 days');
  if (typeof spec.build !== 'function') fail('build is required');
  specs.set(t, Object.freeze({ ...spec }) as CommandSpec<any>);
}

/** The spec of a request type, or undefined (the bus answers 422 unknownRequestType). */
export function commandSpecOrNull(requestType: string): CommandSpec<any> | undefined {
  return specs.get(requestType);
}

export function commandSpecList(): CommandSpec<any>[] {
  return [...specs.values()];
}

// ── The MVP catalogue ──────────────────────────────────────────────────────────

const DAY = 86_400;
const E_C_B: readonly Ownership[] = ['corporate', 'corporate_personal', 'personal'];
const E_C: readonly Ownership[] = ['corporate', 'corporate_personal'];
const BOTH: readonly EnrollmentStateAllowed[] = ['awaiting_configuration', 'enrolled'];
const ENROLLED: readonly EnrollmentStateAllowed[] = ['enrolled'];
const none = z.object({}).strict();

/** A bundle identifier or a profile identifier (reverse DNS, as Apple writes them). */
const identifier = z.string().trim().min(1).max(255).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/);
const identifiers = z.array(identifier).min(1).max(500);

/** Prefix of the identifier of the enrollment profile of a tenant ('tools.obli.obligarth.enroll.<key>', §10.2):
 *  removing it is the removal from management, reserved to the guarded action mdm.remove_management. */
export const ENROLLMENT_PROFILE_PREFIX = 'tools.obli.obligarth.enroll.';

/** Is this the identifier of a profile a policy delivers (shared POLICY_PROFILE_PREFIXES), compared without case? */
export function isPolicyProfileIdentifier(identifier: string): boolean {
  const id = identifier.toLowerCase();
  return POLICY_PROFILE_PREFIXES.some((p) => id.startsWith(p));
}
export const REMOVE_MANAGEMENT_ACTION = 'mdm.remove_management';

/** The identifier of the enrollment profile of the tenant of `mdmKey`. */
export function enrollmentProfileIdentifier(mdmKey: string): string {
  return `${ENROLLMENT_PROFILE_PREFIX}${mdmKey}`;
}

/** The guarded action a command belongs to, from its type and its parameters (RemoveProfile is guarded only for
 *  the enrollment profile, compared without case); null: not guarded. */
export function guardedActionOf(spec: CommandSpec<any>, params: Record<string, unknown>): string | null {
  if (spec.guardedBy) return spec.guardedBy;
  if (spec.requestType === 'RemoveProfile' && typeof params.identifier === 'string'
    && params.identifier.toLowerCase().startsWith(ENROLLMENT_PROFILE_PREFIX)) return REMOVE_MANAGEMENT_ACTION;
  return null;
}

const count = (key: string) => (r: Record<string, unknown>) => {
  const v = r[key];
  return { count: Array.isArray(v) ? v.length : v && typeof v === 'object' ? Object.keys(v as object).length : 0 };
};

const inventory = { restrictionKey: null, capability: 'mdm:inventory' as const, supervised: 'no' as const, ownership: E_C_B,
  enrollmentStates: BOTH, maxTargets: 10_000, expiresInSeconds: 3 * DAY, guardedBy: null, reasonRequired: false, singleOpen: true };

const lostMode = { restrictionKey: 'mdm.lost_mode', capability: 'mdm:lost_mode' as const, supervised: 'required' as const, ownership: E_C,
  enrollmentStates: ENROLLED, perDevice: false, maxTargets: 50, guardedBy: null, params: none, build: () => ({}) };

const SettingsItem = z.discriminatedUnion('item', [
  z.object({ item: z.literal('DeviceName'), deviceName: z.string().trim().min(1).max(255) }).strict(),
  z.object({ item: z.literal('TimeZone'), timeZone: z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9_+\-/]+$/) }).strict(),
  z.object({ item: z.literal('MDMOptions'), activationLockAllowedWhileSupervised: z.boolean() }).strict(),
]);

/** An item of the Settings command as a policy compiles it (modele-donnees-mdm §7.9, channel 'setting'): its
 *  name and its values, validated against the Apple schema when the policy was saved, in typed JSON. Reserved to
 *  the system origins (systemOnly): a console user asks for the three items above only. */
const PolicySettingsItem = z.object({
  item: z.string().regex(/^[A-Z][A-Za-z0-9]{0,63}$/),
  values: z.record(z.string(), z.unknown()),
}).strict();
type PolicySettingsItemT = z.infer<typeof PolicySettingsItem>;
const isPolicyItem = (i: unknown): i is PolicySettingsItemT => !!i && typeof i === 'object' && 'values' in (i as object);

const InstallApplication = z.object({
  iTunesStoreID: z.number().int().positive().optional(),
  identifier: identifier.optional(),
  manifestURL: z.string().url().max(2000).refine((u) => u.startsWith('https://'), 'manifestURL must be an HTTPS URL').optional(),
  /** 1: removed with the management; 4: no backup of the app's data. */
  managementFlags: z.number().int().min(0).max(5).refine((n) => (n & ~5) === 0, 'managementFlags: 1, 4 or 5').optional(),
  /** Managed configuration of the app (APP-03): a dictionary without secret (the scanner refuses one). */
  configuration: z.record(z.unknown()).optional(),
  attributes: z.record(z.unknown()).optional(),
  /** 0: legacy licence; 1: Apps and Books. */
  purchaseMethod: z.union([z.literal(0), z.literal(1)]).optional(),
  changeManagementState: z.literal('Managed').optional(),
  /** The app of the policies this command delivers ('app:<identifier>@<hash>', lot C4): its reconciliation finds it again.
   *  Never in the plist; reserved to the system origins. */
  policyRef: z.string().regex(/^app:[A-Za-z0-9][A-Za-z0-9._-]{0,199}@[0-9a-f]{64}$/).optional(),
}).strict().refine((p) => [p.iTunesStoreID, p.identifier, p.manifestURL].filter((v) => v !== undefined).length === 1,
  'exactly one of iTunesStoreID, identifier and manifestURL');

let registered = false;

/** The 23 command types of the MVP (§8.3). */
export function registerMvpCommandSpecs(): void {
  if (registered) return;
  registered = true;

  // 1 to 6: inventory. What is asked follows the privacy rules of the device's ownership (§10.7, modele §5.2).
  registerCommandSpec({
    ...inventory, requestType: 'DeviceInformation', perDevice: true,
    params: z.object({ queries: z.array(z.string().regex(/^[A-Za-z][A-Za-z0-9]{0,63}$/)).min(1).max(100).optional() }).strict(),
    build: (p, d) => {
      const allowed = d.privacy.deviceInformationQueries;
      const asked = p.queries ? allowed.filter((q) => p.queries!.includes(q)) : allowed;
      return { Queries: [...asked] };
    },
    summarize: (r) => ({ keys: r.QueryResponses && typeof r.QueryResponses === 'object' ? Object.keys(r.QueryResponses as object).length : 0 }),
  });
  registerCommandSpec({ ...inventory, requestType: 'SecurityInfo', perDevice: false, params: none, build: () => ({}) });
  registerCommandSpec({
    ...inventory, requestType: 'InstalledApplicationList', perDevice: false,
    params: z.object({ identifiers: identifiers.optional() }).strict(),
    build: (p, d) => ({
      ...(p.identifiers ? { Identifiers: p.identifiers } : {}),
      // A personal device, and a company one with personal use by default: the managed apps only.
      ...(d.privacy.installedApps === 'managed_only' ? { ManagedAppsOnly: true } : {}),
    }),
    summarize: count('InstalledApplicationList'),
  });
  registerCommandSpec({
    ...inventory, requestType: 'ManagedApplicationList', perDevice: false,
    params: z.object({ identifiers: identifiers.optional() }).strict(),
    build: (p): PlistDict => (p.identifiers ? { Identifiers: p.identifiers } : {}),
    summarize: count('ManagedApplicationList'),
  });
  registerCommandSpec({ ...inventory, requestType: 'ProfileList', perDevice: false, params: none, build: () => ({}), summarize: count('ProfileList') });
  registerCommandSpec({
    ...inventory, requestType: 'CertificateList', perDevice: false, params: none,
    build: (_p, d): PlistDict => (d.privacy.certificates === 'managed_only' ? { ManagedOnly: true } : {}),
    summarize: count('CertificateList'),
  });
  // 7: the bypass code of the activation lock; apple-edge keeps it and hands a reference (SEC-06).
  registerCommandSpec({
    ...inventory, requestType: 'ActivationLockBypassCode', perDevice: false, params: none, supervised: 'required', ownership: E_C,
    expiresInSeconds: 7 * DAY, build: () => ({}),
  });
  // 8: the DDM synchronisation (§9.4): the tokens of the device's set, as the bytes the relay would answer.
  registerCommandSpec({
    requestType: 'DeclarativeManagement', restrictionKey: null, capability: null, supervised: 'no', ownership: E_C_B, enrollmentStates: BOTH,
    perDevice: true, maxTargets: 10_000, expiresInSeconds: 14 * DAY, guardedBy: null, reasonRequired: false, singleOpen: true,
    params: z.object({ data: z.string().max(87_400).regex(/^[A-Za-z0-9+/]*={0,2}$/).optional() }).strict(),
    build: (p): PlistDict => (p.data ? { Data: new PlistData(Buffer.from(p.data, 'base64')) } : {}),
  });
  // 9: the end of the setup assistant (§8.9), for a device awaiting its configuration only.
  registerCommandSpec({
    requestType: 'DeviceConfigured', restrictionKey: null, capability: null, supervised: 'no', ownership: E_C,
    enrollmentStates: ['awaiting_configuration'], perDevice: true, maxTargets: 10_000, expiresInSeconds: DAY, guardedBy: null,
    reasonRequired: false, singleOpen: true, params: none, build: () => ({}),
  });
  // 10: guarded action mdm.device_lock.
  registerCommandSpec({
    requestType: 'DeviceLock', restrictionKey: 'mdm.device_lock', capability: 'mdm:lock', supervised: 'no', ownership: E_C,
    enrollmentStates: ENROLLED, perDevice: true, maxTargets: 10_000, expiresInSeconds: 7 * DAY, guardedBy: 'mdm.device_lock', reasonRequired: false,
    params: z.object({ message: z.string().trim().min(1).max(200).optional(), phoneNumber: z.string().trim().min(1).max(30).optional() }).strict(),
    build: (p) => ({ ...(p.message ? { Message: p.message } : {}), ...(p.phoneNumber ? { PhoneNumber: p.phoneNumber } : {}) }),
  });
  // 11, 12
  for (const requestType of ['RestartDevice', 'ShutDownDevice']) {
    registerCommandSpec({
      requestType, restrictionKey: 'mdm.restart', capability: 'mdm:restart', supervised: 'required', ownership: E_C, enrollmentStates: ENROLLED,
      perDevice: false, maxTargets: 500, expiresInSeconds: DAY, guardedBy: null, reasonRequired: false, params: none, build: () => ({}),
    });
  }
  // 13: guarded action mdm.erase_device.
  registerCommandSpec({
    requestType: 'EraseDevice', restrictionKey: 'mdm.erase_device', capability: 'mdm:wipe', supervised: 'no', ownership: E_C,
    enrollmentStates: BOTH, perDevice: true, maxTargets: 10_000, expiresInSeconds: 7 * DAY, guardedBy: 'mdm.erase_device', reasonRequired: false,
    params: z.object({ preserveDataPlan: z.boolean().default(true), disallowProximitySetup: z.boolean().default(false) }).strict(),
    build: (p) => ({ PreserveDataPlan: p.preserveDataPlan, DisallowProximitySetup: p.disallowProximitySetup }),
  });
  // 14: the UnlockToken is a placeholder apple-edge replaces at delivery (§8.8): one target, the placeholder once.
  registerCommandSpec({
    requestType: 'ClearPasscode', restrictionKey: 'mdm.clear_passcode', capability: 'mdm:passcode', supervised: 'no', ownership: E_C,
    enrollmentStates: ENROLLED, perDevice: true, maxTargets: 1, expiresInSeconds: 3 * DAY, guardedBy: null, reasonRequired: true,
    params: none, build: () => ({ UnlockToken: UNLOCK_PLACEHOLDER }),
  });
  // 15: guarded action mdm.lost_mode_enable.
  registerCommandSpec({
    requestType: 'EnableLostMode', restrictionKey: 'mdm.lost_mode_enable', capability: 'mdm:lost_mode', supervised: 'required', ownership: E_C,
    enrollmentStates: ENROLLED, perDevice: true, maxTargets: 10_000, expiresInSeconds: 30 * DAY, guardedBy: 'mdm.lost_mode_enable', reasonRequired: false,
    params: z.object({
      message: z.string().trim().min(1).max(200).optional(), phoneNumber: z.string().trim().min(1).max(30).optional(),
      footnote: z.string().trim().min(1).max(200).optional(),
    }).strict().refine((p) => p.message !== undefined || p.phoneNumber !== undefined, 'message or phoneNumber is required'),
    build: (p) => ({
      ...(p.message ? { Message: p.message } : {}), ...(p.phoneNumber ? { PhoneNumber: p.phoneNumber } : {}),
      ...(p.footnote ? { Footnote: p.footnote } : {}),
    }),
  });
  // 16 to 18
  registerCommandSpec({ ...lostMode, requestType: 'DisableLostMode', expiresInSeconds: 30 * DAY, reasonRequired: false });
  registerCommandSpec({ ...lostMode, requestType: 'DeviceLocation', expiresInSeconds: DAY, reasonRequired: true });
  registerCommandSpec({ ...lostMode, requestType: 'PlayLostModeSound', expiresInSeconds: DAY, reasonRequired: false });
  // 19: the profile comes from a registered source (§8.8); the bus resolves it per device and builds the Payload
  // (encrypted for the device when it carries a secret), so `build` is not what writes it.
  registerCommandSpec({
    requestType: 'InstallProfile', restrictionKey: 'mdm.profiles', capability: 'mdm:profiles', supervised: 'no', ownership: E_C_B,
    enrollmentStates: BOTH, perDevice: true, maxTargets: 10_000, expiresInSeconds: 14 * DAY, guardedBy: null, reasonRequired: false,
    params: z.object({
      /** Kind of the profile source ('policy', 'wifi'…). */
      source: z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/).default('policy'),
      profileRef: z.string().min(1).max(300),
    }).strict(),
    build: () => { throw new Error('InstallProfile is built by the bus from its profile source'); },
  });
  // 20: the enrollment profile is removed by the guarded action mdm.remove_management only (guardedActionOf). A profile
  // of a policy (tools.obli.obligarth.p. or .raw.) is removed by the reconciliation of its artifacts only: from the
  // console, the same removal on 500 devices escaped the preview and the thresholds of DM23 (review of lot B5c,
  // MDM-B5c-R7; decision of the owners of 15/10/2026). Compared without case, like the enrollment profile.
  registerCommandSpec({
    requestType: 'RemoveProfile', restrictionKey: 'mdm.profiles', capability: 'mdm:profiles', supervised: 'no', ownership: E_C_B,
    enrollmentStates: BOTH, perDevice: false, maxTargets: 10_000, expiresInSeconds: 14 * DAY, guardedBy: null, reasonRequired: false,
    params: z.object({ identifier }).strict(),
    systemOnly: (p) => isPolicyProfileIdentifier(p.identifier),
    build: (p) => ({ Identifier: p.identifier }),
  });
  // 21, 22
  registerCommandSpec({
    requestType: 'InstallApplication', restrictionKey: 'mdm.apps', capability: 'mdm:apps', supervised: 'no', ownership: E_C_B,
    enrollmentStates: BOTH, perDevice: false, maxTargets: 10_000, expiresInSeconds: 14 * DAY, guardedBy: null, reasonRequired: false,
    params: InstallApplication,
    systemOnly: (p) => p.policyRef !== undefined,
    build: (p) => {
      const out: Record<string, PlistValue> = {};
      if (p.iTunesStoreID !== undefined) out.iTunesStoreID = p.iTunesStoreID;
      if (p.identifier !== undefined) out.Identifier = p.identifier;
      if (p.manifestURL !== undefined) out.ManifestURL = p.manifestURL;
      if (p.managementFlags !== undefined) out.ManagementFlags = p.managementFlags;
      if (p.configuration !== undefined) out.Configuration = plistFromJson(p.configuration);
      if (p.attributes !== undefined) out.Attributes = plistFromJson(p.attributes);
      if (p.purchaseMethod !== undefined) out.Options = { PurchaseMethod: p.purchaseMethod };
      if (p.changeManagementState !== undefined) out.ChangeManagementState = p.changeManagementState;
      return out;
    },
  });
  registerCommandSpec({
    requestType: 'RemoveApplication', restrictionKey: 'mdm.apps', capability: 'mdm:apps', supervised: 'no', ownership: E_C_B,
    enrollmentStates: BOTH, perDevice: false, maxTargets: 10_000, expiresInSeconds: 14 * DAY, guardedBy: null, reasonRequired: false,
    params: z.object({ identifier }).strict(),
    build: (p) => ({ Identifier: p.identifier }),
  });
  // 23: the three items of the MVP all need supervision.
  registerCommandSpec({
    requestType: 'Settings', restrictionKey: 'mdm.settings', capability: 'mdm:profiles', supervised: 'required', ownership: E_C,
    enrollmentStates: BOTH, perDevice: false, maxTargets: 10_000, expiresInSeconds: 7 * DAY, guardedBy: null, reasonRequired: false,
    params: z.object({
      items: z.array(z.union([SettingsItem, PolicySettingsItem])).min(1).max(10),
      /** The artifact of a policy these items deliver ('<artifact key>@<hash>'): its reconciliation finds it again. */
      policyRef: z.string().min(1).max(300).optional(),
    }).strict(),
    systemOnly: (p) => p.policyRef !== undefined || p.items.some(isPolicyItem),
    build: (p) => ({
      Settings: p.items.map((i): PlistDict => {
        if (isPolicyItem(i)) return { ...(plistFromTypedJson(i.values) as PlistDict), Item: i.item };
        if (i.item === 'DeviceName') return { Item: 'DeviceName', DeviceName: i.deviceName };
        if (i.item === 'TimeZone') return { Item: 'TimeZone', TimeZone: i.timeZone };
        return { Item: 'MDMOptions', MDMOptions: { ActivationLockAllowedWhileSupervised: i.activationLockAllowedWhileSupervised } };
      }),
    }),
  });
}

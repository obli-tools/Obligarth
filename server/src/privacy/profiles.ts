import type { Knex } from 'knex';
import { z } from 'zod';
import {
  DEFAULT_PRIVACY_PROFILE, OWNERSHIPS, PRIVACY_COLLECTION_SCOPES, privacyRuleViolations,
  type NanoEnrollType, type Ownership, type PrivacyCollectionScope, type PrivacyProfileRules, type PrivacyRuleKey,
} from '@obligarth/shared';
import {
  BASE_QUERIES, BASE_STATUS_ITEMS, DEVICE_NAME_QUERIES, HARDWARE_ID_QUERIES, NETWORK_QUERIES, PHONE_QUERIES,
  SERIAL_QUERIES, SERIAL_STATUS_ITEMS, UDID_QUERIES, UDID_STATUS_ITEMS, setPrivacyRulesResolver,
  type PrivacyRules, type PrivacyRulesResolver,
} from '../apple/devices/privacy';
import { DEFAULT_PRIVACY, type AndroidPrivacyRules } from '../android/inventory/privacy';

// =============================================================================
// Privacy profiles of the tenants (P0-13 T1, CNF-02; conception §10.3): the current version of a tenant's profile
// per ownership (obligarth.privacy_profile_current, cached per tenant), and its translation into the rules of each
// channel:
//   - Apple (toAppleRules): the DeviceInformation keys and DDM status items of defaultPrivacyRules
//     (apple/devices/privacy.ts), composed from the profile; installed as the PrivacyRulesResolver of every Apple
//     consumer (installPrivacyProfiles, called by registerPrivacyModule before anything starts);
//   - Android AMAPI (toAndroidRules): networkInfo, IMEI (hardware identifiers), installed applications; read by the
//     ingestion filter (enrollment/handler.ts, inventory/statusReport.ts) and by the compilation of
//     statusReportingSettings (policies/push.ts) through androidPrivacyRulesFor (P0-13 T2);
//   - bridge agent (toLegacyAgentRules, decision D14): IMEI and the full application list of the corporate
//     profile (legacyAgent/enroll.ts, legacyAgent/inventory.ts); the serial number stays collected (identity of the
//     device, PB13);
//   - location in lost mode (P0-13 T2): lostModeLocation of the Apple rules for the bus and the command routes
//     (DeviceLocation: location_disabled, 409 locationDisabledByPrivacy); lostModeLocationAllowed for the ingestion
//     of the positions (Apple DeviceLocation, Android usage logs) and their reading (GET /api/mdm/devices/:id/locations).
// A tenant without a version of an ownership keeps exactly the rules applied before P0-13 (acceptance criterion 1):
// defaultPrivacyRules for Apple, DEFAULT_PRIVACY for Android (stricter than DEFAULT_PRIVACY_PROFILE: IMEI of a
// corporate device and network of a COPE device are collected only once the tenant's profile allows them), and
// serial number, IMEI and every application for the bridge agent (= the default corporate profile).
// An unknown ownership (never for a record, DM25) gets the strictest of the tenant's three profiles.
// Reads in the caller's connection or transaction; a failure is thrown, never replaced by the defaults (they may
// collect more than the tenant's profile). The cache (30 s, per tenant) is dropped by a publication in this process;
// another process sees it within its lifetime.
// =============================================================================

const CACHE_TTL_MS = 30_000;
const CACHE_MAX_TENANTS = 5_000;

const scope = z.enum(PRIVACY_COLLECTION_SCOPES);

/** A profile's rules: the eight keys of PrivacyProfileRules, of their types, and no other (the CHECK
 *  privacy_profile_versions_rules_shape of the table). */
export const PrivacyProfileRulesSchema = z.object({
  serialNumber: z.boolean(),
  hardwareIds: z.boolean(),
  deviceName: z.boolean(),
  phoneNumber: z.boolean(),
  network: z.boolean(),
  lostModeLocation: z.boolean(),
  installedApps: scope,
  certificates: scope,
}).strict();

export const OwnershipSchema = z.enum(OWNERSHIPS);

/** Checks a body's rules for `ownership`: shape (400 invalidPrivacyRules), then the imposed rules (400
 *  privacyRuleImposed, with the offending keys). */
export function checkProfileRules(ownership: Ownership, value: unknown):
  { ok: true; rules: PrivacyProfileRules } | { ok: false; code: 'invalidPrivacyRules' | 'privacyRuleImposed'; keys: string[] } {
  const parsed = PrivacyProfileRulesSchema.safeParse(value);
  if (!parsed.success) {
    const keys = [...new Set(parsed.error.issues.map((i) => (i.path.length ? String(i.path[0]) : (i as { keys?: string[] }).keys?.join(',') ?? '')))]
      .filter(Boolean).slice(0, 10);
    return { ok: false, code: 'invalidPrivacyRules', keys };
  }
  const imposed = privacyRuleViolations(ownership, parsed.data);
  if (imposed.length > 0) return { ok: false, code: 'privacyRuleImposed', keys: imposed };
  return { ok: true, rules: parsed.data };
}

/** The current version of a tenant's profile for an ownership. */
export interface CurrentPrivacyProfile {
  id: string;
  ownership: Ownership;
  version: number;
  rules: PrivacyProfileRules;
  createdAt: Date;
}

type Q = Knex | Knex.Transaction;
interface TenantEntry { at: number; profiles: Map<Ownership, CurrentPrivacyProfile> }
const cache = new Map<number, TenantEntry>();

/** Drops the cached profiles of a tenant (every tenant without argument). */
export function invalidatePrivacyProfiles(tenantId?: number): void {
  if (tenantId === undefined) cache.clear();
  else cache.delete(tenantId);
}

const isOwnership = (v: unknown): v is Ownership => (OWNERSHIPS as readonly string[]).includes(v as string);

async function loadTenant(q: Q, tenantId: number): Promise<Map<Ownership, CurrentPrivacyProfile>> {
  const now = Date.now();
  const hit = cache.get(tenantId);
  if (hit && now - hit.at < CACHE_TTL_MS) return hit.profiles;
  const res = await q.raw('SELECT ownership, profile_id, version, rules, created_at FROM obligarth.privacy_profile_current(?)', [tenantId]) as {
    rows: Array<{ ownership: string; profile_id: string; version: number; rules: unknown; created_at: Date }>;
  };
  const profiles = new Map<Ownership, CurrentPrivacyProfile>();
  for (const r of res.rows) {
    const rules = PrivacyProfileRulesSchema.safeParse(r.rules);
    // The CHECKs of the table make both impossible: refuse rather than guess.
    if (!isOwnership(r.ownership) || !rules.success) {
      throw Object.assign(new Error('privacy profile: unreadable version in base'), { code: 'privacyProfileInvalid' });
    }
    profiles.set(r.ownership, { id: r.profile_id, ownership: r.ownership, version: Number(r.version), rules: rules.data, createdAt: new Date(r.created_at) });
  }
  if (cache.size >= CACHE_MAX_TENANTS) cache.delete(cache.keys().next().value as number);
  cache.set(tenantId, { at: now, profiles });
  return profiles;
}

/** The current version of the tenant's profile for `ownership`, or null: none published (the defaults apply). */
export async function currentProfile(q: Q, tenantId: number, ownership: Ownership): Promise<CurrentPrivacyProfile | null> {
  return (await loadTenant(q, tenantId)).get(ownership) ?? null;
}

/** Has the tenant published a profile (any ownership)? */
export async function tenantHasPrivacyProfile(q: Q, tenantId: number): Promise<boolean> {
  return (await loadTenant(q, tenantId)).size > 0;
}

/** The strictest of several rules: a datum collected only when every one collects it. */
export function strictestRules(list: readonly PrivacyProfileRules[]): PrivacyProfileRules {
  const all = (k: Exclude<PrivacyRuleKey, 'installedApps' | 'certificates'>): boolean => list.every((r) => r[k]);
  const sc = (k: 'installedApps' | 'certificates'): PrivacyCollectionScope => (list.every((r) => r[k] === 'all') ? 'all' : 'managed_only');
  return {
    serialNumber: all('serialNumber'), hardwareIds: all('hardwareIds'), deviceName: all('deviceName'), phoneNumber: all('phoneNumber'),
    network: all('network'), lostModeLocation: all('lostModeLocation'), installedApps: sc('installedApps'), certificates: sc('certificates'),
  };
}

/** The rules in force of an ownership of the tenant: its current version, else the default profile; an unknown
 *  ownership gets the strictest of the three. */
export async function effectiveProfileRules(q: Q, tenantId: number, ownership: Ownership | null): Promise<PrivacyProfileRules> {
  const profiles = await loadTenant(q, tenantId);
  const of = (o: Ownership): PrivacyProfileRules => profiles.get(o)?.rules ?? DEFAULT_PRIVACY_PROFILE[o];
  return ownership ? of(ownership) : strictestRules(OWNERSHIPS.map(of));
}

/** May the organisation locate a device of this ownership (lost mode only, REQ-03)? Never a personal device, whatever
 *  the profile (the CHECK privacy_profile_versions_personal_location and lost_mode_locations_guard); otherwise the
 *  lostModeLocation rule of the tenant's profile (P0-13 T2: the DeviceLocation of Apple, the lost mode positions of
 *  Android, their reading). Without a version: the default profile, as before P0-13 (a company device is located). */
export async function lostModeLocationAllowed(q: Q, tenantId: number, ownership: string | null): Promise<boolean> {
  if (ownership === 'personal') return false;
  return (await effectiveProfileRules(q, tenantId, isOwnership(ownership) ? ownership : null)).lostModeLocation;
}

// ── Apple ───────────────────────────────────────────────────────────────────

/** Days a record is kept after its unenrollment by default (conception §10.3): the defaults of the categories
 *  unenrolled_*_days. The retention of a record is the tenant's (P0-13 T4, CNF-04): mdm/registry/unenroll.ts reads it
 *  (privacy/retention.ts), not this field. */
const retentionDaysAfterUnenroll = (ownership: Ownership | null): number => (ownership === 'corporate' || ownership === 'corporate_personal' ? 90 : 30);

/** The Apple rules of a profile (the composition of defaultPrivacyRules, parameterised by the profile). User
 *  Enrollment never gives a serial number, hardware identifiers nor a UDID, whatever the profile. */
export function toAppleRules(rules: PrivacyProfileRules, ownership: Ownership | null, enrollmentType: NanoEnrollType): PrivacyRules {
  const userEnrollment = enrollmentType === 'User Enrollment (Device)';
  const storeSerialNumber = rules.serialNumber && !userEnrollment;
  const storeHardwareIds = rules.hardwareIds && !userEnrollment;
  return {
    storeSerialNumber,
    storeHardwareIds,
    storeDeviceName: rules.deviceName,
    installedApps: rules.installedApps,
    deviceInformationQueries: [
      ...BASE_QUERIES,
      ...(storeSerialNumber ? SERIAL_QUERIES : []),
      ...(userEnrollment ? [] : UDID_QUERIES),
      ...(storeHardwareIds ? HARDWARE_ID_QUERIES : []),
      ...(rules.deviceName ? DEVICE_NAME_QUERIES : []),
      ...(rules.phoneNumber ? PHONE_QUERIES : []),
      ...(rules.network ? NETWORK_QUERIES : []),
    ],
    statusItems: [
      ...BASE_STATUS_ITEMS,
      ...(storeSerialNumber ? SERIAL_STATUS_ITEMS : []),
      ...(userEnrollment ? [] : UDID_STATUS_ITEMS),
    ],
    retentionDaysAfterUnenroll: retentionDaysAfterUnenroll(ownership),
    certificates: rules.certificates,
    storePhoneNumber: rules.phoneNumber,
    storeNetwork: rules.network,
    lostModeLocation: rules.lostModeLocation,
  };
}

/** The resolver of the Apple consumers: the tenant's profile, the default profile otherwise (= defaultPrivacyRules). */
export const profilePrivacyRulesResolver: PrivacyRulesResolver = {
  async rulesFor(q, tenantId, ownership, enrollmentType) {
    return toAppleRules(await effectiveProfileRules(q, tenantId, ownership), ownership, enrollmentType);
  },
};

// ── Android AMAPI ──────────────────────────────────────────────────────────

/** The Android rules of a device: those of the ingestion filter and of the compilation (statusReportingSettings),
 *  with the applications' scope. */
export interface AndroidProfileRules extends AndroidPrivacyRules {
  installedApps: PrivacyCollectionScope;
}

type AndroidOwnership = 'corporate' | 'corporate_personal' | 'personal';
const androidKey = (ownership: string | null): AndroidOwnership | null => (isOwnership(ownership) ? ownership : null);

/** The Android rules of a profile. Network information comes from a company device only (Google reports none of a
 *  personal one, and the ingestion keeps none: AN19); the IMEI is part of it, under the hardware identifiers rule. */
export function toAndroidRules(rules: PrivacyProfileRules, ownership: string | null): AndroidProfileRules {
  const company = ownership === 'corporate' || ownership === 'corporate_personal';
  const networkInfo = company && rules.network;
  return { networkInfo, imei: networkInfo && rules.hardwareIds, installedApps: rules.installedApps };
}

/** The rules of an Android device of the tenant: its profile; without a version of the ownership, the rules of
 *  before P0-13 (DEFAULT_PRIVACY), with the applications of the default profile. */
export async function androidPrivacyRulesFor(q: Q, tenantId: number, ownership: string | null): Promise<AndroidProfileRules> {
  const o = androidKey(ownership);
  if (!o) return toAndroidRules(await effectiveProfileRules(q, tenantId, null), null);   // as a personal device: nothing of the network
  const profile = await currentProfile(q, tenantId, o);
  return profile ? toAndroidRules(profile.rules, o) : { ...DEFAULT_PRIVACY[o], installedApps: DEFAULT_PRIVACY_PROFILE[o].installedApps };
}

// ── Bridge agent (legacy_agent) ─────────────────────────────────────────────

/** What the bridge agent keeps of a device (corporate only, legacyAgent/enroll.ts): the serial number always (its
 *  identity, PB13), the IMEI and the full list of applications according to the corporate profile (D14). */
export interface LegacyAgentProfileRules {
  imei: boolean;
  installedApps: PrivacyCollectionScope;
}

export const toLegacyAgentRules = (rules: PrivacyProfileRules): LegacyAgentProfileRules =>
  ({ imei: rules.hardwareIds, installedApps: rules.installedApps });

/** The bridge agent's rules of the tenant (its corporate profile, the default one otherwise: IMEI and every
 *  application, as before P0-13). */
export async function legacyAgentPrivacyRulesFor(q: Q, tenantId: number): Promise<LegacyAgentProfileRules> {
  return toLegacyAgentRules(await effectiveProfileRules(q, tenantId, 'corporate'));
}

// ── Publication ────────────────────────────────────────────────────────────

/** Publishes the next version of a profile (obligarth.privacy_profile_publish, in the tenant's context: the
 *  approval executor, as the requester). The CHECKs refuse an imposed rule (23514, constraint
 *  privacy_profile_versions_personal_* or _shared_apps); the function refuses a request that does not match
 *  (42501). The cache of the tenant is dropped now and after the transaction ends. */
export async function publishProfile(trx: Knex.Transaction, tenantId: number, input: {
  ownership: Ownership; rules: PrivacyProfileRules; justification: string | null; approvalId: number | null;
}): Promise<{ id: string; version: number; previousId: string | null }> {
  const res = await trx.raw('SELECT profile_id, profile_version, previous_id FROM obligarth.privacy_profile_publish(?, ?::jsonb, ?, ?)',
    [input.ownership, JSON.stringify(input.rules), input.justification, input.approvalId]) as {
    rows: Array<{ profile_id: string; profile_version: number; previous_id: string | null }>;
  };
  invalidatePrivacyProfiles(tenantId);
  void trx.executionPromise?.then(() => invalidatePrivacyProfiles(tenantId), () => invalidatePrivacyProfiles(tenantId));
  const r = res.rows[0];
  return { id: r.profile_id, version: Number(r.profile_version), previousId: r.previous_id ?? null };
}

/** The constraints of the imposed rules (a check_violation on one of them: 400 privacyRuleImposed). */
export const IMPOSED_RULE_CONSTRAINTS: readonly string[] = [
  'privacy_profile_versions_personal_location', 'privacy_profile_versions_personal_serial', 'privacy_profile_versions_shared_apps',
];

let installed = false;

/** Installs the profiles as the resolver of the Apple consumers (registerPrivacyModule, before anything starts). */
export function installPrivacyProfiles(): void {
  if (installed) return;
  installed = true;
  setPrivacyRulesResolver(profilePrivacyRulesResolver);
}

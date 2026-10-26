// =============================================================================
// Privacy profiles of a tenant (P0-13 T1, CNF-02; conception §10.3, REQ-02): what the organisation collects from
// its devices, one profile per tenant and ownership (D1). Versioned and immutable in base
// (obligarth.privacy_profile_versions, written by obligarth.privacy_profile_publish only, after an approval). A
// tenant without a version of an ownership gets DEFAULT_PRIVACY_PROFILE, the rules applied before P0-13.
// The imposed rules (IMPOSED_RULES) are refused by the API (400 privacyRuleImposed) and by the CHECKs of the table
// (migration privacy_profiles): both change together. Validation of a body: the zod schema of the server
// (privacy/profiles.ts), built on these keys.
// =============================================================================

import type { Ownership } from './mdm/enums';

/** Rules that allow or refuse the collection of a datum. */
export const PRIVACY_BOOLEAN_RULES = [
  'serialNumber',       // serial number (Apple: SerialNumber; Android: hardwareInfo.serialNumber)
  'hardwareIds',        // IMEI, MEID, EID, MAC addresses (Android: IMEI of networkInfo; bridge agent: IMEI)
  'deviceName',         // name given to the device by its user
  'phoneNumber',        // phone number, ICCID, subscriptions
  'network',            // carrier, roaming, Wi-Fi and Bluetooth MAC (Android: networkInfo)
  'lostModeLocation',   // location of a lost device, in lost mode only (REQ-03)
] as const;
export type PrivacyBooleanRule = typeof PRIVACY_BOOLEAN_RULES[number];

/** Rules of an inventory that may be limited to what the organisation manages. */
export const PRIVACY_SCOPE_RULES = ['installedApps', 'certificates'] as const;
export type PrivacyScopeRule = typeof PRIVACY_SCOPE_RULES[number];

export const PRIVACY_COLLECTION_SCOPES = ['all', 'managed_only'] as const;
export type PrivacyCollectionScope = typeof PRIVACY_COLLECTION_SCOPES[number];

/** Every key of a profile, in display order (the CHECK of the table admits these keys and no other). */
export const PRIVACY_RULE_KEYS = [...PRIVACY_BOOLEAN_RULES, ...PRIVACY_SCOPE_RULES] as const;
export type PrivacyRuleKey = typeof PRIVACY_RULE_KEYS[number];

export interface PrivacyProfileRules {
  serialNumber: boolean;
  hardwareIds: boolean;
  deviceName: boolean;
  phoneNumber: boolean;
  network: boolean;
  lostModeLocation: boolean;
  installedApps: PrivacyCollectionScope;
  certificates: PrivacyCollectionScope;
}

/** The rules of a tenant without a profile (conception §10.3): exactly those applied to Apple before P0-13
 *  (apple/devices/privacy.ts defaultPrivacyRules). Android and the bridge agent keep their own minimal rules
 *  while the tenant has no version of the ownership (privacy/profiles.ts). */
export const DEFAULT_PRIVACY_PROFILE: Readonly<Record<Ownership, Readonly<PrivacyProfileRules>>> = {
  corporate: {
    serialNumber: true, hardwareIds: true, deviceName: true, phoneNumber: true, network: true, lostModeLocation: true,
    installedApps: 'all', certificates: 'all',
  },
  corporate_personal: {
    serialNumber: true, hardwareIds: true, deviceName: false, phoneNumber: false, network: true, lostModeLocation: true,
    installedApps: 'managed_only', certificates: 'managed_only',
  },
  personal: {
    serialNumber: false, hardwareIds: false, deviceName: false, phoneNumber: false, network: false, lostModeLocation: false,
    installedApps: 'managed_only', certificates: 'managed_only',
  },
};

/** The rules no profile may change, per ownership (conception §10.3; D2: applications managed only in COPE). */
export const IMPOSED_RULES: Readonly<Record<Ownership, Readonly<Partial<PrivacyProfileRules>>>> = {
  corporate: {},
  corporate_personal: { installedApps: 'managed_only' },
  personal: { serialNumber: false, lostModeLocation: false, installedApps: 'managed_only' },
};

/** The keys of `rules` that break an imposed rule of `ownership` (empty: none). */
export function privacyRuleViolations(ownership: Ownership, rules: PrivacyProfileRules): PrivacyRuleKey[] {
  const imposed = IMPOSED_RULES[ownership];
  return PRIVACY_RULE_KEYS.filter((k) => imposed[k] !== undefined && rules[k] !== imposed[k]);
}

/** Is `key` imposed for `ownership` (shown as such, never editable)? */
export const isImposedRule = (ownership: Ownership, key: PrivacyRuleKey): boolean => IMPOSED_RULES[ownership][key] !== undefined;

/** What a change of rules does to the collection: the keys that collect less (their data are cleaned once the version
 *  is published, privacy.apply-profile) and those that collect more (new data, to tell the employees: USR-01). */
export function privacyRuleChanges(from: PrivacyProfileRules, to: PrivacyProfileRules): { narrowed: PrivacyRuleKey[]; widened: PrivacyRuleKey[] } {
  const narrowed: PrivacyRuleKey[] = [];
  const widened: PrivacyRuleKey[] = [];
  for (const k of PRIVACY_RULE_KEYS) {
    if (from[k] === to[k]) continue;
    const collectsMore = typeof to[k] === 'boolean' ? to[k] === true : to[k] === 'all';
    (collectsMore ? widened : narrowed).push(k);
  }
  return { narrowed, widened };
}

// ── API of the profiles (P0-13 T3: GET /api/privacy/profiles, GET …/:ownership/impact) ─────────────────────────

/** One version of a profile of the tenant. */
export interface PrivacyProfileVersionDto {
  id: string;
  version: number;
  rules: PrivacyProfileRules;
  justification: string | null;
  approvalId: number | null;
  createdBy: number | null;
  approvedBy: number | null;
  createdAt: string;
  supersededAt: string | null;
}

/** A change of the profile waiting for its approval (one at most per ownership). */
export interface PrivacyProfilePendingDto {
  approvalId: number;
  requestedBy: number;
  requestedAt: string;
  expiresAt: string;
  rules: PrivacyProfileRules;
}

/** The profile of one ownership: its current version (null: the defaults apply), the rules in force, the imposed keys,
 *  the change waiting for its approval, the last versions (newest first). */
export interface PrivacyOwnershipProfileDto {
  ownership: Ownership;
  current: PrivacyProfileVersionDto | null;
  defaults: PrivacyProfileRules;
  effective: PrivacyProfileRules;
  imposed: PrivacyRuleKey[];
  pending: PrivacyProfilePendingDto | null;
  history: PrivacyProfileVersionDto[];
}

export interface PrivacyProfilesDto {
  profiles: PrivacyOwnershipProfileDto[];
  /** May the reader request a change (mdm.privacy.manage)? */
  canManage: boolean;
}

/** The impact of proposed rules on an ownership of the tenant, before the request is filed. `firstVersion`: the
 *  tenant has no version of the ownership yet; Android and the bridge agent then keep their own minimal rules
 *  (privacy/profiles.ts), and the first version may collect more there than `widened` says (IMEI of a corporate
 *  Android device, network of a COPE one). `scrub`: rows the publication would remove (applications not managed,
 *  positions in lost mode); the other narrowed fields are set to NULL on the records. */
export interface PrivacyImpactDto {
  ownership: Ownership;
  baseVersion: number | null;
  firstVersion: boolean;
  rules: PrivacyProfileRules;
  narrowed: PrivacyRuleKey[];
  widened: PrivacyRuleKey[];
  devices: { total: number; apple: number; android: number; legacyAgent: number };
  scrub: { apps: number; locations: number };
}

// ── Retention per tenant (P0-13 T4, CNF-04; conception §10.4) ───────────────────────────────────────────────────
// How long each category of data is kept, per tenant, within the ranges of the conception. Stored in
// obligarth.tenant_retention_policies (values in force, decreases waiting), read by obligarth.retention_value (the
// purges, the dates of purge, the notice); changed by obligarth.retention_set after an approval (D3). A decrease takes
// effect RETENTION_LOWERING_DELAY_DAYS days after its approval and may be cancelled meanwhile; an increase at once (D4).
// The catalogue is copied into the migration retention_policies (obligarth_private.retention_catalog, the CHECKs): both
// change together (testbed 172 compares them).

export type RetentionUnit = 'days' | 'months';

export interface RetentionCategoryDef {
  key: string;
  /** The value of a tenant that set none. */
  default: number;
  min: number;
  max: number;
  unit: RetentionUnit;
}

/** The categories a tenant may set, in display order (key, default, range, unit), and where each applies. */
export const RETENTION_CATEGORIES = [
  { key: 'unenrolled_corporate_days', default: 90, min: 30, max: 365, unit: 'days' },            // record of a corporate device out of management
  { key: 'unenrolled_corporate_personal_days', default: 90, min: 30, max: 365, unit: 'days' },   // … of a COPE device
  { key: 'unenrolled_personal_days', default: 30, min: 30, max: 365, unit: 'days' },             // … of a personal device
  { key: 'departed_end_user_days', default: 90, min: 30, max: 365, unit: 'days' },               // device ↔ employee link of a departed end user
  { key: 'lost_mode_location_days', default: 30, min: 1, max: 62, unit: 'days' },                // positions of the lost mode
  { key: 'technical_log_months', default: 6, min: 3, max: 12, unit: 'months' },                  // commands (MDM queue, bridge agent), timeline
  { key: 'status_history_days', default: 90, min: 30, max: 365, unit: 'days' },                  // DDM status history
  { key: 'notice_ack_months', default: 36, min: 12, max: 72, unit: 'months' },                   // acknowledgements of the notice (D5)
] as const satisfies readonly RetentionCategoryDef[];

export type RetentionCategory = typeof RETENTION_CATEGORIES[number]['key'];
export const RETENTION_CATEGORY_KEYS: readonly RetentionCategory[] = RETENTION_CATEGORIES.map((c) => c.key);

/** Days between the approval of a decrease and its effect (D4). */
export const RETENTION_LOWERING_DELAY_DAYS = 7;

export const isRetentionCategory = (v: unknown): v is RetentionCategory =>
  typeof v === 'string' && (RETENTION_CATEGORY_KEYS as readonly string[]).includes(v);

export function retentionCategoryDef(key: RetentionCategory): RetentionCategoryDef {
  return RETENTION_CATEGORIES.find((c) => c.key === key)!;
}

/** The category of the retention of a record out of management, per ownership (unknown: the shortest, personal). */
export function unenrolledRetentionCategory(ownership: Ownership | string | null): RetentionCategory {
  if (ownership === 'corporate') return 'unenrolled_corporate_days';
  if (ownership === 'corporate_personal') return 'unenrolled_corporate_personal_days';
  return 'unenrolled_personal_days';
}

/** The defaults of every category. */
export const DEFAULT_RETENTION: Readonly<Record<RetentionCategory, number>> = Object.freeze(
  Object.fromEntries(RETENTION_CATEGORIES.map((c) => [c.key, c.default])) as Record<RetentionCategory, number>);

/** What is wrong with proposed values: keys outside the catalogue, values that are not an integer of their range. */
export function retentionValueErrors(values: Readonly<Record<string, unknown>>): { unknown: string[]; outOfRange: RetentionCategory[] } {
  const unknown: string[] = [];
  const outOfRange: RetentionCategory[] = [];
  for (const [k, v] of Object.entries(values)) {
    if (!isRetentionCategory(k)) { unknown.push(k); continue; }
    const d = retentionCategoryDef(k);
    if (typeof v !== 'number' || !Number.isInteger(v) || v < d.min || v > d.max) outOfRange.push(k);
  }
  return { unknown, outOfRange };
}

/** What proposed values do against the values in force and the decreases waiting: `raised` keep data longer (in force
 *  once approved), `lowered` shorter (in force RETENTION_LOWERING_DELAY_DAYS days after the approval), `restored`
 *  equal the value in force but cancel a decrease waiting; the others change nothing. Display order. */
export function retentionChanges(inForce: Readonly<Record<RetentionCategory, number>>,
  pending: Readonly<Partial<Record<RetentionCategory, number>>> | null, proposed: Readonly<Partial<Record<RetentionCategory, number>>>):
  { raised: RetentionCategory[]; lowered: RetentionCategory[]; restored: RetentionCategory[] } {
  const raised: RetentionCategory[] = [];
  const lowered: RetentionCategory[] = [];
  const restored: RetentionCategory[] = [];
  for (const k of RETENTION_CATEGORY_KEYS) {
    const v = proposed[k];
    if (v === undefined) continue;
    if (v > inForce[k]) raised.push(k);
    else if (v < inForce[k]) { if (pending?.[k] !== v) lowered.push(k); }
    else if (pending?.[k] !== undefined) restored.push(k);
  }
  return { raised, lowered, restored };
}

/** Retentions of the platform, not set per tenant (shown read only; D16 for the notification log and the alerts). */
export type RetentionFixedKey = 'enrollment_sessions' | 'enrollment_tokens' | 'inventory_commands' | 'ade_removed_devices'
  | 'notification_log' | 'live_alerts' | 'app_icons_orphaned' | 'android_inbox' | 'backups';

export interface RetentionFixedDto {
  key: RetentionFixedKey;
  value: number;
  unit: RetentionUnit;
}

// ── API of the retention (P0-13 T4: GET /api/privacy/retention) ──────────────────────────────────────────────────

export interface RetentionCategoryDto extends RetentionCategoryDef {
  key: RetentionCategory;
  /** The value in force now (a decrease past its date included). */
  value: number;
  /** The value the tenant set (null: the default). */
  configured: number | null;
  /** A decrease waiting for its date (null: none). */
  pending: number | null;
}

/** A change of the retention waiting for its approval (one at most). */
export interface RetentionPendingRequestDto {
  approvalId: number;
  requestedBy: number;
  requestedAt: string;
  expiresAt: string;
  values: Partial<Record<RetentionCategory, number>>;
}

export interface RetentionPolicyDto {
  categories: RetentionCategoryDto[];
  /** When the decreases waiting take effect (null: none waits). */
  pendingEffectiveAt: string | null;
  /** Changes applied so far (0: never set). */
  version: number;
  justification: string | null;
  updatedBy: number | null;
  updatedAt: string | null;
  request: RetentionPendingRequestDto | null;
  fixed: RetentionFixedDto[];
  /** The retention of the audit log of the tenant (set apart, audit/admin.routes.ts). */
  auditLog: { months: number; pendingMonths: number | null; pendingEffectiveAt: string | null };
  canManage: boolean;
}

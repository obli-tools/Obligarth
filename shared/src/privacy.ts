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
import type { ObligarthStage } from './ops';

/** Rules that allow or refuse the collection of a datum. */
export const PRIVACY_BOOLEAN_RULES = [
  'serialNumber',       // serial number (Apple: SerialNumber; Android: hardwareInfo.serialNumber)
  'hardwareIds',        // IMEI, MEID, EID, MAC addresses (Android: IMEI of networkInfo; bridge agent: IMEI)
  'deviceName',         // name given to the device by its user
  'phoneNumber',        // phone number, ICCID, subscriptions
  'network',            // carrier, roaming, Wi-Fi and Bluetooth MAC (Android: networkInfo)
  'lostModeLocation',   // location of a lost device, in lost mode only (REQ-03)
  // P0-15 (remote assistance, §0.1 of the spec): may the support see the screen of a device, and control it, during
  // a session shown on the screen by notifications? True by default on a corporate device, never on a personal or
  // COPE device (IMPOSED_RULES, D3). A version published without the key reads it at the default of its ownership
  // (server/src/privacy/profiles.ts).
  'remoteAssistance',
] as const;
export type PrivacyBooleanRule = typeof PRIVACY_BOOLEAN_RULES[number];

/** Rules of an inventory that may be limited to what the organisation manages. */
export const PRIVACY_SCOPE_RULES = ['installedApps', 'certificates'] as const;
export type PrivacyScopeRule = typeof PRIVACY_SCOPE_RULES[number];

export const PRIVACY_COLLECTION_SCOPES = ['all', 'managed_only'] as const;
export type PrivacyCollectionScope = typeof PRIVACY_COLLECTION_SCOPES[number];

/** Every key of a profile, in display order (the CHECK of the table admits these keys and no other;
 *  remoteAssistance may be absent from a version, read at the default of its ownership). */
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
  /** P0-15: sessions of remote assistance (the screen seen, or controlled, during a session shown on the screen). */
  remoteAssistance: boolean;
}

/** The rules of a tenant without a profile (conception §10.3): exactly those applied to Apple before P0-13
 *  (apple/devices/privacy.ts defaultPrivacyRules). Android and the bridge agent keep their own minimal rules
 *  while the tenant has no version of the ownership (privacy/profiles.ts). The remote assistance (P0-15 §0.1 rule 5):
 *  allowed by default on a corporate device, as the support of an MSP works. */
export const DEFAULT_PRIVACY_PROFILE: Readonly<Record<Ownership, Readonly<PrivacyProfileRules>>> = {
  corporate: {
    serialNumber: true, hardwareIds: true, deviceName: true, phoneNumber: true, network: true, lostModeLocation: true,
    installedApps: 'all', certificates: 'all', remoteAssistance: true,
  },
  corporate_personal: {
    serialNumber: true, hardwareIds: true, deviceName: false, phoneNumber: false, network: true, lostModeLocation: true,
    installedApps: 'managed_only', certificates: 'managed_only', remoteAssistance: false,
  },
  personal: {
    serialNumber: false, hardwareIds: false, deviceName: false, phoneNumber: false, network: false, lostModeLocation: false,
    installedApps: 'managed_only', certificates: 'managed_only', remoteAssistance: false,
  },
};

/** The rules no profile may change, per ownership (conception §10.3; D2: applications managed only in COPE; P0-15 D3:
 *  no remote assistance on a personal or COPE device, the capture taking the whole screen, personal apps included). */
export const IMPOSED_RULES: Readonly<Record<Ownership, Readonly<Partial<PrivacyProfileRules>>>> = {
  corporate: {},
  corporate_personal: { installedApps: 'managed_only', remoteAssistance: false },
  personal: { serialNumber: false, lostModeLocation: false, installedApps: 'managed_only', remoteAssistance: false },
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
// The catalogue is copied into the migration retention_policies (obligarth_private.retention_catalog, the CHECKs), and
// widened by p015_remote_retention (remote_sessions_months): both change together (testbeds 172 and 340 compare them).

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
  { key: 'remote_sessions_months', default: 12, min: 6, max: 36, unit: 'months' },               // journal of the remote assistance sessions (P0-15 D7)
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
  | 'notification_log' | 'live_alerts' | 'app_icons_orphaned' | 'android_inbox' | 'backups'
  // P0-5 T4 (D7): the journal of the memberships of the dynamic groups
  | 'smart_group_memberships';

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

// ── Notice of the employees (P0-13 T5, USR-01; conception §10.3) ─────────────────────────────────────────────────
// The notice an employee reads before an enrollment is generated (server: privacy/notice/generate.ts) from the
// privacy profile of the ownership, the retention of the tenant and the settings below, per platform, ownership and
// language (D15: fr and en), and kept as immutable versions (obligarth.notice_versions); each acknowledgement is a row
// of obligarth.notice_acknowledgements, kept notice_ack_months (D5). The settings are plain text: no markup, the pages
// escape every value. Copied into the CHECKs of the migration notices: both change together.

export const NOTICE_PLATFORMS = ['apple', 'android'] as const;
export type NoticePlatform = typeof NOTICE_PLATFORMS[number];

export const NOTICE_LOCALES = ['fr', 'en'] as const;
export type NoticeLocale = typeof NOTICE_LOCALES[number];

/** Where an acknowledgement was given: an Apple enrollment session (OTA, ADE web view, account-driven), a BYOD
 *  invitation of Android, a sign-in session of Android. */
export const NOTICE_ACK_CHANNELS = ['apple_session', 'android_byod_invitation', 'android_signin'] as const;
export type NoticeAckChannel = typeof NOTICE_ACK_CHANNELS[number];

/** The settings of the notice of a tenant (null: not set). */
export interface NoticeSettings {
  /** The data controller (the employer, legal name). */
  controllerName: string | null;
  controllerAddress: string | null;
  /** The data protection officer (name, e-mail or address). */
  dpoContact: string | null;
  /** Another contact for the employees' questions. */
  contact: string | null;
  /** Recipients beyond the operator of the platform and Apple or Google. */
  recipientsExtra: string | null;
  /** A paragraph of the organisation, shown after who manages the device. */
  introFr: string | null;
  introEn: string | null;
}

export type NoticeSettingsKey = keyof NoticeSettings;

/** Maximum length of each setting (characters), and whether it may hold several lines. */
export const NOTICE_SETTINGS_FIELDS: Readonly<Record<NoticeSettingsKey, { max: number; multiline: boolean }>> = {
  controllerName: { max: 200, multiline: false },
  controllerAddress: { max: 500, multiline: true },
  dpoContact: { max: 300, multiline: false },
  contact: { max: 300, multiline: false },
  recipientsExtra: { max: 1000, multiline: true },
  introFr: { max: 2000, multiline: true },
  introEn: { max: 2000, multiline: true },
};
export const NOTICE_SETTINGS_KEYS = Object.keys(NOTICE_SETTINGS_FIELDS) as NoticeSettingsKey[];

export const EMPTY_NOTICE_SETTINGS: Readonly<NoticeSettings> = Object.freeze({
  controllerName: null, controllerAddress: null, dpoContact: null, contact: null, recipientsExtra: null, introFr: null, introEn: null,
});

/** What a notice needs before a pilot (D7): the data controller and a contact (the DPO or another). */
export type NoticeMissing = 'controllerName' | 'contact';

/** The settings a complete notice still lacks (empty: complete). Outside the stage lab, an enrollment is refused while
 *  the notice is not complete (D7). */
export function noticeCompleteness(s: Readonly<NoticeSettings>): NoticeMissing[] {
  const set = (v: string | null): boolean => typeof v === 'string' && v.trim() !== '';
  const missing: NoticeMissing[] = [];
  if (!set(s.controllerName)) missing.push('controllerName');
  if (!set(s.dpoContact) && !set(s.contact)) missing.push('contact');
  return missing;
}

/** Markup and control characters a setting may not hold (the notice is plain text): angle brackets, and every control
 *  character but the line feed and the tab of a multi-line field. */
const MARKUP = /[<>]/;
const CONTROL_SINGLE = /[\u0000-\u001f\u007f]/;
const CONTROL_MULTI = /[\u0000-\u0008\u000b-\u001f\u007f]/;

/** What is wrong with proposed settings: keys outside the list, values that are not a string or null, too long, or
 *  holding markup or control characters. */
export function noticeSettingsErrors(values: Readonly<Record<string, unknown>>): { unknown: string[]; invalid: NoticeSettingsKey[]; tooLong: NoticeSettingsKey[]; markup: NoticeSettingsKey[] } {
  const unknown: string[] = [];
  const invalid: NoticeSettingsKey[] = [];
  const tooLong: NoticeSettingsKey[] = [];
  const markup: NoticeSettingsKey[] = [];
  for (const [k, v] of Object.entries(values)) {
    if (!(NOTICE_SETTINGS_KEYS as string[]).includes(k)) { unknown.push(k); continue; }
    const key = k as NoticeSettingsKey;
    if (v === null) continue;
    if (typeof v !== 'string') { invalid.push(key); continue; }
    const f = NOTICE_SETTINGS_FIELDS[key];
    if ([...v].length > f.max) tooLong.push(key);
    if (MARKUP.test(v) || (f.multiline ? CONTROL_MULTI : CONTROL_SINGLE).test(v)) markup.push(key);
  }
  return { unknown, invalid, tooLong, markup };
}

/** A setting as it is checked and stored: trimmed (each line of a multi-line one at its end), line ends as LF, empty
 *  as null. */
export function normalizeNoticeSetting(key: NoticeSettingsKey, v: string | null): string | null {
  if (v === null) return null;
  const s = NOTICE_SETTINGS_FIELDS[key].multiline ? v.replace(/\r\n?/g, '\n').split('\n').map((l) => l.replace(/\s+$/, '')).join('\n').trim() : v.trim();
  return s === '' ? null : s;
}

/** Is the notice of this platform and ownership shown at an enrollment? Every Apple ownership; on Android the personal
 *  devices only (BYOD link, sign-in): the texts of the company devices are generated, their display waits for the v1
 *  (D13). The console and the public page offer these combinations. */
export function noticeDisplayed(platform: NoticePlatform, ownership: Ownership): boolean {
  return platform === 'apple' || ownership === 'personal';
}

// ── Console API of the notice (P0-13 T6, USR-01): GET/PUT /api/privacy/notice-settings, GET /api/privacy/notices… ──

/** The text of a notice version: plain text only (the console renders it escaped). */
export interface NoticeContentDto {
  title: string;
  sections: Array<{ heading: string; paragraphs: string[] }>;
  /** The summary written into the enrollment profile (ConsentText), 500 characters at most. */
  consentSummary: string;
  contact: string | null;
}

/** GET /api/privacy/notice-settings (and the answer of PUT). */
export interface NoticeSettingsDto {
  settings: NoticeSettings;
  /** Changes of the settings (0: never set). */
  version: number;
  updatedAt: string | null;
  updatedBy: number | null;
  /** What a complete notice still lacks (D7). */
  missing: NoticeMissing[];
  /** The stage of the instance (D8). */
  stage: ObligarthStage;
  /** An enrollment is refused while the notice is not complete (stage pilot or production, D7). */
  enrollmentRefused: boolean;
  /** The public page of the notice in force (https://mdm.<domain>/t/<key>/notice), null without a device surface. */
  publicUrl: string | null;
  canManage: boolean;
  /** The answer of PUT only: whether the settings changed (false: the values given were those in force). */
  changed?: boolean;
}

/** PUT /api/privacy/notice-settings: the settings given replace theirs (null clears one), the others stay;
 *  baseVersion (the version read) refuses a change made meanwhile (409 noticeSettingsChanged). */
export interface NoticeSettingsUpdate {
  settings: Partial<Record<NoticeSettingsKey, string | null>>;
  baseVersion?: number;
}

/** A version of the notice (immutable). */
export interface NoticeVersionDto {
  id: string;
  platform: NoticePlatform;
  ownership: Ownership;
  locale: NoticeLocale;
  sha256: string;
  generatedAt: string;
  /** null: the current version of its platform, ownership and language. */
  supersededAt: string | null;
  /** The privacy profile it was generated from (null: the default profile). */
  profileVersion: number | null;
  settingsVersion: number;
  retentionVersion: number;
  generatorVersion: number;
  acknowledgements: number;
  /** Shown at an enrollment (noticeDisplayed, D13). */
  displayed: boolean;
}

/** GET /api/privacy/notices: the current versions with their text, and the versions of the tenant, the latest first. */
export interface NoticesDto {
  current: Array<NoticeVersionDto & { content: NoticeContentDto }>;
  history: NoticeVersionDto[];
  /** The public page of the notice (as NoticeSettingsDto). */
  publicUrl: string | null;
}

/** GET /api/privacy/notices/preview: the notice the inputs in force give now (nothing is published). */
export interface NoticePreviewDto {
  platform: NoticePlatform;
  ownership: Ownership;
  locale: NoticeLocale;
  content: NoticeContentDto;
  missing: NoticeMissing[];
  displayed: boolean;
}

/** GET /api/privacy/notices/:id/acknowledgements/count. */
export interface NoticeAcknowledgementCountDto {
  versionId: string;
  total: number;
  byChannel: Record<NoticeAckChannel, number>;
}

// =============================================================================
// Bench station (lot BANC, spec banc-spec §2): the Windows station of a technician that enrolls new Android devices by
// ADB, and the bridge agent as the owner of the device (device owner, "DO") when possible. The vocabulary of the
// contract between the station and the server, the pure rules both sides apply (role plan, verification code) and the
// views of the console. No import but types: the client, the station and the unit tests load it as is.
// =============================================================================

export const BENCH_STATION_STATUSES = ['pending', 'approved', 'suspended', 'revoked'] as const;
export type BenchStationStatus = typeof BENCH_STATION_STATUSES[number];

export const BENCH_IDENTITY_STATES = ['confirmed', 'unconfirmed', 'mismatch'] as const;
export type BenchIdentityState = typeof BENCH_IDENTITY_STATES[number];

export const BENCH_ROLE_POLICIES = ['owner_required', 'owner_preferred', 'admin_only'] as const;
export type BenchRolePolicy = typeof BENCH_ROLE_POLICIES[number];

export const BENCH_ROLES = ['device_owner', 'device_admin'] as const;
export type BenchRole = typeof BENCH_ROLES[number];

export const BENCH_PROVISIONING_STATES = ['planned', 'token_issued', 'enrolled', 'completed', 'failed', 'abandoned', 'expired'] as const;
export type BenchProvisioningState = typeof BENCH_PROVISIONING_STATES[number];
/** The states of a provisioning still open (one per station and ADB serial). */
export const BENCH_OPEN_PROVISIONING_STATES = ['planned', 'token_issued', 'enrolled'] as const;
/** The terminal states (outcome_at set). */
export const BENCH_TERMINAL_PROVISIONING_STATES = ['completed', 'failed', 'abandoned', 'expired'] as const;

/** convert: an agent already enrolled (device administrator) turned into the owner of the device. apps (lot BANC-A): a
 *  device already enrolled brought back to the bench to complete its required apps by ADB, nothing else. */
export const BENCH_PROVISIONING_KINDS = ['new', 'convert', 'apps'] as const;
export type BenchProvisioningKind = typeof BENCH_PROVISIONING_KINDS[number];

/** apps (lot BANC-A): the required apps installed by ADB, between the verification and the finalization. */
export const BENCH_STEP_IDS = ['detect', 'identify', 'agent_check', 'preflight', 'install', 'role', 'prepare',
  'configure', 'wait_enroll', 'verify', 'apps', 'finalize'] as const;
export type BenchStepId = typeof BENCH_STEP_IDS[number];

export const BENCH_STEP_STATUSES = ['running', 'ok', 'warn', 'failed', 'skipped'] as const;
export type BenchStepStatus = typeof BENCH_STEP_STATUSES[number];

/** What keeps a device from taking the agent as its owner (AOSP preconditions, §6.3); setup_incomplete is only a
 *  warning (§6.2). Owner decision of 28/11/2026: accounts are a blocker only when the station cannot hide them for the
 *  time of `dpm set-device-owner` (their app disabled, then enabled again: BENCH_ACCOUNT_APP_CODES): an account whose
 *  type or app it cannot read, an app it never disables (Settings, launcher…), or Android refusing (accounts_hide_refused)
 *  or still seeing them (accounts_still_seen). */
export const BENCH_OWNER_BLOCKERS = ['accounts', 'accounts_hide_refused', 'accounts_still_seen', 'accounts_marker_failed',
  'extra_users', 'foreign_owner', 'profile_owner', 'agent_too_old', 'policy_admin_only', 'unknown'] as const;
export type BenchOwnerBlocker = typeof BENCH_OWNER_BLOCKERS[number];

/** Named error codes of the station and of the server (one code = one text bench.error.<code>). */
export const BENCH_ERROR_CODES = [
  'adb_missing', 'adb_server', 'adb_conflict', 'device_unauthorized', 'device_offline', 'device_gone',
  'auto_blocker_suspected', 'adb_blocked_by_policy', 'unsupported_sdk', 'agent_foreign_signer', 'agent_downgrade',
  'agent_already_enrolled', 'install_failed', 'install_restricted', 'apk_mismatch', 'owner_blocked', 'owner_failed',
  'admin_failed', 'admin_lost', 'knox_reactivation', 'configure_failed', 'enroll_timeout', 'token_rejected',
  'identity_mismatch', 'device_outside_target', 'station_refused', 'no_session', 'server_unreachable', 'redirected',
  'target_refused', 'slot_held', 'too_many_cards', 'internal',
] as const;
// no_session: no bench session since 28/11/2026, never raised any more; kept in the vocabulary (the CHECK of the base,
// the history, a station 1.0.3 that may still send it as the code of a result).
export type BenchErrorCode = typeof BENCH_ERROR_CODES[number];

/** The codes the server answers the station with (HTTP refusals, §3.11). */
export const BENCH_API_CODES = [
  'station_pending', 'station_suspended', 'station_revoked', 'station_ip_refused', 'target_refused', 'device_outside_target',
  // no_session: never answered since 28/11/2026 (no bench session any more), kept for the stations 1.0.3.
  'agent_already_enrolled', 'open_provisioning', 'bad_state', 'no_session', 'not_enrolled', 'not_verified', 'too_many_pending',
  'apk_unavailable', 'apk_mismatch', 'verification_mismatch', 'agent_too_old',
  // Lot BANC-T §9: the site chosen on the card is not one of the target's (unknown, archived, of another tenant or
  // outside the target's group); the name of the device is already used in the site (case ignored).
  'site_refused', 'name_taken',
  // Lot BANC-A: « compléter les apps » found no device of the station's targets for the identity proven (one answer for
  // unknown, outside the targets, of another tenant); the proof contradicts the device found (Android ID, API level);
  // two devices of the targets answer the same proof.
  'device_not_found', 'identity_mismatch', 'identity_ambiguous',
] as const;
export type BenchApiCode = typeof BENCH_API_CODES[number];

export const BENCH_LIMITS = {
  maxCards: 16, maxPendingStations: 50, maxPendingPerIp: 3, pendingStationTtlHours: 24, tokenTtlMinutes: 30,
  provisioningTtlMinutes: 120, sessionMaxHours: 8, tokensPerStationPerHour: 120, tokensPerStationPerDay: 300,
  registerPerIpPerHour: 20, maxStepsPerProvisioning: 64, nameMax: 100, maxTargetsPerStation: 200,
  stationIdleSuspendDays: 90,
} as const;

/** The agent version (versionCode) from which the agent knows the device owner role (agent 1.4.0). */
export const BENCH_OWNER_MIN_VERSION_CODE = 10400;

/** The features the server announces to the agent (config.features, closed list): the agent 1.4.0 sends
 *  status.deviceOwner, status.adbEnabled and the device_owner_* events only when it reads device_owner_v1. */
export const LEGACY_AGENT_FEATURES = ['device_owner_v1'] as const;
export type LegacyAgentFeature = typeof LEGACY_AGENT_FEATURES[number];

/** The station's token: 64 to 256 hexadecimal characters, an even count (randomBytes(32) hex is 64). */
export const BENCH_STATION_TOKEN_RE = /^[0-9a-f]{64,256}$/;

/** The detail of a step: a white list, never free text read from the device (§3.5). */
export type BenchStepDetail = {
  code?: string;
  counts?: Record<string, number>;
  accountTypes?: string[];
  sdk?: number;
  versionCode?: number;
  attempt?: number;
  /** Lot BANC-A, step apps: the package of the tenant's store (BenchRequiredAppView.packageId), never a name read on
   *  the device. */
  packageId?: string;
  /** Step role (owner decision of 28/11/2026): the Android package an entry account_app_* is about (the app that
   *  carries accounts, disabled for the time of `dpm set-device-owner`), never an account name. */
  packages?: string[];
};

/** The journal of the accounts hidden at the step role: one entry per package and per action. */
export const BENCH_ACCOUNT_APP_CODES = ['account_app_disabled', 'account_app_disable_refused', 'account_app_enabled',
  'account_app_enable_failed'] as const;
export type BenchAccountAppCode = typeof BENCH_ACCOUNT_APP_CODES[number];

/** What a journal says of the apps disabled to hide accounts: disabled, enabled again, refused, and those still
 *  disabled at its end (never expected: the station re-enables them, at the latest at its next run on the device).
 *  null when the journal has none. The oldest entries may have left a long journal (64 entries at most). */
export interface BenchAccountAppsSummary { disabled: string[]; enabled: string[]; refused: string[]; notEnabled: string[] }

export function benchAccountAppsSummary(steps: readonly BenchStepEntry[] | null | undefined): BenchAccountAppsSummary | null {
  if (!Array.isArray(steps)) return null;
  const disabled = new Set<string>();
  const enabled = new Set<string>();
  const refused = new Set<string>();
  const open = new Set<string>();
  let any = false;
  for (const s of steps) {
    if (s?.step !== 'role' || !(BENCH_ACCOUNT_APP_CODES as readonly string[]).includes(s.code ?? '')) continue;
    any = true;
    for (const p of Array.isArray(s.detail?.packages) ? s.detail!.packages! : []) {
      if (typeof p !== 'string') continue;
      if (s.code === 'account_app_disabled') { disabled.add(p); open.add(p); }
      else if (s.code === 'account_app_enabled') { enabled.add(p); open.delete(p); }
      else if (s.code === 'account_app_disable_refused') refused.add(p);
    }
  }
  if (!any) return null;
  const sorted = (x: Set<string>): string[] => [...x].sort().slice(0, 16);
  return { disabled: sorted(disabled), enabled: sorted(enabled), refused: sorted(refused), notEnabled: sorted(open) };
}

/** One entry of the journal of a provisioning. */
export interface BenchStepEntry {
  step: BenchStepId;
  status: BenchStepStatus;
  /** ISO time given by the station (its clock corrected by the server's Date header). */
  at: string;
  code?: string;
  detail?: BenchStepDetail;
}

/** The verification code a station shows and the administrator types again, `XXXX-XXXX`: 8 hexadecimal characters of a
 *  digest, upper case. The server derives that digest from the sha256 of the station's token (stations.service.ts),
 *  never from its id, which the console shows in its URLs: the code is read on the station's screen only (§3.3). */
export function benchVerificationCode(digestHex: string): string {
  const hex = String(digestHex ?? '').replace(/[^0-9a-fA-F]/g, '').toUpperCase().slice(0, 8).padEnd(8, '0');
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
}

/** The same code, normalised for a comparison (dashes, spaces and case ignored). */
export function normaliseBenchVerificationCode(input: string): string {
  return String(input ?? '').replace(/[\s-]/g, '').toUpperCase();
}

export interface BenchRolePlan {
  target: BenchRole;
  /** The station may fall back to the device administrator when the owner is blocked. */
  fallbackAllowed: boolean;
  /** The fallback needs a second confirmation of the technician (Knox is restricted to an administrator on Android 15). */
  fallbackConfirm: boolean;
}

/**
 * The role a provisioning aims at (§2): admin_only → administrator; an agent older than 1.4.0 → administrator, unless the
 * target carries the exception allow_legacy_owner (D3); owner_required → owner without fallback; owner_preferred →
 * owner with a fallback to the administrator, confirmed twice from Android 15 (sdk 35).
 */
export function benchRolePlan(policy: BenchRolePolicy, sdk: number, agentVersionCode: number, allowLegacyOwner = false): BenchRolePlan {
  if (policy === 'admin_only') return { target: 'device_admin', fallbackAllowed: false, fallbackConfirm: false };
  if (agentVersionCode < BENCH_OWNER_MIN_VERSION_CODE && !allowLegacyOwner) {
    return { target: 'device_admin', fallbackAllowed: false, fallbackConfirm: false };
  }
  if (policy === 'owner_required') return { target: 'device_owner', fallbackAllowed: false, fallbackConfirm: false };
  return { target: 'device_owner', fallbackAllowed: true, fallbackConfirm: sdk >= 35 };
}

// ── Name of a device suggested on the bench (lot BANC-T §9, §10) ─────────────────
//
// A template per target (bench_station_targets.name_template), generic: literal text and the tokens
//   {site.code}      the code of the site chosen on the card
//   {site.code:N}    the same, left-padded with zeros to N characters (never cut: a longer code stays whole)
//   {n} / {n:N}      the number of the device in the site: the highest number already used by THIS template in the
//                    site (the names of its devices and of its open provisionings) + 1, from 1; {n:N} left-pads it
// Example (fictitious): « AB{site.code:5}-{n} » gives AB00042-1, AB00042-2… in the site 42. {n} appears exactly once;
// the literal text is printable, without braces. The name is compared case-insensitively.

export const BENCH_NAME_TEMPLATE_MAX = 64;
const NAME_TOKEN_RE = /\{(site\.code|n)(?::([1-9]|1[0-6]))?\}/g;

export type BenchNameTemplateCheck = { ok: true } | { ok: false; reason: 'empty' | 'too_long' | 'bad_char' | 'bad_token' | 'no_number' | 'two_numbers' };

/** Validates a name template (the console, the server and the station apply the same rule). */
export function checkBenchNameTemplate(template: unknown): BenchNameTemplateCheck {
  if (typeof template !== 'string' || template.trim() === '') return { ok: false, reason: 'empty' };
  if (template.length > BENCH_NAME_TEMPLATE_MAX || template !== template.trim()) return { ok: false, reason: 'too_long' };
  if (/[\u0000-\u001f\u007f]/.test(template)) return { ok: false, reason: 'bad_char' };
  const literal = template.replace(NAME_TOKEN_RE, '');
  if (/[{}]/.test(literal)) return { ok: false, reason: 'bad_token' };
  const numbers = [...template.matchAll(NAME_TOKEN_RE)].filter((m) => m[1] === 'n').length;
  if (numbers === 0) return { ok: false, reason: 'no_number' };
  if (numbers > 1) return { ok: false, reason: 'two_numbers' };
  return { ok: true };
}

const pad = (s: string, width: string | undefined): string => (width ? s.padStart(Number(width), '0') : s);
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** The name of number `n` in the site of code `siteCode` (null: an invalid template). */
export function renderBenchName(template: string, siteCode: string, n: number): string | null {
  if (!checkBenchNameTemplate(template).ok || !Number.isSafeInteger(n) || n < 1) return null;
  return template.replace(NAME_TOKEN_RE, (_m, token: string, width: string | undefined) => pad(token === 'n' ? String(n) : siteCode, width));
}

/** The numbers this template already used in the site, read from names (case ignored; a name of another form is
 *  not counted). */
export function benchNameNumbers(template: string, siteCode: string, names: readonly (string | null | undefined)[]): number[] {
  if (!checkBenchNameTemplate(template).ok) return [];
  let source = '';
  let last = 0;
  for (const m of template.matchAll(NAME_TOKEN_RE)) {
    source += escapeRe(template.slice(last, m.index));
    source += m[1] === 'n' ? '(\\d{1,9})' : escapeRe(pad(siteCode, m[2]));
    last = (m.index ?? 0) + m[0].length;
  }
  source += escapeRe(template.slice(last));
  const re = new RegExp(`^${source}$`, 'i');
  const out: number[] = [];
  for (const name of names) {
    const hit = typeof name === 'string' ? re.exec(name.trim()) : null;
    if (hit) out.push(Number(hit[1]));
  }
  return out;
}

/** The suggested name: the highest number used + 1 (1 in an empty site); null when the template is invalid or the
 *  name would pass the bound of a device name. */
export function suggestBenchName(template: string, siteCode: string, names: readonly (string | null | undefined)[]): string | null {
  const used = benchNameNumbers(template, siteCode, names);
  const next = (used.length ? Math.max(...used) : 0) + 1;
  const name = renderBenchName(template, siteCode, next);
  return name && name.length <= BENCH_LIMITS.nameMax ? name : null;
}

/** Two device names are the same name (the uniqueness in a site ignores the case and the outer spaces). */
export const sameBenchName = (a: string | null | undefined, b: string | null | undefined): boolean =>
  typeof a === 'string' && typeof b === 'string' && a.trim().toLowerCase() === b.trim().toLowerCase();

/** A serial number cut to its last four characters (the audit, and a reader without devices.manage). */
export function truncateSerial(serial: string | null | undefined): string | null {
  if (typeof serial !== 'string' || !serial) return null;
  return serial.length <= 4 ? `…${serial}` : `…${serial.slice(-4)}`;
}

// ── Required apps installed on the bench (lot BANC-A) ─────────────────────────
//
// After the verification, the station installs by ADB (adb install -r, never -t nor -d) the apps the POLICY of the
// device requires (the required apps of the bridge agent policies, decided by the server), each one downloaded from the
// server (GET /api/bench/v1/packages/:sha256?provisioning=<id>) and checked against its SHA-256 before the install. The
// journal (POST /v1/provisionings/:id/steps) carries one entry per app, then one summary:
//   per app   { step: 'apps', status: 'ok' | 'failed' | 'skipped', code: <BenchAppResultCode>,
//               detail: { packageId, versionCode } }
//   summary   { step: 'apps', status: 'ok' (all installed) | 'warn' (some failed) | 'skipped' (none to install, or a
//               server without these routes), detail: { counts: { installed, total, failed } } }
// The history shows the counter of the last summary (benchAppsCounter). A failed app stops neither the others nor the
// finalization (the outcome stays completed: « terminé avec réserves »).

/** The code of the result of one app (code of its entry of the step apps; one text bench.error.<code>). */
export const BENCH_APP_RESULT_CODES = [
  'app_installed', 'app_older_sdk', 'app_version_downgrade', 'app_update_incompatible', 'app_insufficient_storage',
  'app_invalid_apk', 'app_download_failed', 'app_sha_mismatch', 'app_signer_mismatch', 'app_install_failed', 'app_unavailable',
] as const;
export type BenchAppResultCode = typeof BENCH_APP_RESULT_CODES[number];

/** The code of the answer of `adb install -r` (Success, or the INSTALL_FAILED_* / INSTALL_PARSE_FAILED_* token of
 *  PackageManager); any other failure is app_install_failed. */
export function benchAppInstallCode(output: string | null | undefined): BenchAppResultCode {
  const text = String(output ?? '');
  const token = /\[?(INSTALL_(?:FAILED|PARSE_FAILED)_[A-Z_]+)/.exec(text)?.[1] ?? null;
  if (!token) return /^\s*Success\s*$/m.test(text) ? 'app_installed' : 'app_install_failed';
  switch (token) {
    case 'INSTALL_FAILED_OLDER_SDK': return 'app_older_sdk';
    case 'INSTALL_FAILED_VERSION_DOWNGRADE': return 'app_version_downgrade';
    case 'INSTALL_FAILED_UPDATE_INCOMPATIBLE':
    case 'INSTALL_FAILED_SHARED_USER_INCOMPATIBLE':
      return 'app_update_incompatible';
    case 'INSTALL_FAILED_INSUFFICIENT_STORAGE':
    case 'INSTALL_FAILED_MEDIA_UNAVAILABLE':
      return 'app_insufficient_storage';
    case 'INSTALL_FAILED_INVALID_APK':
    case 'INSTALL_FAILED_NO_CERTIFICATES':
      return 'app_invalid_apk';
    default:
      return token.startsWith('INSTALL_PARSE_FAILED_') ? 'app_invalid_apk' : 'app_install_failed';
  }
}

/** A required app the bench installs (GET /api/bench/v1/provisionings/:id/apps): missing on the device or older than the
 *  package (mode minVersion), confirmed in the tenant's store. */
export interface BenchRequiredAppView {
  packageId: string;
  packageName: string;
  versionCode: number;
  versionName: string | null;
  sha256: string;
  size: number;
  /** The signer declared at the upload (null: unknown; the station relies on the SHA-256 of the file then). */
  signerSha256: string | null;
  label: string | null;
  mode: 'install' | 'minVersion';
}

/** POST /api/bench/v1/provisionings/apps: the provisioning « compléter les apps » of a device already enrolled. */
export interface BenchAppsPlanAnswer {
  provisioningId: string;
  kind: 'apps';
  tenantId: number;
  tenantName: string;
  groupId: number;
  deviceUuid: string;
  deviceName: string | null;
  site: { id: string; code: string; name: string } | null;
  roleTarget: BenchRole;
  /** How the identity was proven: the serial pairs that matched, and the Android ID (matched; or not comparable from
   *  Android 8, where the shell reads another value than the agent). */
  proof: { serialPairs: number; androidId: 'matched' | 'not_comparable' };
}

/** The counter of the step apps (its last summary), or null when the step never ran. */
export interface BenchAppsCounter { installed: number; total: number; failed: number }

export function benchAppsCounter(steps: readonly BenchStepEntry[] | null | undefined): BenchAppsCounter | null {
  if (!Array.isArray(steps)) return null;
  for (let i = steps.length - 1; i >= 0; i--) {
    const s = steps[i];
    const c = s?.step === 'apps' ? s.detail?.counts : undefined;
    if (c && Number.isSafeInteger(c.total)) {
      const n = (v: unknown): number => (Number.isSafeInteger(v) && (v as number) >= 0 ? (v as number) : 0);
      return { installed: n(c.installed), total: n(c.total), failed: n(c.failed) };
    }
  }
  return null;
}

// ── Views of the console ─────────────────────────────────────────────────────

/** A target of a station: a group of a tenant. */
export interface BenchTargetView {
  tenantId: number;
  tenantName: string;
  groupId: number;
  groupPath: string;
  rolePolicy: BenchRolePolicy;
  allowLegacyOwner: boolean;
  namePrefix: string | null;
  /** The template of the suggested name (lot BANC-T §10), null: the prefix and the ADB serial as before. */
  nameTemplate: string | null;
  disableDevOptions: boolean;
  suspendedAt: string | null;
  /** Lot BANC-T, Q1: a target of a client's station suspended by the platform (the client does not lift it). */
  suspendedByPlatform: boolean;
  createdAt: string;
}

/** A station seen by a platform administrator (GET /api/admin/bench-stations). */
export interface BenchStationView {
  id: string;
  name: string;
  hostname: string;
  status: BenchStationStatus;
  stationVersion: string | null;
  /** No verification code here: the administrator reads it on the station's screen (§3.3). */
  createdAt: string;
  approvedAt: string | null;
  suspendedAt: string | null;
  revokedAt: string | null;
  revokedReason: string | null;
  lastSeenAt: string | null;
  lastIp: string | null;
  registerIp: string | null;
  targetCount: number;
  enrolledCount: number;
  /** Lot BANC-T: the owner of the station. The stations of the platform belong to the master tenant (Default):
   *  ownerTenantId = MASTER_TENANT_ID, ownerSince null. A station of a client: its tenant, since its claim or its
   *  assignment. null: a revoked station whose tenant was deleted. */
  ownerTenantId: number | null;
  ownerTenantName: string | null;
  ownerSince: string | null;
  /** A station of a client suspended by the platform: the client does not lift this suspension. */
  suspendedByPlatform: boolean;
}

export interface BenchStationDetail extends BenchStationView {
  targets: BenchTargetView[];
}

/** A station that targets the tenant (GET /api/bench-provisionings/stations): no token, no address, no host. */
export interface BenchTenantStationView {
  id: string;
  name: string;
  status: BenchStationStatus;
  lastSeenAt: string | null;
  targets: Array<{ groupId: number; groupPath: string; rolePolicy: BenchRolePolicy; suspendedAt: string | null }>;
  /** Lot BANC-T: the station belongs to this tenant (GET /api/bench-stations manages it). */
  owned: boolean;
}

/** A target of a station of the tenant (GET /api/bench-stations): a group of this tenant. */
export interface BenchOwnedTargetView {
  groupId: number;
  groupPath: string;
  rolePolicy: BenchRolePolicy;
  allowLegacyOwner: boolean;
  namePrefix: string | null;
  nameTemplate: string | null;
  disableDevOptions: boolean;
  suspendedAt: string | null;
  /** Suspended by the platform (Q1): only the platform resumes it, the tenant neither resumes nor removes it. */
  suspendedByPlatform: boolean;
  createdAt: string;
}

/** A station that belongs to the tenant (lot BANC-T, GET /api/bench-stations): host and version, never an address
 *  (Q4). No bench session since 28/11/2026: an approved station acts within its targets by itself. */
export interface BenchOwnedStationView {
  id: string;
  name: string;
  hostname: string;
  status: BenchStationStatus;
  stationVersion: string | null;
  createdAt: string;
  approvedAt: string | null;
  suspendedAt: string | null;
  /** Suspended by the platform: only the platform lifts it (resume answers 409 suspendedByPlatform). */
  suspendedByPlatform: boolean;
  revokedAt: string | null;
  revokedReason: string | null;
  lastSeenAt: string | null;
  ownerSince: string | null;
  targets: BenchOwnedTargetView[];
}

// ── The choice of the station: tenant, site, name (lot BANC-T §9) ─────────────────────

/** GET /api/bench/v1/tenants: the tenants of the station's targets (not suspended). */
export interface BenchStationTenantView { id: number; name: string }

/** GET /api/bench/v1/tenants/:id/sites?search=: a site of the tenant inside one of the station's targets (its group is
 *  a target group or below one; a site without a group belongs to every target of its tenant). 200 at most, by code. */
export interface BenchStationSiteView {
  id: string;
  code: string;
  name: string;
  city: string | null;
  groupId: number | null;
  groupPath: string | null;
  /** The devices of the site under management (0: « new »). */
  deviceCount: number;
  /** The groups of the station's targets this site may be planned into (PlanBody.groupId among them). */
  targetGroupIds: number[];
}

/** A device name already used in the site: a device under management, or an open provisioning of a bench. */
export interface BenchSiteDeviceView {
  kind: 'device' | 'provisioning';
  label: string;
  model: string | null;
  /** The serial number cut to its last four characters. */
  serialTail: string | null;
  lastSeenAt: string | null;
  /** 28/11/2026: the device plugged in on the card asking (its serials given as adbSerial / hwSerial, matched as the
   *  plan does): its own name, which a conversion keeps, is not a name of another device. Absent otherwise. */
  self?: true;
}

/** GET /api/bench/v1/sites/:id/devices[?groupId=]: the names used in the site and, for a target (groupId), the name
 *  its template suggests (null: no template, or no target given). */
export interface BenchSiteDevicesView {
  site: BenchStationSiteView & { tenantId: number };
  devices: BenchSiteDeviceView[];
  nameTemplate: string | null;
  suggestedName: string | null;
}

/** A provisioning in the tenant's history (GET /api/bench-provisionings). */
export interface BenchProvisioningView {
  id: string;
  stationId: string;
  stationName: string | null;
  groupId: number;
  kind: BenchProvisioningKind;
  state: BenchProvisioningState;
  /** In clear with devices.manage, else cut to the last four characters. */
  adbSerial: string;
  hwSerial: string | null;
  model: string;
  manufacturer: string;
  sdkInt: number;
  osRelease: string | null;
  oneUi: string | null;
  deviceName: string | null;
  roleTarget: BenchRole;
  roleDeclared: BenchRole | null;
  managementMode: string | null;
  identityState: BenchIdentityState | null;
  deviceId: number | null;
  deviceUuid: string | null;
  errorCode: string | null;
  steps: BenchStepEntry[];
  stepsDropped: number;
  technician: string | null;
  /** Lot BANC-T §9: the site chosen on the bench (null: none, or deleted since). */
  siteId: string | null;
  siteCode: string | null;
  siteName: string | null;
  /** Lot BANC-A: the required apps installed on the bench (the last summary of the step apps), null: never ran. */
  apps: BenchAppsCounter | null;
  createdAt: string;
  updatedAt: string;
  outcomeAt: string | null;
}

/** The version of the agent served to the stations (bench_served), or null. */
export interface BenchServedRelease {
  releaseId: string;
  versionCode: number;
  versionName: string;
  sha256: string;
  deviceOwnerCapable: boolean;
}

/** The installer of the station next to the server image (GET /api/bench/version). */
export interface BenchStationInstallerInfo {
  version: string | null;
  available: boolean;
  sha256: string | null;
  size: number | null;
  file: 'obligarth-bench.msi';
}

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

/** convert: an agent already enrolled (device administrator) turned into the owner of the device. */
export const BENCH_PROVISIONING_KINDS = ['new', 'convert'] as const;
export type BenchProvisioningKind = typeof BENCH_PROVISIONING_KINDS[number];

export const BENCH_STEP_IDS = ['detect', 'identify', 'agent_check', 'preflight', 'install', 'role', 'prepare',
  'configure', 'wait_enroll', 'verify', 'finalize'] as const;
export type BenchStepId = typeof BENCH_STEP_IDS[number];

export const BENCH_STEP_STATUSES = ['running', 'ok', 'warn', 'failed', 'skipped'] as const;
export type BenchStepStatus = typeof BENCH_STEP_STATUSES[number];

/** What keeps a device from taking the agent as its owner (AOSP preconditions, §6.3); setup_incomplete is only a
 *  warning (§6.2). */
export const BENCH_OWNER_BLOCKERS = ['accounts', 'extra_users', 'foreign_owner', 'profile_owner', 'agent_too_old',
  'policy_admin_only', 'unknown'] as const;
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
export type BenchErrorCode = typeof BENCH_ERROR_CODES[number];

/** The codes the server answers the station with (HTTP refusals, §3.11). */
export const BENCH_API_CODES = [
  'station_pending', 'station_suspended', 'station_revoked', 'station_ip_refused', 'target_refused', 'device_outside_target',
  'agent_already_enrolled', 'open_provisioning', 'bad_state', 'no_session', 'not_enrolled', 'not_verified', 'too_many_pending',
  'apk_unavailable', 'apk_mismatch', 'verification_mismatch', 'agent_too_old',
  // Lot BANC-T §9: the site chosen on the card is not one of the target's (unknown, archived, of another tenant or
  // outside the target's group); the name of the device is already used in the site (case ignored).
  'site_refused', 'name_taken',
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
};

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

export interface BenchSessionView {
  id: string;
  stationId: string;
  userId: number;
  technician: string | null;
  openedAt: string;
  expiresAt: string;
  closedAt: string | null;
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
  session: BenchSessionView | null;
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
  /** technician: only when that user is a member of this tenant (null otherwise); mine: the session of the requesting
   *  user, who alone (with a platform administrator) may close it. */
  session: { id: string; technician: string | null; expiresAt: string; mine: boolean } | null;
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
 *  (Q4); the technician of its session named only when a member of the tenant. */
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
  session: { id: string; technician: string | null; expiresAt: string; mine: boolean } | null;
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

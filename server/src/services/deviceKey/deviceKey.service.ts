import crypto from 'node:crypto';
import path from 'node:path';
import type { Request } from 'express';
import {
  MASTER_TENANT_ID,
  DEVICE_KEY_CHALLENGE_TTL_SECONDS, DEVICE_KEY_ENROL_TTL_SECONDS, DEVICE_KEY_MAX_PER_USER,
  DEVICE_KEY_STALE_DAYS, DEVICE_KEY_MAX_BULK, DEVICE_KEY_BULK_SPREAD_SECONDS, DEVICE_KEY_DEFAULT_APP_ID,
  type DeviceChallenge, type DeviceKeyInfo, type DeviceKeyPolicy, type DeviceKeyRevokeReason,
  type DeviceKeySecurityLevel, type DeviceKeyEnrolBeginResponse, type DeviceKeyEnrolFinishResponse,
  type DeviceKeyAttestationFailureReason, type DeviceKeyEligibilityReason,
} from '@obliance/shared';
import { db } from '../../db';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import { clientAddress } from '../../utils/clientIp';
import { killSessionsForUser, closeSessionChannels } from '../userSessions.service';
import { obligateService, type ObligateMfaEpoch } from '../obligate.service';
import {
  buildPayload, computeBinding, deriveBindingKey, tryNormaliseOrigin, isUuid, fromB64, b64url, spkiFingerprint, enrolKeyRef,
  sortedUniqueDeviceIds, type PayloadChallenge, type PayloadPurpose,
} from './payload';
import { parseEcdsaSignature } from './der';
import { verifyAttestation, type AttestationOutcome, type AttestationFailureReason } from './attestation';
import { PINNED_ROOT_SPKI_SHA256 } from './attestationRoots';
import { createStatusListStore, normaliseSerial, type StatusListView } from './attestationStatus';

// ── Device keys: storage, challenges, assertions, revocation ───────────────
//
// docs/mobile/device-bound-2fa.md §4 (protocol), §5 (tables, migration 128),
// §6.3 (verifyAssertion), §6.5 (enrolment), §6.7 (revocation), §6.8 (the
// assertion / issuance caps), §6.9 (periodic tasks). Lot S1.
//
// Callers (lots S2/S3): routes/deviceKey.routes.ts (profile endpoints, the
// order of checks of enrol/begin, the password + NEW code step-up and the
// 'enrol' throttle of stepUpProof.ts), middleware/deviceKeySession.ts (the
// binding), stepUpProof.ts checkSecondFactor (bound session, assertions),
// auth.controller / twoFactor.controller (sign-in, sign-out, /me),
// users.controller (administration), appConfig.controller (settings),
// index.ts (periodic tasks) and the revocation hooks listed in §6.7.
//
// Never logged nor audited: nonces, signatures, passwords, codes.

// Compile-time guard: the 422 reasons published in @obliance/shared are
// exactly the verifier's (attestation.ts keeps no project import).
type SameUnion<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
const ATTESTATION_REASONS_IN_SYNC: SameUnion<AttestationFailureReason, DeviceKeyAttestationFailureReason> = true;
void ATTESTATION_REASONS_IN_SYNC;

// ── Constants ───────────────────────────────────────────────────────────────

/** mobile/android/RELEASE-FINGERPRINT.txt (APK release signer, SHA-256). */
export const RELEASE_APP_SIGNER = '8c7e67f860beacde55ab2437a41f50c6e2c8f0777f2faca88876676c6d82ac8d';

/** Platform settings (app_config, [D15]) and their defaults (read `=== 'true'`). */
export const DEVICE_KEY_CONFIG_DEFAULTS = Object.freeze({
  device_keys_enabled: 'true',
  device_keys_login: 'true',
  device_keys_require_attestation: 'true',
  device_keys_strict_session: 'true',
});
export type DeviceKeyConfigKey = keyof typeof DEVICE_KEY_CONFIG_DEFAULTS;

/** Enrolment ticket action (payload `action:` line). */
export const ENROL_ACTION = 'device_key.enrol';
/** Key status cache TTL (§6.4) — dropped locally at each revocation. */
export const KEY_STATUS_TTL_MS = 30_000;
/** Assertion failures per session (§6.8). */
export const ASSERTION_FAIL_MAX = 5;
export const ASSERTION_FAIL_WINDOW_MS = 15 * 60 * 1000;
/** Challenge issuance caps (§6.8). Single challenges: 30 / min per session.
 *  Bulk challenges (a deviceBulkId, §4.9.4) have their own per-session
 *  budget: a full bulk of DEVICE_KEY_MAX_BULK plus one renewal of each of
 *  its challenges (challenge_expired) within the minute, so one fingerprint
 *  really covers up to 50 targets. Both count in the per-user hourly cap. */
export const ISSUE_PER_SESSION_MAX = 30;
export const ISSUE_BULK_PER_SESSION_MAX = 2 * DEVICE_KEY_MAX_BULK;
export const ISSUE_PER_SESSION_WINDOW_MS = 60 * 1000;
export const ISSUE_PER_USER_MAX = 600;
export const ISSUE_PER_USER_WINDOW_MS = 60 * 60 * 1000;
/** Expired challenges are deleted after this many days (§6.9). */
export const CHALLENGE_RETENTION_DAYS = 7;
/** Reasons that keep the user's trusted IPs (§6.7 step 4). */
const KEEP_TRUST_REASONS: ReadonlySet<DeviceKeyRevokeReason> = new Set(['replaced', 'stale', 'policy']);

const INSTALL_ID_RE = /^[\x21-\x7e]{1,64}$/;
const ACTION_KEY_RE = /^[\x21-\x7e]{1,120}$/;

// ── Configuration (env) ─────────────────────────────────────────────────────

function csv(s: string): string[] {
  return String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
}

let warnedConfig = false;
function warnConfigOnce(): void {
  if (warnedConfig) return;
  warnedConfig = true;
  for (const raw of [config.publicUrl, ...csv(config.deviceKeys.origins)]) {
    if (raw && !tryNormaliseOrigin(raw)) {
      logger.warn({ origin: raw }, 'device keys: origin ignored (not an ASCII http(s) origin)');
    }
  }
  const debug = appSigners().filter((s) => s !== RELEASE_APP_SIGNER);
  if (debug.length > 0) {
    // [D19] a debug (or other) signer belongs to a development server only.
    logger.warn({ signers: debug }, 'device keys: DEVICE_KEY_APP_SIGNERS accepts a non-release APK signer (development servers only)');
  }
}

/**
 * Origins accepted at enrolment (§4.6, [D17]): the public address (APP_URL,
 * else an explicitly set CLIENT_ORIGIN — config.publicUrl) plus each
 * DEVICE_KEY_ORIGINS entry, normalised, ASCII only. Never derived from Host
 * nor X-Forwarded-*. Empty → enrolment refused (device_keys_origin_unset).
 */
export function allowedOrigins(): string[] {
  warnConfigOnce();
  const out = new Set<string>();
  for (const raw of [config.publicUrl, ...csv(config.deviceKeys.origins)]) {
    const o = raw ? tryNormaliseOrigin(raw) : null;
    if (o) out.add(o);
  }
  return [...out];
}

/** Accepted app packages (DEVICE_KEY_APP_IDS, default tools.obli.obliance.next). */
export function appPackages(): string[] {
  const list = csv(config.deviceKeys.appIds);
  return list.length > 0 ? list : [DEVICE_KEY_DEFAULT_APP_ID];
}

const warnedSigners = new Set<string>();

/** Accepted APK signer digests (DEVICE_KEY_APP_SIGNERS, default the release
 *  signer). An entry that is not 64 hex characters (':' ignored) is dropped,
 *  with a warning (once per value). */
export function appSigners(): string[] {
  const list: string[] = [];
  for (const raw of csv(config.deviceKeys.appSigners)) {
    const v = raw.replace(/:/g, '').toLowerCase();
    if (/^[0-9a-f]{64}$/.test(v)) { list.push(v); continue; }
    if (!warnedSigners.has(raw)) {
      warnedSigners.add(raw);
      logger.warn({ entry: raw.slice(0, 100) }, 'device keys: DEVICE_KEY_APP_SIGNERS entry ignored (not a SHA-256 hex digest)');
    }
  }
  return list.length > 0 ? [...new Set(list)] : [RELEASE_APP_SIGNER];
}

// ── Platform policy ─────────────────────────────────────────────────────────

const POLICY_TTL_MS = 5_000;
let policyCache: { at: number; flags: Record<DeviceKeyConfigKey, boolean> } | null = null;

/** Drops the cached platform flags (call after writing a device_keys_* setting). */
export function invalidatePolicyCache(): void {
  policyCache = null;
}

async function readFlags(): Promise<Record<DeviceKeyConfigKey, boolean>> {
  const now = Date.now();
  if (policyCache && now - policyCache.at < POLICY_TTL_MS) return policyCache.flags;
  const keys = Object.keys(DEVICE_KEY_CONFIG_DEFAULTS) as DeviceKeyConfigKey[];
  const rows = await db('app_config').whereIn('key', keys).select('key', 'value') as Array<{ key: string; value: string | null }>;
  const map = new Map(rows.map((r) => [r.key, r.value]));
  const flags = {} as Record<DeviceKeyConfigKey, boolean>;
  for (const k of keys) flags[k] = (map.get(k) ?? DEVICE_KEY_CONFIG_DEFAULTS[k]) === 'true';
  policyCache = { at: now, flags };
  return flags;
}

/**
 * Lot O (§4.10, §6.10): SSO (Obligate) accounts may enrol and use a phone key
 * only while the configured Obligate announces the three capabilities
 * {stepUpEpoch, reauth, totpReplayGuard} (GET /api/oauth/capabilities, 10-min
 * cache). Any failure closes: 403 device_keys_sso_unsupported at enrolment,
 * 'disabled' at use.
 */
export async function ssoSupported(): Promise<boolean> {
  try {
    return await obligateService.lotOSupported();
  } catch {
    return false;
  }
}

/**
 * Effective policy (§9): DEVICE_KEYS_DISABLED overrides the settings.
 * `ssoSupported` asks Obligate (cached) only with `{sso:true}`; otherwise it
 * is the last known answer, without I/O (the per-request callers never read it).
 */
export async function getPolicy(opts: { sso?: boolean } = {}): Promise<DeviceKeyPolicy> {
  const f = await readFlags();
  const enabled = !config.deviceKeys.disabled && f.device_keys_enabled;
  return {
    enabled,
    loginEnabled: enabled && f.device_keys_login,
    requireAttestation: f.device_keys_require_attestation,
    strictSession: f.device_keys_strict_session,
    originConfigured: allowedOrigins().length > 0,
    ssoSupported: opts.sso ? await ssoSupported() : obligateService.lotOSupportedCached(),
  };
}

// ── Attestation revocation list (§4.3 step 4) ──────────────────────────────

export const attestationStatusStore = createStatusListStore({
  filePath: path.join(config.customDir, 'device-keys', 'attestation-status.json'),
  log: (level, msg, extra) => logger[level](extra ?? {}, msg),
});

// ── Request helpers ─────────────────────────────────────────────────────────

/** sha256(req.sessionID); a missing id hashes a random value (never matches). */
export function sessionHashOf(req: Request): string {
  const sid = req.sessionID ? String(req.sessionID) : crypto.randomBytes(16).toString('hex');
  return crypto.createHash('sha256').update(sid).digest('hex');
}

/** Binding tenant (§4.5): req.tenantId ?? req.session.currentTenantId, else null. */
export function bindingTenantOf(req: Request): number | null {
  const raw = (req as { tenantId?: unknown }).tenantId ?? req.session?.currentTenantId;
  const t = Number(raw);
  return raw != null && Number.isSafeInteger(t) && t > 0 ? t : null;
}

let bindingKeyMemo: { src: string; key: Buffer } | null = null;

/**
 * Body key of the request binding (§4.5 v2): HKDF of DEVICE_KEY_BINDING_SECRET,
 * else SESSION_SECRET: a secret that never reaches the database, so a stored
 * binding_hash (whose body may carry a password) cannot be brute forced from
 * a dump. Changing the secret only invalidates the challenges open at that
 * moment (120 s).
 */
export function bindingKey(): Buffer {
  const src = config.deviceKeys.bindingSecret || config.sessionSecret;
  if (!bindingKeyMemo || bindingKeyMemo.src !== src) bindingKeyMemo = { src, key: deriveBindingKey(src) };
  return bindingKeyMemo.key;
}

/** The binding of THIS request (§4.5), computed where enforce() runs. */
export function requestBinding(req: Request, actionKey: string, deviceIds?: ReadonlyArray<unknown> | null): string {
  return computeBinding({
    method: req.method,
    originalUrl: req.originalUrl,
    tenantId: bindingTenantOf(req),
    actionKey,
    deviceIds: deviceIds ?? [],
    body: req.body,
  }, bindingKey());
}

function ipOf(req: Request | undefined): string | null {
  if (!req) return null;
  try { return clientAddress(req).ip || null; } catch { return null; }
}

function auditTenantOf(req: Request | undefined): number {
  if (!req) return MASTER_TENANT_ID;
  const t = Number((req as { tenantId?: unknown }).tenantId ?? req.session?.currentTenantId ?? MASTER_TENANT_ID);
  return Number.isSafeInteger(t) && t > 0 ? t : MASTER_TENANT_ID;
}

/** Audit context of a call made WITHOUT a request (approval executor, jobs):
 *  the tenant the row belongs to and the acting user. */
export interface AuditContext {
  tenantId?: number | null;
  actorId?: number | null;
}

async function audit(
  req: Request | undefined, userId: number, action: string, details: Record<string, unknown>, ctx: AuditContext = {},
  resource: { resourceType: string; resourcePath: string } = { resourceType: 'user', resourcePath: String(userId) },
): Promise<void> {
  try {
    const { auditService } = await import('../audit.service');
    const ctxTenant = Number(ctx.tenantId);
    await auditService.log({
      tenantId: req ? auditTenantOf(req) : (Number.isSafeInteger(ctxTenant) && ctxTenant > 0 ? ctxTenant : MASTER_TENANT_ID),
      userId: (req?.session?.userId as number | undefined) ?? (ctx.actorId ?? undefined) ?? (userId > 0 ? userId : undefined),
      action,
      resourceType: resource.resourceType,
      resourcePath: resource.resourcePath,
      details,
      ipAddress: ipOf(req) ?? undefined,
    });
  } catch { /* audit never breaks the request */ }
}

function toBuf(v: unknown): Buffer {
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v);
  if (typeof v === 'string' && v.startsWith('\\x')) return Buffer.from(v.slice(2), 'hex');
  throw new Error('device keys: unexpected bytea value');
}

function clean(s: unknown, max: number): string | null {
  if (typeof s !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const v = s.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
  return v || null;
}

// ── In-memory sliding counters (§6.8: assertion failures, issuance) ────────

type Counter = { hit(key: string): boolean; count(key: string): number; reset(key: string): void; clear(): void };

function slidingCounter(limit: number, windowMs: number, maxKeys = 50_000): Counter {
  const m = new Map<string, number[]>();
  const live = (key: string, now: number): number[] => {
    const arr = (m.get(key) ?? []).filter((t) => now - t < windowMs);
    if (arr.length) m.set(key, arr); else m.delete(key);
    return arr;
  };
  return {
    /** Records one event; false when the limit was already reached (not recorded). */
    hit(key) {
      const now = Date.now();
      const arr = live(key, now);
      if (arr.length >= limit) return false;
      if (!m.has(key) && m.size >= maxKeys) m.clear();
      arr.push(now);
      m.set(key, arr);
      return true;
    },
    count(key) { return live(key, Date.now()).length; },
    reset(key) { m.delete(key); },
    clear() { m.clear(); },
  };
}

const assertionFailures = slidingCounter(ASSERTION_FAIL_MAX, ASSERTION_FAIL_WINDOW_MS);
const issuePerSession = slidingCounter(ISSUE_PER_SESSION_MAX, ISSUE_PER_SESSION_WINDOW_MS);
const issueBulkPerSession = slidingCounter(ISSUE_BULK_PER_SESSION_MAX, ISSUE_PER_SESSION_WINDOW_MS);
const issuePerUser = slidingCounter(ISSUE_PER_USER_MAX, ISSUE_PER_USER_WINDOW_MS);

/** Tests / investigation: clears the in-memory caps and caches. */
export function resetDeviceKeyMemory(): void {
  for (const c of [assertionFailures, issuePerSession, issueBulkPerSession, issuePerUser]) c.clear();
  statusCache.clear();
  unknownKeyCache.clear();
  policyCache = null;
}

/** Assertion failures recorded for this session in the window (§6.8). */
export function assertionThrottled(req: Request): boolean {
  return assertionFailures.count(sessionHashOf(req)) >= ASSERTION_FAIL_MAX;
}

function countAssertionFailure(req: Request): void {
  assertionFailures.hit(sessionHashOf(req));
}

// ── Keys ───────────────────────────────────────────────────────────────────

export interface KeyStatus {
  status: 'active' | 'revoked';
  userId: number;
  /** credential_version matches the user's and the user is active. */
  credOk: boolean;
  securityLevel: DeviceKeySecurityLevel;
  /** Serials of the key's attestation chain (compared with Google's list). */
  serials: string[];
}

/** Known keys (cached 30 s). Bounded: when full, the OLDEST entry goes. */
const statusCache = new Map<string, { at: number; st: KeyStatus }>();
/** Unknown key ids (cached 30 s), kept apart and bounded on their own: a
 *  flood of random ids can never evict the entries of real keys. */
const unknownKeyCache = new Map<string, number>();
const STATUS_CACHE_MAX = 10_000;

function boundedSet<V>(m: Map<string, V>, key: string, v: V): void {
  m.delete(key);
  while (m.size >= STATUS_CACHE_MAX) {
    const oldest = m.keys().next();
    if (oldest.done) break;
    m.delete(oldest.value);
  }
  m.set(key, v);
}

/** Drops a key from the status cache (done by every revocation). */
export function forgetKeyStatus(keyId: string): void {
  statusCache.delete(keyId);
  unknownKeyCache.delete(keyId);
}

/** Serials stored with a key's attestation summary (hex strings). */
function serialsOf(attestation: unknown): string[] {
  let a: unknown = attestation;
  if (typeof a === 'string') { try { a = JSON.parse(a); } catch { return []; } }
  const list = a && typeof a === 'object' ? (a as { serials?: unknown }).serials : null;
  return Array.isArray(list) ? list.filter((x): x is string => typeof x === 'string' && /^[0-9a-fA-F]{1,128}$/.test(x)) : [];
}

/**
 * [D4] after enrolment: a serial of the key's (verified) chain that Google's
 * status list NOW marks REVOKED / SUSPENDED (a leaked factory keybox revoked
 * later). In memory only (the list the daily task keeps); null when none,
 * when no list is known, or for an 'unverified' key (no trusted chain).
 */
export function revokedAttestationSerial(
  securityLevel: string, serials: ReadonlyArray<string>, list: StatusListView | null = attestationStatusStore.current(),
): string | null {
  if (!list || securityLevel === 'unverified') return null;
  for (const s of serials) {
    const n = normaliseSerial(s);
    const st = list.entries.get(n);
    if (st === 'REVOKED' || st === 'SUSPENDED') return n;
  }
  return null;
}

/**
 * Status of a key for the per-request session check (§6.4), cached 30 s.
 * null: unknown key (or not a UUID).
 */
export async function keyStatusCached(keyId: unknown): Promise<KeyStatus | null> {
  if (!isUuid(keyId)) return null;
  const now = Date.now();
  const hit = statusCache.get(keyId);
  if (hit && now - hit.at < KEY_STATUS_TTL_MS) return hit.st;
  const miss = unknownKeyCache.get(keyId);
  if (miss !== undefined && now - miss < KEY_STATUS_TTL_MS) return null;
  const r = await db.raw(
    `SELECT k.status, k.user_id, k.security_level, k.attestation -> 'serials' AS serials,
            (k.credential_version = u.credential_version AND u.is_active) AS cred_ok
       FROM user_device_keys k JOIN users u ON u.id = k.user_id
      WHERE k.id = ?`,
    [keyId],
  ) as { rows: Array<{ status: string; user_id: number; security_level: string; serials: unknown; cred_ok: boolean }> };
  const row = r.rows[0];
  if (!row) {
    statusCache.delete(keyId);
    boundedSet(unknownKeyCache, keyId, now);
    return null;
  }
  const st: KeyStatus = {
    status: row.status === 'active' ? 'active' : 'revoked',
    userId: Number(row.user_id),
    credOk: row.cred_ok === true,
    securityLevel: row.security_level as DeviceKeySecurityLevel,
    serials: serialsOf({ serials: typeof row.serials === 'string' ? safeJson(row.serials) : row.serials }),
  };
  unknownKeyCache.delete(keyId);
  boundedSet(statusCache, keyId, { at: now, st });
  return st;
}

function safeJson(v: string): unknown {
  try { return JSON.parse(v); } catch { return null; }
}

/**
 * THE per-request rule of a key named by a session (§6.4): true when the key
 * is dead for use: unknown, not active, credentials changed (revoked here,
 * 'credentials_changed'), 'unverified' while attestation is required (revoked
 * here, 'policy'), or its attestation chain revoked by Google since enrolment
 * (revoked here, 'attestation_revoked'). The caller checks the key's owner.
 * Used by deviceKeySession, the Socket.io handshake and the remote tunnel
 * upgrade (boundSessionDead).
 */
export async function deadKeyStatus(
  keyId: string, st: KeyStatus | null, requireAttestation: boolean, req?: Request,
): Promise<boolean> {
  if (!st) return true;
  if (st.status !== 'active') return true;
  if (!st.credOk) { await revoke(keyId, 'credentials_changed', { req }); return true; }
  if (requireAttestation && st.securityLevel === 'unverified') { await revoke(keyId, 'policy', { req }); return true; }
  const serial = revokedAttestationSerial(st.securityLevel, st.serials);
  if (serial) {
    logger.warn({ keyId, serial }, 'device key: attestation chain revoked by Google since enrolment, key revoked');
    await revoke(keyId, 'attestation_revoked', { req });
    return true;
  }
  return false;
}

/**
 * Must a session bound to `keyId` (sess.deviceKeyId) of user `userId` die?
 * false while the feature is off (bound sessions then behave as unbound) or
 * when the session is not bound; true when the key is another user's or dead
 * (deadKeyStatus). For the channels that authenticate once (Socket.io
 * handshake, remote tunnel upgrade) and never go through deviceKeySession.
 */
export async function boundSessionDead(keyId: unknown, userId: unknown, req?: Request): Promise<boolean> {
  if (keyId == null || keyId === '') return false;
  const pol = await getPolicy();
  if (!pol.enabled) return false;
  if (!isUuid(keyId)) return true;
  const st = await keyStatusCached(keyId);
  if (!st || st.userId !== Number(userId)) return true;
  return deadKeyStatus(keyId, st, pol.requireAttestation, req);
}

/** A usable key, as needed by the verifiers. */
export interface ActiveKey {
  id: string;
  userId: number;
  origin: string;
  securityLevel: DeviceKeySecurityLevel;
  spki: Buffer;
  credentialVersion: number;
}

type KeyRow = {
  id: string; user_id: number; origin: string; security_level: string; public_key_spki: unknown;
  credential_version: number; status: string; sso_epoch: number | null; user_cv: number; user_active: boolean;
  foreign_source: string | null; foreign_id: number | null; totp_enabled: boolean; totp_secret: string | null;
  attestation: unknown;
};

async function loadKey(keyId: string): Promise<KeyRow | null> {
  if (!isUuid(keyId)) return null;
  const row = await db('user_device_keys as k')
    .join('users as u', 'u.id', 'k.user_id')
    .where('k.id', keyId)
    .first(
      'k.id', 'k.user_id', 'k.origin', 'k.security_level', 'k.public_key_spki', 'k.credential_version', 'k.status', 'k.sso_epoch', 'k.attestation',
      'u.credential_version as user_cv', 'u.is_active as user_active', 'u.foreign_source', 'u.foreign_id', 'u.totp_enabled', 'u.totp_secret',
    ) as KeyRow | undefined;
  return row ?? null;
}

/**
 * Lot O (§4.10, §6.3 step 3): a key of an SSO account is usable only while
 * Obligate announces the capabilities AND the user's Obligate MFA epoch (5-min
 * cache) still equals user_device_keys.sso_epoch.
 *  - 'ok'       local account, or SSO with the same epoch;
 *  - 'disabled' capabilities gone, Obligate unreachable / not answering,
 *               user inactive there, key without an epoch: refused for THIS
 *               request (fail closed), the key is kept;
 *  - 'revoked'  the epoch moved (password / TOTP / activation change, MFA
 *               reset at Obligate): the key is revoked ('sso_mfa_changed').
 */
async function ssoKeyState(row: KeyRow, req?: Request): Promise<'ok' | 'disabled' | 'revoked'> {
  if (row.foreign_source == null) return 'ok';
  const foreignId = Number(row.foreign_id);
  if (row.foreign_source !== 'obligate' || !Number.isSafeInteger(foreignId) || foreignId <= 0 || row.sso_epoch == null) return 'disabled';
  if (!(await ssoSupported())) return 'disabled';
  const e = await obligateService.getMfaEpoch(foreignId);
  if (!e || !e.active) return 'disabled';
  if (e.mfaEpoch !== Number(row.sso_epoch)) {
    await revoke(row.id, 'sso_mfa_changed', { req });
    return 'revoked';
  }
  return 'ok';
}

/**
 * Lot O (§6.10, O3): an sso-user-sync `credentials-changed` push — which
 * proves nothing by itself (its Bearer secret may be public) — once the route
 * re-read the user's epoch from Obligate itself (uncached, see
 * obligateService.mfaEpochForPush). The user's active SSO keys this epoch
 * does not confirm are revoked ('sso_mfa_changed', which also drops the
 * user's trusted IPs), then every session of the user is killed. `e` null =
 * Obligate no longer knows the user here (confirmed by the caller): every
 * key goes. The pushed epoch value is never used.
 *  - 'none':        no active key, nothing to do;
 *  - 'unconfirmed': every key still matches Obligate's epoch — nothing done;
 *  - 'revoked':     `count` keys revoked, sessions killed.
 */
export async function applySsoCredentialsChanged(
  localUserId: number, e: ObligateMfaEpoch | null,
): Promise<{ outcome: 'none' | 'unconfirmed' | 'revoked'; count: number }> {
  const keys = await db('user_device_keys').where({ user_id: localUserId, status: 'active' })
    .select('id', 'sso_epoch') as Array<{ id: string; sso_epoch: number | null }>;
  if (keys.length === 0) return { outcome: 'none', count: 0 };
  const stale = keys
    .filter((k) => !e || !e.active || k.sso_epoch == null || Number(k.sso_epoch) !== e.mfaEpoch)
    .map((k) => k.id);
  if (stale.length === 0) return { outcome: 'unconfirmed', count: 0 };
  const done = await revoke(stale, 'sso_mfa_changed', { ownerId: localUserId });
  await killSessionsForUser(localUserId, 'sso_mfa_changed');
  return { outcome: 'revoked', count: done.length };
}

function toActiveKey(row: KeyRow): ActiveKey {
  return {
    id: row.id,
    userId: Number(row.user_id),
    origin: row.origin,
    securityLevel: row.security_level as DeviceKeySecurityLevel,
    spki: toBuf(row.public_key_spki),
    credentialVersion: Number(row.credential_version),
  };
}

/**
 * Why a key row cannot be used right now, revoking it when the reason is
 * permanent (credential version drift, 'unverified' under required
 * attestation). null: usable.
 */
async function unusableReason(row: KeyRow, requireAttestation: boolean, req?: Request): Promise<'revoked' | null> {
  if (row.status !== 'active' || !row.user_active) return 'revoked';
  if (Number(row.credential_version) !== Number(row.user_cv)) {
    await revoke(row.id, 'credentials_changed', { req });
    return 'revoked';
  }
  if (requireAttestation && row.security_level === 'unverified') {
    await revoke(row.id, 'policy', { req });
    return 'revoked';
  }
  // [D4] a chain certificate revoked by Google since enrolment (in memory,
  // no I/O: the list the daily task keeps), effective before the next sweep.
  const serial = revokedAttestationSerial(row.security_level, serialsOf(row.attestation));
  if (serial) {
    logger.warn({ keyId: row.id, serial }, 'device key: attestation chain revoked by Google since enrolment, key revoked');
    await revoke(row.id, 'attestation_revoked', { req });
    return 'revoked';
  }
  return null;
}

export type SessionBinding =
  | { kind: 'unbound' }                       // no bound key, or the policy is off (§4.1)
  | { kind: 'bound'; key: ActiveKey }
  | { kind: 'revoked'; keyId: string };      // bound to a dead key: destroy the session, 401 revoked

/**
 * The session's device binding (§4.1, §4.7). 'revoked' means the session is
 * bound to a key that is no longer usable (revoked, other user, credentials
 * changed, unverified under required attestation): the caller destroys the
 * session and answers 401 {error:'Authentication required',
 * deviceKeyStatus:'revoked'}. Never treat 'revoked' as unbound: that would
 * reopen the trusted-IP shortcut and the code-only path on that phone.
 */
export async function sessionBinding(req: Request): Promise<SessionBinding> {
  const keyId = req.session?.deviceKeyId;
  const userId = Number(req.session?.userId);
  if (!keyId || !Number.isSafeInteger(userId) || userId <= 0) return { kind: 'unbound' };
  const pol = await getPolicy();
  if (!pol.enabled) return { kind: 'unbound' };
  const row = await loadKey(keyId);
  if (!row || Number(row.user_id) !== userId) return { kind: 'revoked', keyId };
  if (await unusableReason(row, pol.requireAttestation, req)) return { kind: 'revoked', keyId };
  return { kind: 'bound', key: toActiveKey(row) };
}

/** §6.2 step 3 shorthand: the bound key, or null (unbound OR revoked — use
 *  sessionBinding() where a revoked binding must kill the session). */
export async function boundKey(req: Request): Promise<ActiveKey | null> {
  const b = await sessionBinding(req);
  return b.kind === 'bound' ? b.key : null;
}

/**
 * Sign-in eligibility (§6.5 POST /api/auth/login, [D7]): the header's key is
 * an active key of THIS user with an up-to-date credential version, the
 * account is local (foreign_source IS NULL) with TOTP, device keys and
 * device sign-in are enabled, and the key is acceptable for the attestation
 * policy. Returns the key or null (no information to the caller's client).
 */
export async function loginKeyFor(userId: number, headerKeyId: unknown): Promise<ActiveKey | null> {
  if (!isUuid(headerKeyId)) return null;
  const pol = await getPolicy();
  if (!pol.enabled || !pol.loginEnabled) return null;
  const row = await loadKey(headerKeyId);
  if (!row || Number(row.user_id) !== userId) return null;
  if (row.foreign_source != null || !row.totp_enabled || !row.totp_secret) return null;
  if (await unusableReason(row, pol.requireAttestation)) return null;
  return toActiveKey(row);
}

/**
 * A key the session of `userId` may be bound to (§4.7): policy on, the key
 * active and the user's, credential version current, acceptable for the
 * attestation policy (a key failing a permanent check is revoked here).
 * Used after a sign-in (bind the regenerated session to the header's key).
 */
export async function bindableKey(userId: number, keyId: unknown): Promise<ActiveKey | null> {
  if (!isUuid(keyId)) return null;
  const pol = await getPolicy();
  if (!pol.enabled) return null;
  const row = await loadKey(keyId);
  if (!row || Number(row.user_id) !== userId) return null;
  if (await unusableReason(row, pol.requireAttestation)) return null;
  return toActiveKey(row);
}

/** Why this account cannot enrol right now (GET /api/profile/device-keys
 *  `eligibility`, same order as enrol/begin steps 1–5). */
export async function eligibilityOf(
  user: EnrolUser,
  locked: () => Promise<boolean>,
): Promise<{ ok: true } | { ok: false; reason: DeviceKeyEligibilityReason }> {
  const pre = await enrolPreconditions(user);
  if (!pre.ok) {
    const e = String(pre.body.error);
    const reason: DeviceKeyEligibilityReason =
      e === 'device_keys_disabled' || e === 'device_keys_origin_unset' || e === 'device_keys_sso_unsupported' ? e : 'no_totp';
    return { ok: false, reason };
  }
  if (await locked()) return { ok: false, reason: 'enrol_locked' };
  return { ok: true };
}

/** Active keys of a user, newest first (§6.5 GET /api/profile/device-keys). */
export async function list(userId: number, currentKeyId?: string | null): Promise<DeviceKeyInfo[]> {
  const rows = await db('user_device_keys')
    .where({ user_id: userId, status: 'active' })
    .orderBy('created_at', 'desc')
    .select('id', 'label', 'platform', 'security_level', 'attestation', 'created_at', 'last_used_at', 'last_used_ip', 'use_count') as Array<{
      id: string; label: string | null; platform: string; security_level: string; attestation: unknown;
      created_at: Date | string; last_used_at: Date | string | null; last_used_ip: string | null; use_count: number;
    }>;
  const iso = (d: Date | string | null) => (d == null ? null : new Date(d).toISOString());
  return rows.map((r) => {
    let att: Record<string, unknown> | null = null;
    try { att = typeof r.attestation === 'string' ? JSON.parse(r.attestation) : (r.attestation as Record<string, unknown> | null); } catch { att = null; }
    const patch = att ? Number(att.osPatchLevel) : NaN;
    return {
      id: r.id,
      label: r.label,
      platform: r.platform,
      securityLevel: r.security_level as DeviceKeySecurityLevel,
      osPatchLevel: Number.isFinite(patch) ? patch : null,
      createdAt: iso(r.created_at) as string,
      lastUsedAt: iso(r.last_used_at),
      lastUsedIp: r.last_used_ip,
      useCount: Number(r.use_count) || 0,
      current: !!currentKeyId && r.id === currentKeyId,
    };
  });
}

// ── Sessions ───────────────────────────────────────────────────────────────

/** Deletes every session bound to the key (sess JSON, §5.3) and closes the
 *  live channels those sessions opened (Socket.io, remote relays). */
export async function killSessionsForKey(keyId: string, reason = 'device_key_revoked'): Promise<number> {
  if (!isUuid(keyId)) return 0;
  const r = await db.raw(`DELETE FROM session WHERE (sess::jsonb ->> 'deviceKeyId') = ? RETURNING sid`, [keyId]) as
    { rows?: Array<{ sid: string }> };
  const sids = (r?.rows ?? []).map((x) => String(x.sid));
  await closeSessionChannels(sids, reason);
  return sids.length;
}

/** P6 kill-switch, re-exported for the device-key callers (§6.1). */
export { killSessionsForUser };

// ── Revocation (§6.7) ──────────────────────────────────────────────────────

export interface RevokeOptions {
  /** Administrator (or the user) who revoked; stored in revoked_by. */
  byUserId?: number | null;
  /** Restrict to the keys of this user (routes: "only the caller's key"). */
  ownerId?: number;
  /** Request, for the audit tenant and IP. */
  req?: Request;
  /** Without a request (approval executor, jobs): the audit rows' tenant
   *  (default: master) and actor (default: byUserId, else the key owner). */
  auditTenantId?: number | null;
  actorId?: number | null;
}

/**
 * THE revocation. In one transaction: status 'revoked' (+ when, by whom,
 * why), the keys' open challenges burnt, every session bound to the keys
 * deleted, and — except for 'replaced', 'stale' and 'policy' — every
 * trusted IP of their users deleted. Then the status cache entries are
 * dropped, the live channels of the deleted sessions are closed (their
 * Socket.io connections, authenticated once at the handshake, and the remote
 * relays they started or attached: shell, ObliReach, VM console), and one
 * `device_key.revoked` audit row is written per key.
 * Only active keys are affected; returns them.
 */
export async function revoke(
  keyIds: string | ReadonlyArray<string>,
  reason: DeviceKeyRevokeReason,
  opts: RevokeOptions = {},
): Promise<Array<{ id: string; userId: number; sessionsKilled: number }>> {
  const ids = [...new Set((typeof keyIds === 'string' ? [keyIds] : [...keyIds]).filter(isUuid))];
  if (ids.length === 0) return [];
  const done = await db.transaction(async (trx) => {
    let q = trx('user_device_keys').whereIn('id', ids).andWhere({ status: 'active' });
    if (opts.ownerId != null) q = q.andWhere({ user_id: opts.ownerId });
    const rows = await q.update({
      status: 'revoked',
      revoked_at: trx.fn.now(),
      revoked_by: opts.byUserId ?? null,
      revoke_reason: reason,
    }).returning(['id', 'user_id']) as Array<{ id: string; user_id: number }>;
    if (rows.length === 0) return [];
    const revokedIds = rows.map((r) => r.id);
    await trx('device_key_challenges')
      .whereIn('key_id', revokedIds)
      .whereNull('consumed_at')
      .update({ consumed_at: trx.fn.now(), result: 'revoked' });
    const out: Array<{ id: string; userId: number; sessionsKilled: number; sids: string[] }> = [];
    for (const r of rows) {
      const k = await trx.raw(`DELETE FROM session WHERE (sess::jsonb ->> 'deviceKeyId') = ? RETURNING sid`, [r.id]) as
        { rows?: Array<{ sid: string }> };
      const sids = (k?.rows ?? []).map((x) => String(x.sid));
      out.push({ id: r.id, userId: Number(r.user_id), sessionsKilled: sids.length, sids });
    }
    if (!KEEP_TRUST_REASONS.has(reason)) {
      const users = [...new Set(out.map((o) => o.userId))];
      await trx('tfa_trusted_sessions').whereIn('user_id', users).delete();
    }
    return out;
  });
  const ctx: AuditContext = { tenantId: opts.auditTenantId ?? null, actorId: opts.actorId ?? opts.byUserId ?? null };
  for (const r of done) forgetKeyStatus(r.id);
  // After the commit: the rows are gone, so a channel closed now cannot come
  // back through a new handshake (which checks the key as well). 'replaced'
  // (re-enrolment from the same installation) re-binds the CURRENT session
  // to the new key right after: its channels stay open.
  const keepSid = reason === 'replaced' && typeof opts.req?.sessionID === 'string' ? opts.req.sessionID : null;
  await closeSessionChannels(done.flatMap((r) => r.sids).filter((sid) => sid !== keepSid), `device_key_${reason}`);
  for (const r of done) {
    await audit(opts.req, r.userId, 'device_key.revoked', { keyId: r.id, reason, by: opts.byUserId ?? null }, ctx);
    if (r.sessionsKilled > 0) {
      await audit(opts.req, r.userId, 'device_key.sessions_killed', { keyId: r.id, count: r.sessionsKilled }, ctx);
    }
  }
  if (done.length > 0) logger.info({ reason, keys: done.map((d) => d.id) }, 'device keys revoked');
  return done.map(({ id, userId, sessionsKilled }) => ({ id, userId, sessionsKilled }));
}

/** Revokes every active key of a user (password change, TOTP change, admin, …). */
export async function revokeAllForUser(
  userId: number,
  reason: DeviceKeyRevokeReason,
  opts: Omit<RevokeOptions, 'ownerId'> = {},
): Promise<Array<{ id: string; userId: number; sessionsKilled: number }>> {
  const rows = await db('user_device_keys').where({ user_id: userId, status: 'active' }).select('id') as Array<{ id: string }>;
  return revoke(rows.map((r) => r.id), reason, { ...opts, ownerId: userId });
}

/** `device_keys_require_attestation` switched to 'true': unverified keys die ('policy'). */
export async function revokeUnverifiedKeys(opts: Omit<RevokeOptions, 'ownerId'> = {}): Promise<number> {
  const rows = await db('user_device_keys').where({ status: 'active', security_level: 'unverified' }).select('id') as Array<{ id: string }>;
  return (await revoke(rows.map((r) => r.id), 'policy', opts)).length;
}

// ── Challenges ─────────────────────────────────────────────────────────────

type ChallengeRow = {
  id: string; user_id: number; key_id: string | null; purpose: string; session_hash: string;
  tenant_id: number | null; bulk_id: string | null; nonce: unknown; action_key: string | null;
  binding_hash: string | null; consumed_at: Date | string | null; live: boolean;
  exp: number | string; created_epoch: number | string;
};

function epochOf(v: number | string | bigint): number {
  return Math.floor(Number(v));
}

async function tenantNameOf(tenantId: number | null): Promise<string | null> {
  if (tenantId == null) return null;
  try {
    const row = await db('tenants').where({ id: tenantId }).first('name') as { name: string } | undefined;
    return row?.name ?? null;
  } catch { return null; }
}

/** Issuance caps (§6.8): a bulk challenge draws on the session's bulk
 *  budget (2 × DEVICE_KEY_MAX_BULK / min), any other one on the single
 *  budget (30 / min); both on the user's hourly budget. */
function issueAllowed(req: Request, userId: number, bulk = false): boolean {
  const s = (bulk ? issueBulkPerSession : issuePerSession).hit(sessionHashOf(req));
  if (!s) return false;
  return issuePerUser.hit(String(userId));
}

export interface IssueStepUpOptions {
  actionKey: string;
  deviceIds?: ReadonlyArray<unknown> | null;
  /** The session's bound key (sessionBinding). */
  key: ActiveKey;
  /** Bulk step-up id (§4.9.4), from the request's deviceBulkId proof. */
  bulkId?: unknown;
}

/**
 * Issues a step-up challenge for THIS request (§4.8): single use, 120 s,
 * bound to the user, the session, the key, the binding tenant, the action
 * and the request binding. Issuance caps (§6.8): 30 / min per session (100
 * / min for bulk challenges) and 600 / h per user → null (the caller answers
 * deviceKeyStatus 'throttled').
 */
export async function issueStepUpChallenge(req: Request, o: IssueStepUpOptions): Promise<DeviceChallenge | null> {
  if (!ACTION_KEY_RE.test(o.actionKey)) throw new Error('device keys: bad action key');
  const bulkId = isUuid(o.bulkId) ? o.bulkId : null;
  if (!issueAllowed(req, o.key.userId, bulkId !== null)) return null;
  const tenantId = bindingTenantOf(req);
  const binding = requestBinding(req, o.actionKey, o.deviceIds);
  const ids = sortedUniqueDeviceIds(o.deviceIds ?? []);
  const nonce = crypto.randomBytes(32);
  const [row] = await db('device_key_challenges').insert({
    user_id: o.key.userId,
    key_id: o.key.id,
    purpose: 'stepup',
    session_hash: sessionHashOf(req),
    tenant_id: tenantId,
    bulk_id: bulkId,
    nonce,
    action_key: o.actionKey,
    binding_hash: binding,
    device_ids: ids.length ? db.raw('?::integer[]', [`{${ids.join(',')}}`]) : null,
    ip: ipOf(req),
    expires_at: db.raw(`now() + interval '${DEVICE_KEY_CHALLENGE_TTL_SECONDS} seconds'`),
  }).returning(['id', db.raw('FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint AS exp')]) as Array<{ id: string; exp: number | string }>;
  return {
    v: 1,
    keyId: o.key.id,
    challengeId: row.id,
    purpose: 'stepup',
    userId: o.key.userId,
    tenantId,
    tenantName: await tenantNameOf(tenantId),
    nonce: b64url(nonce),
    action: o.actionKey,
    binding,
    expiresAt: epochOf(row.exp),
    bulkId,
  };
}

/**
 * Issues a sign-in challenge (§4.9.3) on the CURRENT session (the one that
 * holds pendingMfaUserId): purpose 'login', no tenant, action and binding
 * '-'. The caller checked the key with loginKeyFor(). null when throttled.
 */
export async function issueLoginChallenge(req: Request, key: ActiveKey): Promise<DeviceChallenge | null> {
  if (!issueAllowed(req, key.userId)) return null;
  const nonce = crypto.randomBytes(32);
  const [row] = await db('device_key_challenges').insert({
    user_id: key.userId,
    key_id: key.id,
    purpose: 'login',
    session_hash: sessionHashOf(req),
    tenant_id: null,
    bulk_id: null,
    nonce,
    action_key: null,
    binding_hash: null,
    ip: ipOf(req),
    expires_at: db.raw(`now() + interval '${DEVICE_KEY_CHALLENGE_TTL_SECONDS} seconds'`),
  }).returning(['id', db.raw('FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint AS exp')]) as Array<{ id: string; exp: number | string }>;
  return {
    v: 1,
    keyId: key.id,
    challengeId: row.id,
    purpose: 'login',
    userId: key.userId,
    tenantId: null,
    nonce: b64url(nonce),
    action: '-',
    binding: '-',
    expiresAt: epochOf(row.exp),
    bulkId: null,
  };
}

// ── Assertions (§6.3) ──────────────────────────────────────────────────────

export interface ParsedAssertion {
  keyId: string;
  challengeIds: string[];
  signature: Buffer;
}

/** §6.3 step 1 (shape): v 1, UUID key, 1..50 unique UUID challenges, base64
 *  DER signature <= 200 chars, strictly encoded. null → 400 Validation. */
export function parseAssertion(raw: unknown): ParsedAssertion | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const a = raw as { v?: unknown; keyId?: unknown; challengeIds?: unknown; signature?: unknown };
  if (a.v !== 1 || !isUuid(a.keyId)) return null;
  if (!Array.isArray(a.challengeIds) || a.challengeIds.length < 1 || a.challengeIds.length > DEVICE_KEY_MAX_BULK) return null;
  if (!a.challengeIds.every(isUuid) || new Set(a.challengeIds).size !== a.challengeIds.length) return null;
  const sig = fromB64(a.signature, 200);
  if (!sig) return null;
  try { parseEcdsaSignature(sig); } catch { return null; }
  return { keyId: a.keyId, challengeIds: a.challengeIds as string[], signature: sig };
}

export type VerifyAssertionOptions =
  | {
    purpose: 'stepup';
    actionKey: string;
    deviceIds?: ReadonlyArray<unknown> | null;
    /** The session's bound key (sessionBinding → 'bound'). */
    key: ActiveKey;
    /** Default: req.stepUpProof.deviceAssertion. */
    assertion?: unknown;
  }
  | {
    purpose: 'login';
    /** req.session.pendingMfaUserId. */
    userId: number;
    assertion?: unknown;
  };

export type VerifyAssertionResult =
  | { ok: true; keyId: string; challengeId: string; count: number }
  /** 400 Validation (§4.8 "Assertion mal formée"). */
  | { ok: false; error: 'malformed' }
  /** 401 twoFactorRequired + deviceError 'invalid_assertion', no challenge. */
  | { ok: false; error: 'invalid_assertion' }
  /** 401 twoFactorRequired + deviceError 'challenge_expired' + this new
   *  challenge (null when issuance is throttled). */
  | { ok: false; error: 'challenge_expired'; challenge: DeviceChallenge | null }
  /** Key revoked / credentials changed: destroy the session, 401
   *  {error:'Authentication required', deviceKeyStatus:'revoked'}. */
  | { ok: false; error: 'revoked'; keyId: string }
  /** 401 twoFactorRequired + deviceKeyStatus 'throttled' (password + code). */
  | { ok: false; error: 'throttled' }
  /** 401 twoFactorRequired + deviceKeyStatus 'disabled' (code alone accepted). */
  | { ok: false; error: 'disabled' };

async function rejectAudit(req: Request, userId: number, keyId: string, deviceError: string, result?: string): Promise<void> {
  await audit(req, userId, 'device_key.assertion_rejected', { keyId, deviceError, ...(result ? { result } : {}) });
}

/**
 * Verifies a device assertion for THIS request (§6.3), consuming only the
 * request's own challenge. Order: policy, shape, per-session failure cap,
 * key, the listed challenges (same user / key / purpose / session / tenant,
 * bulk rules), this request's challenge (binding), signature, ONE atomic
 * consumption conditioned on the key being active and the credential
 * version unchanged, then the key's usage stamp and audit.
 * The signature is never used as a replay key (ECDSA is malleable).
 */
export async function verifyAssertion(req: Request, o: VerifyAssertionOptions): Promise<VerifyAssertionResult> {
  const pol = await getPolicy();
  if (!pol.enabled || (o.purpose === 'login' && !pol.loginEnabled)) return { ok: false, error: 'disabled' };

  // 1. Shape.
  const a = parseAssertion(o.assertion !== undefined ? o.assertion : req.stepUpProof?.deviceAssertion);
  if (!a) return { ok: false, error: 'malformed' };
  const userId = o.purpose === 'stepup' ? o.key.userId : o.userId;
  if (o.purpose === 'stepup' && a.keyId !== o.key.id) {
    countAssertionFailure(req);
    await rejectAudit(req, userId, a.keyId, 'invalid_assertion', 'not_bound_key');
    return { ok: false, error: 'invalid_assertion' };
  }

  // 2. Per-session failure cap.
  if (assertionThrottled(req)) return { ok: false, error: 'throttled' };

  // 3. Key.
  const row = await loadKey(a.keyId);
  if (!row || Number(row.user_id) !== userId) {
    countAssertionFailure(req);
    await rejectAudit(req, userId, a.keyId, 'invalid_assertion', 'unknown_key');
    return { ok: false, error: 'invalid_assertion' };
  }
  if (o.purpose === 'login' && (row.foreign_source != null || !row.totp_enabled || !row.totp_secret)) {
    countAssertionFailure(req);
    await rejectAudit(req, userId, a.keyId, 'invalid_assertion', 'not_login_eligible');
    return { ok: false, error: 'invalid_assertion' };
  }
  if (await unusableReason(row, pol.requireAttestation, req)) return { ok: false, error: 'revoked', keyId: a.keyId };
  const sso = await ssoKeyState(row, req);
  if (sso === 'revoked') return { ok: false, error: 'revoked', keyId: a.keyId };
  if (sso === 'disabled') return { ok: false, error: 'disabled' };
  const key = toActiveKey(row);

  // 4. The listed challenges.
  const sessionHash = sessionHashOf(req);
  const tenantId = o.purpose === 'stepup' ? bindingTenantOf(req) : null;
  const r = await db.raw(
    `SELECT id, user_id, key_id, purpose, session_hash, tenant_id, bulk_id, nonce, action_key, binding_hash,
            consumed_at, (expires_at > now()) AS live,
            FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint AS exp,
            EXTRACT(EPOCH FROM created_at) AS created_epoch
       FROM device_key_challenges WHERE id = ANY(?::uuid[])`,
    [`{${a.challengeIds.join(',')}}`],
  ) as { rows: ChallengeRow[] };
  const byId = new Map(r.rows.map((c) => [c.id, c]));
  const rows = a.challengeIds.map((id) => byId.get(id));
  const invalid = async (why: string): Promise<VerifyAssertionResult> => {
    countAssertionFailure(req);
    await rejectAudit(req, userId, key.id, 'invalid_assertion', why);
    return { ok: false, error: 'invalid_assertion' };
  };
  if (rows.some((c) => !c)) return invalid('unknown_challenge');
  const list = rows as ChallengeRow[];
  for (const c of list) {
    if (Number(c.user_id) !== userId || c.key_id !== key.id || c.purpose !== o.purpose
      || c.session_hash !== sessionHash || (c.tenant_id == null ? null : Number(c.tenant_id)) !== tenantId) {
      return invalid('challenge_mismatch');
    }
  }
  if (list.length > 1) {
    if (o.purpose !== 'stepup') return invalid('bulk_not_allowed');
    const first = list[0];
    const created = list.map((c) => Number(c.created_epoch));
    if (!first.bulk_id
      || list.some((c) => c.bulk_id !== first.bulk_id || c.action_key !== first.action_key)
      || Math.max(...created) - Math.min(...created) > DEVICE_KEY_BULK_SPREAD_SECONDS) {
      return invalid('bulk_mismatch');
    }
  }

  // 5. This request's challenge.
  let mine: ChallengeRow | undefined;
  if (o.purpose === 'stepup') {
    const binding = requestBinding(req, o.actionKey, o.deviceIds);
    mine = list.find((c) => c.binding_hash === binding && c.action_key === o.actionKey);
    if (!mine) return invalid('binding_mismatch');
  } else {
    if (list.length !== 1) return invalid('bulk_not_allowed');
    mine = list[0];
  }
  const renew = async (): Promise<VerifyAssertionResult> => {
    await rejectAudit(req, userId, key.id, 'challenge_expired');
    const challenge = o.purpose === 'stepup'
      ? await issueStepUpChallenge(req, { actionKey: o.actionKey, deviceIds: o.deviceIds, key, bulkId: mine!.bulk_id ?? req.stepUpProof?.deviceBulkId })
      : await issueLoginChallenge(req, key);
    return { ok: false, error: 'challenge_expired', challenge };
  };
  if (mine.consumed_at != null || !mine.live) return renew();

  // 6. Signature over the payload rebuilt from the database rows.
  const challenges: PayloadChallenge[] = list.map((c) => ({
    challengeId: c.id,
    nonce: toBuf(c.nonce),
    action: c.action_key,
    binding: c.binding_hash,
    exp: epochOf(c.exp),
  }));
  let payload: string;
  try {
    payload = buildPayload({ purpose: o.purpose as PayloadPurpose, origin: key.origin, userId: key.userId, keyRef: key.id, challenges });
  } catch {
    return invalid('payload');
  }
  let valid = false;
  try {
    const pub = crypto.createPublicKey({ key: key.spki, format: 'der', type: 'spki' });
    valid = crypto.verify('sha256', Buffer.from(payload, 'utf8'), { key: pub, dsaEncoding: 'der' }, a.signature);
  } catch { valid = false; }
  if (!valid) {
    await db('device_key_challenges').where({ id: mine.id }).whereNull('consumed_at')
      .update({ consumed_at: db.fn.now(), result: 'bad_signature' });
    return invalid('bad_signature');
  }

  // 7. Atomic consumption (one statement), conditioned on the key and the
  //    credential version at this instant.
  const consumed = await db.raw(
    `UPDATE device_key_challenges c SET consumed_at = now(), result = 'ok'
       FROM user_device_keys k, users u
      WHERE c.id = ? AND c.consumed_at IS NULL AND c.expires_at > now()
        AND k.id = c.key_id AND k.status = 'active'
        AND u.id = k.user_id AND u.is_active AND u.credential_version = k.credential_version
      RETURNING c.id`,
    [mine.id],
  ) as { rows: Array<{ id: string }> };
  if (consumed.rows.length === 0) {
    const again = await db.raw(`SELECT (expires_at > now()) AS live FROM device_key_challenges WHERE id = ?`, [mine.id]) as { rows: Array<{ live: boolean }> };
    if (again.rows[0] && again.rows[0].live === false) return renew();
    return invalid('not_consumed');
  }

  // 8. Usage stamp + audit.
  const ip = ipOf(req);
  await db('user_device_keys').where({ id: key.id }).update({
    last_used_at: db.fn.now(),
    last_used_ip: ip,
    use_count: db.raw('use_count + 1'),
  });
  await audit(req, userId, 'device_key.used', {
    keyId: key.id,
    action: o.purpose === 'stepup' ? o.actionKey : '-',
    purpose: o.purpose,
    count: list.length,
    deviceIds: o.purpose === 'stepup' ? sortedUniqueDeviceIds(o.deviceIds ?? []) : [],
    tenantId,
  });
  return { ok: true, keyId: key.id, challengeId: mine.id, count: list.length };
}

// ── Enrolment (§4.9.1, §6.5) ───────────────────────────────────────────────

export type ServiceFailure = { ok: false; status: number; body: Record<string, unknown> };

/** The account's factor situation, for enrol/begin steps 3–4. */
export interface EnrolUser {
  id: number;
  foreign_source: string | null;
  foreign_id?: number | null;
  totp_enabled: boolean;
  totp_secret: string | null;
}

/** Text the app recognises for "no second factor" (keep "enable TOTP"). */
export const ENROL_NO_TOTP_ERROR = 'Device keys need a second factor — enable TOTP 2FA on your profile first.';

/**
 * enrol/begin steps 1–4 (§6.5): policy on, origin configured, SSO account
 * refused without lot O, local account without TOTP refused. Steps 5
 * (enrol lock) and 6 (password + strict code) belong to the route (S2).
 */
export async function enrolPreconditions(user: EnrolUser): Promise<{ ok: true } | ServiceFailure> {
  // Obligate is asked (cached) only for an SSO account.
  const pol = await getPolicy({ sso: user.foreign_source != null });
  if (!pol.enabled) return { ok: false, status: 403, body: { error: 'device_keys_disabled' } };
  if (!pol.originConfigured) return { ok: false, status: 403, body: { error: 'device_keys_origin_unset' } };
  if (user.foreign_source != null) {
    // Lot O: an Obligate account linked by its foreign id, capabilities announced.
    if (!pol.ssoSupported || user.foreign_source !== 'obligate' || !user.foreign_id) {
      return { ok: false, status: 403, body: { error: 'device_keys_sso_unsupported' } };
    }
  } else if (!user.totp_enabled || !user.totp_secret) {
    return { ok: false, status: 403, body: { error: ENROL_NO_TOTP_ERROR } };
  }
  return { ok: true };
}

/**
 * enrol/begin steps 7–9 (§6.5), AFTER the route passed steps 1–6: at most 5
 * active keys (a key of the same installId is replaced, so it does not
 * count) [D14], then a single-use ticket (purpose 'enrol', 180 s [D16]) on
 * the current session, audit device_key.enrol_begin.
 */
export async function beginEnrol(
  req: Request,
  o: {
    userId: number;
    installId: unknown;
    /** users.credential_version as loaded when the password + code were
     *  checked (checkSecondFactor step 1). The ticket is only issued if it
     *  is still current, and enrol/finish refuses it if it changes later. */
    credentialVersion?: number;
    /** Lot O, SSO account: the Obligate MFA epoch confirmed at the fresh
     *  re-authentication; enrol/finish requires it unchanged and stores it
     *  on the key (user_device_keys.sso_epoch). */
    ssoEpoch?: number | null;
  },
): Promise<{ ok: true; data: DeviceKeyEnrolBeginResponse } | ServiceFailure> {
  if (typeof o.installId !== 'string' || !INSTALL_ID_RE.test(o.installId)) {
    return { ok: false, status: 400, body: { error: 'Validation', details: { installId: ['invalid'] } } };
  }
  const installId = o.installId;
  const pol = await getPolicy();
  const [{ n }] = await db('user_device_keys')
    .where({ user_id: o.userId, status: 'active' })
    .andWhereNot({ install_id: installId })
    .count<{ n: string | number }[]>('id as n');
  if (Number(n) >= DEVICE_KEY_MAX_PER_USER) {
    await audit(req, o.userId, 'device_key.enrol_failed', { reason: 'too_many_keys' });
    return { ok: false, status: 409, body: { error: 'too_many_keys' } };
  }
  const nonce = crypto.randomBytes(32);
  const cv = Number.isSafeInteger(o.credentialVersion) ? Number(o.credentialVersion) : null;
  const ssoEpoch = Number.isSafeInteger(o.ssoEpoch) ? Number(o.ssoEpoch) : null;
  // One statement: the ticket exists only for an active user whose
  // credentials did not change since they were checked, and it records that
  // credential version (and, SSO, the confirmed Obligate MFA epoch).
  const ins = await db.raw(
    `INSERT INTO device_key_challenges
       (user_id, key_id, purpose, session_hash, tenant_id, nonce, action_key, binding_hash, ip, expires_at, credential_version, sso_epoch)
     SELECT u.id, NULL, 'enrol', ?, NULL, ?, ?, NULL, ?, now() + interval '${DEVICE_KEY_ENROL_TTL_SECONDS} seconds', u.credential_version, ?::integer
       FROM users u
      WHERE u.id = ? AND u.is_active AND (?::integer IS NULL OR u.credential_version = ?::integer)
     RETURNING id, FLOOR(EXTRACT(EPOCH FROM expires_at))::bigint AS exp`,
    [sessionHashOf(req), nonce, ENROL_ACTION, ipOf(req), ssoEpoch, o.userId, cv, cv],
  ) as { rows: Array<{ id: string; exp: number | string }> };
  const row = ins.rows[0];
  if (!row) {
    // Credentials changed (or account disabled) while this request ran: the
    // session is about to die anyway (§6.7 hooks) — same answer as then.
    return { ok: false, status: 401, body: { error: 'Authentication required' } };
  }
  await audit(req, o.userId, 'device_key.enrol_begin', { installId, ip: ipOf(req) });
  return {
    ok: true,
    data: {
      ticketId: row.id,
      nonce: b64url(nonce),
      expiresAt: epochOf(row.exp),
      userId: o.userId,
      allowedOrigins: allowedOrigins(),
      requireAttestation: pol.requireAttestation,
    },
  };
}

/** Parsed / validated SPKI: an uncompressed P-256 key, canonical DER. */
export function parseP256Spki(b64: unknown): Buffer | null {
  const der = fromB64(b64, 400);
  if (!der) return null;
  try {
    const k = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (k.asymmetricKeyType !== 'ec' || k.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return null;
    const canonical = k.export({ type: 'spki', format: 'der' }) as Buffer;
    return canonical.equals(der) ? der : null;
  } catch {
    return null;
  }
}

const CHAIN_STORE_MAX = 10;
const CHAIN_ITEM_MAX = 16384;

function storableChain(chain: unknown): string[] | null {
  if (!Array.isArray(chain) || chain.length === 0 || chain.length > CHAIN_STORE_MAX) return null;
  if (!chain.every((c) => typeof c === 'string' && c.length <= CHAIN_ITEM_MAX && /^[A-Za-z0-9+/=]+$/.test(c))) return null;
  return chain as string[];
}

/**
 * enrol/finish (§6.5), steps 1–8. Never answers 401:
 *  1. atomic consumption of the ticket (purpose enrol, same user, same
 *     session, not expired) — else 400 invalid_ticket (a failed finish
 *     burns the ticket: a new begin needs password + a new code again);
 *  2. origin ASCII, normalised and allowed — else 400 origin_mismatch;
 *  3. P-256 SPKI — else 400 bad_key; known fingerprint — 409 already_enrolled;
 *  4. enrolment payload signature — else 400 bad_signature;
 *  5. attestation (§4.3) — else 422 attestation_failed {reason}, or the key
 *     is accepted as 'unverified' when attestation is not required;
 *  6. one transaction: 5-key cap re-checked, keys of the same installId
 *     revoked ('replaced'), insert with the user's credential_version;
 *  7. the current session is bound to the new key;
 *  8. audit device_key.enrolled + e-mail [D13].
 */
export async function finishEnrol(
  req: Request,
  body: unknown,
): Promise<{ ok: true; status: 201; data: DeviceKeyEnrolFinishResponse } | ServiceFailure> {
  const userId = Number(req.session?.userId);
  if (!Number.isSafeInteger(userId) || userId <= 0) return { ok: false, status: 400, body: { error: 'invalid_ticket' } };
  const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  const failAudit = async (reason: string) => { await audit(req, userId, 'device_key.enrol_failed', { reason }); };
  const setResult = async (ticketId: string, result: string) => {
    await db('device_key_challenges').where({ id: ticketId }).update({ result: result.slice(0, 24) });
  };

  const pol = await getPolicy();
  if (!pol.enabled) return { ok: false, status: 403, body: { error: 'device_keys_disabled' } };

  // 1. Ticket.
  if (!isUuid(b.ticketId)) return { ok: false, status: 400, body: { error: 'invalid_ticket' } };
  const ticketId = b.ticketId;
  // Consumed only while the user is active and his credential version is
  // still the one the ticket was issued under.
  const t = await db.raw(
    `UPDATE device_key_challenges c SET consumed_at = now(), result = 'pending'
       FROM users u
      WHERE c.id = ? AND c.purpose = 'enrol' AND c.user_id = ? AND c.session_hash = ?
        AND c.consumed_at IS NULL AND c.expires_at > now()
        AND u.id = c.user_id AND u.is_active
        AND c.credential_version IS NOT NULL AND c.credential_version = u.credential_version
      RETURNING c.nonce, FLOOR(EXTRACT(EPOCH FROM c.expires_at))::bigint AS exp, c.credential_version, c.sso_epoch,
                u.foreign_source, u.foreign_id`,
    [ticketId, userId, sessionHashOf(req)],
  ) as { rows: Array<{
    nonce: unknown; exp: number | string; credential_version: number; sso_epoch: number | null;
    foreign_source: string | null; foreign_id: number | null;
  }> };
  if (t.rows.length === 0) {
    await failAudit('invalid_ticket');
    return { ok: false, status: 400, body: { error: 'invalid_ticket' } };
  }
  const nonce = toBuf(t.rows[0].nonce);
  const exp = epochOf(t.rows[0].exp);
  const ticketCv = Number(t.rows[0].credential_version);

  // 1b. Lot O, SSO account: still supported, and the Obligate MFA epoch is
  //     still the one confirmed at the re-authentication (read uncached, fail
  //     closed). A local ticket never carries an epoch.
  let ssoEpoch: number | null = null;
  if (t.rows[0].foreign_source != null) {
    const ticketEpoch = t.rows[0].sso_epoch == null ? null : Number(t.rows[0].sso_epoch);
    const foreignId = Number(t.rows[0].foreign_id);
    if (t.rows[0].foreign_source !== 'obligate' || !(await ssoSupported())) {
      await setResult(ticketId, 'sso_unsupported');
      return { ok: false, status: 403, body: { error: 'device_keys_sso_unsupported' } };
    }
    if (ticketEpoch == null || !Number.isSafeInteger(foreignId) || foreignId <= 0) {
      await setResult(ticketId, 'invalid_ticket');
      await failAudit('invalid_ticket');
      return { ok: false, status: 400, body: { error: 'invalid_ticket' } };
    }
    const e = await obligateService.getMfaEpoch(foreignId, { fresh: true });
    if (!e) {
      await setResult(ticketId, 'verifier_unavailable');
      return {
        ok: false, status: 503,
        body: { error: 'Two-factor verification is temporarily unavailable', verifierUnavailable: true },
      };
    }
    if (!e.active || e.mfaEpoch !== ticketEpoch) {
      await setResult(ticketId, 'sso_mfa_changed');
      await failAudit('sso_mfa_changed');
      return { ok: false, status: 400, body: { error: 'invalid_ticket' } };
    }
    ssoEpoch = ticketEpoch;
  } else if (t.rows[0].sso_epoch != null) {
    await setResult(ticketId, 'invalid_ticket');
    return { ok: false, status: 400, body: { error: 'invalid_ticket' } };
  }

  // 2. Origin.
  const origins = allowedOrigins();
  if (origins.length === 0) {
    await setResult(ticketId, 'origin_unset');
    return { ok: false, status: 403, body: { error: 'device_keys_origin_unset' } };
  }
  const origin = typeof b.origin === 'string' ? b.origin : '';
  if (!origin || tryNormaliseOrigin(origin) !== origin || !origins.includes(origin)) {
    await setResult(ticketId, 'origin_mismatch');
    await failAudit('origin_mismatch');
    return { ok: false, status: 400, body: { error: 'origin_mismatch' } };
  }

  // 3. Key.
  const spki = parseP256Spki(b.publicKey);
  if (!spki) {
    await setResult(ticketId, 'bad_key');
    await failAudit('bad_key');
    return { ok: false, status: 400, body: { error: 'bad_key' } };
  }
  const fp = spkiFingerprint(spki);
  if (await db('user_device_keys').where({ public_key_fp: fp }).first('id')) {
    await setResult(ticketId, 'already_enrolled');
    return { ok: false, status: 409, body: { error: 'already_enrolled' } };
  }

  // 4. Signature of the enrolment payload.
  const sig = fromB64(b.signature, 200);
  let sigOk = false;
  if (sig) {
    try {
      parseEcdsaSignature(sig);
      const payload = buildPayload({
        purpose: 'enrol', origin, userId, keyRef: enrolKeyRef(spki),
        challenges: [{ challengeId: ticketId, nonce, action: ENROL_ACTION, binding: null, exp }],
      });
      sigOk = crypto.verify('sha256', Buffer.from(payload, 'utf8'),
        { key: crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' }), dsaEncoding: 'der' }, sig);
    } catch { sigOk = false; }
  }
  if (!sigOk) {
    await setResult(ticketId, 'bad_signature');
    await failAudit('bad_signature');
    return { ok: false, status: 400, body: { error: 'bad_signature' } };
  }

  // 5. Attestation.
  const revocation = await attestationStatusStore.get();
  const att: AttestationOutcome = verifyAttestation(b.attestation, spki, nonce, {
    pinnedRootSpkiSha256: PINNED_ROOT_SPKI_SHA256,
    appPackages: appPackages(),
    appSigners: appSigners(),
    releaseSigners: [RELEASE_APP_SIGNER],
    revocation,
    requireRkp: false, // [D5] v1: logged only
  });
  const chain = storableChain(b.attestation);
  let level: DeviceKeySecurityLevel;
  let attestationJson: Record<string, unknown>;
  if (att.ok) {
    level = att.level;
    attestationJson = { verified: true, ...att.summary, chain };
  } else {
    if (pol.requireAttestation) {
      await setResult(ticketId, 'attestation_failed');
      await failAudit(`attestation_failed:${att.reason}`);
      logger.warn({ userId, reason: att.reason, detail: att.detail }, 'device key enrolment: attestation failed');
      return { ok: false, status: 422, body: { error: 'attestation_failed', reason: att.reason } };
    }
    level = 'unverified';
    attestationJson = { verified: false, failure: att.reason, failureDetail: att.detail ?? null, ...att.summary, chain };
  }

  // 6. Transaction: cap, replace, insert.
  const installId = typeof b.installId === 'string' && INSTALL_ID_RE.test(b.installId) ? b.installId : null;
  if (!installId) {
    await setResult(ticketId, 'bad_install_id');
    return { ok: false, status: 400, body: { error: 'Validation', details: { installId: ['invalid'] } } };
  }
  const label = clean(b.label, 120);
  const appVersion = clean(b.appVersion, 32);
  let inserted: { id: string; created_at: Date | string } | null = null;
  let replaced: string[] = [];
  let failure: ServiceFailure | null = null;
  try {
    await db.transaction(async (trx) => {
      const u = await trx.raw(`SELECT credential_version, is_active FROM users WHERE id = ? FOR UPDATE`, [userId]) as {
        rows: Array<{ credential_version: number; is_active: boolean }>;
      };
      const user = u.rows[0];
      // Row locked: a concurrent password / TOTP change either committed
      // before (refused here) or bumps the version after this insert (the
      // key then dies at its first use, 'credentials_changed').
      if (!user || !user.is_active || Number(user.credential_version) !== ticketCv) {
        failure = { ok: false, status: 400, body: { error: 'invalid_ticket' } };
        return;
      }
      const [{ n }] = await trx('user_device_keys')
        .where({ user_id: userId, status: 'active' })
        .andWhereNot({ install_id: installId })
        .count<{ n: string | number }[]>('id as n');
      if (Number(n) >= DEVICE_KEY_MAX_PER_USER) {
        failure = { ok: false, status: 409, body: { error: 'too_many_keys' } };
        return;
      }
      const old = await trx('user_device_keys')
        .where({ user_id: userId, install_id: installId, status: 'active' })
        .select('id') as Array<{ id: string }>;
      replaced = old.map((r) => r.id);
      const [row] = await trx('user_device_keys').insert({
        user_id: userId,
        platform: 'android',
        public_key_spki: spki,
        public_key_fp: fp,
        origin,
        install_id: installId,
        label,
        app_version: appVersion,
        security_level: level,
        attestation: JSON.stringify(attestationJson),
        credential_version: ticketCv,
        sso_epoch: ssoEpoch,
        status: 'active',
      }).returning(['id', 'created_at']) as Array<{ id: string; created_at: Date | string }>;
      inserted = row;
      await trx('device_key_challenges').where({ id: ticketId }).update({ result: 'ok' });
    });
  } catch (err) {
    if ((err as { code?: string })?.code === '23505') {
      await setResult(ticketId, 'already_enrolled');
      return { ok: false, status: 409, body: { error: 'already_enrolled' } };
    }
    throw err;
  }
  if (failure) {
    const f = failure as ServiceFailure;
    await setResult(ticketId, String(f.body.error));
    await failAudit(String(f.body.error));
    return f;
  }
  const created = inserted as unknown as { id: string; created_at: Date | string };
  // The replaced keys go through THE revocation (sessions, audit); the
  // new key is not touched (it is not in the list).
  if (replaced.length > 0) await revoke(replaced, 'replaced', { req, ownerId: userId, byUserId: userId });

  // 7. Bind the current session.
  req.session.deviceKeyId = created.id;

  // 8. Audit + e-mail.
  const summary = att.ok ? att.summary : att.summary;
  await audit(req, userId, 'device_key.enrolled', {
    keyId: created.id,
    label,
    securityLevel: level,
    origin,
    osPatchLevel: summary.osPatchLevel ?? null,
    appVersion,
    rkp: summary.rkp ?? null,
    revocationChecked: summary.revocationCheckedAt ?? null,
    ...(att.ok ? {} : { attestationFailure: att.reason }),
    ...(summary.debugSigner ? { debugSigner: true } : {}),
  });
  notifyEnrolled(userId, { label, origin, ip: ipOf(req) });
  return {
    ok: true,
    status: 201,
    data: { keyId: created.id, label, securityLevel: level, createdAt: new Date(created.created_at).toISOString() },
  };
}

/** [D13] e-mail at each enrolment (fire and forget, if SMTP + address). */
function notifyEnrolled(userId: number, info: { label: string | null; origin: string; ip: string | null }): void {
  void (async () => {
    try {
      const { appConfigService } = await import('../appConfig.service');
      const smtp = await appConfigService.get('otp_smtp_server_id');
      if (!smtp) return;
      const user = await db('users').where({ id: userId }).first('email') as { email: string | null } | undefined;
      if (!user?.email) return;
      const { twoFactorService } = await import('../twoFactor.service');
      await twoFactorService.sendDeviceKeyEnrolledNotice(Number(smtp), user.email, {
        label: info.label, server: info.origin, ip: info.ip, date: new Date(),
      });
    } catch (err) {
      logger.warn({ err, userId }, 'device key enrolment notice not sent');
    }
  })();
}

// ── Periodic tasks (§6.9) ──────────────────────────────────────────────────

/** Hourly: delete challenges expired for more than 7 days. */
export async function sweepChallenges(): Promise<number> {
  return db('device_key_challenges')
    .where('expires_at', '<', db.raw(`now() - interval '${CHALLENGE_RETENTION_DAYS} days'`))
    .delete();
}

/** app_config key: the last time the daily task saw the feature OFF (ISO).
 *  Keys cannot be used while it is off, so that time does not count towards
 *  their 180 days of non-use (§9: disabling keeps the keys). */
export const PAUSED_AT_KEY = 'device_keys_paused_at';

async function markPaused(): Promise<void> {
  await db('app_config').insert({ key: PAUSED_AT_KEY, value: new Date().toISOString() }).onConflict('key').merge();
}

/**
 * Daily: revoke ('stale') keys unused for 180 days [D14], counted from the
 * last use (else the creation), or from the last day the feature was seen
 * off if later: a key unusable because the feature was off is not stale.
 */
export async function revokeStaleKeys(): Promise<number> {
  const row = await db('app_config').where({ key: PAUSED_AT_KEY }).first('value') as { value: string | null } | undefined;
  const paused = row?.value && Number.isFinite(Date.parse(row.value)) ? new Date(row.value).toISOString() : null;
  const rows = await db('user_device_keys')
    .where({ status: 'active' })
    .andWhereRaw(
      `GREATEST(COALESCE(last_used_at, created_at), COALESCE(?::timestamptz, COALESCE(last_used_at, created_at)))
         < now() - interval '${DEVICE_KEY_STALE_DAYS} days'`,
      [paused],
    )
    .select('id') as Array<{ id: string }>;
  return (await revoke(rows.map((r) => r.id), 'stale')).length;
}

/** Daily: refresh the Google status list (no effect when unreachable). */
export async function refreshAttestationStatus(): Promise<boolean> {
  return attestationStatusStore.refresh();
}

/**
 * [D4] after enrolment (daily, after the refresh): revokes ('attestation_revoked')
 * every active verified key whose stored chain serials the CURRENT Google
 * status list marks REVOKED / SUSPENDED (a leaked keybox revoked since). The
 * use-time checks (unusableReason, deadKeyStatus) apply the same list in
 * between. Nothing happens without a list.
 */
export async function revokeKeysWithRevokedAttestation(list: StatusListView | null = attestationStatusStore.current()): Promise<number> {
  if (!list || list.entries.size === 0) return 0;
  const rows = await db('user_device_keys')
    .where({ status: 'active' })
    .whereNot({ security_level: 'unverified' })
    .select('id', 'security_level', 'attestation') as Array<{ id: string; security_level: string; attestation: unknown }>;
  const hits = rows
    .map((r) => ({ id: r.id, serial: revokedAttestationSerial(r.security_level, serialsOf(r.attestation), list) }))
    .filter((h): h is { id: string; serial: string } => h.serial !== null);
  if (hits.length === 0) return 0;
  logger.warn({ keys: hits }, 'device keys: attestation chain revoked by Google since enrolment, keys revoked');
  return (await revoke(hits.map((h) => h.id), 'attestation_revoked')).length;
}

/**
 * The daily tasks (§6.9), only while the feature is on: while it is off no
 * key can be used, so none is swept as stale (the pause is recorded instead,
 * see revokeStaleKeys) and Google is not contacted.
 */
export async function runDailyTasks(): Promise<{
  skipped: boolean; staleRevoked: number; statusRefreshed: boolean; attestationRevoked: number;
}> {
  const pol = await getPolicy();
  if (!pol.enabled) {
    await markPaused().catch((err) => logger.warn({ err }, 'device keys: pause marker not written'));
    return { skipped: true, staleRevoked: 0, statusRefreshed: false, attestationRevoked: 0 };
  }
  const staleRevoked = await revokeStaleKeys().catch((err) => { logger.warn({ err }, 'stale device key sweep failed'); return 0; });
  const statusRefreshed = await refreshAttestationStatus().catch(() => false);
  const attestationRevoked = await revokeKeysWithRevokedAttestation()
    .catch((err) => { logger.warn({ err }, 'device key attestation revocation sweep failed'); return 0; });
  return { skipped: false, staleRevoked, statusRefreshed, attestationRevoked };
}

/** The periodic tasks at once (hourly challenge sweep + the daily tasks). */
export async function sweep(): Promise<{
  challengesDeleted: number; staleRevoked: number; statusRefreshed: boolean; attestationRevoked: number; skipped: boolean;
}> {
  const challengesDeleted = await sweepChallenges().catch((err) => { logger.warn({ err }, 'device key challenge sweep failed'); return 0; });
  const daily = await runDailyTasks();
  return { challengesDeleted, ...daily };
}

// ── Platform settings (§9, [D15]) ──────────────────────────────────────────

/**
 * Writes one device_keys_* platform setting ('true' / 'false'): drops the
 * policy cache, revokes the unverified keys when attestation becomes
 * required ('policy'), records the resume time when the feature is turned
 * back on (stale keys, see revokeStaleKeys), audits `settings.device_keys`.
 * Used by PUT /api/admin/config/:key and by an approved `settings_update`
 * (tenant.manage_settings at the 'restricted' level).
 */
export async function setDeviceKeySetting(
  key: DeviceKeyConfigKey,
  value: 'true' | 'false',
  opts: { byUserId?: number | null; req?: Request; auditTenantId?: number | null; viaApproval?: boolean } = {},
): Promise<{ before: string | null; revoked: number }> {
  if (!Object.prototype.hasOwnProperty.call(DEVICE_KEY_CONFIG_DEFAULTS, key)) throw new Error(`not a device-key setting: ${key}`);
  if (value !== 'true' && value !== 'false') throw new Error(`${key} must be 'true' or 'false'`);
  const beforeRow = await db('app_config').where({ key }).first('value') as { value: string | null } | undefined;
  const before = beforeRow?.value ?? null;
  await db('app_config').insert({ key, value }).onConflict('key').merge();
  invalidatePolicyCache();
  if (key === 'device_keys_enabled' && value === 'true' && (before ?? DEVICE_KEY_CONFIG_DEFAULTS.device_keys_enabled) !== 'true') {
    await markPaused().catch(() => undefined);
  }
  let revoked = 0;
  if (key === 'device_keys_require_attestation' && value === 'true') {
    revoked = await revokeUnverifiedKeys({ byUserId: opts.byUserId ?? null, req: opts.req, auditTenantId: opts.auditTenantId ?? null });
  }
  await audit(opts.req, Number(opts.byUserId) || 0, 'settings.device_keys', {
    key, before, after: value, ...(revoked ? { unverifiedKeysRevoked: revoked } : {}), ...(opts.viaApproval ? { viaApproval: true } : {}),
  }, { tenantId: opts.auditTenantId ?? null, actorId: opts.byUserId ?? null }, { resourceType: 'app_config', resourcePath: key });
  return { before, revoked };
}

/** Everything above, as one object (like the other services). */
export const deviceKeyService = {
  getPolicy, invalidatePolicyCache, allowedOrigins, appPackages, appSigners, ssoSupported, applySsoCredentialsChanged,
  sessionHashOf, bindingTenantOf, bindingKey, requestBinding,
  keyStatusCached, forgetKeyStatus, deadKeyStatus, boundSessionDead, sessionBinding, boundKey, loginKeyFor, bindableKey,
  eligibilityOf, list,
  killSessionsForKey, killSessionsForUser, revoke, revokeAllForUser, revokeUnverifiedKeys,
  issueStepUpChallenge, issueLoginChallenge, parseAssertion, verifyAssertion, assertionThrottled,
  enrolPreconditions, beginEnrol, finishEnrol, parseP256Spki,
  sweepChallenges, revokeStaleKeys, refreshAttestationStatus, revokeKeysWithRevokedAttestation, runDailyTasks, sweep,
  setDeviceKeySetting,
};

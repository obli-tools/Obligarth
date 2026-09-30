import crypto from 'node:crypto';

// ── Device-bound 2FA: signed payload and request binding ───────────────────
//
// docs/mobile/device-bound-2fa.md §4.4 (payload "obli-devkey-v1") and §4.5
// (binding "obli-binding-v2"), frozen shared contract §13.1 items 4 and 5.
// Test vectors V1/V2 and B1..B6: annex A, checked by payload.test.ts and
// binding.test.ts (node --test). The binding is computed by the server only
// (the app copies it), so its version is a server-side matter.
//
// NO project import on purpose: this file is loaded as-is by `node --test`
// (Node 24 strips the types) and mirrored by the Android app
// (DeviceProofPayload.build). Erasable TypeScript only (no enum/namespace).

export const PAYLOAD_VERSION = 'obli-devkey-v1';
export const BINDING_VERSION = 'obli-binding-v2';
/** HKDF `info` of the binding body key (deriveBindingKey). */
export const BINDING_KEY_INFO = 'obli-binding-v2';
/** Minimum length of the binding body key, bytes. */
export const BINDING_KEY_MIN_BYTES = 16;
/** A payload covers 1..50 challenges (bulk step-up, §4.9.4). */
export const MAX_PAYLOAD_CHALLENGES = 50;

export type PayloadPurpose = 'enrol' | 'login' | 'stepup';

export interface PayloadChallenge {
  /** challenges.id (UUID) — for an enrolment, the ticket id. */
  challengeId: string;
  /** 32 random bytes, or their base64url (no padding) form. */
  nonce: Uint8Array | string;
  /** Action key, or null / '-' (login). */
  action: string | null;
  /** Binding hash (64 hex), or null / '-' (login, enrolment). */
  binding: string | null;
  /** expires_at read from the database, unix seconds (floored). */
  exp: number;
}

export interface PayloadInput {
  purpose: PayloadPurpose;
  /** Normalised server origin as the APP knows it (key.origin on the server). */
  origin: string;
  /** Server user id. */
  userId: number;
  /** keyId (UUID), or for an enrolment "spki-sha256:" + hex sha256(SPKI DER). */
  keyRef: string;
  /** In the order of deviceAssertion.challengeIds. */
  challenges: PayloadChallenge[];
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const ACTION_RE = /^[\x21-\x7e]{1,120}$/; // printable ASCII, no space (action keys: "device.delete")

/** True for a lowercase canonical UUID (Postgres `uuid` output form). */
export function isUuid(v: unknown): v is string {
  return typeof v === 'string' && UUID_RE.test(v);
}

function noNewline(field: string, v: string): string {
  if (v.includes('\n') || v.includes('\r')) throw new Error(`device-key payload: ${field} contains a line break`);
  return v;
}

/** base64url without padding. */
export function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Strict base64url (no padding) → bytes, or null. */
export function fromB64url(s: unknown): Buffer | null {
  if (typeof s !== 'string' || s.length === 0 || !B64URL_RE.test(s)) return null;
  const buf = Buffer.from(s, 'base64url');
  return buf.toString('base64url') === s ? buf : null;
}

/** Strict standard base64 (padding required when needed) → bytes, or null. */
export function fromB64(s: unknown, maxChars = 1 << 20): Buffer | null {
  if (typeof s !== 'string' || s.length === 0 || s.length > maxChars) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length % 4 !== 0) return null;
  const buf = Buffer.from(s, 'base64');
  return buf.toString('base64') === s ? buf : null;
}

export function sha256hex(data: string | Uint8Array): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** hex sha256 of the SPKI DER = user_device_keys.public_key_fp. */
export function spkiFingerprint(spkiDer: Uint8Array): string {
  return sha256hex(spkiDer);
}

/** keyRef of an enrolment payload ("spki-sha256:" + fingerprint). */
export function enrolKeyRef(spkiDer: Uint8Array): string {
  return 'spki-sha256:' + spkiFingerprint(spkiDer);
}

/**
 * Normalised origin (§4.4): scheme and host lowercase, port only when it is
 * not the scheme's default, no path, no trailing slash. http/https only.
 * Non-ASCII (IDN) hosts are REFUSED: the app's Origins.of keeps Unicode
 * letters while `new URL` converts to punycode — both sides would not
 * produce the same string. Throws on anything else.
 */
export function normaliseOrigin(input: string): string {
  if (typeof input !== 'string' || input.length === 0 || input.length > 255) throw new Error('invalid origin');
  // eslint-disable-next-line no-control-regex
  if (/[^\x21-\x7e]/.test(input)) throw new Error('invalid origin: non-ASCII or blank characters');
  let u: URL;
  try { u = new URL(input); } catch { throw new Error('invalid origin'); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('invalid origin: http(s) only');
  if (u.username || u.password) throw new Error('invalid origin: credentials');
  if (!u.hostname) throw new Error('invalid origin: no host');
  const origin = u.origin;
  // eslint-disable-next-line no-control-regex
  if (origin === 'null' || /[^\x21-\x7e]/.test(origin)) throw new Error('invalid origin');
  return origin;
}

/** normaliseOrigin, or null instead of throwing. */
export function tryNormaliseOrigin(input: unknown): string | null {
  try { return normaliseOrigin(String(input ?? '')); } catch { return null; }
}

/**
 * The canonical payload (§4.4): UTF-8, '\n'-separated, fixed order, no
 * trailing newline. Throws on a line break in any field, on a count outside
 * 1..50, on an origin that is not ASCII / not normalised, or on a malformed
 * field — the server never signs nor verifies something it cannot rebuild
 * exactly.
 */
export function buildPayload(p: PayloadInput): string {
  if (p.purpose !== 'enrol' && p.purpose !== 'login' && p.purpose !== 'stepup') {
    throw new Error('device-key payload: bad purpose');
  }
  noNewline('origin', String(p.origin));
  let origin: string;
  try { origin = normaliseOrigin(p.origin); } catch { throw new Error('device-key payload: bad origin'); }
  if (origin !== p.origin) throw new Error('device-key payload: origin not normalised');
  if (!Number.isSafeInteger(p.userId) || p.userId <= 0) throw new Error('device-key payload: bad user id');
  noNewline('key', String(p.keyRef));
  if (!(isUuid(p.keyRef) || /^spki-sha256:[0-9a-f]{64}$/.test(p.keyRef))) throw new Error('device-key payload: bad key');
  const list = Array.isArray(p.challenges) ? p.challenges : [];
  if (list.length < 1 || list.length > MAX_PAYLOAD_CHALLENGES) throw new Error('device-key payload: count out of 1..50');

  const lines: string[] = [
    PAYLOAD_VERSION,
    `purpose:${p.purpose}`,
    `origin:${origin}`,
    `user:${p.userId}`,
    `key:${p.keyRef}`,
    `count:${list.length}`,
  ];
  for (const c of list) {
    noNewline('challenge', String(c.challengeId));
    if (!isUuid(c.challengeId)) throw new Error('device-key payload: bad challenge id');
    let nonce: string;
    if (typeof c.nonce === 'string') {
      noNewline('nonce', c.nonce);
      if (!fromB64url(c.nonce)) throw new Error('device-key payload: bad nonce');
      nonce = c.nonce;
    } else {
      if (!(c.nonce instanceof Uint8Array) || c.nonce.length === 0) throw new Error('device-key payload: bad nonce');
      nonce = b64url(c.nonce);
    }
    const action = c.action == null || c.action === '' ? '-' : noNewline('action', String(c.action));
    if (action !== '-' && !ACTION_RE.test(action)) throw new Error('device-key payload: bad action');
    const binding = c.binding == null || c.binding === '' ? '-' : noNewline('binding', String(c.binding));
    if (binding !== '-' && !HEX64_RE.test(binding)) throw new Error('device-key payload: bad binding');
    if (!Number.isSafeInteger(c.exp) || c.exp <= 0) throw new Error('device-key payload: bad exp');
    lines.push(`challenge:${c.challengeId}`, `nonce:${nonce}`, `action:${action}`, `binding:${binding}`, `exp:${c.exp}`);
  }
  return lines.join('\n');
}

// ── Request binding (§4.5) ─────────────────────────────────────────────────

/**
 * Canonical JSON: object keys sorted recursively (code-unit order), array
 * order kept, `undefined` members ignored (in arrays they become null, like
 * JSON.stringify), `toJSON()` honoured, JSON.stringify for scalars.
 * A top-level undefined renders "null".
 */
export function canonicalJson(value: unknown): string {
  return canon(value, 0) ?? 'null';
}

function canon(value: unknown, depth: number): string | undefined {
  if (depth > 64) throw new Error('canonicalJson: nesting too deep');
  if (value !== null && typeof value === 'object' && typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    value = (value as { toJSON: () => unknown }).toJSON();
  }
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol') return undefined;
  if (typeof value === 'bigint') throw new Error('canonicalJson: bigint');
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canon(v, depth + 1) ?? 'null').join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const parts: string[] = [];
  for (const k of Object.keys(obj).sort()) {
    const v = canon(obj[k], depth + 1);
    if (v === undefined) continue;
    parts.push(JSON.stringify(k) + ':' + v);
  }
  return '{' + parts.join(',') + '}';
}

/** Device ids of a binding: numeric sort, no duplicates, integers only. */
export function sortedUniqueDeviceIds(ids: ReadonlyArray<unknown> | null | undefined): number[] {
  const out = new Set<number>();
  for (const raw of ids ?? []) {
    const n = typeof raw === 'number' ? raw : typeof raw === 'string' && /^-?\d+$/.test(raw) ? Number(raw) : NaN;
    if (Number.isSafeInteger(n)) out.add(n);
  }
  return [...out].sort((a, b) => a - b);
}

export interface BindingInput {
  /** HTTP method (uppercased here). */
  method: string;
  /** req.originalUrl: path + query exactly as received. */
  originalUrl: string;
  /** req.tenantId ?? req.session.currentTenantId; null → "-". */
  tenantId: number | null | undefined;
  actionKey: string;
  deviceIds?: ReadonlyArray<unknown> | null;
  /** req.body WITHOUT the proofs (removed by captureStepUpProof, P5). */
  body: unknown;
}

/**
 * The binding body key (§4.5, v2): HKDF-SHA256 of a server secret that is
 * NOT stored in the database (DEVICE_KEY_BINDING_SECRET, else
 * SESSION_SECRET). v1 hashed the body with a plain sha256: the body of some
 * bound requests carries a password (PUT /api/users/:id/password, POST
 * /api/users, PUT /api/profile/password), so the binding_hash column (and the
 * 401 challenge) was a fast, unsalted hash of that password, guessable
 * offline from a database dump. Keyed, it is not.
 */
export function deriveBindingKey(secret: string | Uint8Array): Buffer {
  const ikm = typeof secret === 'string' ? Buffer.from(secret, 'utf8') : Buffer.from(secret);
  if (ikm.length === 0) throw new Error('device-key binding: empty secret');
  return Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), BINDING_KEY_INFO, 32));
}

function bodyDigest(body: unknown, bodyKey: Uint8Array): string {
  if (!(bodyKey instanceof Uint8Array) || bodyKey.length < BINDING_KEY_MIN_BYTES) {
    throw new Error('device-key binding: body key missing or too short');
  }
  return crypto.createHmac('sha256', bodyKey).update(canonicalJson(body), 'utf8').digest('hex');
}

/** The binding preimage (exposed for the tests and for investigation). The
 *  last line is HMAC-SHA256(bodyKey, canonicalJson(body)), never a plain hash. */
export function bindingPreimage(b: BindingInput, bodyKey: Uint8Array): string {
  const method = String(b.method || '').toUpperCase();
  const tenant = b.tenantId == null ? '-' : String(b.tenantId);
  for (const [name, v] of [['method', method], ['url', String(b.originalUrl)], ['tenant', tenant], ['action', String(b.actionKey)]] as const) {
    noNewline(name, v);
  }
  return BINDING_VERSION + '\n'
    + method + '\n'
    + String(b.originalUrl) + '\n'
    + tenant + '\n'
    + String(b.actionKey) + '\n'
    + sortedUniqueDeviceIds(b.deviceIds).join(',') + '\n'
    + bodyDigest(b.body, bodyKey);
}

/** binding = sha256hex(preimage) (§4.5). Server only: the app copies it. */
export function computeBinding(b: BindingInput, bodyKey: Uint8Array): string {
  return sha256hex(bindingPreimage(b, bodyKey));
}

import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

// =============================================================================
// Enrollment secrets (docs: integration-apple-edge §10.3, §10.5): every one is
// stored hashed (SHA-256, hexadecimal) and shown once; a displayable prefix
// tells them apart in the console. Never logged.
//   obe_  link of an OTA enrollment (32 random bytes, base64url: 43 characters)
//   obn_  single-use download nonce of a profile (10 minutes)
//   oba_  single-use bearer of an account-driven enrollment (15 minutes)
//   invitation code: 10 characters of the key's alphabet, shown xxxxx-xxxxx,
//         hashed with the tenant's uuid: obi:<tenants.uuid>:<code>
// =============================================================================

export const LINK_PREFIX = 'obe_';
export const NONCE_PREFIX = 'obn_';
export const ACCESS_PREFIX = 'oba_';
export const INVITATION_PREFIX = 'obi_';

/** The alphabet of the MDM keys and of the invitation codes (no 0, 1, l, o). */
export const CODE_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';
export const CODE_LENGTH = 10;

const SECRET_RE = (prefix: string): RegExp => new RegExp(`^${prefix}[A-Za-z0-9_-]{43}$`);
const LINK_RE = SECRET_RE(LINK_PREFIX);
const NONCE_RE = SECRET_RE(NONCE_PREFIX);
const ACCESS_RE = SECRET_RE(ACCESS_PREFIX);

export const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

export interface NewSecret {
  /** The secret itself: shown once, never stored. */
  value: string;
  hash: string;
  /** 12 characters: the prefix and the first 8 characters. */
  prefix: string;
}

function newSecret(prefix: string): NewSecret {
  const value = `${prefix}${randomBytes(32).toString('base64url')}`;
  return { value, hash: sha256Hex(value), prefix: value.slice(0, 12) };
}

export const newLinkToken = (): NewSecret => newSecret(LINK_PREFIX);
export const newNonce = (): NewSecret => newSecret(NONCE_PREFIX);
export const newAccessToken = (): NewSecret => newSecret(ACCESS_PREFIX);

export const isLinkToken = (v: unknown): v is string => typeof v === 'string' && LINK_RE.test(v);
export const isNonce = (v: unknown): v is string => typeof v === 'string' && NONCE_RE.test(v);
export const isAccessToken = (v: unknown): v is string => typeof v === 'string' && ACCESS_RE.test(v);

/** A new invitation code: 10 characters of the alphabet, uniformly drawn. */
export function newInvitationCode(): string {
  let out = '';
  for (let i = 0; i < CODE_LENGTH; i++) out += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return out;
}

/** The code as shown to the administrator: xxxxx-xxxxx. */
export const formatInvitationCode = (code: string): string => `${code.slice(0, 5)}-${code.slice(5)}`;

/** A code as typed by an employee (spaces, dashes, case): its 10 characters, or null when it cannot be one. */
export function normalizeInvitationCode(typed: unknown): string | null {
  if (typeof typed !== 'string' || typed.length > 40) return null;
  const c = typed.toLowerCase().replace(/[\s-]/g, '');
  if (c.length !== CODE_LENGTH) return null;
  for (const ch of c) if (!CODE_ALPHABET.includes(ch)) return null;
  return c;
}

/** The stored hash of an invitation code, bound to its tenant. */
export const invitationHash = (tenantUuid: string, code: string): string => sha256Hex(`obi:${String(tenantUuid).toLowerCase()}:${code}`);

/** The displayable prefix of an invitation: obi_ and two characters of the code. */
export const invitationPrefix = (code: string): string => `${INVITATION_PREFIX}${code.slice(0, 2)}`;

/** Constant-time comparison of two hexadecimal hashes. */
export function sameHash(a: string, b: string): boolean {
  const x = Buffer.from(String(a), 'utf8');
  const y = Buffer.from(String(b), 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

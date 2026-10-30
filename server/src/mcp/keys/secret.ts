import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { MCP_KEY_PREFIX, MCP_KEY_RE } from '@obligarth/shared';

// =============================================================================
// The secret of a personal access key (docs: specs mcp-server §1.1), without
// any database: obg_<publicId>_<secret>, publicId 12 characters [a-z0-9] (the
// lookup key), secret 32 random bytes in base64url. Only sha256(token) is
// stored; the clear token is returned once by the creation and never logged.
// =============================================================================

const ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** A new public id: 12 characters drawn uniformly from [a-z0-9]. */
export function newPublicId(): string {
  let out = '';
  for (let i = 0; i < 12; i++) out += ALPHABET[randomInt(ALPHABET.length)];
  return out;
}

/** A new token and what is stored of it. */
export function newToken(): { publicId: string; token: string; sha256: string } {
  const publicId = newPublicId();
  const token = `${MCP_KEY_PREFIX}${publicId}_${randomBytes(32).toString('base64url')}`;
  return { publicId, token, sha256: hashToken(token) };
}

/** The public id of a well-formed token, or null (malformed). */
export function parseToken(token: unknown): { publicId: string } | null {
  if (typeof token !== 'string' || token.length > 80) return null;
  const m = MCP_KEY_RE.exec(token);
  return m ? { publicId: m[1] } : null;
}

/** sha256 of the full token, as hex (the stored form). */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** Constant-time comparison of a token with a stored digest (two 32-byte digests). */
export function tokenMatches(token: string, storedSha256: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(storedSha256)) return false;
  const a = createHash('sha256').update(token, 'utf8').digest();
  const b = Buffer.from(storedSha256, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * The Bearer token of an Authorization header, or null: only `Bearer <token>`, the scheme matched without regard to
 * case (RFC 7235 §2.1, RFC 6750), nothing else is accepted.
 */
export function bearerOf(header: string | string[] | undefined): string | null {
  if (typeof header !== 'string') return null;
  const m = /^bearer\s+([^\s]+)$/i.exec(header.trim());
  return m ? m[1] : null;
}

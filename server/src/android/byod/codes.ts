// Codes of the Android BYOD invitations (lot AN-F1, section 10.5), in the form of the invitation codes of the device
// surface of lot C (apple/enrollment/tokens.ts on main: the same alphabet, the same length and display, so that an
// employee types an Android code as an Apple one): 10 characters of the alphabet of the MDM keys (no 0, 1, l, o),
// shown xxxxx-xxxxx once to the administrator, stored hashed and bound to the tenant. The hash domain is Android's
// ('oai:'), distinct from Apple's ('obi:'): a code of one family is never a code of the other. Never logged. Pure.
import { createHash, randomInt, timingSafeEqual } from 'node:crypto';

/** The alphabet of the MDM keys and of the invitation codes (no 0, 1, l, o). */
export const CODE_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';
export const CODE_LENGTH = 10;
export const ANDROID_INVITATION_PREFIX = 'oai_';

/** A new invitation code: 10 characters of the alphabet, uniformly drawn (50 bits). */
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

/** The stored hash of an Android invitation code, bound to its tenant. */
export const invitationHash = (tenantUuid: string, code: string): string =>
  createHash('sha256').update(`oai:${String(tenantUuid).toLowerCase()}:${code}`, 'utf8').digest('hex');

/** The displayable prefix of an invitation: oai_ and two characters of the code. */
export const invitationPrefix = (code: string): string => `${ANDROID_INVITATION_PREFIX}${code.slice(0, 2)}`;

/** Constant-time comparison of two hexadecimal hashes. */
export function sameHash(a: string, b: string): boolean {
  const x = Buffer.from(String(a), 'utf8');
  const y = Buffer.from(String(b), 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

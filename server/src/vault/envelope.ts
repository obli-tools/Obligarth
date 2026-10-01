// Envelope format of the vault, shared with apple-edge (internal/crypto/envelope):
// AES-256-GCM, 96-bit random IV, 128-bit tag,
//   v1:<kid>:<iv>:<ct>:<tag>          (base64url, no padding)
// kid = the DEK id for a secret, the KEK id for a wrapped DEK. The AAD binds a
// ciphertext to its namespace, table, column, row and tenant
// (docs: coffre-secrets §3.2 to §3.4, §5.2).
//
// No database import, and only what Node's native type stripping runs (no
// enum, no parameter property, type-only imports marked as such): the unit
// tests run under `node --test`, like the device-key tests.
//
// Errors carry a code only: never a value, a ciphertext or key material.
import crypto from 'node:crypto';

export const ENVELOPE_VERSION = 'v1';
/** AES-256: KEKs and DEKs are 32 bytes. */
export const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const NO_TENANT = '-';
const B64URL_PART = /^[A-Za-z0-9_-]*$/;
const AAD_PART = /^[A-Za-z0-9_.-]+$/;
/** Whitespace trimmed around a KEK: ASCII only, a subset of what Go's
 *  strings.TrimSpace removes (a byte-order mark is refused, as in Go). */
const KEK_TRIM = /^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g;

/** Logical namespace of the server's AADs (coffre-secrets V3): it never
 *  follows the physical schema. apple-edge uses "apple_edge". Re-exported by
 *  the vault API. */
export const VAULT_NAMESPACE = 'obligarth';

export type EnvelopeErrorCode = 'format' | 'key_id_mismatch' | 'decrypt_failed' | 'invalid_key' | 'invalid_aad';

export class EnvelopeError extends Error {
  readonly code: EnvelopeErrorCode;
  constructor(code: EnvelopeErrorCode) {
    super(`envelope: ${code}`);              // never a value, never a ciphertext
    this.code = code;
    this.name = 'EnvelopeError';
  }
}

/** "<namespace>.<table>:<column>:<pk>:<tenant or ->" (apple-edge: envelope.AAD).
 *  Unlike Go, an empty component or one holding ':' is refused. */
export function aad(namespaceTable: string, column: string, pk: string, tenant: string | null): Buffer {
  const t = tenant ?? NO_TENANT;
  for (const part of [namespaceTable, column, pk, t]) {
    if (typeof part !== 'string' || !AAD_PART.test(part)) throw new EnvelopeError('invalid_aad');
  }
  return Buffer.from(`${namespaceTable}:${column}:${pk}:${t}`, 'utf8');
}

/** 32 random bytes in a buffer of their own (apple-edge: envelope.NewKey). */
export function newKey(): Buffer {
  const key = Buffer.alloc(KEY_BYTES);
  crypto.randomFillSync(key);
  return key;
}

export function seal(key: Buffer, kid: string, aadBytes: Buffer, plaintext: Buffer): string {
  return sealWithIv(key, kid, crypto.randomBytes(IV_BYTES), aadBytes, plaintext);
}

/** Fixed IV: test vectors only, never called by production code. */
export function sealWithIv(key: Buffer, kid: string, iv: Buffer, aadBytes: Buffer, plaintext: Buffer): string {
  if (key.length !== KEY_BYTES) throw new EnvelopeError('invalid_key');
  if (!kid || kid.includes(':') || iv.length !== IV_BYTES) throw new EnvelopeError('format');
  if (aadBytes.length === 0) throw new EnvelopeError('invalid_aad');   // an AAD always names a place
  const c = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  c.setAAD(aadBytes);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return [ENVELOPE_VERSION, kid, iv.toString('base64url'), ct.toString('base64url'),
    c.getAuthTag().toString('base64url')].join(':');
}

/** The key id of a sealed value, without opening it (apple-edge: envelope.KeyID). */
export function keyIdOf(sealed: string): string {
  if (typeof sealed !== 'string') throw new EnvelopeError('format');
  const parts = sealed.split(':');
  if (parts.length !== 5 || parts[0] !== ENVELOPE_VERSION || !parts[1]) throw new EnvelopeError('format');
  return parts[1];
}

/** Decodes one base64url component, strictly: Node's decoder silently skips
 *  invalid characters and ignores non-zero trailing bits; both are refused,
 *  so that a sealed value has a single spelling. */
function decodePart(part: string): Buffer {
  if (!B64URL_PART.test(part)) throw new EnvelopeError('format');
  const bytes = Buffer.from(part, 'base64url');
  if (bytes.toString('base64url') !== part) throw new EnvelopeError('format');
  return bytes;
}

/** Opens a sealed value; the returned buffer is the caller's (fill(0) once used). */
export function open(key: Buffer, kid: string, aadBytes: Buffer, sealed: string): Buffer {
  if (typeof sealed !== 'string') throw new EnvelopeError('format');
  const parts = sealed.split(':');
  if (parts.length !== 5 || parts[0] !== ENVELOPE_VERSION) throw new EnvelopeError('format');
  if (parts[1] !== kid) throw new EnvelopeError('key_id_mismatch');
  const iv = decodePart(parts[2]);
  const ct = decodePart(parts[3]);
  const tag = decodePart(parts[4]);
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new EnvelopeError('format');
  if (key.length !== KEY_BYTES) throw new EnvelopeError('invalid_key');
  if (aadBytes.length === 0) throw new EnvelopeError('invalid_aad');
  // authTagLength: without it, Node accepts truncated (4- or 8-byte) tags.
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  d.setAAD(aadBytes);
  d.setAuthTag(tag);
  // GCM hands out the plaintext before final() checks the tag: the
  // intermediate buffer is zeroed whatever the outcome.
  let head: Buffer | null = null;
  try {
    head = d.update(ct);
    const tail = d.final();
    const out = Buffer.alloc(head.length + tail.length);   // own buffer, never a slice of Node's pool
    head.copy(out, 0);
    tail.copy(out, head.length);
    return out;
  } catch {
    throw new EnvelopeError('decrypt_failed');
  } finally {
    head?.fill(0);
  }
}

/** First 16 hex characters of SHA-256 of the raw key (apple-edge: KEK.ID). */
export function kekIdOf(raw: Buffer): string {
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

/** A 32-byte KEK in base64: standard or URL alphabet (not mixed), padded or
 *  not. Everything accepted here is accepted by apple-edge's ParseKEK with the
 *  same kek_id; the padding, when present, completes the last 4-character
 *  group. The returned key is the caller's (fill(0) once used). */
export function parseKek(text: string): { id: string; key: Buffer } {
  if (typeof text !== 'string') throw new EnvelopeError('invalid_key');
  const t = text.replace(KEK_TRIM, '');
  const std = /^[A-Za-z0-9+/]+={0,2}$/.test(t);
  const url = /^[A-Za-z0-9_-]+={0,2}$/.test(t);
  if ((!std && !url) || (t.endsWith('=') && t.length % 4 !== 0)) throw new EnvelopeError('invalid_key');
  const decoded = Buffer.from(t, std ? 'base64' : 'base64url');
  if (decoded.length !== KEY_BYTES) { decoded.fill(0); throw new EnvelopeError('invalid_key'); }
  const key = Buffer.alloc(KEY_BYTES);      // own buffer, never a slice of Node's pool
  decoded.copy(key);
  decoded.fill(0);
  return { id: kekIdOf(key), key };
}

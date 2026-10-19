import { createHash, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';

// =============================================================================
// Signatures of the agent surface (docs: agent-pont-android §4.2, §4.3, §4.10):
// the canonical strings of a request (OBL-AGENT-1, signed by the agent's key
// of the Keystore) and of a response (OBL-SERVER-2, signed by the instance
// key), ECDSA P-256 / SHA-256, DER, base64url without padding. No database
// import: the unit tests load this module alone.
// =============================================================================

/** SHA-256 of an empty body. */
export const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** DER prefix of an EC P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1, uncompressed point). */
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

export const sha256Hex = (data: Buffer | string): string => createHash('sha256').update(data).digest('hex');

export const b64url = (buf: Buffer): string => buf.toString('base64url');

/** Strict base64url (no padding, no other character); null otherwise. */
export function fromB64url(text: unknown, maxBytes = 4096): Buffer | null {
  if (typeof text !== 'string' || text.length === 0 || text.length > Math.ceil((maxBytes * 4) / 3) + 4) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) return null;
  const buf = Buffer.from(text, 'base64url');
  return buf.toString('base64url') === text ? buf : null;
}

/** The canonical string of a request (§4.2): no final line feed. */
export function requestString(r: { method: string; path: string; agentId: string; seq: number | bigint | string; ts: number | string; bodySha256: string }): string {
  return ['OBL-AGENT-1', r.method.toUpperCase(), r.path, r.agentId, String(r.seq), String(r.ts), r.bodySha256].join('\n');
}

/** The canonical string of a response (§4.3, RC-1). */
export function responseString(r: { status: number; agentId: string; seq: number | bigint | string; requestSha256: string; responseSha256: string }): string {
  return ['OBL-SERVER-2', String(r.status), r.agentId, String(r.seq), r.requestSha256, r.responseSha256].join('\n');
}

/** An EC P-256 public key from its SPKI DER, or null (any other key, any other encoding: badKey). */
export function p256PublicKey(spki: Buffer): KeyObject | null {
  if (spki.length !== 91 || !spki.subarray(0, P256_SPKI_PREFIX.length).equals(P256_SPKI_PREFIX)) return null;
  try {
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return null;
    // The point must be on the curve: createPublicKey checks it; re-export must give the same bytes.
    const again = key.export({ format: 'der', type: 'spki' }) as Buffer;
    return again.equals(spki) ? key : null;
  } catch {
    return null;
  }
}

/** Verifies a DER ECDSA signature (base64url) of `message` (UTF-8); false on any malformation. */
export function verifySignature(key: KeyObject, message: string, signatureB64url: unknown): boolean {
  const sig = fromB64url(signatureB64url, 80);
  if (!sig || sig.length < 8 || sig.length > 72 || sig[0] !== 0x30) return false;
  try {
    return verify('sha256', Buffer.from(message, 'utf8'), { key, dsaEncoding: 'der' }, sig);
  } catch {
    return false;
  }
}

/** Signs `message` (UTF-8) with an EC private key: DER, base64url without padding. */
export function signMessage(key: KeyObject, message: string): string {
  return b64url(sign('sha256', Buffer.from(message, 'utf8'), { key, dsaEncoding: 'der' }));
}

/** 16 first hex characters of SHA-256(SPKI DER): the keyId of the instance key (§4.3). */
export const keyIdOf = (spki: Buffer): string => sha256Hex(spki).slice(0, 16);

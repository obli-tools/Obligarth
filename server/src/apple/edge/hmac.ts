import { createHmac, timingSafeEqual } from 'node:crypto';

// =============================================================================
// HMAC of the DDM relay between apple-edge and the brain (docs: apple-edge
// §5.8; integration-apple-edge §9.5, annex C.1): X-Edge-Timestamp (Unix
// seconds) and X-Edge-Signature = "v1=" + base64(HMAC-SHA256(key,
// timestamp "." body)), in both directions, within ±60 s. The key file holds
// base64 (standard or URL, padded or not) of 32 bytes at least, like
// apple-edge's ParseKey. Self-contained: the unit tests run under node --test.
// =============================================================================

export const HEADER_TIMESTAMP = 'X-Edge-Timestamp';
export const HEADER_SIGNATURE = 'X-Edge-Signature';
export const SIGNATURE_WINDOW_SECONDS = 60;
export const MIN_KEY_BYTES = 32;
const VERSION = 'v1=';

/** Decodes a key file's content; throws an Error whose message never repeats the content. */
export function parseHmacKey(text: string): Buffer {
  const t = String(text ?? '').trim();
  const forms: Array<[RegExp, (s: string) => boolean, BufferEncoding]> = [
    [/^[A-Za-z0-9+/]+={0,2}$/, (s) => s.length % 4 === 0, 'base64'],     // standard, padded
    [/^[A-Za-z0-9+/]+$/, (s) => s.length % 4 !== 1, 'base64'],           // standard, raw
    [/^[A-Za-z0-9_-]+={0,2}$/, (s) => s.length % 4 === 0, 'base64url'],  // URL, padded
    [/^[A-Za-z0-9_-]+$/, (s) => s.length % 4 !== 1, 'base64url'],        // URL, raw
  ];
  for (const [re, lengthOk, enc] of forms) {
    if (!re.test(t) || !lengthOk(t)) continue;
    const raw = Buffer.from(t.replace(/=+$/, ''), enc);
    if (raw.length < MIN_KEY_BYTES) throw new Error(`the DDM relay key must decode to ${MIN_KEY_BYTES} bytes at least`);
    return raw;
  }
  throw new Error('the DDM relay key is not valid base64');
}

/** The X-Edge-Signature of `body` at `timestamp` (Unix seconds, as a string). */
export function signRelay(key: Buffer, timestamp: string, body: Buffer | string): string {
  const m = createHmac('sha256', key);
  m.update(timestamp);
  m.update('.');
  m.update(typeof body === 'string' ? Buffer.from(body, 'utf8') : body);
  return VERSION + m.digest('base64');
}

/** Checks the timestamp (within ±60 s of `nowSeconds`) and the signature, against the current key and the
 *  next one during a rotation; constant-time comparison. */
export function verifyRelay(keys: readonly Buffer[], timestamp: string, signature: string, body: Buffer | string,
  nowSeconds = Math.floor(Date.now() / 1000)): boolean {
  if (!/^[0-9]{1,12}$/.test(String(timestamp ?? ''))) return false;
  const ts = Number(timestamp);
  if (Math.abs(nowSeconds - ts) > SIGNATURE_WINDOW_SECONDS) return false;
  const given = Buffer.from(String(signature ?? ''), 'utf8');
  let ok = false;
  for (const key of keys) {
    const expected = Buffer.from(signRelay(key, timestamp, body), 'utf8');
    if (expected.length === given.length && timingSafeEqual(expected, given)) ok = true;
  }
  return ok;
}

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

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

// Signature v2 of a response (review F100), bound to its request. apple-edge sends a random nonce in
// X-Edge-Nonce; the brain keeps X-Edge-Signature (v1) unchanged and ADDS X-Edge-Response-Signature = "v2=" +
// base64(HMAC-SHA256(key, label LF response ts LF HTTP status LF request ts LF nonce LF hex(sha256(request body))
// LF hex(sha256(response body)))). An apple-edge of an older version ignores the new header and keeps checking
// v1; a newer one checks v2 when present and only falls back to v1 when it is absent (rolling update). Same
// vector as apple-edge's TestResponseSignatureV2Vector (ddm/relay_test.go).
export const HEADER_NONCE = 'X-Edge-Nonce';
export const HEADER_RESPONSE_SIGNATURE = 'X-Edge-Response-Signature';
const RESPONSE_V2_VERSION = 'v2=';
const RESPONSE_V2_LABEL = 'obligarth-ddm-response-v2';
/** A nonce of apple-edge (22 base64url characters today); anything else is signed as an empty nonce. */
const NONCE_RE = /^[A-Za-z0-9_-]{1,128}$/;

/** The nonce of a request as the v2 signature covers it: '' when absent or malformed. */
export function relayNonce(value: unknown): string {
  const v = typeof value === 'string' ? value : '';
  return NONCE_RE.test(v) ? v : '';
}

const sha256Hex = (b: Buffer | string): string =>
  createHash('sha256').update(typeof b === 'string' ? Buffer.from(b, 'utf8') : b).digest('hex');

export interface ResponseV2Input {
  responseTimestamp: string;
  status: number;
  requestTimestamp: string;
  nonce: string;
  requestBody: Buffer | string;
  responseBody: Buffer | string;
}

/** The X-Edge-Response-Signature (v2) of a response to the request it answers. */
export function signRelayResponseV2(key: Buffer, i: ResponseV2Input): string {
  const content = [RESPONSE_V2_LABEL, i.responseTimestamp, String(i.status), i.requestTimestamp, i.nonce,
    sha256Hex(i.requestBody), sha256Hex(i.responseBody)].join('\n');
  return RESPONSE_V2_VERSION + createHmac('sha256', key).update(content, 'utf8').digest('base64');
}

/** The request an answer is bound to (v2 response signature). */
export interface SignedRequest { timestamp: string; nonce: string; body: Buffer }

/**
 * The signature headers of a relay answer: v1 (unchanged) and v2, bound to the request.
 * Kept here, free of database imports, so the unit tests can load it without the server's runtime.
 */
export function answerSignatureHeaders(key: Buffer, request: SignedRequest, status: number, body: Buffer,
  nowSeconds = Math.floor(Date.now() / 1000)): Record<string, string> {
  const ts = String(nowSeconds);
  return {
    [HEADER_TIMESTAMP]: ts,
    [HEADER_SIGNATURE]: signRelay(key, ts, body),
    [HEADER_RESPONSE_SIGNATURE]: signRelayResponseV2(key, {
      responseTimestamp: ts, status, requestTimestamp: request.timestamp, nonce: request.nonce,
      requestBody: request.body, responseBody: body,
    }),
  };
}

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

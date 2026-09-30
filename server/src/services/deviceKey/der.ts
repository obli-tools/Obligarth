// ── Minimal, tolerant DER reader (device-bound 2FA, §4.3) ──────────────────
//
// docs/mobile/device-bound-2fa.md §4.3 "Bibliothèque : aucune": a hand-written
// reader limited to what the Android key attestation needs (TLV, OID,
// INTEGER, ENUMERATED, BOOLEAN, NULL, OCTET STRING, SET/SEQUENCE, explicit
// context tags incl. the high-tag-number form used by KeyMint tags such as
// [709]), plus the X.509 extension walk (TBSCertificate) and the ECDSA
// signature rules. X.509 chains and signatures themselves go through Node's
// crypto.X509Certificate.
//
// "Tolerant" means: the AuthorizationList tags may come in any order (some
// KeyMint versions emit them out of order). It does NOT mean BER: lengths
// must be definite and minimal, nothing may trail a structure, and every
// read is bounds-checked. Anything else throws DerError.
//
// NO project import (node --test, Node 24 type stripping). Erasable
// TypeScript only.

export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DerError';
  }
}

export const CLASS_UNIVERSAL = 0;
export const CLASS_APPLICATION = 1;
export const CLASS_CONTEXT = 2;
export const CLASS_PRIVATE = 3;

export const TAG_BOOLEAN = 1;
export const TAG_INTEGER = 2;
export const TAG_BIT_STRING = 3;
export const TAG_OCTET_STRING = 4;
export const TAG_NULL = 5;
export const TAG_OID = 6;
export const TAG_ENUMERATED = 10;
export const TAG_SEQUENCE = 16;
export const TAG_SET = 17;

export interface Tlv {
  cls: number;           // 0 universal, 1 application, 2 context, 3 private
  constructed: boolean;
  tag: number;
  /** Offset of the identifier octet in `buf`. */
  start: number;
  /** Offset of the first content byte. */
  contentStart: number;
  /** Offset just past the content. */
  end: number;
  /** Content bytes (view on the source buffer). */
  value: Buffer;
  /** Identifier + length + content (view on the source buffer). */
  raw: Buffer;
}

const MAX_TAG_BYTES = 4;
const MAX_DEPTH = 32;

/** Reads one TLV at `offset` of `buf` (never beyond `limit`). */
export function readTlv(buf: Buffer, offset = 0, limit = buf.length): Tlv {
  if (limit > buf.length) throw new DerError('limit beyond buffer');
  let p = offset;
  if (p >= limit) throw new DerError('truncated: identifier');
  const id = buf[p++];
  const cls = id >> 6;
  const constructed = (id & 0x20) !== 0;
  let tag = id & 0x1f;
  if (tag === 0x1f) {
    // High-tag-number form: base-128, no leading 0x80, >= 31.
    tag = 0;
    let n = 0;
    for (;;) {
      if (p >= limit) throw new DerError('truncated: tag');
      const b = buf[p++];
      if (n === 0 && b === 0x80) throw new DerError('non-minimal tag');
      tag = tag * 128 + (b & 0x7f);
      n++;
      if (n > MAX_TAG_BYTES) throw new DerError('tag too large');
      if ((b & 0x80) === 0) break;
    }
    if (tag < 31) throw new DerError('non-minimal tag');
  }
  if (p >= limit) throw new DerError('truncated: length');
  const first = buf[p++];
  let len: number;
  if (first < 0x80) {
    len = first;
  } else if (first === 0x80) {
    throw new DerError('indefinite length');
  } else {
    const nBytes = first & 0x7f;
    if (nBytes > 4) throw new DerError('length too large');
    if (p + nBytes > limit) throw new DerError('truncated: length');
    if (buf[p] === 0) throw new DerError('non-minimal length');
    len = 0;
    for (let i = 0; i < nBytes; i++) len = len * 256 + buf[p++];
    if (len < 0x80) throw new DerError('non-minimal length');
  }
  const contentStart = p;
  const end = contentStart + len;
  if (end > limit) throw new DerError('truncated: content');
  return {
    cls, constructed, tag, start: offset, contentStart, end,
    value: buf.subarray(contentStart, end),
    raw: buf.subarray(offset, end),
  };
}

/** Parses exactly one TLV spanning the whole buffer (no trailing bytes). */
export function parseDer(buf: Buffer): Tlv {
  const t = readTlv(buf, 0, buf.length);
  if (t.end !== buf.length) throw new DerError('trailing bytes');
  return t;
}

/** Children of a constructed TLV, in order. */
export function children(t: Tlv, depth = 0): Tlv[] {
  if (!t.constructed) throw new DerError('not constructed');
  if (depth > MAX_DEPTH) throw new DerError('nesting too deep');
  const out: Tlv[] = [];
  const buf = t.value;
  let p = 0;
  while (p < buf.length) {
    const c = readTlv(buf, p, buf.length);
    out.push(c);
    p = c.end;
  }
  return out;
}

function expectUniversal(t: Tlv | undefined, tag: number, constructed: boolean, what: string): void {
  if (!t) throw new DerError(`missing ${what}`);
  if (t.cls !== CLASS_UNIVERSAL || t.tag !== tag || t.constructed !== constructed) {
    throw new DerError(`expected ${what}`);
  }
}

export function isUniversal(t: Tlv, tag: number): boolean {
  return t.cls === CLASS_UNIVERSAL && t.tag === tag;
}

export function asSequence(t: Tlv): Tlv[] {
  expectUniversal(t, TAG_SEQUENCE, true, 'SEQUENCE');
  return children(t);
}

export function asSet(t: Tlv): Tlv[] {
  expectUniversal(t, TAG_SET, true, 'SET');
  return children(t);
}

function twosComplement(v: Buffer, what: string): bigint {
  if (v.length === 0) throw new DerError(`empty ${what}`);
  if (v.length > 1 && ((v[0] === 0x00 && (v[1] & 0x80) === 0) || (v[0] === 0xff && (v[1] & 0x80) !== 0))) {
    throw new DerError(`non-minimal ${what}`);
  }
  let n = 0n;
  for (const b of v) n = (n << 8n) | BigInt(b);
  if (v[0] & 0x80) n -= 1n << BigInt(v.length * 8);
  return n;
}

export function asBigInt(t: Tlv): bigint {
  expectUniversal(t, TAG_INTEGER, false, 'INTEGER');
  return twosComplement(t.value, 'INTEGER');
}

/** INTEGER that must fit a JS safe integer. */
export function asInt(t: Tlv): number {
  const n = asBigInt(t);
  if (n > BigInt(Number.MAX_SAFE_INTEGER) || n < BigInt(Number.MIN_SAFE_INTEGER)) throw new DerError('INTEGER too large');
  return Number(n);
}

export function asEnumerated(t: Tlv): number {
  expectUniversal(t, TAG_ENUMERATED, false, 'ENUMERATED');
  const n = twosComplement(t.value, 'ENUMERATED');
  if (n > 0xffffffffn || n < 0n) throw new DerError('ENUMERATED out of range');
  return Number(n);
}

/** DER BOOLEAN: one byte, 0x00 or 0xFF. */
export function asBoolean(t: Tlv): boolean {
  expectUniversal(t, TAG_BOOLEAN, false, 'BOOLEAN');
  if (t.value.length !== 1) throw new DerError('bad BOOLEAN length');
  if (t.value[0] === 0x00) return false;
  if (t.value[0] === 0xff) return true;
  throw new DerError('non-DER BOOLEAN');
}

/**
 * BOOLEAN with BER semantics (X.690 §8.2.2: one octet, 0x00 FALSE, any other
 * value TRUE). Used ONLY for RootOfTrust.deviceLocked: genuine KeyMint
 * implementations write 0x01 there (android/keyattestation testdata
 * invalid/malformed_rot_device_locked.pem, a Google-rooted chain that
 * Google's own verifier accepts as deviceLocked=true and logs). The octet is
 * inside the signed leaf, so its encoding cannot be chosen by an attacker;
 * refusing it would only refuse real phones. `der` tells whether it was
 * canonical (for the stored summary).
 */
export function asBooleanBer(t: Tlv): { value: boolean; der: boolean } {
  expectUniversal(t, TAG_BOOLEAN, false, 'BOOLEAN');
  if (t.value.length !== 1) throw new DerError('bad BOOLEAN length');
  const b = t.value[0];
  return { value: b !== 0x00, der: b === 0x00 || b === 0xff };
}

export function asNull(t: Tlv): null {
  expectUniversal(t, TAG_NULL, false, 'NULL');
  if (t.value.length !== 0) throw new DerError('bad NULL');
  return null;
}

export function asOctetString(t: Tlv): Buffer {
  expectUniversal(t, TAG_OCTET_STRING, false, 'OCTET STRING');
  return t.value;
}

export function asOid(t: Tlv): string {
  expectUniversal(t, TAG_OID, false, 'OBJECT IDENTIFIER');
  const v = t.value;
  if (v.length === 0) throw new DerError('empty OID');
  const arcs: bigint[] = [];
  let cur = 0n;
  let started = false;
  for (let i = 0; i < v.length; i++) {
    const b = v[i];
    if (!started && b === 0x80) throw new DerError('non-minimal OID arc');
    started = true;
    cur = (cur << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(cur);
      cur = 0n;
      started = false;
    } else if (i === v.length - 1) {
      throw new DerError('truncated OID');
    }
  }
  const first = arcs[0];
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...head, ...arcs.slice(1)].map(String).join('.');
}

/** Explicit context tag [n] wrapping exactly one element → that element. */
export function explicitInner(t: Tlv): Tlv {
  if (!t) throw new DerError('missing explicit tag');
  if (t.cls !== CLASS_CONTEXT || !t.constructed) throw new DerError('expected explicit context tag');
  const c = children(t);
  if (c.length !== 1) throw new DerError(`explicit tag [${t.tag}] must wrap one element`);
  return c[0];
}

// ── X.509: extensions of a certificate (TBSCertificate walk) ───────────────

export interface CertExtension {
  oid: string;
  critical: boolean;
  /** extnValue content (the DER of the extension's own value). */
  value: Buffer;
}

export interface CertTbs {
  /** serialNumber as a (signed) integer. */
  serial: bigint;
  /** serialNumber content bytes, as encoded. */
  serialBytes: Buffer;
  /** Validity.notBefore / notAfter TLVs (UTCTime or GeneralizedTime),
   *  decoded on demand with derTimeMs() — Android leaf certificates carry
   *  arbitrary dates that are never checked (§4.3 step 2). */
  notBefore: Tlv;
  notAfter: Tlv;
  extensions: CertExtension[];
}

/** Serial as the Google status list writes it: lowercase hex, no leading
 *  zeros ("0" for zero). A negative serial (non-conforming) is written as
 *  its raw two's-complement bytes. */
export function serialHex(serial: bigint, serialBytes: Buffer): string {
  if (serial >= 0n) return serial.toString(16);
  return serialBytes.toString('hex');
}

/**
 * TBSCertificate fields used by the attestation check: serial, validity,
 * extensions. Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
 * signatureValue }; TBSCertificate ::= SEQUENCE { [0] EXPLICIT version
 * OPTIONAL, serialNumber, signature, issuer, validity, subject,
 * subjectPublicKeyInfo, [1] issuerUniqueID OPTIONAL, [2] subjectUniqueID
 * OPTIONAL, [3] EXPLICIT extensions OPTIONAL }.
 */
export function parseCertificateTbs(certDer: Buffer): CertTbs {
  const cert = asSequence(parseDer(certDer));
  if (cert.length !== 3) throw new DerError('Certificate: 3 elements expected');
  const tbs = asSequence(cert[0]);
  let i = 0;
  if (tbs[0] && tbs[0].cls === CLASS_CONTEXT && tbs[0].tag === 0) i = 1;
  if (tbs.length < i + 6) throw new DerError('TBSCertificate: too short');
  const serialTlv = tbs[i];
  const serial = asBigInt(serialTlv);
  const validity = asSequence(tbs[i + 3]);
  if (validity.length !== 2) throw new DerError('Validity: 2 elements expected');
  asSequence(tbs[i + 5]); // subjectPublicKeyInfo shape
  let extensions: CertExtension[] = [];
  let lastTag = -1;
  for (const t of tbs.slice(i + 6)) {
    if (t.cls !== CLASS_CONTEXT || t.tag <= lastTag || t.tag < 1 || t.tag > 3) throw new DerError('TBSCertificate: unexpected trailing element');
    lastTag = t.tag;
    if (t.tag === 3) extensions = parseExtensions(explicitInner(t));
  }
  return { serial, serialBytes: serialTlv.value, notBefore: validity[0], notAfter: validity[1], extensions };
}

/** UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) → epoch ms. */
export function derTimeMs(t: Tlv): number {
  const s = t.value.toString('latin1');
  let m: RegExpExecArray | null;
  let year: number;
  let rest: string[];
  if (t.cls === CLASS_UNIVERSAL && t.tag === 23 && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) {
    const yy = Number(m[1]);
    year = yy < 50 ? 2000 + yy : 1900 + yy;
    rest = m.slice(2);
  } else if (t.cls === CLASS_UNIVERSAL && t.tag === 24 && (m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) {
    year = Number(m[1]);
    rest = m.slice(2);
  } else {
    throw new DerError('bad certificate time');
  }
  const [mo, d, h, mi, se] = rest.map(Number);
  const ms = Date.UTC(year, mo - 1, d, h, mi, se);
  if (!Number.isFinite(ms) || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) {
    throw new DerError('bad certificate time');
  }
  return ms;
}

/**
 * Extensions of a DER certificate: Certificate → TBSCertificate → [3]
 * EXPLICIT Extensions. Duplicate OIDs are refused (RFC 5280 §4.2).
 */
export function certificateExtensions(certDer: Buffer): CertExtension[] {
  return parseCertificateTbs(certDer).extensions;
}

function parseExtensions(extSeq: Tlv): CertExtension[] {
  const list = asSequence(extSeq);
  const out: CertExtension[] = [];
  const seen = new Set<string>();
  for (const e of list) {
    const parts = asSequence(e);
    if (parts.length < 2 || parts.length > 3) throw new DerError('Extension: bad shape');
    const oid = asOid(parts[0]);
    let critical = false;
    let valueTlv = parts[1];
    if (parts.length === 3) {
      critical = asBoolean(parts[1]);
      valueTlv = parts[2];
    }
    if (seen.has(oid)) throw new DerError(`duplicate extension ${oid}`);
    seen.add(oid);
    out.push({ oid, critical, value: asOctetString(valueTlv) });
  }
  return out;
}

// ── ECDSA signatures (P-256) ────────────────────────────────────────────────
//
// Rules (§6.3):
//  - The signature is DER `SEQUENCE { INTEGER r, INTEGER s }`, parsed
//    STRICTLY here (minimal positive integers, 1 <= r,s < n, nothing
//    trailing) before crypto.verify.
//  - High-S is ACCEPTED: Android Keystore / KeyMint (BoringSSL) does not
//    normalise s, so a low-S rule would refuse about half of the genuine
//    signatures. ECDSA is therefore malleable ((r, s) and (r, n - s) both
//    verify — der.test.ts shows it).
//  - Consequence, and the actual rule: a signature is NEVER an anti-replay
//    key or an identifier. Replay protection is the single-use challenge,
//    consumed by one atomic UPDATE (deviceKey.service.ts).

/** Order n of the P-256 group (SEC 2 / FIPS 186-4 D.1.2.3). der.test.ts
 *  checks it: s -> n - s keeps a real signature valid. */
export const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

/** Max DER length of a P-256 signature (2 + 2 × (2 + 33)). */
export const P256_SIG_MAX_DER = 72;

export interface EcdsaSig { r: bigint; s: bigint }

export function parseEcdsaSignature(der: Buffer, n: bigint = P256_N): EcdsaSig {
  if (!Buffer.isBuffer(der) || der.length < 8 || der.length > P256_SIG_MAX_DER) throw new DerError('bad signature length');
  const seq = asSequence(parseDer(der));
  if (seq.length !== 2) throw new DerError('signature: 2 integers expected');
  const r = asBigInt(seq[0]);
  const s = asBigInt(seq[1]);
  if (r <= 0n || r >= n || s <= 0n || s >= n) throw new DerError('signature: r/s out of range');
  return { r, s };
}

function intBytes(n: bigint, size: number): Buffer {
  const hex = n.toString(16).padStart(size * 2, '0');
  if (hex.length > size * 2) throw new DerError('integer too large for size');
  return Buffer.from(hex, 'hex');
}

function derInt(n: bigint): Buffer {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let b = Buffer.from(hex, 'hex');
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return Buffer.concat([Buffer.from([TAG_INTEGER, b.length]), b]);
}

/** (r, s) → DER. */
export function encodeEcdsaSignature(sig: EcdsaSig): Buffer {
  const body = Buffer.concat([derInt(sig.r), derInt(sig.s)]);
  if (body.length > 0x7f) throw new DerError('signature too large');
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/** DER → raw r||s (IEEE P1363, `size` bytes each). */
export function ecdsaDerToRaw(der: Buffer, size = 32, n: bigint = P256_N): Buffer {
  const { r, s } = parseEcdsaSignature(der, n);
  return Buffer.concat([intBytes(r, size), intBytes(s, size)]);
}

/** raw r||s → DER. */
export function ecdsaRawToDer(raw: Buffer, size = 32): Buffer {
  if (raw.length !== size * 2) throw new DerError('bad raw signature length');
  const r = BigInt('0x' + raw.subarray(0, size).toString('hex'));
  const s = BigInt('0x' + raw.subarray(size).toString('hex'));
  return encodeEcdsaSignature({ r, s });
}

export function isLowS(s: bigint, n: bigint = P256_N): boolean {
  return s <= n >> 1n;
}

/** The other valid signature of the same message ((r, n - s)). For tests
 *  and investigation only — never used to accept or refuse anything. */
export function malleate(der: Buffer, n: bigint = P256_N): Buffer {
  const { r, s } = parseEcdsaSignature(der, n);
  return encodeEcdsaSignature({ r, s: n - s });
}

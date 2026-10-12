// =============================================================================
// The little DER the command queue needs (docs: integration-apple-edge §8.8,
// I9): writing a CMS EnvelopedData (the EncryptedPayloadContent of a profile
// that carries a secret) and reading two things back, the issuer and serial
// number of a device's identity certificate, and the content a CMS SignedData
// carries (a signed profile handed to the secret scanner). Definite lengths
// only: a BER form (indefinite length, constructed string) is refused, never
// guessed at. Pure; no dependency.
// =============================================================================

export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DerError';
  }
}

export const TAG = {
  INTEGER: 0x02, OCTET_STRING: 0x04, NULL: 0x05, OID: 0x06, SEQUENCE: 0x30, SET: 0x31,
  /** [0] EXPLICIT (constructed). */
  CTX0: 0xa0,
  /** [0] IMPLICIT of a primitive type. */
  CTX0_PRIMITIVE: 0x80,
} as const;

function lengthBytes(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** One TLV: `tag`, the length, the concatenated contents. */
export function der(tag: number, ...contents: Buffer[]): Buffer {
  const body = Buffer.concat(contents);
  return Buffer.concat([Buffer.from([tag]), lengthBytes(body.length), body]);
}

/** An OBJECT IDENTIFIER from its dotted form. */
export function derOid(dotted: string): Buffer {
  const parts = dotted.split('.').map(Number);
  if (parts.length < 2 || parts.some((p) => !Number.isSafeInteger(p) || p < 0)) throw new DerError('invalid OID');
  const out: number[] = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) {
    const stack: number[] = [p & 0x7f];
    for (let v = Math.floor(p / 128); v > 0; v = Math.floor(v / 128)) stack.unshift((v & 0x7f) | 0x80);
    out.push(...stack);
  }
  return der(TAG.OID, Buffer.from(out));
}

/** A small non-negative INTEGER. */
export function derSmallInt(n: number): Buffer {
  if (!Number.isInteger(n) || n < 0 || n > 127) throw new DerError('small integer out of range');
  return der(TAG.INTEGER, Buffer.from([n]));
}

export interface DerNode {
  tag: number;
  /** Offset of the tag. */
  start: number;
  /** Offset of the content. */
  contentStart: number;
  /** Offset after the content. */
  end: number;
}

/** The TLV at `offset` (within `limit`). Throws on an indefinite or oversized length. */
export function derRead(buf: Buffer, offset: number, limit: number = buf.length): DerNode {
  if (offset + 2 > limit) throw new DerError('truncated element');
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) throw new DerError('high tag numbers are not read');
  let len = buf[offset + 1];
  let contentStart = offset + 2;
  if (len === 0x80) throw new DerError('indefinite length (BER) is refused');
  if (len > 0x80) {
    const n = len & 0x7f;
    if (n > 4 || contentStart + n > limit) throw new DerError('invalid length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[contentStart + i];
    contentStart += n;
  }
  const end = contentStart + len;
  if (end > limit) throw new DerError('element longer than its container');
  return { tag, start: offset, contentStart, end };
}

/** The children of a constructed element. */
export function derChildren(buf: Buffer, node: DerNode): DerNode[] {
  const out: DerNode[] = [];
  for (let i = node.contentStart; i < node.end;) {
    const child = derRead(buf, i, node.end);
    out.push(child);
    i = child.end;
    if (out.length > 10_000) throw new DerError('too many elements');
  }
  return out;
}

const bytesOf = (buf: Buffer, n: DerNode): Buffer => buf.subarray(n.start, n.end);
const contentOf = (buf: Buffer, n: DerNode): Buffer => buf.subarray(n.contentStart, n.end);

/** The issuer (Name) and the serial number (INTEGER) of an X.509 certificate, each as its full TLV. */
export function issuerAndSerialOf(certDer: Buffer): { issuer: Buffer; serial: Buffer } {
  const cert = derRead(certDer, 0);
  if (cert.tag !== TAG.SEQUENCE) throw new DerError('not a certificate');
  const tbs = derChildren(certDer, cert)[0];
  if (!tbs || tbs.tag !== TAG.SEQUENCE) throw new DerError('not a certificate');
  const fields = derChildren(certDer, tbs);
  let i = 0;
  if (fields[i]?.tag === TAG.CTX0) i++;                                   // version
  const serial = fields[i];
  const issuer = fields[i + 2];
  if (!serial || serial.tag !== TAG.INTEGER || !issuer || issuer.tag !== TAG.SEQUENCE) throw new DerError('not a certificate');
  return { issuer: Buffer.from(bytesOf(certDer, issuer)), serial: Buffer.from(bytesOf(certDer, serial)) };
}

const OID_SIGNED_DATA = derOid('1.2.840.113549.1.7.2');

/**
 * The content a CMS SignedData carries (a signed configuration profile). null: `buf` is not a SignedData (any
 * other DER: a certificate, a key…). Throws DerError when it is one whose content cannot be read (detached, BER).
 */
export function signedDataContent(buf: Buffer): Buffer | null {
  let info: DerNode;
  let parts: DerNode[];
  try {
    info = derRead(buf, 0);
    if (info.tag !== TAG.SEQUENCE) return null;
    parts = derChildren(buf, info);
  } catch {
    return null;
  }
  if (parts.length < 2 || parts[0].tag !== TAG.OID || !bytesOf(buf, parts[0]).equals(OID_SIGNED_DATA)) return null;
  if (parts[1].tag !== TAG.CTX0) throw new DerError('SignedData without content');
  const signed = derChildren(buf, parts[1])[0];
  if (!signed || signed.tag !== TAG.SEQUENCE) throw new DerError('unreadable SignedData');
  const fields = derChildren(buf, signed);
  const encap = fields[2];
  if (!encap || encap.tag !== TAG.SEQUENCE) throw new DerError('unreadable SignedData');
  const inner = derChildren(buf, encap);
  if (inner.length < 2 || inner[1].tag !== TAG.CTX0) throw new DerError('detached SignedData');
  const octets = derChildren(buf, inner[1])[0];
  if (!octets || octets.tag !== TAG.OCTET_STRING) throw new DerError('unreadable SignedData content');
  return Buffer.from(contentOf(buf, octets));
}

/**
 * CMS EnvelopedData (RFC 5652) for one recipient, in DER: the content encrypted with AES-256-CBC, its key
 * transported with RSA PKCS#1 v1.5 to the certificate named by its issuer and serial number. The caller
 * encrypts; this only assembles.
 */
export function envelopedData(p: { issuer: Buffer; serial: Buffer; encryptedKey: Buffer; iv: Buffer; encryptedContent: Buffer }): Buffer {
  const recipient = der(TAG.SEQUENCE,
    derSmallInt(0),
    der(TAG.SEQUENCE, p.issuer, p.serial),
    der(TAG.SEQUENCE, derOid('1.2.840.113549.1.1.1'), der(TAG.NULL)),
    der(TAG.OCTET_STRING, p.encryptedKey));
  const content = der(TAG.SEQUENCE,
    derOid('1.2.840.113549.1.7.1'),
    der(TAG.SEQUENCE, derOid('2.16.840.1.101.3.4.1.42'), der(TAG.OCTET_STRING, p.iv)),
    der(TAG.CTX0_PRIMITIVE, p.encryptedContent));
  const enveloped = der(TAG.SEQUENCE, derSmallInt(0), der(TAG.SET, recipient), content);
  return der(TAG.SEQUENCE, derOid('1.2.840.113549.1.7.3'), der(TAG.CTX0, enveloped));
}

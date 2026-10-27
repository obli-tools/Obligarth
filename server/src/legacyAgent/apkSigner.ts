import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';

// =============================================================================
// The signer of an APK as its APK Signature Scheme v2 / v3 block names it
// (lot AGENT-RU): the SHA-256 of the first certificate (DER) of each signer,
// the fingerprint Android reports (PackageInfo.signatures) and the agent
// pins (PINNED_SIGNERS). The signatures themselves are NOT verified here: the
// agent and Android do that before installing (§8.6); the server only refuses
// a version whose block names another certificate than the one declared.
// Bounded reads of the file (no archive in memory). No database import: the
// unit tests load this module alone.
//   EOCD (end of central directory, comment 64 KiB at most, no ZIP64) →
//   offset of the central directory → 'APK Sig Block 42' right before it →
//   ID-value pairs: 0x7109871a (v2), 0xf05368c0 (v3) → signers (length-
//   prefixed) → signed data → certificates → first certificate.
// =============================================================================

const EOCD_MAGIC = 0x06054b50;
const EOCD_SIZE = 22;
const MAX_COMMENT = 0xffff;
const BLOCK_MAGIC = Buffer.from('APK Sig Block 42', 'latin1');
/** A signing block larger than this is refused (a real one is a few KiB, padding included). */
export const MAX_SIGNING_BLOCK = 16 * 1024 * 1024;

export const APK_SIGNATURE_V2 = 0x7109871a;
export const APK_SIGNATURE_V3 = 0xf05368c0;

export interface ApkSigners {
  /** SHA-256 (hex, lower case) of the first certificate of each v2 signer; null: no v2 block. */
  v2: string[] | null;
  /** The same for the v3 block; null: none. */
  v3: string[] | null;
}

export class ApkFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApkFormatError';
  }
}

type Reader = { size: number; read(position: number, length: number): Promise<Buffer> };

const fail = (message: string): never => { throw new ApkFormatError(message); };

/** A length-prefixed (uint32 LE) slice at `at` of `buf`, within `end`. */
function lp(buf: Buffer, at: number, end: number): { value: Buffer; next: number } {
  if (at + 4 > end) fail('truncated length prefix');
  const len = buf.readUInt32LE(at);
  if (at + 4 + len > end) fail('length prefix past its container');
  return { value: buf.subarray(at + 4, at + 4 + len), next: at + 4 + len };
}

/** The sequence of length-prefixed items that fills `buf`. */
function sequence(buf: Buffer): Buffer[] {
  const out: Buffer[] = [];
  let at = 0;
  while (at < buf.length) {
    const item = lp(buf, at, buf.length);
    out.push(item.value);
    at = item.next;
  }
  return out;
}

/** The first certificate of each signer of a v2 or v3 scheme value. */
function signerCertificates(value: Buffer): string[] {
  const signers = sequence(lp(value, 0, value.length).value);
  if (signers.length === 0) fail('no signer');
  return signers.map((signer) => {
    const signedData = lp(signer, 0, signer.length).value;
    const digests = lp(signedData, 0, signedData.length);
    const certificates = sequence(lp(signedData, digests.next, signedData.length).value);
    if (certificates.length === 0 || certificates[0].length === 0) fail('signer without certificate');
    return createHash('sha256').update(certificates[0]).digest('hex');
  });
}

async function eocdOffset(r: Reader): Promise<number> {
  if (r.size < EOCD_SIZE) fail('too small for a ZIP archive');
  const span = Math.min(r.size, EOCD_SIZE + MAX_COMMENT);
  const tail = await r.read(r.size - span, span);
  for (let i = tail.length - EOCD_SIZE; i >= 0; i--) {
    if (tail.readUInt32LE(i) !== EOCD_MAGIC) continue;
    // The comment must end the file exactly: a magic inside the comment or the data is skipped.
    if (tail.readUInt16LE(i + 20) === tail.length - i - EOCD_SIZE) return r.size - span + i;
  }
  return fail('no end of central directory');
}

async function signersOf(r: Reader): Promise<ApkSigners> {
  const eocd = await eocdOffset(r);
  const record = await r.read(eocd, EOCD_SIZE);
  const cdOffset = record.readUInt32LE(16);
  if (cdOffset === 0xffffffff) fail('ZIP64 archives are refused');
  if (cdOffset > eocd) fail('central directory past its end');
  const out: ApkSigners = { v2: null, v3: null };
  if (cdOffset < 32) return out;
  const footer = await r.read(cdOffset - 24, 24);
  if (!footer.subarray(8).equals(BLOCK_MAGIC)) return out;
  const size = Number(footer.readBigUInt64LE(0));
  if (size < 24 || size > MAX_SIGNING_BLOCK || size + 8 > cdOffset) fail('signing block size out of bounds');
  const start = cdOffset - size - 8;
  const block = await r.read(start, size + 8);
  if (Number(block.readBigUInt64LE(0)) !== size) fail('signing block sizes differ');
  const pairs = block.subarray(8, block.length - 24);
  let at = 0;
  while (at < pairs.length) {
    if (at + 12 > pairs.length) fail('truncated ID-value pair');
    const len = Number(pairs.readBigUInt64LE(at));
    if (len < 4 || at + 8 + len > pairs.length) fail('ID-value pair past the block');
    const id = pairs.readUInt32LE(at + 8);
    const value = pairs.subarray(at + 12, at + 8 + len);
    if (id === APK_SIGNATURE_V2) out.v2 = signerCertificates(value);
    else if (id === APK_SIGNATURE_V3) out.v3 = signerCertificates(value);
    at += 8 + len;
  }
  return out;
}

/** The signers of an APK held in memory. Throws ApkFormatError on a malformed archive or block. */
export function apkSignersOfBuffer(buf: Buffer): Promise<ApkSigners> {
  return signersOf({
    size: buf.length,
    read: async (position, length) => {
      if (position < 0 || position + length > buf.length) fail('read past the end');
      return buf.subarray(position, position + length);
    },
  });
}

/** The signers of an APK file (bounded reads). Throws ApkFormatError on a malformed archive or block. */
export async function apkSignersOfFile(file: string): Promise<ApkSigners> {
  const fh = await open(file, 'r');
  try {
    const { size } = await fh.stat();
    return await signersOf({
      size,
      read: async (position, length) => {
        if (position < 0 || position + length > size) fail('read past the end');
        const buf = Buffer.alloc(length);
        const { bytesRead } = await fh.read(buf, 0, length, position);
        if (bytesRead !== length) fail('short read');
        return buf;
      },
    });
  } finally {
    await fh.close();
  }
}

/**
 * True when the APK is signed by `signerSha256` alone: a v2 or v3 block at least, and every block present names one
 * signer, whose certificate has this fingerprint (the agent refuses an installed package with several signers).
 */
export function signedOnlyBy(s: ApkSigners, signerSha256: string): boolean {
  const blocks = [s.v2, s.v3].filter((b): b is string[] => b !== null);
  return blocks.length > 0 && blocks.every((b) => b.length === 1 && b[0] === signerSha256);
}

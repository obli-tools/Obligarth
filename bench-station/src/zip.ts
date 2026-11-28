import { inflateRawSync } from 'node:zlib';

/**
 * Obligarth bench station — a minimal ZIP reader (no dependency in a single-file executable): the central directory,
 * then one entry at a time, stored or deflated. Enough for the platform-tools archive (three files taken out of it,
 * §5.5) and the JAR signature of an APK (provision/apkV1.ts). No ZIP64, no encryption, no multi-disk: refused.
 */

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  localOffset: number;
}

export class ZipError extends Error {
  constructor(message: string) { super(message); this.name = 'ZipError'; }
}

const EOCD = 0x06054b50;
const CEN = 0x02014b50;
const LOC = 0x04034b50;

export function zipEntries(buf: Buffer): ZipEntry[] {
  const min = Math.max(0, buf.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD) { eocd = i; break; }
  }
  if (eocd < 0) throw new ZipError('no end of central directory');
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (cdOffset === 0xffffffff || count === 0xffff) throw new ZipError('ZIP64 is not supported');
  if (cdOffset + cdSize > buf.length) throw new ZipError('central directory past the end');
  const entries: ZipEntry[] = [];
  let at = cdOffset;
  for (let n = 0; n < count; n++) {
    if (at + 46 > buf.length || buf.readUInt32LE(at) !== CEN) throw new ZipError('bad central directory entry');
    const flags = buf.readUInt16LE(at + 8);
    if (flags & 1) throw new ZipError('encrypted entry');
    const nameLen = buf.readUInt16LE(at + 28);
    const extraLen = buf.readUInt16LE(at + 30);
    const commentLen = buf.readUInt16LE(at + 32);
    entries.push({
      name: buf.subarray(at + 46, at + 46 + nameLen).toString('utf8'),
      method: buf.readUInt16LE(at + 10),
      compressedSize: buf.readUInt32LE(at + 20),
      size: buf.readUInt32LE(at + 24),
      localOffset: buf.readUInt32LE(at + 42),
    });
    at += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** The bytes of one entry; its size is checked. */
export function zipRead(buf: Buffer, e: ZipEntry, maxSize = 64 * 1024 * 1024): Buffer {
  if (e.size > maxSize) throw new ZipError(`entry ${e.name} too large`);
  const at = e.localOffset;
  if (at + 30 > buf.length || buf.readUInt32LE(at) !== LOC) throw new ZipError(`bad local header for ${e.name}`);
  const start = at + 30 + buf.readUInt16LE(at + 26) + buf.readUInt16LE(at + 28);
  const data = buf.subarray(start, start + e.compressedSize);
  if (data.length !== e.compressedSize) throw new ZipError(`entry ${e.name} truncated`);
  let out: Buffer;
  if (e.method === 0) out = Buffer.from(data);
  else if (e.method === 8) out = inflateRawSync(data, { maxOutputLength: maxSize });
  else throw new ZipError(`entry ${e.name}: compression method ${e.method} not supported`);
  if (out.length !== e.size) throw new ZipError(`entry ${e.name}: size ${out.length}, expected ${e.size}`);
  return out;
}

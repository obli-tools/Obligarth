import { open } from 'node:fs/promises';
import { inflateRawSync } from 'node:zlib';

// =============================================================================
// The identity of an APK as its own manifest states it (review F028): the
// package name, the versionCode (versionCodeMajor included, as
// PackageInfo.getLongVersionCode) and the versionName of the <manifest>
// element of AndroidManifest.xml, compiled (binary XML, "AXML"). Read by the
// server from the file itself, never from what a device declares about it.
// Bounded reads of the file (no archive in memory):
//   EOCD (comment 64 KiB at most, no ZIP64) → central directory → the one
//   entry AndroidManifest.xml (stored or deflated, 8 MiB at most) → its local
//   header → the bytes → the chunks of the binary XML: string pool, resource
//   map, first start element (must be <manifest>), its attributes.
// The android: attributes are recognised by their resource id, as Android's
// parser does (a string "versionCode" bound to another id is not it). No
// database import: the unit tests load this module alone.
// =============================================================================

const EOCD_MAGIC = 0x06054b50;
const EOCD_SIZE = 22;
const MAX_COMMENT = 0xffff;
const CD_MAGIC = 0x02014b50;
const LOCAL_MAGIC = 0x04034b50;
const MANIFEST_ENTRY = 'AndroidManifest.xml';
/** A central directory larger than this is refused (an APK of 100 MiB has a few MiB at most). */
const MAX_CENTRAL_DIRECTORY = 32 * 1024 * 1024;
/** The compiled manifest, compressed or not (a real one is a few KiB to a few hundred KiB). */
export const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;

const RES_XML_TYPE = 0x0003;
const RES_STRING_POOL_TYPE = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE = 0x0180;
const RES_XML_START_ELEMENT_TYPE = 0x0102;
const UTF8_FLAG = 0x100;
const NO_ENTRY = 0xffffffff;

const TYPE_STRING = 0x03;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;

/** android:versionCode, android:versionName, android:versionCodeMajor (android.R.attr). */
export const ATTR_VERSION_CODE = 0x0101021b;
export const ATTR_VERSION_NAME = 0x0101021c;
export const ATTR_VERSION_CODE_MAJOR = 0x01010576;

export interface ApkManifest {
  packageName: string;
  /** PackageInfo.getLongVersionCode: versionCodeMajor << 32 | versionCode. */
  versionCode: number;
  versionName: string | null;
}

export class ApkManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApkManifestError';
  }
}

const fail = (message: string): never => { throw new ApkManifestError(message); };

type Reader = { size: number; read(position: number, length: number): Promise<Buffer> };

async function eocdOf(r: Reader): Promise<Buffer> {
  if (r.size < EOCD_SIZE) fail('too small for a ZIP archive');
  const span = Math.min(r.size, EOCD_SIZE + MAX_COMMENT);
  const tail = await r.read(r.size - span, span);
  for (let i = tail.length - EOCD_SIZE; i >= 0; i--) {
    if (tail.readUInt32LE(i) !== EOCD_MAGIC) continue;
    // The comment must end the file exactly: a magic inside the comment or the data is skipped.
    if (tail.readUInt16LE(i + 20) === tail.length - i - EOCD_SIZE) return tail.subarray(i, i + EOCD_SIZE);
  }
  return fail('no end of central directory');
}

/** The bytes of the compiled manifest: its single entry of the central directory, stored or deflated. */
async function manifestBytes(r: Reader): Promise<Buffer> {
  const eocd = await eocdOf(r);
  const cdSize = eocd.readUInt32LE(12);
  const cdOffset = eocd.readUInt32LE(16);
  if (cdOffset === 0xffffffff || cdSize === 0xffffffff) fail('ZIP64 archives are refused');
  if (cdSize > MAX_CENTRAL_DIRECTORY) fail('central directory too large');
  if (cdOffset + cdSize > r.size) fail('central directory past the end');
  const cd = await r.read(cdOffset, cdSize);
  const found = bounded(() => manifestEntry(cd));
  if (!found) return fail('no AndroidManifest.xml');
  if ((found.flags & 0x1) !== 0) fail('encrypted manifest entry');
  if (found.compressed > MAX_MANIFEST_BYTES || found.size > MAX_MANIFEST_BYTES) fail('manifest too large');
  if (found.local + 30 > r.size) fail('local header past the end');
  const local = await r.read(found.local, 30);
  if (local.readUInt32LE(0) !== LOCAL_MAGIC) fail('malformed local header');
  const dataAt = found.local + 30 + local.readUInt16LE(26) + local.readUInt16LE(28);
  if (dataAt + found.compressed > r.size) fail('manifest data past the end');
  const raw = await r.read(dataAt, found.compressed);
  if (found.method === 0) return raw;
  if (found.method !== 8) fail(`unsupported compression method ${found.method}`);
  try {
    return inflateRawSync(raw, { maxOutputLength: MAX_MANIFEST_BYTES });
  } catch {
    return fail('the manifest does not inflate');
  }
}

type ManifestEntry = { method: number; flags: number; compressed: number; size: number; local: number };

/** The one AndroidManifest.xml entry of a central directory, or null. */
function manifestEntry(cd: Buffer): ManifestEntry | null {
  let found: ManifestEntry | null = null;
  let at = 0;
  while (at + 46 <= cd.length) {
    if (cd.readUInt32LE(at) !== CD_MAGIC) fail('malformed central directory');
    const nameLen = cd.readUInt16LE(at + 28);
    const extraLen = cd.readUInt16LE(at + 30);
    const commentLen = cd.readUInt16LE(at + 32);
    const end = at + 46 + nameLen + extraLen + commentLen;
    if (end > cd.length) fail('central directory entry past its end');
    const name = cd.toString('utf8', at + 46, at + 46 + nameLen);
    if (name === MANIFEST_ENTRY) {
      // Two entries of the same name: Android refuses such an archive, so does the server.
      if (found) fail('two AndroidManifest.xml entries');
      found = {
        flags: cd.readUInt16LE(at + 8), method: cd.readUInt16LE(at + 10), compressed: cd.readUInt32LE(at + 20),
        size: cd.readUInt32LE(at + 24), local: cd.readUInt32LE(at + 42),
      };
    }
    at = end;
  }
  return found;
}

/** The strings of a string pool chunk, decoded on demand. */
function stringPool(buf: Buffer, start: number, chunkSize: number): (i: number) => string | null {
  const end = start + chunkSize;
  if (chunkSize < 28) fail('string pool too small');
  const headerSize = buf.readUInt16LE(start + 2);
  const count = buf.readUInt32LE(start + 8);
  const flags = buf.readUInt32LE(start + 16);
  const stringsStart = buf.readUInt32LE(start + 20);
  if (headerSize < 28 || start + headerSize + count * 4 > end || start + stringsStart > end) fail('malformed string pool');
  const utf8 = (flags & UTF8_FLAG) !== 0;
  return (i: number): string | null => {
    if (!Number.isInteger(i) || i < 0 || i >= count) return null;
    let p = start + stringsStart + buf.readUInt32LE(start + headerSize + i * 4);
    if (p + 2 > end) return fail('string past its pool');
    if (utf8) {
      // The length in UTF-16 units (skipped), then the length in bytes, each on one or two bytes.
      p += (buf[p] & 0x80) ? 2 : 1;
      if (p + 2 > end) return fail('string past its pool');
      let len = buf[p];
      if (len & 0x80) { len = ((len & 0x7f) << 8) | buf[p + 1]; p += 2; } else p += 1;
      if (p + len > end) return fail('string past its pool');
      return buf.toString('utf8', p, p + len);
    }
    let len = buf.readUInt16LE(p);
    if (len & 0x8000) {
      if (p + 4 > end) return fail('string past its pool');
      len = ((len & 0x7fff) << 16) | buf.readUInt16LE(p + 2);
      p += 4;
    } else p += 2;
    if (p + len * 2 > end) return fail('string past its pool');
    return buf.toString('utf16le', p, p + len * 2);
  };
}

/** A read past a buffer (RangeError) is a malformed file, never another kind of error. */
function bounded<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof RangeError) return fail('malformed (read past a bound)');
    throw err;
  }
}

/** The <manifest> element of a compiled AndroidManifest.xml: package, versionCode (long), versionName. */
export function parseBinaryManifest(buf: Buffer): ApkManifest {
  return bounded(() => parseManifestChunks(buf));
}

function parseManifestChunks(buf: Buffer): ApkManifest {
  if (buf.length < 8 || buf.readUInt16LE(0) !== RES_XML_TYPE) fail('not a compiled XML document');
  const headerSize = buf.readUInt16LE(2);
  const end = Math.min(buf.length, buf.readUInt32LE(4));
  if (headerSize < 8 || headerSize > end) fail('malformed XML header');
  let str: ((i: number) => string | null) | null = null;
  let resIds: number[] = [];
  let at = headerSize;
  while (at + 8 <= end) {
    const type = buf.readUInt16LE(at);
    const hs = buf.readUInt16LE(at + 2);
    const size = buf.readUInt32LE(at + 4);
    if (size < 8 || hs > size || at + size > end) fail('malformed chunk');
    if (type === RES_STRING_POOL_TYPE && !str) {
      str = stringPool(buf, at, size);
    } else if (type === RES_XML_RESOURCE_MAP_TYPE) {
      resIds = [];
      for (let p = at + hs; p + 4 <= at + size; p += 4) resIds.push(buf.readUInt32LE(p));
    } else if (type === RES_XML_START_ELEMENT_TYPE) {
      if (!str) fail('element before the string pool');
      return manifestElement(buf, at, hs, size, str!, resIds);
    }
    at += size;
  }
  return fail('no element');
}

function manifestElement(buf: Buffer, at: number, hs: number, size: number, str: (i: number) => string | null, resIds: number[]): ApkManifest {
  const ext = at + hs;
  if (ext + 20 > at + size) fail('malformed element');
  if (str(buf.readUInt32LE(ext + 4)) !== 'manifest') fail('the first element is not <manifest>');
  const attrStart = buf.readUInt16LE(ext + 8);
  const attrSize = buf.readUInt16LE(ext + 10);
  const attrCount = buf.readUInt16LE(ext + 12);
  if (attrSize < 20 || ext + attrStart + attrSize * attrCount > at + size) fail('malformed attributes');
  let packageName: string | null = null;
  let code: number | null = null;
  let major = 0;
  let versionName: string | null = null;
  const intOf = (p: number): number | null => {
    const type = buf[p + 15];
    if (type === TYPE_INT_DEC || type === TYPE_INT_HEX) return buf.readUInt32LE(p + 16);
    if (type === TYPE_STRING) {
      const s = str(buf.readUInt32LE(p + 16)) ?? '';
      return /^[0-9]{1,10}$/.test(s) && Number(s) <= 0xffffffff ? Number(s) : null;
    }
    return null;
  };
  const textOf = (p: number): string | null => {
    const raw = buf.readUInt32LE(p + 8);
    if (raw !== NO_ENTRY) return str(raw);
    return buf[p + 15] === TYPE_STRING ? str(buf.readUInt32LE(p + 16)) : null;
  };
  for (let i = 0; i < attrCount; i++) {
    const p = ext + attrStart + i * attrSize;
    const nameIdx = buf.readUInt32LE(p + 4);
    const resId = nameIdx < resIds.length ? resIds[nameIdx] : 0;
    if (resId === 0) {
      // package is not an android: attribute (no resource id, no namespace).
      if (buf.readUInt32LE(p) === NO_ENTRY && str(nameIdx) === 'package') packageName = textOf(p);
      continue;
    }
    if (resId === ATTR_VERSION_CODE) code = intOf(p);
    else if (resId === ATTR_VERSION_CODE_MAJOR) major = intOf(p) ?? 0;
    else if (resId === ATTR_VERSION_NAME) versionName = textOf(p);
  }
  if (!packageName) fail('no package name');
  if (code === null || (code === 0 && major === 0)) fail('no versionCode');
  const versionCode = major * 0x100000000 + (code as number);
  if (!Number.isSafeInteger(versionCode)) fail('versionCode out of range');
  return { packageName: packageName as string, versionCode, versionName: versionName ? versionName.slice(0, 64) : null };
}

/** The manifest of an APK held in memory. Throws ApkManifestError on a malformed archive or manifest. */
export async function apkManifestOfBuffer(buf: Buffer): Promise<ApkManifest> {
  return parseBinaryManifest(await manifestBytes({
    size: buf.length,
    read: async (position, length) => {
      if (position < 0 || position + length > buf.length) fail('read past the end');
      return buf.subarray(position, position + length);
    },
  }));
}

/** The manifest of an APK file (bounded reads). Throws ApkManifestError on a malformed archive or manifest. */
export async function apkManifestOfFile(file: string): Promise<ApkManifest> {
  const fh = await open(file, 'r');
  try {
    const { size } = await fh.stat();
    const bytes = await manifestBytes({
      size,
      read: async (position, length) => {
        if (position < 0 || position + length > size) fail('read past the end');
        const buf = Buffer.alloc(length);
        const { bytesRead } = await fh.read(buf, 0, length, position);
        if (bytesRead !== length) fail('short read');
        return buf;
      },
    });
    return parseBinaryManifest(bytes);
  } finally {
    await fh.close();
  }
}

import { createHash } from 'node:crypto';
import { crc32, deflateSync, inflateSync } from 'node:zlib';

// =============================================================================
// The icon of an app sent by a device (POST /agent/v1/icons): a file from a
// device is never trusted. canonicalPng(buf) accepts a PNG only (WebP, JPEG,
// SVG or anything else: badFormat), checks every chunk (length bounded by the file, type, CRC),
// IHDR first (square, 16 to 192 px, a valid depth and colour type, no
// interlacing), keeps PLTE, tRNS, the IDAT (contiguous) and IEND (last,
// nothing after it), refuses an unknown critical chunk, drops the ancillary
// ones, inflates the image data with an output bounded by the size the header
// announces (a decompression bomb never inflates further), checks its exact
// length and the filter byte of each row, then writes a new PNG: the same
// header, palette and transparency, ONE IDAT deflated again (level 6: the
// work of a request stays small, the caller bounds the pixels it decodes by
// maxRawBytes). No byte of the device's file survives but the pixels. 32 KiB
// at most; the SHA-256 is that of the canonical bytes. Pure: no database (unit
// tests, npm run test:mdm).
// =============================================================================

export const ICON_MAX_BYTES = 32 * 1024;
export const ICON_MIN_PX = 16;
export const ICON_MAX_PX = 192;
/** Days a device that could not send an icon is not asked for it again (app_icons.failed_at; legacyAgent/icons.ts):
 *  the retention keeps its row as long (mdm/inventory/retention.ts). */
export const ICON_FAILED_DAYS = 30;
/** The smallest valid PNG: signature, IHDR, an IDAT, IEND. */
const PNG_MIN_BYTES = 67;

export type IconRejection = 'badFormat' | 'badPng' | 'badDimensions' | 'interlaced' | 'unsupported' | 'tooLarge';

/** rawBytes: the size of the decoded pixels (the header's), counted by the caller against its budget; absent when the
 *  file was refused before its header was read. */
export type CanonicalPng =
  | { ok: true; png: Buffer; sha256: string; width: number; rawBytes: number }
  | { ok: false; reason: IconRejection; rawBytes?: number };

const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
/** Bit depths allowed by colour type (PNG specification, table 11.1); channels of each type. */
const DEPTHS: Record<number, readonly number[]> = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
const CHANNELS: Record<number, number> = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
const MAX_CHUNKS = 1024;

const fail = (reason: IconRejection): CanonicalPng => ({ ok: false, reason });

function chunk(type: string, data: Buffer): Buffer {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'latin1');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)) >>> 0, 8 + data.length);
  return out;
}

/** The canonical PNG of `buf`, or why it is refused; tooLarge when its decoded pixels exceed `maxRawBytes` (never
 *  inflated then). */
export function canonicalPng(buf: Buffer, opts: { maxRawBytes?: number } = {}): CanonicalPng {
  if (!Buffer.isBuffer(buf)) return fail('badFormat');
  if (buf.length > ICON_MAX_BYTES) return fail('tooLarge');
  if (buf.length < SIGNATURE.length || !buf.subarray(0, SIGNATURE.length).equals(SIGNATURE)) return fail('badFormat');
  if (buf.length < PNG_MIN_BYTES) return fail('badPng');

  let pos = SIGNATURE.length;
  let count = 0;
  let header: { width: number; height: number; depth: number; colour: number } | null = null;
  let plte: Buffer | null = null;
  let trns: Buffer | null = null;
  const idat: Buffer[] = [];
  let idatClosed = false;
  let ended = false;
  while (pos < buf.length) {
    if (ended) return fail('badPng');                                  // nothing after IEND
    if (++count > MAX_CHUNKS || buf.length - pos < 12) return fail('badPng');
    const length = buf.readUInt32BE(pos);
    if (length > buf.length - pos - 12) return fail('badPng');
    const type = buf.toString('latin1', pos + 4, pos + 8);
    if (!/^[A-Za-z]{4}$/.test(type)) return fail('badPng');
    const data = buf.subarray(pos + 8, pos + 8 + length);
    const crc = buf.readUInt32BE(pos + 8 + length);
    if ((crc32(buf.subarray(pos + 4, pos + 8 + length)) >>> 0) !== crc) return fail('badPng');
    pos += 12 + length;

    if (count === 1 && type !== 'IHDR') return fail('badPng');
    if (type !== 'IDAT' && idat.length > 0) idatClosed = true;
    switch (type) {
      case 'IHDR': {
        if (count !== 1 || length !== 13) return fail('badPng');
        const width = data.readUInt32BE(0);
        const height = data.readUInt32BE(4);
        const depth = data[8];
        const colour = data[9];
        if (!DEPTHS[colour] || !DEPTHS[colour].includes(depth) || data[10] !== 0 || data[11] !== 0) return fail('unsupported');
        if (data[12] === 1) return fail('interlaced');
        if (data[12] !== 0) return fail('unsupported');
        if (width !== height || width < ICON_MIN_PX || width > ICON_MAX_PX) return fail('badDimensions');
        header = { width, height, depth, colour };
        break;
      }
      case 'PLTE':
        if (!header || plte || idat.length || header.colour === 0 || header.colour === 4) return fail('badPng');
        if (length === 0 || length % 3 !== 0 || length / 3 > 256 || (header.colour === 3 && length / 3 > 2 ** header.depth)) return fail('badPng');
        plte = Buffer.from(data);
        break;
      case 'tRNS':
        if (!header || trns || idat.length) return fail('badPng');
        if (header.colour === 0 ? length !== 2 : header.colour === 2 ? length !== 6
          : header.colour === 3 ? (!plte || length > plte.length / 3) : true) return fail('badPng');
        trns = Buffer.from(data);
        break;
      case 'IDAT':
        if (!header || idatClosed) return fail('badPng');
        if (header.colour === 3 && !plte) return fail('badPng');
        idat.push(data);
        break;
      case 'IEND':
        if (length !== 0 || idat.length === 0) return fail('badPng');
        ended = true;
        break;
      default:
        // Bit 5 of the first byte: 0 = critical (unknown: refused), 1 = ancillary (dropped).
        if ((type.charCodeAt(0) & 0x20) === 0) return fail('unsupported');
    }
  }
  if (!ended || !header) return fail('badPng');

  // Decoding bounded by the size the header announces (+1: a longer stream is detected, never inflated further).
  const bitsPerPixel = CHANNELS[header.colour] * header.depth;
  const rowBytes = Math.ceil((header.width * bitsPerPixel) / 8);
  const expected = header.height * (1 + rowBytes);
  if (opts.maxRawBytes !== undefined && expected > opts.maxRawBytes) return fail('tooLarge');
  const refused = (reason: IconRejection): CanonicalPng => ({ ok: false, reason, rawBytes: expected });
  let raw: Buffer;
  try {
    raw = inflateSync(Buffer.concat(idat), { maxOutputLength: expected + 1 });
  } catch {
    return refused('badPng');
  }
  if (raw.length !== expected) return refused('badPng');
  for (let row = 0; row < header.height; row++) if (raw[row * (1 + rowBytes)] > 4) return refused('badPng');

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(header.width, 0);
  ihdr.writeUInt32BE(header.height, 4);
  ihdr[8] = header.depth;
  ihdr[9] = header.colour;
  const png = Buffer.concat([
    SIGNATURE, chunk('IHDR', ihdr),
    ...(plte ? [chunk('PLTE', plte)] : []), ...(trns ? [chunk('tRNS', trns)] : []),
    chunk('IDAT', deflateSync(raw, { level: 6 })), chunk('IEND', Buffer.alloc(0)),
  ]);
  if (png.length > ICON_MAX_BYTES) return refused('tooLarge');
  return { ok: true, png, sha256: createHash('sha256').update(png).digest('hex'), width: header.width, rawBytes: expected };
}

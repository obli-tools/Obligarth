import { createHash, randomUUID, X509Certificate } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, open, readdir, readFile, rename, rm, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Request } from 'express';
import type { Knex } from 'knex';
import { LEGACY_AGENT_POLICY_LIMITS as L, type LegacyAgentFileKind, type LegacyAgentFileView } from '@obligarth/shared';
import { db } from '../db';
import { asNone } from '../db/context';
import { allTenantIds, forEachTenant } from '../db/tenantContext';
import type { JobContext } from '../jobs';
import { AppError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
import { filesDir } from './config';

// =============================================================================
// The file store of the agent policies (lot PONT-POL §9.1): what a policy
// deposits on the devices (a stored file), the images of the kiosk and the CAs
// of the Wi-Fi networks, by content, per tenant: <filesDir>/<tenant>/<sha256>.bin,
// its row in legacy_agent_files (name, kind, size). The server computes the
// SHA-256 and the size of an upload, infers its kind (an image checked by its
// magic bytes and its dimensions, a certificate parsed as X.509 and kept as
// PEM, anything else a file), and enforces the tenant's quota. A file still
// referenced by a policy version or a desired artifact is never deleted
// (fileUsage). The collection (a minute step, once an hour) runs per tenant in
// its context and removes the bytes no row names any more, after 24 hours, then
// the folders of deleted tenants (context none, tenant ids only).
// Never a byte of a file in a log.
// =============================================================================

/** The accepted media types of an upload (anything else 415); SVG never. JSON travels as application/octet-stream (the
 *  API's JSON parser would read the body first). */
const ACCEPTED = new Set(['application/octet-stream', 'application/xml', 'application/x-x509-ca-cert',
  'application/pkix-cert', 'image/png', 'image/jpeg', 'image/gif', 'image/x-icon', 'image/vnd.microsoft.icon']);

/** The folder of a tenant's files. */
export function tenantFilesDir(tenantId: number): string {
  if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new Error('tenantFilesDir: tenant');
  return path.join(filesDir(), String(tenantId));
}

/** The path of a stored file. */
export function storedFilePath(tenantId: number, sha256: string): string {
  if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error('storedFilePath: sha256');
  return path.join(tenantFilesDir(tenantId), `${sha256}.bin`);
}

export function mediaTypeOf(req: Request): string {
  return String(req.headers['content-type'] ?? '').toLowerCase().split(';')[0].trim();
}

/** Receives an upload (raw body) into the tenant's folder: its SHA-256 and size computed here; a file already stored
 *  with the same content is kept as is. */
export async function receiveFile(req: Request, tenantId: number, maxBytes: number): Promise<{ sha256: string; size: number }> {
  const ctype = mediaTypeOf(req);
  if (ctype === 'image/svg+xml') throw new AppError(415, 'SVG images are refused', 'unsupportedMediaType');
  if (!ACCEPTED.has(ctype) && !ctype.startsWith('text/')) throw new AppError(415, 'This media type is not accepted', 'unsupportedMediaType');
  if (req.headers['content-encoding'] !== undefined) throw new AppError(415, 'Compressed uploads are refused', 'unsupportedMediaType');
  const declared = Number(req.headers['content-length'] ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) throw new AppError(413, 'The file is too large', 'tooLarge');
  const dir = tenantFilesDir(tenantId);
  await mkdir(dir, { recursive: true });
  const tmp = path.join(dir, `.upload-${randomUUID()}`);
  const hash = createHash('sha256');
  let size = 0;
  try {
    await new Promise<void>((resolve, reject) => {
      const out = createWriteStream(tmp, { flags: 'wx', mode: 0o640 });
      let failed = false;
      const fail = (err: Error) => { if (failed) return; failed = true; out.destroy(); req.unpipe(out); reject(err); };
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        hash.update(chunk);
        if (size > maxBytes) { fail(new AppError(413, 'The file is too large', 'tooLarge')); req.destroy(); }
      });
      req.on('error', fail);
      out.on('error', fail);
      out.on('finish', () => { if (!failed) resolve(); });
      req.pipe(out);
    });
    if (size === 0) throw new AppError(400, 'Empty upload', 'invalidRequest');
    const sha256 = hash.digest('hex');
    const final = path.join(dir, `${sha256}.bin`);
    const exists = await stat(final).then((s) => s.isFile() && s.size === size).catch(() => false);
    if (exists) await unlink(tmp).catch(() => undefined);
    else await rename(tmp, final);
    return { sha256, size };
  } catch (err) {
    await unlink(tmp).catch(() => undefined);
    throw err;
  }
}

// ── Kind of a file ───────────────────────────────────────────────────────────

/** The type of an image by its magic bytes, and its dimensions from its header (null when unreadable). */
export function imageOf(b: Buffer): { type: 'image/png' | 'image/jpeg' | 'image/gif' | 'image/x-icon'; width: number; height: number } | null {
  if (b.length >= 24 && b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return { type: 'image/png', width: b.readUInt32BE(16), height: b.readUInt32BE(20) };
  }
  if (b.length >= 10 && (b.subarray(0, 6).toString('latin1') === 'GIF87a' || b.subarray(0, 6).toString('latin1') === 'GIF89a')) {
    return { type: 'image/gif', width: b.readUInt16LE(6), height: b.readUInt16LE(8) };
  }
  if (b.length >= 22 && b.readUInt16LE(0) === 0 && b.readUInt16LE(2) === 1 && b.readUInt16LE(4) >= 1) {
    return { type: 'image/x-icon', width: b[6] || 256, height: b[7] || 256 };
  }
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
    // The first frame header (SOF0 to SOF15, DHT/JPG/DAC excepted) carries the dimensions.
    let i = 2;
    while (i + 9 < b.length) {
      if (b[i] !== 0xff) { i++; continue; }
      const marker = b[i + 1];
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { i += 2; continue; }
      const len = b.readUInt16BE(i + 2);
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return { type: 'image/jpeg', height: b.readUInt16BE(i + 5), width: b.readUInt16BE(i + 7) };
      }
      i += 2 + len;
    }
    return null;
  }
  return null;
}

/** A certificate file (PEM or DER) as PEM; null when it is not one X.509 certificate (or a PEM bundle). */
export function certificatePem(bytes: Buffer): string | null {
  if (bytes.length === 0 || bytes.length > L.pemBytes * 2) return null;
  const text = bytes.toString('latin1');
  if (text.includes('-----BEGIN CERTIFICATE-----')) {
    const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
    if (!blocks.length || blocks.length > 8) return null;
    try { blocks.forEach((p) => new X509Certificate(p)); } catch { return null; }
    const pem = `${blocks.join('\n')}\n`;
    return Buffer.byteLength(pem) <= L.pemBytes ? pem : null;
  }
  try {
    const cert = new X509Certificate(bytes);
    const pem = cert.toString();
    return Buffer.byteLength(pem) <= L.pemBytes ? pem : null;
  } catch {
    return null;
  }
}

const isCertName = (name: string): boolean => /\.(crt|pem|cer|der)$/i.test(name);

/**
 * The kind of a received file (B5, B7): an image (an image/* upload: magic bytes of PNG, JPEG, GIF or ICO, 256 KiB at
 * most, the header's dimensions within the limit; stored with the type of its magic bytes), a certificate (by its name
 * or media type: parsed as X.509, stored as PEM, 8 KiB at most), a file otherwise. A certificate received as DER is
 * stored again as PEM (its content, hence its SHA-256, changes). 422 imageInvalid / certificateInvalid.
 */
export async function settleKind(tenantId: number, received: { sha256: string; size: number }, o: { name: string; mediaType: string }):
  Promise<{ sha256: string; size: number; kind: LegacyAgentFileKind; contentType: string }> {
  const file = storedFilePath(tenantId, received.sha256);
  if (o.mediaType.startsWith('image/')) {
    if (received.size > L.imageBytes) throw new AppError(422, 'An image is 256 KiB at most', 'imageInvalid');
    const head = await readHead(file, Math.min(received.size, 64 * 1024));
    const img = imageOf(head);
    if (!img || img.width <= 0 || img.height <= 0 || img.width * img.height > L.imagePixelsMax) {
      throw new AppError(422, 'The file is not a PNG, JPEG, GIF or ICO image of an admitted size', 'imageInvalid');
    }
    return { ...received, kind: 'image', contentType: img.type };
  }
  if (o.mediaType === 'application/x-x509-ca-cert' || o.mediaType === 'application/pkix-cert' || isCertName(o.name)) {
    if (received.size > L.pemBytes * 2) throw new AppError(422, 'A certificate is 8 KiB at most', 'certificateInvalid');
    const pem = certificatePem(await readFile(file));
    if (!pem) throw new AppError(422, 'The file is not an X.509 certificate', 'certificateInvalid');
    const bytes = Buffer.from(pem, 'utf8');
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    if (sha256 !== received.sha256) await writeFile(storedFilePath(tenantId, sha256), bytes, { mode: 0o640 });
    return { sha256, size: bytes.length, kind: 'certificate', contentType: 'application/x-x509-ca-cert' };
  }
  const contentType = /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(o.mediaType) ? o.mediaType : 'application/octet-stream';
  return { ...received, kind: 'file', contentType };
}

async function readHead(file: string, n: number): Promise<Buffer> {
  const fh = await open(file, 'r');
  try {
    const buf = Buffer.alloc(n);
    const { bytesRead } = await fh.read(buf, 0, n, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

/** The bytes of a stored certificate (8 KiB at most) as text, or null when it is missing. */
export async function readStoredPem(tenantId: number, sha256: string, size: number): Promise<string | null> {
  if (size > L.pemBytes) return null;
  try {
    const b = await readFile(storedFilePath(tenantId, sha256));
    if (b.length !== size || createHash('sha256').update(b).digest('hex') !== sha256) return null;
    return b.toString('utf8');
  } catch {
    return null;
  }
}

// ── Usage and views ──────────────────────────────────────────────────────────

/**
 * How many things reference a stored file (B6): the policy versions not archived (draft, submitted, published) whose
 * content names its SHA-256, and the bodies of the artifacts a device desires that list it among their blobs or name it
 * (a CA file). In the caller's transaction (the deletion runs it under the configuration lock).
 */
export async function fileUsage(q: Knex | Knex.Transaction, tenantId: number, sha256: string): Promise<number> {
  const like = `%${sha256}%`;
  const versions = await q('policy_versions').where({ tenant_id: tenantId }).whereIn('state', ['draft', 'pending_approval', 'published'])
    .whereRaw('content::text LIKE ?', [like]).count<{ n: string }[]>('id as n').first();
  const artifacts = await q('device_artifacts as x')
    .join('mdm_artifacts as m', function j() { this.on('m.tenant_id', '=', 'x.tenant_id').andOn('m.hash', '=', 'x.desired_hash'); })
    .where({ 'x.tenant_id': tenantId, 'x.artifact_key': 'agent:policy' })
    .whereRaw("(m.body -> 'blobs' @> jsonb_build_array(?::text) OR m.body::text LIKE ?)", [sha256, like])
    .countDistinct<{ n: string }[]>('m.hash as n').first();
  return Number(versions?.n ?? 0) + Number(artifacts?.n ?? 0);
}

export function fileView(r: Record<string, any>, usedBy = 0): LegacyAgentFileView {
  return {
    id: String(r.id), sha256: String(r.sha256).trim(), sizeBytes: Number(r.size_bytes), name: r.name, contentType: r.content_type,
    kind: r.kind, origin: r.origin === 'import' ? 'import' : 'upload', note: r.note ?? null, usedBy,
    createdAt: new Date(r.created_at).toISOString(), createdBy: r.created_by ?? null,
  };
}

// ── Collection (B6) ──────────────────────────────────────────────────────────

let lastCollection = 0;

/** A minute step of the bridge agent: once an hour, per tenant in its context, the bytes no row names any more (24 hours
 *  old) and the uploads left behind (1 hour old). Never a read of another tenant's rows. */
export async function collectPolicyFiles(ctx: JobContext<Record<string, never>>): Promise<Record<string, number>> {
  if (Date.now() - lastCollection < 3_600_000) return {};
  lastCollection = Date.now();
  let removed = 0;
  const root = filesDir();
  await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const dir = path.join(root, String(tenantId));
    const names = await readdir(dir).catch(() => [] as string[]);
    if (!names.length) return;
    const known = new Set((await db('legacy_agent_files').where({ tenant_id: tenantId }).pluck('sha256') as string[]).map((s) => String(s).trim()));
    const now = Date.now();
    for (const name of names) {
      const full = path.join(dir, name);
      const st = await stat(full).catch(() => null);
      if (!st || !st.isFile()) continue;
      const age = now - st.mtimeMs;
      const bin = /^([0-9a-f]{64})\.bin$/.exec(name);
      const stale = bin ? !known.has(bin[1]) && age > 86_400_000 : name.startsWith('.upload-') && age > 3_600_000;
      if (!stale) continue;
      await unlink(full).then(() => { removed++; }, (err) => logger.warn({ tenantId, code: (err as { code?: string }).code }, 'agent files: a stale file was not removed'));
    }
  });
  const orphans = await collectDeletedTenantDirs(ctx, root);
  return { policyFilesRemoved: removed, policyFileDirsRemoved: orphans };
}

/**
 * The folders of deleted tenants: the vault keys are shredded and the rows cascade on a tenant's deletion, but its
 * bytes are plain files the deletion does not reach. A numeric folder that names no live tenant goes, once it has not
 * changed for 24 hours (a tenant created after the list was read has a greater id and is never touched). Context
 * 'none': only the list of tenant ids is read, never a row of a tenant.
 */
async function collectDeletedTenantDirs(ctx: JobContext<Record<string, never>>, root: string): Promise<number> {
  const entries = await readdir(root, { withFileTypes: true }).catch(() => []);
  const candidates = entries.filter((e) => e.isDirectory() && /^[1-9][0-9]{0,9}$/.test(e.name)).map((e) => e.name);
  if (!candidates.length) return 0;
  const live = new Set(await asNone(ctx.dbActor, () => allTenantIds()));
  const maxLive = Math.max(0, ...live);
  let removed = 0;
  for (const name of candidates) {
    ctx.throwIfAborted();
    const id = Number(name);
    if (live.has(id) || id > maxLive) continue;
    const dir = path.join(root, name);
    const st = await stat(dir).catch(() => null);
    if (!st || !st.isDirectory() || Date.now() - st.mtimeMs < 86_400_000) continue;
    await rm(dir, { recursive: true, force: true }).then(() => { removed++; },
      (err) => logger.warn({ tenantId: id, code: (err as { code?: string }).code }, 'agent files: the folder of a deleted tenant was not removed'));
  }
  return removed;
}

/** The store's root, created at start. */
export async function ensureFilesDir(): Promise<void> {
  await mkdir(filesDir(), { recursive: true });
}

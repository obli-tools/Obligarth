import { createHash, randomUUID } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import type { Request } from 'express';
import { AppError } from '../middleware/errorHandler';
import { WITHDRAWN_UPDATE_EXCLUDED_SQL } from './commands';
import { apkDir, MAX_APK_BYTES } from './config';
import { withAgentTransaction } from './session';
import { errorReply, type AgentIdentity, type Exchange, type Reply } from './surface';

// =============================================================================
// APKs (docs: agent-pont-android §4.7, PB12): stored by content under
// CUSTOM_DIR/agent-apk/<sha256>.apk (100 MiB at most), their metadata in
// legacy_agent_packages (a tenant's apps) and legacy_agent_releases (the
// versions of the agent). The server computes the SHA-256 and the size of an
// upload; the agent checks them again, with the signer (§8.6).
//   GET /agent/v1/packages/<sha256>: 200 only when an OPEN ('sent') app.install
//   or agent.update of this device names this SHA-256; else 404 notFound, the
//   same for every other reason. The sequence number is consumed.
// =============================================================================

export type PackageReply = { reply: Reply } | { size: number };

export async function handlePackage(who: AgentIdentity, ex: Exchange, sha: string): Promise<PackageReply> {
  let size = 0;
  const reply = await withAgentTransaction(who, ex, async (trx) => {
    const row = await trx('legacy_agent_commands').where({ tenant_id: who.tenantId, device_id: who.deviceId, state: 'sent' })
      .whereIn('request_type', ['app.install', 'agent.update']).whereRaw("params->>'sha256' = ?", [sha]).whereRaw(WITHDRAWN_UPDATE_EXCLUDED_SQL)
      .first('params') as { params: unknown } | undefined;
    if (!row) return errorReply(404, 'notFound', 'Not found');
    const p = (typeof row.params === 'string' ? JSON.parse(row.params) : row.params) as { size?: unknown };
    size = Number(p.size);
    return { status: 200, body: {} };
  });
  if (reply.status !== 200) return { reply };
  return { size };
}

/**
 * GET /agent/v1/files/<sha256> (lot PONT-POL §8.3): 200 only when the body of the device's desired artifact agent:policy
 * lists this SHA-256 among its blobs and the tenant's store holds it; else 404 notFound, the same for another device,
 * another tenant, an unknown file or a file of an older policy. The sequence number is consumed.
 */
export async function handleFile(who: AgentIdentity, ex: Exchange, sha: string): Promise<PackageReply> {
  let size = 0;
  const reply = await withAgentTransaction(who, ex, async (trx) => {
    const row = await trx('device_artifacts as x')
      .join('mdm_artifacts as m', function j() { this.on('m.tenant_id', '=', 'x.tenant_id').andOn('m.hash', '=', 'x.desired_hash'); })
      .join('legacy_agent_files as f', function j() { this.on('f.tenant_id', '=', 'x.tenant_id').andOnVal('f.sha256', '=', sha); })
      .where({ 'x.tenant_id': who.tenantId, 'x.device_id': who.deviceId, 'x.artifact_key': 'agent:policy' })
      .whereRaw("m.body -> 'blobs' @> jsonb_build_array(?::text)", [sha])
      .first('f.size_bytes') as { size_bytes: string | number } | undefined;
    if (!row) return errorReply(404, 'notFound', 'Not found');
    size = Number(row.size_bytes);
    return { status: 200, body: {} };
  });
  if (reply.status !== 200) return { reply };
  return { size };
}

/** Receives an APK upload (raw body, application/vnd.android.package-archive): stored by content, its SHA-256 and
 *  size computed here. A file already stored with the same content is kept as is. */
export async function receiveApk(req: Request): Promise<{ sha256: string; size: number }> {
  const ctype = String(req.headers['content-type'] ?? '').toLowerCase().split(';')[0].trim();
  if (ctype !== 'application/vnd.android.package-archive' && ctype !== 'application/octet-stream') {
    throw new AppError(415, 'Send the APK as application/vnd.android.package-archive', 'unsupportedMediaType');
  }
  if (req.headers['content-encoding'] !== undefined) throw new AppError(415, 'Compressed uploads are refused', 'unsupportedMediaType');
  const declared = Number(req.headers['content-length'] ?? NaN);
  if (Number.isFinite(declared) && declared > MAX_APK_BYTES) throw new AppError(413, 'The APK is larger than 100 MiB', 'tooLarge');
  const dir = apkDir();
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
        if (size > MAX_APK_BYTES) { fail(new AppError(413, 'The APK is larger than 100 MiB', 'tooLarge')); req.destroy(); }
      });
      req.on('error', fail);
      out.on('error', fail);
      out.on('finish', () => { if (!failed) resolve(); });
      req.pipe(out);
    });
    if (size === 0) throw new AppError(400, 'Empty upload', 'invalidRequest');
    const sha256 = hash.digest('hex');
    // An APK is a ZIP archive: 'PK\x03\x04' (the agent checks the rest).
    const final = path.join(dir, `${sha256}.apk`);
    const exists = await stat(final).then((s) => s.isFile() && s.size === size).catch(() => false);
    if (exists) await unlink(tmp).catch(() => undefined);
    else await rename(tmp, final);
    return { sha256, size };
  } catch (err) {
    await unlink(tmp).catch(() => undefined);
    throw err;
  }
}

/** Checks the first bytes of a stored APK (a ZIP archive). */
export async function looksLikeApk(sha256: string): Promise<boolean> {
  const { open } = await import('node:fs/promises');
  const fh = await open(path.join(apkDir(), `${sha256}.apk`), 'r').catch(() => null);
  if (!fh) return false;
  try {
    const buf = Buffer.alloc(4);
    await fh.read(buf, 0, 4, 0);
    return buf.equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  } finally {
    await fh.close();
  }
}

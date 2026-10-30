import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { appendFile, mkdir, open, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { LEGACY_AGENT_PACKAGE, LEGACY_AGENT_PULL_CHUNK_BYTES } from '@obligarth/shared';
import { z } from 'zod';
import { audit } from '../audit';
import { LEGACY_AGENT_ACTOR } from './actor';
import { apkDir, MAX_APK_BYTES } from './config';
import { withAgentTransaction } from './session';
import { errorReply, type AgentIdentity, type Exchange, type Reply } from './surface';

// =============================================================================
// POST /agent/v1/pull/<commandId> (agent 1.2.0, app.pull): the APK of an app
// installed on the device, sent back by chunks of LEGACY_AGENT_PULL_CHUNK_BYTES
// at most (base64 in a signed, numbered JSON body). Taken only for an OPEN
// ('sent') app.pull of THIS device; the chunks are appended in order to
// CUSTOM_DIR/agent-apk/.pull-<commandId> (an offset other than the size
// received so far is answered with that size, the agent resumes there). The
// last chunk closes it: the size and the SHA-256 announced must hold and the
// file must be a ZIP archive, then it joins the store by content and becomes
// a package of the tenant (created by the author of the command, none for the
// harvest job; its source device kept; audited legacy_agent.package_pulled). The command's result comes by /poll (pulled).
// The packageName stored is the command's, never the body's.
// =============================================================================

const SHA_RE = /^[0-9a-f]{64}$/;
const B64_STD = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export const PullBody = z.object({
  offset: z.number().int().min(0).max(MAX_APK_BYTES),
  total: z.number().int().min(1).max(MAX_APK_BYTES),
  sha256: z.string().regex(SHA_RE),
  versionCode: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  versionName: z.string().max(64).nullable().optional(),
  signerSha256: z.string().regex(SHA_RE).nullable().optional(),
  data: z.string().max(Math.ceil(LEGACY_AGENT_PULL_CHUNK_BYTES / 3) * 4),
}).strict();

/** JSON around a full chunk: base64 of 1 MiB plus the fields. */
export const MAX_PULL_BODY = Math.ceil(LEGACY_AGENT_PULL_CHUNK_BYTES / 3) * 4 + 4096;

const partOf = (commandId: string): string => path.join(apkDir(), `.pull-${commandId}`);

async function sizeOf(file: string): Promise<number> {
  const s = await stat(file).catch(() => null);
  return s && s.isFile() ? s.size : 0;
}

async function sha256Of(file: string): Promise<string> {
  const hash = createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const s = createReadStream(file);
    s.on('data', (c) => hash.update(c));
    s.on('error', reject);
    s.on('end', () => resolve());
  });
  return hash.digest('hex');
}

async function isZip(file: string): Promise<boolean> {
  const fh = await open(file, 'r').catch(() => null);
  if (!fh) return false;
  try {
    const buf = Buffer.alloc(4);
    await fh.read(buf, 0, 4, 0);
    return buf.equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  } finally {
    await fh.close();
  }
}

export async function handlePull(who: AgentIdentity, ex: Exchange, commandId: string, raw: Buffer): Promise<Reply> {
  let json: unknown;
  try { json = JSON.parse(raw.toString('utf8')); } catch { return errorReply(400, 'badRequest', 'Malformed JSON'); }
  const parsed = PullBody.safeParse(json);
  if (!parsed.success) return errorReply(400, 'badRequest', `Invalid body: ${parsed.error.issues[0]?.path.join('.') ?? ''}`.slice(0, 200));
  const b = parsed.data;
  if (!B64_STD.test(b.data)) return errorReply(400, 'badRequest', 'Invalid body: data');
  const bytes = Buffer.from(b.data, 'base64');
  if (bytes.length === 0 || bytes.length > LEGACY_AGENT_PULL_CHUNK_BYTES || b.offset + bytes.length > b.total) {
    return errorReply(400, 'badRequest', 'Invalid body: data');
  }

  return withAgentTransaction(who, ex, async (trx) => {
    const cmd = await trx('legacy_agent_commands').where({ tenant_id: who.tenantId, id: commandId, device_id: who.deviceId, request_type: 'app.pull', state: 'sent' })
      .first('params', 'requested_by') as { params: unknown; requested_by: number | null } | undefined;
    if (!cmd) return errorReply(404, 'notFound', 'Not found');
    const p = (typeof cmd.params === 'string' ? JSON.parse(cmd.params) : cmd.params) as { packageName?: unknown };
    const packageName = String(p.packageName ?? '');
    if (!packageName || packageName === LEGACY_AGENT_PACKAGE || packageName.startsWith(`${LEGACY_AGENT_PACKAGE}.`)) return errorReply(404, 'notFound', 'Not found');

    await mkdir(apkDir(), { recursive: true });
    const part = partOf(commandId);
    // A new transfer (offset 0) starts the file again; any other offset must follow what was received.
    if (b.offset === 0) await unlink(part).catch(() => undefined);
    const have = await sizeOf(part);
    if (b.offset !== have) return { status: 200, body: { received: have, complete: false } };
    await appendFile(part, bytes, { mode: 0o640 });
    const received = have + bytes.length;
    if (received < b.total) return { status: 200, body: { received, complete: false } };

    const sha = await sha256Of(part);
    if (sha !== b.sha256 || !(await isZip(part))) {
      await unlink(part).catch(() => undefined);
      return errorReply(400, 'badRequest', sha !== b.sha256 ? 'The SHA-256 of the file does not match' : 'This file is not an APK (ZIP archive)');
    }
    const final = path.join(apkDir(), `${sha}.apk`);
    if ((await sizeOf(final)) === b.total) await unlink(part).catch(() => undefined);
    else await rename(part, final);

    let row = await trx('legacy_agent_packages').where({ tenant_id: who.tenantId, sha256: sha }).first('id') as { id: string } | undefined;
    if (!row) {
      [row] = await trx('legacy_agent_packages').insert({
        tenant_id: who.tenantId, package_name: packageName, version_code: b.versionCode, version_name: b.versionName ?? null, sha256: sha,
        size_bytes: b.total, signer_sha256: b.signerSha256 ?? null, label: null, created_by: cmd.requested_by ?? null,
        source_device_id: who.deviceId,
      }).returning('id') as Array<{ id: string }>;
      const ctx = await audit.fromDbActor(LEGACY_AGENT_ACTOR, who.tenantId);
      await audit.appendInTx(trx, {
        tenantId: who.tenantId, action: 'legacy_agent.package_pulled', target: { type: 'legacy_agent_package', id: String(row.id) },
        links: { command: commandId }, details: { packageName, versionCode: b.versionCode, sha256: sha, size: b.total, deviceId: who.deviceId },
      }, ctx, { onFailure: 'spool' });
    }
    return { status: 200, body: { received, complete: true, packageId: String(row.id) } };
  });
}

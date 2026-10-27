import { createHash, randomUUID } from 'node:crypto';
import { createReadStream, createWriteStream, readFileSync } from 'node:fs';
import { mkdir, open, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { z } from 'zod';
import { MASTER_TENANT_ID, type LegacyAgentBundleRefusal, type LegacyAgentBundleStatus } from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { asNone, switchToIdentity } from '../db/context';
import { logger } from '../utils/logger';
import { legacyAgentJobActor } from './actor';
import { apkSignersOfFile, ApkFormatError, signedOnlyBy } from './apkSigner';
import { apkDir, bundleDir, MAX_APK_BYTES, signersFromEnv } from './config';

// =============================================================================
// The version of the bridge agent embedded in the server image (lot AGENT-RU
// T1): the update of the instance (RegularUpdate) drops the signed APK of the
// agent and its description in /app/server/agent-release/:
//   obligarth-agent.apk   the release build, signed by obligarth-agent
//   release.json          { versionCode, versionName, sha256, signerSha256 }
// At start (start task legacy-agent.bundled-release, after the migrations),
// when present: the description is read strictly; the signer must be in
// LEGACY_AGENT_SIGNERS (nothing is copied otherwise); the APK is copied to a
// temporary file of the store by content, its SHA-256 computed on the way
// and compared with the description; a ZIP archive whose APK Signature
// Scheme v2/v3 block names this signer alone (apkSigner.ts; the agent checks
// the signature itself, and its own pinned signers, before installing); then
// renamed to <sha256>.apk and recorded in legacy_agent_releases (origin
// 'bundled', created_by NULL, bundled_in = the version of the image) in ONE
// transaction with its audit entry (legacy_agent.release_bundled, actor
// j:legacy-agent.bundled-release) when no version has its versionCode:
// idempotent, and safe when several instances start together (ON CONFLICT DO
// NOTHING, the loser reads the winner's row). Never an update of an existing
// row: a withdrawn version stays withdrawn, another APK under a known
// versionCode (or the same APK under another one) is refused. A refusal is
// logged and kept for the console (GET /api/admin/legacy-agent/settings),
// never fatal: the server starts. A failure is told apart the same way: the
// store of the APKs (a file error: full or read-only volume, rights) or the
// database; both are tried again at the next start.
// =============================================================================

export const BUNDLED_APK = 'obligarth-agent.apk';
export const BUNDLED_MANIFEST = 'release.json';
const MAX_MANIFEST_BYTES = 4096;
const TASK = 'legacy-agent.bundled-release';
const ACTOR = legacyAgentJobActor(TASK);

const Manifest = z.object({
  versionCode: z.number().int().min(1).max(2_000_000_000),
  versionName: z.string().trim().min(1).max(32).regex(/^[0-9A-Za-z.+_-]+$/),
  sha256: z.string().transform((s) => s.trim().toLowerCase()).pipe(z.string().regex(/^[0-9a-f]{64}$/)),
  signerSha256: z.string().transform((s) => s.trim().replace(/:/g, '').toLowerCase()).pipe(z.string().regex(/^[0-9a-f]{64}$/)),
}).strict();
type Manifest = z.infer<typeof Manifest>;

let imageVersionCache: string | null = null;

/** The version of the server image (server/package.json, read from the working directory like app.ts); 'dev' when
 *  unreadable. Only the characters the column admits are kept. */
export function imageVersion(): string {
  if (imageVersionCache) return imageVersionCache;
  let v = 'dev';
  try {
    const pkg = JSON.parse(readFileSync(path.join(process.cwd(), 'package.json'), 'utf-8')) as { version?: unknown };
    if (typeof pkg.version === 'string' && /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$/.test(pkg.version)) v = pkg.version;
  } catch { /* 'dev' */ }
  imageVersionCache = v;
  return v;
}

let last: LegacyAgentBundleStatus | null = null;

/** What the start of this server found in its image (null before the start task ran). */
export function bundleStatus(): LegacyAgentBundleStatus | null {
  return last;
}

function outcome(state: LegacyAgentBundleStatus['state'], m: Partial<Manifest> | null, reason: LegacyAgentBundleRefusal | null = null): LegacyAgentBundleStatus {
  last = {
    state, reason, versionCode: m?.versionCode ?? null, versionName: m?.versionName ?? null, imageVersion: imageVersion(),
    checkedAt: new Date().toISOString(),
  };
  return last;
}

async function isFile(file: string): Promise<{ size: number } | null> {
  return stat(file).then((s) => (s.isFile() ? { size: s.size } : null)).catch(() => null);
}

/** The description of the bundle; null: unreadable or invalid (never more than 4 KiB read). */
async function readManifest(file: string): Promise<Manifest | null> {
  const fh = await open(file, 'r').catch(() => null);
  if (!fh) return null;
  let text: string;
  try {
    const buf = Buffer.alloc(MAX_MANIFEST_BYTES + 1);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    if (bytesRead > MAX_MANIFEST_BYTES) return null;
    text = buf.subarray(0, bytesRead).toString('utf8');
  } finally {
    await fh.close();
  }
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { return null; }
  const parsed = Manifest.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

/** Copies the bundled APK into a temporary file of the store, its SHA-256 computed on the way. */
async function stage(source: string): Promise<{ tmp: string; sha256: string; size: number }> {
  const dir = apkDir();
  await mkdir(dir, { recursive: true });
  const tmp = path.join(dir, `.bundle-${randomUUID()}`);
  const hash = createHash('sha256');
  let size = 0;
  const input = createReadStream(source);
  input.on('data', (chunk) => { size += chunk.length; hash.update(chunk); });
  try {
    await pipeline(input, createWriteStream(tmp, { flags: 'wx', mode: 0o640 }));
  } catch (err) {
    await unlink(tmp).catch(() => undefined);
    throw err;
  }
  return { tmp, sha256: hash.digest('hex'), size };
}

async function startsLikeZip(file: string): Promise<boolean> {
  const fh = await open(file, 'r');
  try {
    const buf = Buffer.alloc(4);
    const { bytesRead } = await fh.read(buf, 0, 4, 0);
    return bytesRead === 4 && buf.equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  } finally {
    await fh.close();
  }
}

/** Checks the staged copy; null when it is the version described. */
async function verify(tmp: string, staged: { sha256: string }, m: Manifest): Promise<LegacyAgentBundleRefusal | null> {
  if (staged.sha256 !== m.sha256) return 'sha256Mismatch';
  if (!(await startsLikeZip(tmp))) return 'notAnApk';
  try {
    if (!signedOnlyBy(await apkSignersOfFile(tmp), m.signerSha256)) return 'signerMismatch';
  } catch (err) {
    if (err instanceof ApkFormatError) return 'signerMismatch';
    throw err;
  }
  return null;
}

/** Puts the verified copy at its place in the store (a file already there with the same content is kept). */
async function place(tmp: string, sha256: string, size: number): Promise<void> {
  const final = path.join(apkDir(), `${sha256}.apk`);
  const there = await isFile(final);
  if (there && there.size === size) await unlink(tmp).catch(() => undefined);
  else await rename(tmp, final);
}

/** Stages, verifies and places the bundled APK in the store: its size, or why it is refused (no file left behind). */
async function stageVerified(apk: string, m: Manifest): Promise<{ size: number } | LegacyAgentBundleRefusal> {
  const staged = await stage(apk);
  let why: LegacyAgentBundleRefusal | null;
  try {
    why = await verify(staged.tmp, staged, m);
    if (!why) await place(staged.tmp, staged.sha256, staged.size);
  } catch (err) {
    await unlink(staged.tmp).catch(() => undefined);
    throw err;
  }
  if (why) {
    await unlink(staged.tmp).catch(() => undefined);
    return why;
  }
  return { size: staged.size };
}

interface ReleaseRow { id: string; version_code: number; sha256: string; withdrawn_at: Date | null }

/** What a row of the catalog means for the bundle. */
function compare(row: ReleaseRow, m: Manifest): 'present' | 'withdrawn' | 'versionConflict' {
  if (Number(row.version_code) !== m.versionCode || String(row.sha256) !== m.sha256) return 'versionConflict';
  return row.withdrawn_at ? 'withdrawn' : 'present';
}

async function existing(m: Manifest): Promise<ReleaseRow | undefined> {
  return db('legacy_agent_releases').where({ version_code: m.versionCode }).orWhere({ sha256: m.sha256 })
    .orderByRaw('(version_code = ?) DESC', [m.versionCode]).first('id', 'version_code', 'sha256', 'withdrawn_at') as Promise<ReleaseRow | undefined>;
}

/** A file error of Node (it names its system call), as opposed to an error of the database. */
function isFileError(err: unknown): boolean {
  return typeof (err as NodeJS.ErrnoException | null)?.syscall === 'string';
}

/**
 * Registers the version embedded in the image (start task legacy-agent.bundled-release; also called by the tests).
 * Never throws for a refused bundle: the outcome says why. A failure is logged: the outcome is 'storeError' for the
 * store of the APKs (a file error), 'error' for the database.
 */
export async function registerBundledRelease(): Promise<LegacyAgentBundleStatus> {
  return asNone(ACTOR, async () => {
    const dir = bundleDir();
    const apk = path.join(dir, BUNDLED_APK);
    const manifestFile = path.join(dir, BUNDLED_MANIFEST);
    const [apkStat, manifestStat] = await Promise.all([isFile(apk), isFile(manifestFile)]);
    if (!apkStat && !manifestStat) return outcome('absent', null);
    const m = manifestStat ? await readManifest(manifestFile) : null;
    if (!m) return refuse(null, 'manifestInvalid');
    if (!apkStat) return refuse(m, 'apkMissing');
    if (apkStat.size === 0 || apkStat.size > MAX_APK_BYTES) return refuse(m, 'apkTooLarge');
    if (!signersFromEnv().signers.includes(m.signerSha256)) return refuse(m, 'signerNotAdmitted');

    try {
      const known = await existing(m);
      if (known) {
        const state = compare(known, m);
        if (state === 'versionConflict') return refuse(m, 'versionConflict');
        // Registered already: the store keeps its file (put back when the volume lost it, after the same checks).
        const there = await isFile(path.join(apkDir(), `${m.sha256}.apk`));
        if (!there) {
          const staged = await stageVerified(apk, m);
          if (typeof staged === 'string') return refuse(m, staged);
        }
        return outcome(state, m);
      }

      const staged = await stageVerified(apk, m);
      if (typeof staged === 'string') return refuse(m, staged);

      const ctx = await audit.fromDbActor(ACTOR, MASTER_TENANT_ID);
      const image = imageVersion();
      const inserted = await switchToIdentity(() => db.transaction(async (trx) => {
        const rows = await trx('legacy_agent_releases').insert({
          version_code: m.versionCode, version_name: m.versionName, sha256: m.sha256, size_bytes: staged.size, signer_sha256: m.signerSha256,
          notes: null, created_by: null, origin: 'bundled', bundled_in: image,
        }).onConflict().ignore().returning('id') as Array<{ id: string }>;
        if (rows.length === 0) return null;
        const id = String(rows[0].id);
        await audit.appendInTx(trx, {
          tenantId: MASTER_TENANT_ID, action: 'legacy_agent.release_bundled', target: { type: 'legacy_agent_release', id },
          details: { versionCode: m.versionCode, versionName: m.versionName, sha256: m.sha256, size: staged.size, signerSha256: m.signerSha256, image },
        }, ctx);
        return id;
      }));
      if (inserted) {
        logger.info({ versionCode: m.versionCode, versionName: m.versionName, image }, 'legacy agent: version embedded in the image registered');
        return outcome('registered', m);
      }
      // Another instance (or start) registered a version meanwhile: its row decides.
      const winner = await existing(m);
      if (!winner) throw new Error('legacy_agent_releases: insert ignored without a conflicting row');
      const state = compare(winner, m);
      return state === 'versionConflict' ? refuse(m, 'versionConflict') : outcome(state, m);
    } catch (err) {
      const store = isFileError(err);
      logger.error({ code: (err as { code?: unknown })?.code, store, message: (err as Error)?.message?.slice(0, 200) },
        store ? 'legacy agent: the version embedded in the image was not copied to the store of the APKs'
          : 'legacy agent: the version embedded in the image was not registered');
      return outcome(store ? 'storeError' : 'error', m);
    }
  });
}

function refuse(m: Manifest | null, reason: LegacyAgentBundleRefusal): LegacyAgentBundleStatus {
  logger.warn({ reason, versionCode: m?.versionCode ?? null }, 'legacy agent: the version embedded in the image is refused');
  return outcome('refused', m, reason);
}

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { BENCH_OWNER_MIN_VERSION_CODE, type BenchServedRelease } from '@obligarth/shared';
import { db } from '../db';
import { apkDir, signersFromEnv } from '../legacyAgent/config';

// =============================================================================
// The APK served to the bench stations (lot BANC §3.9, D23) and the installer of the station next to the server image.
//   APK   the version marked bench_served (chosen explicitly by a platform administrator, never withdrawn), uploaded or
//         embedded, its signer admitted (LEGACY_AGENT_SIGNERS); read from the store of the APKs, its SHA-256 computed
//         again at its first read and compared to the database (500 apk_mismatch otherwise). The station trusts none
//         of it: it compares the signer to the fingerprint pinned in its binary.
//   MSI   BENCH_ARTEFACT_DIR (default <server>/bench-release, /app/server/bench-release in the image):
//         obligarth-bench.msi and VERSION; its hash cached by (size, mtime); an absent folder is available:false.
// =============================================================================

/** The agent's minimal API level (agent-android/app/build.gradle.kts). */
export const AGENT_MIN_SDK = 24;

export interface ServedApk extends BenchServedRelease { signerSha256: string; size: number; file: string }

export async function servedRelease(): Promise<ServedApk | null> {
  const r = await db('legacy_agent_releases').where({ bench_served: true }).whereNull('withdrawn_at')
    .first('id', 'version_code', 'version_name', 'sha256', 'signer_sha256', 'size_bytes') as Record<string, any> | undefined;
  if (!r) return null;
  const sha256 = String(r.sha256).trim();
  return {
    releaseId: String(r.id), versionCode: Number(r.version_code), versionName: String(r.version_name), sha256,
    deviceOwnerCapable: Number(r.version_code) >= BENCH_OWNER_MIN_VERSION_CODE,
    signerSha256: String(r.signer_sha256).trim(), size: Number(r.size_bytes), file: path.join(apkDir(), `${sha256}.apk`),
  };
}

/** The signer of the served version is still admitted by the instance. */
export const signerAdmitted = (signerSha256: string): boolean => signersFromEnv().signers.includes(signerSha256);

const verified = new Map<string, string>();

async function sha256OfFile(file: string): Promise<string> {
  const h = createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    createReadStream(file).on('data', (c) => h.update(c)).on('error', reject).on('end', () => resolve());
  });
  return h.digest('hex');
}

/** The file of the served APK checked against its SHA-256 (once per size and modification time); 'missing' or
 *  'mismatch' otherwise. */
export async function checkedApk(apk: ServedApk): Promise<{ ok: true; size: number } | { ok: false; reason: 'missing' | 'mismatch' }> {
  const st = await stat(apk.file).catch(() => null);
  if (!st || !st.isFile()) return { ok: false, reason: 'missing' };
  const key = `${apk.file}|${st.size}|${st.mtimeMs}`;
  if (verified.get(key) !== apk.sha256) {
    const sha = await sha256OfFile(apk.file);
    if (sha !== apk.sha256) return { ok: false, reason: 'mismatch' };
    verified.set(key, sha);
    if (verified.size > 64) verified.delete(verified.keys().next().value as string);
  }
  return { ok: true, size: st.size };
}

// ── The installer of the station ─────────────────────────────────────────────

export const BENCH_MSI = 'obligarth-bench.msi' as const;

export function benchArtefactDir(): string {
  return path.resolve(process.env.BENCH_ARTEFACT_DIR || path.join(process.cwd(), 'bench-release'));
}

const msiCache = new Map<string, string>();

export interface InstallerState { version: string | null; available: boolean; sha256: string | null; size: number | null; file: string }

export async function installerState(): Promise<InstallerState> {
  const dir = benchArtefactDir();
  const file = path.join(dir, BENCH_MSI);
  const st = await stat(file).catch(() => null);
  const versionText = await readFile(path.join(dir, 'VERSION'), 'utf8').catch(() => null);
  const version = versionText && /^[0-9A-Za-z.+_-]{1,32}$/.test(versionText.trim()) ? versionText.trim() : null;
  if (!st || !st.isFile() || st.size <= 0 || !version) return { version, available: false, sha256: null, size: null, file };
  const key = `${st.size}|${st.mtimeMs}`;
  let sha = msiCache.get(key) ?? null;
  if (!sha) {
    sha = await sha256OfFile(file);
    msiCache.clear();
    msiCache.set(key, sha);
  }
  return { version, available: true, sha256: sha, size: st.size, file };
}

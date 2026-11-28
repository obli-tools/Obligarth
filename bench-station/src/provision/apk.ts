import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { apkSignersOfFile, signedOnlyBy } from '../../../server/src/legacyAgent/apkSigner';
import type { BenchAppResultCode } from '../../../shared/src/mdm/bench';
import { BenchApiError } from '../benchApi';
import { v1SignersOfFile } from './apkV1';

/**
 * Obligarth bench station — the agent's APK on this PC (lot BANC §6.3, §6.4).
 *
 * ┌─ THE SERVER IS NOT TRUSTED FOR THE SIGNER ───────────────────────────────┐
 * │ The fingerprint of the agent's signing certificate is PINNED in this     │
 * │ binary (pins.ts, read off obligarth-agent.jks's pin at build time). An   │
 * │ APK is used only when its v2 block names that certificate alone; what    │
 * │ the server announces (`signerSha256`) is a consistency check and must    │
 * │ match the pin too. Same rule for the package INSTALLED on a device       │
 * │ (`pm path` + `adb pull` of base.apk): another signer is                  │
 * │ `agent_foreign_signer`, and the station never uninstalls anything.        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Cache: apk-cache\<sha256>.apk, checked again (SHA-256 and signer) every time it is used.
 */

export const sha256OfFile = (file: string): Promise<string> => new Promise((resolve, reject) => {
  const h = createHash('sha256');
  createReadStream(file).on('data', (c) => h.update(c)).on('error', reject).on('end', () => resolve(h.digest('hex')));
});

/** The signer of an APK file: the v2/v3 blocks first, the JAR signature when there is none. `null`: unreadable or
 *  several signers. */
export async function signerOfApk(file: string): Promise<string | null> {
  try {
    const s = await apkSignersOfFile(file);
    const blocks = [s.v2, s.v3].filter((b): b is string[] => b !== null);
    if (blocks.length > 0) {
      const first = blocks[0][0];
      return first && signedOnlyBy(s, first) ? first : null;
    }
    const v1 = await v1SignersOfFile(file);
    return v1.length === 1 ? v1[0] : null;
  } catch {
    return null;
  }
}

export interface ServedAgent {
  versionCode: number;
  versionName: string;
  sha256: string;
  signerSha256: string;
  size: number;
  minSdk: number;
  deviceOwnerCapable: boolean;
}

export type ApkCheck = { ok: true; file: string } | { ok: false; code: 'apk_mismatch'; reason: string };

/** The checks under way, by cache file: the cards that reach `install` together share one download and one check. */
const inFlight = new Map<string, Promise<ApkCheck>>();

/** Downloads (when needed) and checks the served APK; `download` writes the bytes to the path it is given. One check at
 *  a time per APK (the cards share it), each download into a temporary file of its own. */
export function ensureServedApk(
  cacheDir: string,
  served: ServedAgent,
  pin: string | null,
  download: (dest: string) => Promise<void>,
): Promise<ApkCheck> {
  const key = join(cacheDir, `${served.sha256}.apk`);
  const running = inFlight.get(key);
  if (running) return running;
  const p = checkServedApk(cacheDir, served, pin, download).finally(() => inFlight.delete(key));
  inFlight.set(key, p);
  return p;
}

async function checkServedApk(
  cacheDir: string,
  served: ServedAgent,
  pin: string | null,
  download: (dest: string) => Promise<void>,
): Promise<ApkCheck> {
  if (!pin || !/^[0-9a-f]{64}$/.test(pin)) return { ok: false, code: 'apk_mismatch', reason: 'no_pin' };
  if (served.signerSha256.toLowerCase() !== pin) return { ok: false, code: 'apk_mismatch', reason: 'announced_signer' };
  if (!/^[0-9a-f]{64}$/.test(served.sha256)) return { ok: false, code: 'apk_mismatch', reason: 'sha256' };
  mkdirSync(cacheDir, { recursive: true });
  const file = join(cacheDir, `${served.sha256}.apk`);
  if (!existsSync(file)) {
    const part = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.part`;
    try {
      await download(part);
      if (statSync(part).size !== served.size) throw new Error('size');
      if ((await sha256OfFile(part)) !== served.sha256) throw new Error('sha256');
      renameSync(part, file);
    } catch (err) {
      rmSync(part, { force: true });
      return { ok: false, code: 'apk_mismatch', reason: err instanceof Error ? err.message.slice(0, 60) : 'download' };
    }
  }
  if ((await sha256OfFile(file)) !== served.sha256) {
    rmSync(file, { force: true });
    return { ok: false, code: 'apk_mismatch', reason: 'cache_sha256' };
  }
  const signer = await signerOfApk(file);
  if (signer !== pin) return { ok: false, code: 'apk_mismatch', reason: 'signer' };
  return { ok: true, file };
}

// ── The required apps (lot BANC-A) ─────────────────────────────────────────────
//
// An app the policy of the device requires, downloaded from the server (GET /v1/packages/:sha256?provisioning=) into the
// same cache (apk-cache\<sha256>.apk), checked before every install:
//   - its size and its SHA-256 against the ones of the list (the server re-checks the file before serving it, and the
//     download checks the stream again): another file is app_sha_mismatch and is never installed;
//   - its signer against `signerSha256` when the store knows it: the certificates of the v2/v3 blocks (the v1 JAR
//     signature when there is none), read here in TypeScript (apksigner is not on the PC), the SHA-256 of each first
//     certificate. One of them must be the declared one (a v3 rotation names the new certificate, v2 the old one);
//     none is app_signer_mismatch. Unreadable (no block this code understands): the SHA-256 of the file served by the
//     server is relied on, and the card's raw log says so. Unknown to the store (null): the SHA-256 alone.
// The certificates are read, not verified: Android verifies the signature itself at the install.

/** An app file larger than this is refused (the store takes 100 MiB at most). */
export const APP_MAX_BYTES = 200 * 1024 * 1024;

export interface AppApkSpec { sha256: string; size: number; signerSha256: string | null }

export type AppApkCheck =
  | { ok: true; file: string; signer: 'match' | 'unread' | 'unknown' }
  | { ok: false; code: BenchAppResultCode; reason: string };

/** Every signer an APK names: the first certificate of each signer of its v2 and v3 blocks, or of its v1 signature
 *  blocks when it has no v2/v3 block (Android ignores v1 then). [] when nothing could be read. */
export async function apkSignerSet(file: string): Promise<string[]> {
  const out = new Set<string>();
  try {
    const s = await apkSignersOfFile(file);
    for (const b of [s.v2, s.v3]) for (const x of b ?? []) out.add(x.toLowerCase());
  } catch { /* no signing block this code reads */ }
  if (out.size === 0) {
    try { for (const x of await v1SignersOfFile(file)) out.add(x.toLowerCase()); } catch { /* none */ }
  }
  return [...out];
}

const appInFlight = new Map<string, Promise<AppApkCheck>>();

/** Downloads (when needed) and checks the file of a required app; one check at a time per file (the cards share it).
 *  A refusal of the station itself (401/403) and a temporary failure (downloadIsTemporary) are thrown: the card holds on
 *  them (Retry resumes the step apps, the apps already installed kept); any other failure is the app's code. */
export function ensureAppApk(cacheDir: string, app: AppApkSpec, download: (dest: string) => Promise<void>): Promise<AppApkCheck> {
  const key = `${join(cacheDir, `${app.sha256}.apk`)}|${app.signerSha256 ?? ''}`;
  const running = appInFlight.get(key);
  if (running) return running;
  const p = checkAppApk(cacheDir, app, download).finally(() => appInFlight.delete(key));
  appInFlight.set(key, p);
  return p;
}

/** A failure of a download that says nothing of the app: the server unreachable (a network error, a time-out, the stream
 *  cut), a 5xx other than apk_mismatch, a redirection or the rate still refused after the retries (429). Never app_download_failed: the run holds, the step stays to do. */
export function downloadIsTemporary(err: unknown): boolean {
  if (!(err instanceof BenchApiError)) return false;
  if (err.code === 'apk_mismatch') return false;
  return err.code === 'server_unreachable' || err.code === 'redirected' || err.code === 'rate_limited'
    || err.status === 429 || err.status >= 500;
}

function downloadFailure(err: unknown): AppApkCheck {
  if (err instanceof BenchApiError) {
    if (err.status === 404 || err.code === 'apk_unavailable') return { ok: false, code: 'app_unavailable', reason: err.code };
    if (err.code === 'apk_mismatch') return { ok: false, code: 'app_sha_mismatch', reason: err.message.slice(0, 60) };
    return { ok: false, code: 'app_download_failed', reason: err.code };
  }
  const m = err instanceof Error ? err.message.slice(0, 60) : 'download';
  return { ok: false, code: m === 'size' || m === 'sha256' ? 'app_sha_mismatch' : 'app_download_failed', reason: m };
}

async function checkAppApk(cacheDir: string, app: AppApkSpec, download: (dest: string) => Promise<void>): Promise<AppApkCheck> {
  if (!/^[0-9a-f]{64}$/.test(app.sha256)) return { ok: false, code: 'app_sha_mismatch', reason: 'sha256' };
  if (!Number.isSafeInteger(app.size) || app.size <= 0 || app.size > APP_MAX_BYTES) return { ok: false, code: 'app_invalid_apk', reason: 'size' };
  const declared = app.signerSha256 ? app.signerSha256.replace(/:/g, '').toLowerCase() : null;
  if (declared !== null && !/^[0-9a-f]{64}$/.test(declared)) return { ok: false, code: 'app_signer_mismatch', reason: 'declared' };
  mkdirSync(cacheDir, { recursive: true });
  const file = join(cacheDir, `${app.sha256}.apk`);
  if (!existsSync(file)) {
    const part = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.part`;
    try {
      await download(part);
      if (statSync(part).size !== app.size) throw new Error('size');
      if ((await sha256OfFile(part)) !== app.sha256) throw new Error('sha256');
      renameSync(part, file);
    } catch (err) {
      rmSync(part, { force: true });
      if (err instanceof BenchApiError && err.code === 'station_refused') throw err;
      if (downloadIsTemporary(err)) throw err;
      return downloadFailure(err);
    }
  }
  if ((await sha256OfFile(file)) !== app.sha256) {
    rmSync(file, { force: true });
    return { ok: false, code: 'app_sha_mismatch', reason: 'cache_sha256' };
  }
  if (declared === null) return { ok: true, file, signer: 'unknown' };
  const signers = await apkSignerSet(file);
  if (signers.length === 0) return { ok: true, file, signer: 'unread' };
  if (!signers.includes(declared)) return { ok: false, code: 'app_signer_mismatch', reason: 'signer' };
  return { ok: true, file, signer: 'match' };
}

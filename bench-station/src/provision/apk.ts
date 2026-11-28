import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { apkSignersOfFile, signedOnlyBy } from '../../../server/src/legacyAgent/apkSigner';
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

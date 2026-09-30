import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// ── Agent dist folder (agent/dist, baked into the server image) ─────────────
//
// The files /api/agent/download serves. Their SHA-256 is computed once per
// file content (cached on mtime + size, re-checked at most every 60 s unless
// asked fresh, streamed: never blocks the event loop).

const DIST_DIR = path.resolve(__dirname, '../../../../agent/dist');

const STAT_TTL_MS = 60_000;

export interface DistFileInfo { sha256: string; size: number }
interface HashEntry { checkedAt: number; info: DistFileInfo | null; mtimeMs: number; size: number }
const hashCache = new Map<string, HashEntry>();
const inflight = new Map<string, Promise<DistFileInfo | null>>();

/** Absolute path of a file of the agent dist folder (name already allow-listed by the caller). */
export function distFilePath(fileName: string): string {
  return path.join(DIST_DIR, fileName);
}

function hashFile(fp: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(fp);
    s.on('error', reject);
    s.on('data', (chunk) => h.update(chunk));
    s.on('end', () => resolve(h.digest('hex')));
  });
}

/**
 * SHA-256 + size of a dist file, or null when it is missing. Cached per file
 * content; concurrent callers share one computation. `fresh`: stat the file
 * now (the download route) instead of trusting a check younger than 60 s;
 * the hash is still reused while mtime + size match.
 */
export async function getDistFileInfo(fileName: string, opts: { fresh?: boolean } = {}): Promise<DistFileInfo | null> {
  const fp = path.join(DIST_DIR, fileName);
  const now = Date.now();
  const cached = hashCache.get(fp);
  if (!opts.fresh && cached && now - cached.checkedAt < STAT_TTL_MS) return cached.info;
  const running = inflight.get(fp);
  if (running) return running;

  const p = (async (): Promise<DistFileInfo | null> => {
    try {
      const st = await fs.promises.stat(fp);
      if (!st.isFile()) {
        hashCache.set(fp, { checkedAt: Date.now(), info: null, mtimeMs: 0, size: 0 });
        return null;
      }
      const prev = hashCache.get(fp);
      if (prev?.info && prev.mtimeMs === st.mtimeMs && prev.size === st.size) {
        hashCache.set(fp, { ...prev, checkedAt: Date.now() });
        return prev.info;
      }
      const sha256 = await hashFile(fp);
      // Replaced while being read: do not pair this hash with the new file.
      const st2 = await fs.promises.stat(fp);
      if (st2.mtimeMs !== st.mtimeMs || st2.size !== st.size) {
        hashCache.delete(fp);
        return null;
      }
      const info = { sha256, size: st.size };
      hashCache.set(fp, { checkedAt: Date.now(), info, mtimeMs: st.mtimeMs, size: st.size });
      return info;
    } catch {
      // Missing / unreadable: remembered for the TTL.
      hashCache.set(fp, { checkedAt: Date.now(), info: null, mtimeMs: 0, size: 0 });
      return null;
    } finally {
      inflight.delete(fp);
    }
  })();
  inflight.set(fp, p);
  return p;
}

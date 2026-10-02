import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

// =============================================================================
// The brain's own version (server/package.json), for the compatibility matrix
// with apple-edge (compat.ts): found from this file's folder (src/apple/edge
// under tsx, dist/src/apple/edge once compiled), else from the working
// directory as app.ts reads it. 'dev' when no package.json of the server is
// found.
// =============================================================================

let cached: string | null = null;

export function serverVersion(): string {
  if (cached !== null) return cached;
  const candidates: string[] = [];
  let dir = __dirname;
  for (let i = 0; i < 6; i++) {
    candidates.push(path.join(dir, 'package.json'));
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  candidates.push(path.join(process.cwd(), 'package.json'));
  for (const file of candidates) {
    try {
      if (!existsSync(file)) continue;
      const pkg = JSON.parse(readFileSync(file, 'utf8')) as { name?: unknown; version?: unknown };
      if (pkg.name === '@obligarth/server' && typeof pkg.version === 'string' && pkg.version) {
        cached = pkg.version;
        return cached;
      }
    } catch { /* next candidate */ }
  }
  cached = 'dev';
  return cached;
}

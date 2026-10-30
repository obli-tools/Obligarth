import { normalizeIp } from '../utils/clientIp';

// =============================================================================
// Addresses carrying a live console session (the reporting guard of the MCP
// blocks, docs: specs mcp-server §3.6): a block of such an address is never
// reported to Obliguard, which would cut a known office off every service.
// The session store keeps no client address, so the addresses are remembered
// here, in memory, by the session guard (middleware/sessionUserGuard.ts) on
// every signed-in request, for as long as a session lives without activity.
// Lost at a restart: an address counts again from the next signed-in request.
// =============================================================================

/** As long as an idle session lives (the session cookie's maxAge, app.ts). */
const TTL_MS = 7 * 24 * 3_600_000;
const MAX_ENTRIES = 50_000;
/** An address is written at most once a minute (the guard runs on every request). */
const REFRESH_MS = 60_000;

const seen = new Map<string, number>();

/** A signed-in request came from this address now. */
export function noteSessionAddress(ip: string | null | undefined): void {
  const a = ip ? normalizeIp(ip) : '';
  if (!a) return;
  const now = Date.now();
  const at = seen.get(a);
  if (at !== undefined && now - at < REFRESH_MS) return;
  if (at === undefined && seen.size >= MAX_ENTRIES) {
    for (const [k, t] of seen) if (now - t >= TTL_MS) seen.delete(k);
    // Still full: the oldest entries go first (a Map iterates in insertion order; a refresh re-inserts).
    for (const k of seen.keys()) { if (seen.size < MAX_ENTRIES) break; seen.delete(k); }
  }
  seen.delete(a);
  seen.set(a, now);
}

/** Did a signed-in session come from this address within the life of a session? */
export function hasLiveSessionAt(ip: string | null | undefined): boolean {
  const a = ip ? normalizeIp(ip) : '';
  if (!a) return false;
  const at = seen.get(a);
  return at !== undefined && Date.now() - at < TTL_MS;
}

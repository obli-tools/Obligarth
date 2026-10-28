// =============================================================================
// The viewer's tokens of this tab (P0-15 §4.2, §4.4). The server hands a token once (the request of a session, or
// viewer-token for a session approved later) and keeps its SHA-256 only; it stays valid until the end of the session,
// for a reload of the tab. Kept in the sessionStorage of the tab (never localStorage: another tab or a later visit has
// none; never in a URL), removed when the session ends. A failing storage (private mode) keeps it in memory only.
// =============================================================================

const PREFIX = 'obl.remote.viewer.';
const memory = new Map<string, string>();

export function keepViewerToken(sessionId: string, token: string): void {
  memory.set(sessionId, token);
  try { sessionStorage.setItem(PREFIX + sessionId, token); } catch { /* memory only */ }
}

export function viewerTokenOf(sessionId: string): string | null {
  const m = memory.get(sessionId);
  if (m) return m;
  try { return sessionStorage.getItem(PREFIX + sessionId); } catch { return null; }
}

export function dropViewerToken(sessionId: string): void {
  memory.delete(sessionId);
  try { sessionStorage.removeItem(PREFIX + sessionId); } catch { /* none */ }
}

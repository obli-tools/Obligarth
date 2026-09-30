/**
 * Clipboard sync rules of the ObliReach web viewer (pure — unit-tested in node).
 *
 * Ctrl+V in the viewer may first put the LOCAL clipboard text on the remote
 * clipboard, then the key goes out and the remote pastes. Only when:
 *   - the agent advertises `clipboard_text` and sync is on (checked by the
 *     caller: otherwise Ctrl+V is forwarded at once, as before);
 *   - the text is new: not the last text sent to the remote nor the last one
 *     received from it;
 *   - "last copy wins": a copy made INSIDE the session after the local one is
 *     never overwritten — the remote's files, images or text stay what Ctrl+V
 *     pastes there. The browser cannot see copies made in other local apps:
 *     it only knows that the operator LEFT the page (window blur) since the
 *     remote copy, and what the local clipboard held at the previous paste.
 *     A remote copy is newer unless the operator left the page afterwards and
 *     the local text is not the one seen at the previous paste.
 * The paste keys themselves are ALWAYS forwarded (read refused, text too
 * large, nothing to send): the remote then pastes its own clipboard.
 */

export interface ReachClipSyncState {
  /** Last text sent to the remote clipboard. */
  lastSent: string | null;
  /** Last text received from the remote clipboard. */
  lastRemote: string | null;
  /** The remote copied something (text or files) after our last send. */
  remoteNewer: boolean;
  /** The page lost the focus since that remote copy (a local copy may have happened). */
  awaySinceRemote: boolean;
  /** Local clipboard text seen at the previous paste (null: never read). */
  localSeen: string | null;
}

export function newClipSyncState(): ReachClipSyncState {
  return { lastSent: null, lastRemote: null, remoteNewer: false, awaySinceRemote: false, localSeen: null };
}

/** The remote clipboard changed (agent push, or the answer to a Ctrl+C there). */
export function noteRemoteCopy(s: ReachClipSyncState, text?: string | null): void {
  if (typeof text === 'string') s.lastRemote = text;
  s.remoteNewer = true;
  s.awaySinceRemote = false;
}

/** The page lost the focus (window blur / hidden). */
export function notePageLeft(s: ReachClipSyncState): void {
  if (s.remoteNewer) s.awaySinceRemote = true;
}

/** Local text was put on the remote clipboard. */
export function noteLocalSent(s: ReachClipSyncState, text: string): void {
  s.lastSent = text;
  s.remoteNewer = false;
  s.awaySinceRemote = false;
}

/**
 * Ctrl+V with the local clipboard holding `localText` (null: could not be
 * read): 'send' = put it on the remote clipboard before the keys, 'skip' =
 * forward the keys only. Records what the local clipboard held.
 */
export function pasteDecision(s: ReachClipSyncState, localText: string | null): 'send' | 'skip' {
  if (localText === null) return 'skip';
  const seenBefore = s.localSeen;
  s.localSeen = localText;
  if (!localText) return 'skip';
  if (localText === s.lastSent || localText === s.lastRemote) return 'skip';
  if (s.remoteNewer) {
    // The operator never left the page since the remote copy: no local copy can be newer.
    if (!s.awaySinceRemote) return 'skip';
    // Left, but the local clipboard still holds what it held before.
    if (seenBefore !== null && localText === seenBefore) return 'skip';
  }
  return 'send';
}

/** Identity of a set of local files (same copy pasted twice = same signature). */
export function filesSignature(files: ReadonlyArray<{ name: string; size: number; lastModified?: number }>): string {
  return files.map((f) => `${f.name}\u0000${f.size}\u0000${f.lastModified ?? 0}`).join('\u0001');
}

/**
 * Ctrl+V with local FILES on the clipboard (agent with file_upload): upload
 * them (and do not forward V) only for a copy not already uploaded and not
 * older than a remote copy; otherwise the remote pastes its own clipboard.
 */
export function pasteFilesDecision(s: ReachClipSyncState, signature: string, lastUploaded: string | null): 'upload' | 'skip' {
  if (!signature || signature === lastUploaded) return 'skip';
  if (s.remoteNewer && !s.awaySinceRemote) return 'skip';
  return 'upload';
}

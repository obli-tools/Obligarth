/**
 * ObliReach — file-transfer permission of a remote session (owner's decision
 * 29/09, point 1).
 *
 * Every Reach file transfer — a paste / drop upload (file_begin + 0x20 data),
 * the list of files copied on the remote (clipboard_files) and their download
 * (file_get + 0x21 data) — needs:
 *   - the capability 'files' on the device (admins hold every capability),
 *     like the Obliance file explorer;
 *   - no tenant action restriction on the explorer's transfers
 *     (`command.upload_file` / `command.download_file` at 'none'): 'restricted'
 *     forbids them, and 'sensitive' needs a per-operation confirmation Reach
 *     cannot ask for — both refuse Reach transfers (reason 'restriction'; the
 *     file explorer stays the way to do them, with its confirmation);
 *   - when privacy mode is on for the device, the privacy unlock of the
 *     'files' feature (for everyone: privacy mode protects the device's user).
 * A technician with 'remote' but not 'files' keeps the remote session without
 * any file transfer.
 *
 * The server decides once, when the session is created (remote.service
 * createSession), and:
 *   1. tells the agent: open_remote_tunnel carries `files: boolean`. An
 *      ObliReach agent that knows it starts its capture helper with
 *      --no-files (no file feature advertised, every file_* refused with
 *      file_error{code:'forbidden'});
 *   2. enforces it in the relay as well (defence in depth, and the only
 *      barrier for older agents): viewer file messages and binary frames never
 *      reach the agent (a request the viewer waits on is answered
 *      file_error{code:'forbidden'}), the agent's file messages and 0x21 frames
 *      never reach the viewer, and the agent's `init` is rewritten — file
 *      features removed, `filesPolicy: {allowed:false, reason}` added — so both
 *      viewers (web, Oblireach Desktop) hide or disable their file actions
 *      with the reason.
 *
 * This module is pure (no DB, no I/O): the decision and the frame filters are
 * checked by .local-verify/reach-files/verify-reach-files.ts.
 */

export type ReachFilesDeniedReason = 'capability' | 'restriction' | 'privacy';

export interface ReachFilesPolicy {
  allowed: boolean;
  /** Why transfers are refused (allowed:false only). */
  reason?: ReachFilesDeniedReason;
}

export const FILES_ALLOWED: ReachFilesPolicy = Object.freeze({ allowed: true }) as ReachFilesPolicy;

/**
 * The decision. `hasFilesCapability` already includes the admin bypass
 * (permissionService.canUseCapability(…, isAdmin, 'files')). The capability is
 * checked first (without it an unlock would not help), then the tenant's
 * restriction (an admin setting: an unlock would not help either), then the
 * privacy unlock. `restricted`: `command.upload_file` or
 * `command.download_file` is not 'none' for this device (admins included:
 * the restriction matrix binds them too).
 */
export function decideReachFilesPolicy(i: {
  hasFilesCapability: boolean;
  restricted?: boolean;
  privacyEnabled: boolean;
  hasFilesUnlock: boolean;
}): ReachFilesPolicy {
  if (!i.hasFilesCapability) return { allowed: false, reason: 'capability' };
  if (i.restricted) return { allowed: false, reason: 'restriction' };
  if (i.privacyEnabled && !i.hasFilesUnlock) return { allowed: false, reason: 'privacy' };
  return FILES_ALLOWED;
}

/** Viewer text frames above this size are dropped unread when files are refused
 *  (the largest legitimate one, a 1 MB clipboard_set, stays far below). */
export const GATE_BROWSER_MAX_TEXT = 4 * 1024 * 1024;
/** Agent text frames above this size are forwarded unread (no file message is
 *  that large; the viewer could not have asked for one anyway). */
export const GATE_AGENT_MAX_TEXT = 8 * 1024 * 1024;

/** A refused transfer request, for the audit (remote.file_denied). */
export interface DeniedFileAttempt {
  type: string;
  tid?: number;
  name?: string;
  size?: number;
}

export type BrowserFrameVerdict =
  | { forward: true }
  | { forward: false; reply?: string; attempt?: DeniedFileAttempt };

const TYPE_KEY = /^type$/i;
const TID_KEY = /^tid$/i;

function toBuffer(data: unknown): Buffer | null {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (Array.isArray(data) && data.every((d) => Buffer.isBuffer(d))) return Buffer.concat(data as Buffer[]);
  return null;
}

/**
 * Every value the agent could read as the message's `type`. The agent (Go
 * encoding/json) matches the `type` key case-insensitively and takes the last
 * matching key; here EVERY such key counts (stricter). JSON.parse already
 * collapses exact duplicates to the last one and decodes \u escapes, like Go.
 */
function typeValues(obj: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const k of Object.keys(obj)) {
    if (TYPE_KEY.test(k) && typeof obj[k] === 'string') out.push(obj[k] as string);
  }
  return out;
}

function lastMatching(obj: Record<string, unknown>, re: RegExp): unknown {
  let v: unknown;
  for (const k of Object.keys(obj)) if (re.test(k)) v = obj[k];
  return v;
}

function isFileType(t: string): boolean {
  return t.startsWith('file_') || t.startsWith('clipboard_files');
}

/** Types that never get an answer (an acknowledgement, a cancel, an error). */
const NO_REPLY_TYPES: ReadonlySet<string> = new Set(['file_progress', 'file_cancel', 'file_error']);

export function forbiddenFileError(tid: number): string {
  return JSON.stringify({
    type: 'file_error', tid, code: 'forbidden',
    message: 'File transfer is not permitted in this session',
  });
}

/**
 * Viewer → agent frame of a session whose file transfers are refused.
 * Forwarded: the viewer's JSON control messages that are not file ones.
 * Dropped: every binary frame (the only viewer binary frame is 0x20 upload
 * data), every file_* / clipboard_files* message, and anything that cannot be
 * read with certainty (not JSON, not an object, too large) — fail closed. A
 * transfer request the viewer waits on (it carries a tid) is answered with
 * file_error{code:'forbidden'} and reported for the audit.
 */
export function gateBrowserFrame(data: unknown, isBinary: boolean): BrowserFrameVerdict {
  if (isBinary) return { forward: false };
  const buf = toBuffer(data);
  if (!buf || buf.length > GATE_BROWSER_MAX_TEXT) return { forward: false };
  let msg: unknown;
  try { msg = JSON.parse(buf.toString('utf8')); } catch { return { forward: false }; }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return { forward: false };
  const obj = msg as Record<string, unknown>;
  const types = typeValues(obj);
  const fileType = types.find(isFileType);
  if (fileType === undefined) return { forward: true };
  const rawTid = lastMatching(obj, TID_KEY);
  const tid = typeof rawTid === 'number' && Number.isInteger(rawTid) && rawTid >= 0 && rawTid <= 0xffffffff
    ? rawTid : undefined;
  if (tid === undefined || NO_REPLY_TYPES.has(fileType)) return { forward: false };
  const name = typeof obj.name === 'string' ? obj.name : undefined;
  const size = typeof obj.size === 'number' && Number.isFinite(obj.size) && obj.size >= 0 ? Math.floor(obj.size) : undefined;
  return {
    forward: false,
    reply: forbiddenFileError(tid),
    attempt: { type: fileType, tid, ...(name !== undefined ? { name } : {}), ...(size !== undefined ? { size } : {}) },
  };
}

const FILE_FEATURES: ReadonlySet<string> = new Set(['clipboard_files', 'file_upload', 'file_download']);
const INIT_MARK = Buffer.from('"init"');
const FILE_MARK = Buffer.from('file');

/**
 * The agent's `init` with file transfers taken away: file features removed,
 * clipboard.files / files.upload / files.download false, and
 * `filesPolicy: {allowed:false, reason}` for the viewers to say why.
 */
export function rewriteInitForDeniedFiles(init: Record<string, unknown>, policy: ReachFilesPolicy): Record<string, unknown> {
  const out: Record<string, unknown> = { ...init };
  if (Array.isArray(init.features)) {
    out.features = (init.features as unknown[]).filter((f) => !(typeof f === 'string' && FILE_FEATURES.has(f)));
  }
  if (init.clipboard && typeof init.clipboard === 'object' && !Array.isArray(init.clipboard)) {
    out.clipboard = { ...(init.clipboard as Record<string, unknown>), files: false };
  }
  if (init.files && typeof init.files === 'object' && !Array.isArray(init.files)) {
    out.files = { ...(init.files as Record<string, unknown>), upload: false, download: false };
  }
  out.filesPolicy = { allowed: false, reason: policy.reason ?? 'capability' };
  return out;
}

/**
 * Agent → viewer frame of a session whose file transfers are refused.
 * Returns null to drop it, or the frame to forward (the same Buffer when it is
 * unchanged, a new one for a rewritten init).
 * Dropped: 0x21 download data, file_* messages except file_error (the
 * refusals), clipboard_files* (names of files copied on the remote).
 */
export function gateAgentFrame(data: Buffer, isBinary: boolean, policy: ReachFilesPolicy): Buffer | null {
  if (isBinary) return data.length > 0 && data[0] === 0x21 ? null : data;
  // The agent writes its JSON with Go's encoder (letters never escaped): a
  // frame that mentions neither "init" nor "file" is none of ours.
  if (data.length > GATE_AGENT_MAX_TEXT || (data.indexOf(INIT_MARK) < 0 && data.indexOf(FILE_MARK) < 0)) return data;
  let msg: unknown;
  try { msg = JSON.parse(data.toString('utf8')); } catch { return data; }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return data;
  const obj = msg as Record<string, unknown>;
  const type = typeof obj.type === 'string' ? obj.type : '';
  if (type === 'init') return Buffer.from(JSON.stringify(rewriteInitForDeniedFiles(obj, policy)), 'utf8');
  if (type.startsWith('clipboard_files')) return null;
  if (type.startsWith('file_') && type !== 'file_error') return null;
  return data;
}

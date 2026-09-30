import crypto from 'node:crypto';
import type { ChatUnavailableCode, ObliReachWebView2Mode, ObliReachWebView2Status } from '@obliance/shared';
import { db } from '../db';
import { logger } from '../utils/logger';

// ── ObliReach: Microsoft Edge WebView2 runtime of the chat window ───────────
//
// The end user's side of a chat is a WebView2 page. The runtime is missing on
// Windows Server 2016/2019/2022, Windows 10 LTSC and images that never got it.
// The ObliReach agent (Windows) reports the runtime in its heartbeat
// (`webview2` block) and installs it per machine on the server's order
// (`webview2_install {source:'microsoft', force?}`) with the Microsoft-signed
// Evergreen Bootstrapper shipped in its MSI. The agent guards (one attempt at
// a time, back-off); the server decides WHEN, from the platform setting:
//   proactive  (default) — within about an hour of this server first seeing
//                          the runtime missing, at the device's own minute of
//                          the hour (a hash of the device: spread over the
//                          fleet, kept across reconnects and restarts);
//   on_demand             — when a chat could not open because the runtime is
//                          missing (chat_unavailable), plus the device page's
//                          Install button;
//   disabled              — never (the button is refused too).
// No per-tenant switch for now (owner's decision, 29/09).

export const WEBVIEW2_MODE_KEY = 'oblireach_webview2_install';
export const WEBVIEW2_MODES: readonly ObliReachWebView2Mode[] = ['proactive', 'on_demand', 'disabled'];
export const DEFAULT_WEBVIEW2_MODE: ObliReachWebView2Mode = 'proactive';

/** Proactive installs are spread over this window (each device has its own
 *  offset in it, see webview2SlotAt). */
export const WEBVIEW2_SPREAD_MS = 60 * 60_000;
/** A device's "first seen installable" mark is forgotten after this long without news. */
const FIRST_SEEN_TTL_MS = 7 * 24 * 60 * 60_000;
/** Bound on those marks (one per device reporting the runtime missing). */
const FIRST_SEEN_MAX = 100_000;
/** The agent refuses a forced attempt within 1 min of the previous one's start
 *  (webview2MinGap); the route says so instead of a silent no-op (+ a margin
 *  for the clock difference). */
export const WEBVIEW2_MANUAL_GAP_MS = 60_000 + 3_000;
/** At most one automatic `webview2_install` per device in this window (the agent's own back-off applies too). */
export const WEBVIEW2_AUTO_THROTTLE_MS = 10 * 60_000;
/** The mode is re-read at most this often (writes refresh it at once). */
const MODE_CACHE_MS = 60_000;

export function parseWebView2Mode(v: unknown): ObliReachWebView2Mode {
  return typeof v === 'string' && (WEBVIEW2_MODES as readonly string[]).includes(v)
    ? v as ObliReachWebView2Mode
    : DEFAULT_WEBVIEW2_MODE;
}

let cachedMode: ObliReachWebView2Mode = DEFAULT_WEBVIEW2_MODE;
let cachedAt = 0;
let loading: Promise<ObliReachWebView2Mode> | null = null;

/** Current mode (app_config), cached MODE_CACHE_MS. */
export async function getWebView2Mode(now = Date.now()): Promise<ObliReachWebView2Mode> {
  if (now - cachedAt < MODE_CACHE_MS) return cachedMode;
  if (!loading) {
    loading = db('app_config').where({ key: WEBVIEW2_MODE_KEY }).first('value')
      .then((row: { value?: string } | undefined) => {
        cachedMode = parseWebView2Mode(row?.value);
        cachedAt = Date.now();
        return cachedMode;
      })
      .catch((err: unknown) => {
        logger.warn({ err: (err as Error)?.message }, 'ObliReach WebView2: install mode not readable — last known kept');
        return cachedMode;
      })
      .finally(() => { loading = null; });
  }
  return loading;
}

/**
 * The last known mode, without waiting (used where the decision must be
 * taken synchronously: a chat_unavailable is handled before any await). A
 * stale value starts a background refresh. null until it was read once
 * (nothing is installed on a guess: the setting may be 'disabled').
 */
export function webview2ModeCached(now = Date.now()): ObliReachWebView2Mode | null {
  if (now - cachedAt >= MODE_CACHE_MS) void getWebView2Mode(now);
  return cachedAt === 0 ? null : cachedMode;
}

/** A write of the setting (settingsWrite.writeConfigKey): applied at once. */
export function noteWebView2Mode(mode: ObliReachWebView2Mode, now = Date.now()): void {
  cachedMode = mode;
  cachedAt = now;
}

// ── Heartbeat block ─────────────────────────────────────────────────────────

const STATES = new Set(['ok', 'missing', 'installing', 'failed', 'blocked', 'unsupported', 'unknown']);
const SCOPES = new Set(['machine', 'other', 'user_only', 'none', 'unknown']);
const REASON_RE = /^[a-z][a-z0-9_]{0,39}$/;
const VERSION_RE = /^\d{1,5}(\.\d{1,6}){1,3}$/;

function text(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return s ? s.slice(0, max) : null;
}

function time(v: unknown): string | null {
  if (typeof v !== 'string' || v.length > 40) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

/** Validated copy of a heartbeat's `webview2` block (agent input: never trusted as is); null when absent / not an object / unknown state. */
export function sanitizeObliReachWebView2(raw: unknown): ObliReachWebView2Status | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.state !== 'string' || !STATES.has(r.state)) return null;
  const version = text(r.version, 32);
  const scope = text(r.scope, 20);
  const reason = text(r.reason, 40);
  const attempts = Number(r.attempts);
  return {
    state: r.state as ObliReachWebView2Status['state'],
    version: version && VERSION_RE.test(version) ? version : null,
    scope: scope && SCOPES.has(scope) ? scope : null,
    reason: reason && REASON_RE.test(reason) ? reason : null,
    installer: r.installer === true,
    installingSince: time(r.installingSince),
    attempts: Number.isInteger(attempts) && attempts > 0 ? Math.min(attempts, 1000) : 0,
    lastError: text(r.lastError, 400),
    lastAttemptAt: time(r.lastAttemptAt),
    lastResultAt: time(r.lastResultAt),
    nextAttemptAt: time(r.nextAttemptAt),
    checkedAt: time(r.checkedAt),
  };
}

/** What the device page / logs care about (a change emits OBLIREACH_AGENT_UPDATED). */
export function webview2Key(s: ObliReachWebView2Status | null | undefined): string {
  return s ? [s.state, s.version, s.scope, s.reason, s.installer, s.attempts, s.nextAttemptAt, s.installingSince, s.lastError].join('|') : '';
}

// ── Automatic installs ──────────────────────────────────────────────────────

/** Offset of a device inside the proactive spread window (stable per device). */
export function webview2SpreadMs(deviceUuid: string): number {
  const h = crypto.createHash('sha256').update(String(deviceUuid)).digest();
  return h.readUInt32BE(0) % WEBVIEW2_SPREAD_MS;
}

/**
 * The proactive slot of a device first seen installable at `firstSeen`: the
 * first moment at or after it whose position in the (wall-clock) hour is the
 * device's offset. Anchored on the wall clock, not on the channel's
 * connection: a device whose channel reconnects often still gets its turn
 * (within the hour), and a server restart keeps the fleet spread.
 */
export function webview2SlotAt(deviceUuid: string, firstSeen: number): number {
  const hourStart = firstSeen - (((firstSeen % WEBVIEW2_SPREAD_MS) + WEBVIEW2_SPREAD_MS) % WEBVIEW2_SPREAD_MS);
  let slot = hourStart + webview2SpreadMs(deviceUuid);
  if (slot < firstSeen) slot += WEBVIEW2_SPREAD_MS;
  return slot;
}

/**
 * When the device page's Install / Retry button can be used again: the
 * agent ignores a forced request within 1 min of the previous attempt's start.
 * null: usable now — no attempt known, the minute is over, or the agent's
 * clock is ahead (an attempt "in the future" beyond the gap: the button is
 * never blocked for longer than the agent's own floor).
 */
export function webview2ManualRetryAt(s: ObliReachWebView2Status | null | undefined, now = Date.now()): number | null {
  const last = s?.lastAttemptAt ? Date.parse(s.lastAttemptAt) : NaN;
  if (!Number.isFinite(last)) return null;
  const at = last + WEBVIEW2_MANUAL_GAP_MS;
  return at > now && at - now <= WEBVIEW2_MANUAL_GAP_MS ? at : null;
}

/**
 * What the operator can do about a missing runtime from the device page:
 * 'button' (Install / Retry offered), 'disabled' (platform setting),
 * 'no_installer' (an ObliReach build without the bootstrapper), null when
 * nothing applies (installed, installing, blocked, unsupported) or unknown.
 */
export type WebView2InstallOffer = 'button' | 'disabled' | 'no_installer';

export function webview2InstallOffer(
  mode: ObliReachWebView2Mode | null,
  s: ObliReachWebView2Status | null | undefined,
): WebView2InstallOffer | null {
  if (!s || (s.state !== 'missing' && s.state !== 'failed' && s.state !== 'unknown')) return null;
  if (mode === 'disabled') return 'disabled';
  if (!s.installer) return 'no_installer';
  return mode ? 'button' : null;
}

/**
 * The agent would start an automatic attempt now: runtime missing, or the
 * last attempt failed and its back-off is over; the bootstrapper ships with
 * this agent. (blocked / unsupported / unknown / installing / ok: never.)
 */
export function webview2AutoInstallable(s: ObliReachWebView2Status | null | undefined, now = Date.now()): boolean {
  if (!s || !s.installer) return false;
  if (s.state === 'missing') return true;
  if (s.state !== 'failed') return false;
  const next = s.nextAttemptAt ? Date.parse(s.nextAttemptAt) : NaN;
  return !Number.isFinite(next) || next <= now;
}

/** `${tenantId}:${deviceUuid}` → last automatic `webview2_install` sent. */
const autoGate = new Map<string, number>();
const gateKey = (deviceUuid: string, tenantId: number) => `${Number(tenantId)}:${deviceUuid}`;
/** `${tenantId}:${deviceUuid}` → when this server first saw the device
 *  installable in proactive mode (the anchor of its slot) and last saw it so. */
const firstSeen = new Map<string, { first: number; last: number }>();

/** Tests only. */
export function __resetWebView2ForTests(): void {
  autoGate.clear();
  firstSeen.clear();
  cachedMode = DEFAULT_WEBVIEW2_MODE;
  cachedAt = 0;
  loading = null;
}

/** Tests only: pretend the device was first seen installable at `at`. */
export function __setWebView2FirstSeenForTests(deviceUuid: string, tenantId: number, at: number): void {
  firstSeen.set(gateKey(deviceUuid, tenantId), { first: at, last: at });
}

/** The runtime is installed (or the device left): its slot anchor goes. */
export function forgetWebView2FirstSeen(deviceUuid: string, tenantId: number): void {
  firstSeen.delete(gateKey(deviceUuid, tenantId));
}

/** Drop the gate entries whose window is over, and slot anchors without news for a week (hub keepalive sweep). */
export function pruneWebView2Gate(now = Date.now()): void {
  for (const [k, at] of autoGate) if (now - at >= WEBVIEW2_AUTO_THROTTLE_MS) autoGate.delete(k);
  for (const [k, v] of firstSeen) if (now - v.last >= FIRST_SEEN_TTL_MS) firstSeen.delete(k);
}

/** Claims the automatic send for this device (false: one went out within WEBVIEW2_AUTO_THROTTLE_MS). */
export function claimWebView2Auto(deviceUuid: string, tenantId: number, now = Date.now()): boolean {
  const k = gateKey(deviceUuid, tenantId);
  const last = autoGate.get(k);
  if (last !== undefined && now - last < WEBVIEW2_AUTO_THROTTLE_MS) return false;
  autoGate.set(k, now);
  return true;
}

/** The claimed send did not go out (channel closed): the next heartbeat may try again. */
export function releaseWebView2Auto(deviceUuid: string, tenantId: number): void {
  autoGate.delete(gateKey(deviceUuid, tenantId));
}

/**
 * Proactive mode: send `webview2_install` now? When the agent would start an
 * attempt, once the device's slot has come (webview2SlotAt: within the hour
 * after this server first saw it installable, at the device's own offset —
 * NOT counted from its channel's connection, which a flaky link resets), at
 * most once per WEBVIEW2_AUTO_THROTTLE_MS. Pure except for the slot anchor
 * and the gate (claimed when true).
 */
export function decideProactiveInstall(p: {
  mode: ObliReachWebView2Mode;
  status: ObliReachWebView2Status | null | undefined;
  deviceUuid: string;
  tenantId: number;
  now?: number;
}): boolean {
  const now = p.now ?? Date.now();
  if (p.mode !== 'proactive') return false;
  const k = gateKey(p.deviceUuid, p.tenantId);
  if (p.status?.state === 'ok') { firstSeen.delete(k); return false; }
  if (!webview2AutoInstallable(p.status, now)) return false;
  let mark = firstSeen.get(k);
  if (!mark) {
    if (firstSeen.size >= FIRST_SEEN_MAX) {
      const oldest = firstSeen.keys().next();
      if (!oldest.done) firstSeen.delete(oldest.value);
    }
    mark = { first: now, last: now };
    firstSeen.set(k, mark);
  }
  mark.last = now;
  if (now < webview2SlotAt(p.deviceUuid, mark.first)) return false;
  return claimWebView2Auto(p.deviceUuid, p.tenantId, now);
}

/**
 * On-demand mode: a chat could not open because the runtime is missing —
 * send `webview2_install` now? (Also in proactive mode: the chat failure
 * does not wait for the device's spread slot.) Claims the gate when true.
 */
export function decideOnDemandInstall(p: {
  mode: ObliReachWebView2Mode | null;
  status: ObliReachWebView2Status | null | undefined;
  code: ChatUnavailableCode;
  deviceUuid: string;
  tenantId: number;
  now?: number;
}): boolean {
  const now = p.now ?? Date.now();
  if (!p.mode || p.mode === 'disabled' || p.code !== 'webview2_missing') return false;
  if (!webview2AutoInstallable(p.status, now)) return false;
  return claimWebView2Auto(p.deviceUuid, p.tenantId, now);
}

export function buildWebView2InstallCommand(idPrefix: string, force: boolean, now = Date.now()): {
  type: 'webview2_install'; id: string; payload: Record<string, unknown>;
} {
  return { type: 'webview2_install', id: `${idPrefix}_${now}`, payload: { source: 'microsoft', force } };
}

// ── chat_unavailable (agent chat_event) ─────────────────────────────────────

const CHAT_CODES = new Set<ChatUnavailableCode>(['webview2_missing', 'webview2_failed', 'webview2_timeout', 'helper_failed', 'no_user']);

export interface ChatUnavailableInfo {
  code: ChatUnavailableCode;
  /** An install of the runtime is running (reported by the agent, or just sent by this server). */
  installing: boolean;
  /** The agent's WebView2 state when it refused (ObliReachWebView2State), if any. */
  state: string | null;
  /** The agent's detail (last install error, WebView2 failure…): English,
   *  technical — the clients show it apart ("technical detail"), never inside
   *  a translated sentence. */
  detail: string | null;
  /** Reason code of the runtime's state (ObliReachWebView2Status.reason:
   *  network, signature, per_user_only…): what the clients translate. */
  wv2Reason: string | null;
  /** What the operator can do from the device page (webview2InstallOffer):
   *  the clients never point to an Install button that is not there. */
  installOffer: WebView2InstallOffer | null;
}

/** Validated chat_unavailable payload (unknown codes count as helper_failed). */
export function sanitizeChatUnavailable(payload: unknown): ChatUnavailableInfo {
  const p = (payload && typeof payload === 'object' && !Array.isArray(payload)) ? payload as Record<string, unknown> : {};
  const code = typeof p.reason === 'string' && CHAT_CODES.has(p.reason as ChatUnavailableCode)
    ? p.reason as ChatUnavailableCode
    : 'helper_failed';
  const state = typeof p.state === 'string' && STATES.has(p.state) ? p.state : null;
  return { code, installing: p.installing === true, state, detail: text(p.detail, 300), wv2Reason: null, installOffer: null };
}

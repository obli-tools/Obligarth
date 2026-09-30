/**
 * ObliReach keepalive — viewer side (agents that list 'keepalive' in
 * init.features; same protocol and setting as the Oblireach Desktop viewer).
 *
 * The agent ends a stream after 10 minutes without input. A session that is
 * only watched (View only, or nobody touching it) sends none and was cut.
 * The viewer sends `{"type":"keepalive"}` every 60 s on a live session: it
 * resets the agent's idle timer and injects nothing. A per-user setting
 * (this browser, localStorage) says when:
 *   'always'  — while the session is open (tab hidden, window minimized too);
 *   'visible' — (default) only while its picture is on screen
 *               (document.visibilityState === 'visible');
 *   'never'   — nothing (the behaviour before keepalive).
 * An agent that does not list the feature gets nothing new. When the picture
 * comes back on screen more than 60 s after the last keepalive, one goes out
 * at once: a long-hidden session is not cut seconds after being shown.
 */

export type KeepaliveMode = 'always' | 'visible' | 'never';

export const KEEPALIVE_MODES: readonly KeepaliveMode[] = ['always', 'visible', 'never'];
export const KEEPALIVE_DEFAULT_MODE: KeepaliveMode = 'visible';
export const KEEPALIVE_INTERVAL_MS = 60_000;
/** localStorage key (shared by every viewer of this browser). */
export const KEEPALIVE_STORAGE_KEY = 'obliance.reach.keepalive';

/** i18n key + English fallback of each choice. */
export const KEEPALIVE_LABELS: Readonly<Record<KeepaliveMode, { key: string; fallback: string }>> = {
  always: { key: 'reach.keepalive.always', fallback: 'Always' },
  visible: { key: 'reach.keepalive.visible', fallback: 'While visible (default)' },
  never: { key: 'reach.keepalive.never', fallback: 'Never' },
};

/** A stored value → a mode (anything unknown: the default). */
export function parseKeepaliveMode(v: unknown): KeepaliveMode {
  return v === 'always' || v === 'visible' || v === 'never' ? v : KEEPALIVE_DEFAULT_MODE;
}

export function loadKeepaliveMode(): KeepaliveMode {
  try { return parseKeepaliveMode(localStorage.getItem(KEEPALIVE_STORAGE_KEY)); } catch { return KEEPALIVE_DEFAULT_MODE; }
}

export function saveKeepaliveMode(mode: KeepaliveMode): void {
  try { localStorage.setItem(KEEPALIVE_STORAGE_KEY, mode); } catch { /* private mode, storage blocked */ }
}

export interface KeepaliveState {
  mode: KeepaliveMode;
  /** The agent listed 'keepalive' in THIS connection's init. */
  supported: boolean;
  /** The session is live (its stream is up). */
  live: boolean;
  /** Its picture is on screen (page visible). */
  visible: boolean;
}

/** Keepalives flow in this state. */
export function keepaliveWanted(s: KeepaliveState): boolean {
  if (!s.supported || !s.live || s.mode === 'never') return false;
  return s.mode === 'always' || s.visible;
}

/**
 * Milliseconds until the next keepalive (0: now), or null when none is
 * wanted in this state (nothing to wait for until it changes).
 * `lastSentAt`: the last keepalive, or when the viewer started.
 */
export function keepaliveDelay(s: KeepaliveState, lastSentAt: number, now: number): number | null {
  if (!keepaliveWanted(s)) return null;
  return Math.max(0, lastSentAt + KEEPALIVE_INTERVAL_MS - now);
}

export interface KeepaliveClock {
  now: () => number;
  setTimeout: (fn: () => void, ms: number) => unknown;
  clearTimeout: (handle: unknown) => void;
}

const browserClock: KeepaliveClock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

/**
 * Sends the keepalives of one viewer. The viewer reports every change of
 * state (setting, agent support, live, visibility) with update(); a due
 * keepalive goes out at once (the picture came back after more than 60 s),
 * the next one is timed from the last (also when the socket was not open:
 * nothing is retried before the next period).
 */
export class KeepaliveScheduler {
  private state: KeepaliveState = { mode: 'never', supported: false, live: false, visible: false };
  private lastSentAt: number;
  private timer: unknown = null;

  constructor(private readonly send: () => void, private readonly clock: KeepaliveClock = browserClock) {
    this.lastSentAt = clock.now();
  }

  update(partial: Partial<KeepaliveState>): void {
    this.state = { ...this.state, ...partial };
    this.schedule();
  }

  /** Stops the timer (unmount). A later update() arms it again. */
  stop(): void {
    this.clearTimer();
  }

  private clearTimer(): void {
    if (this.timer !== null) {
      this.clock.clearTimeout(this.timer);
      this.timer = null;
    }
  }

  private schedule(): void {
    this.clearTimer();
    const delay = keepaliveDelay(this.state, this.lastSentAt, this.clock.now());
    if (delay === null) return;
    if (delay === 0) {
      this.fire();
      return;
    }
    this.timer = this.clock.setTimeout(() => {
      this.timer = null;
      this.fire();
    }, delay);
  }

  private fire(): void {
    if (!keepaliveWanted(this.state)) return;
    // Timed from this attempt, sent or not (no busy loop on a closed socket).
    this.lastSentAt = this.clock.now();
    this.send();
    this.schedule();
  }
}

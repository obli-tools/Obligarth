import { REMOTE_LIMITS } from '@obligarth/shared';

// =============================================================================
// The long waits of the bridge agents (P0-15 §4.1 wake.ts, §4.3 B, D9): POST /agent/v1/wait, held while the agent is in
// its armed window (15 min after « Demander de l'aide » or after a session, or always with remote.waitChannel), so a
// session, a lock or an erase reaches the device within a second instead of its period of interrogation (300 s).
//   one wait per agent    the most recent replaces the older one, answered at once { wake: false } (a dead 4G
//                         connection still held on the server never keeps the wake from the live one: no
//                         ConcurrencyLimiter, which would refuse the new wait and lose the wake);
//   50 s at most          { wake: false } (under the 60 s of Nginx Proxy Manager), or the connection closed;
//   2 000 on the instance beyond, refused (429, Retry-After): the agent tries again later;
//   a wake                answers the device's wait { wake: true } (the agent interrogates at once); a device whose
//                         agent waited in the last two minutes but is between two waits keeps the wake 60 s for its
//                         next wait (never for a device that does not wait: nothing grows with the fleet).
// In memory: the instance is one process (§0 « Dehors »). A replay of a wait teaches one boolean (the surface refuses
// a signature already seen).
// =============================================================================

interface Waiter { agentId: string; key: string; answer: (wake: boolean) => void }

const byAgent = new Map<string, Waiter>();
const byDevice = new Map<string, Waiter>();
/** Devices whose agent waited lately (ms until which a wake without a waiter is kept for its next wait). */
const recent = new Map<string, number>();
/** Wakes waiting for the next wait of their device (ms until which they stand). */
const pending = new Map<string, number>();

const RECENT_MS = 120_000;
const PENDING_MS = 60_000;
const MAX_KEYS = 20_000;
let holdMs = REMOTE_LIMITS.waitSeconds * 1000;

const deviceKey = (tenantId: number, deviceId: number): string => `${tenantId}:${deviceId}`;

function remember(map: Map<string, number>, key: string, until: number): void {
  if (!map.has(key) && map.size >= MAX_KEYS) {
    const now = Date.now();
    for (const [k, v] of map) if (v <= now) map.delete(k);
    if (map.size >= MAX_KEYS) map.clear();
  }
  map.set(key, until);
}

/**
 * Holds the wait of an agent: resolves true when its device is woken, false at the end of the hold, when a newer wait of
 * the same agent replaces it or when its connection closes (`onClose`). null: the instance holds its maximum.
 */
export function holdWait(who: { tenantId: number; deviceId: number; agentId: string }, onClose: (fn: () => void) => void): Promise<boolean> | null {
  const key = deviceKey(who.tenantId, who.deviceId);
  const now = Date.now();
  const woken = pending.get(key);
  if (woken !== undefined) {
    pending.delete(key);
    if (woken > now) {
      remember(recent, key, now + RECENT_MS);
      return Promise.resolve(true);
    }
  }
  const previous = byAgent.get(who.agentId);
  if (previous) previous.answer(false);
  else if (byAgent.size >= REMOTE_LIMITS.waitPerInstance) return null;
  return new Promise<boolean>((resolve) => {
    let done = false;
    const waiter: Waiter = {
      agentId: who.agentId, key,
      answer: (wake) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (byAgent.get(who.agentId) === waiter) byAgent.delete(who.agentId);
        if (byDevice.get(key) === waiter) byDevice.delete(key);
        remember(recent, key, Date.now() + RECENT_MS);
        resolve(wake);
      },
    };
    const timer = setTimeout(() => waiter.answer(false), holdMs);
    timer.unref?.();
    byAgent.set(who.agentId, waiter);
    byDevice.set(key, waiter);
    onClose(() => waiter.answer(false));
  });
}

/** Wakes the wait of a device (true: a wait was held and answered). Without one, a device that waited lately keeps
 *  the wake for its next wait. Never throws. */
export function wakeDevice(tenantId: number, deviceId: number): boolean {
  const key = deviceKey(tenantId, deviceId);
  const w = byDevice.get(key);
  if (w) {
    w.answer(true);
    return true;
  }
  const lately = recent.get(key);
  if (lately !== undefined && lately > Date.now()) remember(pending, key, Date.now() + PENDING_MS);
  return false;
}

/** The waits held now. */
export function waitsHeld(): number {
  return byAgent.size;
}

/** Answers every wait { wake: false } (the stop of the server). */
export function releaseAllWaits(): number {
  const all = [...byAgent.values()];
  for (const w of all) w.answer(false);
  return all.length;
}

/** Testbeds: the hold of a wait (ms), and a clean state. */
export function setWaitHoldMs(ms: number | null): void {
  holdMs = ms === null ? REMOTE_LIMITS.waitSeconds * 1000 : Math.max(10, Math.floor(ms));
}

export function resetWaits(): void {
  releaseAllWaits();
  recent.clear();
  pending.clear();
}

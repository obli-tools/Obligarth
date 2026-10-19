// =============================================================================
// In-memory limiters of the agent surface (docs: agent-pont-android §6): one
// server process serves the surface (the edge proxy has one upstream); the
// address keys the limiters only, never a log line.
// =============================================================================

/** A sliding window: `max` hits per `windowMs` and per key. */
export class WindowLimiter {
  private hits = new Map<string, number[]>();

  constructor(private readonly max: number, private readonly windowMs: number, private readonly maxKeys = 50_000) {}

  /** Records a hit; the seconds to wait when refused, else 0. */
  hit(key: string, now = Date.now()): number {
    const from = now - this.windowMs;
    const list = (this.hits.get(key) ?? []).filter((t) => t > from);
    if (list.length >= this.max) {
      this.hits.set(key, list);
      return Math.max(1, Math.ceil((list[0] + this.windowMs - now) / 1000));
    }
    list.push(now);
    if (!this.hits.has(key) && this.hits.size >= this.maxKeys) this.sweep(now);
    this.hits.set(key, list);
    return 0;
  }

  private sweep(now: number): void {
    const from = now - this.windowMs;
    for (const [k, v] of this.hits) if (!v.some((t) => t > from)) this.hits.delete(k);
    if (this.hits.size >= this.maxKeys) this.hits.clear();
  }

  reset(): void { this.hits.clear(); }
}

/**
 * A token bucket: `burst` tokens, one more every `everyMs`. The interrogation is « one per 20 s and per agent »
 * (§4.5) on average; a burst of 3 lets the follow-up interrogation 10 s after a command (§8.4) and the result of
 * an erase or a reboot (sent before acting, §5.3) through.
 */
export class BucketLimiter {
  private buckets = new Map<string, { tokens: number; at: number }>();

  constructor(private readonly burst: number, private readonly everyMs: number, private readonly maxKeys = 50_000) {}

  take(key: string, now = Date.now()): number {
    const b = this.buckets.get(key) ?? { tokens: this.burst, at: now };
    const tokens = Math.min(this.burst, b.tokens + (now - b.at) / this.everyMs);
    if (tokens < 1) {
      this.buckets.set(key, { tokens, at: now });
      return Math.max(1, Math.ceil(((1 - tokens) * this.everyMs) / 1000));
    }
    if (!this.buckets.has(key) && this.buckets.size >= this.maxKeys) this.buckets.clear();
    this.buckets.set(key, { tokens: tokens - 1, at: now });
    return 0;
  }

  reset(): void { this.buckets.clear(); }
}

/** Concurrent downloads per key (the APKs: 4 per tenant). */
export class ConcurrencyLimiter {
  private running = new Map<string, number>();

  constructor(private readonly max: number) {}

  acquire(key: string): (() => void) | null {
    const n = this.running.get(key) ?? 0;
    if (n >= this.max) return null;
    this.running.set(key, n + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const left = (this.running.get(key) ?? 1) - 1;
      if (left <= 0) this.running.delete(key); else this.running.set(key, left);
    };
  }
}

// The only timer of the Android module (G-A5: no application timer; periodic and deferred work goes through durable
// jobs). Three bounded waits use it, never a periodic timer: the pull loop between two pulls and after a failure (a
// continuous loop, like the outbox consumer), the single retry of an idempotent call to Google (250 to 500 ms), the
// wait of the rate limiter for a token (10 s at most). Ended early by `signal`.
export function androidWait(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) { resolve(); return; }
    const done = () => { clearTimeout(t); resolve(); };
    const t = setTimeout(() => { signal?.removeEventListener('abort', done); resolve(); }, Math.max(0, ms));
    t.unref?.();
    signal?.addEventListener('abort', done, { once: true });
  });
}

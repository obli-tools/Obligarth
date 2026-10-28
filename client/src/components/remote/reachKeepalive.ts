// =============================================================================
// The keepalive of the remote viewer (P0-15 §5.2), written again for this dialect (Obliance's reachKeepalive.ts follows
// a desktop agent): the viewer sends { type: 'keepalive' } every few seconds (the agent counts the operator as present,
// the proxies keep the connection), and watches what arrives. Nothing from the tunnel for `stallMs` (no picture, no
// keepalive of the agent) is a stall shown to the operator; the relay's own ping (25 s) closes a dead end.
// =============================================================================

export const KEEPALIVE_MS = 10_000;
export const STALL_MS = 20_000;

export class ReachKeepalive {
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastIn = Date.now();
  private stalled = false;

  constructor(
    private readonly send: () => void,
    private readonly onStall: (stalled: boolean) => void,
    private readonly everyMs: number = KEEPALIVE_MS,
    private readonly stallMs: number = STALL_MS,
  ) {}

  start(): void {
    this.stop();
    this.lastIn = Date.now();
    let lastOut = Date.now();
    this.timer = setInterval(() => {
      const now = Date.now();
      if (now - lastOut >= this.everyMs) { lastOut = now; this.send(); }
      const stalled = now - this.lastIn > this.stallMs;
      if (stalled !== this.stalled) { this.stalled = stalled; this.onStall(stalled); }
    }, 1_000);
  }

  /** Anything arrived from the tunnel. */
  seen(): void {
    this.lastIn = Date.now();
    if (this.stalled) { this.stalled = false; this.onStall(false); }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

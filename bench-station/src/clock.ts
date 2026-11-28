/**
 * Obligarth bench station — the server's time (lot BANC §3.5): every answer of the platform carries a `Date` header;
 * the offset to this PC's clock is kept, and the steps sent to the server are stamped with the corrected time.
 */
export class ServerClock {
  private offsetMs = 0;
  private known = false;

  constructor(private readonly local: () => number = Date.now) {}

  /** Learn from a response's Date header (second precision: an offset under 2 s is ignored). */
  observe(dateHeader: string | null | undefined): void {
    if (!dateHeader) return;
    const t = Date.parse(dateHeader);
    if (!Number.isFinite(t)) return;
    const off = t - this.local();
    if (!this.known || Math.abs(off - this.offsetMs) > 2_000) this.offsetMs = Math.abs(off) < 2_000 ? 0 : off;
    this.known = true;
  }

  now(): number { return this.local() + this.offsetMs; }
  iso(): string { return new Date(this.now()).toISOString(); }
  /** The measured offset, for the page (a PC more than 5 minutes off is shown). */
  offset(): number { return this.offsetMs; }
}

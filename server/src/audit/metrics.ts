// Values of the journal for the observability work (docs: audit-durci §13.3,
// FND-14): counters and gauges kept in memory, read by metricsSnapshot().
// Never a value of an entry: actions, classes, codes, counts.

const counters = new Map<string, number>();
const gauges = new Map<string, number>();
const durations: number[] = [];
const MAX_DURATIONS = 2_048;
const SAFE = /^[A-Za-z0-9_.:-]{1,80}$/;

function key(name: string, labels: Record<string, string | number> = {}): string {
  const parts = Object.entries(labels)
    .map(([k, v]) => `${k}=${SAFE.test(String(v)) ? String(v) : 'other'}`)
    .sort();
  return parts.length ? `${name}{${parts.join(',')}}` : name;
}

export const auditMetrics = {
  inc(name: string, labels?: Record<string, string | number>, by = 1): void {
    const k = key(name, labels);
    counters.set(k, (counters.get(k) ?? 0) + by);
  },
  set(name: string, value: number, labels?: Record<string, string | number>): void {
    gauges.set(key(name, labels), value);
  },
  get(name: string, labels?: Record<string, string | number>): number {
    const k = key(name, labels);
    return counters.get(k) ?? gauges.get(k) ?? 0;
  },
  /** obligarth_audit_append_duration_seconds (kept as a window of samples). */
  observeAppend(ms: number): void {
    durations.push(ms);
    if (durations.length > MAX_DURATIONS) durations.splice(0, durations.length - MAX_DURATIONS);
  },
  snapshot(): { counters: Record<string, number>; gauges: Record<string, number>; appendP95Ms: number | null } {
    const sorted = [...durations].sort((a, b) => a - b);
    const p95 = sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))] : null;
    return { counters: Object.fromEntries(counters), gauges: Object.fromEntries(gauges), appendP95Ms: p95 };
  },
  /** Tests only. */
  reset(): void {
    counters.clear();
    gauges.clear();
    durations.length = 0;
  },
};

// Values of the guard engine for the observability work (docs: audit-durci
// §13.3, FND-14): counters kept in memory, read by guard.metricsSnapshot().
// Never a value of a request: action keys, codes, states, counts.

const counters = new Map<string, number>();
const SAFE = /^[A-Za-z0-9_.:-]{1,80}$/;

function key(name: string, labels: Record<string, string | number> = {}): string {
  const parts = Object.entries(labels)
    .map(([k, v]) => `${k}=${SAFE.test(String(v)) ? String(v) : 'other'}`)
    .sort();
  return parts.length ? `${name}{${parts.join(',')}}` : name;
}

export const guardMetrics = {
  /** obligarth_guard_requests_total{action, outcome}, obligarth_guard_refusals_total{code}. */
  inc(name: string, labels?: Record<string, string | number>, by = 1): void {
    const k = key(name, labels);
    counters.set(k, (counters.get(k) ?? 0) + by);
  },
  get(name: string, labels?: Record<string, string | number>): number {
    return counters.get(key(name, labels)) ?? 0;
  },
  snapshot(): { counters: Record<string, number> } {
    return { counters: Object.fromEntries(counters) };
  },
  /** Tests only. */
  reset(): void {
    counters.clear();
  },
};

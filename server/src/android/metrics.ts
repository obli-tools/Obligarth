// Counters of the Android integration for the observability work (FND-14): operation names, status codes, outcomes
// and durations only; never a resource name, a device identifier nor a payload (G-A4).

type Labels = string;

const requests = new Map<Labels, number>();
const latency = new Map<string, { count: number; sumMs: number }>();
const events = new Map<Labels, number>();
let rateWaitMs = 0;
let inboxDead = 0;

const inc = (m: Map<string, number>, k: string, n = 1) => m.set(k, (m.get(k) ?? 0) + n);

export const androidMetrics = {
  googleRequest(op: string, code: number, ms: number): void {
    inc(requests, `${op}|${code}`);
    const l = latency.get(op) ?? { count: 0, sumMs: 0 };
    l.count += 1;
    l.sumMs += ms;
    latency.set(op, l);
  },
  event(type: string, outcome: string, n = 1): void {
    inc(events, `${type}|${outcome}`, n);
  },
  rateWait(ms: number): void {
    rateWaitMs += ms;
  },
  deadLetter(): void {
    inboxDead += 1;
  },
  /** android_google_requests_total{op,code}, android_google_latency_seconds{op}, android_rate_wait_seconds,
   *  android_inbox_dead_total, android_events_total{type,outcome}. */
  snapshot() {
    return {
      googleRequests: Object.fromEntries(requests),
      googleLatency: Object.fromEntries([...latency].map(([k, v]) => [k, { count: v.count, avgSeconds: v.count ? v.sumMs / v.count / 1000 : 0 }])),
      rateWaitSeconds: rateWaitMs / 1000,
      inboxDead,
      events: Object.fromEntries(events),
    };
  },
  /** Count of an event outcome (tests, health). */
  eventCount(type: string, outcome: string): number {
    return events.get(`${type}|${outcome}`) ?? 0;
  },
};

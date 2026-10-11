// =============================================================================
// Metrics of the apple-edge integration (docs: integration-apple-edge §5.2,
// §5.5, §7.4, §8.2; FND-14 publishes them): in-process values, no tenant
// label, no identifier (routes are patterns).
//   obligarth_apple_edge_up                      1 when the last probe answered
//   obligarth_apple_edge_info{version}           1 for the version seen last
//   obligarth_apple_edge_circuit_open            1 while the client's circuit is open
//   obligarth_apple_edge_calls_total{route, outcome}  answered (2xx), refused (4xx), failed (5xx, transport, timeout)
//   obligarth_apple_provisioning_total{outcome}  created, existing, failed
//   obligarth_apple_events_ignored_total{type}   outbox events without effect: the device has no record
//                                                yet (column « Sans fiche » of §7.4), or names nothing
//                                                the brain knows (a command, a session, an ADE server)
//   obligarth_apple_command_duplicate_results_total   a final result repeated (§8.2: the first one stays)
//   obligarth_apple_token_update_after_unenroll_total a TokenUpdate of a device already out of management
//   obligarth_apple_apns_throttled_total         pushes throttled by Apple (apns.throttled)
// =============================================================================

const calls = new Map<string, number>();
const provisioning = new Map<string, number>();
const ignored = new Map<string, number>();
let duplicateResults = 0;
let tokenUpdateAfterUnenroll = 0;
let apnsThrottled = 0;
let up = 0;
let version: string | null = null;
let circuitOpen: () => boolean = () => false;

const EVENT_TYPE_RE = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;

export const appleMetrics = {
  call(route: string, status: number | null): void {
    const outcome = status === null ? 'failed' : status < 400 ? 'answered' : status < 500 ? 'refused' : 'failed';
    const k = `${route}|${outcome}`;
    calls.set(k, (calls.get(k) ?? 0) + 1);
  },
  provisioned(outcome: 'created' | 'existing' | 'failed'): void {
    provisioning.set(outcome, (provisioning.get(outcome) ?? 0) + 1);
  },
  /** An outbox event of `type` applied without effect (§7.4, « Sans fiche » : ignore). */
  eventIgnored(type: string): void {
    const t = EVENT_TYPE_RE.test(type) ? type : 'other';
    ignored.set(t, (ignored.get(t) ?? 0) + 1);
  },
  duplicateResult(): void {
    duplicateResults += 1;
  },
  tokenUpdateAfterUnenroll(): void {
    tokenUpdateAfterUnenroll += 1;
  },
  apnsThrottled(count: number): void {
    if (Number.isFinite(count) && count > 0) apnsThrottled += Math.floor(count);
  },
  probe(answered: boolean, seenVersion: string | null): void {
    up = answered ? 1 : 0;
    if (seenVersion && /^[0-9A-Za-z.+-]{1,64}$/.test(seenVersion)) version = seenVersion;
  },
  setCircuitSource(fn: () => boolean): void {
    circuitOpen = fn;
  },
  snapshot() {
    return {
      up,
      info: version ? [{ version, value: 1 }] : [],
      circuitOpen: circuitOpen() ? 1 : 0,
      calls: [...calls.entries()].map(([k, value]) => {
        const i = k.lastIndexOf('|');
        return { route: k.slice(0, i), outcome: k.slice(i + 1), value };
      }),
      provisioning: [...provisioning.entries()].map(([outcome, value]) => ({ outcome, value })),
      eventsIgnored: [...ignored.entries()].map(([type, value]) => ({ type, value })),
      commandDuplicateResults: duplicateResults,
      tokenUpdateAfterUnenroll,
      apnsThrottled,
    };
  },
};

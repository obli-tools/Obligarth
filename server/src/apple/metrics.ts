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
//   obligarth_apple_command_submissions_total{outcome}  submissions of the command queue (§8.6): submitted,
//                                                held (frozen, apple-edge unavailable), failed (refused by
//                                                apple-edge), retried (a later attempt follows)
//   obligarth_apple_push_relaunches_total{outcome}      relaunch pushes asked of apple-edge (§8.7), by its answer
//   obligarth_apple_reconcile_fixes_total{kind}  corrections made by the reconciliation with apple-edge (§13.1)
// =============================================================================

const calls = new Map<string, number>();
const provisioning = new Map<string, number>();
const ignored = new Map<string, number>();
const submissions = new Map<string, number>();
const relaunches = new Map<string, number>();
const reconcileFixes = new Map<string, number>();
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
  /** One run of mdm.commands.submit that reached a decision (§8.6). */
  commandSubmission(outcome: 'submitted' | 'held' | 'failed' | 'retried'): void {
    submissions.set(outcome, (submissions.get(outcome) ?? 0) + 1);
  },
  /** Relaunch pushes (§8.7), by the answer of apple-edge (sent, deferred, disabled, error). */
  pushRelaunched(outcome: string, count = 1): void {
    const o = /^[a-z_]{1,24}$/.test(outcome) ? outcome : 'other';
    relaunches.set(o, (relaunches.get(o) ?? 0) + count);
  },
  /** Corrections of the reconciliation with apple-edge (§13.1), by kind. */
  reconcileFix(kind: string, count = 1): void {
    const k = /^[a-z_]{1,32}$/.test(kind) ? kind : 'other';
    if (Number.isFinite(count) && count > 0) reconcileFixes.set(k, (reconcileFixes.get(k) ?? 0) + Math.floor(count));
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
      commandSubmissions: [...submissions.entries()].map(([outcome, value]) => ({ outcome, value })),
      pushRelaunches: [...relaunches.entries()].map(([outcome, value]) => ({ outcome, value })),
      reconcileFixes: [...reconcileFixes.entries()].map(([kind, value]) => ({ kind, value })),
      tokenUpdateAfterUnenroll,
      apnsThrottled,
    };
  },
};

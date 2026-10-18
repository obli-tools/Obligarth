// =============================================================================
// Metrics of the DDM engine and of its relay (docs: integration-apple-edge
// §9.3, §9.5, §9.6; FND-14 publishes them): in-process values, no tenant
// label, no identifier of a device.
//   obligarth_apple_ddm_relay_requests_total{endpoint, outcome}   requests of the relay by endpoint kind
//                                                                 (tokens, declaration-items, declaration,
//                                                                 status, other) and HTTP status
//   obligarth_apple_ddm_relay_auth_failures_total                 requests whose signature was refused (401)
//   obligarth_apple_ddm_relay_duration_ms{le}                     duration of the authenticated requests
//   obligarth_apple_ddm_baseline_used_total                       sets computed with the reference
//                                                                 capabilities of the OS (§9.3 fallback)
//   obligarth_apple_ddm_sets_computed_total                       sets whose token changed
//   obligarth_apple_ddm_declarations_dropped_total{reason}        declarations of a provider set aside
//   obligarth_apple_ddm_sync_commands_total{outcome}              DeclarativeManagement: sent, refused,
//                                                                 acknowledged, error
//   obligarth_apple_ddm_status_reports_total{outcome}             reports ingested, failed, dropped (inbox full)
//   obligarth_apple_ddm_status_errors_total{item}                 Errors of the status reports, by item
// Self-contained: the unit tests load it.
// =============================================================================

const relay = new Map<string, number>();
const dropped = new Map<string, number>();
const sync = new Map<string, number>();
const reports = new Map<string, number>();
const statusErrors = new Map<string, number>();
let authFailures = 0;
let baselineUsed = 0;
let setsComputed = 0;

/** Upper bounds of the relay's duration histogram, milliseconds. */
const BUCKETS = [5, 10, 25, 50, 100, 200, 500, 1000, 2000] as const;
const durations = new Array<number>(BUCKETS.length + 1).fill(0);

const bump = (m: Map<string, number>, k: string, n = 1): void => { m.set(k, (m.get(k) ?? 0) + n); };
const ITEM_RE = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/;

export type RelayEndpointKind = 'tokens' | 'declaration-items' | 'declaration' | 'status' | 'other';

/** Time of the last answered relay request (2xx), in this process: the readiness of the tenants (§11.5, lot C3). */
let lastRelayOk: number | null = null;

export const ddmMetrics = {
  relayRequest(endpoint: RelayEndpointKind, status: number, durationMs?: number): void {
    bump(relay, `${endpoint}|${status}`);
    if (status >= 200 && status < 300) lastRelayOk = Date.now();
    if (durationMs !== undefined && Number.isFinite(durationMs)) {
      const i = BUCKETS.findIndex((b) => durationMs <= b);
      durations[i === -1 ? BUCKETS.length : i] += 1;
    }
  },
  lastRelayOkAt(): number | null {
    return lastRelayOk;
  },
  relayAuthFailure(): void {
    authFailures += 1;
  },
  baselineUsed(): void {
    baselineUsed += 1;
  },
  setComputed(): void {
    setsComputed += 1;
  },
  declarationDropped(reason: string): void {
    bump(dropped, /^[a-z_]{1,40}$/.test(reason) ? reason : 'other');
  },
  syncCommand(outcome: 'sent' | 'refused' | 'acknowledged' | 'error'): void {
    bump(sync, outcome);
  },
  statusReport(outcome: 'ingested' | 'failed' | 'dropped'): void {
    bump(reports, outcome);
  },
  statusError(item: string): void {
    bump(statusErrors, ITEM_RE.test(item) && item.length <= 128 ? item : 'other');
  },
  snapshot() {
    const pairs = (m: Map<string, number>, label: string) => [...m.entries()].map(([k, value]) => ({ [label]: k, value }));
    return {
      relayRequests: [...relay.entries()].map(([k, value]) => {
        const i = k.lastIndexOf('|');
        return { endpoint: k.slice(0, i), status: Number(k.slice(i + 1)), value };
      }),
      relayAuthFailures: authFailures,
      relayDurationMs: { buckets: [...BUCKETS], counts: [...durations] },
      baselineUsed,
      setsComputed,
      declarationsDropped: pairs(dropped, 'reason'),
      syncCommands: pairs(sync, 'outcome'),
      statusReports: pairs(reports, 'outcome'),
      statusErrors: pairs(statusErrors, 'item'),
    };
  },
};

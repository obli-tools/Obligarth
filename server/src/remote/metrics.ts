import { family, type MetricFamily } from '../ops/metrics';

// =============================================================================
// Metrics of the remote assistance (P0-15 §4.6), rendered by the collector 'remote' (modules/remote.ts). No tenant
// label, no session nor device: states, outcomes and directions only.
//   obligarth_remote_sessions_active{state}         open sessions of the instance by state (the database, all tenants,
//                                                   counts only: obligarth.remote_sessions_open_summary, cached 60 s)
//   obligarth_remote_sessions_total{outcome}        sessions closed in this process, by final state (ended,
//                                                   expired, cancelled, failed)
//   obligarth_remote_relay_bytes_total{direction}   bytes relayed (down: agent → viewer, up: viewer → agent), by the
//                                                   relay (T5)
//   obligarth_remote_requests_refused_total{reason} requests of a session refused, by reason of unavailability
//   obligarth_remote_relay_dropped_total{reason}    messages the relay dropped, by reason (remote/protocol.ts DropReason:
//                                                   a type of the other direction, an input in view, the backpressure…)
//   obligarth_remote_relay_tunnels{end}             ends attached to the relay now (agent, viewer)
// =============================================================================

const outcomes = new Map<string, number>();
const refused = new Map<string, number>();
const bytes = new Map<string, number>([['down', 0], ['up', 0]]);
const dropped = new Map<string, number>();
let attachedOf: () => { agent: number; viewer: number } = () => ({ agent: 0, viewer: 0 });

const add = (m: Map<string, number>, k: string, n: number): void => { m.set(k, (m.get(k) ?? 0) + n); };
const rows = (m: Map<string, number>, label: string) => [...m].map(([k, value]) => ({ labels: { [label]: k }, value }));

export const remoteMetrics = {
  closed(outcome: string): void { add(outcomes, outcome, 1); },
  refused(reason: string): void { add(refused, reason, 1); },
  relayed(direction: 'down' | 'up', n: number): void { if (n > 0) add(bytes, direction, n); },
  dropped(reason: string): void { add(dropped, reason, 1); },
  /** The relay's count of its attached ends (remote/relay.ts). */
  attachedFrom(fn: () => { agent: number; viewer: number }): void { attachedOf = fn; },
  /** The families of this process; `active`: the open sessions by state (read by the collector). */
  families(active: Array<{ state: string; sessions: number }>): MetricFamily[] {
    return [
      family('obligarth_remote_sessions_active', 'Open remote assistance sessions of the instance, by state', 'gauge',
        active.map((a) => ({ labels: { state: a.state }, value: a.sessions }))),
      family('obligarth_remote_sessions_total', 'Remote assistance sessions closed, by final state', 'counter', rows(outcomes, 'outcome')),
      family('obligarth_remote_relay_bytes_total', 'Bytes relayed by the remote assistance, by direction', 'counter', rows(bytes, 'direction')),
      family('obligarth_remote_requests_refused_total', 'Requests of a remote assistance session refused, by reason', 'counter',
        rows(refused, 'reason')),
      family('obligarth_remote_relay_dropped_total', 'Messages dropped by the remote assistance relay, by reason', 'counter', rows(dropped, 'reason')),
      family('obligarth_remote_relay_tunnels', 'Ends attached to the remote assistance relay', 'gauge',
        Object.entries(attachedOf()).map(([end, value]) => ({ labels: { end }, value }))),
    ];
  },
  /** Tests only. */
  reset(): void { outcomes.clear(); refused.clear(); dropped.clear(); bytes.set('down', 0); bytes.set('up', 0); },
};

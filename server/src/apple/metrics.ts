// =============================================================================
// Metrics of the apple-edge integration (docs: integration-apple-edge §5.2,
// §5.5; FND-14 publishes them): in-process values, no tenant label, no
// identifier (routes are patterns).
//   obligarth_apple_edge_up                      1 when the last probe answered
//   obligarth_apple_edge_info{version}           1 for the version seen last
//   obligarth_apple_edge_circuit_open            1 while the client's circuit is open
//   obligarth_apple_edge_calls_total{route, outcome}  answered (2xx), refused (4xx), failed (5xx, transport, timeout)
//   obligarth_apple_provisioning_total{outcome}  created, existing, failed
// =============================================================================

const calls = new Map<string, number>();
const provisioning = new Map<string, number>();
let up = 0;
let version: string | null = null;
let circuitOpen: () => boolean = () => false;

export const appleMetrics = {
  call(route: string, status: number | null): void {
    const outcome = status === null ? 'failed' : status < 400 ? 'answered' : status < 500 ? 'refused' : 'failed';
    const k = `${route}|${outcome}`;
    calls.set(k, (calls.get(k) ?? 0) + 1);
  },
  provisioned(outcome: 'created' | 'existing' | 'failed'): void {
    provisioning.set(outcome, (provisioning.get(outcome) ?? 0) + 1);
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
    };
  },
};

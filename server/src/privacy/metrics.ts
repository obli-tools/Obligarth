import { family, type MetricFamily } from '../ops/metrics';

// =============================================================================
// Counters of the privacy module (P0-13 T4, FND-14 subset), in this process, rendered by the collector 'privacy'
// (registerPrivacyModule → ops/metrics.ts). No tenant label: rule names and outcomes only. The age of the last success
// of the retention per tenant and the tenants failing are the core's (ops/collectors.ts, from job_status).
//   obligarth_privacy_retention_purged_rows_total{rule}      rows removed by a rule of privacy.retention-tenant
//   obligarth_privacy_retention_rule_failures_total{rule}    runs of a rule that failed (the others went on)
//   obligarth_privacy_retention_realigned_total              records out of management whose date of purge followed a
//                                                            change of the retention
//   obligarth_privacy_retention_changes_total{outcome}       changes of the retention: applied (a decrease cancelled is
//                                                            one, D4)
// =============================================================================

const purged = new Map<string, number>();
const failures = new Map<string, number>();
const changes = new Map<string, number>();
let realigned = 0;

const add = (m: Map<string, number>, k: string, n: number): void => { m.set(k, (m.get(k) ?? 0) + n); };

export const privacyMetrics = {
  purged(rule: string, n: number): void { if (n > 0) add(purged, rule, n); },
  ruleFailed(rule: string): void { add(failures, rule, 1); },
  realigned(n: number): void { if (n > 0) realigned += n; },
  change(outcome: 'applied'): void { add(changes, outcome, 1); },
  families(): MetricFamily[] {
    const rows = (m: Map<string, number>, label: string) => [...m].map(([k, value]) => ({ labels: { [label]: k }, value }));
    return [
      family('obligarth_privacy_retention_purged_rows_total', 'Rows removed by a rule of the retention, by rule', 'counter', rows(purged, 'rule')),
      family('obligarth_privacy_retention_rule_failures_total', 'Runs of a retention rule that failed, by rule', 'counter', rows(failures, 'rule')),
      family('obligarth_privacy_retention_realigned_total', 'Records out of management whose date of purge followed a change of the retention',
        'counter', [{ value: realigned }]),
      family('obligarth_privacy_retention_changes_total', 'Changes of the retention of a tenant, by outcome', 'counter', rows(changes, 'outcome')),
    ];
  },
  /** Tests only. */
  reset(): void { purged.clear(); failures.clear(); changes.clear(); realigned = 0; },
};

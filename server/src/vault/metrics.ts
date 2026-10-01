// Counters of the vault (docs: coffre-secrets §11.4), kept in memory and
// handed to the observability work (FND-14) by vault.metricsSnapshot(). Labels
// are table names and fixed codes: never a value, a key id or a tenant name.

type Counter = Map<string, number>;

function inc(map: Counter, labels: string): void {
  map.set(labels, (map.get(labels) ?? 0) + 1);
}

const seal: Counter = new Map();
const open: Counter = new Map();
const openFailures: Counter = new Map();
let backfillRemaining: Record<string, number> = {};
let verifyFailures: number | null = null;
let ready = 0;

export const vaultMetrics = {
  sealed(table: string, outcome: string): void { inc(seal, `${table}|${outcome}`); },
  opened(table: string, outcome: string): void { inc(open, `${table}|${outcome}`); },
  openFailed(table: string, code: string): void { inc(openFailures, `${table}|${code}`); },
  setReady(v: boolean): void { ready = v ? 1 : 0; },
  setBackfillRemaining(r: Record<string, number>): void { backfillRemaining = { ...r }; },
  setVerifyFailures(n: number): void { verifyFailures = n; },
  snapshot() {
    const rows = (m: Counter, a: string, b: string) => [...m].map(([k, n]) => {
      const [x, y] = k.split('|');
      return { [a]: x, [b]: y, count: n };
    });
    return {
      /** obligarth_vault_ready */
      ready,
      /** obligarth_vault_seal_total{table, outcome} */
      seal: rows(seal, 'table', 'outcome'),
      /** obligarth_vault_open_total{table, outcome} */
      open: rows(open, 'table', 'outcome'),
      /** obligarth_vault_open_failures_total{table, code} */
      openFailures: rows(openFailures, 'table', 'code'),
      /** obligarth_vault_backfill_remaining{column} */
      backfillRemaining: { ...backfillRemaining },
      /** obligarth_vault_verify_failures (last daily verification; null: none yet) */
      verifyFailures,
    };
  },
};

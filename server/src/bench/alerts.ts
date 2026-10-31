// =============================================================================
// Closed catalogue of the alerts of the bench stations (lot BANC §3.4, §3.10), declared in the catalogue of the alerts
// opened to the modules by registerBenchModule and raised by the catalogue service of the integration
// (apple/alerts/service.ts: i18n key apple.alerts.<kind>). Identifiers and counts only in the parameters.
//   bench.identity_mismatch  tenant: an enrollment by a bench token refused, the serial numbers read by ADB and those
//                            the agent declared differ (another device used the token)
//   bench.token_quota        platform: a station used 80 % of its daily quota of enrollment tokens
// =============================================================================

export const BENCH_ALERTS = {
  'bench.identity_mismatch': { scope: 'tenant', severity: 'warning', title: 'Bench enrollment refused: another device', message: 'An enrollment token of a bench station was used by a device whose serial numbers differ from those read on the bench: the enrollment was refused and the token revoked.' },
  'bench.token_quota': { scope: 'master', severity: 'warning', title: 'Bench station near its token quota', message: 'A bench station issued {count} enrollment tokens in 24 hours (quota {quota}).' },
} as const;

export type BenchAlertKind = keyof typeof BENCH_ALERTS;

export const BENCH_ALERTS_FR: Record<BenchAlertKind, { title: string; message: string }> = {
  'bench.identity_mismatch': { title: "Enrôlement par le banc refusé : autre appareil", message: "Un jeton d'enrôlement d'une station de banc a été utilisé par un appareil dont les numéros de série diffèrent de ceux lus au banc : l'enrôlement est refusé et le jeton révoqué." },
  'bench.token_quota': { title: 'Station de banc proche de son quota de jetons', message: "Une station de banc a émis {count} jetons d'enrôlement en 24 heures (quota {quota})." },
};

export function benchAlertDefinitions(): Array<{
  key: string; scope: 'tenant' | 'master' | 'both'; severity: 'info' | 'warning' | 'critical'; title: string; message: string;
  fr: { title: string; message: string }; i18nKey: string;
}> {
  return (Object.keys(BENCH_ALERTS) as BenchAlertKind[]).map((k) => ({
    key: k, scope: BENCH_ALERTS[k].scope, severity: BENCH_ALERTS[k].severity, title: BENCH_ALERTS[k].title,
    message: BENCH_ALERTS[k].message, fr: BENCH_ALERTS_FR[k], i18nKey: `apple.alerts.${k}`,
  }));
}

declare module '../services/alertCatalog' {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  interface CatalogAlertKinds extends Record<BenchAlertKind, true> {}
}

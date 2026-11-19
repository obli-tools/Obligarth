// =============================================================================
// The alert of the Obliwatch integration (brief GTH-01, criterion 4: a dead letter visible in Obligarth), declared in
// the catalogue of the alerts opened to the modules (services/alertCatalog.ts) by registerObliwatchModule and raised by
// the catalogue service (apple/alerts/service.ts: stable key 'apple:obliwatch.push_dead', i18n key
// apple.alerts.obliwatch.push_dead). Its parameter is a count only. No import at run time.
// =============================================================================

export const OBLIWATCH_ALERTS = {
  'obliwatch.push_dead': {
    scope: 'tenant', severity: 'warning', title: 'Obliwatch signals not delivered',
    message: '{count} mobile security signal(s) could not be delivered to Obliwatch for 72 hours: check the link with Obliwatch, then send them again from the Integrations page.',
  },
} as const;

export type ObliwatchAlertKind = keyof typeof OBLIWATCH_ALERTS;

const FR: Record<ObliwatchAlertKind, { title: string; message: string }> = {
  'obliwatch.push_dead': {
    title: 'Signaux Obliwatch non transmis',
    message: "{count} signal(aux) de sécurité mobile n'ont pas pu être transmis à Obliwatch pendant 72 heures : vérifiez le lien avec Obliwatch, puis renvoyez-les depuis la page Intégrations.",
  },
};

/** The definitions for registerAlertDefinitions. */
export function obliwatchAlertDefinitions(): Array<{
  key: string; scope: 'tenant'; severity: 'warning'; title: string; message: string; fr: { title: string; message: string }; i18nKey: string;
}> {
  return (Object.keys(OBLIWATCH_ALERTS) as ObliwatchAlertKind[]).map((k) => ({
    key: k, scope: OBLIWATCH_ALERTS[k].scope, severity: OBLIWATCH_ALERTS[k].severity, title: OBLIWATCH_ALERTS[k].title,
    message: OBLIWATCH_ALERTS[k].message, fr: FR[k], i18nKey: `apple.alerts.${k}`,
  }));
}

// The kind is raised by the catalogue service (type only).
declare module '../../services/alertCatalog' {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  interface CatalogAlertKinds extends Record<ObliwatchAlertKind, true> {}
}

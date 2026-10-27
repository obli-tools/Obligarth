// =============================================================================
// Alerts of the dynamic groups (P0-5 §4.2, §4.3), declared in the catalogue of the alerts opened to the modules
// (services/alertCatalog.ts, registerAlertDefinitions) by registerMdmModule, and raised by the catalogue service of the
// integration (apple/alerts/service.ts: stable key 'apple:<kind>:<smart group id>', i18n key apple.alerts.<kind>, as
// the bridge agent's). Same rules (I11): the parameters are identifiers and configuration labels (the group's name),
// never a device. No import at run time: the unit tests load it.
//   smart_group.rule_invalid   a static group the rule names was deleted: the group is in error, its members frozen
//                              (P0-5 §4.2); resolved when its rule is changed or the group deleted.
//   smart_group.mass_change    an automatic computation of a group an assignment targets went beyond the mass guard
//                              (D4: max(25, 10 % of the managed devices) entries and exits within the hour): nothing
//                              written, the group held until its pending changes are reviewed and applied (P0-5
//                              §4.3, §4.4); resolved by the release, a new rule or the deletion of the group.
// =============================================================================

export const SMART_GROUP_ALERTS = {
  'smart_group.rule_invalid': { scope: 'tenant', severity: 'warning', title: 'Dynamic group to fix', message: 'The rule of the dynamic group {name} names a static group that was deleted: its members are frozen until its rule is changed.' },
  'smart_group.mass_change': { scope: 'tenant', severity: 'warning', title: 'Dynamic group held', message: 'The inventory would change the members of the dynamic group {name} beyond {limit} entries and exits within the hour: nothing was applied, its changes wait to be reviewed.' },
} as const;

export type SmartGroupAlertKind = keyof typeof SMART_GROUP_ALERTS;

export const SMART_GROUP_ALERTS_FR: Record<SmartGroupAlertKind, { title: string; message: string }> = {
  'smart_group.rule_invalid': { title: 'Groupe dynamique à corriger', message: "La règle du groupe dynamique {name} cite un groupe statique qui a été supprimé : ses membres restent figés jusqu'à ce que sa règle soit modifiée." },
  'smart_group.mass_change': { title: 'Groupe dynamique suspendu', message: "L'inventaire changerait les membres du groupe dynamique {name} au-delà de {limit} entrées et sorties dans l'heure : rien n'a été appliqué, ses changements attendent d'être examinés." },
};

/** The definitions of the alerts of the dynamic groups for registerAlertDefinitions. */
export function smartGroupAlertDefinitions(): Array<{
  key: string; scope: 'tenant'; severity: 'info' | 'warning' | 'critical'; title: string; message: string;
  fr: { title: string; message: string }; i18nKey: string;
}> {
  return (Object.keys(SMART_GROUP_ALERTS) as SmartGroupAlertKind[]).map((k) => ({
    key: k, scope: SMART_GROUP_ALERTS[k].scope, severity: SMART_GROUP_ALERTS[k].severity, title: SMART_GROUP_ALERTS[k].title,
    message: SMART_GROUP_ALERTS[k].message, fr: SMART_GROUP_ALERTS_FR[k], i18nKey: `apple.alerts.${k}`,
  }));
}

// The kinds of the dynamic groups are raised by the catalogue service (type only).
declare module '../../services/alertCatalog' {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  interface CatalogAlertKinds extends Record<SmartGroupAlertKind, true> {}
}

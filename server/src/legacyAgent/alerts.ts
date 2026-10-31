// =============================================================================
// Closed catalogue of the alerts of the Android bridge agent (agent-pont-android §6; review PONT-R: filed under the
// family 'legacy_agent.'), declared in the catalogue of the alerts opened to the modules (services/alertCatalog.ts,
// registerAlertDefinitions, lot AN-P) by registerLegacyAgentModule, and raised by the catalogue service of the
// integration (apple/alerts/service.ts: stable key 'apple:<kind>', i18n key apple.alerts.<kind>, unchanged since
// they were part of the Apple catalogue). Same rules (I11): identifiers and counts only in the parameters. No import
// at run time: the unit tests load it.
// =============================================================================

export const LEGACY_AGENT_ALERTS = {
  'legacy_agent.admin_disabled': { scope: 'tenant', severity: 'warning', title: 'Device administrator disabled', message: 'The device administrator of the Android agent was disabled on a device: it can no longer be locked nor erased.' },
  'legacy_agent.identity_conflict': { scope: 'tenant', severity: 'warning', title: 'Android agent identity conflict', message: 'An Android agent declared a serial number or an IMEI already held by another managed device: check that it is the same device.' },
  'legacy_agent.silent': { scope: 'tenant', severity: 'warning', title: 'Android agents silent', message: '{count} Android agent(s) have not contacted the server for 24 hours.' },
  'legacy_agent.license_error': { scope: 'tenant', severity: 'warning', title: 'Knox licence refused', message: 'The Knox licence could not be activated on an Android agent device: silent installation and restart are unavailable.' },
  // Lot BANC §3.4: the agent was the owner of the device and is no longer, without a release asked by the server.
  'legacy_agent.device_owner_lost': { scope: 'tenant', severity: 'warning', title: 'Android agent no longer owner of the device', message: 'The Android agent of a device lost its device owner role without being asked to give the device back: the protections of the owner are gone.' },
} as const;

export type LegacyAgentAlertKind = keyof typeof LEGACY_AGENT_ALERTS;

export const LEGACY_AGENT_ALERTS_FR: Record<LegacyAgentAlertKind, { title: string; message: string }> = {
  'legacy_agent.admin_disabled': { title: "Administrateur de l'appareil désactivé", message: "L'administrateur de l'appareil de l'agent Android a été désactivé sur un appareil : il ne peut plus être verrouillé ni effacé." },
  'legacy_agent.identity_conflict': { title: "Conflit d'identité d'un agent Android", message: "Un agent Android a déclaré un numéro de série ou un IMEI déjà porté par un autre appareil géré : vérifiez qu'il s'agit du même appareil." },
  'legacy_agent.silent': { title: 'Agents Android silencieux', message: "{count} agent(s) Android n'ont pas contacté le serveur depuis 24 heures." },
  'legacy_agent.license_error': { title: 'Licence Knox refusée', message: "La licence Knox n'a pas pu être activée sur un appareil de l'agent Android : installation silencieuse et redémarrage indisponibles." },
  'legacy_agent.device_owner_lost': { title: "L'agent Android n'est plus propriétaire de l'appareil", message: "L'agent Android d'un appareil a perdu son rôle de propriétaire de l'appareil sans qu'on lui ait demandé de le rendre : les protections du propriétaire ont disparu." },
};

/** The definitions of the bridge agent's alerts for registerAlertDefinitions. */
export function legacyAgentAlertDefinitions(): Array<{
  key: string; scope: 'tenant' | 'master'; severity: 'info' | 'warning' | 'critical'; title: string; message: string;
  fr: { title: string; message: string }; i18nKey: string;
}> {
  return (Object.keys(LEGACY_AGENT_ALERTS) as LegacyAgentAlertKind[]).map((k) => ({
    key: k, scope: LEGACY_AGENT_ALERTS[k].scope, severity: LEGACY_AGENT_ALERTS[k].severity, title: LEGACY_AGENT_ALERTS[k].title,
    message: LEGACY_AGENT_ALERTS[k].message, fr: LEGACY_AGENT_ALERTS_FR[k], i18nKey: `apple.alerts.${k}`,
  }));
}

// The kinds of the bridge agent are raised by the catalogue service (type only).
declare module '../services/alertCatalog' {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  interface CatalogAlertKinds extends Record<LegacyAgentAlertKind, true> {}
}

import type { DeclarationProvider } from './engine';
import type { DeclarationSpec } from './validate';

// =============================================================================
// Core provider of the DDM engine (docs: integration-apple-edge §9.3): the
// status channel every managed device gets.
//   obg.cfg.status-subscriptions  com.apple.configuration.management.status-subscriptions
//       { StatusItems: [{ Name }…] }, sorted by name: the intersection of the
//       core list below, of what the device announced
//       (capabilities.statusItems) and of what the privacy rules of its
//       ownership allow (privacy.statusItems);
//   obg.act.core                  com.apple.activation.simple
//       { StandardConfigurations: ['obg.cfg.status-subscriptions'] }.
// management.client-capabilities and management.declarations are reported by
// the device without a subscription. Pure: no database read.
// =============================================================================

/** Status items the core subscribes every device to (when announced and allowed). */
export const CORE_STATUS_ITEMS: readonly string[] = [
  'app.managed.list',
  'device.model.family',
  'device.model.identifier',
  'device.model.marketing-name',
  'device.operating-system.build-version',
  'device.operating-system.family',
  'device.operating-system.marketing-name',
  'device.operating-system.supplemental.build-version',
  'device.operating-system.supplemental.extra-version',
  'device.operating-system.version',
  'passcode.is-compliant',
  'passcode.is-present',
  'security.certificate.list',
  'softwareupdate.failure-reason',
  'softwareupdate.install-reason',
  'softwareupdate.install-state',
  'softwareupdate.pending-version',
];
/** Identifiers: subscribed only when the privacy rules of the ownership allow them. */
export const IDENTIFIER_STATUS_ITEMS: readonly string[] = ['device.identifier.serial-number', 'device.identifier.udid'];
/** Always reported by a device, without subscription. */
export const UNSUBSCRIBED_STATUS_ITEMS: readonly string[] = ['management.client-capabilities', 'management.declarations'];

/** Every status item the engine reads in a report (the names a report is flattened down to). */
export const KNOWN_STATUS_ITEMS: ReadonlySet<string> = new Set([...CORE_STATUS_ITEMS, ...IDENTIFIER_STATUS_ITEMS, ...UNSUBSCRIBED_STATUS_ITEMS]);

export const SUBSCRIPTIONS_IDENTIFIER = 'obg.cfg.status-subscriptions';
export const SUBSCRIPTIONS_TYPE = 'com.apple.configuration.management.status-subscriptions';
export const CORE_ACTIVATION_IDENTIFIER = 'obg.act.core';
export const SIMPLE_ACTIVATION_TYPE = 'com.apple.activation.simple';

/** The two declarations of the core for a list of status items (sorted by name here). */
export function coreDeclarations(statusItems: readonly string[]): DeclarationSpec[] {
  const names = [...new Set(statusItems)].sort();
  if (names.length === 0) return [];
  return [
    { family: 'configuration', identifier: SUBSCRIPTIONS_IDENTIFIER, type: SUBSCRIPTIONS_TYPE, payload: { StatusItems: names.map((Name) => ({ Name })) } },
    { family: 'activation', identifier: CORE_ACTIVATION_IDENTIFIER, type: SIMPLE_ACTIVATION_TYPE, payload: { StandardConfigurations: [SUBSCRIPTIONS_IDENTIFIER] } },
  ];
}

export const coreProvider: DeclarationProvider = {
  name: 'core',
  owns: /^obg\.(cfg\.status-subscriptions|act\.core)$/,
  async declarationsFor(_trx, ctx) {
    if (!ctx.capabilities) return [];
    const announced = new Set(ctx.capabilities.statusItems);
    const allowed = new Set(ctx.privacy.statusItems);
    return coreDeclarations([...CORE_STATUS_ITEMS, ...IDENTIFIER_STATUS_ITEMS].filter((n) => announced.has(n) && allowed.has(n)));
  },
};

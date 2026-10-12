import type { DdmClientCapabilities } from './capabilities';

// =============================================================================
// Reference client capabilities by OS (docs: integration-apple-edge §9.3,
// annex D J-7): the fallback of a device that activated the DDM but reported
// no management.client-capabilities within 15 minutes. Deliberately minimal:
// the simple activation, the status subscriptions, and the status items of the
// core list that Apple documents for the OS. iOS and iPadOS 17 and later only;
// anything else keeps an empty set until the device speaks. A device's own
// report always replaces this. Self-contained: the unit tests run under
// node --test.
// =============================================================================

/** After the first acknowledged DeclarativeManagement, how long the engine waits for the capabilities. */
export const BASELINE_AFTER_SECONDS = 15 * 60;

/** Status items of the core list, with the first iOS / iPadOS release that documents them ([major, minor]). */
const ITEMS_SINCE: ReadonlyArray<[string, number, number]> = [
  ['device.identifier.serial-number', 15, 0],
  ['device.identifier.udid', 15, 0],
  ['device.model.family', 15, 0],
  ['device.model.identifier', 15, 0],
  ['device.model.marketing-name', 15, 0],
  ['device.operating-system.build-version', 15, 0],
  ['device.operating-system.family', 15, 0],
  ['device.operating-system.marketing-name', 15, 0],
  ['device.operating-system.version', 15, 0],
  ['device.operating-system.supplemental.build-version', 16, 1],
  ['device.operating-system.supplemental.extra-version', 16, 1],
  ['passcode.is-compliant', 16, 0],
  ['passcode.is-present', 16, 0],
  ['softwareupdate.failure-reason', 17, 0],
  ['softwareupdate.install-reason', 17, 0],
  ['softwareupdate.install-state', 17, 0],
  ['softwareupdate.pending-version', 17, 0],
  ['security.certificate.list', 17, 0],
  ['app.managed.list', 17, 2],
];

/** '17.5.1' → [17, 5]; null when the version is not readable. */
export function majorMinor(version: string | null | undefined): [number, number] | null {
  const m = /^([0-9]{1,3})(?:\.([0-9]{1,3}))?/.exec(String(version ?? '').trim());
  return m ? [Number(m[1]), Number(m[2] ?? 0)] : null;
}

/** The reference capabilities of a platform and an OS version, or null when the engine knows none for them. */
export function baselineCapabilities(platform: string | null, osVersion: string | null): DdmClientCapabilities | null {
  if (platform !== 'ios' && platform !== 'ipados') return null;
  const v = majorMinor(osVersion);
  if (!v || v[0] < 17) return null;
  const [major, minor] = v;
  return {
    supportedVersions: ['1.0.0'],
    declarationTypes: {
      activation: ['com.apple.activation.simple'],
      asset: [],
      configuration: ['com.apple.configuration.management.status-subscriptions'],
      management: [],
    },
    statusItems: ITEMS_SINCE.filter(([, a, b]) => major > a || (major === a && minor >= b)).map(([name]) => name).sort(),
    supportedFeatures: {},
  };
}

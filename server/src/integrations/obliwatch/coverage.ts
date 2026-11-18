import type { CollectedField, ObliwatchAppsCoverage, ObliwatchCoverage, ObliwatchIntegrityCoverage } from '@obligarth/shared';

// =============================================================================
// The coverage a device declares to Obliwatch (brief GTH-09): what Obligarth can see of it, so that a datum not
// collected is never presented as healthy.
//   integrity   amapi: 'covered' when Play Integrity reported a posture, 'unknown' otherwise (owner decision Q-L2b,
//               announced to Obliwatch); apple_mdm: 'not_covered_apple' (no attestation nor jailbreak datum);
//               legacy_agent: 'not_covered_legacy' (its attestation is not verified, legacyAgent/enroll.ts).
//   apps        'none' while the channel has collected nothing yet (Apple: neither list; AMAPI: no report, or no app
//               in the report; bridge agent: no inventory); 'full' when the privacy profile of the device collects
//               every app (privacy/collected.ts: allApps; Apple: the installed list received too); 'managed_only'
//               otherwise (a personal or COPE device, or a profile limited to the managed apps).
//   securityLogs  always false (no security log is ingested, GTH-08).
// =============================================================================

/** The facts of a device the coverage reads (selected by devices.ts, never an identifier). */
export interface CoverageFacts {
  channel: string;
  /** AMAPI: the posture of the satellite still under management, else null. */
  posture: unknown;
  amapiReportAt: unknown;
  agentInventoryAt: unknown;
  appleAppsAt: unknown;
  appleManagedAppsAt: unknown;
  hasApps: boolean;
}

export function integrityCoverage(f: CoverageFacts): ObliwatchIntegrityCoverage {
  if (f.channel === 'amapi') return f.posture && typeof f.posture === 'object' ? 'covered' : 'unknown';
  if (f.channel === 'apple_mdm') return 'not_covered_apple';
  if (f.channel === 'legacy_agent') return 'not_covered_legacy';
  return 'unknown';
}

export function appsCoverage(f: CoverageFacts, collected: readonly CollectedField[]): ObliwatchAppsCoverage {
  const all = collected.includes('allApps');
  if (f.channel === 'apple_mdm') {
    if (!f.appleAppsAt && !f.appleManagedAppsAt) return 'none';
    // Every app is known only once the installed list came (the managed list alone holds the managed apps).
    return all && f.appleAppsAt ? 'full' : 'managed_only';
  }
  if (f.channel === 'amapi') {
    if (!f.amapiReportAt || !f.hasApps) return 'none';
    return all ? 'full' : 'managed_only';
  }
  if (f.channel === 'legacy_agent') {
    if (!f.agentInventoryAt) return 'none';
    return all ? 'full' : 'managed_only';
  }
  return 'none';
}

export function coverageOf(f: CoverageFacts, collected: readonly CollectedField[]): ObliwatchCoverage {
  return { integrity: integrityCoverage(f), apps: appsCoverage(f, collected), securityLogs: false };
}

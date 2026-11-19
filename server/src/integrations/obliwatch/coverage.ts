import type {
  CollectedField, ObliwatchAppsCoverage, ObliwatchAttestationCoverage, ObliwatchCoverage, ObliwatchIntegrityCoverage,
} from '@obligarth/shared';
import { obliwatchIntegrationEnabled } from './config';

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
//   securityLogs  (lot L5, GTH-08, SEC-13) true only when they are actually collected: an AMAPI company-owned fully
//               managed device (securityLogs.ts), OBLIWATCH_INTEGRATION on, the push consent of the tenant, and security
//               logs received from the device within 7 days. Anything else is false: NOT COLLECTED, never healthy.
//   attestation (lot L5, GTH-08) Apple only: 'verified' or 'failed' from the last verdict of the managed device
//               attestation (appleAttestation.ts) of at most 30 days, with the push consent; 'not_collected' otherwise;
//               'not_applicable' for the other channels.
// =============================================================================

/** A verdict of attestation older than this is not presented (the devices are attested once a week). */
const ATTESTATION_FRESH_MS = 30 * 86_400_000;
const SECURITY_LOGS_FRESH_MS = 7 * 86_400_000;

/** The facts of a device the coverage reads (selected by devices.ts, never an identifier). */
export interface CoverageFacts {
  /** devices.ownership and management_mode (the security logs: company-owned fully managed only). */
  ownership?: string;
  mode?: string;
  /** The push consent of the tenant (the security logs and the attestation are collected under it only). */
  pushConsent?: boolean;
  /** device_security_log_status.last_received_at. */
  securityLogsAt?: unknown;
  /** apple_device_attestations: state and checked_at. */
  attestationState?: unknown;
  attestationAt?: unknown;
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

const fresh = (v: unknown, ms: number, now: number): boolean => {
  if (v === null || v === undefined) return false;
  const t = new Date(v as string).getTime();
  return Number.isFinite(t) && now - t <= ms;
};

export function securityLogsCoverage(f: CoverageFacts, now = Date.now()): boolean {
  return obliwatchIntegrationEnabled() && f.pushConsent === true && f.channel === 'amapi' && f.ownership === 'corporate'
    && f.mode === 'fully_managed' && fresh(f.securityLogsAt, SECURITY_LOGS_FRESH_MS, now);
}

export function attestationCoverage(f: CoverageFacts, now = Date.now()): ObliwatchAttestationCoverage {
  if (f.channel !== 'apple_mdm') return 'not_applicable';
  if (f.pushConsent !== true || !fresh(f.attestationAt, ATTESTATION_FRESH_MS, now)) return 'not_collected';
  return f.attestationState === 'verified' ? 'verified' : f.attestationState === 'failed' ? 'failed' : 'not_collected';
}

export function coverageOf(f: CoverageFacts, collected: readonly CollectedField[]): ObliwatchCoverage {
  return {
    integrity: integrityCoverage(f), apps: appsCoverage(f, collected), securityLogs: securityLogsCoverage(f), attestation: attestationCoverage(f),
  };
}

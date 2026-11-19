import type { ObliwatchRuleId } from '@obligarth/shared';

// =============================================================================
// The D-MOB-* rules Obligarth computes for Obliwatch (brief GTH-01 §4, table of the rules). Pure: no I/O, the unit of
// what signals.ts records. A rule is computed on a TRANSITION only, never continuously:
//   - state rules (INT-*, NONCOMPLIANT, STALE, OS-OUTDATED, and MGMT-REMOVED from the AMAPI state DISABLED or the
//     bridge agent's administrator): active while the condition holds, 'cleared' (same ruleId, details.state
//     'cleared') when it ends. A datum that is not known (no posture, a compliance 'unknown' or 'exempt', the reset
//     of an unenrollment) decides nothing: the state is left as it is;
//   - event rules (ID-MISMATCH, MGMT-REMOVED of a departure, LOST-EXIT): each occurrence is a new transition.
// =============================================================================

export type SignalSeverity = 'info' | 'low' | 'medium' | 'high';

export interface RuleDefinition {
  title: string;
  severity: SignalSeverity;
  mitre?: { tactics: string[]; techniques: string[] };
}

/** Titles (English: Obliwatch translates by ruleId), base severities and MITRE of the rules (brief §4 GTH-01). */
export const RULES: Readonly<Record<ObliwatchRuleId, RuleDefinition>> = {
  'D-MOB-INT-COMPROMISED': { title: 'Android device integrity compromised', severity: 'high', mitre: { tactics: [], techniques: ['T1398'] } },
  'D-MOB-INT-ATRISK': { title: 'Android device integrity at risk', severity: 'medium' },
  'D-MOB-MGMT-REMOVED': { title: 'Company device removed from management', severity: 'high' },
  'D-MOB-ID-MISMATCH': { title: 'Mobile device identity mismatch', severity: 'high' },
  'D-MOB-OS-OUTDATED': { title: 'Mobile device operating system outdated', severity: 'low' },
  'D-MOB-NONCOMPLIANT': { title: 'Mobile device non-compliant', severity: 'low' },
  'D-MOB-STALE': { title: 'Mobile device without contact', severity: 'info' },
  'D-MOB-LOST-EXIT': { title: 'Lost mode left by the user', severity: 'high' },
  // Lot L5 (GTH-08). A state rule: active while the last Apple managed device attestation of the device failed (reason
  // codes attestation_failed and the cause: chain_invalid, identity_mismatch, freshness_mismatch, malformed), cleared by
  // the next one that verifies (appleAttestation.ts).
  'D-MOB-ATTEST-FAILED': { title: 'Apple managed device attestation failed', severity: 'high' },
  // SEC-13: events of the AMAPI security logs, aggregated (securityLogs.ts): at most one transition per device, rule and
  // window (details.count, details.windowMinutes), never a raw log.
  'D-MOB-SEC-USER-CA': { title: 'Certificate authority installed on a company Android device', severity: 'medium' },
  'D-MOB-SEC-ADB': { title: 'ADB shell used on a company Android device', severity: 'medium' },
  'D-MOB-SEC-UNLOCK-BURST': { title: 'Burst of failed unlock attempts on a company Android device', severity: 'medium' },
  'D-MOB-SEC-KEY-INTEGRITY': { title: 'Key integrity violation on a company Android device', severity: 'high' },
  'D-MOB-SEC-LOGGING-STOPPED': { title: 'Security logging stopped on a company Android device', severity: 'medium' },
};

/** A wanted state of a rule of a device (signals.ts compares it with device_signal_state). */
export interface RuleState {
  deviceId: number;
  ruleId: ObliwatchRuleId;
  state: 'active' | 'cleared';
  severity: SignalSeverity;
  /** What makes a new 'active' while active (the severity of NONCOMPLIANT); null otherwise. */
  fingerprint: string | null;
  /** The whitelisted details of the brief, beyond platform, ownership, managementMode and state (signals.ts). */
  reasonCodes: string[];
  posture?: string | null;
  risks?: string[] | null;
  /** An aggregated detection (SEC-13): the events counted in its window, and the window's length. */
  count?: number;
  windowMinutes?: number;
}

const CODE_RE = /^[a-z_]{1,40}$/;

/** The codes of compliance reasons (never their detail), deduplicated, 20 at most. */
export function reasonCodesOf(reasons: unknown): string[] {
  const list = Array.isArray(reasons) ? reasons : [];
  const codes = list.map((x) => (x && typeof x === 'object' ? (x as { code?: unknown }).code : x))
    .filter((c): c is string => typeof c === 'string' && CODE_RE.test(c));
  return [...new Set(codes)].slice(0, 20);
}

const STALE_CODES = ['stale', 'no_contact'];
const OUTDATED_CODES = ['os_update_overdue', 'os_outdated'];

export interface ComplianceInput {
  deviceId: number;
  /** devices.management_channel. */
  channel: string;
  state: string;
  codes: string[];
  /** An AMAPI device DISABLED by Obligarth itself (an operator's disable, an approval hold): never MGMT-REMOVED, and
   *  management_disabled is not counted as a non-compliance. */
  operatorDisabled?: boolean;
  /** A personal device: MGMT-REMOVED is for company devices only. */
  personal?: boolean;
}

/** The wanted states of the compliance rules of a device whose compliance changed (Apple, bridge agent, AMAPI). */
export function complianceRuleStates(c: ComplianceInput): RuleState[] {
  // 'unknown' (no inventory yet, the reset of an unenrollment) and 'exempt' decide nothing.
  if (c.state !== 'compliant' && c.state !== 'non_compliant') return [];
  const out: RuleState[] = [];
  const codes = c.operatorDisabled ? c.codes.filter((x) => x !== 'management_disabled') : c.codes;
  const has = (list: string[]) => codes.filter((x) => list.includes(x));
  const rs = (ruleId: ObliwatchRuleId, active: boolean, reasonCodes: string[], severity = RULES[ruleId].severity, fingerprint: string | null = null): RuleState =>
    ({ deviceId: c.deviceId, ruleId, state: active ? 'active' : 'cleared', severity, fingerprint: active ? fingerprint : null, reasonCodes: active ? reasonCodes : [] });
  // NONCOMPLIANT: low, medium with a passcode reason. A device non-compliant only because Obligarth disabled it
  // decides nothing.
  if (!(c.state === 'non_compliant' && codes.length === 0)) {
    const active = c.state === 'non_compliant';
    const severity: SignalSeverity = codes.includes('passcode') ? 'medium' : 'low';
    out.push(rs('D-MOB-NONCOMPLIANT', active, codes, severity, severity));
  }
  out.push(rs('D-MOB-STALE', has(STALE_CODES).length > 0, has(STALE_CODES)));
  out.push(rs('D-MOB-OS-OUTDATED', has(OUTDATED_CODES).length > 0, has(OUTDATED_CODES)));
  // MGMT-REMOVED from the AMAPI state DISABLED (a user-side or Google-side disable), company devices only.
  if (c.channel === 'amapi' && !c.operatorDisabled && !c.personal) {
    const disabled = codes.includes('management_disabled');
    out.push(rs('D-MOB-MGMT-REMOVED', disabled, disabled ? ['management_disabled'] : []));
  }
  return out;
}

/** The Play Integrity posture of an AMAPI report, reduced ({devicePosture, risks}). */
export interface PostureInput { devicePosture: string; risks: string[] }

/** The wanted states of INT-COMPROMISED and INT-ATRISK (two distinct rules: AT_RISK → POTENTIALLY_COMPROMISED clears
 *  the first and raises the second). No posture: nothing decided. */
export function postureRuleStates(deviceId: number, p: PostureInput | null): RuleState[] {
  if (!p || !p.devicePosture) return [];
  const risks = (p.risks ?? []).filter((r) => typeof r === 'string').map((r) => r.slice(0, 60)).slice(0, 20);
  const compromised = p.devicePosture === 'POTENTIALLY_COMPROMISED' || risks.includes('COMPROMISED_OS');
  const atRisk = !compromised && p.devicePosture === 'AT_RISK';
  const posture = p.devicePosture.slice(0, 40);
  const one = (ruleId: ObliwatchRuleId, active: boolean): RuleState => ({
    deviceId, ruleId, state: active ? 'active' : 'cleared', severity: RULES[ruleId].severity, fingerprint: null,
    reasonCodes: active ? ['integrity_at_risk'] : [], posture, risks,
  });
  return [one('D-MOB-INT-COMPROMISED', compromised), one('D-MOB-INT-ATRISK', atRisk)];
}

/** The alerts of the catalogue that are, for one device, an event of a rule (raised once per occurrence: the alert's
 *  dedup on its open row is the transition). Keyed by kind: [ruleId, reason code]. */
export const ALERT_EVENT_RULES: Readonly<Record<string, readonly [ObliwatchRuleId, string]>> = {
  'security.identity_mismatch': ['D-MOB-ID-MISMATCH', 'identity_mismatch'],
  'device.serial_changed': ['D-MOB-ID-MISMATCH', 'serial_changed'],
  'enrollment.reenrolled_without_proof': ['D-MOB-ID-MISMATCH', 'reenrolled_without_proof'],
  'legacy_agent.identity_conflict': ['D-MOB-ID-MISMATCH', 'identity_conflict'],
  // Raised for company devices only (handlers.mdm.ts): the user removed the MDM profile.
  'device.checked_out': ['D-MOB-MGMT-REMOVED', 'checked_out'],
  // The bridge agent: its administrator disabled, its owner role lost without a release asked (poll.ts).
  'legacy_agent.admin_disabled': ['D-MOB-MGMT-REMOVED', 'admin_disabled'],
  'legacy_agent.device_owner_lost': ['D-MOB-MGMT-REMOVED', 'device_owner_lost'],
};

/** The label of a platform in asset.os ('Android 15', 'iOS 18.1'). */
export function osLabel(platform: string, version: string | null): string | null {
  const names: Record<string, string> = { ios: 'iOS', ipados: 'iPadOS', macos: 'macOS', tvos: 'tvOS', visionos: 'visionOS', android: 'Android' };
  const name = names[platform];
  if (!name) return null;
  return (version ? `${name} ${version}` : name).slice(0, 128);
}

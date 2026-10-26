import type { AndroidDeviceView, ComplianceReason, DeviceDetail, LegacyAgentDeviceDetail } from '@obligarth/shared';

// The health of a device as the console derives it from the record (no server score): 100 minus one penalty per
// problem found, floored at 0. An indicator for the operator, not a stored state: the lost mode is an alert without a
// penalty, and a device out of management has no score.

export type HealthIssueKey = 'nonCompliant' | 'stale' | 'never' | 'quiet' | 'configError' | 'configPending' | 'noPasscode'
  | 'storageFull' | 'batteryLow' | 'osUpdatePending' | 'integrityRisk' | 'adminInactive' | 'lostMode';

export interface HealthIssue {
  key: HealthIssueKey;
  /** Points taken from 100 (0: an alert only). */
  penalty: number;
  severity: 'red' | 'amber' | 'info';
  /** nonCompliant: the reasons; osUpdatePending, storageFull, batteryLow: a figure. */
  reasons?: ComplianceReason['code'][];
  detail?: string;
  /** integrityRisk: the AMAPI risk codes (translated where shown, android.enums.securityRisk.*). */
  risks?: string[];
}

export interface DeviceHealth {
  /** 0-100; null for a device out of management. */
  score: number | null;
  issues: HealthIssue[];
}

export const HEALTH_PENALTY: Record<Exclude<HealthIssueKey, 'lostMode'>, number> = {
  nonCompliant: 30, stale: 25, never: 15, quiet: 10, configError: 15, configPending: 5, noPasscode: 20, storageFull: 10,
  batteryLow: 5, osUpdatePending: 5, integrityRisk: 20, adminInactive: 25,
};

/** Storage used, percent 0-100, or null without both figures. */
export function storageUsedPercent(d: Pick<DeviceDetail, 'storageCapacityBytes' | 'storageAvailableBytes'>): number | null {
  const cap = d.storageCapacityBytes;
  const free = d.storageAvailableBytes;
  if (!cap || cap <= 0 || free === null || free === undefined || free < 0) return null;
  return Math.min(100, Math.max(0, ((cap - free) / cap) * 100));
}

/** The AMAPI posture says the device is at risk (a posture other than SECURE, or risks listed). */
export function androidAtRisk(view: Pick<AndroidDeviceView, 'posture'> | null | undefined): boolean {
  const p = view?.posture;
  if (!p) return false;
  return p.risks.length > 0 || p.devicePosture === 'AT_RISK' || p.devicePosture === 'POTENTIALLY_COMPROMISED';
}

export function deviceHealth(device: DeviceDetail, extra: { android?: AndroidDeviceView | null; legacy?: LegacyAgentDeviceDetail | null } = {}): DeviceHealth {
  const issues: HealthIssue[] = [];
  const add = (key: Exclude<HealthIssueKey, 'lostMode'>, severity: HealthIssue['severity'], more: Partial<HealthIssue> = {}) => {
    issues.push({ key, penalty: HEALTH_PENALTY[key], severity, ...more });
  };
  if (device.lostModeState !== 'off') issues.push({ key: 'lostMode', penalty: 0, severity: 'red' });
  if (device.enrollmentState === 'unenrolled') return { score: null, issues };

  if (device.complianceState === 'non_compliant') add('nonCompliant', 'red', { reasons: device.complianceReasons.map((r) => r.code) });
  if (device.contactState === 'stale') add('stale', 'red');
  else if (device.contactState === 'never') add('never', 'amber');
  else if (device.contactState === 'quiet') add('quiet', 'amber');
  if (device.configState === 'error') add('configError', 'red');
  else if (device.configState === 'pending') add('configPending', 'info');
  if (device.apple?.security?.passcodePresent === false) add('noPasscode', 'red');
  const used = storageUsedPercent(device);
  if (used !== null && used > 90) add('storageFull', 'amber', { detail: `${Math.round(used)} %` });
  if (device.battery && device.battery.level < 15 && device.battery.charging !== true) add('batteryLow', 'amber', { detail: `${device.battery.level} %` });
  const pendingOs = device.apple?.security?.pendingOsVersion;
  if (pendingOs) add('osUpdatePending', 'info', { detail: pendingOs });
  if (androidAtRisk(extra.android)) add('integrityRisk', 'red', { risks: extra.android?.posture?.risks ?? [] });
  if (extra.legacy && extra.legacy.adminActive === false) add('adminInactive', 'red');

  const score = Math.max(0, 100 - issues.reduce((sum, i) => sum + i.penalty, 0));
  return { score, issues };
}

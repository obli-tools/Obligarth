// =============================================================================
// Impact preview of a change of the effective configuration (docs:
// modele-donnees-mdm §7.11, §7.12, PLT-18): the devices it touches, the keys
// and artifacts it adds, changes and removes, the conflicts it would create,
// and whether a second approver is required (DM23).
// =============================================================================
import type { SourceScope } from './effective';

export type ImpactApprovalReason = 'devices_threshold' | 'fleet_share' | 'removal_threshold' | 'restriction';

export interface PolicyConflict {
  settingKey: string;
  target: { scope: SourceScope; id: number | null };
  priority: number;
  resources: Array<{ type: 'policy' | 'app'; id: number; name: string }>;
}

export interface PolicyImpact {
  computedAt: string;
  devicesInScope: number;
  devicesTouched: number;          // at least one effective key changes
  devicesAdded: number;            // the resource starts applying
  devicesRemoved: number;          // the resource stops applying
  keys: Array<{ settingKey: string; added: number; changed: number; removed: number; notApplicable: number }>;
  artifacts: { installs: number; removals: number; kioskLockChanges: number; appRemovals: number };
  conflicts: PolicyConflict[];
  sample: Array<{ deviceId: number; label: string; added: string[]; changed: string[]; removed: string[] }>;  // 50 devices max
  fleetSize: number;
  approval: { required: boolean; reasons: ImpactApprovalReason[] };
  /** Devices with at least one removal (artifact, kiosk lock, app): the measure of the removal threshold. */
  removalDevices?: number;
  /** Signed token of the full list of touched devices (GET /api/mdm/impact/:token/devices), 15 minutes. */
  devicesToken?: string | null;
}

/** A page of GET /api/mdm/impact/:token/devices (the caller's scopes apply). */
export interface ImpactDevicesPage {
  total: number;
  page: number;
  pageSize: number;
  devices: Array<{ deviceId: number; label: string; added: string[]; changed: string[]; removed: string[] }>;
}

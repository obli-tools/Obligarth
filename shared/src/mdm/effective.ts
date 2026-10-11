// =============================================================================
// Effective configuration of a device (docs: modele-donnees-mdm §7.6, §7.8,
// §7.10): one row per setting key retained by the resolution, with its
// provenance, its availability and its conflicts (device_effective_settings),
// and the state of its artifacts (device_artifacts, lot B5c).
// =============================================================================
import type { ArtifactState, ConfigState } from './enums';
import type { JsonValue } from './policyContent';

export type SourceScope = 'device' | 'group' | 'tenant' | 'library';

/** Why a setting does not apply to a device, in the order of section 7.8. */
export const UNAVAILABLE_REASONS = [
  'schema_unknown', 'platform_unsupported', 'enrollment_type_unsupported', 'supervision_required', 'os_removed',
  'os_too_old', 'ownership_forbidden', 'client_unsupported', 'asset_not_supported', 'variable_unresolved',
  'license_unavailable',
] as const;
export type UnavailableReason = typeof UNAVAILABLE_REASONS[number];

export type SettingAvailability = { status: 'available' } | { status: 'not_applicable'; reason: UnavailableReason; detail?: string };

export interface SettingConflictEntry {
  type: 'policy' | 'app';
  id: number;
  tenantId: number;
  assignmentId: number;
  valueHash: string;
}

export interface EffectiveSetting {
  settingKey: string;
  artifactKey: string | null;
  valueHash: string;
  removed: boolean;
  source: { type: 'policy' | 'app'; id: number; tenantId: number; versionId: number | null;
            assignmentId: number; scope: SourceScope; scopeId: number | null; rank: number; priority: number };
  availability: SettingAvailability;
  conflict: null | SettingConflictEntry[];
}

/** A row of GET /api/mdm/devices/:id/configuration: the stored setting, its value (never a secret: a secret
 *  reference shows as {"$secret": true}) and the names of its sources. */
export interface EffectiveSettingView extends EffectiveSetting {
  /** Schema type, top-level key (keyed types) and instance (collections). */
  type: string;
  key: string | null;
  instance: string | null;
  value?: JsonValue;
  sourceName: string | null;
  sourceVersion: number | null;
  conflictNames: Array<{ type: 'policy' | 'app'; id: number; name: string | null }>;
  computedAt: string;
}

export interface DeviceArtifactView {
  artifactKey: string;
  channel: 'ddm' | 'profile' | 'setting' | 'app';
  state: ArtifactState;
  stateReasons: string[];
  desiredAt: string;
  deliveredAt: string | null;
  stateAt: string;
  /** The setting keys that produced the artifact. */
  sources: string[];
}

export interface DeviceConfigurationView {
  deviceId: number;
  configState: ConfigState;
  settings: EffectiveSettingView[];
  artifacts: DeviceArtifactView[];
}

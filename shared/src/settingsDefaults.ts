// =============================================================================
// Obligarth MDM — Settings Keys & Defaults
// =============================================================================

export const SETTINGS_KEYS = {
  NOTIFICATION_COOLDOWN:    'notificationCooldown',   // min seconds between alerts
  INVENTORY_RETENTION_DAYS: 'inventoryRetentionDays', // how long to keep inventory snapshots
  TFA_TRUST_HOURS:          'tfaTrustHours',          // how long a "trust this IP" 2FA grant lasts
  MDM_STALE_AFTER_DAYS:     'mdmStaleAfterDays',      // device contact: stale after (MDM data model)
  PUBLISH_FLEET_SHARE_FLOOR: 'publishFleetShareFloor', // DM23: devices touched before the 10 % share of the fleet counts
} as const;

export type SettingKey = typeof SETTINGS_KEYS[keyof typeof SETTINGS_KEYS];

export interface SettingDefinition {
  key: SettingKey;
  label: string;
  description: string;
  type: 'number' | 'boolean';
  unit?: string;
  min?: number;
  max?: number;
  defaultValue: number | boolean;
  /** Tenant-wide policy that makes no sense to override per group/device.
   *  When true, the setting is only shown/editable at the global scope —
   *  the group and device settings panels hide it. */
  globalOnly?: boolean;
}

export const SETTINGS_DEFINITIONS: SettingDefinition[] = [
  {
    key: SETTINGS_KEYS.NOTIFICATION_COOLDOWN,
    label: 'Notification Cooldown',
    description: 'Minimum time between repeated alerts for the same device',
    type: 'number',
    unit: 'seconds',
    min: 0,
    max: 86400,
    defaultValue: 300,
  },
  {
    key: SETTINGS_KEYS.INVENTORY_RETENTION_DAYS,
    label: 'Inventory Retention',
    description: 'How long to keep historical inventory snapshots',
    type: 'number',
    unit: 'days',
    min: 7,
    max: 365,
    defaultValue: 90,
    globalOnly: true,
  },
  {
    key: SETTINGS_KEYS.TFA_TRUST_HOURS,
    label: '2FA "Trust this IP" duration',
    description: 'How long a "Trust this IP" choice skips the 2FA prompt for a user from the same IP after a successful code. 0 = disable IP trust (always prompt).',
    type: 'number',
    unit: 'hours',
    min: 0,
    max: 8760,
    defaultValue: 24,
    globalOnly: true,
  },
  {
    key: SETTINGS_KEYS.MDM_STALE_AFTER_DAYS,
    label: 'Device contact: stale after',
    description: 'A managed device without any contact for this many days is shown and counted as without contact.',
    type: 'number',
    unit: 'days',
    min: 1,
    max: 90,
    defaultValue: 7,
    globalOnly: true,
  },
  {
    // DM23 (modele-donnees-mdm §7.12; decision of the owners of 15/10/2026): on a small fleet, 10 % would ask a
    // second approver for almost every change. Bounded by the absolute threshold of 25 devices, which applies anyway.
    key: SETTINGS_KEYS.PUBLISH_FLEET_SHARE_FLOOR,
    label: 'Second approver: share of the fleet counted from',
    description: 'A change of the configuration (publication, assignments, group, devices moved) asks a second approver when it touches 10 % of the fleet or more, once it touches at least this many devices.',
    type: 'number',
    unit: 'devices',
    min: 1,
    max: 25,
    defaultValue: 5,
    globalOnly: true,
  },
];

export const HARDCODED_DEFAULTS: Record<SettingKey, number | boolean> = {
  [SETTINGS_KEYS.NOTIFICATION_COOLDOWN]:    300,
  [SETTINGS_KEYS.INVENTORY_RETENTION_DAYS]: 90,
  [SETTINGS_KEYS.TFA_TRUST_HOURS]:          24,
  [SETTINGS_KEYS.MDM_STALE_AFTER_DAYS]:     7,
  [SETTINGS_KEYS.PUBLISH_FLEET_SHARE_FLOOR]: 5,
};

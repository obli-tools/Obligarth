import type { TFunction } from 'i18next';
import {
  DEVICE_LIFECYCLE_STATUSES, DEVICE_WARRANTY_STATUSES, RULE_FIELDS, RULE_FIELD_KEYS,
  type ComplianceState, type ConfigState, type DeviceUsage, type EndUserStatus, type EnrollmentState, type ManagementChannel,
  type RuleFieldDef, type RuleFieldKey, type RuleIssueCode, type RuleOp, type RuleUse,
} from '@obligarth/shared';
import { complianceLabel, configLabel, enrollmentLabel } from '@/components/mdm/DeviceStateBadges';
import { enrollmentMethodLabel, managementModeLabel, ownershipLabel, platformLabel } from '@/components/mdm/PlatformIcon';

// =============================================================================
// What the console shows of the rule language (shared/src/mdm/rules.ts, P0-5 §2): the label of each field of the
// catalog, its category in the field picker, the labels of the operators, of the values of the enum fields and of
// the issues of validateRule, and why a field is not permitted in a use (D2). The catalog itself (types, operators,
// values, bounds) is the shared one: the console never adds a field nor an operator.
// =============================================================================

/** The categories of the field picker, in display order. */
export const RULE_CATEGORIES = ['device', 'management', 'asset', 'labels', 'user', 'android', 'inventory', 'state'] as const;
export type RuleCategory = typeof RULE_CATEGORIES[number];

export const RULE_FIELD_CATEGORY: Readonly<Record<RuleFieldKey, RuleCategory>> = {
  platform: 'device', os_version: 'device', model: 'device', model_name: 'device', name: 'device', serial_number: 'device',
  supervised: 'device', storage_capacity_gb: 'device',
  ownership: 'management', management_mode: 'management', management_channel: 'management', enrollment_type: 'management',
  usage: 'management', enrollment_state: 'management',
  lifecycle_status: 'asset', warranty_status: 'asset',
  tags: 'labels', custom_field: 'labels',
  'end_user.assigned': 'user', 'end_user.email': 'user', 'end_user.external_id': 'user', 'end_user.status': 'user',
  'android.api_level': 'android', 'android.security_patch_level': 'android',
  group: 'inventory', 'app.installed': 'inventory',
  compliance_state: 'state', config_state: 'state', last_checkin: 'state', enrolled_at: 'state',
};

/** The fields of a category, in catalog order. */
export const fieldsOfCategory = (c: RuleCategory): RuleFieldKey[] => RULE_FIELD_KEYS.filter((k) => RULE_FIELD_CATEGORY[k] === c);

// The translation key of a field: the catalog's key without its dots (an i18n key separator).
const FIELD_I18N = {
  platform: 'platform', os_version: 'os_version', model: 'model', model_name: 'model_name', name: 'name',
  serial_number: 'serial_number', ownership: 'ownership', management_mode: 'management_mode',
  management_channel: 'management_channel', enrollment_type: 'enrollment_type', supervised: 'supervised', usage: 'usage',
  enrollment_state: 'enrollment_state', lifecycle_status: 'lifecycle_status', warranty_status: 'warranty_status',
  storage_capacity_gb: 'storage_capacity_gb', tags: 'tags', custom_field: 'custom_field',
  'end_user.assigned': 'end_user_assigned', 'end_user.email': 'end_user_email', 'end_user.external_id': 'end_user_external_id',
  'end_user.status': 'end_user_status', 'android.api_level': 'android_api_level',
  'android.security_patch_level': 'android_security_patch_level', group: 'group', 'app.installed': 'app_installed',
  compliance_state: 'compliance_state', config_state: 'config_state', last_checkin: 'last_checkin', enrolled_at: 'enrolled_at',
} as const satisfies Record<RuleFieldKey, string>;

const FIELD_FALLBACK: Readonly<Record<RuleFieldKey, string>> = {
  platform: 'Platform', os_version: 'OS version', model: 'Model identifier', model_name: 'Model name', name: 'Device name',
  serial_number: 'Serial number', ownership: 'Ownership', management_mode: 'Management mode',
  management_channel: 'Management channel', enrollment_type: 'Enrollment method', supervised: 'Supervised', usage: 'Usage',
  enrollment_state: 'Enrollment state', lifecycle_status: 'Lifecycle status', warranty_status: 'Warranty status',
  storage_capacity_gb: 'Storage capacity (GB)', tags: 'Tags', custom_field: 'Custom field',
  'end_user.assigned': 'End user assigned', 'end_user.email': 'End user email', 'end_user.external_id': 'End user external ID',
  'end_user.status': 'End user status', 'android.api_level': 'Android API level',
  'android.security_patch_level': 'Android security patch', group: 'Static group', 'app.installed': 'Installed application',
  compliance_state: 'Compliance', config_state: 'Configuration', last_checkin: 'Last contact', enrolled_at: 'Enrolled',
};

export const ruleFieldLabel = (t: TFunction, f: RuleFieldKey): string => t(`rules.fields.${FIELD_I18N[f]}`) || FIELD_FALLBACK[f];

const CATEGORY_FALLBACK: Readonly<Record<RuleCategory, string>> = {
  device: 'Device', management: 'Management', asset: 'Asset', labels: 'Tags and custom fields', user: 'End user',
  android: 'Android', inventory: 'Group and applications', state: 'State and activity',
};
export const ruleCategoryLabel = (t: TFunction, c: RuleCategory): string => t(`rules.categories.${c}`) || CATEGORY_FALLBACK[c];

const OP_FALLBACK: Readonly<Record<RuleOp, string>> = {
  eq: 'is', neq: 'is not', in: 'is one of', not_in: 'is none of', lt: 'is below', lte: 'is at most', gt: 'is above',
  gte: 'is at least', between: 'is between', contains: 'contains', starts_with: 'starts with', ends_with: 'ends with',
  exists: 'is set', not_exists: 'is not set', has_any: 'has any of', has_all: 'has all of', has_none: 'has none of',
  older_than_days: 'more than … days ago', within_days: 'in the last … days',
};
export const ruleOpLabel = (t: TFunction, op: RuleOp): string => t(`rules.ops.${op}`) || OP_FALLBACK[op];

/** The operators of an installed application read on the application, not on a value. */
const APP_OP_FALLBACK: Partial<Record<RuleOp, string>> = {
  exists: 'is installed', not_exists: 'is not installed', eq: 'is installed in version', lt: 'is installed below version',
  lte: 'is installed at most in version', gt: 'is installed above version', gte: 'is installed at least in version',
};
type AppOp = 'exists' | 'not_exists' | 'eq' | 'lt' | 'lte' | 'gt' | 'gte';
const isAppOp = (op: RuleOp): op is AppOp => op in APP_OP_FALLBACK;

/** The label of an operator for a field (the application field has its own wording). */
export const ruleOpLabelFor = (t: TFunction, field: RuleFieldKey, op: RuleOp): string =>
  (RULE_FIELDS[field].type === 'app' && isAppOp(op) ? (t(`rules.appOps.${op}`) || APP_OP_FALLBACK[op]!) : ruleOpLabel(t, op));

const CHANNEL_FALLBACK: Record<ManagementChannel, string> = { apple_mdm: 'Apple MDM', amapi: 'Android Enterprise', legacy_agent: 'Android bridge agent' };
const USAGE_FALLBACK: Record<DeviceUsage, string> = { standard: 'Standard', kiosk: 'Kiosk', shared: 'Shared' };
type Lifecycle = typeof DEVICE_LIFECYCLE_STATUSES[number];
type Warranty = typeof DEVICE_WARRANTY_STATUSES[number];
const LIFECYCLE_FALLBACK: Record<Lifecycle, string> = { active: 'Active', aging: 'Aging', end_of_life: 'End of life', retired: 'Retired', unknown: 'Unknown' };
const WARRANTY_FALLBACK: Record<Warranty, string> = { active: 'Under warranty', expired: 'Expired', unknown: 'Unknown' };
const END_USER_STATUS_FALLBACK: Record<EndUserStatus, string> = { active: 'Active', departed: 'Departed' };

/** The label of a value of an enum field. */
export function ruleValueLabel(t: TFunction, field: RuleFieldKey, value: string): string {
  switch (field) {
    case 'platform': return platformLabel(value);
    case 'ownership': return ownershipLabel(t, value);
    case 'management_mode': return managementModeLabel(t, value);
    case 'enrollment_type': return enrollmentMethodLabel(t, value);
    case 'enrollment_state': return enrollmentLabel(t, value as EnrollmentState);
    case 'compliance_state': return complianceLabel(t, value as ComplianceState);
    case 'config_state': return configLabel(t, value as ConfigState);
    case 'management_channel': {
      const v = value as ManagementChannel;
      return t(`rules.values.channel.${v}`) || CHANNEL_FALLBACK[v] || value;
    }
    case 'usage': {
      const v = value as DeviceUsage;
      return t(`rules.values.usage.${v}`) || USAGE_FALLBACK[v] || value;
    }
    case 'lifecycle_status': {
      const v = value as Lifecycle;
      return t(`rules.values.lifecycle.${v}`) || LIFECYCLE_FALLBACK[v] || value;
    }
    case 'warranty_status': {
      const v = value as Warranty;
      return t(`rules.values.warranty.${v}`) || WARRANTY_FALLBACK[v] || value;
    }
    case 'end_user.status': {
      const v = value as EndUserStatus;
      return t(`rules.values.endUserStatus.${v}`) || END_USER_STATUS_FALLBACK[v] || value;
    }
    default: return value;
  }
}

const ISSUE_FALLBACK: Readonly<Record<RuleIssueCode, string>> = {
  invalidNode: 'This part of the rule cannot be read.',
  emptyGroup: 'An empty group: add a condition or remove it.',
  tooDeep: 'Too many nested levels (4 at most, a negation counts as one).',
  tooManyConditions: 'Too many conditions (50 at most).',
  tooLarge: 'The rule is too large.',
  unknownField: 'Unknown field.',
  opNotAllowed: 'This operator is not offered for this field.',
  keyRequired: 'Enter the name.',
  keyNotAllowed: 'This field takes no name.',
  invalidKey: 'Invalid name.',
  invalidValue: 'Enter a valid value.',
  tooManyValues: 'Too many values (100 at most).',
  stringTooLong: 'Text too long (200 characters at most).',
};
/** The key of a keyed field is an application's identifier, or a custom field's name: its own messages. */
const KEY_ISSUE_FALLBACK = {
  app: { keyRequired: 'Enter the identifier of the application.', invalidKey: 'Invalid application identifier.' },
  custom: { keyRequired: 'Enter the name of the custom field.', invalidKey: 'Invalid custom field name.' },
} as const;
/** The message of an issue; `field` (the issue's) gives the key's issues of a keyed field their own. */
export function ruleIssueLabel(t: TFunction, code: RuleIssueCode, field?: string): string {
  const def = field && (RULE_FIELD_KEYS as readonly string[]).includes(field) ? RULE_FIELDS[field as RuleFieldKey] : undefined;
  if (def?.keyed && (code === 'keyRequired' || code === 'invalidKey')) {
    const kind = def.type === 'app' ? 'app' : 'custom';
    const suffix = kind === 'app' ? 'App' : 'Custom';
    return t(`rules.issues.${code}${suffix}`) || KEY_ISSUE_FALLBACK[kind][code];
  }
  return t(`rules.issues.${code}`) || ISSUE_FALLBACK[code];
}

/** Why a field is not permitted in a targeted dynamic group or an assignment filter (D2). */
export type RuleRestriction = 'derived' | 'temporal' | 'group' | 'apps';
export function ruleRestrictionOf(def: RuleFieldDef, use: RuleUse): RuleRestriction | null {
  if (use === 'view' || def[use]) return null;
  if (def.derived) return 'derived';
  if (def.temporal) return 'temporal';
  if (def.type === 'group') return 'group';
  return 'apps';
}
const RESTRICTION_FALLBACK: Readonly<Record<RuleRestriction, string>> = {
  derived: 'Derived from the compliance or the configuration: not permitted here, it would make the targeting depend on itself.',
  temporal: 'Relative to the current time: not permitted here, membership would change without any change of the device.',
  group: 'Not permitted here: target the static group and add a filter instead.',
  apps: 'The installed applications are not permitted here.',
};
export const ruleRestrictionLabel = (t: TFunction, r: RuleRestriction): string => t(`rules.restricted.${r}`) || RESTRICTION_FALLBACK[r];

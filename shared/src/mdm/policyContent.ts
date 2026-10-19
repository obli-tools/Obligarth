// =============================================================================
// Content of a policy version, format 1 (docs: modele-donnees-mdm §7.2):
// native items typed by the Apple schema, secrets as references to the
// tenant's vault ({"$secret": "<uuid>"}), variables resolved per device at
// rendering ({{device.serial_number}}…, closed list). Shared by the server's
// validation and the editor of the console.
// =============================================================================

export type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

import type { AndroidPolicySection } from '../android/policy';

/** policy_versions.content, format 1. */
export interface PolicyContentV1 {
  format: 1;
  sections: {
    apple?: { items: AppleItem[] };
    /** The Android section (android-amapi §9.2): a fragment of the AMAPI Policy resource and the policy's apps. */
    android?: AndroidPolicySection;
  };
}

export interface AppleItem {
  /** Stable id of the item inside the policy (UUID v4): editor, diff, impact. */
  id: string;
  /** Schema type: 'com.apple.configuration.passcode.settings', 'com.apple.wifi.managed',
   *  'raw.profile' (imported .mobileconfig, CFG-06) or 'setting.<Item>' (Settings command, CFG-08). */
  type: string;
  /** Instance of a collection type, when the schema overlay names no instance key (section 7.3). */
  instance?: string;
  /** Tombstone: removes the inherited instance (collection and atomic types only). */
  remove?: true;
  /** Values of the schema keys. Secrets as {"$secret": "<uuid>"}; variables as "{{device.serial_number}}". */
  values?: Record<string, JsonValue>;
  /** Free comment shown in the editor (never compiled). */
  note?: string;
}

export const POLICY_CONTENT_FORMAT = 1;
/** At most 200 items per section. */
export const POLICY_MAX_ITEMS = 200;
/** Serialised content of a version: 512 KiB at most. */
export const POLICY_MAX_CONTENT_BYTES = 512 * 1024;
/** A secret typed in ({"$secretValue": "…"}): 64 KiB at most (a PKCS #12 identity in base64). */
export const POLICY_MAX_SECRET_VALUE_LENGTH = 64 * 1024;
/** The instance of a collection type named by the editor (item.instance). */
export const POLICY_INSTANCE_RE = /^[A-Za-z0-9._ -]{1,64}$/;
/** An instance named by a key of the item (SSID, OS version, certificate file name): 128 characters at most. */
export const POLICY_INSTANCE_VALUE_MAX = 128;

export const emptyPolicyContent = (): PolicyContentV1 => ({ format: 1, sections: {} });

// ── Variables (DM22, CFG-07): closed list, resolved at rendering ─────────────

export const POLICY_VARIABLES = [
  'device.uuid', 'device.name', 'device.serial_number', 'device.udid', 'device.model',
  'user.email', 'user.display_name', 'user.managed_apple_account', 'user.external_id',
  'tenant.name', 'tenant.slug',
] as const;
export type PolicyVariable = typeof POLICY_VARIABLES[number];

const VARIABLE_SET: ReadonlySet<string> = new Set(POLICY_VARIABLES);
const TOKEN_RE = /\{\{([^{}]*)\}\}/g;

export function isPolicyVariable(name: string): name is PolicyVariable {
  return VARIABLE_SET.has(name);
}

/** The variables a string names, known or not ('{{ device.name }}' and '{{device.name}}' alike). */
export function variablesInString(s: string): { known: PolicyVariable[]; unknown: string[] } {
  const known: PolicyVariable[] = [];
  const unknown: string[] = [];
  for (const m of s.matchAll(TOKEN_RE)) {
    const name = m[1].trim();
    if (isPolicyVariable(name)) { if (!known.includes(name)) known.push(name); } else if (!unknown.includes(name)) unknown.push(name);
  }
  return { known, unknown };
}

/** The known variables of a value, at any depth (strings only: a key is never templated). */
export function variablesOf(value: unknown, out: PolicyVariable[] = [], depth = 0): PolicyVariable[] {
  if (depth > 32) return out;
  if (typeof value === 'string') {
    for (const v of variablesInString(value).known) if (!out.includes(v)) out.push(v);
  } else if (Array.isArray(value)) {
    for (const x of value) variablesOf(x, out, depth + 1);
  } else if (value && typeof value === 'object') {
    for (const x of Object.values(value as Record<string, unknown>)) variablesOf(x, out, depth + 1);
  }
  return out;
}

// ── Secrets (DM17): references in, values never stored ───────────────────────

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** {"$secret": "<uuid>"}: a reference to a row of the tenant's tenant_secrets. */
export function isSecretRef(v: unknown): v is { $secret: string } {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const keys = Object.keys(v);
  return keys.length === 1 && keys[0] === '$secret' && typeof (v as { $secret: unknown }).$secret === 'string'
    && UUID_RE.test((v as { $secret: string }).$secret);
}

/** {"$secretValue": "…"}: a secret typed in the editor, replaced by the server before any storage. */
export function isSecretValue(v: unknown): v is { $secretValue: string } {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const keys = Object.keys(v);
  return keys.length === 1 && keys[0] === '$secretValue' && typeof (v as { $secretValue: unknown }).$secretValue === 'string';
}

/** Does an object look like a secret marker at all (any $secret… key)? */
export function looksLikeSecretMarker(v: unknown): boolean {
  return !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).some((k) => k === '$secret' || k === '$secretValue');
}

// ── Typed values (plist types JSON lacks; raw profiles and data/date keys) ────

/** {"$data": "<base64>"}, {"$date": "<RFC 3339>"}, {"$real": n}, {"$int": "<decimal>"}. */
export type TypedValue = { $data: string } | { $date: string } | { $real: number } | { $int: string };

export function typedValueKind(v: unknown): 'data' | 'date' | 'real' | 'int' | null {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const keys = Object.keys(v);
  if (keys.length !== 1) return null;
  const x = (v as Record<string, unknown>)[keys[0]];
  switch (keys[0]) {
    case '$data': return typeof x === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(x) && x.length % 4 === 0 ? 'data' : null;
    case '$date': return typeof x === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(x)
      && Number.isFinite(Date.parse(x)) ? 'date' : null;
    case '$real': return typeof x === 'number' && Number.isFinite(x) ? 'real' : null;
    case '$int': return typeof x === 'string' && /^-?[0-9]{1,30}$/.test(x) ? 'int' : null;
    default: return null;
  }
}

// ── Validation (section 7.2; codes of section 10.8) ─────────────────────────

export const POLICY_VALIDATION_CODES = [
  'invalid_content', 'too_many_items', 'content_too_large', 'invalid_item', 'duplicate_item_id',
  'unknown_type', 'type_disabled', 'unknown_key', 'type_mismatch', 'out_of_range', 'required', 'invalid_instance',
  'duplicate_setting_key', 'unknown_variable', 'secret_expected', 'secret_not_allowed', 'secret_not_found',
  'asset_not_supported', 'secret_requires_asset', 'identifier_too_long', 'remove_not_allowed',
  // The Android section (android-amapi §9.2, §22.4; lot AN-A2): the codes of server/src/mdm/android/validate.ts.
  'too_deep', 'field_reserved', 'field_deprecated', 'package_invalid', 'package_reserved', 'role_reserved', 'onc_guid_invalid',
  'secret_invalid', 'wipe_rule_invalid', 'wipe_threshold_too_low', 'frp_email_outside_domain', 'too_many_setup_actions',
  'too_many_required_for_setup', 'too_many_minimum_version_code', 'too_many_kiosk_apps', 'managed_configuration_exclusive',
  'preferred_activities_conflict', 'duplicate_value', 'kiosk_form_ambiguous', 'kiosk_role_install_type', 'role_duplicate',
  'kiosk_home_conflict', 'system_update_window_invalid', 'freeze_period_invalid', 'freeze_period_too_long',
  'freeze_period_gap_too_short', 'freeze_period_overlap', 'freeze_period_without_type', 'too_many_freeze_periods',
] as const;
export type PolicyValidationCode = typeof POLICY_VALIDATION_CODES[number];

export interface PolicyValidationIssue {
  /** The item (null for the content as a whole). */
  itemId: string | null;
  /** Path of the value inside the item ('values.EAPClientConfiguration.UserPassword', 'type'…). */
  path: string;
  code: PolicyValidationCode;
}

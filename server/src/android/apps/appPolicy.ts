// The options of an assignment of an Android app (android-amapi §4.6, §9.6; lot AN-E1) and the entry of
// applications[] they become in the compiled policy (setting key android:app[<package>]).
//   - closed list of options: installType (never CUSTOM in v1), autoUpdateMode, minimumVersionCode, installPriority
//     (FORCE_INSTALLED and PREINSTALLED, 0 to 10,000), installConstraint (one at most), managedConfiguration or
//     managedConfigurationTemplate (exclusive: Google ignores the template when both are set, an operator would
//     believe the iframe's configuration applies), permissionGrants, defaultPermissionPolicy, accessibleTrackIds
//     (among the app's tracks); roles and delegatedScopes are refused (reserved, AN11; v2), anything else unknown;
//   - a managed configuration by JSON is validated against the app's managed properties (each key known, each value
//     of the property's type, CHOICE and MULTISELECT among the entries, nested bundles); a HIDDEN property holds a
//     secret (a value in clear is refused: secret_expected); a STRING may hold a secret the administrator declares
//     ({"$secretValue"}, moved to the vault before any storage); an OEMConfig app is configured by the iframe only;
//   - the iframe's template: templateId digits only (Google, note of July 2026), its variables bounded.
// Pure: the vault and the database are the caller's (apps/assignments.ts). Unit tests: appPolicy.test.ts.
import {
  POLICY_MAX_SECRET_VALUE_LENGTH, isSecretRef, isSecretValue, looksLikeSecretMarker, variablesInString, variablesOf,
  type JsonValue, type PolicyVariable,
} from '@obligarth/shared';
import { ANDROID_INSTALL_TYPES, type AndroidAppOptions } from '@obligarth/shared/dist/android/apps.js';
import { AMAPI_ARTIFACT_KEY, androidAppKey, isAndroidPackage } from '@obligarth/shared/dist/android/policy.js';
import { valueHashOf } from '../../mdm/policies/contributions';
import { APP_CONFIG_SECRET_PURPOSE, RESERVED_PACKAGES } from '../../mdm/android/overlay';
import type { AndroidAppMetadata, AndroidManagedProperty } from './metadata';

export type AndroidAppOptionCode =
  | 'invalid_options' | 'unknown_option' | 'option_reserved' | 'type_mismatch' | 'out_of_range' | 'install_type_invalid'
  | 'install_priority_not_applicable' | 'too_many_install_constraints' | 'duplicate_value' | 'managed_configuration_exclusive'
  | 'template_id_invalid' | 'template_variables_invalid' | 'metadata_missing' | 'oemconfig_iframe_only'
  | 'managed_configuration_unknown_key' | 'managed_configuration_type' | 'managed_configuration_value' | 'too_deep'
  | 'secret_expected' | 'secret_invalid' | 'secret_not_allowed' | 'unknown_variable' | 'permission_invalid'
  | 'track_unknown' | 'package_invalid' | 'package_reserved' | 'web_app_no_managed_configuration';

export interface AndroidAppOptionIssue { path: string; code: AndroidAppOptionCode }

export interface AndroidAppSecretSite {
  /** Path of the marker from the options ('managedConfiguration.token'). */
  path: Array<string | number>;
  purpose: string;
  kind: 'ref' | 'value';
}

export interface AndroidAppOptionsCheck {
  issues: AndroidAppOptionIssue[];
  /** Not refused, shown to the operator: a permission the app does not declare. */
  warnings: Array<{ path: string; code: 'permission_not_declared' }>;
  secrets: AndroidAppSecretSite[];
}

export interface AndroidAppFacts {
  packageName: string;
  kind: string;
  metadata: AndroidAppMetadata | null;
}

/** Options an assignment may set, and those it never sets (reserved; refused rather than called unknown). */
export const APP_OPTION_KEYS: ReadonlySet<string> = new Set([
  'installType', 'autoUpdateMode', 'minimumVersionCode', 'installPriority', 'installConstraint', 'managedConfiguration',
  'managedConfigurationTemplate', 'permissionGrants', 'defaultPermissionPolicy', 'accessibleTrackIds',
]);
export const RESERVED_APP_OPTIONS: ReadonlySet<string> = new Set([
  'roles', 'delegatedScopes', 'customAppConfig', 'signingKeyCerts', 'extensionConfig', 'lockTaskAllowed', 'packageName',
]);

const AUTO_UPDATE = new Set(['AUTO_UPDATE_DEFAULT', 'AUTO_UPDATE_POSTPONED', 'AUTO_UPDATE_HIGH_PRIORITY']);
const PERMISSION_POLICY = new Set(['PROMPT', 'GRANT', 'DENY']);
const CONSTRAINTS: Readonly<Record<string, ReadonlySet<string>>> = {
  networkTypeConstraint: new Set(['INSTALL_ON_ANY_NETWORK', 'INSTALL_ONLY_ON_UNMETERED_NETWORK']),
  chargingConstraint: new Set(['CHARGING_NOT_REQUIRED', 'INSTALL_ONLY_WHEN_CHARGING']),
  deviceIdleConstraint: new Set(['DEVICE_IDLE_NOT_REQUIRED', 'INSTALL_ONLY_WHEN_DEVICE_IDLE']),
};
const PRIORITY_INSTALL_TYPES = new Set(['FORCE_INSTALLED', 'PREINSTALLED']);
const PERMISSION_RE = /^[A-Za-z][A-Za-z0-9_.]{0,254}$/;
const TEMPLATE_ID_RE = /^[0-9]{1,20}$/;
const TEMPLATE_VARIABLE_RE = /^\$[A-Za-z0-9_.]{1,62}\$$/;
const INT32_MAX = 2 ** 31 - 1;
export const APP_LIMITS = {
  installPriority: 10_000, permissionGrants: 200, tracks: 50, templateVariables: 50, templateValue: 1024, stringValue: 65_535,
  arrayItems: 1000, depth: 10,
} as const;

const isObject = (v: unknown): v is Record<string, JsonValue> => !!v && typeof v === 'object' && !Array.isArray(v);
const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** The checks of the options of an assignment of `app` (an Android app of the catalog). */
export function checkAndroidAppOptions(app: AndroidAppFacts, raw: unknown): AndroidAppOptionsCheck {
  const issues: AndroidAppOptionIssue[] = [];
  const warnings: AndroidAppOptionsCheck['warnings'] = [];
  const secrets: AndroidAppSecretSite[] = [];
  const out = (): AndroidAppOptionsCheck => ({ issues, warnings, secrets });
  if (!isAndroidPackage(app.packageName)) { issues.push({ path: '', code: 'package_invalid' }); return out(); }
  if (RESERVED_PACKAGES.has(app.packageName)) { issues.push({ path: '', code: 'package_reserved' }); return out(); }
  if (!isObject(raw)) { issues.push({ path: '', code: 'invalid_options' }); return out(); }
  for (const k of Object.keys(raw)) {
    if (RESERVED_APP_OPTIONS.has(k)) issues.push({ path: k, code: 'option_reserved' });
    else if (!APP_OPTION_KEYS.has(k)) issues.push({ path: k, code: 'unknown_option' });
  }
  const o = raw;
  const installType = o.installType;
  if (installType !== undefined && !(typeof installType === 'string' && (ANDROID_INSTALL_TYPES as readonly string[]).includes(installType))) {
    issues.push({ path: 'installType', code: 'install_type_invalid' });
  }
  if (o.autoUpdateMode !== undefined && !(typeof o.autoUpdateMode === 'string' && AUTO_UPDATE.has(o.autoUpdateMode))) {
    issues.push({ path: 'autoUpdateMode', code: 'type_mismatch' });
  }
  if (o.minimumVersionCode !== undefined && !(Number.isInteger(o.minimumVersionCode) && Number(o.minimumVersionCode) >= 1
    && Number(o.minimumVersionCode) <= INT32_MAX)) {
    issues.push({ path: 'minimumVersionCode', code: 'out_of_range' });
  }
  if (o.installPriority !== undefined) {
    if (!(Number.isInteger(o.installPriority) && Number(o.installPriority) >= 0 && Number(o.installPriority) <= APP_LIMITS.installPriority)) {
      issues.push({ path: 'installPriority', code: 'out_of_range' });
    } else if (!(typeof installType === 'string' && PRIORITY_INSTALL_TYPES.has(installType))) {
      issues.push({ path: 'installPriority', code: 'install_priority_not_applicable' });
    }
  }
  if (o.installConstraint !== undefined) {
    if (!Array.isArray(o.installConstraint)) issues.push({ path: 'installConstraint', code: 'type_mismatch' });
    else {
      // Google: « You can specify a maximum of one InstallConstraint. Multiple constraints are rejected. »
      if (o.installConstraint.length > 1) issues.push({ path: 'installConstraint', code: 'too_many_install_constraints' });
      o.installConstraint.forEach((c, i) => {
        if (!isObject(c) || Object.keys(c).length === 0) { issues.push({ path: `installConstraint[${i}]`, code: 'type_mismatch' }); return; }
        for (const [k, v] of Object.entries(c)) {
          if (!own(CONSTRAINTS, k) || typeof v !== 'string' || !CONSTRAINTS[k].has(v)) issues.push({ path: `installConstraint[${i}].${k}`, code: 'type_mismatch' });
        }
      });
    }
  }
  if (o.defaultPermissionPolicy !== undefined && !(typeof o.defaultPermissionPolicy === 'string' && PERMISSION_POLICY.has(o.defaultPermissionPolicy))) {
    issues.push({ path: 'defaultPermissionPolicy', code: 'type_mismatch' });
  }
  if (o.permissionGrants !== undefined) {
    if (!Array.isArray(o.permissionGrants) || o.permissionGrants.length > APP_LIMITS.permissionGrants) {
      issues.push({ path: 'permissionGrants', code: Array.isArray(o.permissionGrants) ? 'out_of_range' : 'type_mismatch' });
    } else {
      const seen = new Set<string>();
      const declared = new Set(app.metadata?.permissions ?? []);
      o.permissionGrants.forEach((g, i) => {
        const p = `permissionGrants[${i}]`;
        if (!isObject(g) || Object.keys(g).some((k) => k !== 'permission' && k !== 'policy')
          || typeof g.permission !== 'string' || !PERMISSION_RE.test(g.permission)) { issues.push({ path: p, code: 'permission_invalid' }); return; }
        if (typeof g.policy !== 'string' || !PERMISSION_POLICY.has(g.policy)) issues.push({ path: `${p}.policy`, code: 'type_mismatch' });
        if (seen.has(g.permission)) issues.push({ path: p, code: 'duplicate_value' });
        seen.add(g.permission);
        if (declared.size > 0 && !declared.has(g.permission)) warnings.push({ path: p, code: 'permission_not_declared' });
      });
    }
  }
  if (o.accessibleTrackIds !== undefined) {
    if (!Array.isArray(o.accessibleTrackIds) || o.accessibleTrackIds.length > APP_LIMITS.tracks) {
      issues.push({ path: 'accessibleTrackIds', code: Array.isArray(o.accessibleTrackIds) ? 'out_of_range' : 'type_mismatch' });
    } else if (!app.metadata) {
      issues.push({ path: 'accessibleTrackIds', code: 'metadata_missing' });
    } else {
      const known = new Set(app.metadata.tracks.map((t) => t.trackId));
      const seen = new Set<string>();
      o.accessibleTrackIds.forEach((t, i) => {
        if (typeof t !== 'string' || !known.has(t)) issues.push({ path: `accessibleTrackIds[${i}]`, code: 'track_unknown' });
        else if (seen.has(t)) issues.push({ path: `accessibleTrackIds[${i}]`, code: 'duplicate_value' });
        if (typeof t === 'string') seen.add(t);
      });
    }
  }
  // ── Managed configuration ─────────────────────────────────────────────────
  const hasJson = o.managedConfiguration !== undefined;
  const hasTemplate = o.managedConfigurationTemplate !== undefined;
  if (hasJson && hasTemplate) issues.push({ path: 'managedConfigurationTemplate', code: 'managed_configuration_exclusive' });
  // A web app (a shortcut Google packages) has no managed configuration.
  if ((hasJson || hasTemplate) && app.kind === 'web') { issues.push({ path: hasJson ? 'managedConfiguration' : 'managedConfigurationTemplate', code: 'web_app_no_managed_configuration' }); return out(); }
  if (hasTemplate) {
    const t = o.managedConfigurationTemplate;
    if (!isObject(t) || Object.keys(t).some((k) => k !== 'templateId' && k !== 'configurationVariables')) {
      issues.push({ path: 'managedConfigurationTemplate', code: 'type_mismatch' });
    } else {
      if (typeof t.templateId !== 'string' || !TEMPLATE_ID_RE.test(t.templateId)) issues.push({ path: 'managedConfigurationTemplate.templateId', code: 'template_id_invalid' });
      if (t.configurationVariables !== undefined) {
        const vars = t.configurationVariables;
        if (!isObject(vars) || Object.keys(vars).length > APP_LIMITS.templateVariables) {
          issues.push({ path: 'managedConfigurationTemplate.configurationVariables', code: 'template_variables_invalid' });
        } else {
          for (const [k, v] of Object.entries(vars)) {
            const p = `managedConfigurationTemplate.configurationVariables.${k}`;
            if (!TEMPLATE_VARIABLE_RE.test(k) || typeof v !== 'string' || v.length > APP_LIMITS.templateValue) { issues.push({ path: p, code: 'template_variables_invalid' }); continue; }
            if (v.includes('{{') && variablesInString(v).unknown.length > 0) issues.push({ path: p, code: 'unknown_variable' });
          }
        }
      }
    }
  }
  if (hasJson) {
    if (app.metadata?.oemConfig) issues.push({ path: 'managedConfiguration', code: 'oemconfig_iframe_only' });
    else if (!app.metadata || app.metadata.managedProperties === null) issues.push({ path: 'managedConfiguration', code: 'metadata_missing' });
    else if (looksLikeSecretMarker(o.managedConfiguration)) issues.push({ path: 'managedConfiguration', code: 'secret_not_allowed' });
    else if (!isObject(o.managedConfiguration)) issues.push({ path: 'managedConfiguration', code: 'type_mismatch' });
    else checkBundle(o.managedConfiguration, app.metadata.managedProperties, ['managedConfiguration'], 1, issues, secrets);
  }
  return out();
}

const pathText = (path: Array<string | number>): string =>
  path.reduce<string>((acc, p) => (typeof p === 'number' ? `${acc}[${p}]` : acc ? `${acc}.${p}` : p), '');

function secretSite(v: Record<string, JsonValue>, path: Array<string | number>, issues: AndroidAppOptionIssue[], secrets: AndroidAppSecretSite[]): void {
  if (isSecretRef(v)) secrets.push({ path, purpose: APP_CONFIG_SECRET_PURPOSE, kind: 'ref' });
  else if (isSecretValue(v)) {
    if (v.$secretValue.length === 0 || v.$secretValue.length > Math.min(POLICY_MAX_SECRET_VALUE_LENGTH, APP_LIMITS.stringValue)) {
      issues.push({ path: pathText(path), code: 'secret_invalid' });
    } else secrets.push({ path, purpose: APP_CONFIG_SECRET_PURPOSE, kind: 'value' });
  } else issues.push({ path: pathText(path), code: 'secret_invalid' });
}

function checkBundle(value: Record<string, JsonValue>, props: AndroidManagedProperty[], path: Array<string | number>, depth: number,
  issues: AndroidAppOptionIssue[], secrets: AndroidAppSecretSite[]): void {
  if (depth > APP_LIMITS.depth) { issues.push({ path: pathText(path), code: 'too_deep' }); return; }
  const byKey = new Map(props.map((p) => [p.key, p]));
  for (const [k, v] of Object.entries(value)) {
    const p = byKey.get(k);
    const here = [...path, k];
    if (!p) { issues.push({ path: pathText(here), code: 'managed_configuration_unknown_key' }); continue; }
    checkValue(v, p, here, depth, issues, secrets);
  }
}

function checkValue(v: JsonValue, p: AndroidManagedProperty, path: Array<string | number>, depth: number,
  issues: AndroidAppOptionIssue[], secrets: AndroidAppSecretSite[]): void {
  const at = pathText(path);
  const marker = isObject(v) && looksLikeSecretMarker(v);
  // A hidden property carries a credential the user never sees: a secret marker only, never a value in clear.
  if (p.type === 'HIDDEN') {
    if (!marker) { issues.push({ path: at, code: 'secret_expected' }); return; }
    secretSite(v as Record<string, JsonValue>, path, issues, secrets);
    return;
  }
  if (marker) {
    // A secret the administrator declares, at a text property only.
    if (p.type !== 'STRING') { issues.push({ path: at, code: 'secret_not_allowed' }); return; }
    secretSite(v as Record<string, JsonValue>, path, issues, secrets);
    return;
  }
  switch (p.type) {
    case 'BOOL':
      if (typeof v !== 'boolean') issues.push({ path: at, code: 'managed_configuration_type' });
      return;
    case 'INTEGER':
      if (!Number.isInteger(v) || Math.abs(Number(v)) > INT32_MAX) issues.push({ path: at, code: 'managed_configuration_type' });
      return;
    case 'STRING':
      if (typeof v !== 'string') issues.push({ path: at, code: 'managed_configuration_type' });
      else if (v.length > APP_LIMITS.stringValue) issues.push({ path: at, code: 'managed_configuration_value' });
      else if (v.includes('{{') && variablesInString(v).unknown.length > 0) issues.push({ path: at, code: 'unknown_variable' });
      return;
    case 'CHOICE': {
      const values = new Set((p.entries ?? []).map((e) => e.value));
      if (typeof v !== 'string') issues.push({ path: at, code: 'managed_configuration_type' });
      else if (values.size > 0 && !values.has(v)) issues.push({ path: at, code: 'managed_configuration_value' });
      return;
    }
    case 'MULTISELECT': {
      const values = new Set((p.entries ?? []).map((e) => e.value));
      if (!Array.isArray(v) || v.length > APP_LIMITS.arrayItems || v.some((x) => typeof x !== 'string')) { issues.push({ path: at, code: 'managed_configuration_type' }); return; }
      const seen = new Set<string>();
      v.forEach((x, i) => {
        if (values.size > 0 && !values.has(x as string)) issues.push({ path: `${at}[${i}]`, code: 'managed_configuration_value' });
        if (seen.has(x as string)) issues.push({ path: `${at}[${i}]`, code: 'duplicate_value' });
        seen.add(x as string);
      });
      return;
    }
    case 'BUNDLE':
      if (!isObject(v)) { issues.push({ path: at, code: 'managed_configuration_type' }); return; }
      checkBundle(v, p.nested ?? [], path, depth + 1, issues, secrets);
      return;
    case 'BUNDLE_ARRAY': {
      if (!Array.isArray(v) || v.length > APP_LIMITS.arrayItems) { issues.push({ path: at, code: 'managed_configuration_type' }); return; }
      // Android restrictions: a bundle array holds bundles of one shape, declared as its single nested BUNDLE.
      const nested = p.nested ?? [];
      const shape = nested.length === 1 && nested[0].type === 'BUNDLE' ? nested[0].nested ?? [] : nested;
      v.forEach((x, i) => {
        if (!isObject(x)) { issues.push({ path: `${at}[${i}]`, code: 'managed_configuration_type' }); return; }
        checkBundle(x, shape, [...path, i], depth + 1, issues, secrets);
      });
      return;
    }
    default:
      issues.push({ path: at, code: 'managed_configuration_type' });
  }
}

/** The entry of applications[] of an assignment (its options are already checked). */
export function applicationPolicyOf(packageName: string, options: AndroidAppOptions | Record<string, JsonValue>): Record<string, JsonValue> {
  const entry: Record<string, JsonValue> = { packageName };
  for (const k of [...APP_OPTION_KEYS].sort()) {
    const v = (options as Record<string, JsonValue>)[k];
    if (v !== undefined) entry[k] = v;
  }
  return entry;
}

/** What an assignment of an Android app brings to the resolution (raccord AN-A2/AN-P: resolver.ts takes it instead
 *  of appContribution for the platform family android): the key android:app[<package>], its entry as the value. */
export interface AndroidAppContribution {
  settingKey: string;
  artifactKey: typeof AMAPI_ARTIFACT_KEY;
  value: Record<string, JsonValue>;
  valueHash: string;
  variables: PolicyVariable[];
}

export function androidAppContribution(packageName: string, options: Record<string, JsonValue>): AndroidAppContribution {
  const value = applicationPolicyOf(packageName, options);
  return { settingKey: androidAppKey(packageName), artifactKey: AMAPI_ARTIFACT_KEY, value, valueHash: valueHashOf(value), variables: variablesOf(value) };
}

/** A candidate of one key android:app[<package>] at the resolution (resolver.ts compareCandidates order). */
export interface AndroidAppCandidate {
  rank: number;
  priority: number;
  type: 'policy' | 'app';
  tenantId: number;
  id: number;
  installType?: string;
}

/** The winner among the candidates of one app key: the closest scope, then the priority, then BLOCKED at equal rank
 *  and priority [§9.6, proposition], then the resolver's order. Raccord: compareCandidates of resolver.ts. */
export function compareAndroidAppCandidates(x: AndroidAppCandidate, y: AndroidAppCandidate): number {
  if (x.rank !== y.rank) return x.rank - y.rank;
  if (x.priority !== y.priority) return x.priority - y.priority;
  const bx = x.installType === 'BLOCKED' ? 0 : 1;
  const by = y.installType === 'BLOCKED' ? 0 : 1;
  if (bx !== by) return bx - by;
  return (x.type < y.type ? -1 : x.type > y.type ? 1 : 0) || x.tenantId - y.tenantId || x.id - y.id;
}

export function pickAndroidAppWinner<T extends AndroidAppCandidate>(candidates: T[]): T | null {
  return candidates.length ? [...candidates].sort(compareAndroidAppCandidates)[0] : null;
}

/** What a change of the apps of a device removes from it (impact preview, appRemovals; DM23): under WHITELIST, AMAPI
 *  uninstalls an app that leaves applications[]; an app that becomes BLOCKED is uninstalled too. */
export function androidAppRemovals(before: unknown, after: unknown, playStoreMode: unknown = 'WHITELIST'): { removed: string[]; blocked: string[] } {
  const index = (list: unknown): Map<string, Record<string, JsonValue>> => {
    const m = new Map<string, Record<string, JsonValue>>();
    if (Array.isArray(list)) for (const a of list) if (isObject(a) && typeof a.packageName === 'string') m.set(a.packageName, a);
    return m;
  };
  const b = index(before);
  const a = index(after);
  const removed = playStoreMode === 'BLACKLIST' ? [] : [...b.keys()].filter((p) => !a.has(p) && b.get(p)!.installType !== 'BLOCKED');
  // Under BLACKLIST an app absent from the list may be installed by the user: blocking it uninstalls it as well.
  const blocked = [...a.entries()].filter(([p, e]) => e.installType === 'BLOCKED' && b.get(p)?.installType !== 'BLOCKED'
    && (b.has(p) || playStoreMode === 'BLACKLIST')).map(([p]) => p);
  return { removed: removed.sort(), blocked: blocked.sort() };
}

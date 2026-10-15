import {
  POLICY_MAX_ITEMS, POLICY_MAX_SECRET_VALUE_LENGTH, isSecretRef, isSecretValue, looksLikeSecretMarker, variablesInString, type JsonValue,
} from '@obligarth/shared';
import { ANDROID_ONC_GUID_RE, isAndroidPackage } from '@obligarth/shared/dist/android/policy.js';
import { androidCatalog, type AndroidCatalogView, type SchemaIssue } from './catalog';
import {
  APP_CONFIG_SECRET_PURPOSE, DEPRECATED_APP_FIELDS, DEPRECATED_FIELDS, FAILED_PASSWORDS_FOR_WIPE, MIN_WIPE_AFTER_DAYS,
  ONC_SECRET_KEYS, POLICY_LIMITS, RESERVED_FIELDS, RESERVED_PACKAGES, RESERVED_ROLES,
} from './overlay';

// =============================================================================
// Validation of the Android section of a policy version, applied at each
// write of a draft (the common validation calls it for sections.android):
//   - the section is { fragment, applications? }; a fragment's own
//     applications[] are taken as the policy's apps;
//   - every top-level field exists in the catalog, with its types, formats
//     and enumerations; reserved fields are refused; deprecated fields are
//     refused with their replacement (a deprecated enumeration value is only
//     a warning: Google still accepts it);
//   - apps: valid and unique package names, never the companion app's nor its
//     role, a managed configuration by template or by JSON (not both), the
//     limits of AMAPI (5 REQUIRED_FOR_SETUP, 20 minimumVersionCode, 1 KIOSK);
//   - ONC networks: unique GUIDs (one setting key per network);
//   - the settings that can wipe a device: complete enforcement rules that
//     wipe after 14 days at least, a failed-passwords threshold between the
//     tenant's floor and 100, FRP administrators of the enterprise's domain
//     only, one setup action at most; the keys set are returned (impact
//     preview: wipeRules, publication at the restricted level);
//   - secrets only where the overlay allows them (ONC passphrases, managed
//     configurations), returned with their purpose: the caller moves the
//     values typed in to the vault before any storage;
//   - variables of the closed list only.
// Pure: the vault and the database are the caller's. The unit tests load it.
// =============================================================================

export type AndroidValidationCode =
  | 'invalid_content' | 'too_many_items' | 'unknown_key' | 'type_mismatch' | 'out_of_range' | 'too_deep'
  | 'field_reserved' | 'field_deprecated' | 'package_invalid' | 'package_reserved' | 'role_reserved'
  | 'duplicate_setting_key' | 'onc_guid_invalid' | 'unknown_variable' | 'secret_not_allowed' | 'secret_invalid' | 'secret_expected'
  | 'wipe_rule_invalid' | 'wipe_threshold_too_low' | 'frp_email_outside_domain' | 'too_many_setup_actions'
  | 'too_many_required_for_setup' | 'too_many_minimum_version_code' | 'too_many_kiosk_apps'
  | 'managed_configuration_exclusive' | 'preferred_activities_conflict';

export interface AndroidValidationIssue {
  /** Path of the value in the section ('fragment.cameraDisabled', 'applications[com.example.app].roles[0]'). */
  path: string;
  code: AndroidValidationCode;
  /** field_deprecated: the field to use instead (null: none, the field has no effect). */
  replacement?: string | null;
}

export interface AndroidSecretMarker {
  path: string;
  purpose: string;
  /** 'ref': {"$secret": uuid} (to check against the tenant's vault); 'value': {"$secretValue": …} (to move there). */
  kind: 'ref' | 'value';
}

export interface AndroidValidationResult {
  issues: AndroidValidationIssue[];
  warnings: Array<{ path: string; code: 'value_deprecated' }>;
  /** Setting keys of the wipe-capable settings the section sets. */
  wipeRules: string[];
  secrets: AndroidSecretMarker[];
}

export interface AndroidValidationOptions {
  /** The tenant's floor of maximumFailedPasswordsForWipe (androidMinFailedPasswordsForWipe); never below 6. */
  minFailedPasswordsForWipe?: number;
  /** The domain of the tenant's enterprise (admin_domain); null: none bound yet (FRP administrators refused). */
  adminDomain?: string | null;
  catalog?: AndroidCatalogView;
}

const isObject = (v: unknown): v is Record<string, JsonValue> => !!v && typeof v === 'object' && !Array.isArray(v);
const MAX_DEPTH = 32;
const EMAIL_RE = /^[^\s@]{1,64}@([A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+)$/;

/** Intent domains a persistent preferred activity and a default application setting can both claim. */
function preferredDomains(activity: unknown): Set<string> {
  const out = new Set<string>();
  if (!isObject(activity)) return out;
  const actions = Array.isArray(activity.actions) ? activity.actions : [];
  const categories = Array.isArray(activity.categories) ? activity.categories : [];
  if (categories.includes('android.intent.category.HOME')) out.add('DEFAULT_HOME');
  if (categories.includes('android.intent.category.BROWSABLE') || categories.includes('android.intent.category.APP_BROWSER')) out.add('DEFAULT_BROWSER');
  if (actions.includes('android.intent.action.DIAL') || actions.includes('android.intent.action.CALL')) out.add('DEFAULT_DIALER');
  if (actions.includes('android.intent.action.SENDTO')) out.add('DEFAULT_SMS');
  if (actions.includes('android.intent.action.ASSIST')) out.add('DEFAULT_ASSISTANT');
  return out;
}

export function validateAndroidSection(section: unknown, opts: AndroidValidationOptions = {}): AndroidValidationResult {
  const catalog = opts.catalog ?? androidCatalog();
  const issues: AndroidValidationIssue[] = [];
  const warnings: AndroidValidationResult['warnings'] = [];
  const secrets: AndroidSecretMarker[] = [];
  const wipe = new Set<string>();
  const result = (): AndroidValidationResult => ({ issues, warnings, wipeRules: [...wipe].sort(), secrets });

  if (!isObject(section) || !isObject(section.fragment) || Object.keys(section).some((k) => k !== 'fragment' && k !== 'applications')
    || (section.applications !== undefined && !Array.isArray(section.applications))) {
    issues.push({ path: '', code: 'invalid_content' });
    return result();
  }
  const fragment = section.fragment;
  const apps: Array<{ entry: unknown; path: string }> = [];
  (section.applications as unknown[] | undefined ?? []).forEach((entry, i) => apps.push({ entry, path: `applications[${i}]` }));
  if (Array.isArray(fragment.applications)) fragment.applications.forEach((entry, i) => apps.push({ entry, path: `fragment.applications[${i}]` }));
  if (Object.keys(fragment).length + apps.length > POLICY_MAX_ITEMS) {
    issues.push({ path: '', code: 'too_many_items' });
    return result();
  }

  const fromSchema = (list: SchemaIssue[], deprecations: Readonly<Record<string, string | null>> = {}, base = ''): void => {
    for (const x of list) {
      if (x.code === 'value_deprecated') { warnings.push({ path: x.path, code: 'value_deprecated' }); continue; }
      if (x.code === 'field_deprecated') {
        const leaf = x.path.slice(base.length + 1);
        issues.push({ path: x.path, code: 'field_deprecated',
          replacement: Object.prototype.hasOwnProperty.call(deprecations, leaf) ? deprecations[leaf] : null });
        continue;
      }
      issues.push({ path: x.path, code: x.code });
    }
  };
  // A secret marker is checked by the scan below, never against the schema.
  const skipMarker = (_p: string, v: unknown): boolean => looksLikeSecretMarker(v);

  // ── Top-level fields ──────────────────────────────────────────────────────
  for (const field of Object.keys(fragment).sort()) {
    const path = `fragment.${field}`;
    const value = fragment[field];
    if (RESERVED_FIELDS.has(field)) { issues.push({ path, code: 'field_reserved' }); continue; }
    const node = catalog.field(field);
    if (!node) { issues.push({ path, code: 'unknown_key' }); continue; }
    if (node.deprecated || Object.prototype.hasOwnProperty.call(DEPRECATED_FIELDS, field)) {
      issues.push({ path, code: 'field_deprecated',
        replacement: Object.prototype.hasOwnProperty.call(DEPRECATED_FIELDS, field) ? DEPRECATED_FIELDS[field] : null });
      continue;
    }
    if (field === 'applications') {
      if (!Array.isArray(value)) issues.push({ path, code: 'type_mismatch' });
      continue;                                          // checked with the policy's apps
    }
    const found: SchemaIssue[] = [];
    catalog.check(node, value, path, found, skipMarker);
    fromSchema(found);
  }

  // ── ONC networks: one setting key per GUID ────────────────────────────────
  const onc = fragment.openNetworkConfiguration;
  if (onc !== undefined) {
    if (!isObject(onc)) issues.push({ path: 'fragment.openNetworkConfiguration', code: 'type_mismatch' });
    else if (onc.NetworkConfigurations !== undefined) {
      if (!Array.isArray(onc.NetworkConfigurations)) issues.push({ path: 'fragment.openNetworkConfiguration.NetworkConfigurations', code: 'type_mismatch' });
      else {
        const guids = new Set<string>();
        onc.NetworkConfigurations.forEach((n, i) => {
          const p = `fragment.openNetworkConfiguration.NetworkConfigurations[${i}]`;
          const guid = isObject(n) ? n.GUID : undefined;
          if (typeof guid !== 'string' || !ANDROID_ONC_GUID_RE.test(guid)) { issues.push({ path: `${p}.GUID`, code: 'onc_guid_invalid' }); return; }
          if (guids.has(guid)) issues.push({ path: `${p}.GUID`, code: 'duplicate_setting_key' });
          guids.add(guid);
        });
      }
    }
  }

  // ── Apps ──────────────────────────────────────────────────────────────────
  const appSchema = catalog.schema('ApplicationPolicy');
  const packages = new Set<string>();
  let requiredForSetup = 0;
  let minimumVersionCode = 0;
  let kiosk = 0;
  for (const { entry, path: rawPath } of apps) {
    if (!isObject(entry)) { issues.push({ path: rawPath, code: 'type_mismatch' }); continue; }
    const pkg = entry.packageName;
    if (!isAndroidPackage(pkg)) { issues.push({ path: `${rawPath}.packageName`, code: 'package_invalid' }); continue; }
    const path = `${rawPath.startsWith('fragment.') ? 'fragment.applications' : 'applications'}[${pkg}]`;
    if (RESERVED_PACKAGES.has(pkg)) { issues.push({ path, code: 'package_reserved' }); continue; }
    if (packages.has(pkg)) { issues.push({ path, code: 'duplicate_setting_key' }); continue; }
    packages.add(pkg);
    if (appSchema) {
      const found: SchemaIssue[] = [];
      catalog.check(appSchema, entry, path, found, skipMarker);
      fromSchema(found, DEPRECATED_APP_FIELDS, path);
    }
    for (const k of Object.keys(DEPRECATED_APP_FIELDS)) {
      if (entry[k] !== undefined && !issues.some((x) => x.path === `${path}.${k}` && x.code === 'field_deprecated')) {
        issues.push({ path: `${path}.${k}`, code: 'field_deprecated', replacement: DEPRECATED_APP_FIELDS[k] });
      }
    }
    if (Array.isArray(entry.roles)) {
      entry.roles.forEach((r, i) => {
        if (isObject(r) && typeof r.roleType === 'string' && RESERVED_ROLES.has(r.roleType)) issues.push({ path: `${path}.roles[${i}]`, code: 'role_reserved' });
      });
    }
    if (entry.managedConfiguration !== undefined && entry.managedConfigurationTemplate !== undefined) {
      issues.push({ path: `${path}.managedConfigurationTemplate`, code: 'managed_configuration_exclusive' });
    }
    if (entry.installType === 'REQUIRED_FOR_SETUP') requiredForSetup++;
    if (entry.installType === 'KIOSK') kiosk++;
    if (entry.minimumVersionCode !== undefined) minimumVersionCode++;
  }
  if (requiredForSetup > POLICY_LIMITS.requiredForSetupApps) issues.push({ path: 'applications', code: 'too_many_required_for_setup' });
  if (minimumVersionCode > POLICY_LIMITS.minimumVersionCodeApps) issues.push({ path: 'applications', code: 'too_many_minimum_version_code' });
  if (kiosk > POLICY_LIMITS.kioskApps) issues.push({ path: 'applications', code: 'too_many_kiosk_apps' });

  // ── Wipe-capable settings ─────────────────────────────────────────────────
  const rules = fragment.policyEnforcementRules;
  if (Array.isArray(rules) && rules.length > 0) {
    wipe.add('android:policyEnforcementRules');
    rules.forEach((r, i) => {
      const p = `fragment.policyEnforcementRules[${i}]`;
      const block = isObject(r) ? r.blockAction : undefined;
      const w = isObject(r) ? r.wipeAction : undefined;
      if (!isObject(block) || !isObject(w)) { issues.push({ path: p, code: 'wipe_rule_invalid' }); return; }
      const blockAfter = typeof block.blockAfterDays === 'number' ? block.blockAfterDays : 0;
      const wipeAfter = w.wipeAfterDays;
      if (typeof wipeAfter !== 'number' || !Number.isInteger(wipeAfter) || wipeAfter < MIN_WIPE_AFTER_DAYS || wipeAfter <= blockAfter) {
        issues.push({ path: `${p}.wipeAction.wipeAfterDays`, code: 'wipe_rule_invalid' });
      }
    });
  }
  const floor = Math.max(FAILED_PASSWORDS_FOR_WIPE.min, Number.isInteger(opts.minFailedPasswordsForWipe)
    ? opts.minFailedPasswordsForWipe! : FAILED_PASSWORDS_FOR_WIPE.defaultFloor);
  if (Array.isArray(fragment.passwordPolicies)) {
    fragment.passwordPolicies.forEach((pp, i) => {
      const n = isObject(pp) ? pp.maximumFailedPasswordsForWipe : undefined;
      if (typeof n !== 'number' || n === 0) return;
      wipe.add('android:passwordPolicies');
      const p = `fragment.passwordPolicies[${i}].maximumFailedPasswordsForWipe`;
      if (n < floor) issues.push({ path: p, code: 'wipe_threshold_too_low' });
      else if (n > FAILED_PASSWORDS_FOR_WIPE.max) issues.push({ path: p, code: 'out_of_range' });
    });
  }
  if (Array.isArray(fragment.frpAdminEmails) && fragment.frpAdminEmails.length > 0) {
    wipe.add('android:frpAdminEmails');
    const domain = typeof opts.adminDomain === 'string' && opts.adminDomain ? opts.adminDomain.toLowerCase() : null;
    fragment.frpAdminEmails.forEach((e, i) => {
      const m = typeof e === 'string' ? EMAIL_RE.exec(e) : null;
      if (!m || domain === null || m[1].toLowerCase() !== domain) issues.push({ path: `fragment.frpAdminEmails[${i}]`, code: 'frp_email_outside_domain' });
    });
  }
  if (Array.isArray(fragment.setupActions) && fragment.setupActions.length > 0) {
    wipe.add('android:setupActions');
    if (fragment.setupActions.length > POLICY_LIMITS.setupActions) issues.push({ path: 'fragment.setupActions', code: 'too_many_setup_actions' });
  }

  // ── Preferred activities against default applications ─────────────────────
  if (Array.isArray(fragment.persistentPreferredActivities) && Array.isArray(fragment.defaultApplicationSettings)) {
    const claimed = new Set<string>();
    for (const a of fragment.persistentPreferredActivities) for (const d of preferredDomains(a)) claimed.add(d);
    fragment.defaultApplicationSettings.forEach((s, i) => {
      if (isObject(s) && typeof s.defaultApplicationType === 'string' && claimed.has(s.defaultApplicationType)) {
        issues.push({ path: `fragment.defaultApplicationSettings[${i}]`, code: 'preferred_activities_conflict' });
      }
    });
  }

  // ── Secrets and variables, at any depth ───────────────────────────────────
  const scan = (v: unknown, path: string, place: { onc: boolean; config: boolean }, key: string | null, depth: number): void => {
    if (depth > MAX_DEPTH) { issues.push({ path, code: 'too_deep' }); return; }
    // A secret key of the ONC holds a secret marker, never a value in clear (stored and logged with the version).
    if (place.onc && !place.config && key !== null && Object.prototype.hasOwnProperty.call(ONC_SECRET_KEYS, key)
      && !looksLikeSecretMarker(v)) {
      issues.push({ path, code: 'secret_expected' });
      return;
    }
    if (typeof v === 'string') {
      if (v.includes('{{') && variablesInString(v).unknown.length > 0) issues.push({ path, code: 'unknown_variable' });
      return;
    }
    if (Array.isArray(v)) { v.forEach((x, i) => scan(x, `${path}[${i}]`, place, key, depth + 1)); return; }
    if (!isObject(v)) return;
    if (looksLikeSecretMarker(v)) {
      const purpose = place.config ? APP_CONFIG_SECRET_PURPOSE
        : place.onc && key !== null && Object.prototype.hasOwnProperty.call(ONC_SECRET_KEYS, key) ? ONC_SECRET_KEYS[key] : null;
      if (purpose === null) { issues.push({ path, code: 'secret_not_allowed' }); return; }
      if (isSecretRef(v)) secrets.push({ path, purpose, kind: 'ref' });
      else if (isSecretValue(v)) {
        if (v.$secretValue.length === 0 || v.$secretValue.length > POLICY_MAX_SECRET_VALUE_LENGTH) issues.push({ path, code: 'secret_invalid' });
        else secrets.push({ path, purpose, kind: 'value' });
      }
      else issues.push({ path, code: 'secret_invalid' });
      return;
    }
    for (const [k, x] of Object.entries(v)) {
      scan(x, `${path}.${k}`, place, k, depth + 1);
    }
  };
  for (const field of Object.keys(fragment).sort()) {
    if (field === 'applications') continue;
    scan(fragment[field], `fragment.${field}`, { onc: field === 'openNetworkConfiguration', config: false }, field, 1);
  }
  for (const { entry, path: rawPath } of apps) {
    if (!isObject(entry) || !isAndroidPackage(entry.packageName)) continue;
    const path = `${rawPath.startsWith('fragment.') ? 'fragment.applications' : 'applications'}[${entry.packageName}]`;
    for (const [k, x] of Object.entries(entry)) {
      scan(x, `${path}.${k}`, { onc: false, config: k === 'managedConfiguration' }, k, 2);
    }
  }
  return result();
}

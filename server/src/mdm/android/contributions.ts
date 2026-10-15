import { variablesOf, type JsonValue, type PolicyVariable } from '@obligarth/shared';
import {
  ANDROID_ONC_GUID_RE, androidAppKey, androidFieldKey, androidOncKey, isAndroidPackage, type AndroidPolicySection,
} from '@obligarth/shared/dist/android/policy.js';
import { valueHashOf } from '../policies/contributions';

// =============================================================================
// What the Android section of a policy version brings to the resolution: one
// setting key per top-level field (android:<field>), per app of the policy
// (android:app[<package>], the fragment's own applications[] included) and
// per ONC network (android:onc[<GUID>]; what openNetworkConfiguration holds
// besides its networks stays under android:openNetworkConfiguration). The
// value is kept as the version stores it (secrets as references, variables
// as templates); its hash never derives from a secret nor from a device.
// Computed once per published version (immutable), never per device. Only a
// validated section is read: what the validation refuses is skipped here.
// =============================================================================

export interface AndroidContribution {
  settingKey: string;
  value: JsonValue;
  valueHash: string;
  /** Known variables of the value, resolved per device at rendering. */
  variables: PolicyVariable[];
}

const isObject = (v: unknown): v is Record<string, JsonValue> => !!v && typeof v === 'object' && !Array.isArray(v);

function push(out: AndroidContribution[], seen: Set<string>, settingKey: string, value: JsonValue): void {
  if (seen.has(settingKey)) return;
  seen.add(settingKey);
  out.push({ settingKey, value, valueHash: valueHashOf(value), variables: variablesOf(value) });
}

/** The contributions of an Android section, sorted by setting key. */
export function androidContributions(section: AndroidPolicySection | undefined | null): AndroidContribution[] {
  const out: AndroidContribution[] = [];
  const seen = new Set<string>();
  if (!section || !isObject(section.fragment)) return out;
  const fragment = section.fragment;
  for (const field of Object.keys(fragment).sort()) {
    const value = fragment[field];
    if (field === 'applications') continue;
    if (field === 'openNetworkConfiguration' && isObject(value)) {
      const { NetworkConfigurations, ...rest } = value;
      if (Array.isArray(NetworkConfigurations)) {
        for (const n of NetworkConfigurations) {
          if (isObject(n) && typeof n.GUID === 'string' && ANDROID_ONC_GUID_RE.test(n.GUID)) push(out, seen, androidOncKey(n.GUID), n);
        }
      }
      if (Object.keys(rest).length > 0) push(out, seen, androidFieldKey(field), rest);
      continue;
    }
    push(out, seen, androidFieldKey(field), value);
  }
  const apps = [...(section.applications ?? []), ...(Array.isArray(fragment.applications) ? fragment.applications : [])];
  for (const a of apps) {
    if (isObject(a) && isAndroidPackage(a.packageName)) push(out, seen, androidAppKey(a.packageName), a);
  }
  return out.sort((x, y) => (x.settingKey < y.settingKey ? -1 : x.settingKey > y.settingKey ? 1 : 0));
}

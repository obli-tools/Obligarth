import { createHash } from 'node:crypto';
import {
  artifactOf, settingKeyOf, settingKeysOf, variablesOf,
  type JsonValue, type MergeDescriptor, type PolicyContentV1, type PolicyVariable, type SchemaEntry, type SettingKind,
} from '@obligarth/shared';
import { canonicalJson } from '../../audit/canonical';
import type { AppleCatalogView } from '../apple/catalog';

// =============================================================================
// What a resource brings to the resolution (docs: modele-donnees-mdm §7.3,
// §7.4, §7.6 step 3): the setting keys of each item of a policy version, with
// the hash of the value (SHA-256 of the canonical JSON: sorted keys, no
// whitespace), the artifact it goes to and what its availability depends on
// (variables, assets). Computed once per published version (immutable), never
// per device. A secret stays a reference and a variable a template: the hash
// never derives from a secret nor from a device's value.
// =============================================================================

export interface Contribution {
  settingKey: string;
  type: string;
  kind: SettingKind;
  /** Keyed types: the top-level key. */
  key: string | null;
  /** Collections and raw profiles: the instance. */
  instance: string | null;
  /** Null for an app (its artifact depends on the device, section 8.3). */
  artifactKey: string | null;
  valueHash: string;
  /** The value the key brings (keyed: the key's value; else the item's values), as the version stores it: secrets
   *  as references, variables as templates. Absent for a tombstone. Read by the compilation only (section 7.9):
   *  never stored with the effective state, never logged. */
  value?: JsonValue;
  removed: boolean;
  /** Known variables of the value, resolved per device at rendering. */
  variables: PolicyVariable[];
  /** A declaration key referencing an asset (refused at the MVP). */
  requiresAsset: boolean;
  /** Apps: the identifier and the options of the assignment. */
  app?: { identifier: string; config: boolean; takeOver: boolean; supportedPlatforms: string[] };
}

const REMOVED_HASH = createHash('sha256').update('{"$remove":true}').digest('hex');

/** SHA-256 of the canonical JSON of a value. */
export function valueHashOf(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value === undefined ? null : value)).digest('hex');
}

/** Does a value of a declaration use a key that references an asset (refused at the MVP)? */
function usesAsset(entry: SchemaEntry | undefined, key: string | null, value: unknown): boolean {
  if (!entry || entry.family !== 'declaration' || value === undefined) return false;
  const names = key !== null ? [key] : Object.keys((value ?? {}) as Record<string, unknown>);
  return names.some((n) => entry.keys.find((k) => k.name === n)?.assetReference === true);
}

/** The contributions of the content of a policy version. Items whose type the catalog no longer knows still
 *  contribute (their keys turn out 'schema_unknown'): the resolution never drops a published setting silently. */
export function policyContributions(content: PolicyContentV1, catalog: AppleCatalogView, policyUuid: string): Contribution[] {
  const out: Contribution[] = [];
  const seen = new Set<string>();
  for (const item of content.sections?.apple?.items ?? []) {
    const d: MergeDescriptor = catalog.descriptor(item.type) ?? { kind: 'profile_payload', merge: 'atomic' };
    const keys = settingKeysOf(item, d);
    if ('error' in keys) continue;   // refused at the validation; a version never holds one
    const entry = catalog.entry(item.type);
    for (const part of keys.parts) {
      if (seen.has(part.settingKey)) continue;
      seen.add(part.settingKey);
      const art = artifactOf(item.type, d, part.instance, { policyUuid, itemId: item.id });
      out.push({
        settingKey: part.settingKey,
        type: item.type,
        kind: d.kind,
        key: part.key,
        instance: part.instance,
        artifactKey: `${art.channel}:${art.identifier}`,
        valueHash: part.remove ? REMOVED_HASH : valueHashOf(part.value),
        ...(part.remove || part.value === undefined ? {} : { value: part.value }),
        removed: part.remove,
        variables: part.remove ? [] : variablesOf(part.value),
        requiresAsset: part.remove ? false : usesAsset(entry, part.key, part.value),
      });
    }
  }
  return out;
}

/** The contribution of an app assignment (section 8.2): apple:app[<identifier>], its options as the value. */
export function appContribution(app: { identifier: string; supportedPlatforms: string[] }, options: Record<string, JsonValue>): Contribution {
  const d: MergeDescriptor = { kind: 'app', merge: 'atomic' };
  return {
    settingKey: settingKeyOf('app', d, { instance: app.identifier }),
    type: 'app',
    kind: 'app',
    key: null,
    instance: app.identifier,
    artifactKey: null,
    valueHash: valueHashOf(options),
    value: options,
    removed: false,
    variables: variablesOf(options.config ?? null),
    requiresAsset: false,
    app: {
      identifier: app.identifier,
      config: options.config !== undefined && options.config !== null,
      takeOver: options.takeOver === true,
      supportedPlatforms: app.supportedPlatforms,
    },
  };
}

export { REMOVED_HASH };

import {
  RAW_PROFILE_TYPE, SETTING_TYPE_PREFIX, type AppleSchemaCatalog, type MergeDescriptor, type SchemaEntry, type SchemaKey,
} from '@obligarth/shared';
import { APPLE_OVERLAY, MVP_TYPES, type TypeOverlay } from './overlay';
import { APPLE_MVP_CATALOG } from './schema/appleMvpCatalog';

// =============================================================================
// The current catalog of the Apple schemas, as the resolver, the validation
// and the console read it (docs: modele-donnees-mdm §7.3): the imported schema
// completed by the overlay. The merge descriptor of a type comes from the
// schema (declarations: apply combined → keyed, multiple → collection, single
// → atomic; payloads: multiple → collection, else atomic), unless the overlay
// says otherwise; a raw profile is a collection of one item (its id), a
// Settings item an atomic setting.
// =============================================================================

/** The raw profile (CFG-06): opaque payloads, delivered whole to the Apple devices. */
const RAW_ENTRY: SchemaEntry = Object.freeze({
  type: RAW_PROFILE_TYPE, family: 'profile_payload', title: 'Imported profile', multiple: true, keys: [],
  os: { iOS: { introduced: '4.0' }, macOS: { introduced: '10.7' }, tvOS: { introduced: '9.0' }, visionOS: { introduced: '1.1' } },
}) as SchemaEntry;

export interface AppleCatalogView {
  release: AppleSchemaCatalog['release'];
  /** The schema of a type (the raw profile's included); undefined when unknown. */
  entry(type: string): SchemaEntry | undefined;
  overlay(type: string): TypeOverlay;
  /** How the type resolves; null for an unknown type. */
  descriptor(type: string): MergeDescriptor | null;
  /** Offered at the MVP: a type of the pilot, or a Settings item not disabled (never the raw profile, which only
   *  its import route produces). */
  enabled(type: string): boolean;
  /** The purpose of the secret a key holds (dotted schema path), null when the key holds no secret. */
  secretPurpose(type: string, path: string): string | null;
  /** A top-level key of a type. */
  key(type: string, name: string): SchemaKey | undefined;
  /** The types of the catalog, sorted. */
  types(): string[];
}

function descriptorOf(entry: SchemaEntry, overlay: TypeOverlay): MergeDescriptor {
  if (entry.type === RAW_PROFILE_TYPE) return { kind: 'raw', merge: 'collection' };
  if (entry.family === 'command') return { kind: 'setting', merge: 'atomic' };
  if (entry.family === 'declaration') {
    const merge = overlay.merge ?? (entry.apply === 'combined' ? 'keyed' : entry.apply === 'multiple' ? 'collection' : 'atomic');
    return merge === 'collection' && overlay.instanceKey
      ? { kind: 'declaration', merge, instanceKey: overlay.instanceKey }
      : { kind: 'declaration', merge };
  }
  const merge = overlay.merge ?? (entry.multiple ? 'collection' : 'atomic');
  return merge === 'collection' && overlay.instanceKey
    ? { kind: 'profile_payload', merge, instanceKey: overlay.instanceKey }
    : { kind: 'profile_payload', merge };
}

export function buildCatalogView(catalog: AppleSchemaCatalog, overlays: Record<string, TypeOverlay> = APPLE_OVERLAY): AppleCatalogView {
  const descriptors = new Map<string, MergeDescriptor>();
  const keys = new Map<string, Map<string, SchemaKey>>();
  const entryOf = (type: string): SchemaEntry | undefined => (type === RAW_PROFILE_TYPE ? RAW_ENTRY : catalog.entries[type]);
  const overlayOf = (type: string): TypeOverlay => overlays[type] ?? {};
  return {
    release: catalog.release,
    entry: entryOf,
    overlay: overlayOf,
    descriptor(type) {
      const cached = descriptors.get(type);
      if (cached) return cached;
      const entry = entryOf(type);
      if (!entry) return null;
      const d = Object.freeze(descriptorOf(entry, overlayOf(type))) as MergeDescriptor;
      descriptors.set(type, d);
      return d;
    },
    enabled(type) {
      if (type === RAW_PROFILE_TYPE || !catalog.entries[type] || overlayOf(type).disabled) return false;
      return MVP_TYPES.has(type) || type.startsWith(SETTING_TYPE_PREFIX);
    },
    secretPurpose(type, path) {
      return overlayOf(type).secretKeys?.[path] ?? null;
    },
    key(type, name) {
      let m = keys.get(type);
      if (!m) {
        m = new Map((entryOf(type)?.keys ?? []).map((k) => [k.name, k]));
        keys.set(type, m);
      }
      return m.get(name);
    },
    types() {
      return Object.keys(catalog.entries).sort();
    },
  };
}

let current: AppleCatalogView | null = null;

/** The current catalog (the one shipped with the server). */
export function appleCatalog(): AppleCatalogView {
  if (!current) current = buildCatalogView(APPLE_MVP_CATALOG);
  return current;
}

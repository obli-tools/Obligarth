// =============================================================================
// Setting keys and artifact keys (docs: modele-donnees-mdm §7.3, §7.4): a
// setting key identifies what resolves (one per top-level key of a 'keyed'
// type, one per instance of a 'collection', one per 'atomic' type); an
// artifact key identifies what is delivered (several keyed setting keys of a
// type make one artifact). Instances never appear in clear in an identifier:
// a short hash of the instance does (an SSID can be telling).
// =============================================================================
import { POLICY_INSTANCE_RE, type AppleItem, type JsonValue } from '../policyContent';
import { sha256Hex } from './sha256';

export { sha256Hex } from './sha256';

export type MergeMode = 'keyed' | 'collection' | 'atomic';
/** What a type is, for the keys: a declaration, a profile payload, a raw profile, a Settings item, an app. */
export type SettingKind = 'declaration' | 'profile_payload' | 'raw' | 'setting' | 'app';

/** How a type resolves (section 7.3): from the schema (apply, multiple), completed by the server's overlay. */
export interface MergeDescriptor {
  kind: SettingKind;
  merge: MergeMode;
  /** Collection types: the key whose value names the instance; absent: item.instance names it. */
  instanceKey?: string;
}

export const RAW_PROFILE_TYPE = 'raw.profile';
export const SETTING_TYPE_PREFIX = 'setting.';
export const APP_MANAGED_DECLARATION = 'com.apple.configuration.app.managed';

/** device_effective_settings.setting_key: 300 characters at most. */
export const SETTING_KEY_MAX = 300;
/** device_artifacts.artifact_key (CHECK device_artifacts_key_check). */
export const ARTIFACT_KEY_RE = /^(ddm|profile|app|setting):[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
/** Identifiers of the artifacts, as the base bounds them (CHECK mdm_artifacts_identifier_check). */
export const DECLARATION_IDENTIFIER_RE = /^obg\.cfg\.pol-[A-Za-z0-9._-]{1,52}$/;
export const PROFILE_IDENTIFIER_RE = /^tools\.obli\.obligarth\.(p|raw)\.[A-Za-z0-9._-]{1,140}$/;
export const SETTING_IDENTIFIER_RE = /^[a-z][a-z0-9_]{0,63}$/;
export const APP_IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;

export type ArtifactChannel = 'ddm' | 'profile' | 'setting' | 'app';

/** First 12 hexadecimal characters of the SHA-256 of `s` (instances of a declaration). */
export const h12 = (s: string): string => sha256Hex(s).slice(0, 12);
/** First 16 hexadecimal characters of the SHA-256 of `s` (instances of a profile, raw profiles). */
export const h16 = (s: string): string => sha256Hex(s).slice(0, 16);

const DECLARATION_PREFIX = 'com.apple.configuration.';
const PAYLOAD_PREFIX = 'com.apple.';

/** The type without 'com.apple.configuration.' (declarations) or 'com.apple.' (payloads). */
export function shortType(type: string): string {
  if (type.startsWith(DECLARATION_PREFIX)) return type.slice(DECLARATION_PREFIX.length);
  if (type.startsWith(PAYLOAD_PREFIX)) return type.slice(PAYLOAD_PREFIX.length);
  return type;
}

/** The artifact name of a Settings item: lower case, '_' as separator ('DeviceName' → 'device_name'). */
export function settingItemSlug(item: string): string {
  return item.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .toLowerCase().replace(/[^a-z0-9_]/g, '_');
}

/** The setting key of a part of an item: apple:<type>:<key>, apple:<type>[<instance>], apple:<type>,
 *  apple:raw[<item id>], apple:setting:<Item>, apple:app[<identifier>]. */
export function settingKeyOf(type: string, d: MergeDescriptor, part: { key?: string; instance?: string; itemId?: string }): string {
  switch (d.kind) {
    case 'raw': return `apple:raw[${part.itemId ?? ''}]`;
    case 'setting': return `apple:setting:${type.startsWith(SETTING_TYPE_PREFIX) ? type.slice(SETTING_TYPE_PREFIX.length) : type}`;
    case 'app': return `apple:app[${part.instance ?? ''}]`;
    default:
      if (d.merge === 'keyed') return `apple:${type}:${part.key ?? ''}`;
      if (d.merge === 'collection') return `apple:${type}[${part.instance ?? ''}]`;
      return `apple:${type}`;
  }
}

export interface ParsedSettingKey {
  kind: 'keyed' | 'collection' | 'atomic' | 'raw' | 'setting' | 'app';
  /** The schema type ('setting.<Item>' for a Settings item, 'raw.profile', 'app'). */
  type: string;
  key?: string;
  instance?: string;
}

/** The parts of a setting key (types never hold ':' nor '['); null when it is not one. */
export function parseSettingKey(settingKey: string): ParsedSettingKey | null {
  let m = /^apple:raw\[(.+)\]$/.exec(settingKey);
  if (m) return { kind: 'raw', type: RAW_PROFILE_TYPE, instance: m[1] };
  m = /^apple:app\[(.+)\]$/.exec(settingKey);
  if (m) return { kind: 'app', type: 'app', instance: m[1] };
  m = /^apple:setting:(.+)$/.exec(settingKey);
  if (m) return { kind: 'setting', type: `${SETTING_TYPE_PREFIX}${m[1]}` };
  m = /^apple:([^:[\]]+)\[(.*)\]$/.exec(settingKey);
  if (m) return { kind: 'collection', type: m[1], instance: m[2] };
  m = /^apple:([^:[\]]+):(.+)$/.exec(settingKey);
  if (m) return { kind: 'keyed', type: m[1], key: m[2] };
  m = /^apple:([^:[\]]+)$/.exec(settingKey);
  if (m) return { kind: 'atomic', type: m[1] };
  return null;
}

/** A setting key an item produces, with the value it brings. */
export interface ItemSettingPart {
  settingKey: string;
  /** Keyed types: the top-level key. */
  key: string | null;
  /** Collection types and raw profiles: the instance (item id for a raw profile). */
  instance: string | null;
  /** The key's value (keyed), else the item's values; absent for a tombstone. */
  value?: JsonValue;
  remove: boolean;
}

export type ItemKeysError = 'remove_not_allowed' | 'invalid_instance';

/** Is `s` usable as an instance named by a value (SSID, OS version…): 1 to 128 characters, no control
 *  character, no variable. */
export function isInstanceValue(s: unknown): s is string {
  return typeof s === 'string' && s.length >= 1 && s.length <= 128 && !/[\u0000-\u001f\u007f]/.test(s) && !s.includes('{{');
}

/**
 * The setting keys of an item (section 7.3): keyed → one per top-level key of `values`; collection → one,
 * named by `values[instanceKey]` (or `item.instance` when the overlay names no key, or for a tombstone);
 * atomic, raw profile, Settings item → one. A tombstone (`remove`) is refused on a keyed type.
 */
export function settingKeysOf(item: AppleItem, d: MergeDescriptor): { parts: ItemSettingPart[] } | { error: ItemKeysError } {
  const values = (item.values ?? {}) as Record<string, JsonValue>;
  const remove = item.remove === true;
  if (d.kind === 'raw') {
    return { parts: [{ settingKey: settingKeyOf(item.type, d, { itemId: item.id }), key: null, instance: item.id, remove, ...(remove ? {} : { value: values }) }] };
  }
  if (d.merge === 'keyed') {
    if (remove) return { error: 'remove_not_allowed' };
    return {
      parts: Object.keys(values).sort().map((key) => ({
        settingKey: settingKeyOf(item.type, d, { key }), key, instance: null, value: values[key], remove: false,
      })),
    };
  }
  if (d.merge === 'collection') {
    let instance: string | undefined;
    if (!d.instanceKey) {
      // Named in the editor: 1 to 64 characters among letters, digits, '.', '_', '-' and the space.
      if (typeof item.instance !== 'string' || !POLICY_INSTANCE_RE.test(item.instance)) return { error: 'invalid_instance' };
      instance = item.instance;
    } else if (remove) {
      // A tombstone has no values: it names the inherited instance (an SSID, an OS version…).
      if (!isInstanceValue(item.instance)) return { error: 'invalid_instance' };
      instance = item.instance;
    } else {
      if (item.instance !== undefined) return { error: 'invalid_instance' };
      const v = values[d.instanceKey];
      if (!isInstanceValue(v)) return { error: 'invalid_instance' };
      instance = v;
    }
    return { parts: [{ settingKey: settingKeyOf(item.type, d, { instance }), key: null, instance, remove, ...(remove ? {} : { value: values }) }] };
  }
  if (item.instance !== undefined) return { error: 'invalid_instance' };
  return { parts: [{ settingKey: settingKeyOf(item.type, d, {}), key: null, instance: null, remove, ...(remove ? {} : { value: values }) }] };
}

/**
 * The artifact a setting key of a type goes to (section 7.4): channel and identifier. `instance`: the
 * collection's instance; `raw`: the policy's uuid and the item's id of a raw profile. Settings items go to
 * 'setting:<item>', apps to appArtifactKey.
 */
export function artifactOf(type: string, d: MergeDescriptor, instance: string | null,
  raw?: { policyUuid: string; itemId: string }): { channel: ArtifactChannel; identifier: string } {
  switch (d.kind) {
    case 'declaration': {
      const base = `obg.cfg.pol-${shortType(type)}`;
      return { channel: 'ddm', identifier: d.merge === 'collection' && instance !== null ? `${base}.${h12(instance)}` : base };
    }
    case 'profile_payload': {
      const base = `tools.obli.obligarth.p.${shortType(type)}`;
      return { channel: 'profile', identifier: d.merge === 'collection' && instance !== null ? `${base}.${h16(instance)}` : base };
    }
    case 'raw':
      return { channel: 'profile', identifier: `tools.obli.obligarth.raw.${h16(`${raw?.policyUuid ?? ''}:${raw?.itemId ?? ''}`)}` };
    case 'setting':
      return { channel: 'setting', identifier: settingItemSlug(type.startsWith(SETTING_TYPE_PREFIX) ? type.slice(SETTING_TYPE_PREFIX.length) : type) };
    case 'app':
      return { channel: 'app', identifier: instance ?? '' };
  }
}

/** The artifact key of an app: 'app:<identifier>', or the declaration app.managed when the app goes by DDM
 *  (section 8.3). */
export function appArtifactKey(identifier: string, viaDeclaration: boolean): string {
  return viaDeclaration ? `ddm:obg.cfg.pol-app.managed.${h12(identifier)}` : `app:${identifier}`;
}

/** Does the identifier fit what the base accepts for its channel? */
export function identifierFits(channel: ArtifactChannel, identifier: string): boolean {
  switch (channel) {
    case 'ddm': return DECLARATION_IDENTIFIER_RE.test(identifier);
    case 'profile': return PROFILE_IDENTIFIER_RE.test(identifier);
    case 'setting': return SETTING_IDENTIFIER_RE.test(identifier);
    case 'app': return APP_IDENTIFIER_RE.test(identifier);
  }
}

/** Preferred artifact prefixes of the policies: the reconciliation never touches another profile. */
export const POLICY_PROFILE_PREFIXES = ['tools.obli.obligarth.p.', 'tools.obli.obligarth.raw.'] as const;

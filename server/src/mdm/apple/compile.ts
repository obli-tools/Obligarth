import {
  RAW_PROFILE_TYPE, SETTING_TYPE_PREFIX, identifierFits, isSecretRef, variablesOf,
  type ArtifactChannel, type JsonValue,
} from '@obligarth/shared';
import { canonicalize, sha256Hex } from '../../apple/ddm/canonical';
import type { ResolvedSetting } from '../policies/resolver';
import type { AppleCatalogView } from './catalog';

// =============================================================================
// The Apple compilation (docs: modele-donnees-mdm §7.4, §7.9): the settings a
// resolution retained for one device, grouped by artifact key, become the
// bodies of the artifacts to deliver. Only what is available and not removed
// is compiled; several keyed setting keys of a type make one artifact.
//   ddm      { Type, Identifier, Payload }                     a declaration
//   profile  { PayloadIdentifier, PayloadDisplayName,
//              PayloadOrganization, PayloadContent: [
//                { PayloadType, values } ] }                    a profile
//   setting  { Item, values }                                  a Settings item
// The secret references and the variables stay in the body: the secret and the
// value proper to a device exist at rendering only (render.ts). An artifact is
// addressed by content: hash = SHA-256 of the canonical JSON (RFC 8785) of
// { channel, type, identifier, body, encrypt }; the same settings give the same
// hash, for every device and every run. A profile that carries a secret
// reference, and every raw profile, is encrypted for the device (encrypt).
// A declaration never carries a secret (the validation refuses it; checked
// again here). What cannot be delivered as compiled is returned with its
// problems (a required key no policy brings, an identifier out of bounds): the
// artifact is then recorded in error, never sent.
// The apps (apple:app[…]) are compiled with their catalog (lot C4).
// Pure: no database, no logger; the unit tests load it.
// =============================================================================

/** Bumped when the form of the compiled bodies changes: every tenant is then resolved again (catalogRelease.ts). */
export const COMPILER_VERSION = 1;

export interface CompiledArtifact {
  artifactKey: string;
  channel: ArtifactChannel;
  artifactType: string;
  identifier: string;
  body: Record<string, JsonValue>;
  hash: string;
  secretRefs: string[];
  hasVariables: boolean;
  encrypt: boolean;
  /** Setting keys that produced the artifact (device_artifacts.sources). */
  sources: string[];
  /** Why the artifact cannot be delivered as compiled (codes, never a value); empty: deliverable. */
  problems: string[];
}

export interface CompileOptions {
  /** PayloadOrganization of the profiles: the tenant's name. */
  organization: string;
}

const MAX_DEPTH = 64;

/** The secret references of a value, sorted, each once. */
export function secretRefsOf(value: unknown, out: Set<string> = new Set(), depth = 0): Set<string> {
  if (depth > MAX_DEPTH || value === null || typeof value !== 'object') return out;
  if (isSecretRef(value)) {
    out.add(value.$secret);
    return out;
  }
  for (const v of Array.isArray(value) ? value : Object.values(value as Record<string, unknown>)) secretRefsOf(v, out, depth + 1);
  return out;
}

const asObject = (v: JsonValue | undefined): Record<string, JsonValue> =>
  (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, JsonValue> : {});

/** The hash of an artifact: its content, nothing of a device. */
export function artifactHash(a: Pick<CompiledArtifact, 'channel' | 'artifactType' | 'identifier' | 'body' | 'encrypt'>): string {
  return sha256Hex(canonicalize({ channel: a.channel, type: a.artifactType, identifier: a.identifier, body: a.body, encrypt: a.encrypt }));
}

/**
 * compileApple(effective, catalog, options): the artifacts of the settings retained for one device (section 7.9),
 * sorted by artifact key. The device itself is not read: what depends on it was decided by the resolution (the
 * availability of each key) or is left to the rendering (variables, secrets).
 */
export function compileApple(effective: ResolvedSetting[], catalog: AppleCatalogView, options: CompileOptions): CompiledArtifact[] {
  const groups = new Map<string, ResolvedSetting[]>();
  for (const s of effective) {
    if (s.removed || s.availability.status !== 'available' || !s.artifactKey || s.kind === 'app') continue;
    const g = groups.get(s.artifactKey);
    if (g) g.push(s); else groups.set(s.artifactKey, [s]);
  }
  const out: CompiledArtifact[] = [];
  for (const artifactKey of [...groups.keys()].sort()) {
    const settings = groups.get(artifactKey)!.sort((a, b) => (a.settingKey < b.settingKey ? -1 : a.settingKey > b.settingKey ? 1 : 0));
    const first = settings[0];
    const sep = artifactKey.indexOf(':');
    const channel = artifactKey.slice(0, sep) as ArtifactChannel;
    const identifier = artifactKey.slice(sep + 1);
    const type = first.type;
    const entry = catalog.entry(type);
    const problems: string[] = [];
    // The values of the artifact: the keys of a keyed type gathered, else the values of the one item.
    const keyed = first.key !== null;
    const values: Record<string, JsonValue> = {};
    if (keyed) {
      for (const s of settings) if (s.key !== null && s.value !== undefined) values[s.key] = s.value;
      for (const k of entry?.keys ?? []) {
        if (k.required && k.name !== 'ANY' && !Object.prototype.hasOwnProperty.call(values, k.name)) problems.push(`compile:required:${k.name}`.slice(0, 120));
      }
    } else {
      Object.assign(values, asObject(first.value));
    }

    let body: Record<string, JsonValue>;
    let valuesPart: JsonValue = values;
    if (channel === 'ddm') {
      body = { Type: type, Identifier: identifier, Payload: values };
      if (secretRefsOf(values).size > 0) problems.push('compile:secret_in_declaration');
    } else if (channel === 'profile' && type === RAW_PROFILE_TYPE) {
      const payloads = Array.isArray(values.payloads) ? values.payloads : [];
      const content = payloads.map((p) => {
        const { PayloadType, ...rest } = asObject(p);
        return { PayloadType: typeof PayloadType === 'string' ? PayloadType : '', values: rest };
      });
      if (content.length === 0 || content.some((p) => !p.PayloadType)) problems.push('compile:raw_profile');
      valuesPart = content;
      body = {
        PayloadIdentifier: identifier,
        PayloadDisplayName: typeof values.displayName === 'string' && values.displayName ? values.displayName : 'Imported profile',
        PayloadOrganization: options.organization, PayloadContent: content,
      };
    } else if (channel === 'profile') {
      body = {
        PayloadIdentifier: identifier, PayloadDisplayName: entry?.title ?? type, PayloadOrganization: options.organization,
        PayloadContent: [{ PayloadType: type, values }],
      };
    } else if (channel === 'setting') {
      body = { Item: type.startsWith(SETTING_TYPE_PREFIX) ? type.slice(SETTING_TYPE_PREFIX.length) : type, values };
    } else {
      continue;                                         // 'app': compiled with the catalog of apps (lot C4)
    }
    if (!identifierFits(channel, identifier)) problems.push('compile:identifier');
    const secretRefs = [...secretRefsOf(valuesPart)].sort();
    const encrypt = channel === 'profile' && (type === RAW_PROFILE_TYPE || secretRefs.length > 0);
    let hash: string;
    try {
      hash = artifactHash({ channel, artifactType: type, identifier, body, encrypt });
    } catch {
      // A value no canonical JSON holds (the validation refuses it at the write): nothing to address by content.
      continue;
    }
    out.push({
      artifactKey, channel, artifactType: type, identifier, body, hash, secretRefs, encrypt,
      hasVariables: variablesOf(valuesPart).length > 0,
      sources: settings.map((s) => s.settingKey),
      problems,
    });
  }
  return out;
}

import {
  APP_MANAGED_DECLARATION, APPLE_APP_OPTION_DEFAULTS, RAW_PROFILE_TYPE, SETTING_TYPE_PREFIX, identifierFits, isSecretRef, variablesOf,
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
// An app (apple:app[<identifier>], section 8.3, lot C4) is one artifact of its
// own: 'app:<identifier>' (the command InstallApplication: iTunesStoreID,
// ManagementFlags, Attributes, PurchaseMethod 1, the licence's kind, the managed
// configuration with its variables) or the declaration app.managed
// 'ddm:obg.cfg.pol-app.managed.<h12>' (AppStoreID, InstallBehavior with the
// licence's kind, IncludeInBackup, Attributes); the device's ownership and mode
// decide the licence (device or user), Removable (always true on a personal
// device) and the takeover (never in User Enrollment).
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
  /** The device's ownership and management mode (the apps' licence, Removable, takeover); a company device by default. */
  device?: { ownership: string; mode: string };
}

/** The artifact type of the app channel (mdm_artifacts.artifact_type). */
export const APP_ARTIFACT_TYPE = 'app.install';

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
  const out: CompiledArtifact[] = [];
  for (const s of effective) {
    if (s.removed || s.availability.status !== 'available' || !s.artifactKey) continue;
    if (s.kind === 'app') {
      const a = compileApp(s, options);
      if (a) out.push(a);
      continue;
    }
    const g = groups.get(s.artifactKey);
    if (g) g.push(s); else groups.set(s.artifactKey, [s]);
  }
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
      continue;                                         // 'app': compileApp
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
  return out.sort((a, b) => (a.artifactKey < b.artifactKey ? -1 : a.artifactKey > b.artifactKey ? 1 : 0));
}

const bool = (v: JsonValue | undefined, d: boolean): boolean => (typeof v === 'boolean' ? v : d);

/** The artifact of an app retained for a device (section 8.3); null when its key is not an app's. */
export function compileApp(s: ResolvedSetting, options: CompileOptions): CompiledArtifact | null {
  const artifactKey = s.artifactKey!;
  const sep = artifactKey.indexOf(':');
  const channel = artifactKey.slice(0, sep) as ArtifactChannel;
  const identifier = artifactKey.slice(sep + 1);
  const appId = s.instance ?? '';
  const o = asObject(s.value);
  const personal = options.device?.ownership === 'personal';
  const userEnrollment = options.device?.mode === 'user_enrollment';
  const removable = personal ? true : bool(o.removable, APPLE_APP_OPTION_DEFAULTS.removable);
  const removeOnUnenroll = bool(o.removeOnUnenroll, APPLE_APP_OPTION_DEFAULTS.removeOnUnenroll);
  const preventBackup = bool(o.preventBackup, APPLE_APP_OPTION_DEFAULTS.preventBackup);
  const takeOver = !userEnrollment && bool(o.takeOver, APPLE_APP_OPTION_DEFAULTS.takeOver);
  const config = o.config && typeof o.config === 'object' && !Array.isArray(o.config) ? o.config as Record<string, JsonValue> : null;
  const storeId = s.app?.storeId ?? null;
  const problems: string[] = [];
  if (!storeId || !/^[0-9]{1,20}$/.test(storeId)) problems.push('compile:store_id');
  if (config && secretRefsOf(config).size > 0) problems.push('compile:secret_in_app_config');
  const license = personal ? 'user' : 'device';
  let body: Record<string, JsonValue>;
  let artifactType: string;
  if (channel === 'app') {
    artifactType = APP_ARTIFACT_TYPE;
    body = {
      Identifier: appId, iTunesStoreID: storeId && /^[0-9]{1,15}$/.test(storeId) ? Number(storeId) : 0,
      ManagementFlags: (removeOnUnenroll ? 1 : 0) | (preventBackup ? 4 : 0), Attributes: { Removable: removable }, PurchaseMethod: 1,
      LicenseAssignment: license, ...(takeOver ? { ChangeManagementState: 'Managed' } : {}), ...(config ? { Configuration: config } : {}),
    };
    if (!identifierFits('app', identifier) || identifier !== appId) problems.push('compile:identifier');
  } else if (channel === 'ddm') {
    artifactType = APP_MANAGED_DECLARATION;
    body = {
      Type: APP_MANAGED_DECLARATION, Identifier: identifier,
      Payload: {
        AppStoreID: storeId ?? '', InstallBehavior: { Install: 'Required', License: { Assignment: license === 'user' ? 'User' : 'Device' } },
        IncludeInBackup: !preventBackup, Attributes: { Hideable: false, Lockable: false },
      },
    };
    if (!identifierFits('ddm', identifier)) problems.push('compile:identifier');
  } else {
    return null;
  }
  const encrypt = false;
  let hash: string;
  try {
    hash = artifactHash({ channel, artifactType, identifier, body, encrypt });
  } catch {
    return null;
  }
  return {
    artifactKey, channel, artifactType, identifier, body, hash, secretRefs: [], encrypt,
    hasVariables: config ? variablesOf(config).length > 0 : false, sources: [s.settingKey], problems,
  };
}

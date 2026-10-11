// =============================================================================
// Catalog of the Apple schemas (docs: modele-donnees-mdm §7.3): the interface
// the resolver, the validation, the availability and the editor read. Its
// content is imported from Apple's device-management schema (release branch)
// and versioned with the server; the editor's import chain (CFG-01) produces
// it, the server ships the pilot's types until then.
// =============================================================================
import type { EnrollmentClass, Platform } from '../enums';
import type { JsonValue } from '../policyContent';

export type AppleOs = 'iOS' | 'macOS' | 'tvOS' | 'visionOS' | 'watchOS';
export const APPLE_OSES: readonly AppleOs[] = ['iOS', 'macOS', 'tvOS', 'visionOS', 'watchOS'];

export interface OsSupport {
  introduced: string | 'n/a';
  deprecated?: string;
  removed?: string;
  /** Declarations: allowed-enrollments; profile payloads: derived from supervised and userenrollment.mode. */
  enrollments?: EnrollmentClass[];
  supervised?: boolean;
  userEnrollment?: 'allowed' | 'forbidden' | 'ignored';
  scopes?: Array<'system' | 'user'>;
}

/** The support of a key: only what differs from its type's (an absent field is the type's). */
export type KeyOsSupport = Partial<OsSupport>;

export type SchemaKeyType = 'string' | 'integer' | 'real' | 'boolean' | 'date' | 'data' | 'array' | 'dictionary' | 'any';

export interface SchemaKey {
  name: string;
  /** English title of the key (the editor translates it). */
  title?: string;
  type: SchemaKeyType;
  required?: boolean;
  /** Per-key support, when it differs from the type's. */
  os?: Partial<Record<AppleOs, KeyOsSupport>>;
  /** Dictionary: its keys ('ANY': any key, of the subkey's type); array: one subkey, the type of its elements. */
  subkeys?: SchemaKey[];
  rangelist?: JsonValue[];
  range?: { min?: number; max?: number };
  /** Regular expression a string matches. */
  format?: string;
  /** Declarations: key referencing an asset. */
  assetReference?: boolean;
}

export type SchemaFamily = 'declaration' | 'profile_payload' | 'command';

export interface SchemaEntry {
  /** Payload or declaration type; 'setting.<Item>' for an item of the Settings command. */
  type: string;
  family: SchemaFamily;
  title: string;
  os: Partial<Record<AppleOs, OsSupport>>;
  /** Declarations. */
  apply?: 'single' | 'multiple' | 'combined';
  /** Profile payloads. */
  multiple?: boolean;
  keys: SchemaKey[];
}

export interface AppleSchemaCatalog {
  release: { ref: string; commit: string; importedAt: string };
  entries: Record<string, SchemaEntry>;
}

/** The Apple OS of a platform of the registry (iOS and iPadOS share the iOS schema); null off Apple. */
export function appleOsOfPlatform(platform: Platform | string | null | undefined): AppleOs | null {
  switch (platform) {
    case 'ios':
    case 'ipados':
      return 'iOS';
    case 'macos': return 'macOS';
    case 'tvos': return 'tvOS';
    case 'visionos': return 'visionOS';
    default: return null;
  }
}

/** The key of a dictionary's subkeys by name ('ANY' stands for any name); undefined when unknown. */
export function subkeyNamed(keys: readonly SchemaKey[] | undefined, name: string): SchemaKey | undefined {
  if (!keys) return undefined;
  return keys.find((k) => k.name === name) ?? keys.find((k) => k.name === 'ANY');
}

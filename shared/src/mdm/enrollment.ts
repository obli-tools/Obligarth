// Enrollment as the console sees it (docs: integration-apple-edge §10.1, §10.3, §10.9): enrollment profiles and
// their settings by method, enrollment links (OTA) and invitations (account-driven), enrollment sessions. A
// token, a link or an invitation code is shown once, at its creation; the lists carry its displayable prefix
// only.
import type { Ownership } from './enums';

/** Methods of an enrollment profile (enrollment_profiles.method). */
export const ENROLLMENT_PROFILE_METHODS = ['ota', 'ade', 'byod_account'] as const;
export type EnrollmentProfileMethod = typeof ENROLLMENT_PROFILE_METHODS[number];

/** Ownerships an enrollment profile of a method may declare (enrollment_profiles_rules_check). */
export const ENROLLMENT_METHOD_OWNERSHIPS: Readonly<Record<EnrollmentProfileMethod, readonly Ownership[]>> = {
  ota: ['corporate'],
  ade: ['corporate', 'corporate_personal'],
  byod_account: ['personal'],
};

/** Locales of the enrollment pages and profiles. */
export const ENROLLMENT_LOCALES = ['fr', 'en'] as const;
export type EnrollmentLocale = typeof ENROLLMENT_LOCALES[number];

/** Bounds of the settings (integration §10.1). */
export const ENROLLMENT_LIMITS = Object.freeze({
  linkTtlHours: { min: 1, max: 720, default: 72 },
  // Single use by default (decision of 15/10, MDM-B2-R13): several uses stay an explicit choice.
  linkMaxUses: { min: 1, max: 1000, default: 1 },
  invitationTtlHours: { min: 1, max: 720, default: 168 },
});

/** Settings of a profile (enrollment_profiles.settings); the fields of its method only. */
export interface EnrollmentProfileSettings {
  deviceNameTemplate?: string;
  // ota
  linkTtlHours?: number;
  linkMaxUses?: number;
  // ade
  webAuth?: boolean;
  minOsVersion?: { ios?: string; ipados?: string };
  skipSetupItems?: string[];
  supportPhone?: string;
  supportEmail?: string;
  department?: string;
  language?: string;
  region?: string;
  mdmRemovable?: boolean;
  // byod_account
  invitationTtlHours?: number;
}

export interface EnrollmentProfileView {
  id: string;
  name: string;
  method: EnrollmentProfileMethod;
  ownership: Ownership;
  usage: string | null;
  defaultGroupId: number | null;
  defaultGroupName: string | null;
  noticeRequired: boolean;
  locale: string;
  settings: EnrollmentProfileSettings;
  isDefault: boolean;
  enabled: boolean;
  version: number;
  createdAt: string;
  updatedAt: string;
  archivedAt: string | null;
  /** Usable links and invitations of the profile. */
  activeTokens: number;
  /** ADE profiles: where the profile is defined at Apple, one entry per active ADE server of the tenant (lot C2). */
  adeBindings?: EnrollmentAdeBindingView[];
}

/** An ADE profile as defined at Apple on one ADE server (ade_profile_bindings; integration §10.6). */
export interface EnrollmentAdeBindingView {
  adeTokenId: string;
  serverName: string;
  /** Apple's profile UUID; null: never defined. */
  profileUuid: string | null;
  /** The version of the profile defined at Apple (null: never). */
  definedVersion: number | null;
  definedAt: string | null;
  /** The code of the last failure of the definition, null when it succeeded. */
  lastErrorCode: string | null;
  /** The version defined is the profile's current one. */
  upToDate: boolean;
}

/** What the console sends to create or change a profile (the method never changes). */
export interface EnrollmentProfileInput {
  name: string;
  method: EnrollmentProfileMethod;
  ownership: Ownership;
  usage?: string | null;
  defaultGroupId?: number | null;
  noticeRequired?: boolean;
  locale?: EnrollmentLocale;
  settings?: EnrollmentProfileSettings;
  isDefault?: boolean;
  enabled?: boolean;
}

export const ENROLLMENT_TOKEN_KINDS = ['link', 'invitation'] as const;
export type EnrollmentTokenKind = typeof ENROLLMENT_TOKEN_KINDS[number];

export const ENROLLMENT_TOKEN_STATES = ['active', 'exhausted', 'expired', 'revoked'] as const;
export type EnrollmentTokenState = typeof ENROLLMENT_TOKEN_STATES[number];

/** How the e-mail of a link or an invitation went: not asked (no recipient), no channel configured, sent, failed. */
export type EnrollmentMailOutcome = 'not_requested' | 'not_configured' | 'sent' | 'failed';

export interface EnrollmentTokenView {
  id: string;
  profileId: string;
  profileName: string;
  kind: EnrollmentTokenKind;
  prefix: string;
  label: string | null;
  /** Invitations: shown to the tenant's administrators only (null for the others). */
  managedAppleAccount: string | null;
  uses: number;
  maxUses: number;
  expiresAt: string;
  state: EnrollmentTokenState;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

/** The answer of a new link: the token and its URL are shown once. */
export interface EnrollmentLinkCreated {
  id: string;
  token: string;
  url: string;
  /** data:image/png;base64,… */
  qrPng: string;
  prefix: string;
  maxUses: number;
  expiresAt: string;
  mail: EnrollmentMailOutcome;
}

/** The answer of a new invitation: the code (xxxxx-xxxxx) is shown once; the link opens the instructions. */
export interface EnrollmentInvitationCreated {
  id: string;
  code: string;
  link: string;
  prefix: string;
  expiresAt: string;
  mail: EnrollmentMailOutcome;
}

export const ENROLLMENT_SESSION_STATES = ['started', 'acknowledged', 'profile_issued', 'certificate_issued', 'authenticated',
  'enrolled', 'failed', 'expired'] as const;
export type EnrollmentSessionState = typeof ENROLLMENT_SESSION_STATES[number];

export interface EnrollmentSessionView {
  id: string;
  profileId: string;
  profileName: string;
  tokenPrefix: string | null;
  method: EnrollmentProfileMethod;
  ownership: Ownership;
  state: EnrollmentSessionState;
  stateAt: string;
  failureCode: string | null;
  /** Shown to the tenant's administrators only (null for the others). */
  managedAppleAccount: string | null;
  /** ADE: the serial number of the verified MachineInfo (a company device); null otherwise. */
  serialNumber: string | null;
  deviceId: number | null;
  locale: string | null;
  acknowledgedAt: string | null;
  createdAt: string;
  expiresAt: string;
}

/** A device of Apple Business seen by the ADE synchronisation (apple_ade_devices; integration §10.6, §11.2). */
export interface AdeDeviceView {
  id: number;
  adeTokenId: string;
  serverName: string;
  serialNumber: string;
  model: string | null;
  description: string | null;
  deviceFamily: string | null;
  os: string | null;
  /** Apple's profile status: empty, assigned, pushed, removed. */
  profileStatus: string | null;
  profileAssignTime: string | null;
  /** The enrollment profile Apple's profile UUID corresponds to (null: none of ours, or not known). */
  appliedProfileId: string | null;
  appliedProfileName: string | null;
  /** The enrollment profile an operator chose; null: the tenant's default ADE profile. */
  wantedProfileId: string | null;
  wantedProfileName: string | null;
  /** The enrolled device, once it authenticated. */
  deviceId: number | null;
  firstSeenAt: string;
  removedAt: string | null;
}

export interface AdeDevicePage {
  items: AdeDeviceView[];
  nextCursor: string | null;
}

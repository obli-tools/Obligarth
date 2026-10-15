import { z } from 'zod';
import {
  ENROLLMENT_LIMITS, ENROLLMENT_LOCALES, ENROLLMENT_METHOD_OWNERSHIPS, ENROLLMENT_PROFILE_METHODS, OWNERSHIPS,
  type EnrollmentProfileMethod, type EnrollmentProfileSettings, type Ownership,
} from '@obligarth/shared';

// =============================================================================
// Settings of an enrollment profile, by method (docs: integration-apple-edge
// §10.1): validated by zod, unknown fields refused; the combinations of
// method, ownership, usage and notice that enrollment_profiles_rules_check
// refuses in the database are refused here first, with a code the console
// translates. The device name template takes {serial}, {model}, {n}, never a
// value of the employee.
// =============================================================================

const L = ENROLLMENT_LIMITS;
const int = (min: number, max: number) => z.number().int().min(min).max(max);
const text = (max: number) => z.string().trim().min(1).max(max);
const OS_VERSION = z.string().regex(/^[0-9]{1,2}(\.[0-9]{1,2}){0,2}$/);
/** Keys of the setup assistant the ADE API knows (skip_setup_items); letters only. */
const SETUP_ITEM = z.string().regex(/^[A-Za-z][A-Za-z0-9]{0,39}$/);
/** {serial}, {model}, {n} and printable text; no other variable. */
const NAME_TEMPLATE = z.string().trim().min(1).max(63)
  .refine((v) => !/[\u0000-\u001f\u007f]/.test(v), 'control characters')
  .refine((v) => (v.match(/\{[^}]*\}/g) ?? []).every((m) => ['{serial}', '{model}', '{n}'].includes(m)), 'unknown variable');

/** The ADE usage key (apple-edge §7.4): what the database accepts. */
export const USAGE_RE = /^[a-z][a-z0-9_]{0,31}$/;

export const SETTINGS_SCHEMAS: Readonly<Record<EnrollmentProfileMethod, z.ZodType<EnrollmentProfileSettings>>> = {
  ota: z.object({
    deviceNameTemplate: NAME_TEMPLATE.optional(),
    linkTtlHours: int(L.linkTtlHours.min, L.linkTtlHours.max).optional(),
    linkMaxUses: int(L.linkMaxUses.min, L.linkMaxUses.max).optional(),
  }).strict(),
  ade: z.object({
    deviceNameTemplate: NAME_TEMPLATE.optional(),
    webAuth: z.boolean().optional(),
    minOsVersion: z.object({ ios: OS_VERSION.optional(), ipados: OS_VERSION.optional() }).strict().optional(),
    skipSetupItems: z.array(SETUP_ITEM).max(60).optional(),
    supportPhone: text(40).optional(),
    supportEmail: z.string().trim().email().max(320).optional(),
    department: text(100).optional(),
    language: z.string().regex(/^[a-z]{2}$/).optional(),
    region: z.string().regex(/^[A-Z]{2}$/).optional(),
    mdmRemovable: z.boolean().optional(),
  }).strict(),
  byod_account: z.object({
    deviceNameTemplate: NAME_TEMPLATE.optional(),
    invitationTtlHours: int(L.invitationTtlHours.min, L.invitationTtlHours.max).optional(),
  }).strict(),
};

/** The setup assistant items skipped by default (ADE). */
export const DEFAULT_SKIP_SETUP_ITEMS = ['Location', 'Siri', 'Privacy', 'Diagnostics', 'ScreenTime', 'Appearance', 'iMessageAndFaceTime'];

/** The body of a new profile or of a change (the method is fixed at creation). */
export const ProfileBody = z.object({
  name: text(200),
  method: z.enum(ENROLLMENT_PROFILE_METHODS),
  ownership: z.enum(OWNERSHIPS),
  usage: z.string().regex(USAGE_RE).nullable().optional(),
  defaultGroupId: z.number().int().positive().nullable().optional(),
  noticeRequired: z.boolean().optional(),
  locale: z.enum(ENROLLMENT_LOCALES).optional(),
  settings: z.record(z.unknown()).optional(),
  isDefault: z.boolean().optional(),
  enabled: z.boolean().optional(),
}).strict();
export type ProfileBodyInput = z.infer<typeof ProfileBody>;

export class ProfileRuleError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = 'ProfileRuleError';
  }
}

export interface CheckedProfile {
  name: string;
  method: EnrollmentProfileMethod;
  ownership: Ownership;
  usage: string | null;
  defaultGroupId: number | null;
  noticeRequired: boolean;
  locale: string;
  settings: EnrollmentProfileSettings;
  isDefault: boolean;
  enabled: boolean;
}

/**
 * The rules of a profile (§10.1, enrollment_profiles_rules_check): ownership chosen before the enrollment
 * (REQ-01), personal by account only, no OTA COPE, an ADE usage key for ADE only, a notice turned off on an
 * ADE profile only (kiosks), the web view mandatory when the notice is, a removable MDM never on a corporate
 * device. Throws ProfileRuleError.
 */
export function checkProfile(b: ProfileBodyInput): CheckedProfile {
  const method = b.method;
  if (!ENROLLMENT_METHOD_OWNERSHIPS[method].includes(b.ownership)) {
    throw new ProfileRuleError('ownershipNotAllowed', `The ownership ${b.ownership} is not allowed for the method ${method}`);
  }
  const usage = method === 'ade' ? (b.usage ?? null) : null;
  if (method === 'ade' && !usage) throw new ProfileRuleError('usageRequired', 'An ADE profile needs a usage key');
  if (method !== 'ade' && b.usage) throw new ProfileRuleError('usageNotAllowed', 'Only an ADE profile has a usage key');
  const noticeRequired = b.noticeRequired ?? true;
  if (!noticeRequired && method !== 'ade') throw new ProfileRuleError('noticeRequired', 'The notice can be turned off on an ADE profile only');
  if (b.isDefault && method !== 'ade') throw new ProfileRuleError('defaultNotAde', 'Only an ADE profile can be the default one');
  const parsed = SETTINGS_SCHEMAS[method].safeParse(b.settings ?? {});
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new ProfileRuleError('invalidSettings', `Invalid setting ${issue?.path.join('.') || ''}: ${issue?.message ?? 'refused'}`.trim());
  }
  const settings = parsed.data;
  if (method === 'ade') {
    if (noticeRequired && settings.webAuth === false) {
      throw new ProfileRuleError('webAuthRequired', 'The notice of an ADE profile is shown in the web view: keep it on');
    }
    if (settings.mdmRemovable === true && b.ownership !== 'personal') {
      throw new ProfileRuleError('mdmRemovableCorporate', 'The management profile of a corporate device cannot be removable');
    }
  }
  return {
    name: b.name,
    method,
    ownership: b.ownership,
    usage,
    defaultGroupId: b.defaultGroupId ?? null,
    noticeRequired,
    locale: b.locale ?? 'fr',
    settings,
    isDefault: method === 'ade' ? (b.isDefault ?? false) : false,
    enabled: b.enabled ?? true,
  };
}

/** The link settings of an OTA profile, defaults applied. */
export function linkDefaults(settings: EnrollmentProfileSettings): { ttlHours: number; maxUses: number } {
  return { ttlHours: settings.linkTtlHours ?? L.linkTtlHours.default, maxUses: settings.linkMaxUses ?? L.linkMaxUses.default };
}

/** The invitation lifetime of a BYOD profile, default applied. */
export const invitationTtlOf = (settings: EnrollmentProfileSettings): number => settings.invitationTtlHours ?? L.invitationTtlHours.default;

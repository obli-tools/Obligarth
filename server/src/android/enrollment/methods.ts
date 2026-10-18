// Rules of the Android enrollment (sections 10.1, 10.4, 10.6, 22.2, 22.3; AN17, AN25), pure: the methods and the
// mode they give, the plan of a token (kind, duration, single use, allowPersonalUsage, approval by default), the
// snapshot of a profile frozen in a token, the checks of an enrolled Device against that snapshot (never against the
// current profile), the additionalData of a token, the approval of a long token, the hourly caps, the payload shown
// to the administrator. No database, no logger: the unit tests load it (U-A09).
import { androidProvisioningExtras } from '@obligarth/shared/dist/android/enrollment.js';

export const ANDROID_METHODS = [
  'android_qr', 'android_token', 'android_afw', 'android_nfc', 'android_zero_touch', 'android_kme',
  'android_byod_link', 'android_signin_url',
] as const;
export type AndroidMethod = (typeof ANDROID_METHODS)[number];

export type AndroidOwnership = 'corporate' | 'corporate_personal' | 'personal';
export type AndroidModeName = 'fully_managed' | 'dedicated' | 'work_profile_corporate' | 'work_profile_personal';
export type AndroidUsage = 'standard' | 'kiosk';
export type AndroidTokenKind = 'qr' | 'byod_link' | 'zero_touch' | 'kme' | 'signin';
export type AllowPersonalUsage = 'PERSONAL_USAGE_ALLOWED' | 'PERSONAL_USAGE_DISALLOWED' | 'PERSONAL_USAGE_DISALLOWED_USERLESS';

export const isAndroidMethod = (m: unknown): m is AndroidMethod => typeof m === 'string' && (ANDROID_METHODS as readonly string[]).includes(m);

const HOUR = 3_600;
const DAY = 86_400;
export const TOKEN_DURATIONS = {
  /** QR, typed token, afw#setup (fully managed, COPE): 1 h, up to 24 h (AN17). */
  short: { dflt: HOUR, max: DAY },
  /** Kiosk, zero-touch, KME: one year, several uses, revocable. */
  long: { dflt: 365 * DAY, max: 365 * DAY },
  /** BYOD link (invitation): 7 days, single use. */
  byod: { dflt: 7 * DAY, max: 7 * DAY },
  /** Sign-in URL: 15 minutes, single use (§22.3). */
  signin: { dflt: 15 * 60, max: 15 * 60 },
} as const;

/** The management mode of a profile (section 10.1). */
export function modeOf(ownership: AndroidOwnership, usage: AndroidUsage): AndroidModeName {
  if (ownership === 'personal') return 'work_profile_personal';
  if (ownership === 'corporate_personal') return 'work_profile_corporate';
  return usage === 'kiosk' ? 'dedicated' : 'fully_managed';
}

/** The enrollment_type of a device enrolled by a method (devices_enrollment_type_check widened at part 3b). */
export const enrollmentTypeOf = (method: AndroidMethod): string => method;

/** What a profile freezes in its tokens (SEC-AN-2): the enrollment handler compares the device to it. */
export interface ProfileSnapshot {
  profileId: string;
  method: AndroidMethod;
  ownership: AndroidOwnership;
  mode: AndroidModeName;
  usage: AndroidUsage;
  defaultGroupId: number | null;
  minimumApiLevel: number | null;
}

export interface TokenPlan {
  kind: AndroidTokenKind;
  oneTime: boolean;
  durationSeconds: number;
  allowPersonalUsage: AllowPersonalUsage;
  /** Approval of new devices by default (AN17): zero-touch, KME and the kiosk; the profile may turn it off. */
  approvalByDefault: boolean;
  /** 'long': several uses for a year (rotation, hourly cap). */
  long: boolean;
}

export class EnrollmentRuleError extends Error {
  readonly code: string;
  constructor(code: string, message = code) {
    super(message);
    this.name = 'EnrollmentRuleError';
    this.code = code;
  }
}

/**
 * The plan of a token for a profile (section 10.1, AN17). `expiresInSeconds` shortens a duration, never lengthens it
 * beyond its maximum (a single-use QR goes up to 24 h). EnrollmentRuleError for a method without a token in v1
 * (sign-in tokens are created by the sign-in flow, AN-F2) or an unknown combination.
 */
export function tokenPlan(s: Pick<ProfileSnapshot, 'method' | 'ownership' | 'usage'>, expiresInSeconds?: number): TokenPlan {
  const kiosk = s.usage === 'kiosk';
  const personalUse: AllowPersonalUsage = s.ownership === 'corporate_personal' || s.ownership === 'personal'
    ? 'PERSONAL_USAGE_ALLOWED' : kiosk ? 'PERSONAL_USAGE_DISALLOWED_USERLESS' : 'PERSONAL_USAGE_DISALLOWED';
  let plan: TokenPlan;
  let bounds: { dflt: number; max: number };
  switch (s.method) {
    case 'android_qr': case 'android_token': case 'android_afw': case 'android_nfc':
      if (s.ownership === 'personal') throw new EnrollmentRuleError('androidMethodOwnership');
      bounds = kiosk ? TOKEN_DURATIONS.long : TOKEN_DURATIONS.short;
      plan = { kind: 'qr', oneTime: !kiosk, durationSeconds: 0, allowPersonalUsage: personalUse, approvalByDefault: kiosk, long: kiosk };
      break;
    case 'android_zero_touch': case 'android_kme':
      if (s.ownership === 'personal') throw new EnrollmentRuleError('androidMethodOwnership');
      bounds = TOKEN_DURATIONS.long;
      plan = { kind: s.method === 'android_kme' ? 'kme' : 'zero_touch', oneTime: false, durationSeconds: 0,
        allowPersonalUsage: personalUse, approvalByDefault: true, long: true };
      break;
    case 'android_byod_link':
      if (s.ownership !== 'personal') throw new EnrollmentRuleError('androidMethodOwnership');
      bounds = TOKEN_DURATIONS.byod;
      plan = { kind: 'byod_link', oneTime: true, durationSeconds: 0, allowPersonalUsage: 'PERSONAL_USAGE_ALLOWED', approvalByDefault: false, long: false };
      break;
    case 'android_signin_url':
      // A kiosk is a device without user (USERLESS): nobody signs in (lot AN-G1).
      if (kiosk) throw new EnrollmentRuleError('androidKioskMethod');
      bounds = TOKEN_DURATIONS.signin;
      plan = { kind: 'signin', oneTime: true, durationSeconds: 0, allowPersonalUsage: personalUse, approvalByDefault: false, long: false };
      break;
    default:
      throw new EnrollmentRuleError('androidUnknownMethod');
  }
  let seconds = bounds.dflt;
  if (expiresInSeconds !== undefined) {
    if (!Number.isInteger(expiresInSeconds) || expiresInSeconds < 60) throw new EnrollmentRuleError('androidInvalidDuration');
    seconds = Math.min(expiresInSeconds, bounds.max);
  }
  plan.durationSeconds = seconds;
  return plan;
}

// ── additionalData ─────────────────────────────────────────────────────────

const TOKEN_DATA_RE = /^obg1:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
export const tokenData = (id: string): string => `obg1:${id}`;
/** The token id carried by Device.enrollmentTokenData, or null (a token created outside Obligarth). */
export function tokenIdOf(data: unknown): string | null {
  if (typeof data !== 'string') return null;
  return TOKEN_DATA_RE.exec(data)?.[1] ?? null;
}

// ── checks of an enrolled device ──────────────────────────────────────────

export type SnapshotMismatch = 'ownership_mismatch' | 'mode_mismatch' | 'api_too_low';

export interface EnrolledDeviceFacts {
  ownership?: string;
  managementMode?: string;
  apiLevel?: number;
}

/**
 * The device against the snapshot of its token (section 10.4 step 4): PERSONALLY_OWNED ⇔ personal; PROFILE_OWNER ⇔
 * a work profile mode; apiLevel ≥ the frozen minimum (an API level absent while a minimum is set: refused, fail
 * closed). null: consistent.
 */
export function checkAgainstSnapshot(d: EnrolledDeviceFacts, s: ProfileSnapshot): SnapshotMismatch | null {
  const personalDevice = d.ownership === 'PERSONALLY_OWNED';
  if (d.ownership !== 'PERSONALLY_OWNED' && d.ownership !== 'COMPANY_OWNED') return 'ownership_mismatch';
  if (personalDevice !== (s.ownership === 'personal')) return 'ownership_mismatch';
  const profileOwner = d.managementMode === 'PROFILE_OWNER';
  if (d.managementMode !== 'PROFILE_OWNER' && d.managementMode !== 'DEVICE_OWNER') return 'mode_mismatch';
  if (profileOwner !== (s.mode === 'work_profile_corporate' || s.mode === 'work_profile_personal')) return 'mode_mismatch';
  if (s.minimumApiLevel !== null) {
    if (typeof d.apiLevel !== 'number' || !Number.isInteger(d.apiLevel) || d.apiLevel < s.minimumApiLevel) return 'api_too_low';
  }
  return null;
}

/** The time of the enrollment as Google reports it, or null when unreadable. */
export function enrollmentTimeOf(v: unknown): Date | null {
  if (typeof v !== 'string') return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? new Date(t) : null;
}

/** Was the token usable at `at` (section 10.4 step 3)? Revoked or expired before the enrollment: unknown token. */
export function tokenValidAt(t: { revoked_at: Date | null; expires_at: Date; created_at: Date }, at: Date): boolean {
  if (t.revoked_at && new Date(t.revoked_at).getTime() <= at.getTime()) return false;
  if (new Date(t.expires_at).getTime() < at.getTime()) return false;
  // Two minutes of tolerance for the clocks of Google and of the instance.
  if (new Date(t.created_at).getTime() > at.getTime() + 120_000) return false;
  return true;
}

// ── automatic rejection (the narrow window of step 4) ─────────────────────

export const REJECT_WINDOW_MS = 30 * 60_000;

/** May the instance delete (reject) the device rather than quarantine it? All the conditions of step 4 must hold. */
export function rejectAllowed(o: { hasRecord: boolean; enrollmentTime: Date | null; state: string | undefined; ownership: string | undefined;
  capReached: boolean; now: Date }): boolean {
  return !o.hasRecord && o.enrollmentTime !== null && o.now.getTime() - o.enrollmentTime.getTime() < REJECT_WINDOW_MS
    && o.enrollmentTime.getTime() <= o.now.getTime() + 120_000
    && o.state === 'PROVISIONING' && o.ownership === 'COMPANY_OWNED' && !o.capReached;
}

/** Per tenant and per hour, automatic rejections and quarantines together: 5, or 10 % of the tenant's Android devices. */
export const decisionCap = (androidDevices: number): number => Math.max(5, Math.floor(androidDevices / 10));

/** Enrollments per hour and per long token beyond which the approval is forced (AN17, platform setting, 50). */
export const LONG_TOKEN_HOURLY_CAP = 50;
/** Enrollments per hour on one long token that raise android.enrollment_spike (section 10.3). */
export const SPIKE_PER_HOUR = 20;

// ── approval ──────────────────────────────────────────────────────────────

export const normaliseSerial = (s: unknown): string | null => {
  if (typeof s !== 'string') return null;
  const v = s.trim().toUpperCase();
  return /^[A-Z0-9._-]{1,64}$/.test(v) ? v : null;
};

/** A device enrolled by a token that requires an approval stays pending unless its serial is in the list. */
export function needsApproval(requiresApproval: boolean, serial: string | null, approvedSerials: readonly string[]): boolean {
  if (!requiresApproval) return false;
  const s = normaliseSerial(serial);
  if (!s) return true;
  return !approvedSerials.map(normaliseSerial).includes(s);
}

// ── payload shown to the administrator (section 10.2 step 4) ──────────────

export type TokenPayload =
  | { form: 'qr'; qrCode: string; value: string }
  | { form: 'link'; url: string }
  | { form: 'kme'; json: string }
  | { form: 'zero_touch'; dpcExtras: string }
  | { form: 'signin'; url: string };

export const ENROLL_URL = 'https://enterprise.google.com/android/enroll';

/** The payload of a token (never logged): QR content and typed value (afw#setup), link, KME JSON, zero-touch extras. */
export function tokenPayload(kind: AndroidTokenKind, value: string, qrCode: string | undefined): TokenPayload {
  const extras = androidProvisioningExtras(value);
  switch (kind) {
    case 'qr': return { form: 'qr', qrCode: qrCode ?? '', value };
    case 'byod_link': return { form: 'link', url: `${ENROLL_URL}?et=${encodeURIComponent(value)}` };
    case 'kme': return { form: 'kme', json: extras };
    case 'zero_touch': return { form: 'zero_touch', dpcExtras: extras };
    default: return { form: 'signin', url: `${ENROLL_URL}?et=${encodeURIComponent(value)}` };
  }
}

/** A neutral, translated message shown on a disabled device (never a reason that names a person or a rule). */
export const DISABLED_MESSAGES = {
  quarantine: {
    defaultMessage: 'This device is waiting for a decision of your IT administrator.',
    localizedMessages: { fr: 'Cet appareil attend une décision de votre administrateur informatique.' },
  },
  approval: {
    defaultMessage: 'This device is waiting for the approval of your IT administrator.',
    localizedMessages: { fr: 'Cet appareil attend l’approbation de votre administrateur informatique.' },
  },
} as const;

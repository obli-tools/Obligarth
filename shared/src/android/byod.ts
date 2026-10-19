// =============================================================================
// BYOD Android by link (android-amapi §10.1, §10.5, criterion 6; lot AN-F1), shared by the server and the console:
// the invitation of an end user (single use, 7 days at most, a code shown once to the administrator and a link to the
// notice page of the device surface), its states and its view in the console. Exported by the index of
// shared (junction AN-A2).
// =============================================================================

/** Lifetime of an invitation (AN17: the BYOD link, 7 days, single use): default and bounds, in hours. */
export const ANDROID_BYOD_INVITATION_TTL_HOURS = { dflt: 168, min: 1, max: 168 } as const;

/**
 * States of an invitation:
 *   active    the code serves; nothing handed to the device yet;
 *   issuing   the notice acknowledged, the enrollment token being created at Google (a few seconds);
 *   issued    the token created, the Google link handed to the device (the same code gives the same link again while
 *             the token is active);
 *   used      a device enrolled with its token (the code serves no more);
 *   revoked   revoked by the administrator (its token revoked at Google);
 *   expired   past its end without enrollment.
 */
export const ANDROID_BYOD_INVITATION_STATES = ['active', 'issuing', 'issued', 'used', 'revoked', 'expired'] as const;
export type AndroidByodInvitationState = typeof ANDROID_BYOD_INVITATION_STATES[number];

/** Wrong codes per tenant and per hour beyond which the device surface refuses every code of the tenant until the
 *  hour ends (alert android.byod_code_flood): a code of 10 characters of 32 (50 bits) is never guessed below that.
 *  200 since the decision of the owners of 19/10/2026 on F1R-4 (20 let two addresses block the tenant every hour). */
export const ANDROID_BYOD_WRONG_CODES_PER_HOUR = 200;

/** Wrong codes per address and per hour beyond which the device surface refuses every code from this address until
 *  the hour ends; checked first, before the count of the tenant (decision of 19/10/2026 on F1R-4). */
export const ANDROID_BYOD_WRONG_CODES_PER_ADDRESS_HOUR = 10;

/** POST /api/android/byod/invitations */
export interface AndroidByodInvitationRequest {
  profileId: string;
  endUserId: number;
  label?: string;
  ttlHours?: number;
  locale?: 'fr' | 'en';
  /** A recipient: the code and the link are e-mailed when a channel is configured (never stored). */
  email?: string;
}

export type AndroidByodMailOutcome = 'sent' | 'not_configured' | 'failed' | 'not_requested';

/** The answer of the creation: the code is shown once (stored hashed), the link carries no secret. */
export interface AndroidByodInvitationCreated {
  id: string;
  code: string;
  prefix: string;
  link: string;
  expiresAt: string;
  mail: AndroidByodMailOutcome;
}

/** An invitation in the console (never the code). */
export interface AndroidByodInvitationView {
  id: string;
  profileId: string;
  endUserId: number | null;
  prefix: string;
  label: string | null;
  state: AndroidByodInvitationState;
  expiresAt: string;
  acknowledgedAt: string | null;
  noticeVersionId: string | null;
  deviceId: number | null;
  createdAt: string;
  revokedAt: string | null;
  usedAt: string | null;
}

// =============================================================================
// Android enrollment flows of lot AN-F2 (android-amapi §10.1, §10.5, §22.3; AN17, AN18, AN25), shared by the server
// and the console: the zero-touch iframe (webTokens ZERO_TOUCH_CUSTOMER_MANAGEMENT, the long token in dpcExtras), the
// custom JSON of Samsung Knox Mobile Enrollment (the enrollment token and nothing else), the sign-in URL of the
// enterprise (signinDetails) and the states of a sign-in session of the device surface (provisioningInfo read for the
// tenant's enterprise, the user authenticated by Obligate, a single-use token of 15 minutes). Imported by direct path
// until the shared index exports it (junction AN-A2).
// =============================================================================

/** Package of Android Device Policy, the DPC of every AMAPI enrollment (zero-touch dpcId, Knox EMM agent). */
export const ANDROID_DPC_PACKAGE = 'com.google.android.apps.work.clouddpc';

/** The only key of the provisioning extras the instance ever hands out (zero-touch dpcExtras, KME custom JSON). */
export const ANDROID_ENROLLMENT_TOKEN_EXTRA = 'com.google.android.apps.work.clouddpc.EXTRA_ENROLLMENT_TOKEN';

/** The provisioning extras of an enrollment token: one key, the token; never a Wi-Fi password, an account nor another
 *  extra (a custom JSON is copied out of Obligarth into the Knox portal or the zero-touch configuration). */
export function androidProvisioningExtras(tokenValue: string): string {
  return JSON.stringify({ [ANDROID_ENROLLMENT_TOKEN_EXTRA]: tokenValue });
}

// ── Zero-touch ────────────────────────────────────────────────────────────────

/** The console page that hosts the zero-touch iframe (parentFrameUrl = the console's public origin + this path). */
export const ANDROID_ZERO_TOUCH_PAGE = '/enrollment/android/zero-touch';
/** The one feature of a zero-touch web token: never empty (Google would open every feature), never mixed with Play. */
export const ANDROID_ZERO_TOUCH_FEATURES = ['ZERO_TOUCH_CUSTOMER_MANAGEMENT'] as const;
export const ANDROID_ZERO_TOUCH_IFRAME_BASE = 'https://enterprise.google.com/android/zero-touch/embedded/companyhome';

/** URL of the zero-touch iframe (§10.5): the web token, the DPC and the extras of the long zero-touch token. Never
 *  stored nor logged: it carries the value of a long token. */
export function androidZeroTouchIframeUrl(webToken: string, dpcExtras: string): string {
  const q = new URLSearchParams({ token: webToken, dpcId: ANDROID_DPC_PACKAGE, dpcExtras });
  return `${ANDROID_ZERO_TOUCH_IFRAME_BASE}?${q.toString()}`;
}

/** POST /api/android/zero-touch/iframe-token */
export interface AndroidZeroTouchIframeRequest {
  /** The active zero-touch token (kind zero_touch) whose extras the default configuration will carry. */
  tokenId: string;
  locale?: string;
}

export interface AndroidZeroTouchIframe {
  iframeUrl: string;
  parentFrameUrl: string;
  tokenId: string;
  requiresApproval: boolean;
  /** Translation keys of the warnings the console shows (unlinking the account removes the configuration from every
   *  device; a token without approval enrolls any device that receives it). */
  warnings: string[];
}

// ── Knox Mobile Enrollment ───────────────────────────────────────────────────

/** GET /api/android/enrollment-tokens/:id/kme */
export interface AndroidKmeConfiguration {
  tokenId: string;
  /** Profile type to choose in the Knox Admin Portal. */
  profileType: 'android_enterprise';
  /** EMM agent of the Knox profile. */
  dpcPackage: typeof ANDROID_DPC_PACKAGE;
  /** The custom JSON data of the Knox profile: the enrollment token only. */
  customJson: string;
  expiresAt: string;
  requiresApproval: boolean;
  warnings: string[];
}

// ── Sign-in URL ──────────────────────────────────────────────────────────────

/** Life of a sign-in session of the device surface and of the token it creates (§22.3: single use, 15 minutes). */
export const ANDROID_SIGNIN_TTL_SECONDS = 15 * 60;
/** Where Google expects the device to be sent when the sign-in fails (§10.5). */
export const ANDROID_SIGNIN_INVALID_URL = 'https://enterprise.google.com/android/enroll/invalid';

/**
 * States of a sign-in session (android_signin_sessions):
 *   notice         a personal device: the notice of a personal device is shown before anything else (USR-01);
 *   pending        sent to Obligate, the state of the authorization request waits for its answer;
 *   exchanging     the answer of Obligate arrived, its code is being exchanged (single use: a replay finds this state);
 *   authenticated  the user is an active end user of the tenant; the token is being created;
 *   issued         the token created, the device sent to Google's enrollment page;
 *   used           a device enrolled with the token;
 *   failed         refused (the device was sent to the invalid page); expired: past its end.
 */
export const ANDROID_SIGNIN_STATES = ['notice', 'pending', 'exchanging', 'authenticated', 'issued', 'used', 'failed', 'expired'] as const;
export type AndroidSigninState = typeof ANDROID_SIGNIN_STATES[number];

export const ANDROID_SIGNIN_PERSONAL_USAGE = ['PERSONAL_USAGE_ALLOWED', 'PERSONAL_USAGE_DISALLOWED'] as const;
export type AndroidSigninPersonalUsage = typeof ANDROID_SIGNIN_PERSONAL_USAGE[number];

/** PUT /api/android/enterprise/signin */
export interface AndroidSigninConfigRequest {
  enabled: boolean;
  /** What the devices of the sign-in flow may be: PERSONAL_USAGE_ALLOWED (a work profile, company or personal device),
   *  PERSONAL_USAGE_DISALLOWED (fully managed company devices). Never USERLESS: nobody signs in on a kiosk. */
  allowPersonalUsage?: AndroidSigninPersonalUsage;
}

/** The sign-in configuration of the enterprise as the instance keeps it (android_enterprises.signin): never the
 *  enrollment token nor the QR code Google adds to a SigninDetail. */
export interface AndroidSigninConfig {
  enabled: boolean;
  signinUrl: string | null;
  allowPersonalUsage: AndroidSigninPersonalUsage | null;
  configuredAt: string | null;
}

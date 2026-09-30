// Device-bound 2FA ("validation liée à l'appareil") — shared contract.
//
// docs/mobile/device-bound-2fa.md §13.1 (FROZEN): header, proof fields,
// responses (§4.8), endpoints and JSON (§6.5), web bridge (§7.6). Any change
// of these shapes goes through `v: 2` — a peer ignores a `v` it does not know
// and falls back to the code.

/** Request header carrying the app's key id (§4.7). Never sent by the web. */
export const DEVICE_KEY_HEADER = 'X-Obli-Device-Key';

/** First line of the signed payload (§4.4). */
export const DEVICE_KEY_PAYLOAD_VERSION = 'obli-devkey-v1';
/** First line of the request-binding preimage (§4.5). Server-side only:
 *  the app copies the binding, it never computes it. v2 keys the body digest
 *  with a server secret (HMAC) instead of a plain sha256. */
export const DEVICE_KEY_BINDING_VERSION = 'obli-binding-v2';

/** [D16] challenge / enrolment ticket lifetimes, seconds. */
export const DEVICE_KEY_CHALLENGE_TTL_SECONDS = 120;
export const DEVICE_KEY_ENROL_TTL_SECONDS = 180;
/** [D14] at most 5 active keys per user; revoked after 180 days unused. */
export const DEVICE_KEY_MAX_PER_USER = 5;
export const DEVICE_KEY_STALE_DAYS = 180;
/** Bulk step-up (§4.9.4): 1..50 challenges issued within 60 s. */
export const DEVICE_KEY_MAX_BULK = 50;
export const DEVICE_KEY_BULK_SPREAD_SECONDS = 60;

/** Default accepted app package (DEVICE_KEY_APP_IDS). */
export const DEVICE_KEY_DEFAULT_APP_ID = 'tools.obli.obligarth.next';

export type DeviceKeyPurpose = 'enrol' | 'login' | 'stepup';
export type DeviceKeySecurityLevel = 'strongbox' | 'tee' | 'unverified';
/** `deviceKeyStatus` of a 401 (§4.8). 'revoked' only with "Authentication required". */
export type DeviceKeyStatus = 'active' | 'disabled' | 'throttled' | 'revoked';
/** `deviceError` of a 401 (§4.8). */
export type DeviceKeyError = 'challenge_expired' | 'invalid_assertion';

export type DeviceKeyRevokeReason =
  | 'user' | 'logout' | 'admin' | 'password_change' | 'password_reset'
  | 'totp_changed' | 'totp_disabled' | 'totp_reset' | 'user_disabled'
  | 'credentials_changed' | 'sso_mfa_changed' | 'replaced' | 'invalidated'
  | 'stale' | 'policy'
  /** A certificate of the key's attestation chain was later marked REVOKED /
   *  SUSPENDED in Google's status list (leaked keybox, §3 [D4]). */
  | 'attestation_revoked';

/** A challenge, in a step-up 401, the login response or device-challenge (§4.8). */
export interface DeviceChallenge {
  v: 1;
  keyId: string;
  challengeId: string;
  purpose: 'stepup' | 'login';
  userId: number;
  /** Binding tenant; null for a login. Covered by `binding`. */
  tenantId: number | null;
  /** Display only (never trusted). Absent for a login. */
  tenantName?: string | null;
  /** base64url (no padding) of 32 bytes. */
  nonce: string;
  /** Action key, '-' for a login. */
  action: string;
  /** hex sha256 request binding, '-' for a login. The app copies it. */
  binding: string;
  /** Unix seconds (database clock). */
  expiresAt: number;
  bulkId: string | null;
}

/** Sent as a body field next to where `twoFactorCode` goes today (§4.8). */
export interface DeviceAssertion {
  v: 1;
  keyId: string;
  /** 1..50 unique challenge ids, in payload order. */
  challengeIds: string[];
  /** base64 (standard) DER ECDSA signature, <= 200 characters. */
  signature: string;
}

/** Proof fields (§13.1 item 2): removed from the body by the server
 *  (captureStepUpProof) and excluded from the request binding. */
export interface StepUpProof {
  twoFactorCode?: string;
  trustIp?: boolean;
  stepUpPassword?: string;
  deviceAssertion?: DeviceAssertion;
  deviceBulkId?: string;
}

/** Optional fields a step-up 401 may carry (§4.8); old clients ignore them. */
export interface StepUpRequiredBody {
  error: 'twoFactorCode required';
  twoFactorRequired: true;
  action: string;
  currentIp?: string;
  trustIpAllowed?: boolean;
  codeRequiresPassword?: boolean;
  codeRequiresReauth?: boolean;
  codeMustBeNew?: boolean;
  deviceKeyStatus?: Exclude<DeviceKeyStatus, 'revoked'>;
  deviceChallenge?: DeviceChallenge;
  deviceError?: DeviceKeyError;
}

export interface DeviceKeyPolicy {
  enabled: boolean;
  loginEnabled: boolean;
  requireAttestation: boolean;
  strictSession: boolean;
  originConfigured: boolean;
  ssoSupported: boolean;
}

/** A key as listed to its owner or an administrator (active keys only). */
export interface DeviceKeyInfo {
  id: string;
  label: string | null;
  platform: string;
  securityLevel: DeviceKeySecurityLevel;
  osPatchLevel: number | null;
  createdAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  useCount: number;
  /** True for the key bound to the caller's session. */
  current: boolean;
}

/** `eligibility.reason` of GET /api/profile/device-keys: why this account
 *  cannot enrol a phone right now (same codes as enrol/begin's 403s, plus
 *  `no_totp` for the "enable TOTP" 403). */
export type DeviceKeyEligibilityReason =
  | 'device_keys_disabled' | 'device_keys_origin_unset' | 'device_keys_sso_unsupported'
  | 'no_totp' | 'enrol_locked';

/** GET /api/profile/device-keys → data (§6.5). A 404 means "old server". */
export interface DeviceKeyListResponse {
  policy: DeviceKeyPolicy;
  allowedOrigins: string[];
  boundKeyId: string | null;
  eligibility: { ok: boolean; reason?: DeviceKeyEligibilityReason };
  keys: DeviceKeyInfo[];
  /** Platform admins only: lot O state for the Settings page. */
  ssoStatus?: DeviceKeysSsoStatus;
}

/**
 * Lot O (phone validation for Obligate accounts), as this server sees it:
 *  - 'switch_off'  DEVICE_KEYS_SSO_ENABLED is not set here (Obligate not asked);
 *  - 'sso_off'     Obligate SSO disabled or not configured;
 *  - 'announced'   Obligate announces the capabilities: open to SSO accounts;
 *  - 'withdrawn'   Obligate answered 2xx without them (OAUTH_LOT_O_CAPABILITIES=false):
 *                  closed, bound phones fall back to the code;
 *  - 'unreachable' Obligate did not answer usably — an Obligate older than
 *                  0.1.67 (no capabilities route: its SPA page) included:
 *                  closed, fail closed (bound phones blocked until it answers).
 */
export interface DeviceKeysSsoStatus {
  switchOn: boolean;
  state: 'switch_off' | 'sso_off' | 'announced' | 'withdrawn' | 'unreachable';
}

/** Platform settings of the feature (app_config, [D15]); values 'true' / 'false'. */
export const DEVICE_KEY_SETTING_KEYS = [
  'device_keys_enabled', 'device_keys_login', 'device_keys_require_attestation', 'device_keys_strict_session',
] as const;
export type DeviceKeySettingKey = typeof DEVICE_KEY_SETTING_KEYS[number];

/** POST /api/profile/device-keys/enrol/begin → data. */
export interface DeviceKeyEnrolBeginResponse {
  ticketId: string;
  /** base64url (no padding), 32 bytes: setAttestationChallenge + payload nonce. */
  nonce: string;
  expiresAt: number;
  userId: number;
  allowedOrigins: string[];
  requireAttestation: boolean;
}

/** POST /api/profile/device-keys/enrol/finish body. */
export interface DeviceKeyEnrolFinishRequest {
  ticketId: string;
  origin: string;
  /** SubjectPublicKeyInfo DER, base64. */
  publicKey: string;
  /** KeyStore.getCertificateChain(alias), leaf first, base64 DER. */
  attestation: string[];
  /** base64 DER signature of the enrolment payload. */
  signature: string;
  label: string;
  installId: string;
  appVersion: string;
}

/** POST /api/profile/device-keys/enrol/finish → 201 data. */
export interface DeviceKeyEnrolFinishResponse {
  keyId: string;
  label: string | null;
  securityLevel: DeviceKeySecurityLevel;
  createdAt: string;
}

/** `error` of the enrolment endpoints (§6.5, §4.8 mapping table). */
export type DeviceKeyEnrolError =
  | 'device_keys_disabled' | 'device_keys_origin_unset' | 'device_keys_sso_unsupported' | 'enrol_locked'
  | 'invalid_ticket' | 'origin_mismatch' | 'bad_key' | 'bad_signature'
  | 'too_many_keys' | 'already_enrolled' | 'attestation_failed';

/** `reason` of `422 {error:'attestation_failed', reason}` (§4.3 steps 1..11).
 *  Mirrors AttestationFailureReason in server/src/services/deviceKey/attestation.ts
 *  (checked at compile time there). */
export type DeviceKeyAttestationFailureReason =
  | 'chain_shape' | 'chain_signature' | 'chain_validity' | 'root_unknown' | 'status_unavailable' | 'revoked'
  | 'key_mismatch' | 'extension_missing' | 'extension_misplaced' | 'malformed' | 'security_level' | 'challenge'
  | 'purpose' | 'algorithm' | 'origin' | 'no_auth_required' | 'all_applications' | 'user_auth' | 'auth_timeout'
  | 'root_of_trust' | 'bootloader_unlocked' | 'boot_state' | 'app_id' | 'app_signer' | 'rkp_required';

/** 401 when the session is bound to a revoked key (J4): the session is gone. */
export interface DeviceKeyRevokedBody {
  success?: false;
  error: 'Authentication required';
  deviceKeyStatus: 'revoked';
}

/** POST /api/auth/login → data when a second factor is needed (J7, §4.9.3). */
export interface LoginTwoFactorRequiredData {
  requires2fa: true;
  methods: { totp: boolean; email: boolean; device?: boolean };
  /** purpose 'login', only when methods.device. */
  deviceChallenge?: DeviceChallenge;
}

/** POST /api/profile/2fa/verify with the device method (§4.9.3). */
export interface TwoFactorVerifyDeviceRequest {
  method: 'device';
  deviceAssertion: DeviceAssertion;
}

/** GET /api/auth/me → data.deviceKey. */
export interface AuthMeDeviceKey {
  bound: boolean;
  keyId?: string;
}

/** Web bridge (S90, §7.6): window.ObliNative.signDeviceChallenge result. */
export type SignDeviceChallengeResult =
  | { deviceAssertion: DeviceAssertion }
  | { cancelled: true }
  | { useCode: true }
  | { error: string };

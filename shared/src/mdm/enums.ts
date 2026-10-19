// =============================================================================
// MDM data model — vocabulary of the device registry (docs: modele-donnees-mdm
// §4.2, §4.4, §10.2). The values are those of the CHECK constraints of the
// migration mdm_model_expand: both change together.
// =============================================================================

export const PLATFORMS = ['ios', 'ipados', 'macos', 'tvos', 'visionos', 'android'] as const;
export type Platform = typeof PLATFORMS[number];

export const MANAGEMENT_CHANNELS = ['apple_mdm', 'amapi'] as const;
export type ManagementChannel = typeof MANAGEMENT_CHANNELS[number];

export const OWNERSHIPS = ['corporate', 'corporate_personal', 'personal'] as const;
export type Ownership = typeof OWNERSHIPS[number];

/** Enrollment METHOD (DM3): those of the enrollment profiles, plus Apple Configurator; account-driven device
 *  enrollment and migration are v1. The Android methods since the junction AN-A2 (android-amapi §4.4, part 3b):
 *  mirror of devices_enrollment_type_check. */
export const ENROLLMENT_METHODS = ['ade', 'ota', 'byod_account', 'configurator', 'account_device', 'migration',
  'android_qr', 'android_nfc', 'android_afw', 'android_token', 'android_zero_touch', 'android_kme', 'android_byod_link',
  'android_signin_url'] as const;
export type EnrollmentMethod = typeof ENROLLMENT_METHODS[number];

/** Management SCOPE (DM3): device or User Enrollment on Apple; the Android modes are v1. */
export const MANAGEMENT_MODES = ['device', 'user_enrollment', 'fully_managed', 'dedicated',
  'work_profile_corporate', 'work_profile_personal'] as const;
export type ManagementMode = typeof MANAGEMENT_MODES[number];

/** Declared use of the device (filters, dynamic groups in v1); never a security rule. */
export const DEVICE_USAGES = ['standard', 'kiosk', 'shared'] as const;
export type DeviceUsage = typeof DEVICE_USAGES[number];

export const ENROLLMENT_STATES = ['enrolling', 'awaiting_configuration', 'enrolled', 'unenrolling', 'unenrolled'] as const;
export type EnrollmentState = typeof ENROLLMENT_STATES[number];

/** Why a device left management (the reasons of onUnenrolled, integration §7.3; missing_in_provider and
 *  presumed_gone: an Android device absent at Google or silent too long, android-amapi §13.1, part 3b). */
export const UNENROLL_REASONS = ['checkout', 'retired', 'transfer', 'superseded_by_proof', 'superseded',
  'apns_inactive', 'purged', 'disabled_in_edge', 'removed_by_command', 'wiped', 'missing_in_provider', 'presumed_gone'] as const;
export type UnenrollReason = typeof UNENROLL_REASONS[number];

/** Why an enrollment episode ended: an unenroll reason, or a newer cycle that replaced it. */
export type EpisodeEndReason = UnenrollReason | 'replaced';

/** Reasons apple-edge releases a device identifier (apple-edge §4.5): those of the satellite. */
export const ID_RELEASE_REASONS = ['checkout', 'retired', 'transfer', 'superseded_by_proof', 'superseded',
  'apns_inactive', 'purged'] as const;
export type IdReleaseReason = typeof ID_RELEASE_REASONS[number];

export const COMPLIANCE_STATES = ['unknown', 'compliant', 'non_compliant', 'exempt'] as const;
export type ComplianceState = typeof COMPLIANCE_STATES[number];

export const CONFIG_STATES = ['unknown', 'applied', 'pending', 'error'] as const;
export type ConfigState = typeof CONFIG_STATES[number];

export const LOST_MODE_STATES = ['off', 'enabling', 'on', 'disabling'] as const;
export type LostModeState = typeof LOST_MODE_STATES[number];

export const ARTIFACT_STATES = ['pending', 'delivering', 'applied', 'error', 'not_applicable', 'removing', 'removed'] as const;
export type ArtifactState = typeof ARTIFACT_STATES[number];

/** NanoMDM enrollment type of an Apple device channel (apple-edge §3.5). */
export const NANO_ENROLL_TYPES = ['Device', 'User Enrollment (Device)'] as const;
export type NanoEnrollType = typeof NANO_ENROLL_TYPES[number];

export const PUSH_STATES = ['unknown', 'ready', 'invalid_token', 'inactive', 'topic_error', 'disabled'] as const;
export type PushState = typeof PUSH_STATES[number];

export const IDENTITY_STATES = ['valid', 'expired', 'revoked'] as const;
export type IdentityState = typeof IDENTITY_STATES[number];

export const END_USER_SOURCES = ['manual', 'csv', 'directory', 'enrollment'] as const;
export type EndUserSource = typeof END_USER_SOURCES[number];

export const END_USER_STATUSES = ['active', 'departed'] as const;
export type EndUserStatus = typeof END_USER_STATUSES[number];

/** Enrollment class of the availability of a setting (modele §4.2, §7.8): from the mode and the supervision. */
export type EnrollmentClass = 'supervised' | 'device' | 'user' | 'local';

/** Default of the tenant setting mdmStaleAfterDays (§4.4): the contact turns 'stale' after it. */
export const MDM_STALE_AFTER_DAYS_DEFAULT = 7;

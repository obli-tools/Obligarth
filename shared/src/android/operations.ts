// =============================================================================
// Operation of the Android integration (android-amapi §6.5, §13, §22.5, annexes D and E; lot AN-H1), shared by the
// server and the console: the daily reconciliation and the silent disappearances (presumed gone, forget at 270 days),
// the quota of the project and its weekly recount, the offboarding of a client, the adoption of an orphan enterprise,
// and the deadlines (long tokens, service account key). Imported by direct path until the shared index exports it.
// =============================================================================

/** Days without a status report after which a device is « presumed gone » (mdmStaleAfterDays: 30 by default). */
export const ANDROID_STALE_DEFAULT_DAYS = 30;
/** Bounds of the tenant setting mdmStaleAfterDays for Android (the junction reads the tenant setting). */
export const ANDROID_STALE_DAYS = { min: 7, max: 240 } as const;
/** Days without a report after which Google wants a re-enrollment: the resource is forgotten automatically [NV, RR-11]. */
export const ANDROID_FORGET_AFTER_DAYS = 270;
/** Days without contact after which the tenant alert android.device_offline_long is raised (section 10.7). */
export const ANDROID_OFFLINE_ALERT_DAYS = 240;
/** Rotation proposed for a long enrollment token (AN17, §22.3), and the warning before its end. */
export const ANDROID_LONG_TOKEN_ROTATION_DAYS = 90;
export const ANDROID_TOKEN_WARNING_DAYS = 14;
/** Expiry imposed on a service account key by the organisation policy (REV-2), and the warning before it. */
export const ANDROID_KEY_MAX_AGE_DAYS = 90;
export const ANDROID_KEY_WARNING_DAYS = 14;
/** Quota warning threshold (alert android.quota_warning), in percent of androidProjectDeviceQuota. */
export const ANDROID_QUOTA_WARNING_PERCENT = 80;
/** Automatic forgets per enterprise and per run of the reconciliation (spread; the gateway caps cleanups at 100 per hour). */
export const ANDROID_FORGET_PER_RUN = 20;

/** Why a reconciliation runs: the daily pass, the operator's button, an absence of the instance, a restore. */
export const ANDROID_RECONCILE_TRIGGERS = ['daily', 'operator', 'absence', 'restore'] as const;
export type AndroidReconcileTrigger = typeof ANDROID_RECONCILE_TRIGGERS[number];

/** The counts of one reconciliation (identifiers and counts only). */
export interface AndroidReconcileResult {
  listed: number;
  refreshed: number;
  statePatched: number;
  policyRepushed: number;
  missing: number;
  unknown: number;
  presumedGone: number;
  cleared: number;
  forgotten: number;
  forgetDeferred: number;
  policiesDeleted: number;
  tokensCollected: number;
  googleCount: number;
  googleStale: number;
  complete: boolean;
}

/** Why an Android device left management (android_devices.release_reason; the core reason follows the junction 3b). */
export const ANDROID_RELEASE_REASONS = ['superseded', 'missing_in_provider', 'removed_by_command', 'presumed_gone', 'forgotten', 'offboarding'] as const;
export type AndroidReleaseReason = typeof ANDROID_RELEASE_REASONS[number];

/** A device presumed gone, as the console lists it (identifiers and dates only). */
export interface AndroidPresumedGoneView {
  deviceId: number;
  since: string;
  lastReportAt: string | null;
  forgetDueAt: string;
}

/** The guarded action of the operator's forget of a device presumed gone (restriction key of the specification). */
export const ANDROID_FORGET_ACTION = 'android.device_forget';

/** The steps of the offboarding of a client (section 6.5). */
export const ANDROID_OFFBOARDING_STEPS = ['revoking', 'waiting_devices', 'deleting', 'releasing', 'done'] as const;
export type AndroidOffboardingStep = typeof ANDROID_OFFBOARDING_STEPS[number];

/** The approval request types of the tenant-level restrictions (floor restricted: a second approver). */
export const ANDROID_APPROVAL_TYPES = {
  unlink: 'android_enterprise_unlink',
  forceUnlink: 'android_enterprise_force_unlink',
  adopt: 'android_enterprise_adopt',
} as const;

export interface AndroidOffboardingView {
  id: string;
  step: AndroidOffboardingStep;
  startedAt: string;
  finishedAt: string | null;
  devicesLeft: number;
  forced: boolean;
  releaseFailed: boolean;
  tokensRevoked: number;
  policiesDeleted: number;
  /** i18n keys of the steps the client follows in its Google admin console (section 6.5 step 5). */
  guide: string[];
}

/** The steps shown to the client once released (its Google admin console; the deletion of its data is its own). */
export const ANDROID_OFFBOARDING_GUIDE = [
  'android.offboarding.guide.open_admin_console',
  'android.offboarding.guide.remove_emm_link',
  'android.offboarding.guide.data_deletion_is_yours',
  'android.offboarding.guide.other_emm_without_reenrollment',
] as const;

/** The quota view of the platform screen « Platform > Android » (counts only, never a tenant datum). */
export interface AndroidQuotaView {
  quota: number | null;
  count: number;
  percent: number | null;
  lastRecount: null | {
    at: string;
    instanceCount: number;
    googleCount: number;
    staleExcluded: number;
    gap: number;
    tenantsCounted: number;
    tenantsLinked: number;
  };
}

/** The deadlines of the Android integration (échéancier). */
export const ANDROID_DEADLINE_KINDS = ['long_token_rotation', 'token_expiry', 'service_account_key', 'google_backup_admins'] as const;
export type AndroidDeadlineKind = typeof ANDROID_DEADLINE_KINDS[number];

export interface AndroidDeadline {
  kind: AndroidDeadlineKind;
  /** Internal identifier of the object (token uuid, enterprise id) or null for the platform key. */
  ref: string | null;
  dueAt: string;
  /** warning: within its warning period; overdue: past. */
  status: 'ok' | 'warning' | 'overdue';
}

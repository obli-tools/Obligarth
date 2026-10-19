// =============================================================================
// Dedicated devices and kiosks (android-amapi §9.7; lot AN-G1), shared by the
// server and the console: the three forms of a kiosk, the lock a compiled
// policy holds (counted in kioskLockChanges of the impact preview, DM23), the
// temporary exit of a kiosk (guarded action mdm.android_kiosk_exit), and the
// limits of the windowed system updates and of the yearly freeze periods.
// Exported by the index of shared (junction AN-A2).
// =============================================================================

/**
 * The three forms of a kiosk, chosen by the policy:
 *   single_app  one app installed with installType KIOSK (preferred home, lock task, status bar disabled);
 *   launcher    Google's kiosk launcher (kioskCustomLauncherEnabled): the apps of the policy on one page;
 *   custom      a third-party app holding the KIOSK role (installType REQUIRED_FOR_SETUP), a launcher of its own.
 */
export const ANDROID_KIOSK_FORMS = ['single_app', 'launcher', 'custom'] as const;
export type AndroidKioskForm = typeof ANDROID_KIOSK_FORMS[number];

/** The kiosk lock of a policy: its form and the package that holds it (null for Google's launcher). */
export interface AndroidKioskLock {
  form: AndroidKioskForm;
  packageName: string | null;
}

/** The artifact type of a kiosk lock in the impact preview (kioskLockChanges, DM23). */
export const ANDROID_KIOSK_LOCK_TYPE = 'android.kiosk.lock';

/** The guarded action that lifts the kiosk lock of dedicated devices for a while (new restriction key). */
export const ANDROID_KIOSK_EXIT_ACTION = 'mdm.android_kiosk_exit';
/** Duration of a kiosk exit, in minutes: never more than 8 hours, the lock comes back by itself. */
export const ANDROID_KIOSK_EXIT_MINUTES = { min: 5, max: 480, dflt: 30 } as const;
/**
 * Why a kiosk exit ended: by the operator, at its end, the device left management, the tenant was frozen (the safest
 * state first: review AN-G1), or the device's policy came to carry a wipe-capable setting (the lock is kept: an
 * unlocked policy with such a setting could not be locked again under a freeze, AN15; review AN-G1, G1-R1).
 */
export const ANDROID_KIOSK_EXIT_END_REASONS = ['operator', 'expired', 'device_left', 'frozen', 'wipe_policy'] as const;
export type AndroidKioskExitEndReason = typeof ANDROID_KIOSK_EXIT_END_REASONS[number];

/** A kiosk exit as the console shows it (identifiers and times only). */
export interface AndroidKioskExitView {
  id: string;
  deviceId: number;
  actionUuid: string;
  requestedBy: number | null;
  startedAt: string;
  expiresAt: string;
  endedAt: string | null;
  endReason: AndroidKioskExitEndReason | null;
  /** When Google accepted the policy that holds the lock again (null: not yet, or the exit still runs). */
  lockRestoredAt: string | null;
  /**
   * When the lock came back under a freeze without the wipe-capable settings of the policy (second review AN-G1,
   * G1-S1): the return of the lock is never blocked by a freeze; the full policy follows after the unfreeze. Null: the
   * full policy holds the lock (or the lock is not back yet).
   */
  wipeWithheldAt: string | null;
}

/** The kiosk state of a device for the console. */
export interface AndroidKioskState {
  deviceId: number;
  dedicated: boolean;
  exit: AndroidKioskExitView | null;
  /**
   * An exit ended but the policy that holds the lock again has not been accepted by Google yet (push waiting, or
   * refused): the device may still be out of its lock. The last such exit is `lockPendingExit`.
   */
  lockPending: boolean;
  lockPendingExit: AndroidKioskExitView | null;
  /**
   * The lock is back on the device but its policy was pushed under a freeze without its wipe-capable settings: those
   * settings are withheld until the unfreeze, when the full policy is pushed again (second review AN-G1).
   */
  wipeSettingsWithheld: boolean;
}

/** Refusal of a kiosk exit whose device's policy carries a wipe-capable setting (review AN-G1, G1-R1). */
export const ANDROID_KIOSK_EXIT_WIPE_REFUSAL = 'kiosk_wipe_policy';

/**
 * System updates (Policy.systemUpdate, revision 20261014): the maintenance window is in minutes after midnight, local
 * time of the device (0 to 1439; a window shorter than 30 minutes is extended by the device); a freeze period lasts
 * 90 days at most, two freeze periods are at least 60 days apart (« to prevent freezing the device indefinitely »);
 * during a freeze no system update is installed, security patches included. Obligarth keeps four periods at most.
 */
export const ANDROID_SYSTEM_UPDATE_LIMITS = { maxMinutes: 1439, maxFreezeDays: 90, minFreezeGapDays: 60, maxFreezePeriods: 4 } as const;

/** The system update a kiosk receives when its policies set none: windowed, 02:00 to 05:00 local time (MAJ-04: the
 *  only way Play updates an app pinned to the foreground). */
export const ANDROID_KIOSK_UPDATE_WINDOW = { type: 'WINDOWED', startMinutes: 120, endMinutes: 300 } as const;

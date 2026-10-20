// MDM command queue as the console sees it (docs: integration-apple-edge §8.1, §8.2, §8.12): the states of a
// target, the views of a command and of the queue of a device, the outcomes of the routes. Identifiers and
// states only: never a plist, never a value of a result.
import type { DeviceCapability } from '../capabilities';

/** States of a target (a command for a device), ordered by a monotone rank (obligarth.mdm_target_state_rank):
 *  pending 0 < queued 1 < sent, notnow 2 < expired, cancelled, rejected 3 < acknowledged, error 4. */
export const MDM_TARGET_STATES = ['pending', 'queued', 'sent', 'notnow', 'expired', 'cancelled', 'rejected', 'acknowledged', 'error'] as const;
export type MdmTargetState = typeof MDM_TARGET_STATES[number];

/** A target still waiting for its device. */
export const MDM_OPEN_TARGET_STATES: readonly MdmTargetState[] = ['pending', 'queued', 'sent', 'notnow'];

export const MDM_COMMAND_ORIGINS = ['console', 'bulk', 'policy', 'ddm', 'inventory', 'enrollment', 'setup', 'system', 'approval', 'guard'] as const;
export type MdmCommandOrigin = typeof MDM_COMMAND_ORIGINS[number];

export const MDM_SUBMIT_STATES = ['pending', 'submitted', 'held', 'failed', 'cancelled'] as const;
export type MdmSubmitState = typeof MDM_SUBMIT_STATES[number];

/** Why the bus sets a device aside (the request goes on for the others). */
export const MDM_REFUSAL_CODES = ['not_apple', 'not_enrolled', 'awaiting_configuration_only', 'ownership', 'not_supervised',
  'no_unlock_token', 'already_open', 'identity_unavailable'] as const;
export type MdmRefusalCode = typeof MDM_REFUSAL_CODES[number];

/** The request types a guarded action alone may enqueue (the command routes answer 409 guardedActionRequired). */
export const MDM_GUARDED_REQUEST_TYPES: Readonly<Record<string, string>> = {
  EraseDevice: 'mdm.erase_device',
  DeviceLock: 'mdm.device_lock',
  EnableLostMode: 'mdm.lost_mode_enable',
};

/** One target of the queue of a device or of a command. */
export interface MdmTargetView {
  commandId: string;
  deviceId: number;
  /** The platform of a command that is not Apple's ('android': an AMAPI command, android-amapi §11.5); absent for Apple. */
  platform?: string;
  requestType: string;
  origin: string;
  state: MdmTargetState;
  rejectCode: string | null;
  lastStatus: string | null;
  holdReason: string | null;
  createdAt: string;
  notBefore: string | null;
  expiresAt: string;
  queuedAt: string | null;
  deliveredAt: string | null;
  completedAt: string | null;
  pushCount: number;
  pushedAt: string | null;
  pushOutcome: string | null;
  errorChain: Array<{ code: number; domain: string; description: string }> | null;
  requestedBy: { id: number; name: string } | null;
  reason: string | null;
}

export interface MdmCommandView {
  id: string;
  batchId: string | null;
  /** The platform of a command that is not Apple's ('android'); absent for Apple. */
  platform?: string;
  requestType: string;
  origin: string;
  createdAt: string;
  notBefore: string | null;
  expiresAt: string;
  submitState: string;
  reason: string | null;
  ticket: string | null;
  requestedBy: { id: number; name: string } | null;
  approvalId: number | null;
  /** The command belongs to a guarded action: it is cancelled through the guard engine. */
  guardActionUuid: string | null;
  counts: Partial<Record<MdmTargetState, number>>;
}

/** 202 of POST …/commands: the commands written (their submission follows), and the devices set aside. */
export interface MdmEnqueueResult {
  batchId: string;
  commandIds: string[];
  targets: number;
  refused: Array<{ deviceId: number; code: MdmRefusalCode }>;
  held: boolean;
  notBefore: string | null;
  replayed: boolean;
}

export interface MdmCancelOutcome { cancelled: number; requested: number; notCancellable: number }
export interface MdmRelaunchOutcome { pushed: number; skipped: Array<{ deviceId: number; code: string }> }

/** One action of the menu of a device (GET /api/apple/devices/:id/actions). */
export interface MdmDeviceAction {
  requestType: string;
  /** The capability the action needs on the device; null: a guarded action checks its own. */
  capability: DeviceCapability | null;
  /** Restriction key of the matrix, or the key of the guarded action. */
  restrictionKey: string | null;
  /** The action goes through the guard engine (POST /api/guard/actions). */
  guarded: boolean;
  reasonRequired: boolean;
  available: boolean;
  /** Why it is not: capabilityMissing, notApple, notEnrolled, awaitingConfigurationOnly, ownership, notSupervised,
   *  noUnlockToken, frozen. */
  unavailable: string | null;
}

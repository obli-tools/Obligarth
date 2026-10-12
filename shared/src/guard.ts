// =============================================================================
// Guards against mass erasure (PLT-11, D23-D24): types shared by the server and
// the console
// =============================================================================
//
// A guarded action (record deletion today, the MDM's erase and removal of
// management with lot D) goes through the guard engine only: floors computed
// for each request from the number of targets and the selection (the
// restrictions matrix may raise a level, never lower it), a second approver
// on the client side by default for a batch, a delay before execution that
// anyone allowed may cancel, an hourly cap, an emergency freeze, a cooldown of
// the new administrators, and a complete revalidation at execution.

export type GuardFamily = 'device_records' | 'device_destruction' | 'device_control' | 'device_privacy';
export type GuardLevel = 'sensitive' | 'restricted';
export type GuardSide = 'msp' | 'client';
/** Side required of the approver: a client requester may be approved by a
 *  designated approver of either side ('any'). */
export type GuardApproverSide = GuardSide | 'any';

export type PendingActionState =
  | 'awaiting_approval' | 'scheduled' | 'paused' | 'executing'
  | 'done' | 'partial' | 'cancelled' | 'refused' | 'failed' | 'expired';

export const PENDING_ACTION_STATES: readonly PendingActionState[] = [
  'awaiting_approval', 'scheduled', 'paused', 'executing', 'done', 'partial', 'cancelled', 'refused', 'failed', 'expired',
];
/** States still open: listed with their countdown, cancellable. */
export const OPEN_PENDING_ACTION_STATES: readonly PendingActionState[] = ['awaiting_approval', 'scheduled', 'paused', 'executing'];

/** Not configurable (a new version changes them): D23, J22, J24, J25. */
export const GUARD_BULK_THRESHOLD = 3;
export const GUARD_BURST_WINDOW_MINUTES = 15;
export const GUARD_COOLDOWN_HOURS = 72;
export const GUARD_PAUSE_EXPIRY_HOURS = 24;
export const GUARD_HOURLY_CAP_PERCENT_DEFAULT = 10;
export const GUARD_HOURLY_CAP_MIN_DEFAULT = 5;
export const GUARD_REASON_MIN = 5;
export const GUARD_REASON_MAX = 500;
export const GUARD_TICKET_MAX = 64;
/** After a client approver of a tenant is lost through someone else's act
 *  (revocation by another account, deactivation, change or removal of the
 *  role, deletion), the fallback of D24 on an MSP approver stays closed for
 *  this many days: the MSP cannot remove the client approvers and then
 *  approve alone (AUD-A7-R4). */
export const GUARD_FALLBACK_HOLD_DAYS = 30;

export interface GuardSelection {
  deviceIds?: number[];
  groupIds?: number[];
  tenant?: boolean;
}

export interface GuardRequestInput {
  actionKey: string;
  selection: GuardSelection;
  params?: Record<string, unknown>;
  reason: string;
  ticket?: string;
  confirm?: string;
}

export type GuardRefusalCode =
  | 'noTargets' | 'targetsOutsideScope' | 'tenantFrozen' | 'privilegeCooldown' | 'personalDeviceForbidden'
  | 'wholeFleetForbidden' | 'hourlyCapExceeded' | 'confirmationMismatch' | 'reasonRequired' | 'approverFallbackHeld';

export type GuardOutcome =
  | { state: 'scheduled'; actionUuid: string; executeAfter: string; delaySeconds: number }
  | { state: 'awaiting_approval'; actionUuid: string; approvalId: number; approverSide: GuardApproverSide;
      approverFallback: boolean; expiresAt: string };

export interface GuardActor {
  id: number;
  label: string | null;
  side: GuardSide;
}

export interface PendingActionDto {
  uuid: string;
  tenantId: number;
  actionKey: string;
  family: string;
  state: PendingActionState;
  requestedBy: GuardActor;
  approvalId: number | null;
  approvedBy: GuardActor | null;
  approverFallback: boolean;
  targetCount: number;
  /** The first 1,000. */
  targetDeviceIds: number[];
  reason: string;
  ticket: string | null;
  delaySeconds: number;
  executeAfter: string | null;
  pausedAt: string | null;
  cancelledAt: string | null;
  executedAt: string | null;
  result: { done: number; failed: number; skipped: number } | null;
  createdAt: string;
  /** What the action dispatched may still be withdrawn (POST …/actions/:uuid/cancel on an action being executed
   *  or executed: undelivered MDM commands, until they expire). */
  lateCancellable?: boolean;
  /** A late cancellation was asked (ISO date). */
  lateCancelledAt?: string | null;
}

/** The quota of the hourly cap (family device_destruction). */
export interface GuardQuota {
  cap: number;
  used: number;
  remaining: number;
  /** When the oldest action counted leaves the sliding window (null: none counted). */
  resetsAt: string | null;
}

export interface GuardSettingsDto {
  tenantId: number;
  hourlyCapPercent: number;
  hourlyCapMin: number;
  massApproverSide: GuardSide;
  frozen: boolean;
  frozenAt: string | null;
  frozenBy: number | null;
  frozenSource: 'manual' | 'anomaly' | null;
  frozenReason: string | null;
  updatedAt: string | null;
  /** Last loss of a client approver not decided by the approver (null: none
   *  within GUARD_FALLBACK_HOLD_DAYS). */
  clientApproverLostAt?: string | null;
  /** Until then, a request that needs a client approver does not fall back
   *  on an MSP approver (null: the fallback is open). */
  fallbackHeldUntil?: string | null;
}

export interface GuardSettingsInput {
  hourlyCapPercent?: number;
  hourlyCapMin?: number;
  massApproverSide?: GuardSide;
}

export interface GuardApproverDto {
  id: number;
  tenantId: number;
  userId: number;
  username: string | null;
  displayName: string | null;
  side: GuardSide;
  designatedBy: number;
  approvalId: number | null;
  createdAt: string;
  /** End of the 72-hour cooldown of the designation (null: over). */
  cooldownUntil: string | null;
}

/** What the console shows of a guarded action before a request is sent:
 *  floors and delays of D23 (the matrix may raise the level). */
export interface GuardedActionInfo {
  key: string;
  label: string;
  family: GuardFamily;
  singleFloor: GuardLevel;
  singleStrictStepUp: boolean;
  bulkThreshold: number;
  singleDelaySeconds: number;
  bulkDelaySeconds: number;
  hourlyCap: boolean;
  forbidWholeFleet: boolean;
  confirmation: 'typed' | 'none';
}

/** GUARD_STATE_CHANGED (tenant room). */
export interface GuardStateChanged {
  tenantId: number;
  frozen: boolean;
  frozenAt: string | null;
  source: 'manual' | 'anomaly' | null;
}

/** Payload of an approval request of the guard (pending_approvals.payload):
 *  shown to the reviewers as is. */
export interface GuardApprovalPayload {
  action: 'guarded_action' | 'guard_resume' | 'guard_unfreeze' | 'guard_settings_change' | 'guard_approver_designate';
  actionUuid?: string;
  actionKey?: string;
  targetCount?: number;
  requiredSide: GuardApproverSide;
  approverFallback: boolean;
  [key: string]: unknown;
}

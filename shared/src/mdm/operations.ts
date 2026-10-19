// =============================================================================
// Operations of the Apple integration seen by the console (docs: integration-
// apple-edge §13.1, §13.2, §13.3; lot C5): the enrollments apple-edge holds
// that no record of the tenant holds (to attach to an enrollment profile or to
// release), and the checklist of the verified retirement of a device.
// =============================================================================

/** An enrollment apple-edge holds that no record of the tenant holds (GET /api/apple/enrollments/unknown). */
export interface UnknownEnrollmentView {
  /** '<tenant key>_<device identifier>' (the device's own identifier at apple-edge). */
  enrollmentId: string;
  /** NanoMDM type: 'Device' or 'User Enrollment (Device)'. */
  type: string;
  /** 'ade' when apple-edge holds the proof of an Automated Device Enrollment, 'none' otherwise. */
  proof: string;
  createdAt: string;
  lastSeenAt: string;
}

export const ATTACH_OUTCOMES = ['attached', 'already', 'not_found', 'disabled', 'ownership', 'other_kind', 'managed', 'failed'] as const;
export type AttachOutcome = typeof ATTACH_OUTCOMES[number];
export const RELEASE_OUTCOMES = ['released', 'not_found', 'managed', 'failed'] as const;
export type ReleaseOutcome = typeof RELEASE_OUTCOMES[number];

export interface AttachUnknownResult {
  results: Record<string, AttachOutcome>;
  deviceIds: number[];
  /** Unknown enrollments left after the operation. */
  left: number;
}

export interface ReleaseUnknownResult {
  results: Record<string, ReleaseOutcome>;
  left: number;
}

export const RETIREMENT_STEPS = ['management_removed', 'licenses_released', 'released', 'retired'] as const;
export type RetirementStep = typeof RETIREMENT_STEPS[number];
export const RETIREMENT_MANUAL_ITEMS = ['apple_business', 'activation_lock'] as const;
export type RetirementManualItem = typeof RETIREMENT_MANUAL_ITEMS[number];

/** The checklist of the last verified retirement of a device (GET /api/apple/devices/:id/retirement). */
export interface RetirementView {
  /** null: no retirement was started for the device. */
  startedAt: string | null;
  steps: Array<{ step: RetirementStep; at: string | null; outcome: string | null }>;
  manual: Array<{ item: RetirementManualItem; at: string | null }>;
}

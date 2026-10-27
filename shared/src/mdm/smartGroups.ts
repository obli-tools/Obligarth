// =============================================================================
// Dynamic groups (P0-5 §4.2, §5; D3, D8, D9, D10): a group of devices of a tenant defined by a rule of the rule
// language (rules.ts), whose members are materialised (smart_group_members) and computed again by the server: at once,
// in the request, when an untargeted group is created or its rule changes; incrementally after (P0-5 T5). Never
// members: the devices out of management (D9). A dynamic group gives no team scope (D8); the counts a non-administrator
// reads cover only the devices their teams see (D3). One tenant per group (D10).
// The rule_fields of a group are the families of marking of its rule (DIRTY_FAMILIES, ruleFamiliesOf): the reasons the
// marking of the incremental computation gives a device (P0-5 §3 M2, §4.3) are families, so a group is computed again
// for a device when its families meet the device's reasons. The fields themselves (D2: may an assignment target the
// group?) are read from the rule.
// =============================================================================

import type { PolicyImpact } from './impact';
import type { DirtyFamily, RuleFieldKey, RuleNode } from './rules';

/** active: computed; held: an automatic computation beyond the mass guard waits for a governed release (D4, P0-5 T5);
 *  error: the rule can no longer be computed (a static group it names was deleted): the members are frozen. */
export const SMART_GROUP_STATES = ['active', 'held', 'error'] as const;
export type SmartGroupState = typeof SMART_GROUP_STATES[number];

/** Why a group is not active: mass_change (held, D4), group_deleted and rule_invalid (error). */
export const SMART_GROUP_STATE_REASONS = ['mass_change', 'group_deleted', 'rule_invalid'] as const;
export type SmartGroupStateReason = typeof SMART_GROUP_STATE_REASONS[number];

/** What changed the membership of a device (smart_group_membership_log.cause): a rule written (creation, change), the
 *  inventory (the incremental computation), the release of a held group. */
export const SMART_GROUP_CAUSES = ['rule', 'inventory', 'release'] as const;
export type SmartGroupCause = typeof SMART_GROUP_CAUSES[number];

export const SMART_GROUP_LIMITS = {
  /** Dynamic groups of a tenant. */
  perTenant: 200,
  nameMax: 200,
  descriptionMax: 1000,
  /** Devices of the sample of a preview. */
  previewSample: 20,
  /** Members per page (GET /api/mdm/smart-groups/:id/members). */
  membersPageMax: 1000,
  /** Days the membership log is kept (D7, fixed). */
  membershipLogDays: 90,
} as const;

/** The reasons of a marking of the incremental computation (smart_group_dirty.reasons, P0-5 T5): the families of what
 *  changed, or 'new' (a device created, or entering or leaving management, D9: every group computes it again). */
export const SMART_GROUP_DIRTY_REASONS = ['new', 'facts', 'tags', 'custom', 'user', 'android', 'group', 'apps', 'derived', 'temporal'] as const;
export type SmartGroupDirtyReason = typeof SMART_GROUP_DIRTY_REASONS[number];

/** Does a device marked for `reasons` need the group of families `families` computed again ('new' meets them all)? */
export function dirtyReasonsMeet(reasons: readonly string[], families: readonly string[]): boolean {
  return reasons.includes('new') || reasons.some((r) => families.includes(r));
}

/** The mass guard of the automatic computations of a group an assignment targets (D4): beyond max(25, 10 % of the
 *  managed devices) entries and exits within the hour, nothing is written and the group is held. */
export const SMART_GROUP_GUARD = {
  minChanges: 25,
  /** Tenths of the managed devices: 10 %. */
  shareOfManaged: 0.1,
  /** The window of the changes counted (an hour, from the first change counted). */
  windowMs: 3_600_000,
} as const;

/** The changes an hour of automatic computations may make to a targeted group of a tenant of `managed` devices. */
export function smartGroupGuardLimit(managed: number): number {
  const n = Number.isFinite(managed) && managed > 0 ? Math.ceil(managed * SMART_GROUP_GUARD.shareOfManaged) : 0;
  return Math.max(SMART_GROUP_GUARD.minChanges, n);
}

/**
 * The decision of the mass guard for an automatic computation of a targeted group that would make `changes` entries
 * and exits: `hold` when the changes of the window and these go beyond the limit (nothing is then written: the window
 * stays as it was); otherwise the window to store (a new one when there was none or it ended).
 */
export function smartGroupGuardDecision(w: { windowStart: Date | null; windowChanges: number; changes: number; managed: number; now: Date }):
  { hold: boolean; limit: number; windowStart: Date; windowChanges: number } {
  const limit = smartGroupGuardLimit(w.managed);
  const open = w.windowStart !== null && w.now.getTime() - w.windowStart.getTime() < SMART_GROUP_GUARD.windowMs;
  const start = open ? (w.windowStart as Date) : w.now;
  const before = open ? Math.max(0, w.windowChanges) : 0;
  const hold = w.changes > 0 && before + w.changes > limit;
  return { hold, limit, windowStart: start, windowChanges: hold ? before : before + Math.max(0, w.changes) };
}

/** Socket event SMART_GROUP_CHANGED (to the tenant's room): the groups whose members an automatic computation changed. */
export interface SmartGroupChangedEvent {
  smartGroupIds: number[];
}

/** A device of a preview's sample. */
export interface SmartGroupSampleDevice {
  id: number;
  uuid: string;
  name: string;
  platform: string;
}

export interface SmartGroup {
  id: number;
  uuid: string;
  name: string;
  description: string | null;
  rule: RuleNode;
  /** The families of marking of the rule (smart_groups.rule_fields). */
  ruleFields: DirtyFamily[];
  /** Goes up at every change of the rule. */
  ruleVersion: number;
  ruleSha256: string;
  state: SmartGroupState;
  stateReason: SmartGroupStateReason | null;
  stateSince: string | null;
  /** held: the entries and exits waiting for the release, counted on the tenant; null for a non-administrator, whose
   *  counts never cover the devices out of their teams' reach (D3). */
  pendingAdded: number | null;
  pendingRemoved: number | null;
  /** Its members: all of them for an administrator; for a non-administrator, those their teams see (D3). */
  memberCount: number;
  /** 'visible': memberCount covers only the devices the caller sees. */
  memberCountScope: 'all' | 'visible';
  computedAt: string | null;
  /** Assignments that target the group (P0-5 T6); 0 until then. */
  assignmentCount: number;
  /** May an assignment target it (D2): no derived, temporal, group nor apps field in its rule. */
  targetable: boolean;
  /** The fields of its rule an assignment's target does not permit (D2), in catalog order. */
  notTargetableFields: RuleFieldKey[];
  createdBy: { id: number; name: string | null } | null;
  updatedBy: { id: number; name: string | null } | null;
  createdAt: string;
  updatedAt: string;
}

/** POST /api/mdm/smart-groups/preview: what a rule selects (without writing), and against a group's current members. */
export interface SmartGroupPreview {
  /** Devices the rule selects (the devices the caller sees, for a non-administrator: D3). */
  total: number;
  /** Against the members of `smartGroupId` when given: those the rule would add and remove; else null. */
  added: number | null;
  removed: number | null;
  /** SMART_GROUP_LIMITS.previewSample devices at most, by id. */
  sample: SmartGroupSampleDevice[];
  /** The scope of the counts. */
  scope: 'all' | 'visible';
  /** The token of the full list of the devices whose configuration the rule would change (GET /api/mdm/impact/:token/devices),
   *  for a group an assignment targets (P0-5 T7); null otherwise. */
  devicesToken: string | null;
}

/** POST /api/mdm/smart-groups. */
export interface SmartGroupCreate {
  name: string;
  description?: string | null;
  rule: RuleNode;
}

/** PATCH /api/mdm/smart-groups/:id (the fields to change). */
export type SmartGroupPatch = Partial<SmartGroupCreate>;

/** The outcome of a write: the group, and the members its rule added and removed (null when the rule did not change;
 *  for a non-administrator, those of the devices their teams see: D3). */
export interface SmartGroupWriteResult {
  group: SmartGroup;
  added: number | null;
  removed: number | null;
}

/** DELETE /api/mdm/smart-groups/:id?dryRun=true. */
export interface SmartGroupDeletePreview {
  outcome: 'preview';
  memberCount: number;
  assignmentCount: number;
  /** A group an assignment targets (P0-5 T7): the entries and exits, and the impact on the configuration of its members. */
  membership?: SmartGroupMembershipDelta;
  impact?: PolicyImpact;
}

// ── Governed changes (P0-5 T7, §4.4; D3, D4, D11) ────────────────────────────────────────────────────────────────

/** The entries and exits a governed change of a group makes (a new rule, its release, its deletion): on the devices of
 *  the tenant for an administrator, on the devices their teams see for another caller (D3: `scope`). */
export interface SmartGroupMembershipDelta {
  smartGroupId: number;
  added: number;
  removed: number;
  /** Members once the change is written (0: the group deleted). */
  total: number;
  /** 'visible': the counts cover only the devices the caller sees. */
  scope: 'all' | 'visible';
}

/**
 * PATCH /api/mdm/smart-groups/:id with a new rule, DELETE /api/mdm/smart-groups/:id and POST …/:id/release, on a group
 * an assignment targets (and the release of any held group): the preview of the change (?dryRun=true: the entries and
 * exits, the impact on the configuration of the devices, its keys), the change written (a step-up when it touches the
 * configuration of a device), or the request for a second approver beyond the thresholds of DM23 (202).
 */
export type SmartGroupGovernedOutcome =
  | { outcome: 'preview'; membership: SmartGroupMembershipDelta; impact: PolicyImpact }
  | {
    outcome: 'applied'; membership: SmartGroupMembershipDelta; impact: PolicyImpact;
    /** The group as written; null once deleted (`deleted`). */
    group: SmartGroup | null; added: number | null; removed: number | null; deleted?: true;
  }
  | { outcome: 'awaiting_approval'; status: 'pending_approval'; approvalId: number; membership: SmartGroupMembershipDelta; impact: PolicyImpact };

/** The dynamic groups an assignment targets that a change of the facts of a device (its name, tags, custom fields,
 *  asset statuses: PATCH /api/mdm/devices/:id) makes it enter or leave (D11), by id. */
export interface DeviceFactsEffect {
  entered: number[];
  left: number[];
}

/**
 * PATCH /api/mdm/devices/:id when the change makes the device enter or leave a dynamic group an assignment targets
 * (D11: devices.manage and the governed preview): ?dryRun=true answers the preview (`governed` false: nothing of the
 * kind, the change goes through as before); a second approver beyond the thresholds answers 202. A change written
 * answers the device record, as before.
 */
export type DeviceFactsOutcome =
  | { outcome: 'preview'; governed: boolean; smartGroups: DeviceFactsEffect; impact: PolicyImpact | null }
  | { outcome: 'awaiting_approval'; status: 'pending_approval'; approvalId: number; smartGroups: DeviceFactsEffect; impact: PolicyImpact };

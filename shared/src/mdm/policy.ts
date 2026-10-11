// =============================================================================
// Policies: envelope, versions, assignments (docs: modele-donnees-mdm §7.1,
// §7.5, §7.12, §10.2, §10.3). The values are those of the CHECK constraints
// of the migration mdm_model_expand: both change together.
// =============================================================================
import type { PolicyImpact } from './impact';
import type { JsonValue, PolicyContentV1 } from './policyContent';

export const POLICY_STATES = ['draft', 'published', 'archived'] as const;
export type PolicyState = typeof POLICY_STATES[number];

export const POLICY_VERSION_STATES = ['draft', 'pending_approval', 'published', 'superseded', 'rejected'] as const;
export type PolicyVersionState = typeof POLICY_VERSION_STATES[number];

/** Categories the console proposes; any value of the form below is accepted (policies_category_check). */
export const POLICY_CATEGORIES = ['configuration', 'restrictions', 'network', 'security', 'updates', 'kiosk', 'certificates'] as const;
export const POLICY_CATEGORY_RE = /^[a-z][a-z0-9_]{1,31}$/;

export const ASSIGNMENT_RESOURCE_TYPES = ['policy', 'app'] as const;
export type AssignmentResourceType = typeof ASSIGNMENT_RESOURCE_TYPES[number];
export const ASSIGNMENT_TARGET_SCOPES = ['tenant', 'group', 'device'] as const;
export type AssignmentTargetScope = typeof ASSIGNMENT_TARGET_SCOPES[number];
export const ASSIGNMENT_MODES = ['include', 'exclude'] as const;
export type AssignmentMode = typeof ASSIGNMENT_MODES[number];

/** Priority of an assignment: 0 to 1 000, smaller is stronger; it only breaks ties of the same rank. */
export const ASSIGNMENT_PRIORITY = { min: 0, max: 1000, default: 100 } as const;

/**
 * Second approver of a publication or of a change of assignments (DM23): 25 touched devices or more, or
 * 10 % of the tenant's enrolled fleet or more, or a removal (profile, app, kiosk lock) on 3 devices or more;
 * a step-up below. At the execution of an approved request, an impact grown by more than 20 % (touched
 * devices or removals) is refused (impactChanged).
 */
export const PUBLISH_APPROVAL_THRESHOLDS = {
  devicesTouched: 25,
  fleetShare: 0.10,
  removalDevices: 3,
  recheckTolerance: 0.20,
} as const;

/** Restriction of the matrix that guards a publication or a change of assignments. */
export const POLICY_PUBLISH_ACTION = 'mdm.policy_publish';
/** Request type of an approval of a publication or of a change of assignments. */
export const POLICY_PUBLISH_REQUEST_TYPE = 'mdm_policy_publish';

export interface Policy {
  id: number;
  uuid: string;
  tenantId: number;
  name: string;
  description: string | null;
  category: string;
  state: PolicyState;
  sections: string[];
  currentVersionId: number | null;
  /** Number of the published version. */
  currentVersion: number | null;
  versionCounter: number;
  /** The draft or the version awaiting approval, if any (one at most). */
  openVersion: { id: number; version: number; state: PolicyVersionState } | null;
  assignmentCount: number;
  /** Shared by the master tenant (v1). */
  shared: boolean;
  createdBy: number | null;
  updatedBy: number | null;
  createdAt: string;
  updatedAt: string;
  archivedAt: string | null;
}

/** policy_versions.summary: counters of the content, never a value. */
export interface PolicyVersionSummary {
  items: number;
  removals: number;
  types: Record<string, number>;
  secretRefs: number;
  variables: number;
}

export interface PolicyVersion {
  id: number;
  policyId: number;
  version: number;
  state: PolicyVersionState;
  content: PolicyContentV1;
  contentSha256: string;
  schemaRelease: Record<string, string>;
  summary: PolicyVersionSummary | Record<string, never>;
  changeNote: string | null;
  impact: PolicyImpact | null;
  approvalId: number | null;
  createdBy: number | null;
  createdAt: string;
  submittedBy: number | null;
  submittedAt: string | null;
  publishedBy: number | null;
  publishedAt: string | null;
  supersededAt: string | null;
}

export interface Assignment {
  id: number;
  tenantId: number;
  resourceType: AssignmentResourceType;
  resourceId: number;
  resourceTenantId: number;
  resourceName: string | null;
  targetScope: AssignmentTargetScope;
  targetId: number | null;
  targetName: string | null;
  mode: AssignmentMode;
  priority: number;
  options: Record<string, JsonValue>;
  createdBy: number | null;
  createdAt: string;
  updatedAt: string;
}

/** A change of a batch of POST /api/mdm/assignments/changes. */
export interface AssignmentChange {
  op: 'create' | 'update' | 'delete';
  id?: number;                                   // update, delete
  resourceType?: AssignmentResourceType; resourceId?: number; resourceTenantId?: number;
  targetScope?: AssignmentTargetScope; targetId?: number | null;
  mode?: AssignmentMode; priority?: number; options?: Record<string, JsonValue>;
}

export type SubmitOutcome =
  | { outcome: 'published'; versionId: number; impact: PolicyImpact }
  | { outcome: 'applied'; impact: PolicyImpact }
  | { outcome: 'awaiting_approval'; approvalId: number; impact: PolicyImpact }
  | { outcome: 'preview'; impact: PolicyImpact };


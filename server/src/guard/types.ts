// Types of the guard engine (docs: audit-durci §10). No database import: the
// unit tests load this module without a server.
import type { z } from 'zod';
import type { DeviceCapability, GuardFamily, GuardLevel, GuardSide, TenantCapability } from '@obligarth/shared';

export type { GuardFamily, GuardLevel, GuardSide };

export type DeviceOwnership = 'personal' | 'corporate_personal' | 'corporate';

/** Why a target is set aside at execution (revalidate) or refused by the
 *  executor: a short code ('not_found', 'not_enrolled', 'personal'…). */
export interface GuardTargetRefusal {
  code: string;
  message?: string;
}

/** The outcome of an action on one target. 'queued': handed over to a
 *  channel that completes it later (an MDM command); counted as done in the
 *  summary of pending_actions.result. */
export interface GuardTargetResult {
  status: 'done' | 'queued' | 'failed' | 'skipped';
  code?: string;
}

/** What the executor of a guarded action receives (revalidation, execution,
 *  late cancellation): the action as it was approved, in its tenant's
 *  database context, as the requester. */
export interface GuardExecutionContext<P = Record<string, unknown>> {
  tenantId: number;
  actionUuid: string;
  actionKey: string;
  params: P;
  requesterId: number;
  /** pending_approvals ids that authorised the action. */
  approvalIds: number[];
  reason: string;
  ticket: string | null;
  /** The targets this step works on (revalidation: every target left). */
  deviceIds: number[];
  /** 'job-<id>' of the run (X-Request-ID towards apple-edge), or the request's id. */
  requestId: string;
  /** 'job:<queue>' of the run: X-Obligarth-Actor towards apple-edge. */
  actor: string;
  signal?: AbortSignal;
}

export interface GuardedActionDef<P = Record<string, unknown>> {
  /** Restriction action key, e.g. 'mdm.erase_device'. */
  key: string;
  /** English; the console translates guard.actions.<key>. */
  label: string;
  family: GuardFamily;
  /** One or two devices, explicit ids. */
  singleFloor: GuardLevel;
  /** No trusted-IP shortcut (an erase). */
  singleStrictStepUp: boolean;
  /** 3 (D23): from this count, or any group / tenant selection: bulk. */
  bulkThreshold: number;
  /** 300 for an erase (D23). */
  singleDelaySeconds: number;
  /** 900 (D23). */
  bulkDelaySeconds: number;
  /** Counted in the tenant's destructive budget (family device_destruction). */
  hourlyCap: boolean;
  forbidWholeFleet: boolean;
  refuseOwnership: DeviceOwnership[];
  confirmation: 'typed' | 'none';
  /** Non-secret parameters, strict. */
  paramsSchema: z.ZodType<P>;
  /** Capability the requester must hold on each target (team scopes);
   *  platform administrators pass. */
  deviceCapability?: DeviceCapability;
  /** Tenant capability the requester must hold (device.delete:
   *  devices.manage); platform administrators pass. */
  tenantCapability?: TenantCapability;
  /** Category of the restrictions matrix (default 'Guarded actions'). */
  category?: string;
  /** Recommended level of the matrix of a new tenant (never below the floor). */
  defaultLevel?: GuardLevel;
  /** Serial numbers of the targets, for the execution entry (J29): '' when
   *  unknown. Without it the entry carries the ids only. */
  serialsOf?(tenantId: number, deviceIds: number[]): Promise<Map<number, string>>;
  /** Per target, at execution: still in the tenant, still managed, ownership still allowed… */
  revalidate(ctx: GuardExecutionContext<P>): Promise<Map<number, 'ok' | GuardTargetRefusal>>;
  /** Idempotent: run again after a crash, it must not act twice (deterministic command UUIDs). */
  execute(ctx: GuardExecutionContext<P>, deviceIds: number[]): Promise<Map<number, GuardTargetResult>>;
  /** Optional: withdraw what was dispatched but not yet delivered (undelivered MDM commands). */
  cancelAfterDispatch?(ctx: GuardExecutionContext<P>): Promise<Map<number, 'cancelled' | 'already_delivered' | 'completed'>>;
}

/** Size of a tenant's active fleet (hourly cap, whole fleet). */
export type FleetSizeProvider = (tenantId: number) => Promise<number>;

/** Ownership of devices of a tenant (lot B: devices.ownership); a device
 *  absent from the map is of unknown ownership. */
export type OwnershipProvider = (tenantId: number, deviceIds: number[]) => Promise<Map<number, DeviceOwnership>>;

/** Freeze or unfreeze the commands of a tenant at apple-edge (lot B):
 *  'done', or 'no_edge_tenant' for a tenant apple-edge does not know yet
 *  (its provisioning carries the freeze over). Throws on a failure. */
export type EdgeFreezeHandler = (tenantId: number, frozen: boolean) => Promise<'done' | 'no_edge_tenant'>;

/** Summary of pending_actions.result. */
export interface GuardResultSummary {
  done: number;
  failed: number;
  skipped: number;
  /** Targets set aside at revalidation or refused at execution (200 at most). */
  setAside?: Array<{ id: number; code: string }>;
  failures?: Array<{ id: number; code: string }>;
  /** Late cancellation (cancelAfterDispatch), per target. */
  cancellation?: Array<{ id: number; outcome: string }>;
}

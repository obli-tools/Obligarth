// Types of the guard engine (docs: audit-durci §10). No database import: the
// unit tests load this module without a server.
import type { Knex } from 'knex';
import type { z } from 'zod';
import type { DeviceCapability, GuardFamily, GuardLevel, GuardSide, TenantCapability } from '@obligarth/shared';

export type { GuardFamily, GuardLevel, GuardSide };

export type DeviceOwnership = 'personal' | 'corporate_personal' | 'corporate';

/** The management channels of a device (devices.management_channel). */
export type ManagementChannel = 'apple_mdm' | 'amapi' | 'legacy_agent';
export const MANAGEMENT_CHANNELS: readonly ManagementChannel[] = ['apple_mdm', 'amapi', 'legacy_agent'];

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
  /**
   * The management channels the action acts on (decisions of the owners of 20/10/2026, PONT-R-RV3 and RV4): a
   * request whose targets include a device of another channel is refused at once (422 channelMismatch: nothing
   * scheduled, nothing counted in the hourly cap). An action of one channel only (legacy_agent, or amapi for the
   * Android-only keys) also has the whole fleet and the hourly cap computed on that channel's fleet, besides the
   * tenant's. Absent: every channel (the deletion of records).
   */
  channels?: readonly ManagementChannel[];
  confirmation: 'typed' | 'none';
  /** Non-secret parameters, strict. */
  paramsSchema: z.ZodType<P>;
  /** The parameters as a request may type them, when they differ from what is stored (paramsSchema): a secret typed
   *  in, sealed by prepareParams before anything stores or journals the request (android-amapi §22.9, COH-7). */
  requestParamsSchema?: z.ZodTypeAny;
  /** In the transaction of the request, before the action, its approval and its entries are written: the stored
   *  parameters (a typed secret replaced by its reference in the tenant's vault). */
  prepareParams?(trx: Knex.Transaction, tenantId: number, params: Record<string, unknown>, userId: number): Promise<Record<string, unknown>>;
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
  /**
   * Optional: withdraw what was dispatched but not yet delivered (undelivered MDM commands); the answer names
   * every target something was dispatched for. The engine calls it for a late cancellation: of an action being
   * executed, or already executed while what it dispatched still waits for its devices (states 'executing',
   * 'done', 'partial', 'failed'), and for a paused action that an interrupted run had started. Before the call
   * the engine marks the action (result.lateCancel) under a lock of its row: an action that defines this hook
   * dispatches under a lock of that row too and refuses a marked action (the bus of the MDM commands reads the
   * row FOR SHARE and refuses), so that nothing is dispatched once the withdrawal started. Idempotent; throws when
   * the withdrawal could not be completed (the caller asks again).
   */
  cancelAfterDispatch?(ctx: GuardExecutionContext<P>): Promise<Map<number, 'cancelled' | 'already_delivered' | 'completed'>>;
  /** How long after its execution something of the action may still wait for a device (the expiry of what it
   *  dispatched), in seconds: a late cancellation is refused beyond it. Without it: no limit. */
  cancelWindowSeconds?: number;
}

/** Size of a tenant's active fleet (hourly cap, whole fleet). */
export type FleetSizeProvider = (tenantId: number, channel?: ManagementChannel) => Promise<number>;

/** Ownership of devices of a tenant (lot B: devices.ownership); a device
 *  absent from the map is of unknown ownership. */
export type OwnershipProvider = (tenantId: number, deviceIds: number[]) => Promise<Map<number, DeviceOwnership>>;

/** Freeze or unfreeze the commands of a tenant at apple-edge (lot B):
 *  'done', or 'no_edge_tenant' for a tenant apple-edge does not know yet
 *  (its provisioning carries the freeze over). Throws on a failure. */
export type EdgeFreezeHandler = (tenantId: number, frozen: boolean) => Promise<'done' | 'no_edge_tenant'>;

/** What a module does at a freeze or an unfreeze of a tenant, after its commit (the list of actions.edge-freeze-sync,
 *  lot AN-P): 'done', 'nothing' (nothing of the tenant concerned it), or 'no_edge_tenant' (apple-edge does not know
 *  the tenant yet). Idempotent: the job runs every handler again on a retry. Throws on a failure. */
export type FreezeHandler = (tenantId: number, frozen: boolean) => Promise<'done' | 'nothing' | 'no_edge_tenant'>;

/** Summary of pending_actions.result. */
export interface GuardResultSummary {
  done: number;
  failed: number;
  skipped: number;
  /** Targets set aside at revalidation or refused at execution (200 at most). */
  setAside?: Array<{ id: number; code: string }>;
  failures?: Array<{ id: number; code: string }>;
  /** Late cancellation (cancelAfterDispatch), per target something was dispatched for; present once the
   *  withdrawal completed. */
  cancellation?: Array<{ id: number; outcome: string }>;
  /** A late cancellation was requested: written under the lock of the row before anything is withdrawn; from
   *  then on nothing more is dispatched for the action. */
  lateCancel?: GuardLateCancel;
}

/** The mark of a late cancellation (pending_actions.result.lateCancel). */
export interface GuardLateCancel {
  /** ISO date of the request. */
  at: string;
  /** The account that asked. */
  by: number;
  reason?: string;
}

/** The mark of a late cancellation in a result read from the database, or null (any other shape: none). */
export function lateCancelOf(result: unknown): GuardLateCancel | null {
  const m = (result as { lateCancel?: unknown } | null | undefined)?.lateCancel as Partial<GuardLateCancel> | null | undefined;
  if (!m || typeof m !== 'object' || typeof m.at !== 'string' || Number.isNaN(Date.parse(m.at))) return null;
  const by = Number(m.by);
  if (!Number.isSafeInteger(by) || by <= 0) return null;
  return { at: m.at, by, ...(typeof m.reason === 'string' && m.reason ? { reason: m.reason.slice(0, 500) } : {}) };
}

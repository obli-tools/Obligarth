import type { Knex } from 'knex';
import {
  PUBLISH_APPROVAL_THRESHOLDS,
  type ImpactApprovalReason, type PolicyContentV1, type PolicyImpact,
} from '@obligarth/shared';
import { AppError } from '../../middleware/errorHandler';
import { appleCatalog, type AppleCatalogView } from '../apple/catalog';
import { findConflicts } from './conflicts';
import { ancestryWithout, describeKeys, impactDigest, movedAncestry } from './impactPure';
import {
  contributionsOf, devicesOfTargets, loadDevices, loadGroupAncestors, loadPolicyState, loadResources,
  type DeviceSet, type PolicyState,
} from './loader';
import {
  resolveDevices, resourceKey, type ResolutionAssignment, type ResolutionDevice, type ResolvedResource, type ResolvedSetting,
} from './resolver';

// =============================================================================
// Impact preview (docs: modele-donnees-mdm §7.11, PLT-18): the devices a
// change reaches (those of its targets and their subtrees) are resolved twice
// in memory, current state and proposed state, by the same pure function; the
// comparison bears on (setting key, value hash, removed, availability), then
// on the artifacts the settings make. Nothing is written. The thresholds of
// DM23 say whether a second approver is required.
// A change is a version to publish, a batch of assignment changes, or a change
// of the tree of groups (a group moved under another parent, a group deleted):
// the policies are inherited along the ancestry of the groups, so the tree is
// part of the configuration (review of lot B5b, MDM-B5b-C2).
// The preview also has a digest of its content: what the change sets and
// unsets, whatever the number of devices. An approval is given on that content
// (DM10): at its execution the digest must be the one that was approved
// (MDM-B5b-C3).
// =============================================================================

export type AssignmentDelta = { before: ResolutionAssignment | null; after: ResolutionAssignment | null };

export type ProposedChange =
  | { kind: 'version'; policyId: number; versionId: number }
  | { kind: 'assignments'; changes: AssignmentDelta[] }
  /** A group moved under `newParentId` (null: to the root): the ancestry of its whole subtree changes. */
  | { kind: 'group_move'; groupId: number; newParentId: number | null }
  /** A group deleted: its assignments go with it, its devices leave it, its subgroups lose it as an ancestor. */
  | { kind: 'group_delete'; groupId: number };

export type GroupTreeChange = Extract<ProposedChange, { kind: 'group_move' | 'group_delete' }>;

export interface ImpactOptions {
  catalog?: AppleCatalogView;
  /** Level of mdm.policy_publish in the tenant's matrix: 'restricted' asks a second approver whatever the impact. */
  matrixLevel?: 'none' | 'sensitive' | 'restricted';
  /** Devices the sample may show (the caller's scopes); 'all' for an administrator. */
  visibleDeviceIds?: number[] | 'all';
  sampleSize?: number;
}

export interface TouchedDevice { deviceId: number; label: string; added: string[]; changed: string[]; removed: string[] }

export interface ImpactResult {
  impact: PolicyImpact;
  /** Every touched device, by id (the pages of GET /api/mdm/impact/:token/devices). */
  touched: TouchedDevice[];
  /** SHA-256 of what the change sets and unsets (impactPure.ts, impactDigest). */
  digest: string;
}

const KIOSK_LOCK_TYPE = 'com.apple.app.lock';

type Target = { scope: 'tenant' | 'group' | 'device'; id: number | null };

interface Proposal {
  proposed: PolicyState;
  targets: Target[];
  /** The resources the change is about; null for a change of the tree, which is about none in particular. */
  focus: Set<string> | null;
  /** The devices and the ancestry of their groups once the tree has changed. */
  reshape?: (set: DeviceSet) => DeviceSet;
}

/** The groups of the subtree of a group (itself at depth 0), from the closure; 404 when the tenant has no such group. */
async function subtreeOf(q: Knex | Knex.Transaction, tenantId: number, groupId: number): Promise<Map<number, number>> {
  const rows = await q('device_group_closure').where({ tenant_id: tenantId, ancestor_id: groupId })
    .select('descendant_id', 'depth') as Array<{ descendant_id: number; depth: number }>;
  if (!rows.length) throw new AppError(404, 'Group not found');
  return new Map(rows.map((r) => [Number(r.descendant_id), Number(r.depth)]));
}

/** The proposed state of a change of the tree of groups, as the base will hold it once the change is written. */
async function proposedTree(q: Knex | Knex.Transaction, tenantId: number, state: PolicyState, change: GroupTreeChange): Promise<Proposal> {
  const subtree = await subtreeOf(q, tenantId, change.groupId);
  const targets: Target[] = [{ scope: 'group', id: change.groupId }];
  if (change.kind === 'group_move') {
    let parentLine: Array<{ groupId: number; depth: number }> = [];
    if (change.newParentId !== null) {
      if (subtree.has(change.newParentId)) throw new AppError(400, 'Cannot move group into its own descendant');
      parentLine = (await loadGroupAncestors(q, tenantId, [change.newParentId])).get(change.newParentId) ?? [];
      if (!parentLine.length) throw new AppError(400, 'Parent group not found');
    }
    return {
      proposed: state, targets, focus: null,
      reshape: (set) => ({ devices: set.devices, groupAncestors: movedAncestry(set.groupAncestors, subtree, parentLine) }),
    };
  }
  // A deleted group: its assignments are deleted with it (assignments_cleanup), its devices have no group any more
  // (devices_group_id_tenant_fk), and the closure loses its rows: the groups below it no longer have it as an ancestor.
  const gone = change.groupId;
  return {
    proposed: { ...state, assignments: state.assignments.filter((a) => !(a.targetScope === 'group' && a.targetId === gone)) },
    targets,
    focus: null,
    reshape: (set) => ({
      devices: set.devices.map((d) => (d.groupId === gone ? { ...d, groupId: null } : d)),
      groupAncestors: ancestryWithout(set.groupAncestors, gone),
    }),
  };
}

/** The proposed state of a change, the targets it reaches and the resources it changes. */
async function proposedState(q: Knex | Knex.Transaction, tenantId: number, state: PolicyState, change: ProposedChange,
  catalog: AppleCatalogView): Promise<Proposal> {
  if (change.kind === 'group_move' || change.kind === 'group_delete') return proposedTree(q, tenantId, state, change);
  if (change.kind === 'version') {
    const v = await q('policy_versions as v').join('policies as p', function joinPolicy() { this.on('p.id', '=', 'v.policy_id').andOn('p.tenant_id', '=', 'v.tenant_id'); })
      .where({ 'v.tenant_id': tenantId, 'v.id': change.versionId, 'v.policy_id': change.policyId })
      .first('v.id', 'v.content', 'v.state', 'p.uuid', 'p.name') as { id: number; content: unknown; state: string; uuid: string; name: string } | undefined;
    if (!v) throw new AppError(404, 'Policy version not found');
    const rk = resourceKey('policy', tenantId, change.policyId);
    const resources = new Map(state.resources);
    const content = (typeof v.content === 'string' ? JSON.parse(v.content) : v.content) as PolicyContentV1;
    const res: ResolvedResource = {
      type: 'policy', id: change.policyId, tenantId, versionId: Number(v.id), name: v.name,
      contributions: contributionsOf(tenantId, { id: Number(v.id), content, state: v.state }, v.uuid, catalog),
    };
    resources.set(rk, res);
    const targets = state.assignments.filter((a) => a.resourceType === 'policy' && a.resourceTenantId === tenantId && a.resourceId === change.policyId)
      .map((a) => ({ scope: a.targetScope, id: a.targetId }));
    return { proposed: { ...state, resources }, targets, focus: new Set([rk]) };
  }
  let assignments = [...state.assignments];
  const targets: Target[] = [];
  const focus = new Set<string>();
  for (const ch of change.changes) {
    if (ch.before) {
      assignments = assignments.filter((a) => a.id !== ch.before!.id);
      targets.push({ scope: ch.before.targetScope, id: ch.before.targetId });
      focus.add(resourceKey(ch.before.resourceType, ch.before.resourceTenantId, ch.before.resourceId));
    }
    if (ch.after) {
      assignments.push(ch.after);
      targets.push({ scope: ch.after.targetScope, id: ch.after.targetId });
      focus.add(resourceKey(ch.after.resourceType, ch.after.resourceTenantId, ch.after.resourceId));
    }
  }
  const resources = await loadResources(q, tenantId, assignments, catalog);
  return { proposed: { ...state, assignments, resources }, targets, focus };
}

/** Comparable state of a setting for the diff. */
const settingState = (s: ResolvedSetting): string =>
  `${s.valueHash}|${s.removed ? 1 : 0}|${s.availability.status}|${s.availability.status === 'not_applicable' ? s.availability.reason : ''}`;

/** The artifacts of a device's settings: artifact key → (signature, type), of the available settings not removed. */
function artifactsOf(settings: ResolvedSetting[]): Map<string, { sig: string; type: string; kind: string }> {
  const parts = new Map<string, { list: string[]; type: string; kind: string }>();
  for (const s of settings) {
    if (s.removed || s.availability.status !== 'available' || !s.artifactKey) continue;
    const p = parts.get(s.artifactKey) ?? { list: [], type: s.type, kind: s.kind };
    p.list.push(`${s.settingKey}=${s.valueHash}`);
    parts.set(s.artifactKey, p);
  }
  const out = new Map<string, { sig: string; type: string; kind: string }>();
  for (const [k, p] of parts) out.set(k, { sig: p.list.sort().join('\n'), type: p.type, kind: p.kind });
  return out;
}

const sourceOf = (s: ResolvedSetting): string => resourceKey(s.source.type, s.source.tenantId, s.source.id);

const appliesResource = (settings: ResolvedSetting[], focus: Set<string>): boolean => settings.some((s) => focus.has(sourceOf(s)));

/** computeImpact(tenantId, change): the preview of a change, in the caller's database context (section 7.11). */
export async function computeImpact(q: Knex | Knex.Transaction, tenantId: number, change: ProposedChange,
  opts: ImpactOptions = {}): Promise<ImpactResult> {
  const catalog = opts.catalog ?? appleCatalog();
  const state = await loadPolicyState(q, tenantId, catalog);
  const { proposed, targets, focus, reshape } = await proposedState(q, tenantId, state, change, catalog);
  const deviceIds = targets.length ? await devicesOfTargets(q, tenantId, targets) : [];
  const current: DeviceSet = deviceIds.length ? await loadDevices(q, tenantId, deviceIds) : { devices: [] as ResolutionDevice[], groupAncestors: new Map() };
  const next = reshape ? reshape(current) : current;
  const { devices } = current;
  const before = resolveDevices({ ...state, devices, groupAncestors: current.groupAncestors, catalog });
  const after = resolveDevices({ ...proposed, devices: next.devices, groupAncestors: next.groupAncestors, catalog });

  const keys = new Map<string, { added: number; changed: number; removed: number; notApplicable: number }>();
  const keyStat = (k: string) => {
    let s = keys.get(k);
    if (!s) { s = { added: 0, changed: 0, removed: 0, notApplicable: 0 }; keys.set(k, s); }
    return s;
  };
  const artifacts = { installs: 0, removals: 0, kioskLockChanges: 0, appRemovals: 0 };
  let devicesAdded = 0;
  let devicesRemoved = 0;
  let removalDevices = 0;
  const touched: TouchedDevice[] = [];
  const content = new Set<string>();
  const labelOf = new Map(devices.map((d) => [d.id, d.label]));
  for (let i = 0; i < devices.length; i++) {
    const b = before.devices[i].settings;
    const a = after.devices[i].settings;
    const bm = new Map(b.map((s) => [s.settingKey, s]));
    const am = new Map(a.map((s) => [s.settingKey, s]));
    const added: string[] = [];
    const changed: string[] = [];
    const removed: string[] = [];
    for (const [k, s] of am) {
      const p = bm.get(k);
      const differs = !!p && settingState(p) !== settingState(s);
      if (!p) { added.push(k); keyStat(k).added++; } else if (differs) { changed.push(k); keyStat(k).changed++; }
      if (!p || differs) content.add(`S|${k}|${s.valueHash}|${s.removed ? 1 : 0}`);
      if (s.availability.status === 'not_applicable' && (!p || differs)) keyStat(k).notApplicable++;
    }
    for (const k of bm.keys()) {
      if (am.has(k)) continue;
      removed.push(k);
      keyStat(k).removed++;
      content.add(`U|${k}`);
    }
    if (added.length || changed.length || removed.length) {
      touched.push({ deviceId: devices[i].id, label: labelOf.get(devices[i].id) ?? '', added, changed, removed });
    }
    if (focus) {
      const wasApplying = appliesResource(b, focus);
      const isApplying = appliesResource(a, focus);
      if (!wasApplying && isApplying) devicesAdded++;
      if (wasApplying && !isApplying) devicesRemoved++;
    } else {
      // A change of the tree: the device gains a resource, or loses one.
      const was = new Set(b.map(sourceOf));
      const is = new Set(a.map(sourceOf));
      if ([...is].some((k) => !was.has(k))) devicesAdded++;
      if ([...was].some((k) => !is.has(k))) devicesRemoved++;
    }
    // Artifacts: installed or changed, removed (kiosk locks and apps counted apart).
    const ba = artifactsOf(b);
    const aa = artifactsOf(a);
    let removal = false;
    for (const [k, x] of aa) {
      const p = ba.get(k);
      if (!p || p.sig !== x.sig) {
        artifacts.installs++;
        if (x.type === KIOSK_LOCK_TYPE) artifacts.kioskLockChanges++;
      }
    }
    for (const [k, x] of ba) {
      if (aa.has(k)) continue;
      artifacts.removals++;
      removal = true;
      if (x.type === KIOSK_LOCK_TYPE) artifacts.kioskLockChanges++;
      if (x.kind === 'app') artifacts.appRemovals++;
    }
    if (removal) removalDevices++;
  }

  // A change of the tree sets no two values at one target: the conflicts are those of the assignments (section 7.7).
  const conflicts = focus ? findConflicts(proposed.assignments, proposed.resources, { focus }) : [];
  const fleet = await q('devices').where({ tenant_id: tenantId }).whereNot('enrollment_state', 'unenrolled').count({ n: '*' }).first() as { n: string | number };
  const fleetSize = Number(fleet?.n ?? 0);
  const T = PUBLISH_APPROVAL_THRESHOLDS;
  const reasons: ImpactApprovalReason[] = [];
  if (touched.length >= T.devicesTouched) reasons.push('devices_threshold');
  if (touched.length > 0 && fleetSize > 0 && touched.length >= T.fleetShare * fleetSize) reasons.push('fleet_share');
  if (removalDevices >= T.removalDevices) reasons.push('removal_threshold');
  if (opts.matrixLevel === 'restricted') reasons.push('restriction');

  const visible = opts.visibleDeviceIds ?? 'all';
  const visibleSet = visible === 'all' ? null : new Set(visible);
  const sample = touched.filter((t) => !visibleSet || visibleSet.has(t.deviceId)).slice(0, opts.sampleSize ?? 50);
  const impact: PolicyImpact = {
    computedAt: new Date().toISOString(),
    devicesInScope: devices.length,
    devicesTouched: touched.length,
    devicesAdded,
    devicesRemoved,
    keys: [...keys.entries()].sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)).map(([settingKey, s]) => ({ settingKey, ...s })),
    artifacts,
    conflicts,
    sample,
    fleetSize,
    approval: { required: reasons.length > 0, reasons },
    removalDevices,
  };
  return { impact, touched, digest: impactDigest(content) };
}

/** The conflicts a change would create (section 7.7), without resolving any device. */
export async function conflictsOf(q: Knex | Knex.Transaction, tenantId: number, change: ProposedChange,
  catalog: AppleCatalogView = appleCatalog()): Promise<PolicyImpact['conflicts']> {
  const state = await loadPolicyState(q, tenantId, catalog);
  const { proposed, focus } = await proposedState(q, tenantId, state, change, catalog);
  return focus ? findConflicts(proposed.assignments, proposed.resources, { focus }) : [];
}

/** Has an impact grown beyond the tolerance since it was approved (touched devices or removals, DM23)? */
export function impactGrew(approved: Pick<PolicyImpact, 'devicesTouched' | 'artifacts'>, now: Pick<PolicyImpact, 'devicesTouched' | 'artifacts'>): boolean {
  const tol = 1 + PUBLISH_APPROVAL_THRESHOLDS.recheckTolerance;
  // removals counts every artifact removed, kiosk locks and apps included.
  return now.devicesTouched > approved.devicesTouched * tol || now.artifacts.removals > approved.artifacts.removals * tol;
}

/** The summary of an impact kept with an approval (counters only). */
export function impactSummary(i: PolicyImpact): Record<string, unknown> {
  return {
    devicesInScope: i.devicesInScope, devicesTouched: i.devicesTouched, devicesAdded: i.devicesAdded, devicesRemoved: i.devicesRemoved,
    artifacts: i.artifacts, removalDevices: i.removalDevices ?? 0, fleetSize: i.fleetSize, conflicts: i.conflicts.length,
    reasons: i.approval.reasons,
  };
}

/** Keys of a preview kept in the payload of a request, shown to its reviewers. */
const APPROVAL_KEYS_MAX = 100;

/**
 * What a request for approval keeps of its preview, read by its reviewers and by its executor: the counters, the
 * keys the change adds, changes and removes (their names and counts, never a value), and the digest of the content
 * the approval is given on.
 */
export function approvalImpact(r: ImpactResult): Record<string, unknown> {
  return {
    ...impactSummary(r.impact),
    keys: r.impact.keys.slice(0, APPROVAL_KEYS_MAX),
    keysTotal: r.impact.keys.length,
    digest: r.digest,
  };
}

export { describeKeys };

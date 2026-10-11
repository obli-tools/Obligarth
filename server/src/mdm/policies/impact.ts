import type { Knex } from 'knex';
import {
  PUBLISH_APPROVAL_THRESHOLDS,
  type ImpactApprovalReason, type PolicyContentV1, type PolicyImpact,
} from '@obligarth/shared';
import { AppError } from '../../middleware/errorHandler';
import { appleCatalog, type AppleCatalogView } from '../apple/catalog';
import { findConflicts } from './conflicts';
import { contributionsOf, devicesOfTargets, loadDevices, loadPolicyState, loadResources, type PolicyState } from './loader';
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
// =============================================================================

export type AssignmentDelta = { before: ResolutionAssignment | null; after: ResolutionAssignment | null };

export type ProposedChange =
  | { kind: 'version'; policyId: number; versionId: number }
  | { kind: 'assignments'; changes: AssignmentDelta[] };

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
}

const KIOSK_LOCK_TYPE = 'com.apple.app.lock';

/** The proposed state of a change, the targets it reaches and the resources it changes. */
async function proposedState(q: Knex | Knex.Transaction, tenantId: number, state: PolicyState, change: ProposedChange,
  catalog: AppleCatalogView): Promise<{ proposed: PolicyState; targets: Array<{ scope: 'tenant' | 'group' | 'device'; id: number | null }>; focus: Set<string> }> {
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
  const targets: Array<{ scope: 'tenant' | 'group' | 'device'; id: number | null }> = [];
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

const appliesResource = (settings: ResolvedSetting[], focus: Set<string>): boolean =>
  settings.some((s) => focus.has(resourceKey(s.source.type, s.source.tenantId, s.source.id)));

/** computeImpact(tenantId, change): the preview of a change, in the caller's database context (section 7.11). */
export async function computeImpact(q: Knex | Knex.Transaction, tenantId: number, change: ProposedChange,
  opts: ImpactOptions = {}): Promise<ImpactResult> {
  const catalog = opts.catalog ?? appleCatalog();
  const state = await loadPolicyState(q, tenantId, catalog);
  const { proposed, targets, focus } = await proposedState(q, tenantId, state, change, catalog);
  const deviceIds = targets.length ? await devicesOfTargets(q, tenantId, targets) : [];
  const { devices, groupAncestors } = deviceIds.length ? await loadDevices(q, tenantId, deviceIds) : { devices: [] as ResolutionDevice[], groupAncestors: new Map() };
  const before = resolveDevices({ ...state, devices, groupAncestors, catalog });
  const after = resolveDevices({ ...proposed, devices, groupAncestors, catalog });

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
      if (!p) { added.push(k); keyStat(k).added++; } else if (settingState(p) !== settingState(s)) { changed.push(k); keyStat(k).changed++; }
      if (s.availability.status === 'not_applicable' && (!p || settingState(p) !== settingState(s))) keyStat(k).notApplicable++;
    }
    for (const k of bm.keys()) if (!am.has(k)) { removed.push(k); keyStat(k).removed++; }
    if (added.length || changed.length || removed.length) {
      touched.push({ deviceId: devices[i].id, label: labelOf.get(devices[i].id) ?? '', added, changed, removed });
    }
    const wasApplying = appliesResource(b, focus);
    const isApplying = appliesResource(a, focus);
    if (!wasApplying && isApplying) devicesAdded++;
    if (wasApplying && !isApplying) devicesRemoved++;
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

  const conflicts = findConflicts(proposed.assignments, proposed.resources, { focus });
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
  return { impact, touched };
}

/** The conflicts a change would create (section 7.7), without resolving any device. */
export async function conflictsOf(q: Knex | Knex.Transaction, tenantId: number, change: ProposedChange,
  catalog: AppleCatalogView = appleCatalog()): Promise<PolicyImpact['conflicts']> {
  const state = await loadPolicyState(q, tenantId, catalog);
  const { proposed, focus } = await proposedState(q, tenantId, state, change, catalog);
  return findConflicts(proposed.assignments, proposed.resources, { focus });
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

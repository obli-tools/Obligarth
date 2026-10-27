import type { AssignmentTargetScope, PolicyConflict, SourceScope } from '@obligarth/shared';
import { preferredActivityConflicts } from '../android/validate';
import { appContribution, type Contribution } from './contributions';
import {
  androidAppAssignmentContribution, indexAssignments, resourceKey, scopesOf,
  type ResolutionAssignment, type ResolutionInput, type ResolvedResource,
} from './resolver';

// =============================================================================
// Conflicts at write time (docs: modele-donnees-mdm §7.7, §7.13). Without
// dynamic groups (one group per device), two contributions of the same rank
// come from the same target: the check is complete without enumerating
// devices. For each target, the resources included there with the same
// priority are compared key by key; two different value hashes for one
// setting key are a conflict, refused (422 policyConflict) at the write of an
// assignment, at the submission of a version and at a change of priority.
// `focus`: only the conflicts that involve one of the resources being changed
// (an older conflict elsewhere does not block an unrelated change; the
// resolution breaks it and lists it).
// A dynamic group (P0-5 T6, D1) ranks as the static group a device is directly
// in, and the groups overlap: two targets meet on the devices of their
// intersection. findConflicts keeps comparing each target, dynamic groups
// included (their assignments conflict on every member, present or future);
// findDeviceConflicts compares, device by device, the inclusions of one rank
// and one priority that come from two targets or more (exclusions applied, as
// the resolution does), once per distinct set of such inclusions: this
// enumerates the current intersection. A change is refused for the conflicts
// it creates on a device (newDeviceConflicts: absent from the current state on
// that device); an overlap that appears later (a device entering a group) is
// broken at run time by the resolution and raised as policy.conflict.
// Android (android-amapi §9.7, REV-C1a-4; lot AN-A2): a persistent preferred activity of one resource and a default
// application of another on the same intent domain are a conflict too (two keys, one effect on the device),
// reported under android:persistentPreferredActivities.
// =============================================================================

const SCOPE_OF: Record<AssignmentTargetScope, SourceScope> = { tenant: 'tenant', group: 'group', device: 'device', smart_group: 'smart_group' };

export function contributionsFor(res: ResolvedResource, a: ResolutionAssignment): Contribution[] {
  if (res.type === 'app' && res.app?.platformFamily === 'android') return [androidAppAssignmentContribution(res.app.identifier, a.options ?? {})];
  return res.type === 'app' && res.app ? [appContribution(res.app, a.options ?? {})] : res.contributions;
}

type Holder = { res: ResolvedResource; a: ResolutionAssignment };
type Holders = Map<string, Map<string, Holder[]>>;

/** A setting key that inclusions of one rank and one priority set to two values (or more), with who brings each. */
interface KeyConflict { settingKey: string; involved: Holder[] }

const rkOf = (x: Holder): string => resourceKey(x.res.type, x.res.tenantId, x.res.id);
const rkOfAssignment = (a: ResolutionAssignment): string => resourceKey(a.resourceType, a.resourceTenantId, a.resourceId);

/** The keys a list of inclusions (one target, or one rank of a device, at one priority) sets to two values. */
function compareInclusions(list: ResolutionAssignment[], resources: Map<string, ResolvedResource>, focus?: ReadonlySet<string>): KeyConflict[] {
  // setting key → value hash → resources bringing it
  const byKey: Holders = new Map();
  for (const a of list) {
    const res = resources.get(rkOfAssignment(a));
    if (!res) continue;
    for (const c of contributionsFor(res, a)) {
      const hashes = byKey.get(c.settingKey) ?? new Map<string, Holder[]>();
      const h = `${c.removed ? 'r' : 'v'}:${c.valueHash}`;
      const who = hashes.get(h) ?? [];
      who.push({ res, a });
      hashes.set(h, who);
      byKey.set(c.settingKey, hashes);
    }
  }
  preferredActivitiesConflict(byKey);
  const out: KeyConflict[] = [];
  for (const [settingKey, hashes] of byKey) {
    if (hashes.size < 2) continue;
    const involved = [...hashes.values()].flat();
    if (focus && !involved.some((x) => focus.has(rkOf(x)))) continue;
    out.push({ settingKey, involved });
  }
  return out;
}

/** The resources of a conflict, once each, by id. */
function resourcesOf(involved: Holder[]): PolicyConflict['resources'] {
  const seen = new Set<string>();
  const out: PolicyConflict['resources'] = [];
  for (const x of [...involved].sort((p, q) => p.res.id - q.res.id)) {
    const rk = rkOf(x);
    if (seen.has(rk)) continue;
    seen.add(rk);
    out.push({ type: x.res.type, id: x.res.id, name: x.res.name });
  }
  return out;
}

const byKeyTargetPriority = (x: PolicyConflict, y: PolicyConflict): number => (x.settingKey < y.settingKey ? -1 : x.settingKey > y.settingKey ? 1 : 0)
  || x.target.scope.localeCompare(y.target.scope) || Number(x.target.id ?? 0) - Number(y.target.id ?? 0) || x.priority - y.priority;

export function findConflicts(assignments: ResolutionAssignment[], resources: Map<string, ResolvedResource>,
  opts: { focus?: ReadonlySet<string> } = {}): PolicyConflict[] {
  const groups = new Map<string, ResolutionAssignment[]>();
  for (const a of assignments) {
    if (a.mode !== 'include') continue;
    const k = `${a.targetScope}:${a.targetScope === 'tenant' ? '' : a.targetId}:${a.priority}`;
    const list = groups.get(k);
    if (list) list.push(a); else groups.set(k, [a]);
  }
  const out: PolicyConflict[] = [];
  for (const list of groups.values()) {
    if (list.length < 2) continue;
    if (opts.focus && !list.some((a) => opts.focus!.has(rkOfAssignment(a)))) continue;
    for (const { settingKey, involved } of compareInclusions(list, resources, opts.focus)) {
      const a0 = involved[0].a;
      out.push({
        settingKey,
        target: { scope: SCOPE_OF[a0.targetScope], id: a0.targetScope === 'tenant' ? null : a0.targetId },
        priority: a0.priority,
        resources: resourcesOf(involved),
      });
    }
  }
  return out.sort(byKeyTargetPriority);
}

// ── Per device (P0-5 T6) ─────────────────────────────────────────────────────

/** What the per-device check reads: the devices (with their dynamic groups), the ancestry of their groups, the
 *  assignments and their resources (a state of the tenant, current or proposed). */
export type DeviceConflictInput = Pick<ResolutionInput, 'devices' | 'groupAncestors' | 'assignments' | 'resources'>;

/** A conflict between targets on devices: the conflict (its targets listed) and the devices where it holds. */
export interface DeviceConflict { conflict: PolicyConflict; deviceIds: Set<number> }

/** The identity of a conflict, whatever its targets and its devices: key, priority, resources. */
export const conflictIdentity = (c: Pick<PolicyConflict, 'settingKey' | 'priority' | 'resources'>): string =>
  `${c.settingKey}|${c.priority}|${c.resources.map((r) => `${r.type}:${r.id}`).sort().join(',')}`;

const SCOPE_ORDER: SourceScope[] = ['device', 'group', 'smart_group', 'tenant', 'library'];
const byTarget = (x: { scope: SourceScope; id: number | null }, y: { scope: SourceScope; id: number | null }): number =>
  SCOPE_ORDER.indexOf(x.scope) - SCOPE_ORDER.indexOf(y.scope) || Number(x.id ?? 0) - Number(y.id ?? 0);

/** Does a state hold an assignment to a dynamic group (the only way two targets meet at one rank on a device)? */
export const hasSmartGroupTargets = (assignments: ResolutionAssignment[]): boolean => assignments.some((a) => a.targetScope === 'smart_group');

/**
 * The conflicts of the devices of `input` between inclusions of one rank and one priority that come from two targets or
 * more (a dynamic group and the device's own static group, or another dynamic group), after the exclusions of the
 * device, as the resolution sees them; by identity (conflictIdentity), with the devices where each holds. The
 * inclusions of a single target are findConflicts's. `focus`: only the conflicts that involve one of these resources.
 */
export function findDeviceConflicts(input: DeviceConflictInput, opts: { focus?: ReadonlySet<string> } = {}): Map<string, DeviceConflict> {
  const out = new Map<string, DeviceConflict>();
  if (!hasSmartGroupTargets(input.assignments)) return out;
  const index = indexAssignments(input.assignments);
  // One comparison per distinct set of inclusions (the devices with the same groups share it).
  const cache = new Map<string, KeyConflict[]>();
  for (const d of input.devices) {
    const included: Array<{ a: ResolutionAssignment; rank: number }> = [];
    const excluded = new Set<string>();
    for (const s of scopesOf(d, input.groupAncestors)) {
      for (const a of index.get(s.target) ?? []) {
        if (a.mode === 'exclude') excluded.add(rkOfAssignment(a));
        else included.push({ a, rank: s.rank });
      }
    }
    const buckets = new Map<string, ResolutionAssignment[]>();
    for (const m of included) {
      if (excluded.has(rkOfAssignment(m.a))) continue;
      const k = `${m.rank}:${m.a.priority}`;
      const list = buckets.get(k);
      if (list) list.push(m.a); else buckets.set(k, [m.a]);
    }
    for (const list of buckets.values()) {
      if (list.length < 2) continue;
      if (new Set(list.map((a) => `${a.targetScope}:${a.targetId ?? ''}`)).size < 2) continue;
      if (opts.focus && !list.some((a) => opts.focus!.has(rkOfAssignment(a)))) continue;
      const sig = list.map((a) => a.id).sort((x, y) => x - y).join(',');
      let found = cache.get(sig);
      if (!found) {
        found = compareInclusions(list, input.resources, opts.focus);
        cache.set(sig, found);
      }
      for (const { settingKey, involved } of found) {
        const resources = resourcesOf(involved);
        const priority = involved[0].a.priority;
        const id = conflictIdentity({ settingKey, priority, resources });
        let entry = out.get(id);
        if (!entry) {
          entry = { conflict: { settingKey, target: { scope: 'smart_group', id: null }, priority, resources, targets: [] }, deviceIds: new Set() };
          out.set(id, entry);
        }
        entry.deviceIds.add(d.id);
        const targets = entry.conflict.targets!;
        for (const x of involved) {
          const t = { scope: SCOPE_OF[x.a.targetScope], id: x.a.targetScope === 'tenant' ? null : x.a.targetId };
          if (!targets.some((y) => y.scope === t.scope && y.id === t.id)) targets.push(t);
        }
      }
    }
  }
  for (const e of out.values()) {
    const targets = e.conflict.targets!.sort(byTarget);
    // The target shown: the first dynamic group involved (why the targets meet), else the first target.
    e.conflict.target = targets.find((t) => t.scope === 'smart_group') ?? targets[0];
  }
  return out;
}

/**
 * The conflicts per device a change creates: those of the proposed state on a device where the current state does not
 * have them (same identity), with the number of such devices. An overlap already in conflict on a device (appeared at
 * run time, broken by the resolution) does not block an unrelated change; a change that brings it to other devices is
 * refused for those. The conflicts findConflicts already lists (`listed`, same identity) are left out. Sorted as
 * findConflicts.
 */
export function newDeviceConflicts(current: DeviceConflictInput, proposed: DeviceConflictInput,
  opts: { focus?: ReadonlySet<string>; listed?: PolicyConflict[] } = {}): PolicyConflict[] {
  const after = findDeviceConflicts(proposed, opts);
  if (!after.size) return [];
  const before = findDeviceConflicts(current, opts);
  const listed = new Set((opts.listed ?? []).map(conflictIdentity));
  const out: PolicyConflict[] = [];
  for (const [id, e] of after) {
    if (listed.has(id)) continue;
    const had = before.get(id)?.deviceIds;
    const fresh = had ? [...e.deviceIds].filter((d) => !had.has(d)).length : e.deviceIds.size;
    if (fresh > 0) out.push({ ...e.conflict, devices: fresh });
  }
  return out.sort(byKeyTargetPriority);
}

const PREFERRED = 'android:persistentPreferredActivities';
const DEFAULTS = 'android:defaultApplicationSettings';

/** Adds, under android:persistentPreferredActivities, the resources of a default application that claims the domain
 *  of a preferred activity of another resource (same target, same priority). */
function preferredActivitiesConflict(byKey: Holders): void {
  const preferred = byKey.get(PREFERRED);
  const defaults = byKey.get(DEFAULTS);
  if (!preferred || !defaults) return;
  const valueOf = (x: Holder, key: string): unknown =>
    contributionsFor(x.res, x.a).find((c) => c.settingKey === key)?.value;
  for (const ps of [...preferred.values()]) {
    for (const p of ps) {
      for (const [hd, ds] of defaults.entries()) {
        for (const d of ds) {
          if (d.res === p.res) continue;   // one section: its validation refuses it
          if (!preferredActivityConflicts(valueOf(p, PREFERRED), valueOf(d, DEFAULTS)).length) continue;
          const tag = `d:${hd}`;
          const who = preferred.get(tag) ?? [];
          if (!who.some((x) => x.res === d.res)) who.push(d);
          preferred.set(tag, who);
        }
      }
    }
  }
}

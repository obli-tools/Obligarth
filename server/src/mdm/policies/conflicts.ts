import type { PolicyConflict, SourceScope } from '@obligarth/shared';
import { appContribution, type Contribution } from './contributions';
import { resourceKey, type ResolutionAssignment, type ResolvedResource } from './resolver';

// =============================================================================
// Conflicts at write time (docs: modele-donnees-mdm §7.7). With one group per
// device (MVP), two contributions of the same rank come from the same target:
// the check is complete without enumerating devices. For each target, the
// resources included there with the same priority are compared key by key;
// two different value hashes for one setting key are a conflict, refused
// (422 policyConflict) at the write of an assignment, at the submission of a
// version and at a change of priority. `focus`: only the conflicts that
// involve one of the resources being changed (an older conflict elsewhere
// does not block an unrelated change; the resolution breaks it and lists it).
// =============================================================================

const SCOPE_OF: Record<ResolutionAssignment['targetScope'], SourceScope> = { tenant: 'tenant', group: 'group', device: 'device' };

export function contributionsFor(res: ResolvedResource, a: ResolutionAssignment): Contribution[] {
  return res.type === 'app' && res.app ? [appContribution(res.app, a.options ?? {})] : res.contributions;
}

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
    if (opts.focus && !list.some((a) => opts.focus!.has(resourceKey(a.resourceType, a.resourceTenantId, a.resourceId)))) continue;
    // setting key → value hash → resources bringing it
    const byKey = new Map<string, Map<string, Array<{ res: ResolvedResource; a: ResolutionAssignment }>>>();
    for (const a of list) {
      const res = resources.get(resourceKey(a.resourceType, a.resourceTenantId, a.resourceId));
      if (!res) continue;
      for (const c of contributionsFor(res, a)) {
        const hashes = byKey.get(c.settingKey) ?? new Map<string, Array<{ res: ResolvedResource; a: ResolutionAssignment }>>();
        const h = `${c.removed ? 'r' : 'v'}:${c.valueHash}`;
        const who = hashes.get(h) ?? [];
        who.push({ res, a });
        hashes.set(h, who);
        byKey.set(c.settingKey, hashes);
      }
    }
    for (const [settingKey, hashes] of byKey) {
      if (hashes.size < 2) continue;
      const involved = [...hashes.values()].flat();
      if (opts.focus && !involved.some((x) => opts.focus!.has(resourceKey(x.res.type, x.res.tenantId, x.res.id)))) continue;
      const a0 = involved[0].a;
      const seen = new Set<string>();
      const resourcesOut: PolicyConflict['resources'] = [];
      for (const x of involved.sort((p, q) => p.res.id - q.res.id)) {
        const rk = resourceKey(x.res.type, x.res.tenantId, x.res.id);
        if (seen.has(rk)) continue;
        seen.add(rk);
        resourcesOut.push({ type: x.res.type, id: x.res.id, name: x.res.name });
      }
      out.push({
        settingKey,
        target: { scope: SCOPE_OF[a0.targetScope], id: a0.targetScope === 'tenant' ? null : a0.targetId },
        priority: a0.priority,
        resources: resourcesOut,
      });
    }
  }
  return out.sort((x, y) => (x.settingKey < y.settingKey ? -1 : x.settingKey > y.settingKey ? 1 : 0)
    || x.target.scope.localeCompare(y.target.scope) || Number(x.target.id ?? 0) - Number(y.target.id ?? 0) || x.priority - y.priority);
}

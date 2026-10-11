import { createHash } from 'node:crypto';
import type { PolicyImpact } from '@obligarth/shared';

// =============================================================================
// The pure parts of the impact preview (docs: modele-donnees-mdm §7.11; review
// of lot B5b, MDM-B5b-C2 and C3), without the database: the ancestry of the
// groups once the tree has changed, the digest of the content of a preview,
// its keys in the words of a request. impact.ts reads the tenant and calls
// them.
// =============================================================================

/** For each group: its ancestors with their depth (the group itself at depth 0), as the closure holds them. */
export type GroupAncestry = Map<number, Array<{ groupId: number; depth: number }>>;

/**
 * The ancestry of the groups of a subtree once its root hangs under a new parent: what lies inside the subtree
 * stays, the line of the new parent (itself at depth 0, empty for the root of the tree) comes above it. Same
 * arithmetic as the rewrite of the closure by groupService.move. `subtree`: each group of the subtree with its
 * depth below the moved group (0 for the moved group itself).
 */
export function movedAncestry(groupAncestors: GroupAncestry, subtree: ReadonlyMap<number, number>,
  parentLine: ReadonlyArray<{ groupId: number; depth: number }>): GroupAncestry {
  const out: GroupAncestry = new Map(groupAncestors);
  for (const [groupId, within] of subtree) {
    const inside = (groupAncestors.get(groupId) ?? [{ groupId, depth: 0 }]).filter((a) => subtree.has(a.groupId));
    out.set(groupId, [...inside, ...parentLine.map((p) => ({ groupId: p.groupId, depth: p.depth + within + 1 }))]);
  }
  return out;
}

/**
 * The ancestry of the groups once a group is deleted, as the base leaves it: the closure loses the rows of the
 * group (ON DELETE CASCADE), so the groups below it no longer have it as an ancestor; nothing else is rewritten.
 */
export function ancestryWithout(groupAncestors: GroupAncestry, gone: number): GroupAncestry {
  const out: GroupAncestry = new Map();
  for (const [groupId, list] of groupAncestors) {
    if (groupId !== gone) out.set(groupId, list.filter((a) => a.groupId !== gone));
  }
  return out;
}

/**
 * The digest of the content of a preview: the SHA-256 of the sorted set of what the change does to a device, all
 * touched devices together: a key set to a value ('S', its key, the hash of its value, removed or not) or a key
 * that no longer applies ('U', its key). Neither a device, nor a count, nor an availability: the fleet may move
 * between a request and its approval (the tolerance of DM23 measures that), the content approved may not.
 */
export function impactDigest(parts: Iterable<string>): string {
  return createHash('sha256').update([...new Set(parts)].sort().join('\n'), 'utf8').digest('hex');
}

/**
 * The keys of a preview in a few words, for the description of a request ("key (+added ~changed -removed)"). The
 * description is journaled with the request (approval.requested): the instance of a collection (an SSID, the
 * identifier of an app) is a value of the content and stays out of it ("type[…]", the instances of a type counted
 * together); the payload of the request, read by its reviewers, carries the full keys.
 */
export function describeKeys(i: PolicyImpact, max = 6): string {
  if (!i.keys.length) return 'no key changed';
  const byName = new Map<string, { added: number; changed: number; removed: number }>();
  for (const k of i.keys) {
    const name = k.settingKey.replace(/\[[\s\S]*\]$/, '[…]');
    const s = byName.get(name) ?? { added: 0, changed: 0, removed: 0 };
    s.added += k.added;
    s.changed += k.changed;
    s.removed += k.removed;
    byName.set(name, s);
  }
  const parts = [...byName].map(([name, k]) =>
    `${name} (${[k.added ? `+${k.added}` : '', k.changed ? `~${k.changed}` : '', k.removed ? `-${k.removed}` : ''].filter(Boolean).join(' ') || '0'})`);
  const shown = parts.slice(0, max).join(', ');
  return parts.length > max ? `${shown} (+${parts.length - max} more)` : shown;
}

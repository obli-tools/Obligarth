import type { Knex } from 'knex';
import {
  AGENT_KIOSK_KEY, PUBLISH_APPROVAL_THRESHOLDS,
  type AssignmentTargetScope, type ImpactApprovalReason, type PolicyContentV1, type PolicyImpact, type RuleNode,
} from '@obligarth/shared';
import { AppError } from '../../middleware/errorHandler';
import type { DevicePatch } from '../registry/devicePatch';
import { validateAndroidSection } from '../android/validate';
import { validateLegacyAgentSection } from '../legacyAgent/validate';
import { androidKioskLockArtifact } from '../android/kiosk';
import { appleCatalog, type AppleCatalogView } from '../apple/catalog';
import { fleetShareFloor } from '../settings';
import { recentlyTouched } from './changeLedger';
import { findConflicts, hasSmartGroupTargets, newDeviceConflicts } from './conflicts';
import { ancestryWithout, describeKeys, encodeSpread, entryName, impactDigest, movedAncestry } from './impactPure';
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
// DM23 say whether a second approver is required. The conflicts are those of
// the targets (findConflicts) and, where a dynamic group meets another target
// on devices (P0-5 T6), those the change creates on the devices it reaches
// (newDeviceConflicts).
// A change is a version to publish, a batch of assignment changes, or a change
// of the tree of groups (a group moved under another parent, a group deleted):
// the policies are inherited along the ancestry of the groups, so the tree is
// part of the configuration (review of lot B5b, MDM-B5b-C2). Other modules
// register the proposal of their own kinds (registerProposedKind): the
// governed changes of the dynamic groups (P0-5 T7, mdm/groups/governance.ts:
// a new rule, a deletion, the release of a held group, the facts of a device),
// which reach the devices they name and change their dynamic groups.
// The preview also has a digest of its content: what the change sets and
// unsets, whatever the number of devices. An approval is given on that content
// (DM10): at its execution the digest must be the one that was approved
// (MDM-B5b-C3). And each entry of that content has the number of devices it
// reaches: at the execution of an approval, no entry reaches more devices than
// approved beyond the tolerance of DM23, whatever the total (a key shown to
// the approver on one device is not set on thirty: second review of lot B5b,
// MDM-B5b-C12).
// A wipe-capable Android setting (android-amapi §22.4) that a change sets on a
// device of the channel amapi, or sets there to another value, asks a second
// approver whatever the thresholds (reason wipe_settings): a policy already
// published carried to new devices by an assignment, a device moved or a
// group moved (decision of the owners of 20/10/2026, AN-A2-revue R3).
// =============================================================================

export type AssignmentDelta = { before: ResolutionAssignment | null; after: ResolutionAssignment | null };

export type ProposedChange =
  | { kind: 'version'; policyId: number; versionId: number }
  | { kind: 'assignments'; changes: AssignmentDelta[] }
  /** A group moved under `newParentId` (null: to the root): the ancestry of its whole subtree changes. */
  | { kind: 'group_move'; groupId: number; newParentId: number | null }
  /** A group deleted: its assignments go with it, its devices leave it, its subgroups lose it as an ancestor. */
  | { kind: 'group_delete'; groupId: number }
  /** Devices moved into a group (null: out of any group): they inherit what the new group's ancestry carries (S12). */
  | { kind: 'device_move'; deviceIds: number[]; groupId: number | null }
  // The governed changes of the dynamic groups (P0-5 T7, §4.4): proposals registered by mdm/groups/governance.ts.
  /** A new rule for a dynamic group: its members become those the rule selects (current and proposed members reached). */
  | { kind: 'smart_group_rule'; smartGroupId: number; rule: RuleNode; ruleSha256: string }
  /** A dynamic group deleted: its assignments go with it, its members leave it. */
  | { kind: 'smart_group_delete'; smartGroupId: number }
  /** A held group released: the changes the mass guard kept waiting are applied (its stored rule on the tenant). */
  | { kind: 'smart_group_release'; smartGroupId: number }
  /** The facts of a device changed (its name, tags, custom fields, asset statuses: D11): the dynamic groups an
   *  assignment targets that it enters or leaves, and its name (a variable of the policies). */
  | { kind: 'device_facts'; deviceId: number; patch: DevicePatch };

export type GroupTreeChange = Extract<ProposedChange, { kind: 'group_move' | 'group_delete' }>;
export type DeviceMoveChange = Extract<ProposedChange, { kind: 'device_move' }>;
export type SmartGroupChange = Extract<ProposedChange, { kind: 'smart_group_rule' | 'smart_group_delete' | 'smart_group_release' }>;
export type DeviceFactsChange = Extract<ProposedChange, { kind: 'device_facts' }>;

export interface ImpactOptions {
  catalog?: AppleCatalogView;
  /** Level of mdm.policy_publish in the tenant's matrix: 'restricted' asks a second approver whatever the impact. */
  matrixLevel?: 'none' | 'sensitive' | 'restricted';
  /** Devices the sample may show (the caller's scopes); 'all' for an administrator. */
  visibleDeviceIds?: number[] | 'all';
  sampleSize?: number;
  /** False: the thresholds bear on this change alone (the executor of an approved request compares its own preview). */
  cumulative?: boolean;
}

export interface TouchedDevice { deviceId: number; label: string; added: string[]; changed: string[]; removed: string[] }

/** An entry of the content of a preview (a key set to a value, or a key that no longer applies) and the devices it reaches. */
export interface ContentEntry {
  /** Name of the entry in a request (impactPure.ts, entryName): neither a value nor an instance. */
  name: string;
  settingKey: string;
  devices: number;
}

export interface ImpactResult {
  impact: PolicyImpact;
  /** Every touched device, by id (the pages of GET /api/mdm/impact/:token/devices). */
  touched: TouchedDevice[];
  /** SHA-256 of what the change sets and unsets (impactPure.ts, impactDigest). */
  digest: string;
  /** The entries of that digest, each with the number of devices it reaches. */
  content: ContentEntry[];
  /** The devices with at least one removal (artifact, kiosk lock, app), by id (the cumulative threshold). */
  removalDeviceIds: number[];
  /** A change of the members of a dynamic group (P0-5 T7): the entries and exits it makes. */
  membership?: MembershipDelta;
}

/** The entries and exits of a dynamic group a change makes (device ids), and its members once written (their number,
 *  and their ids: the counts of a caller scoped to some devices are taken from them, P0-5 D3). */
export interface MembershipDelta {
  smartGroupId: number;
  added: number[];
  removed: number[];
  total: number;
  members: number[];
}

const KIOSK_LOCK_TYPE = 'com.apple.app.lock';

/** An Android ApplicationPolicy whose installType is BLOCKED (the app is uninstalled). */
const isBlockedApp = (v: unknown): boolean => !!v && typeof v === 'object' && (v as { installType?: unknown }).installType === 'BLOCKED';

type Target = { scope: AssignmentTargetScope; id: number | null };

/** What a change proposes: the state once written, what it reaches, what it is about. */
export interface Proposal {
  proposed: PolicyState;
  targets: Target[];
  /** The devices the change reaches, when it names them rather than targets (the members of a dynamic group, current
   *  and proposed: P0-5 T7); `targets` is then not read. */
  deviceIds?: number[];
  /** The resources the change is about; null for a change of the tree, which is about none in particular. */
  focus: Set<string> | null;
  /** The devices and the ancestry of their groups once the tree has changed (or their dynamic groups, their name). */
  reshape?: (set: DeviceSet) => DeviceSet;
  /** A change of the dynamic groups of devices (P0-5 T7): the conflicts it creates on them between targets that meet
   *  (newDeviceConflicts, every resource), although it is about no resource in particular. */
  deviceConflicts?: boolean;
  /** The entries and exits of a dynamic group it makes. */
  membership?: MembershipDelta;
}

/** Builds the proposal of a kind of change registered by another module (registerProposedKind). */
export type ProposalBuilder = (q: Knex | Knex.Transaction, tenantId: number, state: PolicyState, change: ProposedChange,
  catalog: AppleCatalogView) => Promise<Proposal>;

/** The kinds of change whose proposal another module builds (the governed changes of the dynamic groups, P0-5 T7; the
 *  coordination's brick « changement gouverné »: P0-4, P0-8, P0-11 register theirs). */
const proposalBuilders = new Map<string, ProposalBuilder>();

/** Registers the builder of the proposal of a kind of change (once, when its module loads). */
export function registerProposedKind(kind: ProposedChange['kind'], build: ProposalBuilder): void {
  proposalBuilders.set(kind, build);
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

/** The proposed state of devices moved into a group (or out of any): their group and its ancestry change (S12). */
async function proposedDeviceMove(q: Knex | Knex.Transaction, tenantId: number, state: PolicyState,
  change: Extract<ProposedChange, { kind: 'device_move' }>): Promise<Proposal> {
  let line: Array<{ groupId: number; depth: number }> = [];
  if (change.groupId !== null) {
    line = (await loadGroupAncestors(q, tenantId, [change.groupId])).get(change.groupId) ?? [];
    if (!line.length) throw new AppError(404, 'Group not found');
  }
  const moved = new Set(change.deviceIds);
  const groupId = change.groupId;
  return {
    proposed: state,
    targets: change.deviceIds.map((id) => ({ scope: 'device' as const, id })),
    focus: null,
    reshape: (set) => {
      const groupAncestors = new Map(set.groupAncestors);
      if (groupId !== null) groupAncestors.set(groupId, line);
      return { devices: set.devices.map((d) => (moved.has(d.id) ? { ...d, groupId } : d)), groupAncestors };
    },
  };
}

/** The proposed state of a change, the targets it reaches and the resources it changes. */
async function proposedState(q: Knex | Knex.Transaction, tenantId: number, state: PolicyState, change: ProposedChange,
  catalog: AppleCatalogView): Promise<Proposal> {
  const registered = proposalBuilders.get(change.kind);
  if (registered) return registered(q, tenantId, state, change, catalog);
  if (change.kind === 'group_move' || change.kind === 'group_delete') return proposedTree(q, tenantId, state, change);
  if (change.kind === 'device_move') return proposedDeviceMove(q, tenantId, state, change);
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
  // A registered kind whose module is not loaded: never computed as another one.
  if (change.kind !== 'assignments') throw new Error(`impact: no proposal registered for the kind ${change.kind}`);
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

/** Does one of these Android settings (set or changed on a device) carry a wipe-capable rule of the version it comes
 *  from? The versions are read once each; their wipe-capable keys are those of the validation (validateAndroidSection). */
async function reachesWipeSettings(q: Knex | Knex.Transaction, set: Array<{ versionId: number; settingKey: string }>): Promise<boolean> {
  if (!set.length) return false;
  const ids = [...new Set(set.map((x) => x.versionId))];
  const rows = await q('policy_versions').whereIn('id', ids).select('id', 'content') as Array<{ id: number; content: unknown }>;
  const wipe = new Map<number, Set<string>>();
  for (const r of rows) {
    let content: PolicyContentV1 | null = null;
    try { content = (typeof r.content === 'string' ? JSON.parse(r.content) : r.content) as PolicyContentV1; } catch { content = null; }
    const android = content?.sections?.android;
    const agent = content?.sections?.legacyAgent;
    wipe.set(Number(r.id), new Set([
      ...(android ? validateAndroidSection(android).wipeRules : []),
      // The bridge agent's wipe threshold (lot PONT-POL §5.7): the floor is the validation's, not this check's.
      ...(agent ? validateLegacyAgentSection(agent, { minFailedPasswordsForWipe: 0 }).wipeRules : []),
    ]));
  }
  // A version that cannot be read counts as wipe-capable (fail closed: a second approver rather than none).
  return set.some((x) => !wipe.has(x.versionId) || wipe.get(x.versionId)!.has(x.settingKey));
}

/** computeImpact(tenantId, change): the preview of a change, in the caller's database context (section 7.11). */
export async function computeImpact(q: Knex | Knex.Transaction, tenantId: number, change: ProposedChange,
  opts: ImpactOptions = {}): Promise<ImpactResult> {
  const catalog = opts.catalog ?? appleCatalog();
  const state = await loadPolicyState(q, tenantId, catalog);
  const proposal = await proposedState(q, tenantId, state, change, catalog);
  const { proposed, targets, focus, reshape } = proposal;
  const deviceIds = proposal.deviceIds ?? (targets.length ? await devicesOfTargets(q, tenantId, targets) : []);
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
  const removalDeviceIds: number[] = [];
  const touched: TouchedDevice[] = [];
  // What the change does, entry by entry (a device counts once per entry: it has one state per key).
  const content = new Map<string, { settingKey: string; devices: number }>();
  const mark = (entry: string, settingKey: string): void => {
    const c = content.get(entry);
    if (c) c.devices++; else content.set(entry, { settingKey, devices: 1 });
  };
  const labelOf = new Map(devices.map((d) => [d.id, d.label]));
  // Android settings set or changed on a device where they apply (the channel amapi), by the version they come from.
  const androidSet: Array<{ versionId: number; settingKey: string }> = [];
  const androidSeen = new Set<string>();
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
      if (!p || differs) mark(`S|${k}|${s.valueHash}|${s.removed ? 1 : 0}`, k);
      if ((!p || differs) && (s.kind === 'android' || s.kind === 'agent') && !s.removed && s.availability.status === 'available'
        && s.source.type === 'policy' && s.source.versionId !== null) {
        const seen = `${s.source.versionId}|${k}`;
        if (!androidSeen.has(seen)) { androidSeen.add(seen); androidSet.push({ versionId: Number(s.source.versionId), settingKey: k }); }
      }
      if (s.availability.status === 'not_applicable' && (!p || differs)) keyStat(k).notApplicable++;
    }
    for (const k of bm.keys()) {
      if (am.has(k)) continue;
      removed.push(k);
      keyStat(k).removed++;
      mark(`U|${k}`, k);
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
    // An Android device (lot AN-C1, raccords of AN-E1 and AN-G1; DM23): its settings all go into one artifact,
    // amapi:policy, counted above as one install when it changes. The kiosk lock (apps installed as KIOSK or holding
    // the KIOSK role, Google's launcher, the customization) is compared as a whole: set or changed, a kiosk lock
    // change; lifted, a removal too. An app that leaves the device's applications[] or becomes BLOCKED is uninstalled
    // by Google (playStoreMode WHITELIST): an app removal.
    // The bridge agent's kiosk (agent:kiosk, lot PONT-POL §5.7): added, changed or removed where it applies.
    const bAgentKiosk = bm.get(AGENT_KIOSK_KEY);
    const aAgentKiosk = am.get(AGENT_KIOSK_KEY);
    const kioskSig = (s: ResolvedSetting | undefined): string | null =>
      (s && !s.removed && s.availability.status === 'available' ? s.valueHash : null);
    if (kioskSig(bAgentKiosk) !== kioskSig(aAgentKiosk)) artifacts.kioskLockChanges++;
    const bk = androidKioskLockArtifact(b);
    const ak = androidKioskLockArtifact(a);
    if ((bk?.sig ?? null) !== (ak?.sig ?? null)) {
      artifacts.kioskLockChanges++;
      if (!ak) { artifacts.removals++; removal = true; }
    }
    for (const [k, s] of bm) {
      if (s.kind !== 'android' || !k.startsWith('android:app[') || s.removed || s.availability.status !== 'available') continue;
      const n = am.get(k);
      const gone = !n || n.removed || n.availability.status !== 'available';
      const blocked = !gone && isBlockedApp(n!.value) && !isBlockedApp(s.value);
      if (gone || blocked) { artifacts.appRemovals++; artifacts.removals++; removal = true; }
    }
    if (removal) { removalDevices++; removalDeviceIds.push(devices[i].id); }
  }

  // A change of the tree sets no two values at one target: the conflicts are those of the assignments (section 7.7),
  // of each target, and of the targets that meet on the devices reached (P0-5 T6). A change of the dynamic groups of
  // devices (P0-5 T7) is about no resource, but brings targets together on devices: the conflicts it creates there.
  const listed = focus ? findConflicts(proposed.assignments, proposed.resources, { focus }) : [];
  const conflicts = focus || proposal.deviceConflicts ? [...listed, ...newDeviceConflicts(
    { devices, groupAncestors: current.groupAncestors, assignments: state.assignments, resources: state.resources },
    { devices: next.devices, groupAncestors: next.groupAncestors, assignments: proposed.assignments, resources: proposed.resources },
    { ...(focus ? { focus } : {}), listed })] : [];
  const fleet = await q('devices').where({ tenant_id: tenantId }).whereNot('enrollment_state', 'unenrolled').count({ n: '*' }).first() as { n: string | number };
  const fleetSize = Number(fleet?.n ?? 0);
  const T = PUBLISH_APPROVAL_THRESHOLDS;
  // The share of the fleet counts from a floor of touched devices (5 by default, set by the tenant): on a small
  // fleet, 10 % would ask a second approver for almost any change (decision of the owners of 15/10/2026).
  const floor = await fleetShareFloor(q, tenantId);
  const beyond = (n: number): boolean => n >= T.devicesTouched || (n >= floor && fleetSize > 0 && n >= T.fleetShare * fleetSize);
  const reasons: ImpactApprovalReason[] = [];
  if (touched.length >= T.devicesTouched) reasons.push('devices_threshold');
  if (touched.length >= floor && fleetSize > 0 && touched.length >= T.fleetShare * fleetSize) reasons.push('fleet_share');
  if (removalDevices >= T.removalDevices) reasons.push('removal_threshold');
  // The same thresholds on this change together with the direct changes of the last hour (MDM-B5b-C7): distinct
  // devices, counted only when this change touches one (or removes something, for the removals).
  let cumulative: PolicyImpact['cumulative'];
  if (opts.cumulative !== false && (touched.length > 0 || removalDevices > 0)) {
    const recent = await recentlyTouched(q, tenantId);
    for (const t of touched) recent.devices.add(t.deviceId);
    for (const d of removalDeviceIds) recent.removals.add(d);
    cumulative = { windowMinutes: T.cumulativeWindowMinutes, devicesTouched: recent.devices.size, removalDevices: recent.removals.size };
    if (!reasons.length && ((touched.length > 0 && beyond(recent.devices.size))
      || (removalDevices > 0 && recent.removals.size >= T.removalDevices))) reasons.push('cumulative');
  }
  if (await reachesWipeSettings(q, androidSet)) reasons.push('wipe_settings');
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
    ...(cumulative ? { cumulative } : {}),
    fleetShareFloor: floor,
  };
  return {
    impact, touched, digest: impactDigest(content.keys()),
    content: [...content].map(([entry, c]) => ({ name: entryName(entry), settingKey: c.settingKey, devices: c.devices })),
    removalDeviceIds,
    ...(proposal.membership ? { membership: proposal.membership } : {}),
  };
}

/** The conflicts a change would create (section 7.7), without resolving any device: those of each target, then, when
 *  a dynamic group is targeted (P0-5 T6), those of the targets that meet on the devices the change reaches. */
export async function conflictsOf(q: Knex | Knex.Transaction, tenantId: number, change: ProposedChange,
  catalog: AppleCatalogView = appleCatalog()): Promise<PolicyImpact['conflicts']> {
  const state = await loadPolicyState(q, tenantId, catalog);
  const { proposed, targets, focus, reshape } = await proposedState(q, tenantId, state, change, catalog);
  if (!focus) return [];
  const listed = findConflicts(proposed.assignments, proposed.resources, { focus });
  if (!hasSmartGroupTargets(state.assignments) && !hasSmartGroupTargets(proposed.assignments)) return listed;
  const deviceIds = targets.length ? await devicesOfTargets(q, tenantId, targets) : [];
  if (!deviceIds.length) return listed;
  const current = await loadDevices(q, tenantId, deviceIds);
  const next = reshape ? reshape(current) : current;
  return [...listed, ...newDeviceConflicts(
    { ...current, assignments: state.assignments, resources: state.resources },
    { ...next, assignments: proposed.assignments, resources: proposed.resources },
    { focus, listed })];
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
 * keys the change adds, changes and removes (their names and counts, never a value), the digest of the content
 * the approval is given on, and the devices each entry of that content reaches (`spread`: every entry, whatever
 * the number of keys shown, in one line of text for the executor: impactPure.ts, encodeSpread).
 */
export function approvalImpact(r: ImpactResult): Record<string, unknown> {
  return {
    ...impactSummary(r.impact),
    keys: r.impact.keys.slice(0, APPROVAL_KEYS_MAX),
    keysTotal: r.impact.keys.length,
    digest: r.digest,
    spread: encodeSpread(r.content),
  };
}

export { describeKeys };

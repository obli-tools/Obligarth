import { create } from 'zustand';
import type { DeviceGroup, DeviceGroupTreeNode } from '@obligarth/shared';
import { SocketEvents } from '@obligarth/shared';
import { groupsApi } from '../api/groups.api';
import { registerSocketListener } from '../socket/socketListeners';
import { onTenantChanged } from './tenantStore';
import { onSessionReset } from './sessionReset';

/** MDM counters of a group and its subtree (modele-donnees-mdm §11.3): the devices under management. */
export interface DeviceGroupStats {
  total: number;
  enrolled: number;
  nonCompliant: number;
  configErrors: number;
  stale: number;
}

interface GroupStore {
  groups: Map<number, DeviceGroup>;
  tree: DeviceGroupTreeNode[];
  /** Parent of every group of `tree` (null for a root): the client walks it to apply a grant given on an
   *  ancestor group, as the server does through its closure table. */
  parents: Map<number, number | null>;
  groupStats: Record<number, DeviceGroupStats>;
  /** The tree of the session's tenant was read (or its read failed): until then a grant inherited from an
   *  ancestor group is unknown, and a page must not conclude "access denied" from its absence. */
  treeLoaded: boolean;
  isLoading: boolean;

  // Actions
  fetchGroups: () => Promise<void>;
  fetchTree: () => Promise<void>;
  /** Takes a tree read elsewhere (the side panel's own reload). */
  setTree: (tree: DeviceGroupTreeNode[]) => void;
  addGroup: (group: DeviceGroup) => void;
  updateGroup: (id: number, data: Partial<DeviceGroup>) => void;
  removeGroup: (id: number) => void;

  // Getters
  getGroup: (id: number) => DeviceGroup | undefined;
  getGroupList: () => DeviceGroup[];
  getRootGroups: () => DeviceGroup[];
  getGroupStats: (id: number) => DeviceGroupStats | undefined;
}

/** Sequence of the tree requests: a response applies only if no later request (or reset) happened. */
let treeSeq = 0;

/** The tree with its parent map and its per-group counters (from the device counts the nodes carry). */
function deriveTree(tree: DeviceGroupTreeNode[]): Pick<GroupStore, 'tree' | 'parents' | 'groupStats'> {
  const groupStats: Record<number, DeviceGroupStats> = {};
  const parents = new Map<number, number | null>();
  const walk = (nodes: DeviceGroupTreeNode[], parentId: number | null) => {
    for (const node of nodes) {
      parents.set(node.id, parentId);
      groupStats[node.id] = {
        total: node.total ?? node.deviceCount ?? 0,
        enrolled: node.enrolledCount ?? 0,
        nonCompliant: node.nonCompliantCount ?? 0,
        configErrors: node.configErrorCount ?? 0,
        stale: node.staleCount ?? 0,
      };
      if (node.children?.length) walk(node.children, node.id);
    }
  };
  walk(tree, null);
  return { tree, parents, groupStats };
}

export const useGroupStore = create<GroupStore>((set, get) => ({
  groups: new Map(),
  tree: [],
  parents: new Map(),
  groupStats: {},
  treeLoaded: false,
  isLoading: false,

  fetchGroups: async () => {
    set({ isLoading: true });
    try {
      const list = await groupsApi.list();
      const groups = new Map<number, DeviceGroup>();
      list.forEach((g) => groups.set(g.id, g));
      set({ groups, isLoading: false });
    } catch {
      set({ isLoading: false });
    }
  },

  fetchTree: async () => {
    const seq = ++treeSeq;
    try {
      const tree = await groupsApi.tree();
      // Only the latest request lands: an older one (previous tenant, before a logout) is dropped.
      if (seq !== treeSeq) return;
      set({ ...deriveTree(tree), treeLoaded: true });
    } catch {
      // The pages then decide on the own grants only (as before the inherited ones were read).
      if (seq === treeSeq) set({ treeLoaded: true });
    }
  },

  setTree: (tree) => {
    // A tree read by someone else (the side panel) is newer than a request of the store still in flight.
    treeSeq++;
    set({ ...deriveTree(tree), treeLoaded: true });
  },

  addGroup: (group) => {
    set((state) => {
      const groups = new Map(state.groups);
      groups.set(group.id, group);
      return { groups };
    });
  },

  updateGroup: (id, data) => {
    set((state) => {
      const groups = new Map(state.groups);
      const existing = groups.get(id);
      if (existing) {
        groups.set(id, { ...existing, ...data });
      }
      return { groups };
    });
  },

  removeGroup: (id) => {
    set((state) => {
      const groups = new Map(state.groups);
      groups.delete(id);
      return { groups };
    });
  },

  // ── Getters ──

  getGroup: (id) => get().groups.get(id),
  getGroupList: () => Array.from(get().groups.values()),
  getRootGroups: () =>
    Array.from(get().groups.values()).filter((g) => g.parentId === null),
  getGroupStats: (id) => get().groupStats[id],
}));

// ── Live updates ─────────────────────────────────────────────────────────────
// The store keeps itself current: server events (bound by useSocket) and
// tenant switches (reload the tenant's tree).

/** What GROUP_UPDATED and GROUP_MOVED carry: the whole group in the room of the tenant's administrators, only its
 *  identifiers elsewhere (the other members of the tenant, the echo to the master tenant's administrators); a
 *  reordering names every group it renumbered (groupIds). */
export type GroupEventRef = Partial<DeviceGroup> & { id: number; tenantId: number };
interface GroupChangeEvent { group?: GroupEventRef; groupIds?: number[] }

/** A complete group (a name): the only kind the store takes as a new entry. */
function isWholeGroup(g: GroupEventRef | undefined): g is DeviceGroup & GroupEventRef {
  return !!g && typeof g.id === 'number' && typeof g.name === 'string';
}

// A burst of events (a reordering, a move of several groups, an approval executed) reads the tree and the list once.
let reloadTimer: ReturnType<typeof setTimeout> | null = null;
let reloadList = false;
function scheduleReload(list: boolean): void {
  reloadList = reloadList || list;
  if (reloadTimer) return;
  reloadTimer = setTimeout(() => {
    reloadTimer = null;
    const { fetchTree, fetchGroups, groups } = useGroupStore.getState();
    // The list is read again only when it was loaded (a page uses it) and an event carried identifiers only.
    if (reloadList && groups.size > 0) void fetchGroups();
    reloadList = false;
    void fetchTree();
  }, 250);
}

/** Applies what an event says of a group: the whole group merged in, identifiers only merged where they are known
 *  (sortOrder of a reordering), and the list read again for what they do not say. */
function applyGroupRef(data: GroupChangeEvent | undefined): void {
  const g = data?.group;
  const { updateGroup } = useGroupStore.getState();
  if (g && typeof g.id === 'number') updateGroup(g.id, g);
  scheduleReload(!isWholeGroup(g) || Array.isArray(data?.groupIds));
}

registerSocketListener(SocketEvents.GROUP_CREATED, (data: GroupChangeEvent) => {
  // Never sent without the whole group; one without a name is not taken as an entry, only reloaded.
  if (isWholeGroup(data?.group)) useGroupStore.getState().addGroup(data.group);
  scheduleReload(!isWholeGroup(data?.group));
});

registerSocketListener(SocketEvents.GROUP_UPDATED, (data: GroupChangeEvent) => { applyGroupRef(data); });

registerSocketListener(SocketEvents.GROUP_DELETED, (data: { groupId?: number; tenantId?: number }) => {
  if (typeof data?.groupId === 'number') useGroupStore.getState().removeGroup(data.groupId);
  scheduleReload(false);
});

registerSocketListener(SocketEvents.GROUP_MOVED, (data: GroupChangeEvent) => { applyGroupRef(data); });

// The tree of the previous tenant says nothing of the new one's ancestors: unknown until the new one is read.
onTenantChanged(() => {
  useGroupStore.setState({ treeLoaded: false });
  return useGroupStore.getState().fetchTree();
});

onSessionReset(() => {
  treeSeq++;
  if (reloadTimer) { clearTimeout(reloadTimer); reloadTimer = null; }
  reloadList = false;
  useGroupStore.setState({ groups: new Map(), tree: [], parents: new Map(), groupStats: {}, treeLoaded: false, isLoading: false });
});

/** The level a group grant gives on `groupId`: its own grant or one of an ancestor's (rw wins), as the server's
 *  closure check does. Ancestors come from the loaded tree; a group missing from it counts on its own grant. */
export function inheritedGroupLevel(
  permissions: Record<string, 'ro' | 'rw'>,
  groupId: number,
): 'ro' | 'rw' | null {
  const { parents } = useGroupStore.getState();
  let level: 'ro' | 'rw' | null = null;
  const seen = new Set<number>();
  let id: number | null | undefined = groupId;
  while (id != null && !seen.has(id)) {
    seen.add(id);
    const own = permissions[`group:${id}`];
    if (own === 'rw') return 'rw';
    if (own === 'ro') level = 'ro';
    id = parents.get(id);
  }
  return level;
}

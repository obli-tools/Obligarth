import { create } from 'zustand';
import type { DeviceGroup, DeviceGroupTreeNode } from '@obligarth/shared';
import { SocketEvents } from '@obligarth/shared';
import { groupsApi } from '../api/groups.api';
import { registerSocketListener } from '../socket/socketListeners';
import { onTenantChanged } from './tenantStore';

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
  groupStats: Record<number, DeviceGroupStats>;
  isLoading: boolean;

  // Actions
  fetchGroups: () => Promise<void>;
  fetchTree: () => Promise<void>;
  addGroup: (group: DeviceGroup) => void;
  updateGroup: (id: number, data: Partial<DeviceGroup>) => void;
  removeGroup: (id: number) => void;

  // Getters
  getGroup: (id: number) => DeviceGroup | undefined;
  getGroupList: () => DeviceGroup[];
  getRootGroups: () => DeviceGroup[];
  getGroupStats: (id: number) => DeviceGroupStats | undefined;
}

export const useGroupStore = create<GroupStore>((set, get) => ({
  groups: new Map(),
  tree: [],
  groupStats: {},
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
    try {
      const tree = await groupsApi.tree();
      // Derive stats from tree nodes if they carry device counts
      const groupStats: Record<number, DeviceGroupStats> = {};
      function walkTree(nodes: DeviceGroupTreeNode[]) {
        for (const node of nodes) {
          groupStats[node.id] = {
            total: node.total ?? node.deviceCount ?? 0,
            enrolled: node.enrolledCount ?? 0,
            nonCompliant: node.nonCompliantCount ?? 0,
            configErrors: node.configErrorCount ?? 0,
            stale: node.staleCount ?? 0,
          };
          if (node.children?.length) walkTree(node.children);
        }
      }
      walkTree(tree);
      set({ tree, groupStats });
    } catch {
      // ignore
    }
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

registerSocketListener(SocketEvents.GROUP_CREATED, (data: { group: DeviceGroup }) => {
  const { addGroup, fetchTree } = useGroupStore.getState();
  addGroup(data.group);
  fetchTree();
});

registerSocketListener(SocketEvents.GROUP_UPDATED, (data: { group: DeviceGroup }) => {
  const { updateGroup, fetchTree } = useGroupStore.getState();
  updateGroup(data.group.id, data.group);
  fetchTree();
});

registerSocketListener(SocketEvents.GROUP_DELETED, (data: { groupId: number }) => {
  const { removeGroup, fetchTree } = useGroupStore.getState();
  removeGroup(data.groupId);
  fetchTree();
});

registerSocketListener(SocketEvents.GROUP_MOVED, (data: { group: DeviceGroup }) => {
  const { updateGroup, fetchTree } = useGroupStore.getState();
  updateGroup(data.group.id, data.group);
  fetchTree();
});

onTenantChanged(() => useGroupStore.getState().fetchTree());

import { create } from 'zustand';
import { SocketEvents, type McpAuthorizationChanged, type McpKeyNewNetwork } from '@obligarth/shared';
import { accessKeysApi } from '@/api/accessKeys.api';
import { registerSocketListener } from '@/socket/socketListeners';

// The user's own MCP notices (docs: specs mcp-server §6.3): the authorizations his AI agents wait for (a sensitive
// action he approves with a second factor) and the "key used from a new network" notices. They are user-scoped
// (socket room user:<id>), never tenant live alerts that other members would see. Loaded once at start, then kept
// up to date by the socket.

/** A pending authorization as the notification centre shows it. */
export interface PendingMcpAuthorization {
  id: string;
  tenantId: number;
  summary: string;
  expiresAt: string;
}

export interface McpNewNetworkNotice extends McpKeyNewNetwork {
  /** Local id (keyId + time). */
  id: string;
}

interface McpAuthorizationsState {
  pending: PendingMcpAuthorization[];
  notices: McpNewNetworkNotice[];
  loaded: boolean;
  load: () => Promise<void>;
  dismissNotice: (id: string) => void;
  clearNotices: () => void;
}

export const useMcpAuthorizationsStore = create<McpAuthorizationsState>((set, get) => ({
  pending: [],
  notices: [],
  loaded: false,

  load: async () => {
    try {
      const rows = await accessKeysApi.authorizations.list('pending');
      set({
        pending: rows.map((r) => ({ id: r.id, tenantId: r.tenantId, summary: r.summary, expiresAt: r.expiresAt })),
        loaded: true,
      });
    } catch {
      // Not fatal: the socket still brings the new ones.
      if (!get().loaded) set({ loaded: true });
    }
  },

  dismissNotice: (id) => set((s) => ({ notices: s.notices.filter((n) => n.id !== id) })),
  clearNotices: () => set({ notices: [] }),
}));

/** The authorizations still waiting, the expired ones dropped (their expiry may pass before the minute step). */
export function livePending(pending: PendingMcpAuthorization[], now = Date.now()): PendingMcpAuthorization[] {
  return pending.filter((p) => new Date(p.expiresAt).getTime() > now);
}

registerSocketListener(SocketEvents.MCP_AUTHORIZATION_CHANGED, (e: McpAuthorizationChanged) => {
  if (!e || typeof e.id !== 'string') return;
  useMcpAuthorizationsStore.setState((s) => {
    const others = s.pending.filter((p) => p.id !== e.id);
    return {
      pending: e.state === 'pending'
        ? [{ id: e.id, tenantId: Number(e.tenantId), summary: String(e.summary ?? ''), expiresAt: String(e.expiresAt) }, ...others]
        : others,
    };
  });
});

registerSocketListener(SocketEvents.MCP_KEY_NEW_NETWORK, (e: McpKeyNewNetwork) => {
  if (!e || typeof e.keyId !== 'string') return;
  useMcpAuthorizationsStore.setState((s) => ({
    notices: [{ ...e, id: `${e.keyId}:${e.at}` }, ...s.notices.filter((n) => n.id !== `${e.keyId}:${e.at}`)].slice(0, 20),
  }));
});

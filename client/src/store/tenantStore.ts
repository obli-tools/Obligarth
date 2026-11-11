import { create } from 'zustand';
import type { TenantWithRole } from '@obligarth/shared';
import { onSessionReset } from './sessionReset';

// ── Tenant changed event ─────────────────────────────────────────────────────
// Fired by the tenant switcher after its switch request. The tenant-scoped
// stores subscribe to it and reload themselves, so the switcher does not need
// to know them. Listeners may be async: the emitter waits for all of them (a
// failing one does not block the others).

type TenantChangedListener = (tenantId: number) => void | Promise<void>;

const tenantChangedListeners = new Set<TenantChangedListener>();

/** Subscribes to tenant switches; returns the unsubscribe function. */
export function onTenantChanged(listener: TenantChangedListener): () => void {
  tenantChangedListeners.add(listener);
  return () => { tenantChangedListeners.delete(listener); };
}

/** Notifies every subscriber and resolves once they are all done. */
export async function emitTenantChanged(tenantId: number): Promise<void> {
  await Promise.all([...tenantChangedListeners].map(async (listener) => {
    try {
      await listener(tenantId);
    } catch {
      // one store failing to reload must not block the switch
    }
  }));
}

/** Asks the server to switch the session's tenant; true when it accepted. Changes no client state: the full
 *  switch (permissions, stores, socket) is switchTenant() in store/tenantSwitch.ts. */
export async function requestTenantSwitch(tenantId: number): Promise<boolean> {
  try {
    const res = await fetch('/api/tenant/switch', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

interface TenantState {
  currentTenantId: number | null;
  tenants: TenantWithRole[];
  isLoading: boolean;
  fetchTenants: () => Promise<void>;
  /** Switches the session's tenant on the server and records it; false when the server refused. Only for
   *  callers that reload the whole page right after (a hard navigation); the others use switchTenant(). */
  setCurrentTenant: (tenantId: number) => Promise<boolean>;
}

export const useTenantStore = create<TenantState>((set) => ({
  currentTenantId: null,
  tenants: [],
  isLoading: false,

  fetchTenants: async () => {
    try {
      set({ isLoading: true });
      const res = await fetch('/api/tenants', { credentials: 'include' });
      if (!res.ok) { set({ isLoading: false }); return; }
      const data = await res.json();
      set({ tenants: data.data ?? [], isLoading: false });
    } catch {
      set({ isLoading: false });
    }
  },

  setCurrentTenant: async (tenantId: number) => {
    if (!(await requestTenantSwitch(tenantId))) return false;
    set({ currentTenantId: tenantId });
    return true;
  },
}));

onSessionReset(() => useTenantStore.setState({ currentTenantId: null, tenants: [], isLoading: false }));

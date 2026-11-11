import { connectSocket, disconnectSocket } from '../socket/socketClient';
import { useAuthStore } from './authStore';
import { emitTenantChanged, requestTenantSwitch, useTenantStore } from './tenantStore';

// ── Tenant switch without a page reload ─────────────────────────────────────
// The one place that switches tenant in place (the tenant switcher, a device
// record opened from another tenant). Everything that depends on the active
// tenant follows, in this order:
//   1. the server switches the session (a refusal stops here, nothing changes);
//   2. the permissions are re-read: tenantCapabilities belong to the active
//      tenant, and the route guards must see the new ones before the pages of
//      the new tenant render;
//   3. currentTenantId changes (pages reload, AppLayout leaves tenant-scoped URLs);
//   4. the socket reconnects: the server fixes its tenant room at the
//      handshake, and useSocket() re-binds the app-wide listeners to the new
//      instance (socketStore.generation);
//   5. the tenant-scoped stores reload themselves (onTenantChanged).

let queue: Promise<unknown> = Promise.resolve();

export interface SwitchTenantOptions {
  /** Keep the current URL across the switch (AppLayout otherwise goes back to the dashboard). */
  keepUrl?: boolean;
  /** Switch the server session even when this tab already shows that tenant: the session is shared by the tabs,
   *  another tab may have moved it elsewhere (the caller learnt it from the server, e.g. /devices/:id/locate). */
  force?: boolean;
}

/** Switches the active tenant; resolves false when the server refused (nothing changed then). */
export function switchTenant(tenantId: number, options: SwitchTenantOptions = {}): Promise<boolean> {
  // One switch at a time: a second request waits for the first, then switches if still needed.
  const run = queue.then(() => doSwitch(tenantId, options));
  queue = run.catch(() => undefined);
  return run;
}

async function doSwitch(tenantId: number, options: SwitchTenantOptions): Promise<boolean> {
  const unchanged = useTenantStore.getState().currentTenantId === tenantId;
  if (unchanged && !options.force) return true;
  if (!(await requestTenantSwitch(tenantId))) return false;

  // A failed re-read must not leave the capabilities of the previous tenant in force: one retry, then the
  // permissions are dropped so that the guards refuse rather than grant (the next /auth/permissions restores them).
  const auth = useAuthStore.getState();
  if (!(await auth.refreshPermissions()) && !(await auth.refreshPermissions())) {
    useAuthStore.setState({ permissions: null });
  }

  // The flag is consumed by AppLayout on a currentTenantId change only: never leave it behind otherwise.
  if (options.keepUrl && !unchanged) sessionStorage.setItem('skipTenantSwitchRedirect', '1');
  useTenantStore.setState({ currentTenantId: tenantId });

  const user = useAuthStore.getState().user;
  if (user) {
    disconnectSocket();
    connectSocket(user.id, tenantId);
  }

  await emitTenantChanged(tenantId);
  return true;
}

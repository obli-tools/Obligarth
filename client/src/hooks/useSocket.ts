import { useEffect } from 'react';
import { getSocket } from '../socket/socketClient';
import { bindSocketListeners } from '../socket/socketListeners';
import { useAuthStore } from '../store/authStore';
import { useLiveAlertsStore } from '../store/liveAlertsStore';
import { SocketEvents } from '@obligarth/shared';
import type { LiveAlert, LiveAlertsResolvedEvent } from '@obligarth/shared';

/**
 * App-wide socket subscriptions: live alerts, plus the listeners other modules
 * registered (socket/socketListeners.ts). Every handler is removed by its own
 * reference — `socket.off(event)` without one would also drop the listeners
 * other components put on the same event.
 */
export function useSocket() {
  const { user } = useAuthStore();

  useEffect(() => {
    if (!user) return;

    const socket = getSocket();
    if (!socket) return;

    // ── Live alerts (notifications) ────────────────────────────────────────────
    const onNotificationNew = (alert: LiveAlert) => {
      useLiveAlertsStore.getState().addAlertFromServer(alert);
    };
    // Alerts marked read server-side (e.g. a metric's alerts were muted
    // while it was breaching) leave the bell without a reload.
    const onNotificationRead = (data: { ids?: number[]; readAt?: string }) => {
      if (!data || !Array.isArray(data.ids) || data.ids.length === 0) return;
      useLiveAlertsStore.getState().markReadFromServer(data.ids, data.readAt ?? new Date().toISOString());
    };
    // Alerts resolved server-side (device back online, metrics back to
    // normal, escalation replaced by a new alert…) disappear at once.
    const onNotificationResolved = (data: Partial<LiveAlertsResolvedEvent> | null) => {
      if (!data || !Array.isArray(data.ids) || data.ids.length === 0) return;
      useLiveAlertsStore.getState().resolveFromServer(data.ids);
    };
    // Events emitted while the socket was down (sleep, network cut) are
    // lost: re-read the active alerts on every REconnect so resolved ones
    // don't linger in the bell. The first connect is covered by the login
    // fetch (authStore).
    let hadConnected = socket.connected;
    const onConnect = () => {
      if (hadConnected) void useLiveAlertsStore.getState().fetchAlerts();
      hadConnected = true;
    };

    socket.on(SocketEvents.NOTIFICATION_NEW, onNotificationNew);
    socket.on(SocketEvents.NOTIFICATION_READ, onNotificationRead);
    socket.on(SocketEvents.NOTIFICATION_RESOLVED, onNotificationResolved);
    socket.on('connect', onConnect);
    const unbindRegistered = bindSocketListeners(socket);

    return () => {
      socket.off(SocketEvents.NOTIFICATION_NEW, onNotificationNew);
      socket.off(SocketEvents.NOTIFICATION_READ, onNotificationRead);
      socket.off(SocketEvents.NOTIFICATION_RESOLVED, onNotificationResolved);
      socket.off('connect', onConnect);
      unbindRegistered();
    };
  }, [user]);
}

import { create } from 'zustand';
import type { Device, DeviceStatus, FleetSummary } from '@obliance/shared';
import { SocketEvents } from '@obliance/shared';
import { deviceApi } from '../api/device.api';
import { registerSocketListener } from '../socket/socketListeners';
import { onTenantChanged } from './tenantStore';

interface DeviceStore {
  devices: Map<number, Device>;
  summary: FleetSummary | null;
  isLoading: boolean;

  // Actions
  fetchDevices: (params?: { groupId?: number; status?: string; search?: string }) => Promise<void>;
  fetchSummary: () => Promise<void>;
  fetchDevice: (id: number) => Promise<Device | null>;
  addDevice: (device: Device) => void;
  updateDevice: (id: number, data: Partial<Device>) => void;
  removeDevice: (id: number) => void;

  // Getters
  getDevice: (id: number) => Device | undefined;
  getDeviceList: () => Device[];
  getDevicesByGroup: (groupId: number | null) => Device[];
  getDevicesByStatus: (status: DeviceStatus) => Device[];
}

export const useDeviceStore = create<DeviceStore>((set, get) => ({
  devices: new Map(),
  summary: null,
  isLoading: false,

  fetchDevices: async (params) => {
    set({ isLoading: true });
    try {
      const list = await deviceApi.list(params);
      const devices = new Map<number, Device>();
      list.forEach((d) => devices.set(d.id, d));
      set({ devices, isLoading: false });
    } catch {
      set({ isLoading: false });
    }
  },

  fetchSummary: async () => {
    try {
      const summary = await deviceApi.getSummary();
      set({ summary });
    } catch { /* ignore */ }
  },

  fetchDevice: async (id) => {
    try {
      const device = await deviceApi.getById(id);
      set((state) => {
        const devices = new Map(state.devices);
        devices.set(device.id, device);
        return { devices };
      });
      return device;
    } catch { return null; }
  },

  addDevice: (device) => {
    set((state) => {
      const devices = new Map(state.devices);
      devices.set(device.id, device);
      return { devices };
    });
  },

  updateDevice: (id, data) => {
    set((state) => {
      const devices = new Map(state.devices);
      const existing = devices.get(id);
      if (existing) devices.set(id, { ...existing, ...data });
      return { devices };
    });
  },

  removeDevice: (id) => {
    set((state) => {
      const devices = new Map(state.devices);
      devices.delete(id);
      return { devices };
    });
  },

  getDevice: (id) => get().devices.get(id),
  getDeviceList: () => Array.from(get().devices.values()),
  getDevicesByGroup: (groupId) => Array.from(get().devices.values()).filter((d) => d.groupId === groupId),
  getDevicesByStatus: (status) => Array.from(get().devices.values()).filter((d) => d.status === status),
}));

// ── Live updates ─────────────────────────────────────────────────────────────
// The store keeps itself current: server events (bound by useSocket) and
// tenant switches (reload the tenant's devices).

/** Notify the native desktop app overlay (if running inside Electron). */
function notifyNative(type: 'device_alert' | 'device_ok' | 'device_critical') {
  const isNativeApp = !!(window as Window & { __obliance_is_native_app?: boolean }).__obliance_is_native_app;
  if (isNativeApp) window.dispatchEvent(new CustomEvent('obliance:notify', { detail: { type } }));
}

// The server emits DEVICE_UPDATED with multiple payload shapes depending
// on the originating code path. Accept them all:
//   1. { device: Device }                 — full device wrapper
//   2. Device                             — full device object
//   3. { id|deviceId, ...partial fields } — partial patch
registerSocketListener(SocketEvents.DEVICE_UPDATED, (data: any) => {
  if (!data) return;
  const { updateDevice } = useDeviceStore.getState();
  if (data.device && typeof data.device === 'object' && data.device.id) {
    updateDevice(data.device.id, data.device);
    return;
  }
  const id: number | undefined = data.id ?? data.deviceId;
  if (!id || typeof id !== 'number') return;
  // Strip the id keys from the patch; keep everything else.
  const { id: _id, deviceId: _deviceId, ...patch } = data;
  updateDevice(id, patch);
});

registerSocketListener(SocketEvents.DEVICE_ONLINE, (data: { deviceId: number; device?: Partial<Device> }) => {
  const { updateDevice, fetchSummary } = useDeviceStore.getState();
  updateDevice(data.deviceId, data.device ? { ...data.device, status: 'online' } : { status: 'online' });
  fetchSummary();
  notifyNative('device_ok');
});

registerSocketListener(SocketEvents.DEVICE_OFFLINE, (data: { deviceId: number; device?: Partial<Device> }) => {
  const { updateDevice, fetchSummary } = useDeviceStore.getState();
  updateDevice(data.deviceId, data.device ? { ...data.device, status: 'offline' } : { status: 'offline' });
  fetchSummary();
  notifyNative('device_alert');
});

registerSocketListener(SocketEvents.DEVICE_APPROVED, (data: { device: Device }) => {
  const { addDevice, fetchSummary } = useDeviceStore.getState();
  addDevice(data.device);
  fetchSummary();
});

registerSocketListener(SocketEvents.DEVICE_DELETED, (data: { deviceId: number }) => {
  const { removeDevice, fetchSummary } = useDeviceStore.getState();
  removeDevice(data.deviceId);
  fetchSummary();
});

onTenantChanged(() => useDeviceStore.getState().fetchDevices());

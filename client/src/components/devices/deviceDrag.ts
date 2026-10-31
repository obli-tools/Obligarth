// A device row dragged onto a group of the side panel (native drag-and-drop, apart from the dnd-kit tree of the panel):
// the row carries its id, the panel announces the drop, and the device table moves the device, or the whole selection
// when the dragged row is part of it, through the same preview as "Change group".

export const DEVICE_DRAG_TYPE = 'application/x-obligarth-device';
export const DEVICE_DROP_EVENT = 'obligarth:device-drop';

export interface DeviceDropDetail { deviceId: number; groupId: number }

/** Whether a drag carries a device row. */
export const isDeviceDrag = (e: { dataTransfer: DataTransfer | null }): boolean =>
  !!e.dataTransfer && Array.from(e.dataTransfer.types).includes(DEVICE_DRAG_TYPE);

export function announceDeviceDrop(e: { dataTransfer: DataTransfer | null }, groupId: number): boolean {
  const deviceId = Number(e.dataTransfer?.getData(DEVICE_DRAG_TYPE));
  if (!Number.isInteger(deviceId) || deviceId <= 0) return false;
  window.dispatchEvent(new CustomEvent<DeviceDropDetail>(DEVICE_DROP_EVENT, { detail: { deviceId, groupId } }));
  return true;
}

import type { DeviceSummary } from '@obligarth/shared';

// "Does this device match the search?" for the local filters (pickers, side lists). The fields are those the
// server searches for GET /api/mdm/devices?q= (label, name, serial number, model, end user), plus the group and
// the tags, so that a local filter and the inventory agree. A field the privacy rules do not collect is absent.
export function deviceMatchesSearch(device: Pick<DeviceSummary, 'label'> & Partial<DeviceSummary>, rawQuery: string): boolean {
  const q = rawQuery.trim().toLowerCase();
  if (!q) return true;
  const fields: Array<string | null | undefined> = [
    device.label,
    device.displayName,
    device.serialNumber,
    device.model,
    device.modelName,
    device.endUser?.displayName,
    device.endUser?.email,
    device.groupName,
    device.uuid,
  ];
  for (const f of fields) {
    if (f && String(f).toLowerCase().includes(q)) return true;
  }
  return (device.tags ?? []).some((tag) => tag && tag.toLowerCase().includes(q));
}

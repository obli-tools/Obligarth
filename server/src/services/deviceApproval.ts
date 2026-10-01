import { db } from '../db';
import {
  auditAs, refuse, requireTenantCapability,
  type ApprovalExecution, type BatchCommandPayload,
} from './approval.service';

// ── Approval executors of the device actions ────────────────────────────────
// Bulk group change and record deletion (single or bulk), executed AS THE
// REQUESTER once a second administrator approved them (approval.service).
// Registered by modules/devices.ts. The tenant transfer is gone
// (rls-tenant R10): a transfer request filed before is refused.

/** Payload of a 'device_uninstall' request (device.routes). */
export interface DeviceUninstallPayload {
  deviceId: number;
  /** DELETE /api/devices/:id (record only). */
  deleteOnly?: boolean;
  /** The former POST /api/devices/:id/transfer (refused since R10). */
  targetTenantId?: number;
}

/** Approved bulk group change (device.bulk_group_change): 'change_group'. */
export async function executeChangeGroup(x: ApprovalExecution): Promise<void> {
  const { tenantId, requesterId } = x;
  const payload = x.payload as BatchCommandPayload;
  await requireTenantCapability(requesterId, tenantId, 'devices.manage');
  const raw = payload.params?.groupId;
  const groupId = raw === null || raw === undefined ? null : Number(raw);
  if (groupId !== null && !(await db('device_groups').where({ id: groupId, tenant_id: tenantId }).first('id'))) refuse('Group not found');
  const ids = [...new Set((payload.deviceIds ?? []).map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  const prev = ids.length ? await db('devices').whereIn('id', ids).andWhere({ tenant_id: tenantId }).select('id', 'group_id') as Array<{ id: number; group_id: number | null }> : [];
  if (!prev.length) refuse('None of the devices of this request is still in the tenant');
  await db('devices').whereIn('id', prev.map((d) => d.id)).andWhere({ tenant_id: tenantId }).update({ group_id: groupId, updated_at: new Date() });
  const changed = prev.filter((d) => d.group_id !== groupId).map((d) => d.id);
  await auditAs(tenantId, requesterId, 'device.bulk_group_changed', {
    resourceType: 'device', resourcePath: prev.map((d) => d.id).join(','), details: { count: prev.length, changed: changed.length, toGroupId: groupId },
  });
}

/**
 * Approved bulk deletion (device.delete, DELETE /api/devices/bulk/delete):
 * 'delete_devices'. Only the devices still in the approval's tenant are
 * deleted (and their data purged); the others are skipped, untouched.
 */
export async function executeBulkDelete(x: ApprovalExecution): Promise<string | void> {
  const { tenantId, requesterId } = x;
  const payload = x.payload as BatchCommandPayload;
  await requireTenantCapability(requesterId, tenantId, 'devices.manage');
  const ids = [...new Set((payload.deviceIds ?? []).map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  const inTenant = ids.length ? await db('devices').whereIn('id', ids).andWhere({ tenant_id: tenantId }).pluck('id') as number[] : [];
  if (!inTenant.length) refuse('None of the devices of this request is still in the tenant');
  const { deviceService } = await import('./device.service');
  const deleted = await deviceService.bulkDelete(inTenant.map(Number), tenantId);
  if (!deleted.length) refuse('None of the devices of this request is still in the tenant');
  await auditAs(tenantId, requesterId, 'device.bulk_deleted', {
    resourceType: 'device', resourcePath: deleted.join(','), details: { count: deleted.length },
  });
  if (deleted.length < ids.length) return `Partially executed — ${ids.length - deleted.length} device(s) no longer in the tenant`;
}

/**
 * Approved device request of type 'device_uninstall' — one route files it
 * now: record deletion (DELETE /:id, `deleteOnly`). The tenant transfer it
 * also carried (`targetTenantId`) is gone (rls-tenant R10), as is the agent
 * uninstall: a request of either kind is refused.
 */
export async function executeDeviceRequest(x: ApprovalExecution): Promise<string | void> {
  const { tenantId, requesterId } = x;
  const payload = x.payload as DeviceUninstallPayload;
  const deviceId = Number(payload.deviceId);
  if (!Number.isInteger(deviceId) || deviceId <= 0) refuse('Device request without a valid device id');
  if (payload.targetTenantId != null) {
    refuse('The transfer of a device to another tenant is no longer supported — nothing was executed');
  }
  if (!payload.deleteOnly) refuse('Agent uninstall is not supported here — nothing was executed');
  await requireTenantCapability(requesterId, tenantId, 'devices.manage');
  const { deviceService } = await import('./device.service');
  // The approval's tenant only (DELETE /:id files it for a device of the
  // session's tenant).
  const existing = await deviceService.getDeviceById(deviceId, tenantId);
  if (!existing) refuse('Device not found');
  if (!(await deviceService.deleteDevice(deviceId, tenantId))) refuse('Device not found');
  await auditAs(tenantId, requesterId, 'device.deleted', {
    deviceId, resourceType: 'device', resourcePath: String(deviceId),
    details: { hostname: existing.hostname, displayName: existing.displayName },
  });
}

import { db } from '../db';
import { logger } from '../utils/logger';
import {
  activeRequester, auditAs, refuse, requireTenantCapability,
  type ApprovalExecution, type BatchCommandPayload,
} from './approval.service';

// ── Approval executors of the device actions ────────────────────────────────
// Bulk group change, tenant transfer and record deletion, executed AS THE
// REQUESTER once a second administrator approved them (approval.service).
// Registered by modules/devices.ts.

/** Payload of a 'device_uninstall' request (device.routes). */
export interface DeviceUninstallPayload {
  deviceId: number;
  /** DELETE /api/devices/:id (record only). */
  deleteOnly?: boolean;
  /** POST /api/devices/:id/transfer */
  targetTenantId?: number;
  targetApiKeyId?: number;
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

/** Approved bulk tenant transfer (device.transfer_tenant): 'transfer_tenant'. */
export async function executeTransferTenant(x: ApprovalExecution): Promise<string | void> {
  const payload = x.payload as BatchCommandPayload;
  const p = payload.params ?? {};
  return transferDevices(x.tenantId, x.requesterId, payload.deviceIds, {
    targetTenantId: Number(p.targetTenantId), targetApiKeyId: Number(p.targetApiKeyId),
  });
}

/**
 * Approved device request of type 'device_uninstall' — two routes file it
 * now: record deletion (DELETE /:id, `deleteOnly`) and tenant transfer
 * (POST /:id/transfer, `targetTenantId`). Each one does what its route does.
 * The agent uninstall this request type also carried went with the agent: a
 * request of that kind is refused.
 */
export async function executeDeviceRequest(x: ApprovalExecution): Promise<string | void> {
  const { tenantId, requesterId } = x;
  const payload = x.payload as DeviceUninstallPayload;
  const deviceId = Number(payload.deviceId);
  if (!Number.isInteger(deviceId) || deviceId <= 0) refuse('Device request without a valid device id');
  if (payload.targetTenantId != null) {
    return transferDevices(tenantId, requesterId, [deviceId], {
      targetTenantId: Number(payload.targetTenantId), targetApiKeyId: Number(payload.targetApiKeyId),
    });
  }
  if (!payload.deleteOnly) refuse('Agent uninstall is not supported here — nothing was executed');
  await requireTenantCapability(requesterId, tenantId, 'devices.manage');
  const { deviceService } = await import('./device.service');
  const existing = await deviceService.getDeviceById(deviceId, tenantId);
  if (!existing) refuse('Device not found');
  await deviceService.deleteDevice(deviceId, tenantId);
  await auditAs(tenantId, requesterId, 'device.deleted', {
    deviceId, resourceType: 'device', resourcePath: String(deviceId),
    details: { hostname: existing.hostname, displayName: existing.displayName },
  });
}

/**
 * Approved tenant transfer (device.transfer_tenant), single or bulk: the
 * same update as the routes (device moved to the target tenant, attached to
 * the target API key, ungrouped). The requester must still be a platform
 * admin or an administrator of BOTH tenants, and the target key must still
 * belong to the target tenant.
 */
async function transferDevices(tenantId: number, requesterId: number, rawIds: unknown[], t: { targetTenantId: number; targetApiKeyId: number }): Promise<string | void> {
  const requester = await activeRequester(requesterId);
  if (!Number.isInteger(t.targetTenantId) || !Number.isInteger(t.targetApiKeyId) || t.targetTenantId === tenantId) {
    refuse('Transfer request without a valid target tenant / API key');
  }
  if (!requester.isPlatformAdmin) {
    const rows = await db('user_tenants').where({ user_id: requesterId, role: 'admin' }).whereIn('tenant_id', [tenantId, t.targetTenantId]).pluck('tenant_id');
    if (new Set(rows.map(Number)).size !== 2) refuse('The requester is no longer an administrator of both tenants');
  }
  const targetKey = await db('agent_api_keys').where({ id: t.targetApiKeyId, tenant_id: t.targetTenantId }).first('id');
  if (!targetKey) refuse('Target API key not found in target tenant');
  const ids = [...new Set(rawIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  const devices = ids.length ? await db('devices').whereIn('id', ids).andWhere({ tenant_id: tenantId }).select('id', 'hostname') as Array<{ id: number; hostname: string }> : [];
  if (!devices.length) refuse('None of the devices of this request is still in the tenant');
  const moved: number[] = [];
  const failed: string[] = [];
  for (const device of devices) {
    try {
      // Keep in sync with device.routes.ts (POST /:id/transfer and /batch/transfer).
      await db('devices').where({ id: device.id }).update({
        tenant_id: t.targetTenantId,
        api_key_id: t.targetApiKeyId,
        group_id: null,
        updated_at: new Date(),
      });
      moved.push(device.id);
    } catch (err) {
      logger.error({ err, deviceId: device.id }, 'approved transfer: failed for device');
      failed.push(device.hostname);
    }
  }
  await auditAs(tenantId, requesterId, moved.length > 1 || devices.length > 1 ? 'device.bulk_transferred' : 'device.transferred', {
    deviceId: devices.length === 1 ? devices[0].id : undefined,
    resourceType: 'device', resourcePath: devices.map((d) => d.id).join(','),
    details: { fromTenantId: tenantId, toTenantId: t.targetTenantId, targetApiKeyId: t.targetApiKeyId, transferred: moved.length, failed: failed.length },
  });
  if (!moved.length) refuse(`No device could be transferred (${failed.join(', ')})`);
  if (failed.length) return `Partially executed — not transferred: ${failed.join(', ')}`;
}

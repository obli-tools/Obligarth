import { db } from '../db';
import {
  auditAs, refuse, requireTenantCapability,
  type ApprovalExecution, type BatchCommandPayload,
} from './approval.service';

// ── Approval executors of the device actions ────────────────────────────────
// Bulk group change, executed AS THE REQUESTER once a second administrator
// approved it (approval.service). Registered by modules/devices.ts. The
// deletion of records is the guarded action device.delete (audit-durci
// §10.2): a deletion request filed before it is refused. The agent's requests
// (device_uninstall, the tenant transfer of rls-tenant R10) are gone with the
// agent (modele-donnees-mdm §11.1): no executor, refused by the engine.

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

/** Message of a deletion request filed before the guard engine. */
const DELETION_GUARDED = 'The deletion of device records goes through the guarded actions since this version '
  + '(Security, Guards): this request was filed before and is not executed — request the deletion again';

/**
 * A bulk deletion request filed before the guard engine ('delete_devices'):
 * refused, nothing deleted. The deletion of records is the guarded action
 * device.delete (audit-durci §10.2): its only path.
 */
export async function executeBulkDelete(_x: ApprovalExecution): Promise<string | void> {
  refuse(DELETION_GUARDED);
}

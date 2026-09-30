import { db } from '../db';
import {
  activeRequester, auditAs, refuse,
  type ApprovalExecution, type BatchCommandPayload,
} from './approval.service';

// ── Approval executor of the manual software remediation ────────────────────
// software.remediate_install / software.remediate_uninstall, executed AS THE
// REQUESTER once a second administrator approved it (approval.service).
// Registered by modules/rmm.ts.

/** A remediation from the software-compliance routes: an install / uninstall
 *  carrying its list and entries (a raw command carries neither). */
export function isSoftwareRemediation(action: string, payload: BatchCommandPayload): boolean {
  const p = payload.params ?? {};
  return (action === 'install_software' || action === 'uninstall_software') && p.listId != null && Array.isArray(p.entryIds);
}

/** Approved manual software remediation (software.remediate_*). */
export async function executeSoftwareRemediation(x: ApprovalExecution): Promise<void> {
  const { tenantId, requesterId } = x;
  const payload = x.payload as BatchCommandPayload;
  const requester = await activeRequester(requesterId);
  const deviceId = Number((payload.deviceIds ?? [])[0]);
  const listId = Number(payload.params?.listId);
  const entryIds = (payload.params?.entryIds as unknown[]).map(Number).filter((n) => Number.isInteger(n) && n > 0);
  if (!(await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id'))) refuse('Device not found');
  if (!requester.isPlatformAdmin) {
    const { permissionService } = await import('./permission.service');
    if (!(await permissionService.canWriteDevice(requesterId, deviceId, false))) refuse('The requester can no longer write to this device');
  }
  const { softwareComplianceService } = await import('./softwareCompliance.service');
  if (!(await softwareComplianceService.getListById(listId, tenantId))) refuse('Software list not found');
  await softwareComplianceService.triggerRemediation(deviceId, listId, entryIds, tenantId, requesterId);
  await auditAs(tenantId, requesterId, `software.${payload.action}`, { deviceId, resourceType: 'device', resourcePath: String(deviceId), details: { listId, entryIds } });
}

import type { Knex } from 'knex';
import type { Ownership } from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { privacyRulesFor } from '../../apple/devices/privacy';
import { applyCollectionRules } from '../inventory/ingestors';

// =============================================================================
// Changes of the record an operator makes (docs: modele-donnees-mdm §4.3,
// §10.3): the ownership (between corporate and corporate_personal, in device
// mode, under the restriction device.change_ownership: the approved circuit
// of REQ-01; any other change goes through a new enrollment, and the trigger
// devices_guard_ownership refuses it in the base), the group of devices.
// In the caller's transaction and tenant context.
// =============================================================================

const CHANGEABLE = new Set<Ownership>(['corporate', 'corporate_personal']);

/**
 * Changes the ownership of a device under management between corporate and corporate_personal (device
 * mode). The reason is required; a ticket too when the change widens the collection (corporate_personal →
 * corporate: the unmanaged apps get inventoried, the employee is to be informed, USR-01). Narrowing
 * (corporate → corporate_personal) applies the new privacy rules at once: the unmanaged apps leave the
 * inventory, the device name and the raw answers keep only what the rules collect. Audit
 * device.ownership_changed (critical, P1: written in the transaction, before its commit).
 */
export async function changeOwnership(trx: Knex.Transaction, tenantId: number, deviceId: number, to: Ownership,
  auditCtx: AuditWriteContext, reason: string, ticket: string | null): Promise<{ from: Ownership; to: Ownership }> {
  const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).forUpdate()
    .first('ownership', 'management_mode', 'enrollment_state') as { ownership: Ownership; management_mode: string; enrollment_state: string } | undefined;
  if (!d) throw new AppError(404, 'Device not found');
  if (!CHANGEABLE.has(d.ownership) || !CHANGEABLE.has(to) || d.management_mode !== 'device' || d.ownership === to
    || d.enrollment_state === 'unenrolled') {
    throw new AppError(409, 'The ownership changes between corporate and corporate_personal only, on a managed device in device mode; any other change is a new enrollment',
      'ownershipChangeNotAllowed', { from: d.ownership, to });
  }
  const why = reason.trim();
  if (!why) throw new AppError(400, 'A reason is required', 'invalidRequest', { field: 'reason' });
  if (d.ownership === 'corporate_personal' && to === 'corporate' && !(ticket && ticket.trim())) {
    throw new AppError(400, 'A ticket is required to widen the collection of a device', 'invalidRequest', { field: 'ticket' });
  }
  await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update({ ownership: to, updated_at: new Date() });
  let purgedApps = 0;
  if (to === 'corporate_personal') {
    // Narrowing: the rules of the new ownership apply at once to what the inventory holds.
    ({ purgedApps } = await applyCollectionRules(trx, tenantId, deviceId, await privacyRulesFor(trx, tenantId, to, 'Device')));
  }
  await audit.appendInTx(trx, {
    tenantId, action: 'device.ownership_changed', target: { type: 'device', id: String(deviceId), device: deviceId },
    reason: why.slice(0, 500), ticket: ticket?.trim() ? ticket.trim().slice(0, 100) : undefined,
    details: { from: d.ownership, to, purgedApps },
  }, auditCtx);
  return { from: d.ownership, to };
}

/**
 * Moves devices of `tenantId` into a group of the same tenant (or out of any group: null). Returns the ids
 * whose group actually changed. The caller checks the rights (devices.manage, write on the group) and the
 * restriction device.bulk_group_change; the resolution of the policies follows the move (lot B5).
 */
export async function moveToGroup(trx: Knex.Transaction, tenantId: number, deviceIds: number[], groupId: number | null): Promise<number[]> {
  if (groupId !== null) {
    const g = await trx('device_groups').where({ tenant_id: tenantId, id: groupId }).first('id');
    if (!g) throw new AppError(404, 'Group not found');
  }
  const ids = [...new Set(deviceIds.filter((n) => Number.isSafeInteger(n) && n > 0))];
  if (ids.length === 0) return [];
  const before = await trx('devices').whereIn('id', ids).where({ tenant_id: tenantId }).select('id', 'group_id') as
    Array<{ id: number; group_id: number | null }>;
  const changed = before.filter((d) => (d.group_id === null ? null : Number(d.group_id)) !== groupId).map((d) => Number(d.id));
  if (changed.length) {
    await trx('devices').whereIn('id', changed).where({ tenant_id: tenantId }).update({ group_id: groupId, updated_at: new Date() });
  }
  return changed;
}

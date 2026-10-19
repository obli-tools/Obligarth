import { refuse, type ApprovalExecution } from './approval.service';

// ── Approval executors of the device actions ────────────────────────────────
// Registered by modules/devices.ts. A bulk group change filed before the moves
// of devices were previewed (change_group) is refused: a move is now a request
// of the type mdm_policy_publish (mdm/policies/deviceMove.ts). The
// deletion of records is the guarded action device.delete (audit-durci
// §10.2): a deletion request filed before it is refused. The agent's requests
// (device_uninstall, the tenant transfer of rls-tenant R10) are gone with the
// agent (modele-donnees-mdm §11.1): no executor, refused by the engine.

/** Message of a bulk group change filed before the moves of devices were previewed. */
const MOVE_PREVIEWED = 'A move of devices into a group is previewed and guarded like a change of assignments since this version '
  + '(modele-donnees-mdm S12): this request was filed before and is not executed — move the devices again';

/**
 * A bulk group change filed before the moves of devices were previewed ('change_group'): refused, nothing moved.
 * A move of devices now files a request of the type mdm_policy_publish (kind device_move, mdm/policies/deviceMove.ts)
 * whose executor compares the preview with the one approved; this one carries no preview (decision of the owners of
 * 15/10/2026 on S12).
 */
export async function executeChangeGroup(_x: ApprovalExecution): Promise<string | void> {
  refuse(MOVE_PREVIEWED);
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

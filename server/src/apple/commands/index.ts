import type { Knex } from 'knex';
import { guardReviewerPolicy } from '../../guard/approvals';
import { registerApprovalRequestType } from '../../services/approval.service';
import { registerRestrictableActions } from '../../services/restriction.service';
import { mdmCommands } from './bus';
import { commandSpecList, registerMvpCommandSpecs } from './catalog';
import { registerGuardedMdmActions } from './guarded';
import { registerInventory } from './inventory';
import { registerResultSummarizer } from './results';
import { executeAppleAction } from './routes';
import { registerSetup } from './setup';
import { registerCommandJobs } from './submit';

// =============================================================================
// The MDM command queue (docs: integration-apple-edge §8; modele-donnees-mdm
// §6): what registerAppleModule registers of it, before anything starts and
// without I/O.
//   catalogue   the 23 command types of the MVP (catalog.ts)
//   jobs        submission, cancellation, held commands, relaunches, expiry
//   guard       the guarded MDM actions (erase, lock, lost mode, removal from
//               management) and their MDM execution
//   matrix      the restrictable actions of the commands and their floors
//   approvals   'apple_action': a command the matrix holds at 'restricted'
//   inventory   the initial inventory (onboarding step), the periodic one
//   setup       the setup plan of an ADE device awaiting its configuration
// =============================================================================

export { mdmCommands } from './bus';
export type { EnqueueOutcome, EnqueueRequest, MdmCommandBus } from './bus';
export { registerCommandSpec, type CommandSpec, type CommandDeviceContext } from './catalog';
export { defineGuardedMdmAction, type GuardedMdmActionOptions } from './guarded';
export { registerProfileSource, type ProfileSource, type ResolvedProfile } from './sensitive';
export { registerSetupContributor, type SetupContributor } from './setup';
export { createAppleCommandsRouter } from './routes';

/** The restrictable actions of the Apple integration (§8.11, I23): floors a tenant's matrix can raise, never lower.
 *  The keys of the guarded actions are registered by registerGuardedAction; those of apple-edge's administration by
 *  the administration routes (lot B1). */
export const APPLE_RESTRICTABLE_ACTIONS = [
  { key: 'mdm.restart', label: 'Restart or shut down devices', category: 'Apple MDM' },
  { key: 'mdm.clear_passcode', label: 'Clear the passcode of a device', category: 'Apple MDM' },
  { key: 'mdm.lost_mode', label: 'Lost mode: disable, locate, play a sound', category: 'Apple MDM' },
  { key: 'mdm.profiles', label: 'Install or remove profiles', category: 'Apple MDM' },
  { key: 'mdm.apps', label: 'Install or remove apps', category: 'Apple MDM' },
  { key: 'mdm.settings', label: 'Change device settings', category: 'Apple MDM' },
  { key: 'apple.integrations', label: 'Import or delete Apple tokens and certificates', category: 'Apple MDM' },
  { key: 'apple.push_topic_change', label: 'Replace the push certificate by one of another topic', category: 'Apple MDM' },
  { key: 'apple.ade_token_delete', label: 'Delete an ADE server', category: 'Apple MDM' },
  { key: 'apple.vpp_token_takeover', label: 'Take over an Apps and Books token used by another MDM', category: 'Apple MDM' },
  { key: 'apple.device_transfer', label: 'Transfer a device to another tenant', category: 'Apple MDM' },
  { key: 'apple.device_identity_revoke', label: 'Revoke the identity of a device', category: 'Apple MDM' },
] as const;

/**
 * The sender of the DeclarativeManagement command the DDM engine asks for (its registerDdmSyncSender, §9.4): one
 * command of origin 'ddm' for the device, in the caller's transaction; `data` is the Command.Data (the bytes of the
 * synchronisation tokens). The bus keeps one such command open per device (already_open).
 */
export async function sendDdmSyncCommand(trx: Knex.Transaction, c: { tenantId: number; deviceId: number; data: Buffer; actor: string }):
  Promise<{ commandId: string } | { refused: string }> {
  const o = await mdmCommands.enqueue(trx, {
    tenantId: c.tenantId, requestType: 'DeclarativeManagement', deviceIds: [c.deviceId], params: { data: c.data.toString('base64') },
    origin: 'ddm', actor: c.actor,
  });
  return o.commandIds[0] ? { commandId: o.commandIds[0] } : { refused: o.refused[0]?.code ?? 'refused' };
}

let registered = false;

export function registerAppleCommands(): void {
  if (registered) return;
  registered = true;
  registerMvpCommandSpecs();
  for (const spec of commandSpecList()) if (spec.summarize) registerResultSummarizer(spec.requestType, spec.summarize);
  registerCommandJobs();
  // Guarded actions first: their keys open the category of the matrix.
  registerGuardedMdmActions();
  // Floors only, no stored default: a floor holds whatever a tenant's matrix says, for the tenants that exist as
  // for the new ones (no row to write for an existing tenant). apple.integrations has no floor (§8.11): its
  // recommended level is stored with its routes (lot C3).
  registerRestrictableActions(APPLE_RESTRICTABLE_ACTIONS, {}, {
    'mdm.clear_passcode': { level: 'sensitive' }, 'mdm.lost_mode': { level: 'sensitive' }, 'apple.push_topic_change': { level: 'restricted' },
    'apple.ade_token_delete': { level: 'restricted' }, 'apple.vpp_token_takeover': { level: 'sensitive' }, 'apple.device_transfer': { level: 'restricted' },
    'apple.device_identity_revoke': { level: 'sensitive' },
  });
  // A command the matrix holds at 'restricted': a second person approves it (the guard's examination policy: a
  // client approver by default, the MSP as a signalled fallback), with a strict step-up of the reviewer.
  registerApprovalRequestType('apple_action', executeAppleAction, { expiryMinutes: 240, reviewerPolicy: guardReviewerPolicy, reviewerStepUp: 'strict' });
  registerInventory();
  registerSetup();
}

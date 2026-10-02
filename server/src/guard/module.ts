// Registration of the guard engine in the core's registries (index.ts, with
// the other modules, no I/O): its audit actions, its restrictable actions
// and their floors, its request types in the approval engine, its jobs.
import { registerAuditActions } from '../audit';
import { registerRestrictableActions } from '../services/restriction.service';
import { registerGuardApprovals } from './approvals';
import { registerGuardJobs } from './jobs';

/** The restrictable actions of the engine itself (audit-durci §12.2): floors
 *  'restricted', not lowerable by any matrix. */
export const GUARD_RESTRICTABLE_ACTIONS = [
  { key: 'guard.unfreeze', label: 'Lift the emergency freeze of the tenant', category: 'Guards' },
  { key: 'guard.settings_change', label: 'Change the hourly cap or the side of the approver of mass actions', category: 'Guards' },
  { key: 'guard.approvers_change', label: 'Designate an approver of the guarded actions', category: 'Guards' },
] as const;

let registered = false;

export function registerGuardModule(): void {
  if (registered) return;
  registered = true;
  // Classes of audit-durci §3.4: 'critical' written before the action (P1),
  // 'protective' never blocked (P4), 'standard' after the fact (P3).
  registerAuditActions([
    { name: 'guard.action_requested', criticality: 'critical', label: 'Guarded action requested' },
    { name: 'guard.action_targets', criticality: 'critical', label: 'Targets of the guarded action (continued)' },
    { name: 'guard.action_scheduled', criticality: 'critical', label: 'Guarded action scheduled' },
    { name: 'guard.action_resumed', criticality: 'critical', label: 'Guarded action resumed' },
    { name: 'guard.action_executing', criticality: 'critical', label: 'Guarded action executing' },
    { name: 'guard.tenant_unfrozen', criticality: 'critical', label: 'Tenant unfrozen' },
    { name: 'guard.settings_changed', criticality: 'critical', label: 'Guard settings changed' },
    { name: 'guard.approver_designated', criticality: 'critical', label: 'Approver designated' },
    { name: 'guard.action_cancelled', criticality: 'protective', label: 'Guarded action cancelled' },
    { name: 'guard.action_paused', criticality: 'protective', label: 'Guarded action paused' },
    { name: 'guard.tenant_frozen', criticality: 'protective', label: 'Tenant frozen' },
    { name: 'guard.approver_revoked', criticality: 'protective', label: 'Approver revoked' },
    { name: 'guard.action_executed', criticality: 'standard', label: 'Guarded action executed' },
    { name: 'guard.action_refused', criticality: 'standard', label: 'Guarded action refused' },
    { name: 'guard.action_expired', criticality: 'standard', label: 'Guarded action expired' },
    { name: 'guard.anomaly_detected', criticality: 'standard', label: 'Anomaly detected by the guards' },
    { name: 'guard.approver_fallback', criticality: 'standard', label: 'Approval by the MSP instead of a client approver' },
  ]);
  registerRestrictableActions(GUARD_RESTRICTABLE_ACTIONS, {}, {
    'guard.unfreeze': { level: 'restricted' },
    'guard.settings_change': { level: 'restricted' },
    'guard.approvers_change': { level: 'restricted' },
  });
  registerGuardApprovals();
  registerGuardJobs();
}

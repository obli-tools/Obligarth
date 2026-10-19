import { registerAuditActions } from '../audit';

// =============================================================================
// The audit actions of the bridge agent (docs: agent-pont-android §6, RS-1):
// declared once. 'critical' written before the action (the export of the
// instance key, a release of the agent, its withdrawal); 'protective' never
// blocked (revocations, cancellations); 'standard' after the fact. No entry
// carries a token, a key, a secret nor an inventory value.
// =============================================================================

let registered = false;

export function registerLegacyAgentAuditActions(): void {
  if (registered) return;
  registered = true;
  registerAuditActions([
    { name: 'legacy_agent.token_created', criticality: 'standard', label: 'Android agent enrollment token created' },
    { name: 'legacy_agent.token_revoked', criticality: 'protective', label: 'Android agent enrollment token revoked' },
    { name: 'legacy_agent.device_enrolled', criticality: 'standard', label: 'Android agent enrolled' },
    { name: 'legacy_agent.identity_conflict', criticality: 'standard', label: 'Android agent identity conflict' },
    { name: 'legacy_agent.device_revoked', criticality: 'protective', label: 'Android agent revoked' },
    { name: 'legacy_agent.command_queued', criticality: 'standard', label: 'Android agent command queued' },
    { name: 'legacy_agent.command_cancelled', criticality: 'protective', label: 'Android agent command cancelled' },
    { name: 'legacy_agent.package_uploaded', criticality: 'standard', label: 'Android package uploaded' },
    { name: 'legacy_agent.release_uploaded', criticality: 'critical', label: 'Android agent version uploaded' },
    { name: 'legacy_agent.release_withdrawn', criticality: 'critical', label: 'Android agent version withdrawn' },
    { name: 'legacy_agent.knox_key_set', criticality: 'standard', label: 'Knox licence key of the Android agents changed' },
    { name: 'legacy_agent.admin_disabled', criticality: 'standard', label: 'Device administrator disabled on an Android agent' },
    { name: 'legacy_agent.settings_changed', criticality: 'standard', label: 'Android agent settings changed' },
    { name: 'legacy_agent.server_key_exported', criticality: 'critical', label: 'Android agent instance key exported for escrow' },
  ]);
}

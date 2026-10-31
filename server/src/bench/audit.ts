import { registerAuditActions } from '../audit';

// =============================================================================
// The audit actions of the bench stations (lot BANC §3.10): declared once. 'critical' written before the action (an
// approval, a resumption, an open session, a target added, the exception D3, the version served, a token issued);
// 'protective' never blocked (revocations, suspensions, refusals of identity); 'standard' after the fact. No entry
// carries a token, a configuration, an account name or address; serial numbers cut to their last four characters.
// =============================================================================

let registered = false;

export function registerBenchAuditActions(): void {
  if (registered) return;
  registered = true;
  registerAuditActions([
    { name: 'bench.station_registered', criticality: 'standard', label: 'Bench station registered' },
    { name: 'bench.station_approved', criticality: 'critical', label: 'Bench station approved' },
    { name: 'bench.station_revoked', criticality: 'protective', label: 'Bench station revoked' },
    { name: 'bench.station_suspended', criticality: 'protective', label: 'Bench station suspended' },
    { name: 'bench.station_resumed', criticality: 'critical', label: 'Bench station resumed' },
    { name: 'bench.station_renamed', criticality: 'standard', label: 'Bench station renamed' },
    { name: 'bench.session_opened', criticality: 'critical', label: 'Bench session opened' },
    { name: 'bench.session_closed', criticality: 'protective', label: 'Bench session closed' },
    { name: 'bench.target_added', criticality: 'critical', label: 'Bench station target added' },
    { name: 'bench.target_changed', criticality: 'critical', label: 'Bench station target changed' },
    { name: 'bench.target_removed', criticality: 'protective', label: 'Bench station target removed' },
    { name: 'bench.target_suspended', criticality: 'protective', label: 'Bench station target suspended' },
    { name: 'bench.target_resumed', criticality: 'critical', label: 'Bench station target resumed' },
    { name: 'bench.legacy_owner_allowed', criticality: 'critical', label: 'Bench target: device owner with an agent older than 1.4.0 allowed' },
    { name: 'legacy_agent.bench_release_set', criticality: 'critical', label: 'Android agent version served to the bench stations' },
    { name: 'bench.provisioning_mismatch', criticality: 'protective', label: 'Bench enrollment refused: provisioning mismatch' },
    { name: 'bench.identity_conflict_cross_tenant', criticality: 'protective', label: 'Bench serial number held in another tenant' },
    { name: 'bench.token_quota', criticality: 'protective', label: 'Bench station near its daily token quota' },
    { name: 'bench.provisioning_planned', criticality: 'standard', label: 'Bench provisioning planned' },
    { name: 'bench.token_issued', criticality: 'critical', label: 'Bench enrollment token issued' },
    { name: 'bench.provisioning_completed', criticality: 'standard', label: 'Bench provisioning completed' },
    { name: 'bench.provisioning_failed', criticality: 'standard', label: 'Bench provisioning failed' },
    { name: 'bench.provisioning_abandoned', criticality: 'standard', label: 'Bench provisioning abandoned' },
    { name: 'bench.provisioning_expired', criticality: 'standard', label: 'Bench provisioning expired' },
    { name: 'bench.identity_mismatch', criticality: 'protective', label: 'Bench enrollment refused: serial numbers differ' },
    { name: 'legacy_agent.device_owner_gained', criticality: 'standard', label: 'Android agent became the owner of the device' },
    { name: 'legacy_agent.device_owner_lost', criticality: 'protective', label: 'Android agent lost the owner role of the device' },
    { name: 'legacy_agent.device_owner_released', criticality: 'standard', label: 'Android agent gave the device back' },
    { name: 'legacy_agent.bench_window_opened', criticality: 'protective', label: 'Android agent: bench window opened (Knox lock of the administrator lifted)' },
  ]);
}

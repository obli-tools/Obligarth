import { registerAuditActions } from '../audit';

// =============================================================================
// The audit actions of the Apple integration (docs: integration-apple-edge
// annex F; audit-durci §3.4): declared once, for every lot of the
// integration (an action written by a later lot is declared already). Classes:
// 'critical' written before the action (P1, P2), 'protective' never blocked
// (P4), 'standard' after the fact (P3). The entries of the outbox handlers go
// through ctx.audit (written at the end of the batch: review INT-RC8); none
// carries a plist, a token, a challenge nor an inventory value.
// =============================================================================

let registered = false;

export function registerAppleAuditActions(): void {
  if (registered) return;
  registered = true;
  registerAuditActions([
    // Tenant registry (§6)
    { name: 'apple.tenant_provisioned', criticality: 'standard', label: 'Tenant provisioned at the device service' },
    { name: 'apple.tenant_state_changed', criticality: 'critical', label: 'Tenant suspended or resumed at the device service' },
    { name: 'apple.tenant_ca_rotated', criticality: 'critical', label: 'Device CA of the tenant rotated' },
    // Devices (§7.4)
    { name: 'device.enrolled', criticality: 'standard', label: 'Device enrolled' },
    { name: 'device.checked_out', criticality: 'standard', label: 'Device left management' },
    { name: 'device.id_released', criticality: 'standard', label: 'Device identifier released' },
    { name: 'device.transfer_completed', criticality: 'standard', label: 'Device transfer completed' },
    { name: 'security.topic_mismatch', criticality: 'standard', label: 'Push topic mismatch' },
    { name: 'security.identity_expired', criticality: 'standard', label: 'Expired device identity presented' },
    { name: 'security.identity_revoked', criticality: 'standard', label: 'Revoked device identity presented' },
    { name: 'security.identity_mismatch', criticality: 'standard', label: 'Device identity mismatch' },
    { name: 'security.device_id_conflict', criticality: 'standard', label: 'Device identifier conflict' },
    // The platform event of §7.4 (audited in the master tenant), not listed by annex F (lot B3).
    { name: 'security.foreign_certificate', criticality: 'standard', label: 'Certificate of another tenant presented' },
    { name: 'apns.push_refused', criticality: 'standard', label: 'Push refused by Apple' },
    { name: 'integration.push_certificate_activated', criticality: 'standard', label: 'Push certificate activated' },
    { name: 'integration.ade_token_activated', criticality: 'standard', label: 'ADE server activated' },
    // Commands (§8)
    { name: 'mdm.command_requested', criticality: 'standard', label: 'MDM command requested' },
    { name: 'mdm.command_relaunched', criticality: 'standard', label: 'MDM command relaunched' },
    { name: 'mdm.command_cancelled', criticality: 'protective', label: 'MDM command cancelled' },
    { name: 'mdm.command_acknowledged', criticality: 'standard', label: 'MDM command acknowledged' },
    { name: 'mdm.command_failed', criticality: 'standard', label: 'MDM command failed' },
    // Enrollment (§10)
    { name: 'apple.enrollment_profile_saved', criticality: 'standard', label: 'Enrollment profile saved' },
    { name: 'apple.enrollment_token_created', criticality: 'standard', label: 'Enrollment link created' },
    { name: 'apple.enrollment_token_revoked', criticality: 'protective', label: 'Enrollment link revoked' },
    // Apple integrations (§11)
    { name: 'integration.push_request_created', criticality: 'standard', label: 'Push certificate request created' },
    { name: 'integration.push_vendor_file_imported', criticality: 'standard', label: 'Vendor-signed push request imported' },
    { name: 'integration.push_certificate_imported', criticality: 'critical', label: 'Push certificate imported' },
    { name: 'integration.push_topic_change_requested', criticality: 'critical', label: 'Change of push topic requested' },
    { name: 'integration.ade_token_created', criticality: 'standard', label: 'ADE server created' },
    { name: 'integration.ade_sync_requested', criticality: 'standard', label: 'ADE synchronisation requested' },
    { name: 'integration.ade_byod_discovery_declared', criticality: 'standard', label: 'Account-driven enrollment declared' },
    { name: 'integration.ade_token_uploaded', criticality: 'critical', label: 'ADE server token uploaded' },
    { name: 'integration.ade_token_deleted', criticality: 'critical', label: 'ADE server deleted' },
    { name: 'integration.vpp_token_imported', criticality: 'critical', label: 'Apps and Books token imported' },
    { name: 'integration.vpp_token_taken_over', criticality: 'critical', label: 'Apps and Books token taken over' },
    { name: 'integration.vpp_token_removed', criticality: 'critical', label: 'Apps and Books token removed' },
    // Retirement, transfer, recovery, support (§13, §11.6)
    { name: 'apple.device_identity_revoked', criticality: 'critical', label: 'Device identity revoked' },
    { name: 'apple.device_transfer_executed', criticality: 'critical', label: 'Device transfer executed' },
    { name: 'apple.restore_check', criticality: 'standard', label: 'Device service checked after a restore' },
    { name: 'apple.support_refs_requested', criticality: 'standard', label: 'Support references of devices requested' },
  ]);
}

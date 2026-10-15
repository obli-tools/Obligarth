// Audit actions of the Android integration (annex D of the specification): identifiers and counters only in the
// details, never a token, a key, an e-mail nor a device datum.
import { registerAuditActions } from '../audit';

let registered = false;

export function registerAndroidAuditActions(): void {
  if (registered) return;
  registered = true;
  registerAuditActions([
    { name: 'android.google_credentials_set', criticality: 'critical', label: 'Android: Google identity of the instance set' },
    { name: 'android.google_credentials_rotated', criticality: 'critical', label: 'Android: Google identity of the instance rotated' },
    { name: 'android.project_pinned', criticality: 'critical', label: 'Android: Google Cloud project pinned' },
    { name: 'android.enterprise_signup_started', criticality: 'standard', label: 'Android: enterprise signup started' },
    { name: 'android.signup_callback_rejected', criticality: 'standard', label: 'Android: signup callback rejected' },
    { name: 'android.enterprise_linked', criticality: 'critical', label: 'Android: enterprise linked' },
    { name: 'android.enterprise_adopted', criticality: 'critical', label: 'Android: orphan enterprise adopted' },
    { name: 'android.enterprise_unlink_requested', criticality: 'critical', label: 'Android: enterprise unlink requested' },
    { name: 'android.enterprise_unlinked', criticality: 'critical', label: 'Android: enterprise unlinked' },
    { name: 'android.enterprise_settings_changed', criticality: 'standard', label: 'Android: enterprise settings changed' },
    { name: 'android.enrollment_token_created', criticality: 'standard', label: 'Android: enrollment token created' },
    { name: 'android.enrollment_token_revealed', criticality: 'standard', label: 'Android: enrollment token shown again' },
    { name: 'android.enrollment_token_revoked', criticality: 'standard', label: 'Android: enrollment token revoked' },
    { name: 'android.device_rejected', criticality: 'standard', label: 'Android: device rejected' },
    { name: 'android.device_quarantined', criticality: 'standard', label: 'Android: device quarantined' },
    { name: 'android.inbox_dead_letter_viewed', criticality: 'critical', label: 'Android: dead letter viewed' },
    { name: 'android.inbox_dead_letter_redriven', criticality: 'standard', label: 'Android: dead letter redriven' },
    { name: 'android.inbox_dead_letter_discarded', criticality: 'standard', label: 'Android: dead letter discarded' },
    { name: 'android.device_forgotten', criticality: 'critical', label: 'Android: device forgotten' },
    { name: 'android.enterprise_terms_accepted', criticality: 'critical', label: 'Android: publisher terms accepted' },
    { name: 'android.enterprise_force_unlinked', criticality: 'critical', label: 'Android: enterprise unlinked by force' },
    { name: 'android.enterprise_released', criticality: 'critical', label: 'Android: enterprise released' },
    { name: 'android.gateway_cap_reached', criticality: 'critical', label: 'Android: last-resort cap reached' },
    { name: 'android.ownership_violation', criticality: 'critical', label: 'Android: ownership check refused a call' },
    { name: 'android.device_reject_executed', criticality: 'critical', label: 'Android: device rejection executed' },
    { name: 'android.device_approved', criticality: 'standard', label: 'Android: device approved' },
    { name: 'android.device_approval_refused', criticality: 'standard', label: 'Android: device approval refused' },
    { name: 'android.enterprise_upgraded', criticality: 'standard', label: 'Android: enterprise upgraded to a managed domain' },
  ]);
}

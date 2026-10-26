import { registerAuditActions } from '../audit';
import { registerApprovalRequestType } from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { registerProfileApplicationJob } from './apply';
import { executeProfileChange, privacyReviewerPolicy } from './approvals';
import {
  PROFILE_CHANGE_EXPIRY_MINUTES, PROFILE_CHANGE_REQUEST_TYPE, RETENTION_CHANGE_EXPIRY_MINUTES, RETENTION_CHANGE_REQUEST_TYPE,
} from './requests';
import { executeRetentionChange } from './retentionPolicy';

// =============================================================================
// The privacy profiles (P0-13 T3, CNF-02) and the retention (P0-13 T4, CNF-04) of the tenants in the core's registries,
// called by registerPrivacyModule (modules/privacy.ts) before anything starts, no I/O:
//   audit       privacy.profile_change_requested (standard), privacy.profile_changed (critical, P1 in the transaction of
//               the publication), privacy.data_scrubbed (standard, counters only); privacy.retention_change_requested
//               (standard), privacy.retention_changed (critical, written by obligarth.retention_set in its
//               transaction; a decrease cancelled is such a change, approved: D3, D4)
//   matrix      privacy.profile_change, privacy.retention_change: floor 'restricted' (D3: always a second person, not
//               configurable)
//   approvals   privacy_profile_change: examined by a client approver of the tenant, else another platform
//               administrator (strict second factor of the reviewer), one day to decide; executed as the requester;
//               privacy_retention_change: the same examination (privacy/retentionPolicy.ts)
//   jobs        privacy.apply-profile (privacy/apply.ts)
// The console API is createPrivacyRouter (privacy/routes.ts), mounted at /api/privacy with the tenant's routes.
// =============================================================================

export { createPrivacyRouter } from './routes';
export { onProfilePublished } from './approvals';

let registered = false;

export function registerPrivacyProfileChanges(): void {
  if (registered) return;
  registered = true;
  registerAuditActions([
    { name: 'privacy.profile_change_requested', criticality: 'standard', label: 'Change of a privacy profile requested' },
    { name: 'privacy.profile_changed', criticality: 'critical', label: 'Privacy profile changed' },
    { name: 'privacy.data_scrubbed', criticality: 'standard', label: 'Data no longer collected cleaned' },
    { name: 'privacy.retention_change_requested', criticality: 'standard', label: 'Change of the retention requested' },
    { name: 'privacy.retention_changed', criticality: 'critical', label: 'Retention changed' },
  ]);
  registerRestrictableActions(
    [
      { key: 'privacy.profile_change', label: 'Change a privacy profile (what the devices report)', category: 'Privacy' },
      { key: 'privacy.retention_change', label: 'Change the retention of the data of the devices', category: 'Privacy' },
    ],
    {},
    { 'privacy.profile_change': { level: 'restricted' }, 'privacy.retention_change': { level: 'restricted' } },
  );
  registerApprovalRequestType(PROFILE_CHANGE_REQUEST_TYPE, executeProfileChange, {
    expiryMinutes: PROFILE_CHANGE_EXPIRY_MINUTES, reviewerPolicy: privacyReviewerPolicy, reviewerStepUp: 'strict',
  });
  registerApprovalRequestType(RETENTION_CHANGE_REQUEST_TYPE, executeRetentionChange, {
    expiryMinutes: RETENTION_CHANGE_EXPIRY_MINUTES, reviewerPolicy: privacyReviewerPolicy, reviewerStepUp: 'strict',
  });
  registerProfileApplicationJob();
}

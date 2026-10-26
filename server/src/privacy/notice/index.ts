import { registerAuditActions } from '../../audit';
import { setEnrollmentNoticeProvider } from '../../apple/enrollment/notice';
import { setAndroidNoticeProvider } from '../../android/byod/notice';
import { onProfilePublished } from '../approvals';
import { onRetentionChanged } from '../retentionPolicy';
import { androidNoticeProvider, appleNoticeProvider } from './provider';
import { registerNoticeRegenerationJob, requestNoticeRegeneration } from './regenerate';

// =============================================================================
// The notice of the employees (P0-13 T5, USR-01) in the core's registries, called by registerPrivacyModule
// (modules/privacy.ts) before anything starts, no I/O:
//   providers   the generated notice replaces the laboratory's default notices of Apple (setEnrollmentNoticeProvider)
//               and of personal Android devices (setAndroidNoticeProvider): usesDefaultNotice() is false from then on
//   audit       privacy.notice_published (standard: hash and versions of a version published),
//               privacy.notice_settings_changed (standard: the keys changed, P0-13 T6, written by routes.ts)
//   jobs        privacy.notice-regenerate (regenerate.ts), queued in the transaction of a publication of a privacy
//               profile, of a change of the retention and of a change of the settings of the notice (routes.ts); the
//               daily retention queues it too (modules/privacy.ts)
// The console API (routes.ts) is mounted with the privacy routes; the public page /t/<key>/notice (surface.ts, D6) by
// app.ts.
// The acknowledgements are purged by the rule notice_acknowledgements (retention.ts) of privacy.retention-tenant.
// =============================================================================

export { requestNoticeRegeneration } from './regenerate';
export { noticeRetentionRules } from './retention';

let registered = false;

export function registerNotice(): void {
  if (registered) return;
  registered = true;
  setEnrollmentNoticeProvider(appleNoticeProvider);
  setAndroidNoticeProvider(androidNoticeProvider);
  registerAuditActions([
    { name: 'privacy.notice_published', criticality: 'standard', label: 'Employee notice published (new version)' },
    { name: 'privacy.notice_settings_changed', criticality: 'standard', label: 'Settings of the employee notice changed' },
  ]);
  registerNoticeRegenerationJob();
  onProfilePublished('notice', (trx, p) => requestNoticeRegeneration(trx, p.tenantId).then(() => undefined));
  onRetentionChanged('notice', (trx, p) => requestNoticeRegeneration(trx, p.tenantId).then(() => undefined));
}

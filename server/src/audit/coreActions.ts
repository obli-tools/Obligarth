// The core's audit actions (docs: audit-durci §3.4), declared when the audit
// module is loaded. Families (a name ending with '.') take the class of their
// actions not listed one by one; an exact name always wins over its family.
// Classes: 'critical' is written before the action (P1 in its transaction,
// P2 as a prior intent) and refuses the action when it cannot be written;
// 'protective' never blocks (after the action, spooled on failure);
// 'standard' after the action, spooled on failure.
import { registerAuditActions } from './catalog';

let registered = false;

export function registerCoreAuditActions(): void {
  if (registered) return;
  registered = true;
  registerAuditActions([
    // ── Sign-in, second factors, delegation, SSO (P3; demotions P4) ────────
    { name: 'auth.', criticality: 'standard', label: 'Authentication' },
    { name: 'auth.login', criticality: 'standard', label: 'Signed in' },
    { name: 'auth.login_failed', criticality: 'standard', label: 'Sign-in failed' },
    { name: 'auth.login_refused', criticality: 'standard', label: 'Sign-in refused' },
    { name: 'auth.logout', criticality: 'standard', label: 'Signed out' },
    { name: 'auth.step_up_failed', criticality: 'standard', label: 'Step-up verification failed' },
    { name: 'auth.step_up_locked', criticality: 'standard', label: 'Step-up verification locked' },
    { name: 'auth.totp_drift', criticality: 'standard', label: 'Authenticator clock drift' },
    { name: 'user.totp_enabled', criticality: 'standard', label: 'Two-factor authentication enabled' },
    { name: 'user.totp_disabled', criticality: 'standard', label: 'Two-factor authentication disabled' },
    { name: 'user.totp_replaced', criticality: 'standard', label: 'Two-factor authentication replaced' },
    { name: 'user.email_otp_enabled', criticality: 'standard', label: 'E-mail codes enabled' },
    { name: 'user.email_otp_disabled', criticality: 'standard', label: 'E-mail codes disabled' },
    { name: 'delegation.', criticality: 'standard', label: 'Delegated access' },
    { name: 'device_key.', criticality: 'standard', label: 'Phone key' },
    { name: 'sso.', criticality: 'standard', label: 'Single sign-on' },
    { name: 'sso_sync.', criticality: 'standard', label: 'Account synchronisation from Obligate' },
    { name: 'sso_sync.demoted', criticality: 'protective', label: 'Account demoted by Obligate' },
    { name: 'sso_sync.deactivated', criticality: 'protective', label: 'Account deactivated by Obligate' },
    { name: 'sso_sync.deleted', criticality: 'protective', label: 'Account deleted by Obligate' },

    // ── Accounts and memberships ───────────────────────────────────────────
    { name: 'user.created', criticality: 'standard', label: 'Account created' },
    { name: 'user.updated', criticality: 'standard', label: 'Account updated' },
    { name: 'user.deactivated', criticality: 'protective', label: 'Account deactivated' },
    { name: 'user.deleted', criticality: 'protective', label: 'Account deleted' },
    { name: 'user.device_keys_revoked', criticality: 'protective', label: 'Phone keys revoked' },
    { name: 'user.role_changed', criticality: 'critical', label: 'Platform role changed' },
    { name: 'user.tenants_changed', criticality: 'critical', label: 'Tenant memberships changed' },
    { name: 'user.2fa_reset', criticality: 'critical', label: 'Second factors reset' },
    { name: 'user.password_reset_admin', criticality: 'critical', label: 'Password reset by an administrator' },
    { name: 'tenant.member_added', criticality: 'critical', label: 'Member added to the tenant' },
    { name: 'tenant.member_role_changed', criticality: 'critical', label: 'Member role changed' },
    { name: 'tenant.member_removed', criticality: 'protective', label: 'Member removed from the tenant' },

    // ── Teams ──────────────────────────────────────────────────────────────
    { name: 'team.created', criticality: 'standard', label: 'Team created' },
    { name: 'team.updated', criticality: 'standard', label: 'Team updated' },
    { name: 'team.deleted', criticality: 'standard', label: 'Team deleted' },
    { name: 'team.members_changed', criticality: 'critical', label: 'Team members changed' },
    { name: 'team.permissions_changed', criticality: 'critical', label: 'Team permissions changed' },
    { name: 'team.permission_removed', criticality: 'critical', label: 'Team permission removed' },

    // ── Configuration of the tenant (P3) ───────────────────────────────────
    { name: 'group.', criticality: 'standard', label: 'Device group' },
    // The tree of groups carries the inheritance of the policies (modele-donnees-mdm §7.6, S12): a group moved or
    // deleted changes the configuration of its subtree, written with its entry (P1 in its transaction).
    { name: 'group.moved', criticality: 'critical', label: 'Device group moved in the tree' },
    { name: 'group.deleted', criticality: 'critical', label: 'Device group deleted' },
    { name: 'settings.', criticality: 'standard', label: 'Settings' },
    { name: 'profile.', criticality: 'standard', label: 'Own profile' },
    { name: 'api_key.', criticality: 'standard', label: 'Enrolment key' },
    { name: 'report.', criticality: 'standard', label: 'Report' },
    { name: 'notification_channel.', criticality: 'standard', label: 'Notification channel' },

    // ── Device registry (device.delete goes through the guard engine, lot A7) ─
    { name: 'device.approved', criticality: 'standard', label: 'Device approved' },
    { name: 'device.refused', criticality: 'standard', label: 'Device refused' },
    { name: 'device.suspended', criticality: 'standard', label: 'Device suspended' },
    { name: 'device.unsuspended', criticality: 'standard', label: 'Device resumed' },
    { name: 'device.updated', criticality: 'standard', label: 'Device updated' },
    { name: 'device.bulk_group_changed', criticality: 'standard', label: 'Devices moved to a group' },
    { name: 'device.deleted', criticality: 'standard', label: 'Device record deleted' },
    { name: 'device.bulk_deleted', criticality: 'standard', label: 'Device records deleted' },
    { name: 'device.bulk_approved', criticality: 'standard', label: 'Devices approved' },
    // The registry of the MDM data model (lot B2, modele-donnees-mdm §10.7): its routes are part of the
    // core API (/api/mdm), declared with it. The ownership change is critical (P1 in its transaction).
    { name: 'device.ownership_changed', criticality: 'critical', label: 'Device ownership changed' },
    { name: 'device.group_changed', criticality: 'standard', label: 'Device moved to a group' },
    { name: 'device.end_user_assigned', criticality: 'standard', label: 'End user of a device assigned' },
    // A read of the lost-mode positions of a device (SEC-05, audit-durci §3.4): P2, the critical intent written before
    // the read (refused with 503 when it is not), then the result with the number of positions.
    { name: 'lost_mode.location_viewed', criticality: 'critical', label: 'Lost-mode positions of a device viewed' },
    { name: 'end_user.created', criticality: 'standard', label: 'End user created' },
    { name: 'end_user.updated', criticality: 'standard', label: 'End user updated' },
    { name: 'end_user.departed', criticality: 'standard', label: 'End user departed' },
    { name: 'end_user.imported', criticality: 'standard', label: 'End users imported' },

    // ── Restrictions and approvals ─────────────────────────────────────────
    { name: 'restrictions.updated', criticality: 'critical', label: 'Restrictions matrix changed' },
    { name: 'approval.requested', criticality: 'standard', label: 'Approval requested' },
    { name: 'approval.expired', criticality: 'standard', label: 'Approval expired' },
    { name: 'approval.approved', criticality: 'critical', label: 'Approval granted' },
    { name: 'approval.executed', criticality: 'standard', label: 'Approved action refused or done in part' },
    { name: 'approval.denied', criticality: 'protective', label: 'Approval denied' },
    { name: 'approval.cancelled', criticality: 'protective', label: 'Approval cancelled' },

    // ── Tenants and the global view ────────────────────────────────────────
    { name: 'tenant.created', criticality: 'critical', label: 'Tenant created' },
    { name: 'tenant.updated', criticality: 'critical', label: 'Tenant updated' },
    { name: 'tenant.deletion_scheduled', criticality: 'critical', label: 'Tenant deletion scheduled' },
    { name: 'tenant.deleted', criticality: 'critical', label: 'Tenant deleted' },
    { name: 'tenant.restored', criticality: 'critical', label: 'Tenant restored' },
    { name: 'platform.global_view_opened', criticality: 'critical', label: 'Global view opened' },

    // ── The journal itself ─────────────────────────────────────────────────
    { name: 'audit.viewed', criticality: 'standard', label: 'Audit log viewed' },
    { name: 'audit.verified', criticality: 'standard', label: 'Audit chain verified' },
    { name: 'audit.destination_tested', criticality: 'standard', label: 'SIEM destination tested' },
    { name: 'audit.spool_replayed', criticality: 'standard', label: 'Audit spool replayed' },
    { name: 'audit.chain_broken', criticality: 'standard', label: 'Audit chain broken' },
    { name: 'audit.targets', criticality: 'standard', label: 'Targets of the previous entry (continued)' },
    { name: 'audit.exported', criticality: 'critical', label: 'Audit log exported' },
    { name: 'audit.retention_changed', criticality: 'critical', label: 'Audit retention changed' },
    { name: 'audit.legal_hold_changed', criticality: 'critical', label: 'Legal hold changed' },
    { name: 'audit.retention_purged', criticality: 'critical', label: 'Expired audit entries purged' },
    { name: 'audit.destination_created', criticality: 'critical', label: 'SIEM destination created' },
    { name: 'audit.destination_updated', criticality: 'critical', label: 'SIEM destination updated' },
    { name: 'audit.destination_disabled', criticality: 'critical', label: 'SIEM destination disabled' },
    { name: 'audit.destination_deleted', criticality: 'critical', label: 'SIEM destination deleted' },
    { name: 'audit.seal_key_rotated', criticality: 'critical', label: 'Seal key rotated' },
    { name: 'audit.chain_resumed', criticality: 'critical', label: 'Audit chain resumed after a restore' },
  ]);
}

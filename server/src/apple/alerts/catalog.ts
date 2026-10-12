// =============================================================================
// Closed catalogue of the alerts of the Apple integration (docs: integration-
// apple-edge §12.1, I11; review INT-RC13): a kind that is not listed cannot be
// raised. Stable key: 'apple:<kind>', followed by ':<discriminant>' when the
// kind has one (internal identifiers only). Scope 'master': a platform alert,
// filed in the master tenant (1), seen by the platform administrators only.
// The texts never hold a device name, a serial number, a UDID, an Apple
// account, an address nor the name of another tenant; the parameters are
// numbers, dates and configuration labels. The console translates
// apple.alerts.<kind>.title / .message (i18n_key, i18n_params) and falls back
// on the English text rendered here. No import: the unit tests load it.
// =============================================================================

export type AppleAlertScope = 'tenant' | 'master';
export type AppleAlertSeverity = 'info' | 'warning' | 'critical';

export interface AppleAlertDef {
  scope: AppleAlertScope;
  severity: AppleAlertSeverity;
  /** English title and message, with {param} placeholders. */
  title: string;
  message: string;
}

export const APPLE_ALERTS = {
  // ── Enrollment ────────────────────────────────────────────────────────────
  'enrollment.unknown_session': { scope: 'tenant', severity: 'info', title: 'Enrollments without a session', message: '{count} device(s) authenticated without an enrollment session of this tenant: attach them to an enrollment profile or release them.' },
  'enrollment.spike': { scope: 'tenant', severity: 'warning', title: 'Spike of enrollments', message: '{count} enrollments in {minutes} minutes.' },
  'enrollment.setup_timeout': { scope: 'tenant', severity: 'warning', title: 'Setup not completed in time', message: 'A device waited for its configuration longer than allowed and was released from the setup assistant.' },
  'enrollment.profile_misconfigured': { scope: 'tenant', severity: 'warning', title: 'Enrollment profile to fix', message: 'The enrollment profile {profileName} cannot serve enrollments as configured.' },
  'enrollment.invitation_locked': { scope: 'tenant', severity: 'warning', title: 'Enrollment invitation locked', message: 'An enrollment invitation was revoked after too many wrong codes.' },
  'enrollment.ownership_mismatch': { scope: 'tenant', severity: 'warning', title: 'Ownership differs from the enrollment profile', message: 'A device enrolled with an ownership its enrollment profile does not allow.' },
  // ── Devices ───────────────────────────────────────────────────────────────
  'device.checked_out': { scope: 'tenant', severity: 'info', title: 'Device left management', message: 'A company device removed its management profile.' },
  'device.superseded': { scope: 'tenant', severity: 'warning', title: 'Device enrolled again elsewhere', message: 'A device of this tenant was enrolled again and its previous enrollment was released.' },
  'device.serial_changed': { scope: 'tenant', severity: 'warning', title: 'Serial number changed', message: 'A device reported another serial number than the one recorded.' },
  'devices.apns_inactive_released': { scope: 'tenant', severity: 'info', title: 'Inactive devices released', message: '{count} device(s) no longer reachable through push were released.' },
  'devices.identity_expired': { scope: 'tenant', severity: 'warning', title: 'Device identities expired', message: '{count} device(s) present an expired identity certificate.' },
  'devices.inactive': { scope: 'tenant', severity: 'warning', title: 'Inactive devices', message: '{count} device(s) without contact for {days} days.' },
  'command.failed': { scope: 'tenant', severity: 'warning', title: 'Command failed', message: 'A {requestType} command failed on {count} device(s).' },
  'policy.conflict': { scope: 'tenant', severity: 'warning', title: 'Policy conflict', message: 'Two policies set the same setting differently on some devices.' },
  // ── Security ──────────────────────────────────────────────────────────────
  'security.topic_mismatch': { scope: 'tenant', severity: 'warning', title: 'Push topic mismatch', message: '{count} device(s) presented a push topic that is not this tenant\'s.' },
  'security.identity_revoked': { scope: 'tenant', severity: 'critical', title: 'Revoked identity presented', message: '{count} connection(s) with a revoked device identity were refused.' },
  'security.identity_mismatch': { scope: 'tenant', severity: 'critical', title: 'Device identity mismatch', message: 'A device presented a {field} that differs from its verified identity.' },
  'security.device_id_conflict': { scope: 'tenant', severity: 'warning', title: 'Device identifier conflict', message: 'A device identifier is claimed by another enrollment ({outcome}).' },
  // ── Push (APNs) ───────────────────────────────────────────────────────────
  'apns.no_certificate': { scope: 'tenant', severity: 'critical', title: 'No push certificate', message: 'This tenant has no active push certificate: devices cannot enroll nor be reached.' },
  'apns.circuit_open': { scope: 'tenant', severity: 'critical', title: 'Push refused by Apple', message: 'Apple refuses the pushes of this tenant (HTTP {httpStatus}): check the push certificate.' },
  'apns.topic_config': { scope: 'tenant', severity: 'critical', title: 'Push topic misconfigured', message: 'Apple refuses the push topic of this tenant ({reason}).' },
  'apns.certificate_expired': { scope: 'tenant', severity: 'critical', title: 'Push certificate expired', message: 'The push certificate {topic} has expired: renew it with the same Apple account.' },
  'apns.throttled': { scope: 'tenant', severity: 'info', title: 'Pushes throttled', message: 'Apple throttled {count} push(es) of this tenant.' },
  // ── Apple Business (ADE) ──────────────────────────────────────────────────
  'ade.token_error': { scope: 'tenant', severity: 'warning', title: 'ADE server in error', message: 'The ADE server {serverName} fails to synchronise ({code}).' },
  'ade.terms_not_signed': { scope: 'tenant', severity: 'critical', title: 'Apple Business terms to accept', message: 'The ADE server {serverName} is blocked until new terms are accepted in Apple Business.' },
  'ade.token_expired': { scope: 'tenant', severity: 'critical', title: 'ADE server token expired', message: 'The token of the ADE server {serverName} has expired: renew it in Apple Business.' },
  'ade.assignment_failed': { scope: 'tenant', severity: 'warning', title: 'ADE profile assignment failed', message: '{count} device(s) could not receive their ADE profile.' },
  // ── Apps and Books ────────────────────────────────────────────────────────
  'vpp.foreign_mdm': { scope: 'tenant', severity: 'critical', title: 'Content token used elsewhere', message: 'The content token {label} is used by another MDM.' },
  'vpp.token_invalid': { scope: 'tenant', severity: 'critical', title: 'Content token invalid', message: 'The content token {label} is no longer valid: import a new one.' },
  'vpp.operation_failed': { scope: 'tenant', severity: 'warning', title: 'Apps and Books operations failed', message: '{count} licence operation(s) failed.' },
  'vpp.notification_auth_failed': { scope: 'tenant', severity: 'warning', title: 'Apps and Books notifications refused', message: '{count} notification(s) presented a wrong secret.' },
  // ── Deadlines (INT-05) ────────────────────────────────────────────────────
  'deadline.apns_certificate': { scope: 'tenant', severity: 'warning', title: 'Push certificate expiring', message: '{label} expires in {daysLeft} day(s) ({notAfter}).' },
  'deadline.ade_token': { scope: 'tenant', severity: 'warning', title: 'ADE token expiring', message: '{label} expires in {daysLeft} day(s) ({notAfter}).' },
  'deadline.vpp_token': { scope: 'tenant', severity: 'warning', title: 'Content token expiring', message: '{label} expires in {daysLeft} day(s) ({notAfter}).' },
  'deadline.device_ca': { scope: 'tenant', severity: 'warning', title: 'Device CA expiring', message: '{label} expires in {daysLeft} day(s) ({notAfter}).' },
  'deadline.mdm_tls_certificate': { scope: 'master', severity: 'warning', title: 'TLS certificate of the device service expiring', message: '{label} expires in {daysLeft} day(s) ({notAfter}).' },
  'deadline.vendor_certificate': { scope: 'master', severity: 'warning', title: 'MDM vendor certificate expiring', message: '{label} expires in {daysLeft} day(s) ({notAfter}).' },
  'deadline.mdm_domain': { scope: 'master', severity: 'warning', title: 'Domain of the device service expiring', message: '{label} expires in {daysLeft} day(s) ({notAfter}).' },
  'deadline.profile_signing_identity': { scope: 'master', severity: 'warning', title: 'Profile signing identity expiring', message: '{label} expires in {daysLeft} day(s) ({notAfter}).' },
  'deadline.vault_escrow_test': { scope: 'master', severity: 'warning', title: 'Escrow test due', message: '{label}: due in {daysLeft} day(s) ({notAfter}).' },
  'deadline.vault_kek_rotation': { scope: 'master', severity: 'warning', title: 'Key rotation due', message: '{label}: due in {daysLeft} day(s) ({notAfter}).' },
  'deadline.vault_old_shares': { scope: 'master', severity: 'warning', title: 'Old escrow shares to destroy', message: '{label}: due in {daysLeft} day(s) ({notAfter}).' },
  'deadline.vault_dek_destruction': { scope: 'master', severity: 'warning', title: 'Data key destruction due', message: '{label}: due in {daysLeft} day(s) ({notAfter}).' },
  // ── Tenant registry (master tenant) ───────────────────────────────────────
  'tenant.provisioning_failed': { scope: 'master', severity: 'warning', title: 'Tenant not provisioned at the device service', message: 'The tenant {tenantName} could not be created at apple-edge: retried every hour.' },
  'tenant.edge_retired': { scope: 'master', severity: 'critical', title: 'Tenant retired at the device service', message: 'apple-edge holds the tenant {tenantName} as retired: its devices cannot be served. Create a new tenant.' },
  'tenant.mdm_key_conflict': { scope: 'master', severity: 'critical', title: 'MDM key conflict', message: 'The MDM key of the tenant {tenantName} differs between the brain and apple-edge (partial restore?).' },
  'tenant.edge_missing': { scope: 'master', severity: 'critical', title: 'Tenant missing at the device service', message: 'apple-edge does not know the MDM key of the tenant {tenantName}.' },
  // ── Platform (master tenant) ──────────────────────────────────────────────
  'platform.device_id_conflict': { scope: 'master', severity: 'warning', title: 'Device identifier claimed by two tenants', message: 'A device identifier of {holder} was claimed by {requester} (policy {policy}).' },
  'platform.foreign_certificate': { scope: 'master', severity: 'critical', title: 'Certificate of another tenant presented', message: 'A device presented to {urlTenant} an identity issued by {issuerTenant}.' },
  'platform.edge_orphan': { scope: 'master', severity: 'warning', title: 'Tenant of apple-edge unknown to the brain', message: 'apple-edge holds a tenant ({key}) that no tenant of the brain references.' },
  'platform.tenant_retired': { scope: 'master', severity: 'info', title: 'Tenant retired at the device service', message: 'The tenant {tenantName} is retired at apple-edge.' },
  'platform.tenant_load_failed': { scope: 'master', severity: 'critical', title: 'Tenant not loaded by the device service', message: 'apple-edge failed to load the tenant {tenantName}: its devices are refused.' },
  'edge.unreachable': { scope: 'master', severity: 'critical', title: 'Device service unreachable', message: 'apple-edge does not answer: no enrollment, command nor event until it is back.' },
  'edge.incompatible': { scope: 'master', severity: 'critical', title: 'Device service version incompatible', message: 'apple-edge runs version {version}, out of the compatibility matrix of this brain: calls refused.' },
  'edge.auth_failed': { scope: 'master', severity: 'critical', title: 'Device service refuses the brain', message: 'apple-edge refused the token of the brain: check the secret apple_edge_api_token on both sides.' },
  'edge.kek_shared': { scope: 'master', severity: 'critical', title: 'Same key for the brain and the device service', message: 'apple-edge and the brain use the same key encryption key: give each service its own.' },
  'mdm.command_invalid': { scope: 'master', severity: 'critical', title: 'Command refused by the device service', message: 'apple-edge refused a {requestType} command ({code}).' },
  'ddm.relay_auth_failed': { scope: 'master', severity: 'critical', title: 'DDM relay signatures refused', message: '{count} request(s) of the DDM relay failed their signature.' },
  'ddm.secret_in_declaration': { scope: 'master', severity: 'critical', title: 'Secret in a declaration', message: 'A declaration of {provider} carried a secret and was refused.' },
  'ddm.declaration_conflict': { scope: 'master', severity: 'critical', title: 'Declarations in conflict', message: 'Two declarations of {provider} share the identifier {identifier}: neither is served.' },
  'signing.identity_missing': { scope: 'master', severity: 'warning', title: 'Enrollment profiles not signed', message: 'No profile signing identity is imported: enrollment profiles are served unsigned.' },
} as const satisfies Record<string, AppleAlertDef>;

export type AppleAlertKind = keyof typeof APPLE_ALERTS;
export type AlertParams = Record<string, string | number | boolean>;

export function isAppleAlertKind(kind: string): kind is AppleAlertKind {
  return Object.prototype.hasOwnProperty.call(APPLE_ALERTS, kind);
}

/** 'apple:<kind>[:<discriminant>]': the discriminant is an internal identifier only. */
export function stableKeyOf(kind: AppleAlertKind, discriminant?: string | number): string {
  if (discriminant === undefined || discriminant === null || discriminant === '') return `apple:${kind}`;
  const d = String(discriminant);
  if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(d)) throw new Error(`alert ${kind}: invalid discriminant`);
  return `apple:${kind}:${d}`;
}

/** Parameters kept: scalars of 200 characters at most, names of 40 characters at most. */
export function cleanParams(params: AlertParams | undefined): AlertParams {
  const out: AlertParams = {};
  for (const [k, v] of Object.entries(params ?? {}).slice(0, 12)) {
    if (!/^[A-Za-z][A-Za-z0-9_]{0,39}$/.test(k)) continue;
    if (typeof v === 'string') out[k] = v.slice(0, 200);
    else if (typeof v === 'number' && Number.isFinite(v)) out[k] = v;
    else if (typeof v === 'boolean') out[k] = v;
  }
  return out;
}

/** The English text with its parameters ({name}); an absent parameter stays as written. */
export function render(template: string, params: AlertParams): string {
  return template.replace(/\{([A-Za-z][A-Za-z0-9_]{0,39})\}/g, (m, name: string) => (name in params ? String(params[name]) : m));
}

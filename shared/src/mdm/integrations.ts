// Apple integrations as the console sees them (docs: integration-apple-edge §11.1, §11.2, §11.4 to §11.7; lot C3):
// the push certificate and its requests (exchange files with the vendor's offline signing tool), the ADE servers,
// the deadlines (INT-05) and the readiness checklist of a tenant. No secret ever: a push key and an ADE token live
// in apple-edge, the vendor key at the vendor's; the files the console exchanges are public (a CSR, a signed
// request, a certificate, a public key).

/** Purposes of a push certificate request (tenant_apple_push.purpose). 'import': laboratory only. */
export const PUSH_PURPOSES = ['initial', 'renewal', 'topic_change', 'import'] as const;
export type PushPurpose = typeof PUSH_PURPOSES[number];

/** States of a push certificate row (tenant_apple_push.state). */
export const PUSH_CERT_STATES = ['vendor_signature_pending', 'apple_upload_pending', 'active', 'legacy', 'superseded',
  'expired', 'revoked', 'abandoned'] as const;
export type PushCertState = typeof PUSH_CERT_STATES[number];

/** A push certificate request or certificate, as the console lists it. */
export interface PushRequestView {
  id: string;
  purpose: PushPurpose;
  state: PushCertState;
  stateAt: string;
  topic: string | null;
  notAfter: string | null;
  certSha256: string | null;
  appleAccountHint: string | null;
  /** The CSR is ready (the vendor file can be downloaded). */
  csrReady: boolean;
  vendorSignedAt: string | null;
  activatedAt: string | null;
  closedAt: string | null;
  createdAt: string;
  /** A change of topic waits for its second approver (the certificate is kept until then). */
  topicChangePending: boolean;
  approvalId: number | null;
}

export interface PushOverview {
  active: PushRequestView | null;
  /** The open request (vendor_signature_pending or apple_upload_pending), one at most. */
  open: PushRequestView | null;
  /** Certificates of a previous topic still used by devices not enrolled again, with their count. */
  legacy: Array<PushRequestView & { devices: number }>;
  history: PushRequestView[];
  /** Devices whose push topic is the active one. */
  devicesOnActiveTopic: number;
  /** APPLE_ALLOW_PUSH_KEY_IMPORT: a certificate with its key may be imported (laboratory, platform administrator). */
  keyImportAllowed: boolean;
}

/** States of an ADE server (tenant_apple_ade_tokens.state). */
export const ADE_SERVER_STATES = ['awaiting_token', 'active', 'terms_not_signed', 'expired', 'error', 'removed'] as const;
export type AdeServerState = typeof ADE_SERVER_STATES[number];

export interface AdeServerView {
  id: string;
  label: string;
  state: AdeServerState;
  stateAt: string;
  /** Name and UUID of the server in Apple Business (what the organisation typed). */
  serverName: string | null;
  notAfter: string | null;
  appleAccountHint: string | null;
  lastSyncAt: string | null;
  consecutiveErrors: number;
  lastErrorCode: string | null;
  byodDiscovery: boolean;
  byodDiscoveryAt: string | null;
  createdAt: string;
  /** Devices of Apple Business listed for this server, and those enrolled from it and still managed. */
  devices: number;
  enrolledDevices: number;
}

/** Deadline kinds (integration_deadline_items.kind). */
export const DEADLINE_KINDS = ['apns_certificate', 'ade_token', 'vpp_token', 'device_ca', 'mdm_tls_certificate',
  'vendor_certificate', 'mdm_domain', 'profile_signing_identity', 'vault_escrow_test', 'vault_kek_rotation',
  'vault_old_shares', 'vault_dek_destruction'] as const;
export type DeadlineKind = typeof DEADLINE_KINDS[number];
/** Kinds the platform administrator types in (PUT /api/admin/apple/deadlines/:kind). */
export const MANUAL_DEADLINE_KINDS = ['mdm_domain', 'profile_signing_identity'] as const;
export type ManualDeadlineKind = typeof MANUAL_DEADLINE_KINDS[number];
export const DEADLINE_LEVELS = ['ok', 'warning', 'critical', 'expired', 'unknown', 'retired'] as const;
export type DeadlineLevel = typeof DEADLINE_LEVELS[number];

export interface DeadlineView {
  id: string;
  /** null: an item of the instance (vendor certificate, TLS, domain, vault…). */
  tenantId: number | null;
  /** The tenant's name, in the cross-tenant view of the platform administrators only. */
  tenantName?: string | null;
  kind: DeadlineKind;
  label: string;
  notAfter: string | null;
  daysLeft: number | null;
  level: DeadlineLevel;
  source: 'apple-edge' | 'brain' | 'manual' | 'vault';
  /** The last threshold alerted for this expiry (60, 30, 14, 7, 3, 1, 0), null when none yet. */
  lastAlertThreshold: number | null;
  updatedAt: string;
}

/** The readiness checklist of a tenant (§11.5), in its order. */
export const READINESS_KEYS = ['tenant.provisioned', 'push.active', 'enrollment.profile', 'ade.server', 'byod.discovery',
  'vpp.token', 'signing.identity', 'notice.custom', 'privacy.profile', 'ddm.relay'] as const;
export type ReadinessKey = typeof READINESS_KEYS[number];
export type ReadinessState = 'ready' | 'todo' | 'warning' | 'error' | 'not_applicable';

export interface ReadinessItem {
  key: ReadinessKey;
  state: ReadinessState;
  /** Why it is not ready (a code the console translates: apple.readiness.reason.<code>). */
  reason?: string;
  /** Numbers and dates only (days left, counts). */
  params?: Record<string, string | number>;
}

/** States of an integration card (INT-04). */
export type IntegrationCardState = 'ready' | 'todo' | 'attention' | 'error';

export interface IntegrationsSummary {
  edge: {
    state: IntegrationCardState;
    /** The tenant's mirror at apple-edge (unprovisioned, provisioning, active, suspended…). */
    edgeState: string;
    mdmKey: string | null;
    commandsFrozen: boolean;
    reachable: boolean | null;
  };
  push: {
    state: IntegrationCardState;
    topic: string | null;
    notAfter: string | null;
    openRequestState: PushCertState | null;
    legacyDevices: number;
    appleAccountHint: string | null;
  };
  ade: {
    state: IntegrationCardState;
    servers: number;
    active: number;
    inError: number;
    termsToAccept: number;
    byodDiscovery: boolean;
    devices: number;
    nextExpiry: string | null;
  };
  vpp: {
    state: IntegrationCardState;
    tokens: number;
    active: number;
  };
  deadlines: { state: IntegrationCardState; items: DeadlineView[] };
  readiness: ReadinessItem[];
}

/** Bounds of the files and fields of the integrations (§11.1, §11.2, §11.6). */
export const INTEGRATION_LIMITS = Object.freeze({
  /** .p7m, signed request (JSON), PEM with its key (laboratory). */
  fileBytes: 64 * 1024,
  /** The certificate of Apple (PEM). */
  certificateBytes: 16 * 1024,
  accountHint: 200,
  label: 100,
  /** An open push request is abandoned after this many days (integrations.push-abandon). */
  pushRequestDays: 30,
});

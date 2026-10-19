import { z } from 'zod';

// =============================================================================
// Wire types of the internal API v1 of apple-edge (docs: integration-apple-
// edge §5.3, §5.6; apple-edge §5.3), as read in its code (internal/api,
// internal/tenant, internal/queue, internal/ade). JSON in snake_case, dates in
// RFC 3339 UTC, binaries in standard base64. Every schema is NOT strict
// (passthrough): a field apple-edge adds within v1 breaks nothing (apple-edge
// §5.10). Go's nil slices arrive as null: read as empty lists.
// =============================================================================

const list = <T extends z.ZodTypeAny>(item: T) => z.array(item).nullable().transform((v) => v ?? []);

export const EdgeCaW = z.object({
  id: z.string(),
  sha256: z.string(),
  not_after: z.string(),
  status: z.string().optional(),
}).passthrough();
export type EdgeCa = z.infer<typeof EdgeCaW>;

export const EdgeStatusW = z.object({
  version: z.string(),
  upstream: z.record(z.string()).optional(),
  schema: z.unknown().optional(),
  tenants: z.number().optional(),
  outbox: z.object({ pending: z.number(), oldest_pending_seconds: z.number() }).passthrough().optional(),
  /** Fingerprint of apple-edge's KEK (not secret): must differ from the brain's (coffre §8.4-1). */
  kek_id: z.string().optional(),
  /** Public description of the profile signing identity, null until one is imported. */
  signing_identity: z.object({ sha256: z.string(), not_after: z.string() }).passthrough().nullable().optional(),
}).passthrough();
export type EdgeStatus = z.infer<typeof EdgeStatusW>;

export const EdgeTenantCreatedW = z.object({ key: z.string(), state: z.string(), ca: EdgeCaW }).passthrough();
export type EdgeTenantCreated = z.infer<typeof EdgeTenantCreatedW>;

export const EdgeTenantSummaryW = z.object({
  key: z.string(),
  external_ref: z.string(),
  state: z.string(),
  commands_frozen: z.boolean(),
}).passthrough();
export type EdgeTenantSummary = z.infer<typeof EdgeTenantSummaryW>;

export const EdgeTenantListW = z.object({
  tenants: list(EdgeTenantSummaryW),
  next_cursor: z.string().nullable().optional(),
}).passthrough();

export const EdgePushCertInfoW = z.object({
  id: z.string(),
  state: z.string(),
  topic: z.string().optional(),
  not_after: z.string().optional(),
  activated_at: z.string().optional(),
  apns: z.unknown().optional(),
}).passthrough();
export type EdgePushCertInfo = z.infer<typeof EdgePushCertInfoW>;

export const EdgeTenantInfoW = z.object({
  key: z.string(),
  external_ref: z.string(),
  state: z.string(),
  commands_frozen: z.boolean(),
  retiring_since: z.string().optional(),
  load_failed: z.boolean(),
  cas: list(EdgeCaW),
  push_certificates: list(EdgePushCertInfoW),
  counters: z.record(z.number()).nullable().transform((v) => v ?? {}),
}).passthrough();
export type EdgeTenantInfo = z.infer<typeof EdgeTenantInfoW>;

export const EdgeTenantStateW = z.object({ key: z.string(), state: z.string() }).passthrough();
export const EdgeFreezeW = z.object({ key: z.string(), commands_frozen: z.boolean() }).passthrough();

export const EdgeEnrollmentConfigW = z.object({
  server_url: z.string(),
  checkin_url: z.string(),
  scep_url: z.string(),
  /** null: no active push certificate. */
  topic: z.string().nullable(),
  scep_ca_cert_pem: z.string(),
  scep_ca_sha256: z.string(),
  key_size: z.number(),
  sign_message: z.boolean(),
}).passthrough();
export type EdgeEnrollmentConfig = z.infer<typeof EdgeEnrollmentConfigW>;

export const EdgeCaRotationW = z.object({ ca: EdgeCaW, verify_only: list(EdgeCaW) }).passthrough();
export type EdgeCaRotation = z.infer<typeof EdgeCaRotationW>;

export const EdgePushCsrW = z.object({ id: z.string(), csr_pem: z.string(), csr_der_b64: z.string() }).passthrough();
export type EdgePushCsr = z.infer<typeof EdgePushCsrW>;

export const EdgePushCertListW = z.object({ certificates: list(EdgePushCertInfoW) }).passthrough();

export const EdgePushOutcomeW = z.enum(['sent', 'deferred', 'disabled', 'error', 'not_requested']);
export type EdgePushOutcome = z.infer<typeof EdgePushOutcomeW>;
export const EdgePushResultsW = z.object({ results: z.record(z.string()).nullable().transform((v) => v ?? {}) }).passthrough();

export const EdgeChallengeW = z.object({ challenge: z.string(), challenge_id: z.string(), expires_at: z.string() }).passthrough();
export type EdgeChallenge = z.infer<typeof EdgeChallengeW>;

export const EdgeMachineInfoCheckW = z.object({
  machine_info_id: z.string(),
  udid: z.string(),
  serial: z.string(),
  product: z.string(),
  os_version: z.string(),
  version: z.string(),
  serial_in_tenant: z.boolean(),
  expires_at: z.string(),
}).passthrough();
export type EdgeMachineInfoCheck = z.infer<typeof EdgeMachineInfoCheckW>;

export const EdgeEnrollmentW = z.object({
  enrollment_id: z.string(),
  device_id: z.string(),
  type: z.string(),
  enabled: z.boolean(),
  last_seen_at: z.string(),
  created_at: z.string(),
  cert_sha256: z.string().optional(),
  cert_not_after: z.string().optional(),
  proof: z.string(),
}).passthrough();
export type EdgeEnrollment = z.infer<typeof EdgeEnrollmentW>;

export const EdgeEnrollmentListW = z.object({
  enrollments: list(EdgeEnrollmentW),
  next_cursor: z.string().nullable().optional(),
}).passthrough();

export const EdgeEnrollmentDetailW = z.object({
  enrollment: EdgeEnrollmentW,
  queue: list(z.object({
    command_uuid: z.string(), request_type: z.string(), not_now: z.boolean(), active: z.boolean(), age_seconds: z.number(),
  }).passthrough()),
  certificate_pem: z.string().nullable(),
}).passthrough();
export type EdgeEnrollmentDetail = z.infer<typeof EdgeEnrollmentDetailW>;

export const EdgeReleaseResultW = z.object({
  enrollment_id: z.string(),
  released: list(z.object({ id_kind: z.string(), reason: z.string() }).passthrough()),
  revoked_certificates: z.number(),
}).passthrough();
export type EdgeReleaseResult = z.infer<typeof EdgeReleaseResultW>;

/** PUT …/enrollments/{id}/reenroll-allowance (AE-C0-R2bis, decision of 19/10/2026). */
export const EdgeReenrollAllowanceW = z.object({ enrollment_id: z.string(), expires_at: z.string() }).passthrough();
export type EdgeReenrollAllowance = z.infer<typeof EdgeReenrollAllowanceW>;
/** DELETE …/enrollments/{id}/reenroll-allowance. */
export const EdgeReenrollWithdrawnW = z.object({ enrollment_id: z.string(), withdrawn: z.boolean() }).passthrough();

export const EdgeRevokeW = z.object({ sha256: z.string(), revoked: z.boolean() }).passthrough();

export const EdgeRevealedSecretW = z.object({
  kind: z.string(), enrollment_id: z.string(), value_b64: z.string(), value: z.string().optional(),
}).passthrough();
export type EdgeRevealedSecret = z.infer<typeof EdgeRevealedSecretW>;

export const EdgeEnqueueResponseW = z.object({
  command_uuid: z.string(),
  request_type: z.string(),
  targets: z.record(z.object({ queued: z.boolean(), push: z.string() }).passthrough()).nullable().transform((v) => v ?? {}),
}).passthrough();
export type EdgeEnqueueResponse = z.infer<typeof EdgeEnqueueResponseW>;

export const EdgeCancelResponseW = z.object({
  command_uuid: z.string(),
  targets: z.record(z.string()).nullable().transform((v) => v ?? {}),
}).passthrough();

export const EdgeTransferW = z.object({ id: z.string(), expires_at: z.string() }).passthrough();
export const EdgeLogRefsW = z.object({ refs: z.record(z.string()).nullable().transform((v) => v ?? {}) }).passthrough();

export const EdgeAdeTokenW = z.object({
  id: z.string(),
  state: z.string(),
  certificate_pem: z.string(),
  server_name: z.string().nullable(),
  server_uuid: z.string().nullable(),
  not_after: z.string().nullable(),
  last_sync_at: z.string().nullable(),
  last_fetch_at: z.string().nullable(),
  consecutive_errors: z.number(),
  last_error: z.string().nullable(),
  created_at: z.string(),
  devices: z.number().optional(),
  profiles: z.array(z.object({
    usage: z.string(), profile_uuid: z.string().nullable(), is_default: z.boolean(), defined_at: z.string().nullable(),
  }).passthrough()).optional(),
}).passthrough();
export type EdgeAdeToken = z.infer<typeof EdgeAdeTokenW>;

export const EdgeAdeTokenListW = z.object({ ade_tokens: list(EdgeAdeTokenW) }).passthrough();
export const EdgeAdeProfileW = z.object({ usage: z.string(), profile_uuid: z.string(), is_default: z.boolean() }).passthrough();
export const EdgeAdeAssignW = z.object({
  usage: z.string(), profile_uuid: z.string(), results: z.record(z.string()).nullable().transform((v) => v ?? {}),
}).passthrough();
export const EdgeAccountDrivenW = z.object({ mdm_service_discovery_url: z.string() }).passthrough();
export const EdgeAcceptedW = z.object({}).passthrough();

/** The enqueue request (apple-edge §5.4): command_uuid upper-case, equal to the plist's CommandUUID. */
export interface EdgeEnqueueRequest {
  command_uuid: string;
  /** XML plist starting with <?xml, 4 MiB at most, in standard base64. */
  command_plist_b64: string;
  /** 1 to 10 000 enrollment ids of the tenant. */
  targets: string[];
  push: boolean;
  expires_at?: string;
}

export interface EdgeChallengeRequest {
  /** enrollment_sessions.id (200 characters at most). */
  session_ref: string;
  /** 60 to 3 600, default 900. */
  ttl_seconds?: number;
  bind?: { udid?: string; serial?: string };
  /** ADE. */
  machine_info_id?: string;
}

export interface EdgeTransferRequest {
  id_kind: 'udid';
  id: string;
  from_tenant: string;
  to_tenant: string;
  approval_ref: string;
  expires_at?: string;
}

import { z } from 'zod';
import { MDM_KEY_RE } from '../tenants/key';

// =============================================================================
// Schemas of the payloads of apple-edge's events (docs: integration-apple-
// edge §7.5; apple-edge §5.6): NOT strict (unknown fields ignored, apple-edge
// §5.5), only the fields used declared, checked against what apple-edge
// writes (internal/mdm/guard.go, verifier.go, scep, queue, outbox/jobs.go,
// apns, ade, tenant). The keys '<type>#platform' are the second handler of a
// type registered with the scope 'platform' (file-durable §7.3: one handler
// per scope and type). Go writes a nil list as null: such lists are read as
// empty. A payload a schema refuses goes to the dead letters (invalid_payload):
// the event is lost for its tenant (no alert, no state). A bound is therefore
// set only on what apple-edge bounds itself (its identifiers, its own codes,
// its pages); a value a device chooses and apple-edge copies as it is (the
// topic and the serial number of a refused check-in) or that Apple writes (the
// reason of an APNs refusal; the name and the UUID of an ADE server, the serial
// number of a device of Apple Business, the UUID of an ADE profile) has none,
// and the handler ignores or truncates it: an oversized value must not hide a
// security event from the tenant, nor a page of devices, nor an activation.
// =============================================================================

const iso = z.string().datetime({ offset: true });
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const uuid = z.string().uuid();
const key = z.string().regex(MDM_KEY_RE);
/** NanoMDM enrollment types (mdm/type.go); the device channel is 'Device' or 'User Enrollment (Device)'. */
const nanoType = z.enum(['Device', 'User', 'User Enrollment (Device)', 'User Enrollment', 'Shared iPad']);
/** A list Go may write as null. */
const list = <T extends z.ZodTypeAny>(item: T, max: number) => z.array(item).max(max).nullable().transform((v) => v ?? []);
/** A text Apple writes (the name an organisation gave its server in Apple Business): of any length, the handler
 *  keeps what its column holds. */
const appleText = z.string().nullable().optional();
/** Devices of one ade.devices event: a page of Apple holds 1 000 at most, but the devices gone from a server at the
 *  end of a complete fetch (op_type 'deleted') are written by apple-edge in one event, whatever their number
 *  (internal/ade/sync.go, commitPage); the handler applies the list in one statement. */
const MAX_ADE_DEVICES = 100_000;

export const P = {
  // ── Enrollment cycles ─────────────────────────────────────────────────────
  'mdm.authenticate': z.object({
    device_id: z.string().min(1).max(256),
    enrollment_type: nanoType,
    topic: z.string().max(255),
    proof: z.enum(['none', 'ade']),
    identity: z.object({
      cert_sha256: sha256.optional(),
      not_after: iso.optional(),
      challenge_id: uuid.nullable().optional(),
      session_ref: z.string().max(200).nullable().optional(),
    }),
    message: z.record(z.unknown()),
  }),
  'mdm.token_update': z.object({
    device_id: z.string().min(1).max(256),
    channel: z.enum(['device', 'user']),
    awaiting_configuration: z.boolean(),
    token_update_tally: z.number().int(),
    has_unlock_token: z.boolean(),
    topic: z.string().max(255).optional(),
    message: z.record(z.unknown()),
  }),
  'mdm.checkout': z.object({ device_id: z.string().min(1).max(256) }),
  'mdm.seen_batch': z.object({
    since: iso,
    until: iso,
    enrollments: list(z.object({ enrollment_id: z.string().max(400), last_seen_at: iso }), 1000),
  }),
  'scep.certificate_issued': z.object({
    challenge_id: uuid,
    session_ref: z.string().max(200).nullable(),
    cert_sha256: sha256,
    serial_hex: z.string().max(80),
    not_after: iso,
  }),
  // ── Commands ──────────────────────────────────────────────────────────────
  'mdm.command_delivered': z.object({ device_id: z.string().max(256), request_type: z.string().max(64) }),
  'mdm.command_result': z.object({
    device_id: z.string().max(256),
    status: z.enum(['Acknowledged', 'Error', 'CommandFormatError', 'NotNow']),
    request_type: z.string().max(64),
    error_chain: z.unknown().optional(),
    result: z.record(z.unknown()),
  }),
  'mdm.command_expired': z.object({ targets: z.array(z.string().max(400)).min(1).max(10_000) }),
  // ── Security ──────────────────────────────────────────────────────────────
  // presented_topic: what the refused device sent, of any length (never used, never stored).
  'security.topic_mismatch': z.object({ reason: z.string().max(64), presented_topic: z.string().optional() }),
  'security.identity_expired': z.object({ cert_sha256: sha256, not_after: iso.optional() }),
  'security.identity_revoked': z.object({ cert_sha256: sha256 }),
  'security.identity_mismatch': z.object({
    field: z.enum(['udid', 'serial']),
    /** Not written by apple-edge today: the session of the refused enrollment, when it comes. */
    session_ref: z.string().max(200).nullable().optional(),
  }),
  'security.device_id_conflict': z.object({
    id_kind: z.enum(['udid', 'enrollment_id']),
    outcome: z.string().max(32),
    /** The SerialNumber of the requester's Authenticate as the device sent it (any length): device data, never used. */
    serial: z.string().optional(),
  }),
  'security.device_id_conflict#platform': z.object({
    id_kind: z.string().max(32),
    outcome: z.string().max(32),
    policy: z.string().max(32),
    tenants: z.object({ holder: z.string().max(32), requester: z.string().max(32) }),
  }),
  'security.foreign_certificate': z.object({ url_tenant: z.string().max(32), issuer_tenant: z.string().max(32).optional() }),
  // ── Devices ───────────────────────────────────────────────────────────────
  'device.id_released': z.object({
    id_kind: z.enum(['udid', 'enrollment_id']),
    reason: z.enum(['checkout', 'retired', 'transfer', 'superseded_by_proof', 'superseded', 'apns_inactive', 'purged']),
  }),
  'device.transfer_completed': z.object({ direction: z.enum(['in', 'out']), approval_ref: z.string().max(200) }),
  'device.transfer_completed#platform': z.object({
    approval_ref: z.string().max(200), from: z.string().max(32), to: z.string().max(32),
  }),
  // ── Tenant registry (lot B1) ──────────────────────────────────────────────
  'tenant.created': z.object({ key, state: z.string().max(32), external_ref: uuid }),
  'tenant.state_changed': z.object({ key, state: z.enum(['active', 'suspended', 'retiring', 'retired']) }),
  'tenant.load_failed': z.object({ key }),
  'tenant.ca_rotated': z.object({
    ca_id: uuid, sha256, not_after: iso, verify_only: z.array(uuid).nullable().transform((v) => v ?? []),
  }),
  // ── Push (APNs) ───────────────────────────────────────────────────────────
  // reason: Apple's answer as apple-edge read it (the handlers keep 64 characters).
  'apns.push_failed': z.object({
    http_status: z.number().int(),
    reason: z.string().optional(),
    circuit_open: z.boolean(),
  }),
  'apns.token_inactive': z.object({ apns_timestamp: iso.nullable(), reason: z.string().optional() }),
  'apns.throttled': z.object({ count: z.number().int().nonnegative(), retry_after_s: z.number().nonnegative() }),
  'apns.certificate_expiring': z.object({ topic: z.string().max(255), not_after: iso, days_left: z.number().int() }),
  'apns.certificate_activated': z.object({ topic: z.string().max(255), not_after: iso, cert_sha256: sha256.optional() }),
  'apns.certificate_expired': z.object({ topic: z.string().max(255), not_after: iso }),
  // ── Apple Business (ADE) ──────────────────────────────────────────────────
  'ade.token_activated': z.object({
    token_id: uuid,
    server_name: appleText,
    server_uuid: appleText,
    not_after: iso.nullable().optional(),
  }),
  'ade.devices': z.object({
    token_id: uuid,
    phase: z.enum(['fetch', 'sync']),
    devices: list(z.object({
      // Apple's inventory: one value out of form must not lose the page (the handler skips it).
      serial_number: z.string().min(1),
      model: z.string().optional(),
      description: z.string().optional(),
      color: z.string().optional(),
      device_family: z.string().optional(),
      os: z.string().optional(),
      profile_status: z.string().optional(),
      profile_uuid: z.string().optional(),
      profile_assign_time: iso.optional(),
      device_assigned_date: iso.optional(),
      op_type: z.string().optional(),
      op_date: iso.optional(),
      mdm_migration_deadline: iso.optional(),
      imei: z.array(z.string()).optional(),
      meid: z.array(z.string()).optional(),
      eid: z.string().optional(),
      wifi_mac_address: z.string().optional(),
      bluetooth_mac_address: z.string().optional(),
      ethernet_mac_address: z.string().optional(),
    }), MAX_ADE_DEVICES),
  }),
  'ade.profile_assignment': z.object({
    token_id: uuid,
    usage: z.string().max(32),
    // The UUID Apple gave the profile (the handler keeps 64 characters).
    profile_uuid: z.string(),
    results: z.record(z.string()).nullable().transform((v) => v ?? {}),
  }),
  'ade.sync_error': z.object({ token_id: uuid, code: z.string().max(64) }),
  'ade.terms_not_signed': z.object({ token_id: uuid, code: z.string().max(64) }),
  'ade.token_expiring': z.object({
    token_id: uuid,
    code: z.enum(['token_expiring', 'token_expired']),
    days_left: z.number().int(),
    not_after: iso,
  }),
} as const;

export type PayloadOf<K extends keyof typeof P> = (typeof P)[K]['_output'];

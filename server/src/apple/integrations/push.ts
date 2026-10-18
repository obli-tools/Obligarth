import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import type { PushOverview, PushPurpose, PushRequestView, PushCertState } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import type { DbActor } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { vault } from '../../vault';
import { edgeActorOf } from '../actors';
import { resolveInTx } from '../alerts/service';
import { rethrowForConsole } from '../edge/appError';
import { appleEdge } from '../edge/instance';
import { isAppleEdgeError } from '../edge/errors';
import { realtime } from '../realtime';
import { appleTenants, upsertMirror } from '../tenants/registry';
import { vendorPinRequired } from '../config';
import { recordDeadline } from './deadlines';
import {
  buildRequestFile, checkAppleCertificate, checkSignedFile, checkVendorTrust, PushCertificateError, VendorFileError,
  type PushCertificateCheck, type PushRequestFile, type SignedFileCheck,
} from './pushFiles';

// =============================================================================
// The push certificate of a tenant (docs: integration-apple-edge §11.1,
// INT-01, I16), one open request at most (index tenant_apple_push_one_open):
//   1 create      vault.requireEscrow() first (coffre-secrets V14), the row
//                 claimed (the slot of the open request), then the CSR of a new
//                 push key at apple-edge, out of any transaction
//                 (vendor_signature_pending)
//   2 vendor file obligarth-push-request-<id>.json for the vendor's offline tool
//   3 signed file checked (pushFiles.ts) → apple_upload_pending; the vendor
//                 certificate's deadline (instance item)
//   4 Apple file  PushCertificateRequest-<date>.plist: the vendor's signed
//                 request, uploaded by the client at identity.apple.com with its
//                 service account
//   5 certificate checked against the CSR, then imported at apple-edge (its
//                 pending key) and activated at the answer; a renewal keeps the
//                 topic; a change of topic waits for a second approver (floor
//                 apple.push_topic_change) with the certificate kept public
// The activation (applyPushActivation) is shared with the handler of
// apns.certificate_activated: whichever comes first activates, the other finds
// the row active and does nothing. A request open more than 30 days is
// abandoned (integrations.push-abandon). No key ever passes through the brain,
// except the laboratory's import of a certificate with its key
// (APPLE_ALLOW_PUSH_KEY_IMPORT, platform administrator), handed to apple-edge
// once, never stored nor logged.
// =============================================================================

export const OPEN_REQUEST: readonly PushCertState[] = ['vendor_signature_pending', 'apple_upload_pending'];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const COLS = ['id', 'purpose', 'state', 'state_at', 'topic', 'not_after', 'cert_sha256', 'apple_account_hint', 'csr_der_b64', 'vendor_request_b64',
  'vendor_signed_at', 'activated_at', 'closed_at', 'created_at', 'pending_cert_pem', 'approval_id', 'edge_cert_id'];

interface PushRow {
  id: string;
  purpose: PushPurpose;
  state: PushCertState;
  state_at: Date;
  topic: string | null;
  not_after: Date | null;
  cert_sha256: string | null;
  apple_account_hint: string | null;
  csr_der_b64: string | null;
  vendor_request_b64: string | null;
  vendor_signed_at: Date | null;
  activated_at: Date | null;
  closed_at: Date | null;
  created_at: Date;
  pending_cert_pem: string | null;
  approval_id: number | null;
  edge_cert_id: string | null;
}

const iso = (v: Date | string | null | undefined): string | null => (v ? new Date(v).toISOString() : null);

function view(r: PushRow): PushRequestView {
  return {
    id: r.id, purpose: r.purpose, state: r.state, stateAt: iso(r.state_at)!, topic: r.topic, notAfter: iso(r.not_after), certSha256: r.cert_sha256,
    appleAccountHint: r.apple_account_hint, csrReady: !!r.csr_der_b64, vendorSignedAt: iso(r.vendor_signed_at), activatedAt: iso(r.activated_at),
    closedAt: iso(r.closed_at), createdAt: iso(r.created_at)!, topicChangePending: !!r.pending_cert_pem, approvalId: r.approval_id ?? null,
  };
}

export function requestId(raw: unknown): string {
  const id = String(raw ?? '').toLowerCase();
  if (!UUID_RE.test(id)) throw new AppError(404, 'Not found', 'pushRequestNotFound');
  return id;
}

async function rowOf(q: Knex | Knex.Transaction, tenantId: number, id: string, lock = false): Promise<PushRow> {
  let qb = q('tenant_apple_push').where({ tenant_id: tenantId, id });
  if (lock) qb = qb.forUpdate();
  const r = await qb.first(COLS) as PushRow | undefined;
  if (!r) throw new AppError(404, 'Not found', 'pushRequestNotFound');
  return r;
}

/** A request of the tenant (404 pushRequestNotFound otherwise, a request of another tenant included). */
export async function getPushRequest(q: Knex | Knex.Transaction, tenantId: number, id: string): Promise<PushRequestView> {
  return view(await rowOf(q, tenantId, id));
}

/** Devices still managed whose push topic is `topic`. */
async function devicesOnTopic(q: Knex | Knex.Transaction, tenantId: number, topic: string): Promise<number> {
  const r = await q('apple_devices as a').join('devices as d', function on() { this.on('d.id', 'a.device_id').andOn('d.tenant_id', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId, 'a.topic': topic }).whereNot('d.enrollment_state', 'unenrolled').count({ n: '*' }).first() as { n: string | number };
  return Number(r?.n ?? 0);
}

export async function pushOverview(q: Knex, tenantId: number): Promise<PushOverview> {
  const rows = await q('tenant_apple_push').where({ tenant_id: tenantId }).orderBy('created_at', 'desc').limit(200).select(COLS) as PushRow[];
  const active = rows.find((r) => r.state === 'active') ?? null;
  const open = rows.find((r) => OPEN_REQUEST.includes(r.state)) ?? null;
  const legacy = [];
  for (const r of rows.filter((x) => x.state === 'legacy' && x.topic)) legacy.push({ ...view(r), devices: await devicesOnTopic(q, tenantId, r.topic!) });
  return {
    active: active ? view(active) : null, open: open ? view(open) : null, legacy,
    history: rows.filter((r) => r !== active && r !== open).slice(0, 50).map(view),
    devicesOnActiveTopic: active?.topic ? await devicesOnTopic(q, tenantId, active.topic) : 0,
    keyImportAllowed: config.apple.allowPushKeyImport === true,
  };
}

/** Step 1 (§11.1): the escrow guard, the slot of the open request, the CSR at apple-edge (out of any transaction). */
export async function createPushRequest(tenantId: number, userId: number, input: { purpose: 'initial' | 'renewal' | 'topic_change'; appleAccountHint?: string | null },
  actor: DbActor): Promise<PushRequestView> {
  await vault.requireEscrow();
  const key = await appleTenants.keyOf(tenantId);
  const id = randomUUID();
  const now = new Date();
  await db.transaction(async (trx) => {
    const rows = await trx('tenant_apple_push').where({ tenant_id: tenantId }).whereIn('state', ['active', ...OPEN_REQUEST]).forUpdate()
      .select('state', 'apple_account_hint') as Array<{ state: PushCertState; apple_account_hint: string | null }>;
    if (rows.some((r) => OPEN_REQUEST.includes(r.state))) {
      throw new AppError(409, 'A request is already open: finish it or abandon it first', 'pushRequestOpen');
    }
    const active = rows.find((r) => r.state === 'active');
    if (input.purpose === 'initial' && active) {
      throw new AppError(409, 'This tenant has a push certificate: renew it (same Apple account) instead', 'pushCertificateExists');
    }
    if (input.purpose !== 'initial' && !active) {
      throw new AppError(409, 'This tenant has no active push certificate to renew', 'pushCertificateMissing');
    }
    const hint = input.appleAccountHint?.trim() || active?.apple_account_hint || null;
    try {
      await trx('tenant_apple_push').insert({
        id, tenant_id: tenantId, purpose: input.purpose, state: 'vendor_signature_pending', state_at: now, apple_account_hint: hint,
        created_by: userId, created_at: now, updated_at: now,
      });
    } catch (err) {
      if ((err as { code?: string }).code === '23505') throw new AppError(409, 'A request is already open: finish it or abandon it first', 'pushRequestOpen');
      throw err;
    }
  });
  let csr: { id: string; csr_der_b64: string };
  try {
    csr = await appleEdge.createPushCsr(key, { actor: edgeActorOf(actor) });
  } catch (err) {
    // The slot is given back: nothing was made at apple-edge (or nothing usable).
    await db('tenant_apple_push').where({ tenant_id: tenantId, id, state: 'vendor_signature_pending' }).whereNull('csr_der_b64').del();
    rethrowForConsole(err);
  }
  await db('tenant_apple_push').where({ tenant_id: tenantId, id })
    .update({ edge_cert_id: UUID_RE.test(csr.id.toLowerCase()) ? csr.id.toLowerCase() : null, csr_der_b64: csr.csr_der_b64, updated_at: new Date() });
  realtime.integrationChanged(tenantId, 'push');
  return view(await rowOf(db, tenantId, id));
}

/** The instance's identifier (app_config.instance_id, class catalog). */
export async function instanceId(q: Knex | Knex.Transaction = db): Promise<string> {
  const row = await q('app_config').where({ key: 'instance_id' }).first('value') as { value: string } | undefined;
  if (!row?.value) throw new AppError(500, 'The instance has no identifier', 'instanceIdMissing');
  return row.value.toLowerCase();
}

/** Step 2: the request file for the vendor's offline tool. */
export async function pushVendorFile(q: Knex, tenantId: number, id: string): Promise<{ filename: string; file: PushRequestFile }> {
  const r = await rowOf(q, tenantId, id);
  if (r.state !== 'vendor_signature_pending' || !r.csr_der_b64) {
    throw new AppError(409, 'This request does not wait for the vendor\'s signature', 'pushRequestState');
  }
  const t = await q('tenants').where({ id: tenantId }).first('uuid') as { uuid: string };
  const file = buildRequestFile({
    instanceId: await instanceId(q), requestId: r.id, tenantRef: String(t.uuid), purpose: r.purpose,
    csrDer: Buffer.from(r.csr_der_b64, 'base64'), createdAt: new Date(r.created_at),
  });
  return { filename: `obligarth-push-request-${r.id}.json`, file };
}

/** Step 3: the vendor's signed file, checked (422 vendorFileInvalid with its reason), kept, the request moves on. */
export async function importVendorSigned(tenantId: number, id: string, text: string): Promise<{ view: PushRequestView; check: SignedFileCheck }> {
  const inst = await instanceId();
  const out = await db.transaction(async (trx) => {
    const r = await rowOf(trx, tenantId, id, true);
    if (r.state !== 'vendor_signature_pending' || !r.csr_der_b64) {
      throw new AppError(409, 'This request does not wait for the vendor\'s signature', 'pushRequestState');
    }
    let check: SignedFileCheck;
    try {
      check = checkSignedFile(text, { instanceId: inst, requestId: r.id, csrDer: Buffer.from(r.csr_der_b64, 'base64') });
      // Review of lot C3, R2: the vendor certificate must be one the platform pinned (the file names its own).
      check.vendorTrusted = checkVendorTrust(check.vendorCertSha256, config.apple.vendorCertPins ?? [], vendorPinRequired(config.nodeEnv));
    } catch (err) {
      if (err instanceof VendorFileError) {
        throw new AppError(422, `The vendor's file is refused: ${err.message}`, 'vendorFileInvalid', { reason: err.reason });
      }
      throw err;
    }
    const now = new Date();
    await trx('tenant_apple_push').where({ tenant_id: tenantId, id }).update({
      vendor_request_b64: check.appleRequestB64, vendor_signed_at: check.signedAt ?? now, state: 'apple_upload_pending', state_at: now, updated_at: now,
    });
    return { view: view(await rowOf(trx, tenantId, id)), check };
  });
  realtime.integrationChanged(tenantId, 'push');
  return out;
}

/** Step 4: the file the client uploads at Apple (the base64 of the signed request plist). */
export async function pushAppleFile(q: Knex, tenantId: number, id: string): Promise<{ filename: string; content: string }> {
  const r = await rowOf(q, tenantId, id);
  if (r.state !== 'apple_upload_pending' || !r.vendor_request_b64) {
    throw new AppError(409, 'This request has no signed file for Apple yet', 'pushRequestState');
  }
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  return { filename: `PushCertificateRequest-${day}.plist`, content: r.vendor_request_b64 };
}

export interface CertificateToImport {
  row: PushRequestView;
  check: PushCertificateCheck;
  /** The topic of the active certificate, if any. */
  activeTopic: string | null;
  topicChange: boolean;
}

/** Step 5, the checks before anything is asked of the user (a second factor, a second approver). */
export async function checkCertificateForRequest(q: Knex | Knex.Transaction, tenantId: number, id: string, pem: string): Promise<CertificateToImport> {
  const r = await rowOf(q, tenantId, id);
  if (r.state !== 'apple_upload_pending' || !r.csr_der_b64) {
    throw new AppError(409, 'This request does not wait for the certificate of Apple', 'pushRequestState');
  }
  let check: PushCertificateCheck;
  try {
    check = checkAppleCertificate(pem, Buffer.from(r.csr_der_b64, 'base64'));
  } catch (err) {
    if (err instanceof PushCertificateError) throw new AppError(422, err.message, err.code);
    throw err;
  }
  const active = await q('tenant_apple_push').where({ tenant_id: tenantId, state: 'active' }).first('topic') as { topic: string | null } | undefined;
  const activeTopic = active?.topic ?? null;
  const differs = activeTopic !== null && activeTopic !== check.topic;
  if (differs && r.purpose !== 'topic_change') {
    throw new AppError(422, 'This certificate was created with another Apple account (another topic): the devices would have to enroll '
      + 'again. Create a request for a change of topic if that is intended.', 'pushTopicMismatch');
  }
  return { row: view(r), check, activeTopic, topicChange: differs };
}

/** apple-edge's refusals of an import, as the console says them. */
function importError(err: unknown): never {
  if (isAppleEdgeError(err)) {
    switch (String(err.code)) {
      case 'topic_change_not_allowed': throw new AppError(422, 'The certificate changes the push topic', 'pushTopicMismatch');
      case 'key_mismatch': throw new AppError(422, 'This certificate was not issued for the pending request of this tenant', 'pushCertificateNotForRequest');
      case 'no_pending_key': throw new AppError(409, 'The device service no longer holds the key of this request: create a new request', 'pushNoPendingKey');
      case 'certificate_not_valid_now': throw new AppError(422, 'The certificate is expired or not yet valid', 'pushCertificateExpired');
      case 'invalid_topic': throw new AppError(422, 'The certificate carries no MDM push topic', 'pushCertificateNoTopic');
      case 'invalid_certificate': throw new AppError(422, 'The certificate cannot be read', 'pushCertificateInvalid');
      default: break;
    }
  }
  rethrowForConsole(err);
}

/** Imports the checked certificate at apple-edge (its pending key) and activates the request at the answer. */
export async function importAndActivate(tenantId: number, id: string, c: PushCertificateCheck, actor: DbActor,
  o: { allowTopicChange?: boolean } = {}): Promise<PushRequestView> {
  const key = await appleTenants.keyOf(tenantId);
  try {
    await appleEdge.importPushCertificate(key, { cert_pem: c.certPem, ...(o.allowTopicChange ? { allow_topic_change: true } : {}) },
      { actor: edgeActorOf(actor) });
  } catch (err) {
    importError(err);
  }
  await db.transaction((trx) => applyPushActivation(trx, tenantId, { topic: c.topic, certSha256: c.sha256, notAfter: c.notAfter }, new Date(), { preferredId: id }));
  realtime.integrationChanged(tenantId, 'push', 'deadlines');
  return view(await rowOf(db, tenantId, id));
}

/** A change of topic, before its approval: the certificate (public) kept on the request, with its approval. */
export async function holdTopicChange(trx: Knex.Transaction, tenantId: number, id: string, certPem: string, approvalId: number | null): Promise<void> {
  await trx('tenant_apple_push').where({ tenant_id: tenantId, id }).whereIn('state', OPEN_REQUEST as string[])
    .update({ pending_cert_pem: certPem, approval_id: approvalId, updated_at: new Date() });
}

/** The approved change of topic (executor): the kept certificate checked again, imported, activated. The approval must
 *  be the one the certificate was kept with, and the certificate's topic the one the approver was shown (review of lot
 *  C3, R1: a certificate posted after the approval request never rides on it). */
export async function executeTopicChange(tenantId: number, id: string, actor: DbActor,
  approved: { approvalId: number | null; topic: string }): Promise<{ topic: string; notAfter: string; previousTopic: string | null }> {
  const r = await rowOf(db, tenantId, id);
  if (r.purpose !== 'topic_change' || r.state !== 'apple_upload_pending' || !r.pending_cert_pem) {
    throw new AppError(409, 'This request no longer waits for its change of topic', 'pushRequestState');
  }
  if (approved.approvalId === null || r.approval_id === null || Number(r.approval_id) !== Number(approved.approvalId)) {
    throw new AppError(409, 'The kept certificate is not the one this approval was asked for', 'pushTopicChangeMismatch');
  }
  const c = await checkCertificateForRequest(db, tenantId, id, r.pending_cert_pem);
  if (c.check.topic !== approved.topic) {
    throw new AppError(409, 'The kept certificate is not the one this approval was asked for', 'pushTopicChangeMismatch');
  }
  await importAndActivate(tenantId, id, c.check, actor, { allowTopicChange: true });
  return { topic: c.check.topic, notAfter: c.check.notAfter.toISOString(), previousTopic: c.activeTopic };
}

export async function abandonPushRequest(tenantId: number, id: string): Promise<PushRequestView> {
  const n = await db('tenant_apple_push').where({ tenant_id: tenantId, id }).whereIn('state', OPEN_REQUEST as string[])
    .update({ state: 'abandoned', state_at: new Date(), closed_at: new Date(), pending_cert_pem: null, updated_at: new Date() });
  if (!n) {
    await rowOf(db, tenantId, id);
    throw new AppError(409, 'This request is not open', 'pushRequestState');
  }
  realtime.integrationChanged(tenantId, 'push');
  return view(await rowOf(db, tenantId, id));
}

/** Laboratory: a certificate with its key (APPLE_ALLOW_PUSH_KEY_IMPORT, platform administrator): handed to apple-edge
 *  once, never stored nor logged; the row is written by the activation (purpose 'import'). */
export async function importWithKey(tenantId: number, certPem: string, keyPem: string, actor: DbActor): Promise<PushRequestView | null> {
  if (!config.apple.allowPushKeyImport) throw new AppError(404, 'Not found');
  await vault.requireEscrow();
  const key = await appleTenants.keyOf(tenantId);
  let info: { topic?: string; not_after?: string };
  try {
    info = await appleEdge.importPushCertificate(key, { cert_pem: certPem, key_pem: keyPem }, { actor: edgeActorOf(actor) });
  } catch (err) {
    importError(err);
  }
  if (!info.topic || !info.not_after) return null;
  const topic = info.topic;
  const notAfter = new Date(info.not_after);
  await db.transaction((trx) => applyPushActivation(trx, tenantId, { topic, certSha256: null, notAfter }, new Date(), { importRow: true }));
  realtime.integrationChanged(tenantId, 'push', 'deadlines');
  const row = await db('tenant_apple_push').where({ tenant_id: tenantId, state: 'active' }).first(COLS) as PushRow | undefined;
  return row ? view(row) : null;
}

export interface PushActivation {
  topic: string;
  certSha256: string | null;
  notAfter: Date;
}

/**
 * Activates a push certificate in the tenant's mirror (the transaction's context is the tenant's): the row of this
 * certificate (by fingerprint), else the request the console names, else the open request of its topic, else any
 * open request, else a row 'import'. The previous certificate is superseded (same topic) or kept as legacy (another
 * topic). Monotone by `at`: a row already newer, or a newer active certificate, wins. The enrollment configuration
 * (it names the topic) is invalidated, the push alerts resolved, the deadline recorded. Returns null when nothing
 * changed (a replay, an older event).
 */
export async function applyPushActivation(trx: Knex.Transaction, tenantId: number, p: PushActivation, at: Date,
  o: { preferredId?: string; importRow?: boolean } = {}): Promise<{ renewal: boolean; previousTopic: string | null } | null> {
  const rows = await trx('tenant_apple_push').where({ tenant_id: tenantId }).forUpdate()
    .select('id', 'state', 'state_at', 'topic', 'cert_sha256') as Array<Pick<PushRow, 'id' | 'state' | 'state_at' | 'topic' | 'cert_sha256'>>;
  const sha = p.certSha256 ?? null;
  const isOpen = (r: { state: PushCertState }) => OPEN_REQUEST.includes(r.state);
  const target = (sha ? rows.find((r) => r.cert_sha256 === sha) : undefined)
    ?? (o.preferredId ? rows.find((r) => r.id === o.preferredId && isOpen(r)) : undefined)
    ?? (o.importRow ? undefined : rows.find((r) => isOpen(r) && r.topic === p.topic) ?? rows.find(isOpen));
  const current = rows.find((r) => r.state === 'active');
  if (target && target === current) return null;                       // already active (a replay)
  if (!target && current && current.topic === p.topic && o.importRow && current.cert_sha256 === sha) return null;
  // Monotony (occurred_at): the row already reflects this event or a newer one (expired since, superseded…).
  if (target && new Date(target.state_at).getTime() >= at.getTime()) return null;
  if (current && new Date(current.state_at).getTime() > at.getTime()) {
    // A newer certificate is active: this activation is older (consumed late), superseded since.
    if (target && isOpen(target)) {
      await trx('tenant_apple_push').where({ tenant_id: tenantId, id: target.id }).update({
        state: 'superseded', state_at: at, topic: p.topic, cert_sha256: sha, not_after: p.notAfter, closed_at: at, pending_cert_pem: null, updated_at: new Date(),
      });
    }
    return null;
  }
  if (current) {
    // A renewal at the same topic supersedes; a change of topic keeps the previous certificate for the devices
    // enrolled under it (legacy).
    await trx('tenant_apple_push').where({ tenant_id: tenantId, id: current.id })
      .update({ state: current.topic && current.topic !== p.topic ? 'legacy' : 'superseded', state_at: at, closed_at: at, updated_at: new Date() });
  }
  const cols = {
    state: 'active', state_at: at, activated_at: at, topic: p.topic, cert_sha256: sha, not_after: p.notAfter, pending_cert_pem: null, updated_at: new Date(),
  };
  if (target) {
    await trx('tenant_apple_push').where({ tenant_id: tenantId, id: target.id }).update(cols);
  } else {
    // Activated without a request of the console (an import of the laboratory, a restore): mirrored as an import.
    await trx('tenant_apple_push').insert({ id: randomUUID(), tenant_id: tenantId, purpose: 'import', ...cols });
  }
  await upsertMirror(trx, tenantId, { enrollment_config: null });    // the enrollment configuration names the topic
  for (const kind of ['apns.no_certificate', 'apns.circuit_open', 'apns.certificate_expired', 'apns.topic_config'] as const) {
    await resolveInTx(trx, tenantId, kind);
  }
  await recordDeadline(trx, tenantId, { kind: 'apns_certificate', subjectRef: p.topic, label: p.topic, notAfter: p.notAfter });
  return { renewal: current?.topic === p.topic, previousTopic: current?.topic ?? null };
}

/** integrations.push-abandon: the requests of the tenant open for more than 30 days. */
export async function abandonStaleRequests(trx: Knex.Transaction, tenantId: number, days: number): Promise<number> {
  const n = await trx('tenant_apple_push').where({ tenant_id: tenantId }).whereIn('state', OPEN_REQUEST as string[])
    .where('created_at', '<', new Date(Date.now() - days * 86_400_000))
    .update({ state: 'abandoned', state_at: new Date(), closed_at: new Date(), pending_cert_pem: null, updated_at: new Date() });
  return Number(n);
}

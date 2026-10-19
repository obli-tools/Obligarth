import { randomUUID } from 'node:crypto';
import { appleModeOfNanoType, ownershipAllows } from '@obligarth/shared';
import { db } from '../../db';
import type { DbActor } from '../../db/context';
import { withTenantTransaction } from '../../db/tenantContext';
import { jobIdFor } from '../../jobs';
import { AppError } from '../../middleware/errorHandler';
import { edgeActorOf } from '../actors';
import { resolveInTx } from '../alerts/service';
import { deviceEvents } from '../devices/events';
import { deviceJobs } from '../devices/jobs';
import { onAuthenticate, onTokenUpdate, type AuthenticateFacts } from '../devices/lifecycle';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import type { EdgeEnrollment } from '../edge/wire';
import { realtime } from '../realtime';
import { listAll, pendingEnrollments } from './tenant';

// =============================================================================
// Enrollments apple-edge holds that the brain does not (docs: integration-
// apple-edge §13.1, first row; §13.2, attachment in batch after a restore;
// review INT-RC4; modele DM25): never a record of a guessed ownership. The
// operator (mdm.enrollment.manage) either attaches an enrollment to an
// enrollment profile of the tenant — the record is born with the profile's
// ownership and method, through the same path as an enrollment (an
// enrollment session of the profile, 'certificate_issued' with the
// certificate apple-edge holds, then onAuthenticate and onTokenUpdate, then
// apple.device-onboard) — or releases it at apple-edge (its certificates
// revoked: the device enrolls again). The list is read from apple-edge
// (outside any transaction), against the records of the tenant.
// =============================================================================

const ENROLLMENT_ID_RE = /^[a-km-np-z2-9]{16}_[A-Za-z0-9._-]{1,128}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MANAGED = new Set(['enrolling', 'awaiting_configuration', 'enrolled']);
/** Enrollments handled per request. */
export const UNKNOWN_BATCH_MAX = 200;

export interface UnknownEnrollmentView {
  enrollmentId: string;
  type: string;
  proof: string;
  createdAt: string;
  lastSeenAt: string;
}

export type AttachOutcome = 'attached' | 'already' | 'not_found' | 'disabled' | 'ownership' | 'other_kind' | 'managed' | 'pending' | 'failed';
export type ReleaseOutcome = 'released' | 'not_found' | 'managed' | 'pending' | 'failed';

interface Ctx { tenantId: number; key: string; actor: DbActor; requestId?: string }

async function keyOf(tenantId: number): Promise<string> {
  const t = await db('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
  if (!t?.mdm_key) throw new AppError(409, 'This tenant is not provisioned at the device service yet', 'appleTenantNotProvisioned');
  return t.mdm_key;
}

const opts = (c: Ctx) => ({ actor: edgeActorOf(c.actor), requestId: c.requestId });

function edgeError(err: unknown): never {
  if (isAppleEdgeError(err)) throw new AppError(err.retryable ? 503 : 502, 'The device service did not answer as expected', 'appleEdgeUnavailable');
  throw err;
}

/** The unknown enrollments of a tenant: enabled at apple-edge, without a record under management that holds their
 *  current certificate, and with no event waiting in the outbox. */
async function computeUnknown(c: Ctx): Promise<EdgeEnrollment[]> {
  let list: EdgeEnrollment[];
  try {
    list = await listAll(c.key, null, { full: true, actor: c.actor, requestId: c.requestId });
  } catch (err) { edgeError(err); }
  const pending = await pendingEnrollments(c.key);
  const records = await db('apple_devices as a')
    .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where('a.tenant_id', c.tenantId).select('a.enrollment_id', 'a.cert_sha256', 'd.enrollment_state') as
    Array<{ enrollment_id: string; cert_sha256: string | null; enrollment_state: string }>;
  const byId = new Map(records.map((r) => [String(r.enrollment_id), r]));
  return list.filter((e) => {
    if (!e.enabled || pending.has(e.enrollment_id)) return false;
    const r = byId.get(e.enrollment_id);
    if (!r) return true;
    const same = !!e.cert_sha256 && !!r.cert_sha256 && String(r.cert_sha256).trim().toLowerCase() === e.cert_sha256.toLowerCase();
    return !(same && MANAGED.has(r.enrollment_state));
  });
}

const view = (e: EdgeEnrollment): UnknownEnrollmentView => ({
  enrollmentId: e.enrollment_id, type: e.type, proof: e.proof, createdAt: e.created_at, lastSeenAt: e.last_seen_at,
});

export async function listUnknownEnrollments(tenantId: number, actor: DbActor, requestId?: string): Promise<UnknownEnrollmentView[]> {
  const key = await keyOf(tenantId);
  return (await computeUnknown({ tenantId, key, actor, requestId })).map(view);
}

/** After an attachment or a release: the aggregated alert follows what is left. */
async function settleAlert(c: Ctx): Promise<number> {
  const left = (await computeUnknown(c)).length;
  if (left === 0) await withTenantTransaction(c.tenantId, c.actor, (trx) => resolveInTx(trx, c.tenantId, 'enrollment.unknown_session'));
  return left;
}

function checkIds(ids: string[], key: string): string[] {
  const out = [...new Set(ids.map(String))];
  if (out.length === 0 || out.length > UNKNOWN_BATCH_MAX) throw new AppError(400, `1 to ${UNKNOWN_BATCH_MAX} enrollments`, 'invalidRequest');
  for (const id of out) {
    if (!ENROLLMENT_ID_RE.test(id) || !id.startsWith(`${key}_`) || id.includes(':')) throw new AppError(404, 'Enrollment not found', 'enrollmentNotFound');
  }
  return out;
}

/** The topic the tenant's devices push on (the active push certificate, else the cached enrollment configuration). */
async function topicOf(tenantId: number): Promise<string | null> {
  const push = await db('tenant_apple_push').where({ tenant_id: tenantId, state: 'active' }).first('topic') as { topic: string | null } | undefined;
  if (push?.topic) return push.topic;
  const m = await db('tenant_apple_edge').where({ tenant_id: tenantId }).first('enrollment_config') as { enrollment_config: { topic?: string | null } | null } | undefined;
  return m?.enrollment_config?.topic ?? null;
}

/**
 * Attaches enrollments to an enrollment profile of the tenant (in the tenant's context: the caller's request).
 * Each enrollment in its own transaction; the answer says what became of each.
 */
export async function attachUnknownEnrollments(tenantId: number, actor: DbActor, input: { profileId: string; enrollmentIds: string[] },
  requestId?: string): Promise<{ results: Record<string, AttachOutcome>; deviceIds: number[]; left: number }> {
  const key = await keyOf(tenantId);
  const c: Ctx = { tenantId, key, actor, requestId };
  const ids = checkIds(input.enrollmentIds, key);
  if (!UUID_RE.test(input.profileId)) throw new AppError(404, 'Enrollment profile not found', 'enrollmentProfileNotFound');
  const profile = await db('enrollment_profiles').where({ tenant_id: tenantId, id: input.profileId.toLowerCase() }).whereNull('archived_at')
    .first('id', 'method', 'ownership', 'enabled', 'locale') as { id: string; method: string; ownership: string; enabled: boolean; locale: string } | undefined;
  if (!profile) throw new AppError(404, 'Enrollment profile not found', 'enrollmentProfileNotFound');
  if (!profile.enabled) throw new AppError(409, 'This enrollment profile is disabled', 'enrollmentProfileDisabled');
  const topic = await topicOf(tenantId);
  if (!topic) throw new AppError(409, 'This tenant has no active push certificate', 'appleTopicMissing');
  const results: Record<string, AttachOutcome> = {};
  const deviceIds: number[] = [];
  // An enrollment with an event still waiting in the outbox is left to the consumer (its Authenticate may carry the
  // session that says its ownership): never attached under another profile, nor released (review of lot C5).
  const pending = await pendingEnrollments(key);
  for (const id of ids) {
    if (pending.has(id)) { results[id] = 'pending'; continue; }
    let e: EdgeEnrollment;
    try {
      e = (await appleEdge.getEnrollment(key, id, opts(c))).enrollment;
    } catch (err) {
      if (isAppleEdgeError(err) && (err.code === 'enrollment_not_found' || err.status === 404)) { results[id] = 'not_found'; continue; }
      edgeError(err);
    }
    if (!e.enabled) { results[id] = 'disabled'; continue; }
    const certSha = e.cert_sha256 ? e.cert_sha256.toLowerCase() : null;
    const type = e.type === 'Device' || e.type === 'User Enrollment (Device)' ? e.type : null;
    const mode = type ? appleModeOfNanoType(type) : null;
    if (!type || !certSha || !mode) { results[id] = 'failed'; continue; }
    if (!ownershipAllows(profile.ownership, profile.method, mode)) { results[id] = 'ownership'; continue; }
    try {
      const r = await withTenantTransaction(tenantId, actor, async (trx) => {
        const sat = await trx('apple_devices as a')
          .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
          .where({ 'a.tenant_id': tenantId, 'a.enrollment_id': id })
          .first('a.device_id', 'a.cert_sha256', 'a.nano_enroll_type', 'd.enrollment_state') as
          { device_id: number; cert_sha256: string | null; nano_enroll_type: string; enrollment_state: string } | undefined;
        if (sat && sat.nano_enroll_type !== type) return { outcome: 'other_kind' as AttachOutcome };
        if (sat && String(sat.cert_sha256 ?? '').trim().toLowerCase() === certSha) {
          return { outcome: (MANAGED.has(sat.enrollment_state) ? 'already' : 'failed') as AttachOutcome };
        }
        if (sat && MANAGED.has(sat.enrollment_state)) return { outcome: 'managed' as AttachOutcome };
        const now = new Date();
        const [session] = await trx('enrollment_sessions').insert({
          tenant_id: tenantId, profile_id: profile.id, method: profile.method, ownership: profile.ownership, state: 'certificate_issued',
          state_at: now, cert_sha256: certSha, locale: profile.locale ?? 'fr', expires_at: new Date(now.getTime() + 3_600_000),
        }).returning('id') as Array<{ id: string }>;
        const facts: AuthenticateFacts = {
          enrollmentId: id, kind: type === 'Device' ? 'udid' : 'enrollment_id', rawId: id.slice(key.length + 1), enrollmentType: type,
          topic, proof: e.proof === 'ade' ? 'ade' : 'none', certSha256: certSha,
          certNotAfter: e.cert_not_after ? new Date(e.cert_not_after) : null, challengeId: null, sessionRef: String(session.id),
          message: {}, occurredAt: now, eventId: randomUUID(),
        };
        const a = await onAuthenticate(trx, tenantId, facts);
        if ((a.outcome !== 'created' && a.outcome !== 'new_cycle') || !a.deviceId) {
          throw new AttachRefused(a.outcome === 'ownership_mismatch' ? 'ownership' : 'failed');
        }
        const deviceId = Number(a.deviceId);
        await deviceEvents.add(trx, tenantId, deviceId, 'enrollment_started', now, facts.eventId, { cycle: a.outcome === 'created' ? 'first' : 'new', attached: true });
        const at = new Date(now.getTime() + 1);
        const tokenEvent = randomUUID();
        const u = await onTokenUpdate(trx, tenantId, { enrollmentId: id, awaitingConfiguration: false, hasUnlockToken: false, topic, occurredAt: at, eventId: tokenEvent });
        if (!u || (u.outcome !== 'completed' && u.outcome !== 'refreshed')) throw new AttachRefused('failed');
        await deviceJobs.onboard().sendInTx(trx, { tenantId, deviceId }, { id: jobIdFor('apple.device-onboard', tokenEvent), tenantId });
        await deviceEvents.add(trx, tenantId, deviceId, 'enrolled', at, tokenEvent, { attached: true });
        return { outcome: 'attached' as AttachOutcome, deviceId, sessionId: String(session.id) };
      });
      results[id] = r.outcome;
      if (r.outcome === 'attached' && 'deviceId' in r && r.deviceId) {
        deviceIds.push(r.deviceId);
        realtime.deviceChanged(tenantId, r.deviceId);
        realtime.sessionChanged(tenantId, r.sessionId);
      }
    } catch (err) {
      if (err instanceof AttachRefused) { results[id] = err.outcome; continue; }
      // A refusal of this enrollment alone (a uniqueness or check of the records, a missing prerequisite) is its
      // outcome, not the batch's: what was attached before stays attached and is journaled (review of lot C5, R5).
      if (attachRefusalOf(err)) { results[id] = 'failed'; continue; }
      throw err;
    }
  }
  const left = await settleAlert(c);
  return { results, deviceIds, left };
}

class AttachRefused extends Error {
  constructor(readonly outcome: AttachOutcome) { super(outcome); }
}

/** An error that refuses one enrollment only: a client error of the lifecycle, or an integrity violation (class 23). */
function attachRefusalOf(err: unknown): boolean {
  if (err instanceof AppError) return err.statusCode >= 400 && err.statusCode < 500;
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' && code.startsWith('23');
}

/** Releases enrollments unknown to the brain at apple-edge (never one a record under management holds). */
export async function releaseUnknownEnrollments(tenantId: number, actor: DbActor, input: { enrollmentIds: string[] }, requestId?: string):
  Promise<{ results: Record<string, ReleaseOutcome>; left: number }> {
  const key = await keyOf(tenantId);
  const c: Ctx = { tenantId, key, actor, requestId };
  const ids = checkIds(input.enrollmentIds, key);
  const managed = new Set((await db('apple_devices as a')
    .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where('a.tenant_id', tenantId).whereIn('a.enrollment_id', ids).whereIn('d.enrollment_state', [...MANAGED])
    .pluck('a.enrollment_id') as string[]).map(String));
  const results: Record<string, ReleaseOutcome> = {};
  const pending = await pendingEnrollments(key);
  for (const id of ids) {
    if (managed.has(id)) { results[id] = 'managed'; continue; }
    if (pending.has(id)) { results[id] = 'pending'; continue; }
    try {
      await appleEdge.releaseEnrollment(key, id, opts(c));
      results[id] = 'released';
    } catch (err) {
      if (isAppleEdgeError(err) && (err.code === 'enrollment_not_found' || err.status === 404)) { results[id] = 'not_found'; continue; }
      if (isAppleEdgeError(err) && !err.retryable) { results[id] = 'failed'; continue; }
      edgeError(err);
    }
  }
  const left = await settleAlert(c);
  return { results, left };
}

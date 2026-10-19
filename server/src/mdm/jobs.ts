import { z } from 'zod';
import { config } from '../config';
import { db } from '../db';
import { PermanentJobError, registerJob, type JobContext, type JobHandle, type JobResult } from '../jobs';
import { isAppleEdgeError } from '../apple/edge/errors';
import { appleEdge } from '../apple/edge/instance';

// =============================================================================
// Durable jobs of the MDM data model (docs: modele-donnees-mdm §10.5; file
// durable §5.1, annex B). Lot B2: mdm.enrollment-release; the resolution,
// reconciliation, compliance and garbage collection queues come with their
// lots (B5, C5). Payloads carry internal identifiers only (file-durable S4):
// never an enrollment id, a UDID nor a serial number.
// =============================================================================

const ReleasePayload = z.object({
  tenantId: z.number().int().positive(),
  /** The outbox event of the refused Authenticate (apple_edge.outbox.event_id): the enrollment is read there. */
  eventId: z.string().uuid(),
}).strict();

let releaseJob: JobHandle<z.infer<typeof ReleasePayload>> | null = null;

/** The handle of mdm.enrollment-release (registerMdmModule must have run). */
export function enrollmentReleaseJob(): JobHandle<z.infer<typeof ReleasePayload>> {
  if (!releaseJob) throw new Error('mdm.enrollment-release is not registered (registerMdmModule)');
  return releaseJob;
}

/** A certificate fingerprint as the events and apple-edge write it (SHA-256, lower-case hexadecimal), or null. */
function fingerprint(v: unknown): string | null {
  const s = typeof v === 'string' ? v.trim().toLowerCase() : '';
  return /^[0-9a-f]{64}$/.test(s) ? s : null;
}

/**
 * mdm.enrollment-release (barrier 2 of modele §4.3, §4.5; integration §7.3): an Authenticate the brain refused (a
 * mode the session's ownership forbids, a serial number or a kind of identifier that contradicts what is verified)
 * wrote no record; the enrollment apple-edge accepted is released there (apple-edge §3.7). The enrollment id is
 * read from the outbox event (never carried by the payload) and checked against the tenant's key (integration
 * T-3). A release takes a device out of management (its certificates are revoked): only the enrollment of the
 * refused Authenticate is released (review of lot B2, MDM-B2-R3):
 *   - the event is an mdm.authenticate, and not the one a record under management was enrolled by (the record's
 *     current certificate is not the event's): a payload that names another event releases nothing;
 *   - apple-edge still holds the enrollment under the certificate of that Authenticate: authenticated again since
 *     (another certificate), the enrollment has its own event, accepted, or refused with its own release.
 * Done when apple-edge no longer knows the enrollment.
 */
async function releaseEnrollment(ctx: JobContext<z.infer<typeof ReleasePayload>>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  const tenantId = ctx.tenantId as number;
  const target = await ctx.inTenant(async () => {
    const t = await db('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
    if (!t?.mdm_key) return null;
    // The event through the guarded function (INT-B1-R9 B): an event of this tenant, or only that it is another's.
    type Read = { other_tenant?: true; tenant_key?: string | null; enrollment_id?: string | null; type?: string; cert_sha256?: string | null };
    const read = ((await db.raw('SELECT obligarth.edge_outbox_event(?::uuid) AS ev', [ctx.payload.eventId])) as { rows: Array<{ ev: Read | null }> })
      .rows[0]?.ev ?? null;
    const ev = read === null ? undefined : read.other_tenant
      ? { tenant_key: null, enrollment_id: null, type: '', cert_sha256: null }
      : { tenant_key: read.tenant_key ?? null, enrollment_id: read.enrollment_id ?? null, type: String(read.type ?? ''), cert_sha256: read.cert_sha256 ?? null };
    // The record of the tenant still under management that holds this enrollment id, if any.
    const holder = ev?.enrollment_id
      ? await db('apple_devices as a')
        .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
        .where({ 'a.tenant_id': tenantId, 'a.enrollment_id': ev.enrollment_id }).whereNot('d.enrollment_state', 'unenrolled')
        .first('a.cert_sha256') as { cert_sha256: string | null } | undefined
      : undefined;
    return { key: t.mdm_key, event: ev ?? null, holder: holder ? { cert: fingerprint(holder.cert_sha256) } : null };
  });
  if (!target) throw new PermanentJobError('tenant_without_key', 'the tenant has no MDM key');
  if (!target.event) return { output: { skipped: 'event_purged' } };
  const enrollmentId = target.event.enrollment_id ?? '';
  if (target.event.tenant_key !== target.key || !enrollmentId.startsWith(`${target.key}_`)) {
    throw new PermanentJobError('tenant_mismatch', 'the event is not an enrollment of this tenant');
  }
  if (target.event.type !== 'mdm.authenticate') throw new PermanentJobError('not_an_authenticate', 'the event is not an Authenticate');
  const refused = fingerprint(target.event.cert_sha256);
  if (target.holder && (refused === null || target.holder.cert === refused)) {
    // The Authenticate a record under management was enrolled by, or one that cannot be told from it.
    throw new PermanentJobError('enrollment_accepted', 'the Authenticate is the one of a record under management');
  }
  const o = { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal };
  try {
    const detail = await appleEdge.getEnrollment(target.key, enrollmentId, o);
    const atEdge = fingerprint(detail.enrollment.cert_sha256);
    if (refused !== null && atEdge !== null && atEdge !== refused) return { output: { released: false, reason: 'superseded' } };
    // An enrollment whose certificate apple-edge does not show, while a record under management holds its id.
    if (atEdge === null && target.holder) return { output: { released: false, reason: 'unverified' } };
    const r = await appleEdge.releaseEnrollment(target.key, enrollmentId, o);
    return { output: { released: true, idsReleased: r.released.length, revokedCertificates: r.revoked_certificates } };
  } catch (err) {
    if (isAppleEdgeError(err) && (err.code === 'enrollment_not_found' || err.status === 404)) return { output: { released: false, reason: 'not_found' } };
    throw err;
  }
}

let registered = false;

/** The jobs of the data model (registerMdmModule). */
export function registerMdmJobs(): void {
  if (registered) return;
  registered = true;
  releaseJob = registerJob({
    name: 'mdm.enrollment-release',
    scope: 'tenant',
    description: 'Release at apple-edge an enrollment refused by the ownership rules',
    payload: ReleasePayload,
    policy: 'standard',
    retry: { limit: 5, delaySeconds: 30, backoff: true, maxDelaySeconds: 1800 },
    timeoutSeconds: 60,
    notify: true,
    handler: releaseEnrollment,
  });
}

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

/**
 * mdm.enrollment-release (barrier 2 of modele §4.3, §4.5): an Authenticate whose observed mode the session's
 * ownership forbids created no record; the enrollment is released at apple-edge (apple-edge §3.7). The
 * enrollment id is read from the outbox event (never carried by the payload) and checked against the
 * tenant's key (integration T-3). Done when apple-edge no longer knows it.
 */
async function releaseEnrollment(ctx: JobContext<z.infer<typeof ReleasePayload>>): Promise<JobResult> {
  if (config.apple.mode !== 'on') return { output: { skipped: 'apple_edge_off' } };
  const tenantId = ctx.tenantId as number;
  const target = await ctx.inTenant(async () => {
    const t = await db('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
    if (!t?.mdm_key) return null;
    const ev = await db('apple_edge.outbox').where({ event_id: ctx.payload.eventId }).first('tenant_key', 'enrollment_id') as
      { tenant_key: string | null; enrollment_id: string | null } | undefined;
    return { key: t.mdm_key, event: ev ?? null };
  });
  if (!target) throw new PermanentJobError('tenant_without_key', 'the tenant has no MDM key');
  if (!target.event) return { output: { skipped: 'event_purged' } };
  const enrollmentId = target.event.enrollment_id ?? '';
  if (target.event.tenant_key !== target.key || !enrollmentId.startsWith(`${target.key}_`)) {
    throw new PermanentJobError('tenant_mismatch', 'the event is not an enrollment of this tenant');
  }
  try {
    const r = await appleEdge.releaseEnrollment(target.key, enrollmentId, { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal });
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

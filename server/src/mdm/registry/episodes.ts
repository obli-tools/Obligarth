import type { Knex } from 'knex';
import type {
  EnrollmentEpisode, EnrollmentMethod, EpisodeEndReason, ManagementMode, Ownership, UnenrollReason,
} from '@obligarth/shared';
import { db } from '../../db';

// =============================================================================
// Enrollment episodes (docs: modele-donnees-mdm §4.7, §10.3, §10.4): one row of
// device_enrollments per enrollment cycle of a device, one open at most
// (device_enrollments_one_open). Called by the lifecycle of the integration
// (onAuthenticate, onTokenUpdate, onUnenrolled) in the transaction and the
// tenant context of the outbox consumer; no other writer.
// =============================================================================

export interface NewEpisode {
  /** The enrollment id of the channel ('<MDM key>_<UDID or EnrollmentID>'). */
  channelEnrollmentId: string;
  method: EnrollmentMethod;
  mode: ManagementMode;
  ownership: Ownership;
  enrollmentProfileId: string | null;
  enrollmentSessionId: string | null;
  endUserId: number | null;
  certSha256: string | null;
  startedAt: Date;
}

/** Opens the episode of a new cycle; an episode still open is closed first ('replaced', at the start of the
 *  new one: a device has one open episode at most). */
export async function openEpisode(trx: Knex.Transaction, tenantId: number, deviceId: number, e: NewEpisode): Promise<void> {
  await closeEpisode(trx, tenantId, deviceId, 'replaced', e.startedAt);
  await trx('device_enrollments').insert({
    tenant_id: tenantId,
    device_id: deviceId,
    channel_enrollment_id: e.channelEnrollmentId,
    enrollment_type: e.method,
    management_mode: e.mode,
    ownership: e.ownership,
    enrollment_profile_id: e.enrollmentProfileId,
    enrollment_session_id: e.enrollmentSessionId,
    end_user_id: e.endUserId,
    cert_sha256: e.certSha256,
    started_at: e.startedAt,
  });
}

/** The first TokenUpdate of the cycle: the open episode is enrolled (the first date is kept). */
export async function markEpisodeEnrolled(trx: Knex.Transaction, tenantId: number, deviceId: number, at: Date): Promise<void> {
  await trx('device_enrollments')
    .where({ tenant_id: tenantId, device_id: deviceId })
    .whereNull('ended_at')
    .whereNull('enrolled_at')
    .update({ enrolled_at: at });
}

/** Closes the open episode (none: nothing to do). An episode never ends before it started. */
export async function closeEpisode(trx: Knex.Transaction, tenantId: number, deviceId: number,
  reason: UnenrollReason | 'replaced', at: Date): Promise<void> {
  await trx('device_enrollments')
    .where({ tenant_id: tenantId, device_id: deviceId })
    .whereNull('ended_at')
    .update({ ended_at: trx.raw('GREATEST(?::timestamptz, started_at)', [at]), end_reason: reason });
}

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);

/** The episodes of a device, newest first (GET /api/mdm/devices/:id/enrollments), in the caller's context. */
export async function listEpisodes(tenantId: number, deviceId: number): Promise<EnrollmentEpisode[]> {
  const rows = await db('device_enrollments')
    .where({ tenant_id: tenantId, device_id: deviceId })
    .orderBy('started_at', 'desc')
    .orderBy('id', 'desc')
    .select('*') as Array<Record<string, any>>;
  return rows.map((r) => ({
    id: Number(r.id),
    deviceId: Number(r.device_id),
    channelEnrollmentId: r.channel_enrollment_id,
    enrollmentMethod: r.enrollment_type,
    managementMode: r.management_mode,
    ownership: r.ownership,
    enrollmentProfileId: r.enrollment_profile_id ?? null,
    enrollmentSessionId: r.enrollment_session_id ?? null,
    endUserId: r.end_user_id === null || r.end_user_id === undefined ? null : Number(r.end_user_id),
    certSha256: r.cert_sha256 ? String(r.cert_sha256).trim() : null,
    startedAt: iso(r.started_at)!,
    enrolledAt: iso(r.enrolled_at),
    endedAt: iso(r.ended_at),
    endReason: (r.end_reason ?? null) as EpisodeEndReason | null,
  }));
}

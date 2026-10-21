// The barrier of the BYOD Android enrollment on the token and the enrollment side (lot AN-F1, section 10.5): no
// enrollment token of a personal device without an invitation whose notice was acknowledged in this very flow, and
// no device of such a token accepted unless its invitation is issued (not revoked, not used). Kept apart from
// invitations.ts so that enrollment/tokens.ts and enrollment/handler.ts depend on it without a cycle.
import type { Knex } from 'knex';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * The check createEnrollmentToken makes for a byod_link token (in its first transaction): the invitation is the
 * tenant's, issuing (its notice acknowledged in this flow), for this profile and this end user.
 */
export async function checkInvitationIssuing(trx: Knex.Transaction, tenantId: number, invitationId: unknown, profileId: string,
  endUserId: number | undefined): Promise<boolean> {
  if (typeof invitationId !== 'string' || !UUID_RE.test(invitationId)) return false;
  const row = await trx('android_byod_invitations').where({ tenant_id: tenantId, id: invitationId }).forShare()
    .first('state', 'profile_id', 'end_user_id', 'notice_version_id', 'acknowledged_at') as
    { state: string; profile_id: string; end_user_id: number; notice_version_id: string | null; acknowledged_at: Date | null } | undefined;
  return !!row && row.state === 'issuing' && !!row.notice_version_id && !!row.acknowledged_at && String(row.profile_id) === profileId
    && Number(row.end_user_id) === Number(endUserId);
}

export interface EnrollmentInvitation {
  id: string;
  noticeVersionId: string;
  /** 'issued', or revoked / expired AFTER the device enrolled (section 10.4 step 3, F1R-5): the event came late. */
  state: 'issued' | 'revoked' | 'expired';
}

/**
 * In the transaction of the ENROLLMENT event: the invitation of a byod_link token, when it may enroll a device enrolled
 * at `enrolledAt` (Device.enrollmentTime): issued after an acknowledged notice and not used; a revocation or an end
 * AFTER the enrollment prevents nothing (section 10.4 step 3: the event may be applied late, F1R-5), one before it
 * does. Null otherwise (the device is then an unknown enrollment: quarantined, DISABLED, never erased: a personal device
 * is never deleted automatically).
 */
export async function invitationForEnrollment(trx: Knex.Transaction, tenantId: number, tokenId: string, enrolledAt?: Date):
  Promise<EnrollmentInvitation | null> {
  const row = await trx('android_byod_invitations').where({ tenant_id: tenantId, token_id: tokenId }).forUpdate()
    .first('id', 'state', 'notice_version_id', 'acknowledged_at', 'revoked_at', 'expires_at', 'device_id') as
    { id: string; state: string; notice_version_id: string | null; acknowledged_at: Date | null; revoked_at: Date | null; expires_at: Date;
      device_id: number | null } | undefined;
  if (!row || !row.notice_version_id || !row.acknowledged_at) return null;
  const out = (state: EnrollmentInvitation['state']): EnrollmentInvitation => ({ id: String(row.id), noticeVersionId: String(row.notice_version_id), state });
  if (row.state === 'issued') return out('issued');
  const at = enrolledAt instanceof Date && Number.isFinite(enrolledAt.getTime()) ? enrolledAt.getTime() : null;
  // Late: only with the time of the enrollment, after the acknowledgement, and once (no device recorded yet).
  if (at === null || row.device_id !== null || at < new Date(row.acknowledged_at).getTime()) return null;
  if (row.state === 'revoked' && row.revoked_at && at < new Date(row.revoked_at).getTime()) return out('revoked');
  if (row.state === 'expired' && at < new Date(row.expires_at).getTime()) return out('expired');
  return null;
}

/** The invitation used by the device just recorded (same transaction): its code serves no more. An invitation revoked
 *  or expired after the enrollment keeps its state and names the device. */
export async function markInvitationUsed(trx: Knex.Transaction, tenantId: number, invitation: string | EnrollmentInvitation, deviceId: number): Promise<void> {
  const inv = typeof invitation === 'string' ? { id: invitation, state: 'issued' as const } : invitation;
  if (inv.state !== 'issued') {
    await trx('android_byod_invitations').where({ tenant_id: tenantId, id: inv.id, state: inv.state }).whereNull('device_id')
      .update({ device_id: deviceId, updated_at: trx.fn.now() });
    return;
  }
  await trx('android_byod_invitations').where({ tenant_id: tenantId, id: inv.id, state: 'issued' })
    .update({ state: 'used', used_at: trx.fn.now(), device_id: deviceId, issuing_at: null, updated_at: trx.fn.now() });
}

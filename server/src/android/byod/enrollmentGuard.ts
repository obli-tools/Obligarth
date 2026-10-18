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

/**
 * In the transaction of the ENROLLMENT event: the invitation of a byod_link token, when it may enroll a device (issued
 * after an acknowledged notice, not revoked, not used); null otherwise (the device is then an unknown enrollment:
 * quarantined, DISABLED, never erased: a personal device is never deleted automatically).
 */
export async function invitationForEnrollment(trx: Knex.Transaction, tenantId: number, tokenId: string):
  Promise<{ id: string; noticeVersionId: string } | null> {
  const row = await trx('android_byod_invitations').where({ tenant_id: tenantId, token_id: tokenId }).forUpdate()
    .first('id', 'state', 'notice_version_id', 'acknowledged_at') as
    { id: string; state: string; notice_version_id: string | null; acknowledged_at: Date | null } | undefined;
  if (!row || row.state !== 'issued' || !row.notice_version_id || !row.acknowledged_at) return null;
  return { id: String(row.id), noticeVersionId: String(row.notice_version_id) };
}

/** The invitation used by the device just recorded (same transaction): its code serves no more. */
export async function markInvitationUsed(trx: Knex.Transaction, tenantId: number, invitationId: string, deviceId: number): Promise<void> {
  await trx('android_byod_invitations').where({ tenant_id: tenantId, id: invitationId, state: 'issued' })
    .update({ state: 'used', used_at: trx.fn.now(), device_id: deviceId, issuing_at: null, updated_at: trx.fn.now() });
}

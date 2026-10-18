// The barrier of the sign-in URL flow on the token and the enrollment side (lot AN-F2, section 10.5, §22.3): no
// enrollment token of kind signin without a sign-in session of the device surface whose user Obligate just
// authenticated as an active end user of the tenant, and no device of such a token accepted unless its session is
// issued (the token handed to that device, not used yet). Kept apart from flow.ts so that enrollment/tokens.ts and
// enrollment/handler.ts depend on it without a cycle.
import type { Knex } from 'knex';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * The check createEnrollmentToken makes for a signin token (in its first transaction): the session is the tenant's,
 * authenticated (an end user identified by Obligate), not expired, for this profile and this end user, and holds no
 * token yet.
 */
export async function checkSigninSessionAuthenticated(trx: Knex.Transaction, tenantId: number, sessionId: unknown, profileId: string,
  endUserId: number | undefined): Promise<boolean> {
  if (typeof sessionId !== 'string' || !UUID_RE.test(sessionId)) return false;
  const row = await trx('android_signin_sessions').where({ tenant_id: tenantId, id: sessionId }).forShare()
    .first('state', 'profile_id', 'end_user_id', 'token_id', 'expires_at') as
    { state: string; profile_id: string; end_user_id: number | null; token_id: string | null; expires_at: Date } | undefined;
  return !!row && row.state === 'authenticated' && !row.token_id && new Date(row.expires_at).getTime() > Date.now()
    && String(row.profile_id) === profileId && row.end_user_id !== null && Number(row.end_user_id) === Number(endUserId);
}

/**
 * In the transaction of the ENROLLMENT event: the session of a signin token, when it may enroll a device (issued, not
 * used); null otherwise (the device is then an unknown enrollment: quarantined, DISABLED).
 */
export async function signinSessionForEnrollment(trx: Knex.Transaction, tenantId: number, tokenId: string): Promise<{ id: string } | null> {
  const row = await trx('android_signin_sessions').where({ tenant_id: tenantId, token_id: tokenId }).forUpdate()
    .first('id', 'state') as { id: string; state: string } | undefined;
  if (!row || row.state !== 'issued') return null;
  return { id: String(row.id) };
}

/** The session used by the device just recorded (same transaction). */
export async function markSigninSessionUsed(trx: Knex.Transaction, tenantId: number, sessionId: string, deviceId: number): Promise<void> {
  await trx('android_signin_sessions').where({ tenant_id: tenantId, id: sessionId, state: 'issued' })
    .update({ state: 'used', used_at: trx.fn.now(), device_id: deviceId, updated_at: trx.fn.now() });
}

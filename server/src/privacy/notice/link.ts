import type { Knex } from 'knex';

// =============================================================================
// The acknowledgement of the notice attached to its device and its end user (P0-13 T5, USR-01; M3 of the spec, D5).
// An acknowledgement is recorded at the notice's page, before the device exists and, for the ADE web view or the
// Android sign-in, before the end user is known: its row names the session or the invitation only (subject_ref). The
// sessions go after 30 days, the acknowledgements stay 36 months (notice_ack_months): the device and the end user are
// written into the acknowledgement once the subject knows them, in the transaction that records them there:
//   - enrollment_sessions: the device of the Authenticate (apple/devices/lifecycle.ts onAuthenticate);
//   - android_byod_invitations: the device of the enrollment (markInvitationUsed);
//   - android_signin_sessions: the end user authenticated by Obligate (signin/flow.ts), the device of the enrollment
//     (markSigninSessionUsed).
// From the subject's own columns, which the caller has just written: the device of the subject when it has one, else
// the acknowledgement's; its end user when it has one, else the acknowledgement's (never cleared here). The runtime
// role updates these two columns only (GRANT UPDATE (end_user_id, device_id)). No acknowledgement (the default notice
// of the laboratory's unit tests keeps a random id, or none was recorded): nothing changes.
// No import but Knex's types: the barriers of the Android enrollment (enrollmentGuard.ts, guard.ts) depend on it
// without a cycle.
// =============================================================================

/** The subjects of an acknowledgement, each with its notice_ack_id, end_user_id and device_id. */
export type NoticeAckSubject = 'enrollment_sessions' | 'android_byod_invitations' | 'android_signin_sessions';

const SUBJECTS: readonly NoticeAckSubject[] = ['enrollment_sessions', 'android_byod_invitations', 'android_signin_sessions'];

/** In the caller's transaction, in the tenant's context: the acknowledgement of the subject takes its device and its end
 *  user. Returns the number of acknowledgements updated (0 or 1). */
export async function linkNoticeAcknowledgement(trx: Knex.Transaction, tenantId: number, subject: NoticeAckSubject,
  subjectId: string): Promise<number> {
  if (!SUBJECTS.includes(subject)) throw new Error(`notice: unknown acknowledgement subject ${String(subject)}`);
  // The subject's table: one of SUBJECTS, as an identifier binding (??), quoted by knex.
  const r = await trx.raw(`
    UPDATE obligarth.notice_acknowledgements a
       SET device_id = COALESCE(s.device_id, a.device_id), end_user_id = COALESCE(s.end_user_id, a.end_user_id)
      FROM ?? s
     WHERE s.tenant_id = ? AND s.id = ?::uuid AND s.notice_ack_id IS NOT NULL
       AND a.tenant_id = s.tenant_id AND a.id = s.notice_ack_id
       AND (a.device_id IS DISTINCT FROM COALESCE(s.device_id, a.device_id)
            OR a.end_user_id IS DISTINCT FROM COALESCE(s.end_user_id, a.end_user_id))`, [`obligarth.${subject}`, tenantId, subjectId]) as { rowCount?: number };
  return Number(r.rowCount ?? 0);
}

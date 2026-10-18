import type { Knex } from 'knex';

// =============================================================================
// Wrong codes of an invitation (docs: integration-apple-edge §10.5, lot C2): five wrong codes for an invitation
// revoke it (alert enrollment.invitation_locked). The count is kept on the invitation itself
// (enrollment_tokens.failed_attempts): an employee's web view (GET/POST /t/<key>/byod/auth) names the Managed
// Apple Account, whose live invitations each count a wrong code; a right code presented with another account
// counts on its own invitation. A link (OTA) never counts one.
// No table, no function, no policy: the classification of the RLS is unchanged. Runs as obligarth_owner
// (server-migrate), after retention_indexes; ends with obligarth.rls_assert_clean(). No question mark in the SQL
// (knex.raw would bind it); kept verbatim by String.raw.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Wrong codes of an invitation (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.enrollment_tokens') IS NULL THEN
    RAISE EXCEPTION 'enrollment_invitation_attempts: apply apple_enrollment first';
  END IF;
END $$;

ALTER TABLE obligarth.enrollment_tokens
  ADD COLUMN failed_attempts integer NOT NULL DEFAULT 0,
  ADD CONSTRAINT enrollment_tokens_failed_attempts_check CHECK (failed_attempts BETWEEN 0 AND 1000);

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}

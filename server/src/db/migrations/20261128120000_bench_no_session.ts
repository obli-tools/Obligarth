import type { Knex } from 'knex';

// =============================================================================
// The bench without a session (decision of the owners of 28/11/2026)
// =============================================================================
//   The bench session disappears: an APPROVED station (not suspended, not revoked) issues the enrollment tokens of its
//   provisionings by itself, within its targets. Its actor is the station (i:bench-station:<id>), not a user:
//   a) legacy_agent_enrollment_tokens.created_by may be NULL for a token of origin 'bench' only (a token of the console
//      keeps its creator): legacy_agent_tokens_created_by_check.
//   b) legacy_agent_tokens_revoked: a revoked token names who revoked it, except a bench token without a creator (its
//      revocation by the station, the abandonment of its provisioning, the archive of its site that names the creator
//      of the token, bench/enrollment.ts on an identity mismatch): revoked_by never without revoked_at.
//   bench_sessions is LEFT IN PLACE, unused: bench_station_lookup, bench_tenant_stations, bench_tenant_owned_stations,
//   bench_owned_station_set and bench_station_revoke_cascade read or close it, bench_provisionings.session_id points to
//   it (history), the job closes and audits its last open rows (8 hours at most); dropping it would rewrite five definer
//   functions for nothing. No row is written there any more (the routes that opened a session are gone).
// Idempotent: DROP NOT NULL is, and each constraint is dropped if it exists before it is added. Rules of the specs
// README §3: SQL by String.raw, no question mark, rls_assert_clean() last, a down that raises. Runs as obligarth_owner
// (server-migrate), after bench_stations and bench_apps.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- The bench without a session (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.legacy_agent_enrollment_tokens') IS NULL OR to_regclass('obligarth.bench_sessions') IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
                     WHERE a.attrelid = 'obligarth.legacy_agent_enrollment_tokens'::regclass AND a.attname = 'origin' AND NOT a.attisdropped) THEN
    RAISE EXCEPTION 'bench_no_session: apply the legacy_agent and bench_stations migrations first';
  END IF;
END $$;

ALTER TABLE obligarth.legacy_agent_enrollment_tokens
  ALTER COLUMN created_by DROP NOT NULL,
  DROP CONSTRAINT IF EXISTS legacy_agent_tokens_created_by_check,
  DROP CONSTRAINT IF EXISTS legacy_agent_tokens_revoked,
  -- a) a token of the console keeps its creator; a token of a station may have none (the station issues it).
  ADD CONSTRAINT legacy_agent_tokens_created_by_check CHECK (origin = 'bench' OR created_by IS NOT NULL),
  -- b) revoked_by only on a revoked token; a revoked token names who revoked it, but a bench token without a creator.
  ADD CONSTRAINT legacy_agent_tokens_revoked CHECK ((revoked_by IS NULL OR revoked_at IS NOT NULL)
    AND (revoked_at IS NULL OR revoked_by IS NOT NULL OR (origin = 'bench' AND created_by IS NULL)));

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('bench_no_session cannot be rolled back: restore the backup taken before the upgrade');
}

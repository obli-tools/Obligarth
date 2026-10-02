import type { Knex } from 'knex';

// Durable jobs, lot 2 (docs: file-durable §7, §8.5): the outbox dead letters seen by the platform administrators.
//   - apple_edge_dead_letters (class custom, migration C block C.11) is written by the consumer and its jobs
//     (policy rls_job: context 'none', job actor). A platform administrator of the master tenant discards
//     one from the administration API (DELETE /api/admin/outbox/dead-letters/:eventId) through
//     obligarth.outbox_dead_letter_discard(), which checks the context (master tenant, active platform
//     administrator as the actor) whatever the route does, deletes that row only and returns what the audit
//     entry names (type, reason, tenant), never the payload.
//   - reads stay those of migration C: the dead letters of a tenant in its context, every one of them in the
//     context 'platform' under a journaled grant (the administration API), the consumer's in 'none'.
// Runs as obligarth_owner (server-migrate), after the migrations of lot A; ends with
// obligarth.rls_assert_clean(). The SQL holds no question mark (knex.raw would bind it) and is kept verbatim
// by String.raw.
const UP = String.raw`-- =============================================================================
-- Outbox dead letters: discard by a platform administrator of the master tenant.
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.apple_edge_dead_letters') IS NULL
     OR to_regprocedure('obligarth.ctx_actor_is_platform_admin()') IS NULL THEN
    RAISE EXCEPTION 'outbox_admin: apply the migrations jobs and rls_policies first';
  END IF;
END $$;

CREATE FUNCTION obligarth.outbox_dead_letter_discard(p_event_id uuid)
  RETURNS TABLE (event_type text, reason text, tenant_id integer)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_tenant() IS DISTINCT FROM 1 OR NOT obligarth.ctx_actor_is_platform_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'outbox_dead_letter_discard: a platform administrator in the master tenant is required';
  END IF;
  RETURN QUERY
    DELETE FROM obligarth.apple_edge_dead_letters d WHERE d.event_id = p_event_id
    RETURNING d.type::text, d.reason::text, d.tenant_id;
END $$;
REVOKE ALL ON FUNCTION obligarth.outbox_dead_letter_discard(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.outbox_dead_letter_discard(uuid) TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.outbox_dead_letter_discard', 'definer',
   'outbox administration: a platform administrator of the master tenant discards one dead letter')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the migration');
}

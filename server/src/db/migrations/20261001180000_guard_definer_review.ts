import type { Knex } from 'knex';

// Review of lot A8 (hardening): two SECURITY DEFINER functions of the guard (migration guard_foundation,
// audit-durci annex A.2) brought in line with the review of the definer functions of migration D
// (rls-tenant, notes of lot A8, note 10; audit-durci, review of lot A7, AUD-A7-R6). The checks below only
// hold with the signed context (migration D): before it, an injected set_config named any actor and any
// kind. This migration therefore follows D.
//   - obligarth.guard_cooldown_until(user, tenant, kinds) answered in every context, for any account and
//     any tenant (AUD-A7-R6): the end of a user's 72-hour cooldown in a tenant leaked to the context of
//     another tenant. For the runtime role it now answers only in the context of the tenant it is asked
//     about (p_tenant = ctx_tenant()), or in the context 'identity'. Any other context is refused (42501),
//     never answered NULL, which a caller reads as "no cooldown". Both allowed contexts use the role
//     obligarth; the function is granted to obligarth only (guard_foundation), so the read-only role
//     obligarth_reader (contexts member and platform) could not call it anyway, and no caller does: every
//     real caller runs in the tenant of the approval or the request (guard/people.ts, approvals.ts,
//     engine.ts, operations.ts). (The review AUD-A7-R6 also named 'platform'; dropped here because the
//     reader role has no EXECUTE on this function and the global view never reads a cooldown.)
//   - obligarth.guard_actor_recent_tenants(families) evaluated ctx_actor_user() in its WHERE clause, with
//     no index on requested_by: one HMAC per action scanned of the last hour. It now reads it once, as an
//     InitPlan ((SELECT obligarth.ctx_actor_user())).
// Same results otherwise. Runs as obligarth_owner (server-migrate), after guard_foundation and migration D
// in every admitted order (applied last, like any migration an order does not name: essai 121); ends with
// obligarth.rls_assert_clean(). The SQL holds no question mark (knex.raw would bind it) and is kept
// verbatim by String.raw.
const UP = String.raw`-- =============================================================================
-- Review of lot A8: guard definer functions (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $do$
BEGIN
  IF to_regprocedure('obligarth.guard_cooldown_until(integer, integer, text[])') IS NOT NULL THEN
    EXECUTE $f$
CREATE OR REPLACE FUNCTION obligarth.guard_cooldown_until(p_user integer, p_tenant integer, p_kinds text[])
  RETURNS timestamptz
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $b$
DECLARE
  v_ctx  text := obligarth.ctx_raw();
  v_kind text := obligarth.ctx_kind_of(v_ctx);
BEGIN
  -- The runtime role: the tenant of the context only, or the context identity. NULL-safe: a context the
  -- database refused (ctx_raw() NULL) is refused here too, never answered.
  IF session_user = 'obligarth'
     AND NOT (v_kind IS NOT DISTINCT FROM 'identity'
              OR (v_kind IS NOT DISTINCT FROM 'tenant' AND p_tenant IS NOT NULL
                  AND obligarth.ctx_tenant_of(v_ctx) IS NOT DISTINCT FROM p_tenant)) THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = 'guard_cooldown_until: reserved to the context of the tenant asked about, or identity';
  END IF;
  RETURN (SELECT max(g.granted_at) + interval '72 hours'
            FROM obligarth.privilege_grants g
           WHERE g.user_id = p_user AND g.source = 'change' AND g.kind = ANY (p_kinds)
             AND g.granted_at > now() - interval '72 hours'
             AND (g.tenant_id IS NULL OR g.tenant_id = p_tenant));
END $b$;
$f$;
    UPDATE obligarth_private.rls_registry
       SET note = 'end of the 72-hour cooldown of a user in a tenant (context of that tenant, or identity)'
     WHERE object_kind = 'function' AND object_name = 'obligarth.guard_cooldown_until';
  END IF;

  IF to_regprocedure('obligarth.guard_actor_recent_tenants(text[])') IS NOT NULL THEN
    EXECUTE $f$
CREATE OR REPLACE FUNCTION obligarth.guard_actor_recent_tenants(p_families text[])
  RETURNS integer
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $b$
  SELECT count(DISTINCT a.tenant_id)::integer
    FROM obligarth.pending_actions a
   WHERE a.requested_by = (SELECT obligarth.ctx_actor_user()) AND a.family = ANY (p_families)
     AND a.created_at > now() - interval '1 hour'
$b$;
$f$;
  END IF;
END $do$;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the migration');
}

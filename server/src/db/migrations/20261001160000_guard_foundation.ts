import type { Knex } from 'knex';

// Guards against mass erasure (PLT-11, D23-D24; docs: audit-durci annex A.2): guard settings and emergency
// freeze of a tenant, approvers designated per tenant, guarded actions (requested, approved, delayed,
// cancellable, revalidated at execution), privilege grants recorded by triggers whatever the path (72-hour
// cooldown), the end of a cooldown, the housekeeping of the actions.purge job, and (an addition to the
// annex) the number of tenants where the context's own actor requested guarded actions of some families in
// the last hour (anomaly A3: pending_actions is readable per tenant only).
// The part G.5 of the annex (audience of a role, client permission sets) was applied with the journal
// (audit_hardening, block H.12b): left out here. One change to the annex: the first administrator's own
// tenant memberships, granted while no other platform administrator exists, are 'bootstrap' too (the annex
// recorded them as a change, putting the first administrator in cooldown on the master tenant).
// Runs as obligarth_owner (server-migrate), after audit_hardening, and ends with obligarth.rls_assert_clean()
// when rls_policies (C) already ran. The SQL holds no question mark (knex.raw would bind it) and no
// backslash; it is kept verbatim by String.raw.
const UP = String.raw`-- =============================================================================
-- Migration: guard_foundation (PLT-11, D23-D24). Run as obligarth_owner, in one transaction.
-- Needs audit_hardening (and therefore rls_foundation). No question mark anywhere.
-- =============================================================================

DO $$
BEGIN
  IF to_regprocedure('obligarth.audit_append(text)') IS NULL THEN
    RAISE EXCEPTION 'guard_foundation: apply audit_hardening (PLT-12) first';
  END IF;
END $$;

-- G.1 Guard settings of a tenant: hourly cap, side of the approver of mass actions, emergency freeze
CREATE TABLE obligarth.tenant_guard_settings (
  tenant_id          integer      PRIMARY KEY REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  hourly_cap_percent smallint     NOT NULL DEFAULT 10 CHECK (hourly_cap_percent BETWEEN 5 AND 50),
  hourly_cap_min     smallint     NOT NULL DEFAULT 5 CHECK (hourly_cap_min BETWEEN 3 AND 50),
  mass_approver_side varchar(8)   NOT NULL DEFAULT 'client' CHECK (mass_approver_side IN ('client', 'msp')),
  frozen_at          timestamptz,
  frozen_by          integer,
  frozen_source      varchar(16)  CHECK (frozen_source IN ('manual', 'anomaly')),
  frozen_reason      varchar(500),
  updated_by         integer,
  updated_at         timestamptz  NOT NULL DEFAULT now(),
  CHECK ((frozen_at IS NULL) = (frozen_source IS NULL)),
  CHECK (frozen_at IS NULL OR frozen_reason IS NOT NULL)
);

-- G.2 Approvers designated for a tenant (D24): client side or MSP side
CREATE TABLE obligarth.tenant_approvers (
  id            serial      PRIMARY KEY,
  tenant_id     integer     NOT NULL REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  user_id       integer     NOT NULL REFERENCES obligarth.users (id) ON DELETE CASCADE,
  side          varchar(8)  NOT NULL CHECK (side IN ('client', 'msp')),
  designated_by integer     NOT NULL,
  approval_id   integer,
  created_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz,
  revoked_by    integer,
  CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE UNIQUE INDEX tenant_approvers_active ON obligarth.tenant_approvers (tenant_id, user_id) WHERE revoked_at IS NULL;

-- G.3 Guarded actions: requested, approved, delayed, cancellable, revalidated at execution
CREATE TABLE obligarth.pending_actions (
  id                bigserial    PRIMARY KEY,
  uuid              uuid         NOT NULL UNIQUE,
  tenant_id         integer      NOT NULL REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  action_key        varchar(100) NOT NULL,
  family            varchar(32)  NOT NULL,
  state             varchar(20)  NOT NULL CHECK (state IN ('awaiting_approval', 'scheduled', 'paused', 'executing',
                                   'done', 'partial', 'cancelled', 'refused', 'failed', 'expired')),
  requested_by      integer      NOT NULL,
  requester_side    varchar(8)   NOT NULL CHECK (requester_side IN ('msp', 'client')),
  approval_id       integer,
  approved_by       integer,
  approver_side     varchar(8)   CHECK (approver_side IN ('msp', 'client')),
  approver_fallback boolean      NOT NULL DEFAULT false,
  selection         jsonb        NOT NULL,
  target_device_ids integer[]    NOT NULL,
  target_count      integer      NOT NULL CHECK (target_count > 0 AND target_count = cardinality(target_device_ids)),
  params            jsonb        NOT NULL DEFAULT '{}',
  reason            varchar(500) NOT NULL CHECK (length(trim(reason)) >= 5),
  ticket            varchar(64),
  delay_seconds     integer      NOT NULL CHECK (delay_seconds BETWEEN 0 AND 86400),
  execute_after     timestamptz,
  job_id            uuid,
  paused_at         timestamptz,
  cancelled_by      integer,
  cancelled_at      timestamptz,
  cancel_reason     varchar(500),
  executed_at       timestamptz,
  result            jsonb,
  created_at        timestamptz  NOT NULL DEFAULT now(),
  updated_at        timestamptz  NOT NULL DEFAULT now(),
  CHECK (state <> 'scheduled' OR execute_after IS NOT NULL),
  CHECK ((state = 'cancelled') = (cancelled_at IS NOT NULL))
);
CREATE INDEX pending_actions_tenant_state ON obligarth.pending_actions (tenant_id, state, execute_after);
CREATE INDEX pending_actions_tenant_family ON obligarth.pending_actions (tenant_id, family, executed_at);

-- G.4 Privilege grants, recorded by the database whatever the path (cooldown of 72 h)
CREATE TABLE obligarth.privilege_grants (
  id         bigserial   PRIMARY KEY,
  user_id    integer     NOT NULL,
  tenant_id  integer,                                         -- NULL: platform role
  kind       varchar(24) NOT NULL CHECK (kind IN ('platform_admin', 'tenant_admin', 'approver')),
  source     varchar(16) NOT NULL CHECK (source IN ('change', 'bootstrap')),
  granted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX privilege_grants_user ON obligarth.privilege_grants (user_id, granted_at DESC);

-- The first administrator of the instance (no other platform administrator exists) is 'bootstrap', and so are
-- that administrator's own tenant memberships while it is still the only one: no cooldown for the install.
CREATE FUNCTION obligarth_private.record_privilege_grant() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_TABLE_NAME = 'users' THEN
    IF NEW.role = 'admin' AND (TG_OP = 'INSERT' OR OLD.role IS DISTINCT FROM 'admin') THEN
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source)
      VALUES (NEW.id, NULL, 'platform_admin',
              CASE WHEN EXISTS (SELECT 1 FROM obligarth.users u WHERE u.role = 'admin' AND u.id <> NEW.id)
                   THEN 'change' ELSE 'bootstrap' END);
    END IF;
  ELSIF TG_TABLE_NAME = 'user_tenants' THEN
    IF NEW.role = 'admin' AND (TG_OP = 'INSERT' OR OLD.role IS DISTINCT FROM 'admin') THEN
      INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source)
      VALUES (NEW.user_id, NEW.tenant_id, 'tenant_admin',
              CASE WHEN EXISTS (SELECT 1 FROM obligarth.privilege_grants g
                                 WHERE g.user_id = NEW.user_id AND g.kind = 'platform_admin' AND g.source = 'bootstrap')
                        AND NOT EXISTS (SELECT 1 FROM obligarth.users u WHERE u.role = 'admin' AND u.id <> NEW.user_id)
                   THEN 'bootstrap' ELSE 'change' END);
    END IF;
  ELSIF TG_TABLE_NAME = 'tenant_approvers' THEN
    INSERT INTO obligarth.privilege_grants (user_id, tenant_id, kind, source)
    VALUES (NEW.user_id, NEW.tenant_id, 'approver', 'change');
  END IF;
  RETURN NULL;
END $$;

CREATE TRIGGER users_privilege_grant AFTER INSERT OR UPDATE OF role ON obligarth.users
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_privilege_grant();
CREATE TRIGGER user_tenants_privilege_grant AFTER INSERT OR UPDATE OF role ON obligarth.user_tenants
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_privilege_grant();
CREATE TRIGGER tenant_approvers_privilege_grant AFTER INSERT ON obligarth.tenant_approvers
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.record_privilege_grant();

-- End of the cooldown of a user in a tenant (NULL: none). Kinds: what the guard checks.
CREATE FUNCTION obligarth.guard_cooldown_until(p_user integer, p_tenant integer, p_kinds text[])
  RETURNS timestamptz
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT max(g.granted_at) + interval '72 hours'
    FROM obligarth.privilege_grants g
   WHERE g.user_id = p_user AND g.source = 'change' AND g.kind = ANY (p_kinds)
     AND g.granted_at > now() - interval '72 hours'
     AND (g.tenant_id IS NULL OR g.tenant_id = p_tenant)
$$;

-- Anomaly A3 (audit-durci section 10.9): in how many tenants did the actor of the context request
-- guarded actions of these families in the last hour. The actor's own requests only: no parameter
-- names a user, and the answer is a count.
CREATE FUNCTION obligarth.guard_actor_recent_tenants(p_families text[])
  RETURNS integer
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT count(DISTINCT a.tenant_id)::integer
    FROM obligarth.pending_actions a
   WHERE a.requested_by = obligarth.ctx_actor_user() AND a.family = ANY (p_families)
     AND a.created_at > now() - interval '1 hour'
$$;

-- Housekeeping (job actions.purge): finished actions and old grants after 13 months
CREATE FUNCTION obligarth.guard_purge()
  RETURNS TABLE (actions bigint, grants bigint)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_actions bigint;
  v_grants  bigint;
BEGIN
  IF session_user = 'obligarth' AND obligarth.ctx_actor() IS DISTINCT FROM 'j:actions.purge' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'guard_purge: reserved to the actions.purge job';
  END IF;
  DELETE FROM obligarth.pending_actions a
   WHERE a.state IN ('done', 'partial', 'cancelled', 'refused', 'failed', 'expired')
     AND a.updated_at < now() - interval '13 months';
  GET DIAGNOSTICS v_actions = ROW_COUNT;
  DELETE FROM obligarth.privilege_grants g WHERE g.granted_at < now() - interval '13 months';
  GET DIAGNOSTICS v_grants = ROW_COUNT;
  RETURN QUERY SELECT v_actions, v_grants;
END $$;

-- G.5 (audience of a role, client permission sets approver and auditor, audit.read in the admin set):
-- applied by audit_hardening (block H.12b).

-- G.6 Classification and privileges
SELECT obligarth_private.rls_apply('obligarth.tenant_guard_settings', 'tenant', 'guard settings and emergency freeze');
SELECT obligarth_private.rls_apply('obligarth.tenant_approvers', 'tenant', 'approvers designated per tenant (D24)');
SELECT obligarth_private.rls_apply('obligarth.pending_actions', 'tenant', 'guarded actions (PLT-11)');
ALTER TABLE obligarth.tenant_guard_settings ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.tenant_approvers ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
ALTER TABLE obligarth.pending_actions ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
REVOKE DELETE ON obligarth.tenant_approvers, obligarth.pending_actions FROM obligarth;   -- revoked or cancelled, never deleted
SELECT obligarth_private.rls_apply('obligarth.privilege_grants', 'custom', 'written by record_privilege_grant only; read through guard_cooldown_until');
REVOKE ALL ON SEQUENCE obligarth.privilege_grants_id_seq FROM obligarth, obligarth_reader;
CREATE POLICY rls_identity_read ON obligarth.privilege_grants FOR SELECT TO obligarth
  USING ((SELECT obligarth.ctx_kind()) = 'identity');
GRANT SELECT ON obligarth.privilege_grants TO obligarth;

REVOKE ALL ON FUNCTION obligarth_private.record_privilege_grant(), obligarth.guard_cooldown_until(integer, integer, text[]),
  obligarth.guard_actor_recent_tenants(text[]), obligarth.guard_purge() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.guard_cooldown_until(integer, integer, text[]), obligarth.guard_actor_recent_tenants(text[]),
  obligarth.guard_purge() TO obligarth;
INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth_private.record_privilege_grant', 'definer', 'trigger: records admin and approver grants'),
  ('function', 'obligarth.guard_cooldown_until',           'definer', 'end of the 72-hour cooldown of a user in a tenant'),
  ('function', 'obligarth.guard_actor_recent_tenants',     'definer', 'anomaly A3: tenants of the actor''s own recent guarded actions'),
  ('function', 'obligarth.guard_purge',                    'definer', 'actions.purge job: finished actions and grants after 13 months');

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM obligarth_private.rls_registry
             WHERE object_kind = 'table' AND object_name = 'obligarth.tenants') THEN
    PERFORM obligarth.rls_assert_clean();
  END IF;
END $$;
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the migration');
}

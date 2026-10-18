import type { Knex } from 'knex';

// =============================================================================
// Android, part 7: operation of the integration (lot AN-H1; android-amapi §6.5, §13, §22.5)
// =============================================================================
//   - android_reconcile_state (class tenant): the daily reconciliation of a tenant (its slot in the day, the next run,
//     a request of the operator, of a restore or of an absence of the instance, the counts of the last run and the
//     devices Google lists, for the weekly recount of the quota);
//   - android_presumed_gone (class tenant): the devices without a status report for mdmStaleAfterDays (« presumed
//     gone »), proposed to the operator's forget, forgotten automatically at 270 days [NV, RR-11];
//   - android_offboardings (class tenant): the offboarding of a client (section 6.5), step by step, one open per tenant;
//   - android_quota_recounts (class technical: counts of the whole project, no tenant datum): the weekly recount of
//     the quota (AN49), the gap shown on the platform screen;
//   - functions: android_operations_due() (tenants with work for android.maintenance, ids and flags only) and
//     android_quota_census() (counts of the project, numbers only), android_linked_tenants() (ids only).
// New tables and functions only: nothing existing is altered. Runs as obligarth_owner (server-migrate); ends with
// obligarth.rls_assert_clean(). No question mark in the SQL (knex.raw would bind it).

const UP = String.raw`-- =============================================================================
-- Android, part 7: operation (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_devices') IS NULL OR to_regclass('obligarth.android_enterprises') IS NULL THEN
    RAISE EXCEPTION 'android_operations: apply android_enterprises and android_devices first';
  END IF;
END $$;

-- ── android_reconcile_state ─────────────────────────────────────────────────────
CREATE TABLE obligarth.android_reconcile_state (   -- one row per enterprise of the tenant (a new link, a new row)
  id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id         integer NOT NULL DEFAULT obligarth.ctx_tenant()
                      REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_id     integer NOT NULL,
  slot_minute       smallint NOT NULL,                 -- minute of the day of the daily pass (spread by tenant)
  next_due_at       timestamptz NOT NULL DEFAULT now(),
  requested_at      timestamptz,                       -- an extra run asked (operator, absence, restore)
  request_trigger   varchar(12),
  last_started_at   timestamptz,
  last_finished_at  timestamptz,
  last_trigger      varchar(12),
  last_result       jsonb,                             -- counts only (AndroidReconcileResult)
  last_error        varchar(64),
  google_count      integer,                           -- devices Google lists, without those silent for 270 days
  google_stale      integer,                           -- devices Google lists silent for more than 270 days
  counted_at        timestamptz,
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT android_reconcile_state_enterprise_unique UNIQUE (tenant_id, enterprise_id),
  CONSTRAINT android_reconcile_state_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_reconcile_state_slot_check CHECK (slot_minute BETWEEN 0 AND 1439),
  CONSTRAINT android_reconcile_state_trigger_check
    CHECK (request_trigger IS NULL OR request_trigger IN ('operator', 'absence', 'restore')),
  CONSTRAINT android_reconcile_state_requested CHECK ((requested_at IS NULL) = (request_trigger IS NULL)),
  CONSTRAINT android_reconcile_state_last_trigger_check
    CHECK (last_trigger IS NULL OR last_trigger IN ('daily', 'operator', 'absence', 'restore')),
  CONSTRAINT android_reconcile_state_result_object CHECK (last_result IS NULL OR jsonb_typeof(last_result) = 'object'),
  CONSTRAINT android_reconcile_state_counts CHECK ((google_count IS NULL OR google_count >= 0) AND (google_stale IS NULL OR google_stale >= 0))
);
CREATE INDEX android_reconcile_state_due ON obligarth.android_reconcile_state (next_due_at);
SELECT obligarth_private.rls_apply('obligarth.android_reconcile_state', 'tenant', 'android: daily reconciliation of a tenant (lot AN-H1)');

-- ── android_presumed_gone ───────────────────────────────────────────────────────
CREATE TABLE obligarth.android_presumed_gone (
  id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id          integer NOT NULL DEFAULT obligarth.ctx_tenant()
                       REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id          integer NOT NULL,
  since              timestamptz NOT NULL DEFAULT now(),
  last_report_at     timestamptz,                    -- the last report known when marked (enrolled_at if none)
  forget_due_at      timestamptz NOT NULL,           -- last report + 270 days: automatic forget
  state              varchar(12) NOT NULL DEFAULT 'open',
  ended_at           timestamptz,
  forget_attempts    smallint NOT NULL DEFAULT 0,
  next_forget_at     timestamptz,                    -- a forget refused or deferred is tried again from then
  last_forget_error  varchar(64),
  CONSTRAINT android_presumed_gone_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT android_presumed_gone_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_presumed_gone_state_check CHECK (state IN ('open', 'cleared', 'forgotten')),
  CONSTRAINT android_presumed_gone_ended CHECK ((state = 'open') = (ended_at IS NULL)),
  CONSTRAINT android_presumed_gone_attempts CHECK (forget_attempts >= 0)
);
CREATE UNIQUE INDEX android_presumed_gone_open ON obligarth.android_presumed_gone (tenant_id, device_id) WHERE state = 'open';
CREATE INDEX android_presumed_gone_due ON obligarth.android_presumed_gone (forget_due_at) WHERE state = 'open';
SELECT obligarth_private.rls_apply('obligarth.android_presumed_gone', 'tenant', 'android: devices presumed gone (silent disappearances, AN36)');

-- ── android_offboardings ────────────────────────────────────────────────────────
CREATE TABLE obligarth.android_offboardings (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         integer NOT NULL DEFAULT obligarth.ctx_tenant()
                      REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_id     integer NOT NULL,
  step              varchar(16) NOT NULL DEFAULT 'revoking',
  approval_id       integer,                        -- pending_approvals.id of the restricted request
  requested_by      integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  reason            varchar(500) NOT NULL,
  forced_at         timestamptz,
  forced_by         integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  devices_left      integer NOT NULL DEFAULT 0,
  tokens_revoked    integer NOT NULL DEFAULT 0,
  policies_deleted  integer NOT NULL DEFAULT 0,
  policies_kept     integer NOT NULL DEFAULT 0,
  release_failed    boolean NOT NULL DEFAULT false,
  next_run_at       timestamptz NOT NULL DEFAULT now(),
  attempts          smallint NOT NULL DEFAULT 0,
  last_error        varchar(64),
  started_at        timestamptz NOT NULL DEFAULT now(),
  finished_at       timestamptz,
  CONSTRAINT android_offboardings_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT android_offboardings_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_offboardings_step_check CHECK (step IN ('revoking', 'waiting_devices', 'deleting', 'releasing', 'done')),
  CONSTRAINT android_offboardings_finished CHECK ((step = 'done') = (finished_at IS NOT NULL)),
  CONSTRAINT android_offboardings_reason_check CHECK (char_length(reason) BETWEEN 5 AND 500),
  CONSTRAINT android_offboardings_forced CHECK ((forced_at IS NULL) = (forced_by IS NULL)),
  CONSTRAINT android_offboardings_counts CHECK (devices_left >= 0 AND tokens_revoked >= 0 AND policies_deleted >= 0
    AND policies_kept >= 0 AND attempts >= 0)
);
CREATE UNIQUE INDEX android_offboardings_open ON obligarth.android_offboardings (tenant_id) WHERE finished_at IS NULL;
CREATE INDEX android_offboardings_due ON obligarth.android_offboardings (next_run_at) WHERE finished_at IS NULL;
SELECT obligarth_private.rls_apply('obligarth.android_offboardings', 'tenant', 'android: offboarding of a client (section 6.5)');

-- ── android_quota_recounts ──────────────────────────────────────────────────────
CREATE TABLE obligarth.android_quota_recounts (       -- counts of the whole project; no tenant datum
  id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  counted_at       timestamptz NOT NULL DEFAULT now(),
  instance_count   integer NOT NULL,                  -- android_project_device_count()
  google_count     integer NOT NULL,                  -- devices Google lists (linked tenants counted), 270 days excluded
  stale_excluded   integer NOT NULL,                  -- devices Google lists silent for more than 270 days
  gap              integer NOT NULL,                  -- google_count - instance_count
  tenants_linked   integer NOT NULL,
  tenants_counted  integer NOT NULL,
  CONSTRAINT android_quota_recounts_counts CHECK (instance_count >= 0 AND google_count >= 0 AND stale_excluded >= 0
    AND tenants_linked >= 0 AND tenants_counted >= 0 AND tenants_counted <= tenants_linked)
);
SELECT obligarth_private.rls_apply('obligarth.android_quota_recounts', 'technical', 'android (AN49): weekly recount of the quota of the project');
GRANT SELECT, INSERT, DELETE ON obligarth.android_quota_recounts TO obligarth;

-- ── Functions ───────────────────────────────────────────────────────────────────
-- Tenants with operation work for android.maintenance (context 'none'; tenant ids and flags only): a reconciliation
-- due (a linked enterprise without a state row, past its next run, or a run asked; never during an offboarding), a
-- forget due (presumed gone for 270 days without report), an offboarding step due, rows of these tables to purge.
CREATE FUNCTION obligarth.android_operations_due()
  RETURNS TABLE (tenant_id integer, reconcile_due boolean, forget_due boolean, offboarding_due boolean, purge_due boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_operations_due: context none of the maintenance required';
  END IF;
  RETURN QUERY
  WITH o AS (
    SELECT f.tenant_id, f.next_run_at FROM obligarth.android_offboardings f WHERE f.finished_at IS NULL
  ), r AS (
    SELECT e.tenant_id FROM obligarth.android_enterprises e
      LEFT JOIN obligarth.android_reconcile_state s ON s.tenant_id = e.tenant_id AND s.enterprise_id = e.id
     WHERE e.state = 'linked'
       AND (s.id IS NULL OR s.next_due_at <= now() OR s.requested_at IS NOT NULL)
       AND e.tenant_id NOT IN (SELECT o.tenant_id FROM o)
  ), g AS (
    SELECT DISTINCT p.tenant_id FROM obligarth.android_presumed_gone p
     WHERE p.state = 'open' AND p.forget_due_at <= now() AND (p.next_forget_at IS NULL OR p.next_forget_at <= now())
  ), b AS (
    SELECT o.tenant_id FROM o WHERE o.next_run_at <= now()
  ), u AS (
    SELECT DISTINCT p.tenant_id FROM obligarth.android_presumed_gone p
     WHERE p.state <> 'open' AND p.ended_at < now() - interval '400 days'
    UNION
    SELECT DISTINCT f.tenant_id FROM obligarth.android_offboardings f
     WHERE f.finished_at IS NOT NULL AND f.finished_at < now() - interval '400 days'
  )
  SELECT t.id, t.id IN (SELECT r.tenant_id FROM r), t.id IN (SELECT g.tenant_id FROM g), t.id IN (SELECT b.tenant_id FROM b),
         t.id IN (SELECT u.tenant_id FROM u)
    FROM obligarth.tenants t
   WHERE t.id IN (SELECT r.tenant_id FROM r UNION SELECT g.tenant_id FROM g UNION SELECT b.tenant_id FROM b UNION SELECT u.tenant_id FROM u)
   ORDER BY t.id;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_operations_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_operations_due() TO obligarth;

-- Counts of the project for the weekly recount of the quota (AN49): the devices of the instance not released, the
-- devices Google listed at the last reconciliation of each linked tenant counted within 8 days (those silent for more
-- than 270 days excluded and counted apart). Numbers only.
CREATE FUNCTION obligarth.android_quota_census()
  RETURNS TABLE (instance_count integer, google_count integer, stale_excluded integer, tenants_linked integer, tenants_counted integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_quota_census: context none of the maintenance required';
  END IF;
  RETURN QUERY
  SELECT (SELECT count(*)::integer FROM obligarth.android_devices d WHERE d.released_at IS NULL),
         (SELECT COALESCE(sum(s.google_count), 0)::integer FROM obligarth.android_reconcile_state s
            JOIN obligarth.android_enterprises e ON e.tenant_id = s.tenant_id AND e.id = s.enterprise_id AND e.state = 'linked'
           WHERE s.counted_at > now() - interval '8 days'),
         (SELECT COALESCE(sum(s.google_stale), 0)::integer FROM obligarth.android_reconcile_state s
            JOIN obligarth.android_enterprises e ON e.tenant_id = s.tenant_id AND e.id = s.enterprise_id AND e.state = 'linked'
           WHERE s.counted_at > now() - interval '8 days'),
         (SELECT count(*)::integer FROM obligarth.android_enterprises e WHERE e.state = 'linked'),
         (SELECT count(*)::integer FROM obligarth.android_reconcile_state s
            JOIN obligarth.android_enterprises e ON e.tenant_id = s.tenant_id AND e.id = s.enterprise_id AND e.state = 'linked'
           WHERE s.counted_at > now() - interval '8 days');
END $$;
REVOKE ALL ON FUNCTION obligarth.android_quota_census() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_quota_census() TO obligarth;

-- Tenants whose enterprise is linked (context 'none'; tenant ids only): a reconciliation of each after a restore or an
-- absence of the instance.
CREATE FUNCTION obligarth.android_linked_tenants()
  RETURNS TABLE (tenant_id integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_linked_tenants: context none of the maintenance required';
  END IF;
  RETURN QUERY SELECT e.tenant_id FROM obligarth.android_enterprises e WHERE e.state = 'linked' ORDER BY 1;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_linked_tenants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_linked_tenants() TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.android_operations_due', 'definer', 'android maintenance: tenants with operation work (ids and flags)'),
  ('function', 'obligarth.android_quota_census', 'definer', 'android maintenance: counts of the project for the quota recount'),
  ('function', 'obligarth.android_linked_tenants', 'definer', 'android maintenance: tenants whose enterprise is linked (ids)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}

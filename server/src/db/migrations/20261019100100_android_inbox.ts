import type { Knex } from 'knex';

// =============================================================================
// Android, part 2: inbox of the Pub/Sub notifications, platform state, rate limiter
// =============================================================================
//   - android_inbox (class tenant): the notifications pulled from the project's subscription, written in the tenant
//     of their enterprise, applied by the job android.inbox-drain of the tenant;
//   - android_platform_state, android_rate_buckets (class technical: no tenant data; rls_apply grants nothing for
//     this class, hence the explicit grants);
//   - obligarth.android_maintenance_due(): the tenants with due inbox events, stale signups or rows to purge, for
//     the platform job android.maintenance (context 'none'; tenant ids and flags only).
// New tables and functions only. Runs as obligarth_owner (server-migrate); ends with obligarth.rls_assert_clean().
// No question mark in the SQL.

const UP = String.raw`-- =============================================================================
-- Android, part 2: inbox, platform state, rate limiter (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_enterprises') IS NULL THEN
    RAISE EXCEPTION 'android_inbox: apply android_enterprises first';
  END IF;
END $$;

CREATE TABLE obligarth.android_inbox (
  id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id         integer NOT NULL DEFAULT obligarth.ctx_tenant()
                      REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  message_id        varchar(64) NOT NULL,            -- Pub/Sub messageId
  event_type        varchar(48) NOT NULL,            -- amapi.enrollment, amapi.status_report, …, amapi.oversized
  enterprise_name   varchar(128) NOT NULL,           -- every written event names an enterprise of the tenant
  resource_name     varchar(255),                    -- enterprises/{e}/devices/{d} or …/operations/{o}
  published_at      timestamptz NOT NULL,            -- Pub/Sub publishTime
  occurred_at       timestamptz NOT NULL,            -- best time of the resource
  payload           jsonb,                           -- decoded resource, NULL once applied and purged
  payload_bytes     integer NOT NULL,
  state             varchar(12) NOT NULL DEFAULT 'pending',
  attempts          smallint NOT NULL DEFAULT 0,
  next_attempt_at   timestamptz NOT NULL DEFAULT now(),
  last_error        varchar(64),
  applied_at        timestamptz,
  received_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT android_inbox_state_check CHECK (state IN ('pending', 'applied', 'skipped', 'dead')),
  CONSTRAINT android_inbox_payload_size CHECK (payload_bytes >= 0 AND payload_bytes <= 8388608),
  CONSTRAINT android_inbox_enterprise_check CHECK (enterprise_name ~ '^enterprises/[A-Za-z0-9_-]{1,100}$')
);
CREATE UNIQUE INDEX android_inbox_message ON obligarth.android_inbox (tenant_id, message_id);
CREATE INDEX android_inbox_due ON obligarth.android_inbox (tenant_id, occurred_at, id)
  WHERE state = 'pending';
CREATE INDEX android_inbox_resource ON obligarth.android_inbox (tenant_id, resource_name, occurred_at);
CREATE INDEX android_inbox_next ON obligarth.android_inbox (next_attempt_at) WHERE state = 'pending';
SELECT obligarth_private.rls_apply('obligarth.android_inbox', 'tenant', 'android: notifications to apply');

CREATE TABLE obligarth.android_platform_state (        -- one row; no tenant data
  id                       smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  pinned_project_id        varchar(64),
  credential_fingerprint   varchar(64),                  -- private_key_id (vault_key) or principal (adc); never the key
  credential_set_at        timestamptz,
  last_pull_at             timestamptz,
  last_applied_publish_at  timestamptz,
  last_test_message_at     timestamptz,
  updated_at               timestamptz NOT NULL DEFAULT now()
);
SELECT obligarth_private.rls_apply('obligarth.android_platform_state', 'technical', 'android (FND-11): platform state of the AMAPI link');

CREATE TABLE obligarth.android_rate_buckets (          -- 'project' | 'k:<action>:<enterprise>:<resource>'
  bucket        varchar(255) PRIMARY KEY,
  tokens        double precision NOT NULL,
  refreshed_at  timestamptz NOT NULL
);
SELECT obligarth_private.rls_apply('obligarth.android_rate_buckets', 'technical', 'android (FND-11): AMAPI rate limiter');
GRANT SELECT, INSERT, UPDATE ON obligarth.android_platform_state TO obligarth;
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.android_rate_buckets TO obligarth;

-- Tenants with work for android.maintenance: due inbox events, stale signups, rows to purge. Identifiers and
-- flags only.
CREATE FUNCTION obligarth.android_maintenance_due()
  RETURNS TABLE (tenant_id integer, inbox_due boolean, signups_due boolean, purge_due boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_maintenance_due: context none of the maintenance required';
  END IF;
  RETURN QUERY
  WITH i AS (
    SELECT DISTINCT b.tenant_id FROM obligarth.android_inbox b WHERE b.state = 'pending' AND b.next_attempt_at <= now()
  ), s AS (
    SELECT DISTINCT g.tenant_id FROM obligarth.android_signups g
     WHERE (g.state = 'consuming' AND g.consuming_at < now() - interval '10 minutes')
        OR (g.state IN ('requested', 'url_issued') AND g.expires_at <= now())
  ), p AS (
    SELECT DISTINCT b.tenant_id FROM obligarth.android_inbox b
     WHERE (b.state IN ('applied', 'skipped') AND b.payload IS NOT NULL AND b.applied_at < now() - interval '24 hours')
        OR (b.state IN ('applied', 'skipped') AND b.applied_at < now() - interval '7 days')
        OR (b.state = 'dead' AND b.received_at < now() - interval '30 days')
    UNION
    SELECT DISTINCT d.tenant_id FROM obligarth.android_destructive_events d WHERE d.at < now() - interval '2 hours'
    UNION
    SELECT DISTINCT g.tenant_id FROM obligarth.android_signups g
     WHERE g.state IN ('completed', 'failed', 'expired', 'cancelled') AND g.created_at < now() - interval '30 days'
  )
  SELECT t.id, t.id IN (SELECT i.tenant_id FROM i), t.id IN (SELECT s.tenant_id FROM s), t.id IN (SELECT p.tenant_id FROM p)
    FROM obligarth.tenants t
   WHERE t.id IN (SELECT i.tenant_id FROM i UNION SELECT s.tenant_id FROM s UNION SELECT p.tenant_id FROM p)
   ORDER BY t.id;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_maintenance_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_maintenance_due() TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.android_maintenance_due', 'definer', 'android maintenance: tenants with due work (ids and flags)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}

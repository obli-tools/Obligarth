import type { Knex } from 'knex';

// =============================================================================
// Backups of the instance (P0-13 T9, FND-09; decisions D9, D10; M4 of the spec)
// =============================================================================
//   - ops_backup_reports (class technical, the instance): one row per report of the services of the compose profile
//     backup (backup-wal: the WAL stream and its replication slot, every 5 minutes; backup-base: the daily base backup;
//     backup-offsite: the encrypted copy to the S3 storage, every 5 minutes, and its nightly rotation) and, from P0-13
//     T10, of the restore drill and of the verification of a restore. Codes and counters only: detail is a JSON object
//     of 4 KiB at most, never an address with credentials (refused by a CHECK). Written by the role obligarth_backup
//     (db/bootstrap.ts: LOGIN REPLICATION, no other attribute), which may insert and nothing else: it reads no table of
//     the schema, not even this one. A trigger stamps recorded_at with the clock of the database and brings an end in
//     the future back to now: a clock of a backup container ahead never makes a backup look fresh.
//   - obligarth.ops_backup_status(): the last success and the last report of each kind, the failures since the last
//     success, the size of the last success. obligarth.ops_backup_recent(limit): the last reports (1 to 100).
//     Context 'none' of a job actor only (readiness ops.ready, ops.watch, metrics ops.metrics, ops status ops.status).
//   - obligarth.ops_backup_prune(): the reports past their keeping (WAL and offsite 14 days, base and rotation 400 days,
//     drill and verification 1100 days), the last one of each kind and its last success always kept. Actor j:ops.watch.
//   - integration_deadline_items.kind widened with backup_restore_drill (half-yearly restore drill; brick S3:
//     widen_in_check).
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean()
// last. Runs as obligarth_owner (server-migrate), after notices. The grants to obligarth_backup are given here when the
// role exists, and again by every run of server-migrate (bootstrap): a database whose administrator may not create a
// REPLICATION role has no such role, and no backup service.
// =============================================================================

const KINDS = ['base', 'wal', 'offsite', 'prune', 'drill', 'restore_verify'];
const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

const UP = String.raw`-- =============================================================================
-- Backups of the instance: reports, status (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regprocedure('obligarth_private.widen_in_check(regclass, text, text[])') IS NULL
     OR to_regprocedure('obligarth.ctx_kind()') IS NULL
     OR to_regclass('obligarth.integration_deadline_items') IS NULL THEN
    RAISE EXCEPTION 'ops_backups: apply the RLS migrations, apple_tenants and coordination_socle first';
  END IF;
END $$;

-- 1. ops_backup_reports -----------------------------------------------------------------
CREATE TABLE obligarth.ops_backup_reports (
  id               bigserial    NOT NULL,
  kind             varchar(16)  NOT NULL,
  started_at       timestamptz  NOT NULL DEFAULT now(),
  finished_at      timestamptz  NOT NULL DEFAULT now(),
  ok               boolean      NOT NULL,
  bytes            bigint,
  disk_free_bytes  bigint,
  detail           jsonb        NOT NULL DEFAULT '{}'::jsonb,
  recorded_at      timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT ops_backup_reports_pkey PRIMARY KEY (id),
  CONSTRAINT ops_backup_reports_kind_check CHECK (kind IN (${list(KINDS)})),
  CONSTRAINT ops_backup_reports_span_check CHECK (started_at <= finished_at),
  CONSTRAINT ops_backup_reports_bytes_check CHECK (bytes IS NULL OR bytes >= 0),
  CONSTRAINT ops_backup_reports_disk_check CHECK (disk_free_bytes IS NULL OR disk_free_bytes >= 0),
  CONSTRAINT ops_backup_reports_detail_check CHECK (jsonb_typeof(detail) = 'object' AND octet_length(detail::text) <= 4096),
  -- never an address with credentials (scheme://user:password@host)
  CONSTRAINT ops_backup_reports_detail_credentials_check CHECK (detail::text !~* '[a-z][a-z0-9+.-]*://[^/"@[:space:]]*@')
);
CREATE INDEX ops_backup_reports_last ON obligarth.ops_backup_reports (kind, finished_at DESC, id DESC);
CREATE INDEX ops_backup_reports_success ON obligarth.ops_backup_reports (kind, finished_at DESC, id DESC) WHERE ok;
CREATE INDEX ops_backup_reports_failures ON obligarth.ops_backup_reports (kind, id) WHERE NOT ok;
SELECT obligarth_private.rls_apply('obligarth.ops_backup_reports', 'technical',
  'FND-09 reports of the backups (instance); insert by obligarth_backup only, read through ops_backup_status/recent');

-- The clock of the database, never the container's: recorded_at stamped, an end in the future brought back to now.
CREATE FUNCTION obligarth_private.ops_backup_reports_stamp() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  NEW.recorded_at := now();
  IF NEW.finished_at > now() THEN
    NEW.finished_at := now();
  END IF;
  IF NEW.started_at > NEW.finished_at THEN
    NEW.started_at := NEW.finished_at;
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.ops_backup_reports_stamp() FROM PUBLIC;
CREATE TRIGGER ops_backup_reports_stamp BEFORE INSERT ON obligarth.ops_backup_reports
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.ops_backup_reports_stamp();

-- The role of the backup services (db/bootstrap.ts): insert only.
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'obligarth_backup') THEN
    GRANT USAGE ON SCHEMA obligarth TO obligarth_backup;
    GRANT INSERT ON obligarth.ops_backup_reports TO obligarth_backup;
    GRANT USAGE ON SEQUENCE obligarth.ops_backup_reports_id_seq TO obligarth_backup;
  END IF;
END $$;

-- 2. Status, recent reports, prune ----------------------------------------------------------
CREATE FUNCTION obligarth.ops_backup_status()
  RETURNS TABLE (kind text, last_success_at timestamptz, last_report_at timestamptz, last_ok boolean,
                 failures_since_success bigint, last_bytes bigint)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR COALESCE(obligarth.ctx_actor(), '') !~ '^j:' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ops_backup_status: reserved to the jobs of the platform';
  END IF;
  RETURN QUERY
    SELECT k.kind, s.finished_at, l.finished_at, l.ok,
           (SELECT count(*) FROM obligarth.ops_backup_reports f
             WHERE f.kind = k.kind AND NOT f.ok AND f.id > COALESCE(s.id, 0))::bigint,
           s.bytes
      FROM unnest(ARRAY[${list(KINDS)}]::text[]) WITH ORDINALITY AS k(kind, ord)
      LEFT JOIN LATERAL (SELECT r.id, r.finished_at, r.bytes FROM obligarth.ops_backup_reports r
                          WHERE r.kind = k.kind AND r.ok ORDER BY r.finished_at DESC, r.id DESC LIMIT 1) s ON true
      LEFT JOIN LATERAL (SELECT r.finished_at, r.ok FROM obligarth.ops_backup_reports r
                          WHERE r.kind = k.kind ORDER BY r.finished_at DESC, r.id DESC LIMIT 1) l ON true
     ORDER BY k.ord;
END $$;
REVOKE ALL ON FUNCTION obligarth.ops_backup_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ops_backup_status() TO obligarth;
COMMENT ON FUNCTION obligarth.ops_backup_status() IS
  'FND-09: last success and last report of each kind of backup report (context none of a job actor)';

CREATE FUNCTION obligarth.ops_backup_recent(p_limit integer)
  RETURNS TABLE (id bigint, kind text, started_at timestamptz, finished_at timestamptz, ok boolean, bytes bigint,
                 disk_free_bytes bigint, detail jsonb)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR COALESCE(obligarth.ctx_actor(), '') !~ '^j:' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ops_backup_recent: reserved to the jobs of the platform';
  END IF;
  RETURN QUERY
    SELECT r.id, r.kind::text, r.started_at, r.finished_at, r.ok, r.bytes, r.disk_free_bytes, r.detail
      FROM obligarth.ops_backup_reports r
     ORDER BY r.recorded_at DESC, r.id DESC
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 20), 1), 100);
END $$;
REVOKE ALL ON FUNCTION obligarth.ops_backup_recent(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ops_backup_recent(integer) TO obligarth;
COMMENT ON FUNCTION obligarth.ops_backup_recent(integer) IS
  'FND-09: the last backup reports, 1 to 100 (context none of a job actor)';

CREATE FUNCTION obligarth.ops_backup_prune() RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_n integer;
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'j:ops.watch' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'ops_backup_prune: reserved to ops.watch';
  END IF;
  WITH keep AS (
    SELECT DISTINCT ON (r.kind) r.id FROM obligarth.ops_backup_reports r ORDER BY r.kind, r.finished_at DESC, r.id DESC
  ), keep_ok AS (
    SELECT DISTINCT ON (r.kind) r.id FROM obligarth.ops_backup_reports r WHERE r.ok ORDER BY r.kind, r.finished_at DESC, r.id DESC
  )
  DELETE FROM obligarth.ops_backup_reports r
   WHERE r.recorded_at < now() - CASE r.kind WHEN 'wal' THEN interval '14 days'
                                             WHEN 'offsite' THEN interval '14 days'
                                             WHEN 'base' THEN interval '400 days'
                                             WHEN 'prune' THEN interval '400 days'
                                             ELSE interval '1100 days' END
     AND r.id NOT IN (SELECT id FROM keep) AND r.id NOT IN (SELECT id FROM keep_ok);
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END $$;
REVOKE ALL ON FUNCTION obligarth.ops_backup_prune() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.ops_backup_prune() TO obligarth;
COMMENT ON FUNCTION obligarth.ops_backup_prune() IS
  'FND-09: backup reports past their keeping removed, the last of each kind and its last success kept (actor j:ops.watch)';

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.ops_backup_status', 'definer', 'FND-09: last success and last report of each kind (job actors, context none)'),
  ('function', 'obligarth.ops_backup_recent', 'definer', 'FND-09: last backup reports (job actors, context none)'),
  ('function', 'obligarth.ops_backup_prune', 'definer', 'FND-09: keeping of the backup reports (j:ops.watch)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

-- 3. Deadline of the half-yearly restore drill --------------------------------------------------
SELECT obligarth_private.widen_in_check('obligarth.integration_deadline_items', 'integration_deadline_items_kind_check',
  ARRAY['backup_restore_drill']);

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}

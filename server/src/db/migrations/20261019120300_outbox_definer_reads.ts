import type { Knex } from 'knex';

// =============================================================================
// The outbox of apple-edge read through functions guarded by the signed context (decision of the owners of
// 19/10/2026, INT-B1-R9 option B). Until now the runtime role was the grantee of apple_edge_outbox_reader: from the
// context of a tenant (an SQL injection in a request), it read the outbox of every tenant. From this migration on, the
// grantee is the owner role of the brain (EDGE_OUTBOX_READER_GRANTEE = obligarth_owner: compose files, apple-edge's
// default, and apple-edge's migration revokes the reader role from any other member), and the runtime role reads the
// outbox only through these SECURITY DEFINER functions, each checking the context first:
//   - the consumer (context 'none', actor j:apple-edge.outbox-consumer only): edge_outbox_head (the head of the queue,
//     locked FOR UPDATE SKIP LOCKED in the caller's transaction), edge_outbox_load, edge_outbox_due,
//     edge_outbox_mark_consumed (consumed_at only);
//   - the jobs (context 'none', a job actor j:…): edge_outbox_lag (counts only, no tenant data);
//   - a tenant (its context, or a job in 'none'): edge_outbox_pending_enrollments(key), the enrollments of the key with
//     an event not consumed — the key of the tenant of the context only; edge_outbox_event(event_id): an event of the
//     tenant of the context (another tenant's: only that it is another tenant's);
//   - edge_outbox_ready(): is the outbox there and usable by the functions (catalogs only, any context).
// The functions name apple_edge.outbox in their bodies only (PL/pgSQL): they are created whether apple-edge's schema
// exists yet or not. Runs as obligarth_owner (server-migrate), after android_byod_address_attempts; ends with
// obligarth.rls_assert_clean(). No question mark in the SQL (knex.raw would bind it); kept verbatim by String.raw.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Outbox of apple-edge: reads guarded by the signed context (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth.ctx_kind()') IS NULL OR to_regclass('obligarth.apple_edge_inbox_attempts') IS NULL THEN
    RAISE EXCEPTION 'outbox_definer_reads: apply the RLS migrations and jobs first';
  END IF;
END $$;

-- The consumer of the outbox: context 'none', its own job actor.
CREATE FUNCTION obligarth_private.edge_outbox_consumer_only(p_fn text) RETURNS void
  LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR obligarth.ctx_actor() IS DISTINCT FROM 'j:apple-edge.outbox-consumer' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = p_fn || ': reserved to the outbox consumer';
  END IF;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.edge_outbox_consumer_only(text) FROM PUBLIC;

CREATE FUNCTION obligarth.edge_outbox_ready() RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN COALESCE((SELECT has_schema_privilege(n.oid, 'USAGE') AND has_table_privilege(c.oid, 'SELECT')
                          AND has_column_privilege(c.oid, 'consumed_at', 'UPDATE')
                     FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'apple_edge' AND c.relname = 'outbox' AND c.relkind IN ('r', 'p')), false);
END $$;

CREATE FUNCTION obligarth.edge_outbox_head(p_limit integer)
  RETURNS TABLE (seq text, attempts integer, bytes integer)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM obligarth_private.edge_outbox_consumer_only('edge_outbox_head');
  RETURN QUERY
    SELECT o.seq::text, COALESCE(a.attempts, 0)::integer, pg_column_size(o.payload)::integer
      FROM apple_edge.outbox o
      LEFT JOIN obligarth.apple_edge_inbox_attempts a ON a.event_id = o.event_id
     WHERE o.consumed_at IS NULL
       AND (a.next_attempt_at IS NULL OR a.next_attempt_at <= now())
     ORDER BY o.seq
     LIMIT GREATEST(1, LEAST(p_limit, 1000))
       FOR UPDATE OF o SKIP LOCKED;
END $$;

CREATE FUNCTION obligarth.edge_outbox_load(p_seqs bigint[])
  RETURNS TABLE (seq text, event_id text, schema_version integer, scope text, tenant_key text, type text, enrollment_id text,
                 command_uuid text, request_id text, occurred_at timestamptz, payload jsonb)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM obligarth_private.edge_outbox_consumer_only('edge_outbox_load');
  RETURN QUERY
    SELECT o.seq::text, o.event_id::text, o.schema_version::integer, o.scope, o.tenant_key, o.type, o.enrollment_id,
           o.command_uuid, o.request_id, o.occurred_at, o.payload
      FROM apple_edge.outbox o
     WHERE o.seq = ANY (p_seqs);
END $$;

CREATE FUNCTION obligarth.edge_outbox_due() RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM obligarth_private.edge_outbox_consumer_only('edge_outbox_due');
  RETURN EXISTS (
    SELECT 1 FROM apple_edge.outbox o
      LEFT JOIN obligarth.apple_edge_inbox_attempts a ON a.event_id = o.event_id
     WHERE o.consumed_at IS NULL AND (a.next_attempt_at IS NULL OR a.next_attempt_at <= now()));
END $$;

CREATE FUNCTION obligarth.edge_outbox_mark_consumed(p_seqs bigint[]) RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_count integer;
BEGIN
  PERFORM obligarth_private.edge_outbox_consumer_only('edge_outbox_mark_consumed');
  UPDATE apple_edge.outbox SET consumed_at = now() WHERE seq = ANY (p_seqs) AND consumed_at IS NULL;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END $$;

CREATE FUNCTION obligarth.edge_outbox_lag()
  RETURNS TABLE (pending integer, retrying integer, oldest double precision)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none' OR COALESCE(obligarth.ctx_actor(), '') !~ '^j:' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'edge_outbox_lag: reserved to the jobs';
  END IF;
  RETURN QUERY
    SELECT (count(*) FILTER (WHERE a.event_id IS NULL))::integer,
           (count(*) FILTER (WHERE a.event_id IS NOT NULL))::integer,
           extract(epoch FROM now() - min(o.occurred_at) FILTER (WHERE a.event_id IS NULL))::double precision
      FROM apple_edge.outbox o
      LEFT JOIN obligarth.apple_edge_inbox_attempts a ON a.event_id = o.event_id
     WHERE o.consumed_at IS NULL;
END $$;

-- The key a request may name: the key of the tenant of the context; a job in 'none' may name any key.
CREATE FUNCTION obligarth_private.edge_outbox_key_allowed(p_fn text, p_key text) RETURNS void
  LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_tenant integer := obligarth.ctx_tenant();
BEGIN
  IF v_tenant IS NULL THEN
    IF obligarth.ctx_kind() = 'none' AND COALESCE(obligarth.ctx_actor(), '') ~ '^j:' THEN
      RETURN;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = p_fn || ': the context of a tenant or of a job is required';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM obligarth.tenants t WHERE t.id = v_tenant AND t.mdm_key = p_key) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = p_fn || ': not the key of the tenant of the context';
  END IF;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.edge_outbox_key_allowed(text, text) FROM PUBLIC;

CREATE FUNCTION obligarth.edge_outbox_pending_enrollments(p_key text) RETURNS SETOF text
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM obligarth_private.edge_outbox_key_allowed('edge_outbox_pending_enrollments', p_key);
  RETURN QUERY
    SELECT DISTINCT o.enrollment_id FROM apple_edge.outbox o
     WHERE o.consumed_at IS NULL AND o.tenant_key = p_key AND o.enrollment_id IS NOT NULL;
END $$;

-- An event of the tenant of the context; another tenant's (or a platform event): {"other_tenant": true}, nothing else.
CREATE FUNCTION obligarth.edge_outbox_event(p_event_id uuid) RETURNS jsonb
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_tenant integer := obligarth.ctx_tenant();
  v_key text;
  v_row record;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'edge_outbox_event: the context of a tenant is required';
  END IF;
  SELECT t.mdm_key INTO v_key FROM obligarth.tenants t WHERE t.id = v_tenant;
  SELECT o.tenant_key, o.enrollment_id, o.type, o.payload #>> '{identity,cert_sha256}' AS cert_sha256 INTO v_row
    FROM apple_edge.outbox o WHERE o.event_id = p_event_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF v_key IS NULL OR v_row.tenant_key IS DISTINCT FROM v_key THEN
    RETURN jsonb_build_object('other_tenant', true);
  END IF;
  RETURN jsonb_build_object('tenant_key', v_row.tenant_key, 'enrollment_id', v_row.enrollment_id, 'type', v_row.type,
                            'cert_sha256', v_row.cert_sha256);
END $$;

DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY['obligarth.edge_outbox_ready()', 'obligarth.edge_outbox_head(integer)', 'obligarth.edge_outbox_load(bigint[])',
    'obligarth.edge_outbox_due()', 'obligarth.edge_outbox_mark_consumed(bigint[])', 'obligarth.edge_outbox_lag()',
    'obligarth.edge_outbox_pending_enrollments(text)', 'obligarth.edge_outbox_event(uuid)'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO obligarth', f);
  END LOOP;
END $$;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.edge_outbox_ready', 'definer', 'outbox of apple-edge: present and usable (catalogs only)'),
  ('function', 'obligarth.edge_outbox_head', 'definer', 'outbox of apple-edge: head of the queue, locked; the consumer only (INT-B1-R9)'),
  ('function', 'obligarth.edge_outbox_load', 'definer', 'outbox of apple-edge: events by seq; the consumer only (INT-B1-R9)'),
  ('function', 'obligarth.edge_outbox_due', 'definer', 'outbox of apple-edge: an event due; the consumer only (INT-B1-R9)'),
  ('function', 'obligarth.edge_outbox_mark_consumed', 'definer', 'outbox of apple-edge: consumed_at only; the consumer only (INT-B1-R9)'),
  ('function', 'obligarth.edge_outbox_lag', 'definer', 'outbox of apple-edge: counts of the lag; the jobs only (INT-B1-R9)'),
  ('function', 'obligarth.edge_outbox_pending_enrollments', 'definer',
   'outbox of apple-edge: enrollments of the key of the tenant of the context with an event pending (INT-B1-R9)'),
  ('function', 'obligarth.edge_outbox_event', 'definer', 'outbox of apple-edge: an event of the tenant of the context (INT-B1-R9)')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}

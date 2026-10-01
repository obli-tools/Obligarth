import type { Knex } from 'knex';

// Hardened audit journal (PLT-12, docs: audit-durci annex A.1): append-only through obligarth.audit_append,
// one hash chain per tenant (heads, anchors), no foreign key any more (an entry outlives its tenant, its
// device and its author), retention per tenant, seals over a Merkle tree of the chain heads, SIEM
// destinations and cursors, verification results; app_config.instance_id; the inherited audit.clear key
// leaves the matrices. Also the part G.5 of guard_foundation (audience of a role, client permission sets
// approver and auditor, audit.read in the admin set), needed by the delegated reading of the journal
// (audit-durci section 12.4, step 3); guard_foundation (lot A7) leaves it out.
// Runs as obligarth_owner (server-migrate), after rls_foundation, and ends with obligarth.rls_assert_clean()
// when rls_policies (C) already ran. The SQL holds no question mark (knex.raw would bind it) and no
// backslash; it is kept verbatim by String.raw.
const UP = String.raw`-- =============================================================================
-- Migration: audit_hardening (PLT-12). Run as obligarth_owner, in one transaction.
-- Needs rls_foundation (FND-08, migration A). Works before or after rls_integrity (B)
-- and rls_policies (C). No question mark anywhere (knex.raw would bind it).
-- =============================================================================

-- H.0 Preconditions
DO $$
BEGIN
  IF to_regprocedure('obligarth.ctx_tenant()') IS NULL
     OR to_regprocedure('obligarth_private.rls_apply(regclass,text,text)') IS NULL THEN
    RAISE EXCEPTION 'audit_hardening: apply rls_foundation (FND-08, migration A) first';
  END IF;
  IF current_setting('server_encoding') <> 'UTF8' THEN
    RAISE EXCEPTION 'audit_hardening: the database encoding must be UTF8';
  END IF;
END $$;

-- H.1 Hash of a chain link: SHA-256(previous hash || sequence on 8 bytes, big-endian || body in UTF-8)
CREATE FUNCTION obligarth.audit_link_hash(p_prev bytea, p_seq bigint, p_body text) RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT sha256(p_prev || int8send(p_seq) || convert_to(p_body, 'UTF8'))
$$;

-- H.2 Chain heads and anchors: one row per tenant chain, no foreign key (a chain outlives its tenant)
CREATE TABLE obligarth.audit_chain_heads (
  tenant_id        integer     PRIMARY KEY CHECK (tenant_id > 0),
  last_seq         bigint      NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  last_hash        bytea       NOT NULL DEFAULT decode(repeat('00', 32), 'hex') CHECK (length(last_hash) = 32),
  last_appended_at timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE obligarth.audit_chain_anchors (
  tenant_id   integer     PRIMARY KEY CHECK (tenant_id > 0),
  anchor_seq  bigint      NOT NULL CHECK (anchor_seq > 0),
  anchor_hash bytea       NOT NULL CHECK (length(anchor_hash) = 32),
  purged_at   timestamptz NOT NULL DEFAULT now()
);

-- H.3 audit_logs: no foreign key any more (an entry outlives its tenant, its device and its author),
-- chain columns, canonical body, projections of the body
ALTER TABLE obligarth.audit_logs DROP CONSTRAINT IF EXISTS audit_logs_tenant_id_foreign;
ALTER TABLE obligarth.audit_logs DROP CONSTRAINT IF EXISTS audit_logs_user_id_foreign;
ALTER TABLE obligarth.audit_logs DROP CONSTRAINT IF EXISTS audit_logs_device_id_foreign;
ALTER TABLE obligarth.audit_logs DROP CONSTRAINT IF EXISTS audit_logs_device_id_tenant_fk;   -- rls_integrity (B), if applied
ALTER TABLE obligarth.audit_logs ALTER COLUMN tenant_id DROP DEFAULT;                     -- B's default: the body decides
ALTER TABLE obligarth.audit_logs ALTER COLUMN created_at DROP DEFAULT;                    -- set by audit_append (clock_timestamp)
ALTER TABLE obligarth.audit_logs ALTER COLUMN id TYPE bigint;
ALTER SEQUENCE obligarth.audit_logs_id_seq AS bigint MAXVALUE 9223372036854775807;
ALTER TABLE obligarth.audit_logs
  ADD COLUMN chain_seq              bigint,
  ADD COLUMN prev_hash              bytea,
  ADD COLUMN hash                   bytea,
  ADD COLUMN body                   text,
  ADD COLUMN uuid                   uuid,
  ADD COLUMN occurred_at            timestamptz,
  ADD COLUMN schema_version         smallint,
  ADD COLUMN outcome                varchar(16),
  ADD COLUMN criticality            varchar(12),
  ADD COLUMN actor_type             varchar(16),
  ADD COLUMN actor_ref              varchar(66),
  ADD COLUMN actor_label            varchar(100),
  ADD COLUMN actor_side             varchar(8),
  ADD COLUMN actor_home_tenant_id   integer,
  ADD COLUMN on_behalf_of_tenant_id integer,
  ADD COLUMN target_count           integer,
  ADD COLUMN user_agent             varchar(300),
  ADD COLUMN request_id             varchar(64),
  ADD COLUMN session_ref            varchar(64),
  ADD COLUMN reason                 varchar(500),
  ADD COLUMN ticket                 varchar(64),
  ADD COLUMN approval_ids           integer[],
  ADD COLUMN is_legacy              boolean NOT NULL DEFAULT false;

-- H.4 Rows written before this migration: a body rebuilt from their columns, chained tenant by
-- tenant in id order. Their bodies are in PostgreSQL's jsonb text form: verification hashes the
-- stored body as it is and never re-serializes it.
DO $$
DECLARE
  r      record;
  v_cur  integer := NULL;
  v_prev bytea;
  v_seq  bigint;
  v_body text;
BEGIN
  FOR r IN SELECT * FROM obligarth.audit_logs ORDER BY tenant_id, id LOOP
    IF v_cur IS DISTINCT FROM r.tenant_id THEN
      v_cur := r.tenant_id; v_prev := decode(repeat('00', 32), 'hex'); v_seq := 0;
    END IF;
    v_seq := v_seq + 1;
    v_body := jsonb_strip_nulls(jsonb_build_object(
      'v', 1, 'id', gen_random_uuid(), 'legacy', true,
      'ts', to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'tenant', r.tenant_id, 'action', r.action, 'outcome', 'success', 'crit', 'standard',
      'actor', jsonb_build_object(
        'type', CASE WHEN r.user_id IS NULL THEN 'job' ELSE 'user' END,
        'ref',  CASE WHEN r.user_id IS NULL THEN 'j:legacy' ELSE 'u:' || r.user_id END,
        'side', 'unknown'),
      'target', CASE WHEN r.resource_type IS NULL AND r.device_id IS NULL THEN NULL
                     ELSE jsonb_strip_nulls(jsonb_build_object(
                       'type', COALESCE(r.resource_type, 'device'),
                       'id', COALESCE(r.resource_path, r.device_id::text),
                       'device', r.device_id)) END,
      'origin', CASE WHEN r.ip_address IS NULL THEN NULL ELSE jsonb_build_object('ip', r.ip_address) END,
      'details', r.details))::text;
    UPDATE obligarth.audit_logs l
       SET chain_seq = v_seq, prev_hash = v_prev, body = v_body,
           hash = obligarth.audit_link_hash(v_prev, v_seq, v_body), is_legacy = true
     WHERE l.id = r.id;
    v_prev := obligarth.audit_link_hash(v_prev, v_seq, v_body);
  END LOOP;
END $$;

UPDATE obligarth.audit_logs l SET
  uuid = (l.body::jsonb ->> 'id')::uuid, occurred_at = l.created_at, schema_version = 1,
  outcome = 'success', criticality = 'standard',
  actor_type = l.body::jsonb #>> '{actor,type}', actor_ref = l.body::jsonb #>> '{actor,ref}', actor_side = 'unknown'
WHERE l.is_legacy;

INSERT INTO obligarth.audit_chain_heads (tenant_id, last_seq, last_hash, last_appended_at)
SELECT DISTINCT ON (l.tenant_id) l.tenant_id, l.chain_seq, l.hash, l.created_at
  FROM obligarth.audit_logs l ORDER BY l.tenant_id, l.chain_seq DESC;

ALTER TABLE obligarth.audit_logs
  ALTER COLUMN chain_seq SET NOT NULL, ALTER COLUMN prev_hash SET NOT NULL, ALTER COLUMN hash SET NOT NULL,
  ALTER COLUMN body SET NOT NULL, ALTER COLUMN uuid SET NOT NULL, ALTER COLUMN occurred_at SET NOT NULL,
  ALTER COLUMN schema_version SET NOT NULL, ALTER COLUMN outcome SET NOT NULL, ALTER COLUMN criticality SET NOT NULL,
  ALTER COLUMN actor_type SET NOT NULL, ALTER COLUMN actor_ref SET NOT NULL, ALTER COLUMN actor_side SET NOT NULL;

ALTER TABLE obligarth.audit_logs
  ADD CONSTRAINT audit_logs_chain_uq UNIQUE (tenant_id, chain_seq),
  ADD CONSTRAINT audit_logs_uuid_uq UNIQUE (uuid),
  ADD CONSTRAINT audit_logs_chain_seq_check CHECK (chain_seq > 0),
  ADD CONSTRAINT audit_logs_hash_check CHECK (length(hash) = 32 AND length(prev_hash) = 32),
  ADD CONSTRAINT audit_logs_body_check CHECK (octet_length(body) <= 32768),
  ADD CONSTRAINT audit_logs_outcome_check CHECK (outcome IN ('success', 'failure', 'denied', 'requested', 'scheduled', 'cancelled')),
  ADD CONSTRAINT audit_logs_criticality_check CHECK (criticality IN ('critical', 'protective', 'standard')),
  ADD CONSTRAINT audit_logs_actor_type_check CHECK (actor_type IN ('user', 'job', 'integration', 'enrollment', 'anonymous')),
  ADD CONSTRAINT audit_logs_actor_side_check CHECK (actor_side IN ('msp', 'client', 'system', 'unknown'));

DROP INDEX obligarth.idx_audit_logs_tenant;
DROP INDEX obligarth.idx_audit_logs_device;
DROP INDEX obligarth.idx_audit_logs_action;
DROP INDEX obligarth.idx_audit_logs_created;
CREATE INDEX audit_logs_tenant_created ON obligarth.audit_logs (tenant_id, created_at);
CREATE INDEX audit_logs_tenant_action ON obligarth.audit_logs (tenant_id, action);
CREATE INDEX audit_logs_tenant_device ON obligarth.audit_logs (tenant_id, device_id) WHERE device_id IS NOT NULL;
CREATE INDEX audit_logs_tenant_user ON obligarth.audit_logs (tenant_id, user_id) WHERE user_id IS NOT NULL;
CREATE INDEX audit_logs_created ON obligarth.audit_logs (created_at);

-- H.5 Append-only, even for the owner: UPDATE and TRUNCATE always refused; DELETE only inside
-- obligarth.audit_purge (owner and transaction flag). A superuser can still disable triggers:
-- the seals and the external copy are what detect it.
CREATE FUNCTION obligarth_private.audit_logs_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_user = 'obligarth_owner'
     AND current_setting('obligarth.audit_purge', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION USING ERRCODE = '42501',
    MESSAGE = format('audit_logs is append-only: %s refused', TG_OP);
END $$;

CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON obligarth.audit_logs
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.audit_logs_guard();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON obligarth.audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION obligarth_private.audit_logs_guard();

-- H.6 Append: validation, chain, projections. The internal function trusts its caller (owner only);
-- obligarth.audit_append adds the context rules of the runtime role.
CREATE FUNCTION obligarth_private.audit_append_internal(p_body text)
  RETURNS TABLE (entry_id bigint, entry_seq bigint, entry_hash text, appended_at timestamptz)
  LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  b           jsonb;
  v_tenant    integer;
  v_last_seq  bigint;
  v_last_hash bytea;
  v_seq       bigint;
  v_hash      bytea;
  v_id        bigint;
  v_now       timestamptz := clock_timestamp();
  v_device    text;
  v_approvals integer[];
BEGIN
  IF p_body IS NULL OR octet_length(p_body) > 32768 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit: body missing or larger than 32 KiB';
  END IF;
  b := p_body::jsonb;
  IF jsonb_typeof(b) <> 'object' OR (b ->> 'v') IS DISTINCT FROM '1' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit: body is not a version 1 object';
  END IF;
  IF COALESCE(b ->> 'id', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR COALESCE(b ->> 'ts', '') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$'
     OR jsonb_typeof(b -> 'tenant') IS DISTINCT FROM 'number' OR (b ->> 'tenant') !~ '^[1-9][0-9]{0,9}$'
     OR COALESCE(b ->> 'action', '') !~ '^[a-z][a-z0-9_]*([.][a-z0-9_]+){1,4}$' OR length(b ->> 'action') > 100
     OR COALESCE(b ->> 'outcome', '') NOT IN ('success', 'failure', 'denied', 'requested', 'scheduled', 'cancelled')
     OR COALESCE(b ->> 'crit', '') NOT IN ('critical', 'protective', 'standard')
     OR COALESCE(b #>> '{actor,type}', '') NOT IN ('user', 'job', 'integration', 'enrollment', 'anonymous')
     OR COALESCE(b #>> '{actor,ref}', '') !~ '^[ujiea]:[A-Za-z0-9._:-]{1,64}$'
     OR COALESCE(b #>> '{actor,side}', '') NOT IN ('msp', 'client', 'system', 'unknown') THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit: missing or malformed envelope field';
  END IF;
  v_device := b #>> '{target,device}';
  IF v_device IS NOT NULL AND v_device !~ '^[1-9][0-9]{0,9}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit: malformed target.device';
  END IF;
  IF b -> 'approvals' IS NOT NULL THEN
    IF jsonb_typeof(b -> 'approvals') <> 'array' OR EXISTS (
         SELECT 1 FROM jsonb_array_elements(b -> 'approvals') e
         WHERE jsonb_typeof(e) <> 'number' OR e::text !~ '^[1-9][0-9]{0,9}$') THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit: malformed approvals';
    END IF;
    v_approvals := ARRAY(SELECT e::text::integer FROM jsonb_array_elements(b -> 'approvals') e);
  END IF;
  v_tenant := (b ->> 'tenant')::integer;

  -- the chain head of the tenant: created at first use, then locked until the end of the transaction
  INSERT INTO obligarth.audit_chain_heads AS h (tenant_id) VALUES (v_tenant) ON CONFLICT (tenant_id) DO NOTHING;
  SELECT h.last_seq, h.last_hash INTO v_last_seq, v_last_hash
    FROM obligarth.audit_chain_heads h WHERE h.tenant_id = v_tenant FOR UPDATE;
  v_seq  := v_last_seq + 1;
  v_hash := obligarth.audit_link_hash(v_last_hash, v_seq, p_body);

  INSERT INTO obligarth.audit_logs AS l (
    tenant_id, chain_seq, prev_hash, hash, body, uuid, occurred_at, created_at, schema_version,
    action, outcome, criticality, actor_type, actor_ref, actor_label, actor_side, user_id,
    actor_home_tenant_id, on_behalf_of_tenant_id, device_id, resource_type, resource_path, target_count,
    details, ip_address, user_agent, request_id, session_ref, reason, ticket, approval_ids)
  VALUES (
    v_tenant, v_seq, v_last_hash, v_hash, p_body, (b ->> 'id')::uuid, (b ->> 'ts')::timestamptz, v_now, 1,
    b ->> 'action', b ->> 'outcome', b ->> 'crit', b #>> '{actor,type}', b #>> '{actor,ref}',
    left(b #>> '{actor,label}', 100), b #>> '{actor,side}',
    CASE WHEN (b #>> '{actor,ref}') ~ '^u:[0-9]{1,9}$' THEN substr(b #>> '{actor,ref}', 3)::integer END,
    CASE WHEN (b #>> '{actor,homeTenant}') ~ '^[1-9][0-9]{0,9}$' THEN (b #>> '{actor,homeTenant}')::integer END,
    CASE WHEN (b ->> 'onBehalfOf') ~ '^[1-9][0-9]{0,9}$' THEN (b ->> 'onBehalfOf')::integer END,
    v_device::integer, left(b #>> '{target,type}', 50), b #>> '{target,id}',
    CASE WHEN (b #>> '{targets,count}') ~ '^[0-9]{1,9}$' THEN (b #>> '{targets,count}')::integer END,
    b -> 'details', left(b #>> '{origin,ip}', 45), left(b #>> '{origin,ua}', 300),
    left(b #>> '{origin,requestId}', 64), left(b #>> '{actor,session}', 64),
    left(b ->> 'reason', 500), left(b ->> 'ticket', 64), v_approvals)
  RETURNING l.id INTO v_id;

  UPDATE obligarth.audit_chain_heads h
     SET last_seq = v_seq, last_hash = v_hash, last_appended_at = v_now
   WHERE h.tenant_id = v_tenant;
  PERFORM pg_notify('obligarth_audit', v_tenant::text);   -- delivered at commit, once per transaction
  RETURN QUERY SELECT v_id, v_seq, encode(v_hash, 'hex'), v_now;
END $$;

CREATE FUNCTION obligarth.audit_append(p_body text)
  RETURNS TABLE (entry_id bigint, entry_seq bigint, entry_hash text, appended_at timestamptz)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '5s' AS $$
DECLARE
  b        jsonb;
  v_tenant integer;
  v_ts     timestamptz;
  v_now    timestamptz := clock_timestamp();
BEGIN
  IF session_user = 'obligarth' THEN          -- the runtime role; administration connections are trusted
    b := p_body::jsonb;
    IF (b ->> 'tenant') !~ '^[1-9][0-9]{0,9}$' THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_append: malformed tenant';
    END IF;
    v_tenant := (b ->> 'tenant')::integer;
    -- NULL-safe: outside a 'tenant' context ctx_tenant() is NULL, and a bare
    -- comparison would let any chain through.
    IF NOT (v_tenant IS NOT DISTINCT FROM obligarth.ctx_tenant()
            OR (v_tenant = 1 AND COALESCE(obligarth.ctx_kind(), '') IN ('identity', 'none'))) THEN
      RAISE EXCEPTION USING ERRCODE = '42501',
        MESSAGE = 'audit_append: the entry''s tenant is outside the database context';
    END IF;
    IF COALESCE(b ->> 'ts', '') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$' THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_append: malformed ts';
    END IF;
    v_ts := (b ->> 'ts')::timestamptz;
    IF (b -> 'late') IS NULL
       AND (v_ts < v_now - interval '5 minutes' OR v_ts > v_now + interval '1 minute') THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_append: ts outside [now - 5 min, now + 1 min]';
    END IF;
    IF (b -> 'late') IS NOT NULL
       AND (v_ts < v_now - interval '7 days' OR v_ts > v_now + interval '1 minute') THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_append: late entry older than 7 days';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM obligarth.tenants t WHERE t.id = v_tenant) THEN
      RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'audit_append: unknown tenant';
    END IF;
  END IF;
  RETURN QUERY SELECT * FROM obligarth_private.audit_append_internal(p_body);
END $$;

-- H.7 Retention (D25): 12 months by default, 6 to 36 with a justification; a decrease takes effect
-- after 30 days; legal hold. No foreign key: the setting outlives the tenant, like its chain.
CREATE TABLE obligarth.audit_retention (
  tenant_id            integer     PRIMARY KEY CHECK (tenant_id > 0),
  months               smallint    NOT NULL DEFAULT 12 CHECK (months BETWEEN 6 AND 36),
  justification        varchar(1000) CHECK (justification IS NULL OR length(justification) >= 10),
  effective_months     smallint    NOT NULL DEFAULT 12 CHECK (effective_months BETWEEN 6 AND 36),
  pending_months       smallint    CHECK (pending_months BETWEEN 6 AND 36),
  pending_effective_at timestamptz,
  legal_hold_until     timestamptz,
  legal_hold_reason    varchar(500),
  updated_by           integer,
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CHECK (months = 12 OR justification IS NOT NULL),
  CHECK ((pending_months IS NULL) = (pending_effective_at IS NULL)),
  CHECK ((legal_hold_until IS NULL) = (legal_hold_reason IS NULL))
);

-- Months in force for a tenant (a decrease applies once its 30 days have passed).
CREATE FUNCTION obligarth.audit_retention_months(p_tenant integer) RETURNS integer
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT COALESCE((SELECT CASE WHEN r.pending_effective_at IS NOT NULL AND r.pending_effective_at <= now()
                               THEN r.pending_months ELSE r.effective_months END
                     FROM obligarth.audit_retention r WHERE r.tenant_id = p_tenant), 12)
$$;

CREATE FUNCTION obligarth.audit_set_retention(p_tenant integer, p_months integer, p_justification text, p_body text)
  RETURNS TABLE (months integer, effective_months integer, pending_effective_at timestamptz)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  b         jsonb := p_body::jsonb;
  v_current integer;
BEGIN
  IF session_user = 'obligarth' AND NOT (COALESCE(obligarth.ctx_tenant() = p_tenant, false) AND obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit_set_retention: platform administrator in the tenant''s context';
  END IF;
  IF p_months NOT BETWEEN 6 AND 36 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_set_retention: months must be between 6 and 36';
  END IF;
  IF p_months <> 12 AND COALESCE(length(trim(p_justification)), 0) < 10 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_set_retention: a justification is required';
  END IF;
  IF b ->> 'action' IS DISTINCT FROM 'audit.retention_changed' OR (b ->> 'tenant')::integer IS DISTINCT FROM p_tenant
     OR (b #>> '{details,months}')::integer IS DISTINCT FROM p_months THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_set_retention: the event does not describe this change';
  END IF;
  v_current := obligarth.audit_retention_months(p_tenant);
  INSERT INTO obligarth.audit_retention AS r (tenant_id) VALUES (p_tenant) ON CONFLICT (tenant_id) DO NOTHING;
  UPDATE obligarth.audit_retention r SET
    months = p_months,
    justification = NULLIF(trim(p_justification), ''),
    effective_months = CASE WHEN p_months >= v_current THEN p_months ELSE v_current END,
    pending_months = CASE WHEN p_months >= v_current THEN NULL ELSE p_months END,
    pending_effective_at = CASE WHEN p_months >= v_current THEN NULL ELSE now() + interval '30 days' END,
    updated_by = obligarth.ctx_actor_user(), updated_at = now()
  WHERE r.tenant_id = p_tenant;
  PERFORM obligarth.audit_append(p_body);
  RETURN QUERY SELECT r.months::integer, r.effective_months::integer, r.pending_effective_at
    FROM obligarth.audit_retention r WHERE r.tenant_id = p_tenant;
END $$;

CREATE FUNCTION obligarth.audit_set_legal_hold(p_tenant integer, p_until timestamptz, p_reason text, p_body text)
  RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE b jsonb := p_body::jsonb;
BEGIN
  IF session_user = 'obligarth' AND NOT (COALESCE(obligarth.ctx_tenant() = p_tenant, false) AND obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit_set_legal_hold: platform administrator in the tenant''s context';
  END IF;
  IF p_until IS NOT NULL AND (p_until <= now() OR p_until > now() + interval '5 years'
                              OR COALESCE(length(trim(p_reason)), 0) < 10) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_set_legal_hold: end within 5 years and a reason are required';
  END IF;
  IF b ->> 'action' IS DISTINCT FROM 'audit.legal_hold_changed' OR (b ->> 'tenant')::integer IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_set_legal_hold: the event does not describe this change';
  END IF;
  INSERT INTO obligarth.audit_retention AS r (tenant_id) VALUES (p_tenant) ON CONFLICT (tenant_id) DO NOTHING;
  UPDATE obligarth.audit_retention r
     SET legal_hold_until = p_until, legal_hold_reason = CASE WHEN p_until IS NULL THEN NULL ELSE trim(p_reason) END,
         updated_by = obligarth.ctx_actor_user(), updated_at = now()
   WHERE r.tenant_id = p_tenant;
  PERFORM obligarth.audit_append(p_body);
END $$;

-- H.8 Seals: signing keys (Ed25519, public part only), instance-wide seals over a Merkle tree of the
-- chain heads that moved (RFC 6962), one leaf per tenant with its inclusion proof.
CREATE TABLE obligarth.audit_seal_keys (
  key_id     text        PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{16}$'),
  algorithm  text        NOT NULL CHECK (algorithm = 'ed25519'),
  public_key bytea       NOT NULL UNIQUE CHECK (length(public_key) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE UNIQUE INDEX audit_seal_keys_one_active ON obligarth.audit_seal_keys ((true)) WHERE retired_at IS NULL;

CREATE TABLE obligarth.audit_seals (
  id             bigserial   PRIMARY KEY,
  seal_seq       bigint      NOT NULL UNIQUE CHECK (seal_seq > 0),
  instance_id    uuid        NOT NULL,
  sealed_at      timestamptz NOT NULL,
  leaf_count     integer     NOT NULL CHECK (leaf_count >= 0),
  merkle_root    bytea       NOT NULL CHECK (length(merkle_root) = 32),
  prev_seal_hash bytea       NOT NULL CHECK (length(prev_seal_hash) = 32),
  seal_hash      bytea       NOT NULL UNIQUE CHECK (length(seal_hash) = 32),
  key_id         text        NOT NULL REFERENCES obligarth.audit_seal_keys (key_id),
  signature      bytea       NOT NULL CHECK (length(signature) = 64),
  tsa_status     text        NOT NULL CHECK (tsa_status IN ('ok', 'disabled', 'failed')),
  tsa_token      bytea,
  tsa_gen_time   timestamptz,
  recorded_at    timestamptz NOT NULL DEFAULT now(),
  CHECK ((tsa_status = 'ok') = (tsa_token IS NOT NULL AND tsa_gen_time IS NOT NULL))
);

CREATE TABLE obligarth.audit_seal_leaves (
  seal_id    bigint  NOT NULL REFERENCES obligarth.audit_seals (id),
  tenant_id  integer NOT NULL CHECK (tenant_id > 0),
  leaf_index integer NOT NULL CHECK (leaf_index >= 0),
  chain_seq  bigint  NOT NULL CHECK (chain_seq > 0),
  chain_hash bytea   NOT NULL CHECK (length(chain_hash) = 32),
  proof      bytea[] NOT NULL,
  PRIMARY KEY (seal_id, tenant_id),
  UNIQUE (seal_id, leaf_index)
);
CREATE INDEX audit_seal_leaves_tenant ON obligarth.audit_seal_leaves (tenant_id, chain_seq DESC);

-- The text the seal key signs (and whose SHA-256 the TSA timestamps).
CREATE FUNCTION obligarth.audit_seal_message(p_instance uuid, p_seq bigint, p_sealed_at timestamptz, p_leaves integer,
                                             p_root bytea, p_prev bytea, p_key_id text) RETURNS text
  LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT 'obligarth-audit-seal/v1' || chr(10)
      || 'instance=' || p_instance::text || chr(10)
      || 'seq=' || p_seq::text || chr(10)
      || 'sealed_at=' || to_char(p_sealed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') || chr(10)
      || 'leaves=' || p_leaves::text || chr(10)
      || 'root=' || encode(p_root, 'hex') || chr(10)
      || 'prev=' || encode(p_prev, 'hex') || chr(10)
      || 'key=' || p_key_id
$$;

-- Chain heads that moved since their last seal (the seal job's input).
CREATE FUNCTION obligarth.audit_seal_candidates()
  RETURNS TABLE (tenant_id integer, chain_seq bigint, chain_hash bytea)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF session_user = 'obligarth' AND obligarth.ctx_actor() IS DISTINCT FROM 'j:audit.seal' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit_seal_candidates: reserved to the audit.seal job';
  END IF;
  RETURN QUERY
    SELECT h.tenant_id, h.last_seq, h.last_hash
      FROM obligarth.audit_chain_heads h
     WHERE h.last_seq > COALESCE((SELECT max(s.chain_seq) FROM obligarth.audit_seal_leaves s
                                   WHERE s.tenant_id = h.tenant_id), 0)
     ORDER BY h.tenant_id;
END $$;

CREATE FUNCTION obligarth.audit_seal_record(
    p_seal_seq bigint, p_instance uuid, p_sealed_at timestamptz, p_root bytea, p_prev bytea,
    p_seal_hash bytea, p_key_id text, p_signature bytea, p_tsa_status text, p_tsa_token bytea,
    p_tsa_gen_time timestamptz, p_leaves jsonb)
  RETURNS bigint
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_last  record;
  v_id    bigint;
  v_count integer := COALESCE(jsonb_array_length(p_leaves), 0);
  l       jsonb;
BEGIN
  IF session_user = 'obligarth' AND obligarth.ctx_actor() IS DISTINCT FROM 'j:audit.seal' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit_seal_record: reserved to the audit.seal job';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('obligarth.audit_seal'));
  SELECT s.seal_seq, s.seal_hash INTO v_last FROM obligarth.audit_seals s ORDER BY s.seal_seq DESC LIMIT 1;
  IF p_seal_seq <> COALESCE(v_last.seal_seq, 0) + 1
     OR p_prev <> COALESCE(v_last.seal_hash, decode(repeat('00', 32), 'hex')) THEN
    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'audit_seal_record: not the next seal of the instance';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM obligarth.audit_seal_keys k WHERE k.key_id = p_key_id AND k.retired_at IS NULL) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_seal_record: unknown or retired key';
  END IF;
  IF p_seal_hash <> sha256(convert_to(obligarth.audit_seal_message(
        p_instance, p_seal_seq, p_sealed_at, v_count, p_root, p_prev, p_key_id), 'UTF8')) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_seal_record: seal_hash does not match the sealed fields';
  END IF;
  IF p_sealed_at > clock_timestamp() + interval '1 minute' OR p_sealed_at < clock_timestamp() - interval '1 hour' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_seal_record: sealed_at out of range';
  END IF;
  INSERT INTO obligarth.audit_seals AS s (seal_seq, instance_id, sealed_at, leaf_count, merkle_root, prev_seal_hash,
      seal_hash, key_id, signature, tsa_status, tsa_token, tsa_gen_time)
  VALUES (p_seal_seq, p_instance, p_sealed_at, v_count, p_root, p_prev, p_seal_hash, p_key_id, p_signature,
      p_tsa_status, p_tsa_token, p_tsa_gen_time)
  RETURNING s.id INTO v_id;
  FOR l IN SELECT * FROM jsonb_array_elements(COALESCE(p_leaves, '[]'::jsonb)) LOOP
    -- the leaf must name an entry that exists with this hash
    IF NOT EXISTS (SELECT 1 FROM obligarth.audit_logs a
                    WHERE a.tenant_id = (l ->> 'tenant')::integer AND a.chain_seq = (l ->> 'seq')::bigint
                      AND a.hash = decode(l ->> 'hash', 'hex')) THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_seal_record: a leaf names no such entry';
    END IF;
    INSERT INTO obligarth.audit_seal_leaves (seal_id, tenant_id, leaf_index, chain_seq, chain_hash, proof)
    VALUES (v_id, (l ->> 'tenant')::integer, (l ->> 'index')::integer, (l ->> 'seq')::bigint, decode(l ->> 'hash', 'hex'),
            ARRAY(SELECT decode(p, 'hex') FROM jsonb_array_elements_text(l -> 'proof') p));
  END LOOP;
  RETURN v_id;
END $$;

CREATE FUNCTION obligarth.audit_seal_key_register(p_public_key bytea)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_kid text := left(encode(sha256(p_public_key), 'hex'), 16);
BEGIN
  IF session_user = 'obligarth' AND obligarth.ctx_actor() IS DISTINCT FROM 'j:audit.seal-keys'
     AND NOT obligarth.ctx_actor_is_platform_admin() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit_seal_key_register: seal-key job or platform administrator';
  END IF;
  IF length(p_public_key) <> 32 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'audit_seal_key_register: an Ed25519 public key has 32 bytes';
  END IF;
  UPDATE obligarth.audit_seal_keys k SET retired_at = now() WHERE k.retired_at IS NULL;
  INSERT INTO obligarth.audit_seal_keys (key_id, algorithm, public_key) VALUES (v_kid, 'ed25519', p_public_key);
  RETURN v_kid;
END $$;

-- H.9 Export to the SIEM: destinations (settings in clear, secrets sealed by the vault) and cursors
CREATE TABLE obligarth.audit_export_destinations (
  id                 serial       PRIMARY KEY,
  uuid               uuid         NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  name               varchar(100) NOT NULL,
  kind               varchar(16)  NOT NULL CHECK (kind IN ('syslog_tls', 'webhook')),
  scope_tenant_id    integer      CHECK (scope_tenant_id > 0),         -- NULL: every tenant (SIEM of the MSP)
  config             jsonb        NOT NULL DEFAULT '{}',
  secrets_enc        text,
  enabled            boolean      NOT NULL DEFAULT true,
  required_for_purge boolean      NOT NULL DEFAULT true,
  include_seals      boolean      NOT NULL DEFAULT true,
  last_seal_seq      bigint       NOT NULL DEFAULT 0,
  last_success_at    timestamptz,
  last_error_at      timestamptz,
  last_error_code    varchar(64),
  created_by         integer,
  created_at         timestamptz  NOT NULL DEFAULT now(),
  updated_at         timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT audit_export_destinations_secrets_enc_sealed CHECK (secrets_enc IS NULL OR secrets_enc ~
    '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$')
);

CREATE TABLE obligarth.audit_export_cursors (
  destination_id integer     NOT NULL REFERENCES obligarth.audit_export_destinations (id) ON DELETE CASCADE,
  tenant_id      integer     NOT NULL CHECK (tenant_id > 0),
  last_seq       bigint      NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  last_sent_at   timestamptz,
  PRIMARY KEY (destination_id, tenant_id)
);

-- H.9b Results of the chain verifications (jobs and on-demand checks)
CREATE TABLE obligarth.audit_verifications (
  id           bigserial   PRIMARY KEY,
  tenant_id    integer     NOT NULL CHECK (tenant_id > 0),
  kind         varchar(16) NOT NULL CHECK (kind IN ('incremental', 'full', 'on_demand')),
  from_seq     bigint,
  to_seq       bigint,
  to_hash      bytea       CHECK (to_hash IS NULL OR length(to_hash) = 32),
  entries      bigint      NOT NULL DEFAULT 0,
  seals        integer     NOT NULL DEFAULT 0,
  status       varchar(16) NOT NULL CHECK (status IN ('running', 'ok', 'broken', 'error')),
  problem      jsonb,
  requested_by integer,
  started_at   timestamptz NOT NULL DEFAULT now(),
  finished_at  timestamptz
);
CREATE INDEX audit_verifications_tenant ON obligarth.audit_verifications (tenant_id, started_at DESC);

-- H.10 Purge (retention job only): a contiguous prefix of a chain, older than the retention in force,
-- already sealed and exported to every destination required for it; anchor kept; event appended.
CREATE FUNCTION obligarth.audit_purge(p_tenant integer, p_max integer)
  RETURNS TABLE (purged bigint, through_seq bigint, blocked_by text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '5s' AS $$
DECLARE
  v_months  integer := obligarth.audit_retention_months(p_tenant);
  v_hold    timestamptz;
  v_cutoff  timestamptz;
  v_anchor  bigint;
  v_due     bigint;
  v_sealed  bigint;
  v_export  bigint;
  v_through bigint;
  v_hash    bytea;
  v_count   bigint;
  v_body    text;
BEGIN
  IF session_user = 'obligarth' AND obligarth.ctx_actor() IS DISTINCT FROM 'j:audit.retention' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit_purge: reserved to the audit.retention job';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('obligarth.audit_purge'), p_tenant);
  SELECT r.legal_hold_until INTO v_hold FROM obligarth.audit_retention r WHERE r.tenant_id = p_tenant;
  IF v_hold IS NOT NULL AND v_hold > now() THEN
    RETURN QUERY SELECT 0::bigint, NULL::bigint, 'legal_hold'::text; RETURN;
  END IF;
  v_cutoff := now() - make_interval(months => v_months);
  v_anchor := COALESCE((SELECT a.anchor_seq FROM obligarth.audit_chain_anchors a WHERE a.tenant_id = p_tenant), 0);
  SELECT max(l.chain_seq) INTO v_due FROM obligarth.audit_logs l
   WHERE l.tenant_id = p_tenant AND l.created_at < v_cutoff;
  IF v_due IS NULL OR v_due <= v_anchor THEN
    RETURN QUERY SELECT 0::bigint, NULL::bigint, 'nothing_due'::text; RETURN;
  END IF;
  v_sealed := COALESCE((SELECT max(s.chain_seq) FROM obligarth.audit_seal_leaves s WHERE s.tenant_id = p_tenant), 0);
  SELECT min(COALESCE(c.last_seq, 0)) INTO v_export
    FROM obligarth.audit_export_destinations d
    LEFT JOIN obligarth.audit_export_cursors c ON c.destination_id = d.id AND c.tenant_id = p_tenant
   WHERE d.enabled AND d.required_for_purge AND (d.scope_tenant_id IS NULL OR d.scope_tenant_id = p_tenant);
  v_through := LEAST(v_due, v_sealed, COALESCE(v_export, v_due), v_anchor + GREATEST(LEAST(p_max, 50000), 1));
  IF v_through <= v_anchor THEN
    RETURN QUERY SELECT 0::bigint, NULL::bigint,
      (CASE WHEN v_sealed <= v_anchor THEN 'not_sealed' ELSE 'not_exported' END)::text;
    RETURN;
  END IF;
  SELECT l.hash INTO v_hash FROM obligarth.audit_logs l WHERE l.tenant_id = p_tenant AND l.chain_seq = v_through;
  PERFORM set_config('obligarth.audit_purge', 'on', true);
  DELETE FROM obligarth.audit_logs l WHERE l.tenant_id = p_tenant AND l.chain_seq > v_anchor AND l.chain_seq <= v_through;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  PERFORM set_config('obligarth.audit_purge', 'off', true);
  INSERT INTO obligarth.audit_chain_anchors AS a (tenant_id, anchor_seq, anchor_hash, purged_at)
  VALUES (p_tenant, v_through, v_hash, now())
  ON CONFLICT (tenant_id) DO UPDATE SET anchor_seq = EXCLUDED.anchor_seq, anchor_hash = EXCLUDED.anchor_hash,
                                        purged_at = EXCLUDED.purged_at;
  v_body := jsonb_build_object(
    'v', 1, 'id', gen_random_uuid(),
    'ts', to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'tenant', p_tenant, 'action', 'audit.retention_purged', 'outcome', 'success', 'crit', 'critical',
    'actor', jsonb_build_object('type', 'job', 'ref', COALESCE(obligarth.ctx_actor(), 'j:audit.retention'), 'side', 'system'),
    'details', jsonb_build_object('fromSeq', v_anchor + 1, 'throughSeq', v_through, 'entries', v_count,
      'anchorHash', encode(v_hash, 'hex'), 'retentionMonths', v_months,
      'cutoff', to_char(v_cutoff AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')))::text;
  PERFORM * FROM obligarth_private.audit_append_internal(v_body);
  RETURN QUERY SELECT v_count, v_through, NULL::text;
END $$;

-- Housekeeping of the retention job: seal leaves older than 37 months (the latest leaf of each
-- chain is kept: the purge needs it), verification results older than 90 days.
CREATE FUNCTION obligarth.audit_housekeeping()
  RETURNS TABLE (seal_leaves bigint, verifications bigint)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_leaves bigint;
  v_checks bigint;
BEGIN
  IF session_user = 'obligarth' AND obligarth.ctx_actor() IS DISTINCT FROM 'j:audit.retention' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit_housekeeping: reserved to the audit.retention job';
  END IF;
  DELETE FROM obligarth.audit_seal_leaves l USING obligarth.audit_seals s
   WHERE s.id = l.seal_id AND s.sealed_at < now() - interval '37 months'
     AND l.chain_seq < (SELECT max(x.chain_seq) FROM obligarth.audit_seal_leaves x WHERE x.tenant_id = l.tenant_id);
  GET DIAGNOSTICS v_leaves = ROW_COUNT;
  DELETE FROM obligarth.audit_verifications v WHERE v.started_at < now() - interval '90 days';
  GET DIAGNOSTICS v_checks = ROW_COUNT;
  RETURN QUERY SELECT v_leaves, v_checks;
END $$;

-- Chains of the instance, for the retention and verification jobs (tenant ids only).
CREATE FUNCTION obligarth.audit_chains()
  RETURNS TABLE (tenant_id integer, last_seq bigint, anchor_seq bigint, tenant_exists boolean)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.tenant_id, h.last_seq, COALESCE(a.anchor_seq, 0),
         EXISTS (SELECT 1 FROM obligarth.tenants t WHERE t.id = h.tenant_id)
    FROM obligarth.audit_chain_heads h
    LEFT JOIN obligarth.audit_chain_anchors a ON a.tenant_id = h.tenant_id
   ORDER BY h.tenant_id
$$;

-- H.11 Classification and privileges: read-only for the runtime roles, writes through the functions
SELECT obligarth_private.rls_apply('obligarth.audit_logs', 'custom', 'append-only journal (audit_append); purge by audit_purge');
REVOKE ALL ON SEQUENCE obligarth.audit_logs_id_seq FROM obligarth, obligarth_reader;
CREATE POLICY rls_tenant_read ON obligarth.audit_logs FOR SELECT TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_reader ON obligarth.audit_logs FOR SELECT TO obligarth_reader
  USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
GRANT SELECT ON obligarth.audit_logs TO obligarth, obligarth_reader;

SELECT obligarth_private.rls_apply('obligarth.audit_chain_heads', 'custom', 'chain heads; written by audit_append only');
CREATE POLICY rls_tenant_read ON obligarth.audit_chain_heads FOR SELECT TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_reader ON obligarth.audit_chain_heads FOR SELECT TO obligarth_reader
  USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
GRANT SELECT ON obligarth.audit_chain_heads TO obligarth, obligarth_reader;

SELECT obligarth_private.rls_apply('obligarth.audit_chain_anchors', 'custom', 'purge anchors; written by audit_purge only');
CREATE POLICY rls_tenant_read ON obligarth.audit_chain_anchors FOR SELECT TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_reader ON obligarth.audit_chain_anchors FOR SELECT TO obligarth_reader
  USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
GRANT SELECT ON obligarth.audit_chain_anchors TO obligarth, obligarth_reader;

SELECT obligarth_private.rls_apply('obligarth.audit_retention', 'custom', 'retention per tenant; written by audit_set_retention');
CREATE POLICY rls_tenant_read ON obligarth.audit_retention FOR SELECT TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_reader ON obligarth.audit_retention FOR SELECT TO obligarth_reader
  USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
GRANT SELECT ON obligarth.audit_retention TO obligarth, obligarth_reader;

SELECT obligarth_private.rls_apply('obligarth.audit_seal_keys', 'custom', 'public seal keys; no tenant data');
CREATE POLICY rls_read ON obligarth.audit_seal_keys FOR SELECT TO obligarth, obligarth_reader USING (true);
GRANT SELECT ON obligarth.audit_seal_keys TO obligarth, obligarth_reader;

SELECT obligarth_private.rls_apply('obligarth.audit_seals', 'custom', 'instance seals; no tenant data');
CREATE POLICY rls_read ON obligarth.audit_seals FOR SELECT TO obligarth, obligarth_reader USING (true);
GRANT SELECT ON obligarth.audit_seals TO obligarth, obligarth_reader;
REVOKE ALL ON SEQUENCE obligarth.audit_seals_id_seq FROM obligarth, obligarth_reader;

SELECT obligarth_private.rls_apply('obligarth.audit_seal_leaves', 'custom', 'seal leaves and proofs per tenant');
CREATE POLICY rls_tenant_read ON obligarth.audit_seal_leaves FOR SELECT TO obligarth
  USING (tenant_id = (SELECT obligarth.ctx_tenant()));
CREATE POLICY rls_reader ON obligarth.audit_seal_leaves FOR SELECT TO obligarth_reader
  USING (tenant_id = ANY (CAST((SELECT obligarth.ctx_read_tenants()) AS integer[])));
GRANT SELECT ON obligarth.audit_seal_leaves TO obligarth, obligarth_reader;

SELECT obligarth_private.rls_apply('obligarth.audit_verifications', 'tenant', 'chain verification results');
ALTER TABLE obligarth.audit_verifications ALTER COLUMN tenant_id SET DEFAULT obligarth.ctx_tenant();
REVOKE DELETE ON obligarth.audit_verifications FROM obligarth;

SELECT obligarth_private.rls_apply('obligarth.audit_export_destinations', 'technical', 'SIEM destinations (platform settings, secrets sealed)');
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.audit_export_destinations TO obligarth;
GRANT USAGE ON SEQUENCE obligarth.audit_export_destinations_id_seq TO obligarth;
SELECT obligarth_private.rls_apply('obligarth.audit_export_cursors', 'technical', 'SIEM cursors (ids and sequence numbers only)');
GRANT SELECT, INSERT, UPDATE, DELETE ON obligarth.audit_export_cursors TO obligarth;

REVOKE ALL ON FUNCTION obligarth.audit_link_hash(bytea, bigint, text), obligarth.audit_append(text),
  obligarth.audit_retention_months(integer), obligarth.audit_set_retention(integer, integer, text, text),
  obligarth.audit_set_legal_hold(integer, timestamptz, text, text),
  obligarth.audit_seal_message(uuid, bigint, timestamptz, integer, bytea, bytea, text),
  obligarth.audit_seal_candidates(), obligarth.audit_seal_record(bigint, uuid, timestamptz, bytea, bytea, bytea, text, bytea, text, bytea, timestamptz, jsonb),
  obligarth.audit_seal_key_register(bytea), obligarth.audit_purge(integer, integer), obligarth.audit_chains(),
  obligarth.audit_housekeeping()
  FROM PUBLIC;
REVOKE ALL ON FUNCTION obligarth_private.audit_append_internal(text), obligarth_private.audit_logs_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.audit_link_hash(bytea, bigint, text), obligarth.audit_append(text),
  obligarth.audit_retention_months(integer), obligarth.audit_set_retention(integer, integer, text, text),
  obligarth.audit_set_legal_hold(integer, timestamptz, text, text),
  obligarth.audit_seal_message(uuid, bigint, timestamptz, integer, bytea, bytea, text),
  obligarth.audit_seal_candidates(), obligarth.audit_seal_record(bigint, uuid, timestamptz, bytea, bytea, bytea, text, bytea, text, bytea, timestamptz, jsonb),
  obligarth.audit_seal_key_register(bytea), obligarth.audit_purge(integer, integer), obligarth.audit_chains(),
  obligarth.audit_housekeeping()
  TO obligarth;
GRANT EXECUTE ON FUNCTION obligarth.audit_link_hash(bytea, bigint, text),
  obligarth.audit_seal_message(uuid, bigint, timestamptz, integer, bytea, bytea, text),
  obligarth.audit_retention_months(integer) TO obligarth_reader;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.audit_append',            'definer', 'the only writer of audit_logs: tenant of the context, chain head locked'),
  ('function', 'obligarth.audit_retention_months',  'definer', 'retention in force of a tenant'),
  ('function', 'obligarth.audit_set_retention',     'definer', 'platform administrator in the tenant context; decrease after 30 days'),
  ('function', 'obligarth.audit_set_legal_hold',    'definer', 'platform administrator in the tenant context'),
  ('function', 'obligarth.audit_seal_candidates',   'definer', 'audit.seal job: heads moved since their last seal'),
  ('function', 'obligarth.audit_seal_record',       'definer', 'audit.seal job: next seal, leaves checked against the chains'),
  ('function', 'obligarth.audit_seal_key_register', 'definer', 'seal key job or platform administrator'),
  ('function', 'obligarth.audit_purge',             'definer', 'audit.retention job: sealed, exported, older than the retention'),
  ('function', 'obligarth.audit_chains',            'definer', 'tenant ids of the chains (jobs)'),
  ('function', 'obligarth.audit_housekeeping',      'definer', 'audit.retention job: old seal leaves and verification results');

-- H.12 Identifier of the instance (bound into every seal); the inherited audit.clear key leaves the matrix
INSERT INTO obligarth.app_config (key, value) VALUES ('instance_id', gen_random_uuid()::text) ON CONFLICT (key) DO NOTHING;
UPDATE obligarth.tenants SET action_restrictions = action_restrictions - 'audit.clear'
 WHERE action_restrictions -> 'audit.clear' IS NOT NULL;

-- H.12b Readers of the journal (audit-durci section 9.1; part G.5 of guard_foundation, applied with the
-- journal: section 12.4, step 3): audience of a role (msp or client), the two client permission sets of
-- the MVP (D42, option 1), and audit.read shown in the admin set. guard_foundation (lot A7) leaves G.5 out.
ALTER TABLE obligarth.permission_sets ADD COLUMN audience varchar(8) NOT NULL DEFAULT 'msp';
ALTER TABLE obligarth.permission_sets ADD CONSTRAINT permission_sets_audience_check CHECK (audience IN ('msp', 'client'));
INSERT INTO obligarth.permission_sets (name, slug, capabilities, is_default, audience) VALUES
  ('Approver', 'approver', '["approvals.review", "audit.read"]', true, 'client'),
  ('Auditor / DPO', 'auditor', '["audit.read"]', true, 'client')
ON CONFLICT (slug) DO NOTHING;
UPDATE obligarth.permission_sets SET capabilities = capabilities || '["audit.read"]'::jsonb
 WHERE slug = 'admin' AND NOT capabilities @> '["audit.read"]'::jsonb;

-- H.13 Catalogue check: here when rls_policies (C) already ran, else C runs it after classifying the rest
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

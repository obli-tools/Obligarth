import type { Knex } from 'knex';

// Durable jobs (pg-boss) and the brain-side state of the apple-edge outbox consumer (docs: file-durable §4.2).
//   - schema pgboss: created by the bootstrap of server-migrate (rls-tenant annex A.1), owned by the runtime
//     role; only checked here. pg-boss installs and migrates its own objects inside it at start
//     (createSchema: false).
//   - job_status: last run of each queue (and of each tenant for the fan-outs that track it).
//   - job_once: keys of the side effects already done by at-least-once jobs.
//   - apple_edge_inbox_attempts, apple_edge_dead_letters: the outbox consumer's attempts and dead letters
//     (the brain may only set consumed_at in apple_edge.outbox).
// Runs as obligarth_owner (server-migrate), before the RLS migration C, which classifies these tables
// (block C.11): no rls_apply and no rls_assert_clean() here, as in migrations A and B. The SQL holds no
// question mark (knex.raw would bind it) and is kept verbatim by String.raw.
const UP = String.raw`
CREATE TABLE obligarth.job_status (
  queue                varchar(64)  NOT NULL,
  key                  varchar(100) NOT NULL DEFAULT '',
  last_job_id          uuid,
  last_started_at      timestamptz,
  last_succeeded_at    timestamptz,
  last_failed_at       timestamptz,
  last_error_code      varchar(64),
  consecutive_failures integer      NOT NULL DEFAULT 0,
  last_duration_ms     integer,
  succeeded_count      bigint       NOT NULL DEFAULT 0,
  failed_count         bigint       NOT NULL DEFAULT 0,
  updated_at           timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT job_status_pkey PRIMARY KEY (queue, key)
);

CREATE TABLE obligarth.job_once (
  key         varchar(200) NOT NULL,
  queue       varchar(64)  NOT NULL,
  state       varchar(16)  NOT NULL,
  lease_until timestamptz  NOT NULL,
  done_at     timestamptz,
  expires_at  timestamptz  NOT NULL,
  CONSTRAINT job_once_pkey PRIMARY KEY (key),
  CONSTRAINT job_once_state_check CHECK (state IN ('pending', 'done'))
);
CREATE INDEX job_once_expires_at_idx ON obligarth.job_once (expires_at);

CREATE TABLE obligarth.apple_edge_inbox_attempts (
  event_id        uuid        NOT NULL,
  seq             bigint      NOT NULL,
  type            varchar(64) NOT NULL,
  attempts        integer     NOT NULL,
  first_failed_at timestamptz NOT NULL,
  last_failed_at  timestamptz NOT NULL,
  next_attempt_at timestamptz NOT NULL,
  last_error_code varchar(64) NOT NULL,
  CONSTRAINT apple_edge_inbox_attempts_pkey PRIMARY KEY (event_id)
);
CREATE INDEX apple_edge_inbox_attempts_next_idx ON obligarth.apple_edge_inbox_attempts (next_attempt_at);

CREATE TABLE obligarth.apple_edge_dead_letters (
  event_id         uuid        NOT NULL,
  seq              bigint      NOT NULL,
  schema_version   smallint    NOT NULL,
  scope            varchar(16) NOT NULL,
  tenant_key       varchar(16),
  tenant_id        integer,
  type             varchar(64) NOT NULL,
  enrollment_id    text,
  command_uuid     varchar(64),
  request_id       varchar(64),
  occurred_at      timestamptz NOT NULL,
  payload          jsonb       NOT NULL,
  reason           varchar(32) NOT NULL,
  attempts         integer     NOT NULL,
  last_error_code  varchar(64) NOT NULL,
  dead_lettered_at timestamptz NOT NULL DEFAULT now(),
  redriven_at      timestamptz,
  redrive_outcome  varchar(16),
  redriven_by      integer,
  CONSTRAINT apple_edge_dead_letters_pkey PRIMARY KEY (event_id),
  CONSTRAINT apple_edge_dead_letters_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT apple_edge_dead_letters_redriven_by_foreign FOREIGN KEY (redriven_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT apple_edge_dead_letters_scope_check CHECK (scope IN ('tenant', 'platform')),
  CONSTRAINT apple_edge_dead_letters_reason_check CHECK (reason IN (
    'unknown_type', 'unsupported_schema_version', 'invalid_payload', 'tenant_mismatch',
    'unknown_tenant', 'handler_error', 'permanent_error')),
  CONSTRAINT apple_edge_dead_letters_redrive_outcome_check CHECK (redrive_outcome IS NULL OR redrive_outcome IN ('applied', 'failed'))
);
CREATE INDEX apple_edge_dead_letters_at_idx ON obligarth.apple_edge_dead_letters (dead_lettered_at);
CREATE INDEX apple_edge_dead_letters_tenant_idx ON obligarth.apple_edge_dead_letters (tenant_id);
`;

export async function up(knex: Knex): Promise<void> {
  // Created by the bootstrap of server-migrate, owned by the runtime role: the migrations run as
  // obligarth_owner, which can neither create nor own it (review FD-RC2).
  const { rows } = await knex.raw(`SELECT 1 FROM pg_namespace WHERE nspname = 'pgboss'`) as { rows: unknown[] };
  if (rows.length === 0) {
    throw new Error('jobs migration: schema pgboss is missing; run server-migrate (its bootstrap creates it) first');
  }
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the migration');
}

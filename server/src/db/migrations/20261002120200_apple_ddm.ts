import type { Knex } from 'knex';

// =============================================================================
// Apple integration, part 6: the DDM engine (docs: integration-apple-edge §4.7, §9; conception §5.4.5)
// =============================================================================
//   - apple_declarations: every declaration served, addressed by (identifier, server token), never a secret
//     (I8), named by its provider;
//   - apple_declaration_sets: the declaration set of a device, its tokens and its synchronisation;
//   - apple_declaration_status: the status of each declaration reported by the device;
//   - apple_ddm_status_inbox: status reports waiting for their ingestion.
// Same columns, types, constraints and names as the specification, written in SQL like the migrations of lot
// B1; tenant_id of the tenant tables defaults to the context's tenant (rls-tenant §5.4, rule 5). The data
// model's policies provider (modele §7.10) serves its declarations through this engine. Runs as
// obligarth_owner (server-migrate), after apple_enrollment; ends with obligarth.rls_assert_clean(). No
// question mark in the SQL (knex.raw would bind it); kept verbatim by String.raw.

const FAMILIES = ['activation', 'asset', 'configuration', 'management'];

const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

const UP = String.raw`-- =============================================================================
-- Apple integration, part 6: DDM engine (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.apple_devices') IS NULL THEN
    RAISE EXCEPTION 'apple_ddm: apply the RLS migrations and mdm_model_expand first';
  END IF;
END $$;

CREATE TABLE obligarth.apple_declarations (
  id            bigserial     NOT NULL,
  tenant_id     integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  identifier    varchar(255)  NOT NULL,
  family        varchar(16)   NOT NULL,
  type          varchar(128)  NOT NULL,                    -- e.g. com.apple.configuration.passcode.settings
  server_token  varchar(64)   NOT NULL,                    -- SHA-256 of the canonical declaration
  payload       jsonb         NOT NULL,                    -- never a secret (I8)
  source        varchar(48)   NOT NULL,                    -- provider name
  created_at    timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at  timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT apple_declarations_pkey PRIMARY KEY (id),
  CONSTRAINT apple_declarations_tenant_id_identifier_server_token_unique UNIQUE (tenant_id, identifier, server_token),
  CONSTRAINT apple_declarations_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT apple_declarations_family_check CHECK (family IN (${list(FAMILIES)})),
  CONSTRAINT apple_declarations_identifier_check
    CHECK (identifier ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$' AND server_token ~ '^[0-9a-f]{64}$')
);
SELECT obligarth_private.rls_apply('obligarth.apple_declarations', 'tenant');

CREATE TABLE obligarth.apple_declaration_sets (
  device_id           integer       NOT NULL,
  tenant_id           integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  declarations_token  varchar(64)   NOT NULL,
  items               jsonb         NOT NULL,              -- [{family, identifier, server_token, type}] sorted
  previous_items      jsonb,                               -- still served until previous_until
  previous_until      timestamptz,
  computed_at         timestamptz   NOT NULL,
  sent_token          varchar(64),                         -- token carried by the last DeclarativeManagement
  sync_command_id     uuid,                                -- open DeclarativeManagement command
  fetched_token       varchar(64),                         -- token of the last declaration-items served
  fetched_at          timestamptz,
  CONSTRAINT apple_declaration_sets_pkey PRIMARY KEY (device_id),
  CONSTRAINT apple_declaration_sets_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
SELECT obligarth_private.rls_apply('obligarth.apple_declaration_sets', 'tenant');

CREATE TABLE obligarth.apple_declaration_status (
  tenant_id     integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id     integer       NOT NULL,
  identifier    varchar(255)  NOT NULL,
  family        varchar(16)   NOT NULL,
  server_token  varchar(64),
  active        boolean,
  valid         varchar(16),                               -- valid | invalid | unknown
  reasons       jsonb,                                     -- 4 KiB at most
  observed_at   timestamptz   NOT NULL,
  CONSTRAINT apple_declaration_status_pkey PRIMARY KEY (tenant_id, device_id, identifier),
  CONSTRAINT apple_declaration_status_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
SELECT obligarth_private.rls_apply('obligarth.apple_declaration_status', 'tenant');

CREATE TABLE obligarth.apple_ddm_status_inbox (
  id               uuid          NOT NULL DEFAULT gen_random_uuid(),
  tenant_id        integer       NOT NULL DEFAULT obligarth.ctx_tenant(),
  device_id        integer       NOT NULL,
  received_at      timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  report           jsonb         NOT NULL,                 -- push token and magic removed (integration §9.6)
  attempts         integer       NOT NULL DEFAULT 0,
  last_error_code  varchar(64),
  CONSTRAINT apple_ddm_status_inbox_pkey PRIMARY KEY (id),
  CONSTRAINT apple_ddm_status_inbox_device_id_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE
);
SELECT obligarth_private.rls_apply('obligarth.apple_ddm_status_inbox', 'tenant');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}

import type { Knex } from 'knex';

// Vault (FND-03), expand step (docs: coffre-secrets §4.1).
//
// Envelope encryption of the secrets the server stores: one data key (DEK) per
// tenant plus one for the instance (tenant_id NULL), wrapped by the server's
// key-encryption key (KEK: a Docker secret file, never in the database). A
// secret column holds
//   v1:<DEK id>:<iv>:<ct>:<tag>          (base64url, AES-256-GCM)
// sealed with the AAD "obligarth.<table>:<column>:<primary key>:<tenant id or ->".
// Same format as apple-edge (internal/crypto/envelope).
//
// Expand step: the encrypted twin of each column that held a secret in clear
// is added next to it. The server's boot backfill (vault/backfill.ts) moves the
// clear values into the twins and empties the clear columns; the contract
// migration of a later version drops them once none is left.
//
// Runs as obligarth_owner (server-migrate), before the RLS migration C, which
// classifies these tables (block C.11: data_keys, instance_secrets and
// vault_operations technical, tenant_secrets tenant): no rls_apply and no
// rls_assert_clean() here, as in migrations A, B and jobs. The SQL holds no
// question mark (knex.raw would bind it) and is kept verbatim by String.raw.
// No application code is imported (rules of the base migration).
//
// Concurrent lazy creation of a tenant's first DEK inserts with ON CONFLICT DO
// NOTHING without a conflict target: every unique index is then an arbiter
// (data_keys_version as well as data_keys_one_active), so two creators racing
// never fail on the version index.

const UP = String.raw`
CREATE TABLE obligarth.data_keys (
  id            uuid         NOT NULL,
  tenant_id     integer,
  version       integer      NOT NULL,
  kek_id        varchar(128) NOT NULL,
  dek_wrapped   text,
  state         varchar(16)  NOT NULL DEFAULT 'active',
  destroy_after timestamptz,
  created_at    timestamptz  NOT NULL DEFAULT now(),
  retired_at    timestamptz,
  destroyed_at  timestamptz,
  CONSTRAINT data_keys_pkey PRIMARY KEY (id),
  CONSTRAINT data_keys_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE RESTRICT,
  CONSTRAINT data_keys_state_check CHECK (state IN ('active', 'retired', 'destroyed')),
  CONSTRAINT data_keys_destroyed_check CHECK ((state = 'destroyed') = (dek_wrapped IS NULL)),
  CONSTRAINT data_keys_dek_wrapped_format CHECK (dek_wrapped IS NULL OR dek_wrapped ~
    '^(v1:[0-9a-f]{16}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]{43}:[A-Za-z0-9_-]{22}|vault:v[0-9]+:[A-Za-z0-9+/]+={0,2})$'),
  CONSTRAINT data_keys_version_check CHECK (version > 0)
);
CREATE UNIQUE INDEX data_keys_version ON obligarth.data_keys ((coalesce(tenant_id, 0)), version);
CREATE UNIQUE INDEX data_keys_one_active ON obligarth.data_keys ((coalesce(tenant_id, 0))) WHERE state = 'active';
CREATE INDEX data_keys_destroy_due ON obligarth.data_keys (destroy_after)
  WHERE destroy_after IS NOT NULL AND state <> 'destroyed';

-- Named secrets of the instance (Obligate API key...)
CREATE TABLE obligarth.instance_secrets (
  name       varchar(64) NOT NULL,
  value_enc  text        NOT NULL,
  version    integer     NOT NULL DEFAULT 1,
  updated_by integer,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT instance_secrets_pkey PRIMARY KEY (name),
  CONSTRAINT instance_secrets_updated_by_foreign FOREIGN KEY (updated_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT instance_secrets_name_check CHECK (name ~ '^[a-z][a-z0-9_]{1,63}$'),
  CONSTRAINT instance_secrets_value_enc_sealed CHECK (value_enc IS NULL OR value_enc ~
    '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$')
);

-- Secrets referenced from documents ({"$secret": "<id>"})
CREATE TABLE obligarth.tenant_secrets (
  id          uuid        NOT NULL,
  tenant_id   integer     NOT NULL,
  purpose     varchar(64) NOT NULL,
  value_enc   text        NOT NULL,
  created_by  integer,
  created_at  timestamptz NOT NULL DEFAULT now(),
  orphaned_at timestamptz,
  CONSTRAINT tenant_secrets_pkey PRIMARY KEY (id),
  CONSTRAINT tenant_secrets_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT tenant_secrets_created_by_foreign FOREIGN KEY (created_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT tenant_secrets_purpose_check CHECK (purpose ~ '^[a-z][a-z0-9_.]{1,63}$'),
  CONSTRAINT tenant_secrets_value_enc_sealed CHECK (value_enc IS NULL OR value_enc ~
    '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$')
);
CREATE INDEX tenant_secrets_tenant_id_purpose_index ON obligarth.tenant_secrets (tenant_id, purpose);

-- Operations on the keys (backfill, rotations, escrow), never a secret
CREATE TABLE obligarth.vault_operations (
  id               uuid        NOT NULL,
  kind             varchar(32) NOT NULL,
  state            varchar(16) NOT NULL,
  tenant_id        integer,
  approval_id      integer,
  requested_by     integer,
  reason           text,
  params           jsonb       NOT NULL DEFAULT '{}',
  progress         jsonb       NOT NULL DEFAULT '{}',
  authorized_until timestamptz,
  started_at       timestamptz,
  finished_at      timestamptz,
  error            varchar(1000),
  created_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT vault_operations_pkey PRIMARY KEY (id),
  CONSTRAINT vault_operations_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE SET NULL,
  CONSTRAINT vault_operations_approval_id_foreign FOREIGN KEY (approval_id)
    REFERENCES obligarth.pending_approvals (id) ON DELETE SET NULL,
  CONSTRAINT vault_operations_requested_by_foreign FOREIGN KEY (requested_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT vault_operations_kind_check CHECK (kind IN (
    'backfill', 'dek_rotation', 'kek_rotation', 'verify',
    'escrow_confirmation', 'escrow_test', 'escrow_retirement', 'kek_loss_recovery')),
  CONSTRAINT vault_operations_state_check CHECK (state IN (
    'pending_approval', 'authorized', 'running', 'done', 'failed', 'expired', 'cancelled'))
);
CREATE INDEX vault_operations_kind_created_at_index ON obligarth.vault_operations (kind, created_at);

-- Encrypted twins of the inherited clear columns: only sealed values (or NULL), never a clear one.
ALTER TABLE obligarth.users ADD COLUMN totp_secret_enc text;                       -- was users.totp_secret
ALTER TABLE obligarth.users ADD CONSTRAINT users_totp_secret_enc_sealed CHECK (totp_secret_enc IS NULL OR totp_secret_enc ~
  '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$');
ALTER TABLE obligarth.smtp_servers ADD COLUMN password_enc text;                   -- was smtp_servers.password
ALTER TABLE obligarth.smtp_servers ADD CONSTRAINT smtp_servers_password_enc_sealed CHECK (password_enc IS NULL OR password_enc ~
  '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$');
ALTER TABLE obligarth.notification_channels ADD COLUMN secrets_enc text;           -- secret fields of notification_channels.config
ALTER TABLE obligarth.notification_channels ADD CONSTRAINT notification_channels_secrets_enc_sealed CHECK (secrets_enc IS NULL OR secrets_enc ~
  '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$');
ALTER TABLE obligarth.device_licenses ADD COLUMN license_key_enc text;             -- was device_licenses.license_key
ALTER TABLE obligarth.device_licenses ADD CONSTRAINT device_licenses_license_key_enc_sealed CHECK (license_key_enc IS NULL OR license_key_enc ~
  '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$');
ALTER TABLE obligarth.pending_approvals ADD COLUMN sealed_payload_enc text;        -- was pending_approvals.sealed_payload
ALTER TABLE obligarth.pending_approvals ADD CONSTRAINT pending_approvals_sealed_payload_enc_sealed CHECK (sealed_payload_enc IS NULL OR sealed_payload_enc ~
  '^v1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]*:[A-Za-z0-9_-]{22}$');

-- Names of the secret fields set in secrets_enc: shown as "set", never their values.
ALTER TABLE obligarth.notification_channels ADD COLUMN secret_fields jsonb NOT NULL DEFAULT '[]';
ALTER TABLE obligarth.notification_channels ADD CONSTRAINT notification_channels_secret_fields_check
  CHECK (jsonb_typeof(secret_fields) = 'array');

-- A vault reseal (backfill, DEK rotation: vault/reseal.ts sets obligarth.vault_reseal = 'on' for its
-- transaction) rewrites the TOTP secret's ciphertext, never its value: no credential change, so the
-- phone keys enrolled under the current version survive. Any other change of the TOTP secret, clear or
-- sealed, bumps credential_version as before.
CREATE OR REPLACE FUNCTION obligarth.users_bump_credential_version() RETURNS trigger AS $$
DECLARE
  reseal boolean := coalesce(current_setting('obligarth.vault_reseal', true), '') = 'on';
BEGIN
  IF NEW.password_hash  IS DISTINCT FROM OLD.password_hash
  OR (NOT reseal AND (NEW.totp_secret     IS DISTINCT FROM OLD.totp_secret
                   OR NEW.totp_secret_enc IS DISTINCT FROM OLD.totp_secret_enc))
  OR NEW.totp_enabled   IS DISTINCT FROM OLD.totp_enabled
  OR NEW.is_active      IS DISTINCT FROM OLD.is_active
  OR NEW.foreign_source IS DISTINCT FROM OLD.foreign_source
  OR NEW.foreign_id     IS DISTINCT FROM OLD.foreign_id THEN
    NEW.credential_version := OLD.credential_version + 1;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  // Rolling back once keys exist would lose every secret they protect (V17).
  throw new Error('irreversible: restore the backup taken before the migration');
}

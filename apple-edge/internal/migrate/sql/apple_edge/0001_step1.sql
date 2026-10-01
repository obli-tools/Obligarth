-- apple_edge schema, step 1: tenants, keys, CAs, topics, push certificates,
-- SCEP, device registries, secrets, command view and outbox.
-- Columns named *_enc hold "v1:<kid>:<iv>:<ct>:<tag>" ciphertexts.

CREATE TABLE apple_edge.tenants (
    key              text        PRIMARY KEY CHECK (key ~ '^[a-km-np-z2-9]{16}$'),
    external_ref     uuid        NOT NULL UNIQUE,          -- tenant id on the brain side
    state            text        NOT NULL DEFAULT 'active'
                     CHECK (state IN ('active', 'suspended', 'retiring', 'retired')),
    commands_frozen  boolean     NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    retiring_since   timestamptz,
    retired_at       timestamptz
);

-- Data encryption keys: one active per tenant, one for the instance (tenant_key NULL)
CREATE TABLE apple_edge.data_keys (
    id             uuid        PRIMARY KEY,
    tenant_key     text        REFERENCES apple_edge.tenants (key),
    version        integer     NOT NULL,
    kek_id         text        NOT NULL,
    dek_wrapped    text,                                   -- NULL once destroyed
    state          text        NOT NULL DEFAULT 'active'
                   CHECK (state IN ('active', 'retired', 'destroyed')),
    destroy_after  timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    destroyed_at   timestamptz
);
CREATE UNIQUE INDEX data_keys_version    ON apple_edge.data_keys ((coalesce(tenant_key, '-')), version);
CREATE UNIQUE INDEX data_keys_one_active ON apple_edge.data_keys ((coalesce(tenant_key, '-'))) WHERE state = 'active';

CREATE TABLE apple_edge.instance_secrets (
    name        text        PRIMARY KEY CHECK (name IN ('log_pseudonym_key', 'profile_signing_identity')),
    value_enc   text        NOT NULL,
    cert_pem    text,                                       -- public part when relevant
    not_after   timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE apple_edge.tenant_cas (
    id          uuid        PRIMARY KEY,
    tenant_key  text        NOT NULL REFERENCES apple_edge.tenants (key),
    status      text        NOT NULL CHECK (status IN ('active', 'verify_only', 'retired')),
    cert_pem    text        NOT NULL,
    key_enc     text,                                       -- NULL once retired
    sha256      char(64)    NOT NULL UNIQUE,
    not_after   timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX tenant_cas_one_active ON apple_edge.tenant_cas (tenant_key) WHERE status = 'active';

CREATE TABLE apple_edge.topics (
    topic       text        PRIMARY KEY CHECK (topic LIKE 'com.apple.mgmt.%'),
    tenant_key  text        NOT NULL REFERENCES apple_edge.tenants (key),
    bound_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE apple_edge.push_certs (
    id            uuid        PRIMARY KEY,
    tenant_key    text        NOT NULL REFERENCES apple_edge.tenants (key),
    state         text        NOT NULL
                  CHECK (state IN ('pending', 'active', 'legacy', 'superseded', 'revoked')),
    topic         text        REFERENCES apple_edge.topics (topic),
    csr_pem       text,
    cert_pem      text,
    key_enc       text        NOT NULL,
    not_after     timestamptz,
    stale_token   bigint      NOT NULL DEFAULT 0,          -- bumped on every change
    created_at    timestamptz NOT NULL DEFAULT now(),
    activated_at  timestamptz,
    CHECK (state = 'pending' OR (topic IS NOT NULL AND cert_pem IS NOT NULL))
);
CREATE UNIQUE INDEX push_certs_one_active  ON apple_edge.push_certs (tenant_key) WHERE state = 'active';
CREATE UNIQUE INDEX push_certs_topic_live  ON apple_edge.push_certs (topic) WHERE state IN ('active', 'legacy');
CREATE UNIQUE INDEX push_certs_one_pending ON apple_edge.push_certs (tenant_key) WHERE state = 'pending';

CREATE TABLE apple_edge.scep_challenges (
    id                uuid        PRIMARY KEY,
    tenant_key        text        NOT NULL REFERENCES apple_edge.tenants (key),
    hash              bytea       NOT NULL UNIQUE,          -- SHA-256 of the challenge
    session_ref       text,                                 -- opaque reference from the brain
    bind_udid         text,
    bind_serial       text,
    machine_info_id   uuid,                                 -- step 2: verified MachineInfo
    expires_at        timestamptz NOT NULL,
    used_at           timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scep_challenges_expires ON apple_edge.scep_challenges (expires_at);

CREATE TABLE apple_edge.issued_certs (
    sha256         char(64)    PRIMARY KEY,
    tenant_key     text        NOT NULL REFERENCES apple_edge.tenants (key),
    ca_id          uuid        NOT NULL REFERENCES apple_edge.tenant_cas (id),
    serial_hex     text        NOT NULL,
    challenge_id   uuid        REFERENCES apple_edge.scep_challenges (id),
    not_after      timestamptz NOT NULL,
    revoked_at     timestamptz,
    revoke_reason  text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (ca_id, serial_hex)
);
CREATE INDEX issued_certs_tenant ON apple_edge.issued_certs (tenant_key);

CREATE TABLE apple_edge.device_ids (
    tenant_key      text        NOT NULL REFERENCES apple_edge.tenants (key),
    id_kind         text        NOT NULL CHECK (id_kind IN ('udid', 'enrollment_id')),
    raw_id          text        NOT NULL,
    enrollment_id   text        NOT NULL,
    proof           text        NOT NULL CHECK (proof IN ('none', 'ade')),
    state           text        NOT NULL CHECK (state IN ('active', 'released')),
    since           timestamptz NOT NULL DEFAULT now(),
    released_at     timestamptz,
    release_reason  text CHECK (release_reason IN
        ('checkout', 'retired', 'transfer', 'superseded_by_proof', 'superseded', 'apns_inactive', 'purged')),
    PRIMARY KEY (tenant_key, id_kind, raw_id)
);
CREATE UNIQUE INDEX device_ids_one_active ON apple_edge.device_ids (id_kind, raw_id) WHERE state = 'active';
CREATE INDEX device_ids_enrollment ON apple_edge.device_ids (enrollment_id);

CREATE TABLE apple_edge.transfers (
    id            uuid        PRIMARY KEY,
    id_kind       text        NOT NULL CHECK (id_kind IN ('udid', 'enrollment_id')),
    raw_id        text        NOT NULL,
    from_tenant   text        NOT NULL REFERENCES apple_edge.tenants (key),
    to_tenant     text        NOT NULL REFERENCES apple_edge.tenants (key),
    approval_ref  text        NOT NULL,
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (from_tenant <> to_tenant)
);
CREATE INDEX transfers_lookup ON apple_edge.transfers (id_kind, raw_id, to_tenant) WHERE used_at IS NULL;

CREATE TABLE apple_edge.device_secrets (
    id             uuid        PRIMARY KEY,
    tenant_key     text        NOT NULL REFERENCES apple_edge.tenants (key),
    enrollment_id  text        NOT NULL,
    kind           text        NOT NULL
                   CHECK (kind IN ('unlock_token', 'bootstrap_token', 'activation_lock_bypass_code')),
    value_enc      text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    superseded_at  timestamptz
);
CREATE UNIQUE INDEX device_secrets_current ON apple_edge.device_secrets (enrollment_id, kind)
    WHERE superseded_at IS NULL;

-- Business view of the queue: idempotency, delivery, cancellation, expiry
CREATE TABLE apple_edge.commands (
    command_uuid    text        PRIMARY KEY,
    tenant_key      text        NOT NULL REFERENCES apple_edge.tenants (key),
    request_type    text        NOT NULL,
    body_sha256     char(64)    NOT NULL,
    targets_sha256  char(64)    NOT NULL,
    secret_kind     text,                                   -- e.g. 'unlock_token'
    expires_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX commands_expiry ON apple_edge.commands (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX commands_tenant ON apple_edge.commands (tenant_key, created_at);

CREATE TABLE apple_edge.command_targets (
    command_uuid   text        NOT NULL REFERENCES apple_edge.commands (command_uuid) ON DELETE CASCADE,
    enrollment_id  text        NOT NULL,
    delivered_at   timestamptz,
    completed_at   timestamptz,                             -- Acknowledged, Error, CommandFormatError
    cancelled_at   timestamptz,
    expired_at     timestamptz,
    PRIMARY KEY (command_uuid, enrollment_id)
);
CREATE INDEX command_targets_open ON apple_edge.command_targets (command_uuid)
    WHERE completed_at IS NULL AND cancelled_at IS NULL AND expired_at IS NULL;
CREATE INDEX command_targets_enrollment ON apple_edge.command_targets (enrollment_id);

CREATE TABLE apple_edge.outbox (
    seq             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id        uuid        NOT NULL UNIQUE,
    schema_version  smallint    NOT NULL DEFAULT 1,
    scope           text        NOT NULL CHECK (scope IN ('tenant', 'platform')),
    tenant_key      text,                                   -- NULL for platform scope; no FK on purpose
    type            text        NOT NULL,
    enrollment_id   text,
    command_uuid    text,
    request_id      text,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    payload         jsonb       NOT NULL,
    consumed_at     timestamptz,
    CHECK ((scope = 'tenant') = (tenant_key IS NOT NULL))
);
CREATE INDEX outbox_pending  ON apple_edge.outbox (seq) WHERE consumed_at IS NULL;
CREATE INDEX outbox_consumed ON apple_edge.outbox (consumed_at) WHERE consumed_at IS NOT NULL;

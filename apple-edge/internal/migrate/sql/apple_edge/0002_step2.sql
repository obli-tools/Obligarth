-- apple_edge schema, step 2: ADE tokens, profiles and devices, MachineInfo
-- checks, APNs inactivity proofs and expiry alerts.

CREATE TABLE apple_edge.ade_tokens (
    id                 uuid        PRIMARY KEY,
    tenant_key         text        NOT NULL REFERENCES apple_edge.tenants (key),
    state              text        NOT NULL CHECK (state IN
        ('awaiting_token', 'active', 'terms_not_signed', 'expired', 'error', 'removed')),
    tokenpki_cert_pem  text        NOT NULL,
    tokenpki_key_enc   text,                                -- NULL once removed
    oauth_enc          text,                                -- the 4 OAuth 1.0a secrets, JSON, encrypted
    token_not_after    timestamptz,
    server_name        text,
    server_uuid        text,
    last_sync_at       timestamptz,
    last_fetch_at      timestamptz,                         -- last complete fetch (cursor age)
    consecutive_errors integer     NOT NULL DEFAULT 0,
    last_error         text,                                -- error code only, no payload
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CHECK (state = 'removed' OR tokenpki_key_enc IS NOT NULL),
    CHECK (state <> 'removed' OR (tokenpki_key_enc IS NULL AND oauth_enc IS NULL))
);
CREATE INDEX ade_tokens_tenant ON apple_edge.ade_tokens (tenant_key);

CREATE TABLE apple_edge.ade_profiles (
    token_id      uuid        NOT NULL REFERENCES apple_edge.ade_tokens (id),
    usage         text        NOT NULL CHECK (usage ~ '^[a-z][a-z0-9_]{0,31}$'),
    profile_json  jsonb       NOT NULL,
    profile_uuid  text,
    is_default    boolean     NOT NULL DEFAULT false,
    defined_at    timestamptz,
    PRIMARY KEY (token_id, usage)
);
CREATE UNIQUE INDEX ade_profiles_one_default ON apple_edge.ade_profiles (token_id) WHERE is_default;

CREATE TABLE apple_edge.ade_devices (
    token_id        uuid        NOT NULL REFERENCES apple_edge.ade_tokens (id),
    serial          text        NOT NULL,
    tenant_key      text        NOT NULL,
    op_type         text,
    op_date         timestamptz,
    profile_uuid    text,
    profile_status  text,
    wanted_usage    text,                                   -- NULL: default profile
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (token_id, serial)
);
CREATE INDEX ade_devices_serial ON apple_edge.ade_devices (serial);
CREATE INDEX ade_devices_tenant ON apple_edge.ade_devices (tenant_key, serial);

CREATE TABLE apple_edge.machine_info_checks (
    id          uuid        PRIMARY KEY,
    tenant_key  text        NOT NULL REFERENCES apple_edge.tenants (key),
    udid        text        NOT NULL,
    serial      text        NOT NULL,
    token_id    uuid        REFERENCES apple_edge.ade_tokens (id),   -- NULL: serial not in the tenant
    verified_at timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX machine_info_checks_expires ON apple_edge.machine_info_checks (expires_at);
CREATE INDEX scep_challenges_machine_info ON apple_edge.scep_challenges (machine_info_id) WHERE machine_info_id IS NOT NULL;

-- APNs proof of inactivity (410, or 400 BadDeviceToken) for a device
-- channel; the identifier is released after EDGE_RELEASE_AFTER_410 without
-- any check-in since the report.
CREATE TABLE apple_edge.apns_inactive (
    enrollment_id   text        PRIMARY KEY,
    tenant_key      text        NOT NULL REFERENCES apple_edge.tenants (key),
    reason          text        NOT NULL CHECK (reason IN ('unregistered', 'bad_device_token')),
    apns_timestamp  timestamptz,
    reported_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX apns_inactive_tenant ON apple_edge.apns_inactive (tenant_key);

-- Expiry thresholds already reported (push certificates, ADE tokens).
CREATE TABLE apple_edge.expiry_alerts (
    tenant_key  text        NOT NULL REFERENCES apple_edge.tenants (key),
    subject     text        NOT NULL CHECK (subject ~ '^(push_cert|ade_token):[0-9a-f-]{36}$'),
    threshold   integer     NOT NULL CHECK (threshold >= 0),   -- days before expiry; 0: expired
    emitted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, threshold)
);
CREATE INDEX expiry_alerts_tenant ON apple_edge.expiry_alerts (tenant_key);

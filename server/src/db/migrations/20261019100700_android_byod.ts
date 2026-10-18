import type { Knex } from 'knex';

// =============================================================================
// Android, part 8: BYOD by link (lot AN-F1; android-amapi §10.1, §10.5, criterion 6)
// =============================================================================
//   - android_byod_invitations (class tenant): the invitation of an end user to enroll a personal device: single use,
//     7 days at most (AN17), its code stored hashed (SHA-256 of 'oai:<tenants.uuid>:<code>', the code shown once to
//     the administrator), the acknowledgement of the notice shown by the device surface before the Google link
//     (version, time, language: USR-01), the enrollment token created at Google once the notice is acknowledged, the
//     device enrolled with it;
//   - android_byod_attempts (class tenant): wrong codes per tenant and per hour (the device surface refuses every code
//     of the tenant beyond ANDROID_BYOD_WRONG_CODES_PER_HOUR until the hour ends).
// enrollment_tokens (lot C) is not used: its CHECKs admit neither the Android profiles nor an invitation without a
// Managed Apple Account, and the branch alters no existing table. New tables only: nothing existing is altered.
// Runs as obligarth_owner (server-migrate); ends with obligarth.rls_assert_clean(). No question mark in the SQL
// (knex.raw would bind it).

const UP = String.raw`-- =============================================================================
-- Android, part 8: BYOD by link (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_enrollment_tokens') IS NULL OR to_regclass('obligarth.enrollment_profiles') IS NULL
     OR to_regclass('obligarth.end_users') IS NULL THEN
    RAISE EXCEPTION 'android_byod: apply apple_enrollment and android_devices first';
  END IF;
END $$;

-- ── android_byod_invitations ────────────────────────────────────────────────────
CREATE TABLE obligarth.android_byod_invitations (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          integer NOT NULL DEFAULT obligarth.ctx_tenant()
                       REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  enterprise_id      integer NOT NULL,
  profile_id         uuid NOT NULL,
  end_user_id        integer NOT NULL,                 -- a BYOD link is bound to an end user (section 10.1)
  code_hash          varchar(64) NOT NULL,             -- SHA-256 (hex) of 'oai:<tenants.uuid>:<code>'
  prefix             varchar(12) NOT NULL,             -- displayable: 'oai_' and two characters of the code
  label              varchar(200),
  locale             varchar(8) NOT NULL DEFAULT 'fr',
  state              varchar(12) NOT NULL DEFAULT 'active',
  expires_at         timestamptz NOT NULL,
  notice_version_id  uuid,                             -- USR-01: the version acknowledged
  notice_ack_id      uuid,
  acknowledged_at    timestamptz,
  ack_locale         varchar(8),
  issuing_at         timestamptz,                      -- the creation of the token started (state issuing)
  token_id           uuid,                             -- android_enrollment_tokens.id (kind byod_link)
  device_id          integer,
  used_at            timestamptz,
  revoked_at         timestamptz,
  revoked_by         integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_by         integer REFERENCES obligarth.users (id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT android_byod_invitations_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT android_byod_invitations_enterprise_fk FOREIGN KEY (tenant_id, enterprise_id)
    REFERENCES obligarth.android_enterprises (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_byod_invitations_profile_fk FOREIGN KEY (tenant_id, profile_id)
    REFERENCES obligarth.enrollment_profiles (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_byod_invitations_end_user_fk FOREIGN KEY (tenant_id, end_user_id)
    REFERENCES obligarth.end_users (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT android_byod_invitations_token_fk FOREIGN KEY (tenant_id, token_id)
    REFERENCES obligarth.android_enrollment_tokens (tenant_id, id) ON DELETE SET NULL (token_id),
  CONSTRAINT android_byod_invitations_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (device_id),
  CONSTRAINT android_byod_invitations_state_check
    CHECK (state IN ('active', 'issuing', 'issued', 'used', 'revoked', 'expired')),
  CONSTRAINT android_byod_invitations_code_hash_check CHECK (code_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT android_byod_invitations_prefix_check CHECK (prefix ~ '^oai_[a-z2-9]{2}$'),
  CONSTRAINT android_byod_invitations_locale_check CHECK (locale IN ('fr', 'en') AND (ack_locale IS NULL OR ack_locale IN ('fr', 'en'))),
  -- 7 days at most (AN17), a few seconds of tolerance for the clocks of the transaction.
  CONSTRAINT android_byod_invitations_ttl_check CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days 1 minute'),
  -- Nothing reaches the device before the notice is acknowledged: issuing, issued and used carry the acknowledgement.
  CONSTRAINT android_byod_invitations_ack_check CHECK (state IN ('active', 'revoked', 'expired')
    OR (notice_version_id IS NOT NULL AND acknowledged_at IS NOT NULL AND ack_locale IS NOT NULL)),
  CONSTRAINT android_byod_invitations_ack_whole CHECK ((notice_version_id IS NULL) = (acknowledged_at IS NULL)),
  CONSTRAINT android_byod_invitations_issuing_check CHECK ((state = 'issuing') = (issuing_at IS NOT NULL)),
  CONSTRAINT android_byod_invitations_issued_check CHECK (state <> 'issued' OR token_id IS NOT NULL),
  CONSTRAINT android_byod_invitations_used_check CHECK ((state = 'used') = (used_at IS NOT NULL)),
  CONSTRAINT android_byod_invitations_revoked_check CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX android_byod_invitations_code ON obligarth.android_byod_invitations (code_hash);
CREATE UNIQUE INDEX android_byod_invitations_token ON obligarth.android_byod_invitations (token_id) WHERE token_id IS NOT NULL;
CREATE INDEX android_byod_invitations_open ON obligarth.android_byod_invitations (tenant_id, state, expires_at)
  WHERE state IN ('active', 'issuing', 'issued');
CREATE INDEX android_byod_invitations_user ON obligarth.android_byod_invitations (tenant_id, end_user_id);
SELECT obligarth_private.rls_apply('obligarth.android_byod_invitations', 'tenant', 'android (lot AN-F1): BYOD invitations by link');

-- ── android_byod_attempts ───────────────────────────────────────────────────────
CREATE TABLE obligarth.android_byod_attempts (
  tenant_id     integer NOT NULL DEFAULT obligarth.ctx_tenant()
                  REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  hour_start    timestamptz NOT NULL,
  wrong_codes   integer NOT NULL DEFAULT 0,
  alerted       boolean NOT NULL DEFAULT false,
  CONSTRAINT android_byod_attempts_pkey PRIMARY KEY (tenant_id, hour_start),
  CONSTRAINT android_byod_attempts_count_check CHECK (wrong_codes BETWEEN 0 AND 1000000),
  CONSTRAINT android_byod_attempts_hour_check CHECK (date_trunc('hour', hour_start AT TIME ZONE 'UTC') = hour_start AT TIME ZONE 'UTC')
);
SELECT obligarth_private.rls_apply('obligarth.android_byod_attempts', 'tenant', 'android (lot AN-F1): wrong BYOD codes per hour');

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}

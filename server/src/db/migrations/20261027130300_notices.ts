import type { Knex } from 'knex';

// =============================================================================
// Notice of the employees (P0-13 T5, USR-01; conception §10.3; M3 of the spec)
// =============================================================================
//   - tenant_notice_settings (class tenant): one row per tenant, the settings of its notice (data controller, its
//     address, DPO, contact, other recipients, a paragraph per language). Plain text: no angle bracket, no control
//     character (but the line feed and the tab of the multi-line fields); the lengths of NOTICE_SETTINGS_FIELDS
//     (shared/src/privacy.ts); an empty value is NULL. version counts the changes (a trigger moves it at each update
//     of the content, with updated_at). Written by the console (P0-13 T6, capability mdm.privacy.manage, D3).
//   - notice_versions (class tenant): the generated notices, immutable. One per platform, ownership, language and
//     content (content_sha256: SHA-256 of content::text, computed by notice_ensure); the current one of a platform,
//     ownership and language is the one not superseded (notice_versions_current). content holds the sections of an
//     EnrollmentNotice (title, sections, consentSummary of 500 characters at most, contact); the inputs it was first
//     generated from: the version of the privacy profile of the ownership (NULL: the defaults), of the settings (0: none),
//     of the retention (0: never set), of the generator. The runtime role reads only: notice_ensure is the only writer.
//   - obligarth.notice_ensure(platform, ownership, locale, content, profile, settings_version, retention_version,
//     generator): in the tenant's context, the current version of these platform, ownership and language when its
//     content is this one (published false), else this content becomes the current version (published true): a new
//     row, or the earlier row of the same content when the inputs came back to it (its supersession lifted), the
//     previous current version superseded. One publication at a time per tenant, platform, ownership and language
//     (advisory lock).
//   - notice_acknowledgements (class tenant): one row per acknowledgement of a version (USR-01), from an Apple
//     enrollment session, a BYOD invitation or a sign-in session of Android (subject_ref: its id), with the end user and
//     the device when known (SET NULL when they go), the language, the instant. Neither address nor user agent
//     (minimisation). Kept notice_ack_months of the tenant (36 by default, D5; privacy.retention-tenant). No foreign key
//     from enrollment_sessions.notice_ack_id: the sessions go after 30 days, the acknowledgements stay. The runtime role
//     inserts and purges; it updates the end user and the device only.
//   The foreign keys towards notice_versions and privacy_profile_versions are NO ACTION (checked at the end of the
//     statement), not RESTRICT: a version acknowledged is never deleted alone, and the deletion of a tenant
//     (obligarth.tenant_delete, cascade) removes its acknowledgements and its versions in one statement.
// Rules of the specs README §3: SQL by String.raw, no question mark, rls_apply for each table, rls_assert_clean()
// last. Runs as obligarth_owner (server-migrate), after retention_policies.
// =============================================================================

const UP = String.raw`-- =============================================================================
-- Notice of the employees (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regprocedure('obligarth_private.rls_apply(regclass, text, text)') IS NULL
     OR to_regclass('obligarth.privacy_profile_versions') IS NULL
     OR to_regclass('obligarth.tenant_retention_policies') IS NULL
     OR to_regclass('obligarth.end_users') IS NULL
     OR to_regclass('obligarth.devices') IS NULL THEN
    RAISE EXCEPTION 'notices: apply the RLS migrations, privacy_profiles and retention_policies first';
  END IF;
END $$;

-- 1. tenant_notice_settings ------------------------------------------------------------
CREATE TABLE obligarth.tenant_notice_settings (
  tenant_id          integer        NOT NULL DEFAULT obligarth.ctx_tenant(),
  controller_name    varchar(200),
  controller_address varchar(500),
  dpo_contact        varchar(300),
  contact            varchar(300),
  recipients_extra   varchar(1000),
  intro_fr           varchar(2000),
  intro_en           varchar(2000),
  version            integer        NOT NULL DEFAULT 1,     -- changes (moved by tenant_notice_settings_version)
  updated_by         integer,
  updated_at         timestamptz    NOT NULL DEFAULT now(),
  CONSTRAINT tenant_notice_settings_pkey PRIMARY KEY (tenant_id),
  CONSTRAINT tenant_notice_settings_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT tenant_notice_settings_updated_by_foreign FOREIGN KEY (updated_by)
    REFERENCES obligarth.users (id) ON DELETE SET NULL,
  CONSTRAINT tenant_notice_settings_version_check CHECK (version >= 1),
  -- An empty value is NULL.
  CONSTRAINT tenant_notice_settings_not_blank CHECK (
        (controller_name IS NULL OR btrim(controller_name) <> '')
    AND (controller_address IS NULL OR btrim(controller_address) <> '')
    AND (dpo_contact IS NULL OR btrim(dpo_contact) <> '')
    AND (contact IS NULL OR btrim(contact) <> '')
    AND (recipients_extra IS NULL OR btrim(recipients_extra) <> '')
    AND (intro_fr IS NULL OR btrim(intro_fr) <> '')
    AND (intro_en IS NULL OR btrim(intro_en) <> '')),
  -- Plain text (noticeSettingsErrors of shared/src/privacy.ts): no angle bracket; a single-line field holds no control
  -- character, a multi-line one the line feed and the tab only.
  CONSTRAINT tenant_notice_settings_plain_text CHECK (
        COALESCE(controller_name !~ '[<>\x01-\x1f\x7f]', true)
    AND COALESCE(dpo_contact !~ '[<>\x01-\x1f\x7f]', true)
    AND COALESCE(contact !~ '[<>\x01-\x1f\x7f]', true)
    AND COALESCE(controller_address !~ '[<>\x01-\x08\x0b-\x1f\x7f]', true)
    AND COALESCE(recipients_extra !~ '[<>\x01-\x08\x0b-\x1f\x7f]', true)
    AND COALESCE(intro_fr !~ '[<>\x01-\x08\x0b-\x1f\x7f]', true)
    AND COALESCE(intro_en !~ '[<>\x01-\x08\x0b-\x1f\x7f]', true))
);
SELECT obligarth_private.rls_apply('obligarth.tenant_notice_settings', 'tenant',
  'settings of the employee notice (USR-01): data controller, DPO, contacts, recipients, paragraphs');

-- Each change moves the version and the instant (the notices name the version they were generated from). Only a change
-- of the content does: the SET NULL of updated_by, when its user goes, is not a change of the settings. Neither the
-- version nor the instant is ever written directly.
CREATE FUNCTION obligarth_private.tenant_notice_settings_version() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF (OLD.controller_name, OLD.controller_address, OLD.dpo_contact, OLD.contact, OLD.recipients_extra, OLD.intro_fr, OLD.intro_en)
     IS DISTINCT FROM
     (NEW.controller_name, NEW.controller_address, NEW.dpo_contact, NEW.contact, NEW.recipients_extra, NEW.intro_fr, NEW.intro_en) THEN
    NEW.version := OLD.version + 1;
    NEW.updated_at := now();
  ELSE
    NEW.version := OLD.version;
    NEW.updated_at := OLD.updated_at;
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION obligarth_private.tenant_notice_settings_version() FROM PUBLIC;
CREATE TRIGGER tenant_notice_settings_version BEFORE UPDATE ON obligarth.tenant_notice_settings
  FOR EACH ROW EXECUTE FUNCTION obligarth_private.tenant_notice_settings_version();

-- 2. notice_versions -------------------------------------------------------------------
CREATE TABLE obligarth.notice_versions (
  tenant_id                  integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  id                         uuid         NOT NULL DEFAULT gen_random_uuid(),
  platform                   varchar(16)  NOT NULL,
  ownership                  varchar(24)  NOT NULL,
  locale                     varchar(5)   NOT NULL,
  content                    jsonb        NOT NULL,          -- title, sections, consentSummary, contact
  content_sha256             char(64)     NOT NULL,
  privacy_profile_version_id uuid,                           -- NULL: the default profile
  settings_version           integer      NOT NULL,          -- 0: no settings
  retention_version          integer      NOT NULL,          -- 0: the retention never set
  generator_version          integer      NOT NULL,
  generated_at               timestamptz  NOT NULL DEFAULT now(),
  superseded_at              timestamptz,
  CONSTRAINT notice_versions_pkey PRIMARY KEY (id),
  CONSTRAINT notice_versions_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT notice_versions_content_uq UNIQUE (tenant_id, platform, ownership, locale, content_sha256),
  CONSTRAINT notice_versions_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT notice_versions_profile_tenant_fk FOREIGN KEY (tenant_id, privacy_profile_version_id)
    REFERENCES obligarth.privacy_profile_versions (tenant_id, id),
  CONSTRAINT notice_versions_platform_check CHECK (platform IN ('apple', 'android')),
  CONSTRAINT notice_versions_ownership_check CHECK (ownership IN ('corporate', 'corporate_personal', 'personal')),
  CONSTRAINT notice_versions_locale_check CHECK (locale IN ('fr', 'en')),
  CONSTRAINT notice_versions_sha_check CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT notice_versions_inputs_check CHECK (settings_version >= 0 AND retention_version >= 0 AND generator_version >= 1),
  CONSTRAINT notice_versions_superseded_after CHECK (superseded_at IS NULL OR superseded_at >= generated_at),
  -- The sections of an EnrollmentNotice (apple/enrollment/notice.ts), 64 KiB at most, and no other key.
  CONSTRAINT notice_versions_content_shape CHECK (
        COALESCE(jsonb_typeof(content) = 'object', false)
    AND COALESCE((content - ARRAY['title', 'sections', 'consentSummary', 'contact']::text[]) = '{}'::jsonb, false)
    AND COALESCE(jsonb_typeof(content -> 'title') = 'string', false)
    AND COALESCE(jsonb_typeof(content -> 'sections') = 'array', false)
    AND COALESCE(jsonb_typeof(content -> 'consentSummary') = 'string', false)
    AND COALESCE(char_length(content ->> 'consentSummary') <= 500, false)
    AND COALESCE(jsonb_typeof(content -> 'contact') IN ('string', 'null'), false)
    AND octet_length(content::text) <= 65536)
);
CREATE UNIQUE INDEX notice_versions_current ON obligarth.notice_versions (tenant_id, platform, ownership, locale)
  WHERE superseded_at IS NULL;
SELECT obligarth_private.rls_apply('obligarth.notice_versions', 'tenant',
  'employee notices (USR-01): immutable generated versions, written by notice_ensure only');
-- Immutable for the runtime role: read only (the insertion and the supersession go through notice_ensure).
REVOKE INSERT, UPDATE, DELETE ON obligarth.notice_versions FROM obligarth;

-- 3. Publication ----------------------------------------------------------------------
CREATE FUNCTION obligarth.notice_ensure(p_platform text, p_ownership text, p_locale text, p_content jsonb, p_profile uuid,
  p_settings_version integer, p_retention_version integer, p_generator integer)
  RETURNS TABLE (notice_id uuid, published boolean, previous_id uuid, content_sha text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '5s' AS $$
DECLARE
  v_tenant  integer := obligarth.ctx_tenant();
  v_sha     text;
  v_cur     uuid;
  v_cur_sha text;
  v_same    uuid;
  v_id      uuid;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'notice_ensure: the tenant''s context is required';
  END IF;
  IF p_content IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '22004', MESSAGE = 'notice_ensure: no content';
  END IF;
  -- The profile named is one of the tenant's for this ownership (the foreign key checks the tenant).
  IF p_profile IS NOT NULL AND NOT EXISTS (SELECT 1 FROM obligarth.privacy_profile_versions p
                                            WHERE p.tenant_id = v_tenant AND p.id = p_profile AND p.ownership = p_ownership) THEN
    RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'notice_ensure: the privacy profile is not one of this ownership';
  END IF;
  v_sha := encode(sha256(convert_to(p_content::text, 'UTF8')), 'hex');

  -- The current version holds this content: nothing to publish (the common case, no lock).
  SELECT v.id, v.content_sha256 INTO v_cur, v_cur_sha
    FROM obligarth.notice_versions v
   WHERE v.tenant_id = v_tenant AND v.platform = p_platform AND v.ownership = p_ownership AND v.locale = p_locale
     AND v.superseded_at IS NULL;
  IF v_cur IS NOT NULL AND v_cur_sha = v_sha THEN
    RETURN QUERY SELECT v_cur, false, NULL::uuid, v_sha;
    RETURN;
  END IF;

  -- One publication at a time per tenant, platform, ownership and language; read again under the lock.
  PERFORM pg_advisory_xact_lock(hashtext('obligarth.notice_ensure'),
    hashtext(v_tenant::text || ':' || p_platform || ':' || p_ownership || ':' || p_locale));
  SELECT v.id, v.content_sha256 INTO v_cur, v_cur_sha
    FROM obligarth.notice_versions v
   WHERE v.tenant_id = v_tenant AND v.platform = p_platform AND v.ownership = p_ownership AND v.locale = p_locale
     AND v.superseded_at IS NULL
     FOR UPDATE;
  IF v_cur IS NOT NULL AND v_cur_sha = v_sha THEN
    RETURN QUERY SELECT v_cur, false, NULL::uuid, v_sha;
    RETURN;
  END IF;
  SELECT v.id INTO v_same
    FROM obligarth.notice_versions v
   WHERE v.tenant_id = v_tenant AND v.platform = p_platform AND v.ownership = p_ownership AND v.locale = p_locale
     AND v.content_sha256 = v_sha
     FOR UPDATE;
  IF v_cur IS NOT NULL THEN
    UPDATE obligarth.notice_versions v SET superseded_at = greatest(now(), v.generated_at)
     WHERE v.tenant_id = v_tenant AND v.id = v_cur;
  END IF;
  IF v_same IS NOT NULL THEN
    -- The inputs came back to an earlier content: that version is current again (its acknowledgements still point to
    -- the same text).
    UPDATE obligarth.notice_versions v SET superseded_at = NULL WHERE v.tenant_id = v_tenant AND v.id = v_same;
    v_id := v_same;
  ELSE
    INSERT INTO obligarth.notice_versions
      (tenant_id, platform, ownership, locale, content, content_sha256, privacy_profile_version_id, settings_version,
       retention_version, generator_version)
    VALUES (v_tenant, p_platform, p_ownership, p_locale, p_content, v_sha, p_profile, COALESCE(p_settings_version, 0),
       COALESCE(p_retention_version, 0), p_generator)
    RETURNING id INTO v_id;
  END IF;
  RETURN QUERY SELECT v_id, true, v_cur, v_sha;
END $$;

REVOKE ALL ON FUNCTION obligarth.notice_ensure(text, text, text, jsonb, uuid, integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.notice_ensure(text, text, text, jsonb, uuid, integer, integer, integer) TO obligarth;
COMMENT ON FUNCTION obligarth.notice_ensure(text, text, text, jsonb, uuid, integer, integer, integer) IS
  'employee notices (USR-01): the current version of a platform, ownership and language, published when its content changed';

-- 4. notice_acknowledgements ------------------------------------------------------------
CREATE TABLE obligarth.notice_acknowledgements (
  tenant_id         integer      NOT NULL DEFAULT obligarth.ctx_tenant(),
  id                uuid         NOT NULL DEFAULT gen_random_uuid(),
  notice_version_id uuid         NOT NULL,
  channel           varchar(32)  NOT NULL,
  subject_ref       uuid         NOT NULL,                   -- the session or the invitation
  end_user_id       integer,
  device_id         integer,
  locale            varchar(5)   NOT NULL,
  acknowledged_at   timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT notice_acknowledgements_pkey PRIMARY KEY (id),
  CONSTRAINT notice_acknowledgements_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT notice_acknowledgements_tenant_id_foreign FOREIGN KEY (tenant_id)
    REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  CONSTRAINT notice_acknowledgements_version_tenant_fk FOREIGN KEY (tenant_id, notice_version_id)
    REFERENCES obligarth.notice_versions (tenant_id, id),
  CONSTRAINT notice_acknowledgements_end_user_tenant_fk FOREIGN KEY (tenant_id, end_user_id)
    REFERENCES obligarth.end_users (tenant_id, id) ON DELETE SET NULL (end_user_id),
  CONSTRAINT notice_acknowledgements_device_tenant_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE SET NULL (device_id),
  CONSTRAINT notice_acknowledgements_channel_check CHECK (channel IN ('apple_session', 'android_byod_invitation', 'android_signin')),
  CONSTRAINT notice_acknowledgements_locale_check CHECK (locale IN ('fr', 'en'))
);
CREATE INDEX notice_acknowledgements_purge ON obligarth.notice_acknowledgements (tenant_id, acknowledged_at);
CREATE INDEX notice_acknowledgements_version ON obligarth.notice_acknowledgements (tenant_id, notice_version_id);
CREATE INDEX notice_acknowledgements_subject ON obligarth.notice_acknowledgements (tenant_id, subject_ref);
-- The SET NULL of the end user and of the device find their rows by these (the purge of the end users goes by slices).
CREATE INDEX notice_acknowledgements_end_user ON obligarth.notice_acknowledgements (tenant_id, end_user_id)
  WHERE end_user_id IS NOT NULL;
CREATE INDEX notice_acknowledgements_device ON obligarth.notice_acknowledgements (tenant_id, device_id)
  WHERE device_id IS NOT NULL;
SELECT obligarth_private.rls_apply('obligarth.notice_acknowledgements', 'tenant',
  'acknowledgements of the employee notice (USR-01): inserted, linked to the end user and the device, purged');
-- An acknowledgement is not rewritten: only its end user and its device are set afterwards.
REVOKE UPDATE ON obligarth.notice_acknowledgements FROM obligarth;
GRANT UPDATE (end_user_id, device_id) ON obligarth.notice_acknowledgements TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.notice_ensure', 'definer', 'tenant context; current notice version, published when its content changed')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}

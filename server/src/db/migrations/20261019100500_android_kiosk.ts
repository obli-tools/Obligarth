import type { Knex } from 'knex';

// =============================================================================
// Android, part 6a: kiosk exits (lot AN-G1, android-amapi §9.7)
// =============================================================================
//   - android_kiosk_exits (class tenant): the temporary exit of the kiosk of a dedicated device, granted by the
//     guarded action mdm.android_kiosk_exit (one row per action and device): while it runs, the device's own policy is
//     compiled without its kiosk lock; it ends by itself at expires_at (8 hours after its start at most, a CHECK of
//     the base as the last barrier), by the operator, or when the device leaves management. One running exit per
//     device (unique partial index). Review AN-G1 (G1-R1): an exit also ends when the tenant is frozen (the safest
//     state first) or when the device's policy comes to carry a wipe-capable setting; the end of an exit is not the
//     return of the lock: lock_restored_at is set when Google accepts the policy that holds the lock again, and the
//     push is sent again (lock_retry_at, every 15 minutes) until it is;
//   - function android_kiosk_due() (SECURITY DEFINER, context none of android.maintenance): the tenants with a
//     running exit past its end, whose device left management, or of a frozen tenant (the lock is then pushed back),
//     and the tenants with an ended exit whose lock is still pending (its push sent again).
// New table and function only. Runs as obligarth_owner (server-migrate); ends with obligarth.rls_assert_clean(). No
// question mark in the SQL.

const END_REASONS = ['operator', 'expired', 'device_left', 'frozen', 'wipe_policy'];
const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

const UP = String.raw`-- =============================================================================
-- Android, part 6a: kiosk exits (run as obligarth_owner)
-- =============================================================================
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF to_regclass('obligarth.android_devices') IS NULL THEN
    RAISE EXCEPTION 'android_kiosk: apply android_devices first';
  END IF;
END $$;

CREATE TABLE obligarth.android_kiosk_exits (
  id                 uuid          NOT NULL,
  tenant_id          integer       NOT NULL DEFAULT obligarth.ctx_tenant()
                       REFERENCES obligarth.tenants (id) ON DELETE CASCADE,
  device_id          integer       NOT NULL,
  guard_action_uuid  uuid          NOT NULL,              -- pending_actions.uuid of mdm.android_kiosk_exit
  requested_by       integer       REFERENCES obligarth.users (id) ON DELETE SET NULL,
  started_at         timestamptz   NOT NULL DEFAULT now(),
  expires_at         timestamptz   NOT NULL,
  ended_at           timestamptz,
  end_reason         varchar(16),
  ended_by           integer       REFERENCES obligarth.users (id) ON DELETE SET NULL,
  lock_restored_at   timestamptz,                          -- Google accepted the policy with the lock again
  lock_retry_at      timestamptz,                          -- next push of the lock while it is pending
  created_at         timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT android_kiosk_exits_pkey PRIMARY KEY (id),
  CONSTRAINT android_kiosk_exits_tenant_id_id_unique UNIQUE (tenant_id, id),
  CONSTRAINT android_kiosk_exits_device_fk FOREIGN KEY (tenant_id, device_id)
    REFERENCES obligarth.devices (tenant_id, id) ON DELETE CASCADE,
  -- 5 minutes to 8 hours (ANDROID_KIOSK_EXIT_MINUTES): the lock always comes back by itself.
  CONSTRAINT android_kiosk_exits_duration_check CHECK (expires_at >= started_at + interval '5 minutes'
    AND expires_at <= started_at + interval '8 hours'),
  CONSTRAINT android_kiosk_exits_end_check CHECK ((ended_at IS NULL) = (end_reason IS NULL)
    AND (end_reason IS NULL OR end_reason IN (${list(END_REASONS)}))),
  CONSTRAINT android_kiosk_exits_ended_after_check CHECK (ended_at IS NULL OR ended_at >= started_at),
  CONSTRAINT android_kiosk_exits_lock_check CHECK (lock_restored_at IS NULL OR ended_at IS NOT NULL)
);
CREATE UNIQUE INDEX android_kiosk_exits_open ON obligarth.android_kiosk_exits (tenant_id, device_id) WHERE ended_at IS NULL;
CREATE UNIQUE INDEX android_kiosk_exits_action ON obligarth.android_kiosk_exits (tenant_id, guard_action_uuid, device_id);
CREATE INDEX android_kiosk_exits_due ON obligarth.android_kiosk_exits (expires_at) WHERE ended_at IS NULL;
CREATE INDEX android_kiosk_exits_device ON obligarth.android_kiosk_exits (tenant_id, device_id, started_at);
CREATE INDEX android_kiosk_exits_lock_pending ON obligarth.android_kiosk_exits (lock_retry_at)
  WHERE ended_at IS NOT NULL AND lock_restored_at IS NULL AND end_reason <> 'device_left';
SELECT obligarth_private.rls_apply('obligarth.android_kiosk_exits', 'tenant', 'android: kiosk exits of dedicated devices (lot AN-G1)');

-- Tenants with a running kiosk exit past its end, whose device left management or of a frozen tenant, and tenants
-- with an ended exit whose lock is still pending past its retry time (context 'none'; tenant ids only).
CREATE FUNCTION obligarth.android_kiosk_due()
  RETURNS TABLE (tenant_id integer)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
  IF obligarth.ctx_kind() IS DISTINCT FROM 'none'
     OR NOT (obligarth.ctx_actor() = 'j:android.maintenance' OR obligarth.ctx_actor_is_platform_admin()) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'android_kiosk_due: context none of the maintenance required';
  END IF;
  RETURN QUERY
  SELECT DISTINCT k.tenant_id
    FROM obligarth.android_kiosk_exits k
    LEFT JOIN obligarth.android_devices a ON a.tenant_id = k.tenant_id AND a.device_id = k.device_id
   WHERE (k.ended_at IS NULL
          AND (k.expires_at <= now() OR a.device_id IS NULL OR a.released_at IS NOT NULL
               OR EXISTS (SELECT 1 FROM obligarth.tenant_guard_settings g
                           WHERE g.tenant_id = k.tenant_id AND g.frozen_at IS NOT NULL)))
      OR (k.ended_at IS NOT NULL AND k.lock_restored_at IS NULL AND k.end_reason <> 'device_left'
          AND a.device_id IS NOT NULL AND a.released_at IS NULL
          AND COALESCE(k.lock_retry_at, k.ended_at + interval '10 minutes') <= now())
   ORDER BY 1;
END $$;
REVOKE ALL ON FUNCTION obligarth.android_kiosk_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION obligarth.android_kiosk_due() TO obligarth;

INSERT INTO obligarth_private.rls_registry (object_kind, object_name, rls_class, note) VALUES
  ('function', 'obligarth.android_kiosk_due', 'definer', 'android maintenance: tenants with kiosk exits to end')
ON CONFLICT (object_kind, object_name) DO UPDATE SET rls_class = EXCLUDED.rls_class, note = EXCLUDED.note;

SELECT obligarth.rls_assert_clean();
`;

export async function up(knex: Knex): Promise<void> {
  await knex.raw(UP);
}

export async function down(): Promise<void> {
  throw new Error('irreversible: restore the backup taken before the upgrade');
}

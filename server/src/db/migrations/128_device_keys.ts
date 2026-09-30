import type { Knex } from 'knex';

// Device-bound 2FA — keys, challenges and the credential version
// (docs/mobile/device-bound-2fa.md §5.2, lot S1).
//
// users.credential_version   bumped by a BEFORE UPDATE trigger whenever the
//                            password, the TOTP secret / activation, the
//                            account activation or the SSO identity changes
//                            (R8, [D8]). A key stores the version it was
//                            enrolled under; any difference at use revokes
//                            it ('credentials_changed'), even when the change
//                            came through a path without a revocation hook,
//                            and even after a code rollback (the trigger
//                            stays in the database).
// user_device_keys           one row per (user, server origin, app install):
//                            P-256 public key (SPKI DER) only, attested
//                            level, status. No tenant column: keys belong to
//                            the platform user (like user_ssh_keys).
// device_key_challenges      single-use challenges (stepup / login) and
//                            enrolment tickets (enrol), bound to the session
//                            (sha256 of its id), the tenant and the request
//                            binding; consumed by one atomic UPDATE.
//
// Idempotent (hasColumn / hasTable guards, CREATE OR REPLACE, DROP TRIGGER
// IF EXISTS); down() undoes everything.

export async function up(knex: Knex): Promise<void> {
  // 1. Credential version, kept by the database (R8).
  if (!(await knex.schema.hasColumn('users', 'credential_version'))) {
    await knex.schema.alterTable('users', (t) => {
      t.integer('credential_version').notNullable().defaultTo(1);
    });
  }
  await knex.raw(`
    CREATE OR REPLACE FUNCTION users_bump_credential_version() RETURNS trigger AS $$
    BEGIN
      IF NEW.password_hash  IS DISTINCT FROM OLD.password_hash
      OR NEW.totp_secret    IS DISTINCT FROM OLD.totp_secret
      OR NEW.totp_enabled   IS DISTINCT FROM OLD.totp_enabled
      OR NEW.is_active      IS DISTINCT FROM OLD.is_active
      OR NEW.foreign_source IS DISTINCT FROM OLD.foreign_source
      OR NEW.foreign_id     IS DISTINCT FROM OLD.foreign_id THEN
        NEW.credential_version := OLD.credential_version + 1;
      END IF;
      RETURN NEW;
    END $$ LANGUAGE plpgsql;
  `);
  await knex.raw('DROP TRIGGER IF EXISTS users_credential_version ON users');
  await knex.raw(`
    CREATE TRIGGER users_credential_version BEFORE UPDATE ON users
      FOR EACH ROW EXECUTE FUNCTION users_bump_credential_version()
  `);

  // 2. Keys.
  if (!(await knex.schema.hasTable('user_device_keys'))) {
    await knex.schema.createTable('user_device_keys', (t) => {
      t.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));   // = keyId
      t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      t.string('platform', 16).notNullable().defaultTo('android');
      t.binary('public_key_spki').notNullable();
      t.string('public_key_fp', 64).notNullable().unique();              // sha256 hex of the SPKI DER
      t.string('origin', 255).notNullable();                             // §4.6
      t.string('install_id', 64).notNullable();
      t.string('label', 120);                                            // Build.MANUFACTURER + MODEL, cleaned
      t.string('app_version', 32);
      t.string('security_level', 16).notNullable();                      // strongbox | tee | unverified
      t.jsonb('attestation');
      t.integer('credential_version').notNullable();                     // users.credential_version at enrolment
      t.integer('sso_epoch');                                            // lot O; null for a local account
      t.string('status', 16).notNullable().defaultTo('active');          // active | revoked
      t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
      t.timestamp('last_used_at', { useTz: true });
      t.string('last_used_ip', 64);
      t.integer('use_count').notNullable().defaultTo(0);
      t.timestamp('revoked_at', { useTz: true });
      t.integer('revoked_by').references('id').inTable('users').onDelete('SET NULL');
      t.string('revoke_reason', 40);
      // user | logout | admin | password_change | password_reset | totp_changed | totp_disabled |
      // totp_reset | user_disabled | credentials_changed | sso_mfa_changed | replaced |
      // invalidated | stale | policy
      t.index(['user_id', 'status']);
    });
  }

  // 3. Challenges and enrolment tickets.
  if (!(await knex.schema.hasTable('device_key_challenges'))) {
    await knex.schema.createTable('device_key_challenges', (t) => {
      t.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));   // challengeId or ticketId
      t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      t.uuid('key_id').references('id').inTable('user_device_keys').onDelete('CASCADE'); // null: enrolment
      t.string('purpose', 16).notNullable();                             // enrol | login | stepup
      t.string('session_hash', 64).notNullable();                        // sha256(req.sessionID)
      t.integer('tenant_id');                                            // binding tenant (null: login / enrol)
      t.uuid('bulk_id');
      t.binary('nonce').notNullable();                                   // 32 random bytes
      t.string('action_key', 120);
      t.string('binding_hash', 64);
      t.specificType('device_ids', 'integer[]');                         // audit only
      t.string('ip', 64);
      t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
      t.timestamp('expires_at', { useTz: true }).notNullable();
      t.timestamp('consumed_at', { useTz: true });
      t.string('result', 24);  // ok | bad_signature | binding_mismatch | revoked | expired | attestation_failed | …
      t.integer('credential_version');                                   // enrol: users.credential_version when the password + code were checked
      t.integer('sso_epoch');                                            // enrol, SSO (lot O): Obligate MFA epoch at the re-authentication
      t.index(['user_id', 'created_at']);
      t.index(['key_id', 'consumed_at']);
      t.index('expires_at');
    });
  }
  // Addition to §5.2 (not part of the shared contract): an enrolment ticket
  // remembers the credential version its password + code were checked
  // under; enrol/finish refuses the ticket when it changed in between (a
  // password / TOTP change during the 180 s would otherwise let the key be
  // stored under the NEW version and survive the change). Separate guard
  // for a table created by an earlier draft of this migration.
  if (!(await knex.schema.hasColumn('device_key_challenges', 'credential_version'))) {
    await knex.schema.alterTable('device_key_challenges', (t) => {
      t.integer('credential_version');
    });
  }
  // Lot O (not part of the shared contract): the enrolment ticket of an SSO
  // account remembers the Obligate MFA epoch confirmed at the fresh
  // re-authentication; enrol/finish refuses it when the epoch moved in
  // between and stores it on the key (user_device_keys.sso_epoch).
  if (!(await knex.schema.hasColumn('device_key_challenges', 'sso_epoch'))) {
    await knex.schema.alterTable('device_key_challenges', (t) => {
      t.integer('sso_epoch');
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('device_key_challenges');
  await knex.schema.dropTableIfExists('user_device_keys');
  await knex.raw('DROP TRIGGER IF EXISTS users_credential_version ON users');
  await knex.raw('DROP FUNCTION IF EXISTS users_bump_credential_version()');
  if (await knex.schema.hasColumn('users', 'credential_version')) {
    await knex.schema.alterTable('users', (t) => t.dropColumn('credential_version'));
  }
}

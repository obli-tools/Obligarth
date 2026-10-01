import './env';
import http from 'http';
import { config, isWeakAdminPassword, startupConfigErrors } from './config';
import { db } from './db';
import { asIdentity, configureContextSigning, loadContextKeyFile } from './db/context';
import { bootGuard, BootGuardError } from './db/bootGuard';
import { forEachTenant, runJob } from './db/tenantContext';
import { purgePlatformGrants } from './db/platformAccess';
import { createApp } from './app';
import { createSocketServer } from './socket';
import { logger } from './utils/logger';
import { generatePassword, hashPassword } from './utils/crypto';
import { deviceService } from './services/device.service';
import { setLiveAlertIO } from './services/liveAlert.service';
import { obligateService } from './services/obligate.service';
import {
  installUpgradeDispatcher,
  runBootTasks,
  runStartTasks,
  runStopTasks,
} from './lifecycle';
import { registerDeviceModule } from './modules/devices';

// Start-up order (docs: specs README §4, rls-tenant §7.9): configuration,
// registries, (development only) migrations, database boot guard, initial
// administrator, boot tasks, HTTP and Socket.io, start tasks, listen. The
// server never migrates in production: the server-migrate service does
// (src/db/migrate.ts), and the boot guard refuses a schema it did not bring
// up to date.

/** Development only (MIGRATE_ON_BOOT): the runtime role's password the
 *  migration sets — DB_APP_PASSWORD(_FILE), else the one of DATABASE_URL. */
function devAppPassword(): string | null {
  if (process.env.DB_APP_PASSWORD_FILE) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return String(require('fs').readFileSync(process.env.DB_APP_PASSWORD_FILE, 'utf8')).trim() || null;
  }
  if (process.env.DB_APP_PASSWORD) return process.env.DB_APP_PASSWORD;
  try {
    const pw = new URL(config.databaseUrl).password;
    return pw ? decodeURIComponent(pw) : null;
  } catch {
    return null;
  }
}

async function main() {
  // Unsafe configuration (missing database URL, weak or missing session
  // secret, weak initial admin password, database context settings; see
  // config.ts): refuse to start before anything touches the database.
  const configErrors = startupConfigErrors();
  let contextKey: Buffer | null = null;
  try {
    contextKey = loadContextKeyFile(config.rlsContextKeyFile);
  } catch (err) {
    configErrors.push(`RLS_CONTEXT_KEY_FILE unreadable: ${(err as Error).message}`);
  }
  if (configErrors.length > 0) {
    for (const message of configErrors) logger.fatal(message);
    logger.fatal('Unsafe configuration: refusing to start.');
    process.exit(1);
  }
  // Signed database context (rls-tenant §4.6, R12): from the key file, when
  // given; checked against the database by the boot guard.
  configureContextSigning(contextKey);

  // Modules hook into the core's registries (lifecycle tasks, upgrades,
  // Socket.io handlers, approvals, restrictions, settings…) before anything
  // starts.
  registerDeviceModule();

  // Development only: the server migrates its own database (server-migrate
  // in production). Refused outside development by startupConfigErrors.
  if (config.migrateOnBoot) {
    logger.info('MIGRATE_ON_BOOT: running server-migrate in the server process (development)');
    const { runMigrations } = await import('./db/migrate');
    await runMigrations({ adminUrl: config.databaseAdminUrl, appPassword: devAppPassword(), contextKey });
  }

  // Database boot guard: runtime role, ownership, migrations applied,
  // classification, database context (rls-tenant §7.9).
  try {
    await bootGuard();
  } catch (err) {
    if (err instanceof BootGuardError) {
      for (const finding of err.findings) logger.fatal(finding);
      logger.fatal('Database not ready for this server: refusing to start.');
      process.exit(1);
    }
    throw err;
  }

  // Initial administrator, on a database that has none (accounts: the
  // identity context).
  await asIdentity({ type: 'job', name: 'boot.default-admin' }, () => ensureDefaultAdmin());

  // Modules' boot tasks: awaited, before any request can reach the API.
  await runBootTasks();

  // Create Express app and HTTP server
  const app = createApp();
  const server = http.createServer(app);

  // Attach Socket.io — this registers its own 'upgrade' listener on `server`
  const io = createSocketServer(server);

  // Raw WebSocket upgrades of the modules (next to Socket.io, same port).
  installUpgradeDispatcher(server);

  // Initialize services that need the io instance
  deviceService.setIO(io);
  setLiveAlertIO(io);

  // Modules' background jobs (lifecycle.ts): in registration order.
  await runStartTasks({ server, io });

  // Device-bound 2FA periodic tasks (docs/mobile/device-bound-2fa.md §6.9):
  //  - hourly: delete challenges expired for more than 7 days;
  //  - daily, ONLY while the feature is on (runDailyTasks): revoke ('stale')
  //    keys unused for 180 days [D14] (time spent with the feature off does
  //    not count), refresh the Google attestation revocation list (no effect
  //    when unreachable) and revoke the keys whose chain it now marks
  //    revoked ('attestation_revoked', [D4]). Off: no sweep, no call to Google.
  // First run 2 min after start (never in the boot path). Accounts and phone
  // keys: the identity context (rls-tenant §6.5).
  {
    const dk = () => import('./services/deviceKey/deviceKey.service');
    const hourly = () => runJob('deviceKeys.sweepChallenges', (actor) => asIdentity(actor, async () => {
      const { deviceKeyService } = await dk();
      await deviceKeyService.sweepChallenges();
    }));
    const daily = () => runJob('deviceKeys.daily', (actor) => asIdentity(actor, async () => {
      const { deviceKeyService } = await dk();
      await deviceKeyService.runDailyTasks();
    }));
    setTimeout(() => { void hourly(); void daily(); }, 2 * 60 * 1000);
    setInterval(() => { void hourly(); }, 60 * 60 * 1000);
    setInterval(() => { void daily(); }, 24 * 60 * 60 * 1000);
  }

  // Self-healing: reports left stuck in 'generating' by a mid-generation
  // restart never resolve on their own (generation is fire-and-forget). Mark
  // orphaned rows (>15 min) as errored — once at startup so pre-existing
  // zombies clear on deploy, then every 15 min for runtime crashes. Tenant
  // by tenant.
  {
    const { reportService } = require('./services/report.service');
    const sweep = () => runJob('reports.sweepStale', async (actor) => {
      await forEachTenant(actor, (tenantId) => reportService.sweepStaleGenerating(15, tenantId));
    });
    void sweep();
    setInterval(() => { void sweep(); }, 15 * 60 * 1000);
  }

  // Two-step approvals: pending requests past their 30-min expiry become
  // 'expired' (audited 'approval.expired', APPROVAL_UPDATED pushed, sealed
  // executor data wiped) — once at startup, then every minute.
  {
    const { approvalService } = require('./services/approval.service');
    approvalService.startSweeper();
  }

  // Journal of the cross-tenant read grants: daily purge
  // (PLATFORM_GRANT_RETENTION_DAYS, rls-tenant §6.2).
  {
    const purge = () => runJob('platform.grantsPurge', async () => {
      const n = await purgePlatformGrants();
      if (n > 0) logger.info({ count: n }, 'platform grants journal purged');
    });
    setTimeout(() => { void purge(); }, 5 * 60 * 1000).unref();
    setInterval(() => { void purge(); }, 24 * 60 * 60 * 1000).unref();
  }

  server.listen(config.port, () => {
    logger.info({ port: config.port, env: config.nodeEnv }, `Obligarth MDM started`);

    // Sync preference schemas with Obligate (non-blocking)
    void runJob('obligate.syncPreferenceSchemas', () => obligateService.syncPreferenceSchemas());
    // Capability schemas USED to be pushed to Obligate so admins could
    // tick per-user capability boxes from there. Dropped: capabilities
    // live entirely in Obligarth now (role = what / team = where), and
    // pushing them to Obligate created confusing user-level toggles
    // that didn't map to anything on the Obligarth side. Obligate-side
    // cleanup is handled separately.
  });

  // Graceful shutdown
  const shutdown = async () => {
    logger.info('Shutting down...');
    runStopTasks();
    server.close(() => {
      db.destroy();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

/**
 * Initial administrator, created only while no administrator exists (fresh
 * database): DEFAULT_ADMIN_USERNAME with DEFAULT_ADMIN_PASSWORD when set,
 * else with a random password printed ONCE in the startup logs. Only its
 * hash is stored: it can never be shown again. Outside development, a weak
 * DEFAULT_ADMIN_PASSWORD never gets here (startupConfigErrors). The account
 * then remains the break-glass access when Obligate is unreachable.
 * Runs in the identity context; the master tenant (id 1) is created by the
 * base seed migration.
 */
async function ensureDefaultAdmin() {
  if (await db('users').where({ role: 'admin' }).first('id')) return;

  const username = config.defaultAdminUsername;
  if (await db('users').where({ username }).first('id')) {
    logger.warn(
      { username },
      'No administrator exists, but this username belongs to a non-admin account: no initial administrator ' +
      'created. Set DEFAULT_ADMIN_USERNAME to a free username to get one.',
    );
    return;
  }

  const generated = !config.defaultAdminPassword;
  const password = config.defaultAdminPassword || generatePassword();
  if (!generated && isWeakAdminPassword(password)) {
    logger.warn('The initial administrator gets a weak DEFAULT_ADMIN_PASSWORD (accepted in development only).');
  }
  const hash = await hashPassword(password);

  // All or nothing: a half-created account would keep a password nobody saw.
  await db.transaction(async (trx) => {
    const [user] = await trx('users').insert({
      username,
      password_hash: hash,
      display_name: 'Administrator',
      role: 'admin',
      is_active: true,
    }).returning('id');
    const userId = user?.id ?? user;
    await trx('user_tenants').insert({ user_id: userId, tenant_id: 1, role: 'admin' }).onConflict(['user_id','tenant_id']).ignore();
  });

  if (generated) {
    logger.warn(
      { username },
      `Initial administrator "${username}" created: sign in, change the password and enable two-factor ` +
      `authentication. Generated password, shown only this once: ${password}`,
    );
  } else {
    logger.info(
      { username },
      'Initial administrator created with DEFAULT_ADMIN_PASSWORD: change it and enable two-factor authentication at first sign-in',
    );
  }
}

main().catch((err) => {
  logger.error(err, 'Fatal error during startup');
  process.exit(1);
});

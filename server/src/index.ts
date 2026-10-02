import './env';
import http from 'http';
import { config, isWeakAdminPassword, startupConfigErrors } from './config';
import { db } from './db';
import { asIdentity, asNone, configureContextSigning, loadContextKeyFile } from './db/context';
import { bootGuard, BootGuardError } from './db/bootGuard';
import { createApp } from './app';
import { createSocketServer } from './socket';
import { logger } from './utils/logger';
import { generatePassword, hashPassword } from './utils/crypto';
import { deviceService } from './services/device.service';
import { setLiveAlertIO } from './services/liveAlert.service';
import {
  installUpgradeDispatcher,
  runBootTasks,
  runStartTasks,
  runStopTasks,
} from './lifecycle';
import { jobs, JobsStartError, safeErr } from './jobs';
import { registerCoreJobs } from './jobs/core.jobs';
import { registerOutboxJobs } from './jobs/outbox/jobs';
import { registerDeviceModule } from './modules/devices';
import { registerReportsModule } from './modules/reports';
import { registerSsoSyncJobs } from './routes/obligateCallback.routes';
import { BackfillError, backfillLegacySecrets, isVaultError, vault, vaultConfigErrors, VaultStartupError } from './vault';
import { registerVaultJobs } from './vault/jobs';
import { registerAuditModule } from './audit/module';
import { registerGuardModule } from './guard/module';
import { registerAppleModule } from './modules/apple';
import { AuditClockError, auditClockCheck } from './audit/clock';
import { ensureSealKey } from './audit/sealKeys';

// Start-up order (docs: specs README §4, rls-tenant §7.9, file-durable §3.3,
// coffre-secrets §6.1): configuration (the vault's KEK file included),
// registries (no I/O), (development only) migrations, database boot guard,
// vault (KEK, online lock, canary, tenant keys) and backfill of the inherited
// clear secrets, initial administrator, durable jobs (pg-boss: queues and
// schedules), boot tasks, HTTP and Socket.io, start tasks, job workers,
// listen. The server never migrates in production: the server-migrate
// service does (src/db/migrate.ts), and the boot guard refuses a schema it
// did not bring up to date. No timer of this process does periodic work:
// the modules' durable jobs do (jobs/).

/** Exit budget of a shutdown: forced exit past it (the compose gives the
 *  server 30 s, stop_grace_period). */
const SHUTDOWN_DEADLINE_MS = 25_000;
/** Longest wait for the HTTP server to close (open keep-alive connections). */
const HTTP_CLOSE_WAIT_MS = 5_000;

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
  // config.ts; the vault's KEK file, vault/config.ts): refuse to start before
  // anything touches the database.
  const configErrors = [...startupConfigErrors(), ...vaultConfigErrors({ warn: (m) => logger.warn(m) })];
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

  // Modules hook into the core's registries (durable jobs, lifecycle tasks,
  // upgrades, Socket.io handlers, approvals, restrictions, settings…) before
  // anything starts. No I/O: the job registry is frozen by jobs.start().
  registerDeviceModule();
  registerReportsModule();
  registerCoreJobs();
  registerSsoSyncJobs();
  registerOutboxJobs();
  registerVaultJobs();
  registerAuditModule();
  registerGuardModule();
  registerAppleModule();

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

  // Clock of the audit entries (audit-durci §5.6, §12.2): the database refuses
  // an entry more than 5 minutes away from its own clock; refused to start
  // beyond AUDIT_MAX_CLOCK_SKEW_SECONDS.
  try {
    await auditClockCheck();
  } catch (err) {
    if (err instanceof AuditClockError) {
      logger.fatal(err.message);
      await db.destroy().catch(() => undefined);
      process.exit(1);
    }
    throw err;
  }

  // Vault (coffre-secrets §6.1; review COF-RC3): the KEK provider, the online
  // lock, the canary (a KEK that does not open this database's keys: message
  // A), an interrupted KEK rotation (message B), the first data key of every
  // tenant that has none; then the backfill of the inherited clear secrets,
  // each class of table in its own database context. Any failure: refusal.
  try {
    await asNone({ type: 'job', name: 'vault.init' }, () => vault.init());
    await asNone({ type: 'job', name: 'vault.backfill' }, () => backfillLegacySecrets());
  } catch (err) {
    if (err instanceof VaultStartupError) logger.fatal(err.refusal);
    else if (err instanceof BackfillError) logger.fatal(err.message);
    else if (isVaultError(err)) logger.fatal(err.message);
    else logger.fatal({ err: safeErr(err) }, 'vault start-up failed');
    logger.fatal('Vault not ready: refusing to start.');
    await vault.close().catch(() => undefined);
    await db.destroy().catch(() => undefined);
    process.exit(1);
  }

  // The key that signs the audit seals (audit-durci §6.3, §12.2), once the
  // vault is ready: created on a fresh instance, replaced (and alerted) when
  // it no longer matches the vault's. A failure does not stop the start: the
  // job audit.seal-keys tries again.
  try {
    await ensureSealKey({ requestId: 'boot' });
  } catch (err) {
    logger.error({ err: safeErr(err) }, 'audit: seal key not checked at start (the audit.seal-keys job retries)');
  }

  // Initial administrator, on a database that has none (accounts: the
  // identity context).
  await asIdentity({ type: 'job', name: 'boot.default-admin' }, () => ensureDefaultAdmin());

  // Durable jobs (file-durable §5.9): pg-boss installs or migrates its schema
  // (pgboss, owned by the runtime role), queues and schedules follow the
  // registry, the jobs "at start" are sent (JOBS_MODE=all). A failure stops
  // the server: no periodic work would run.
  try {
    await jobs.start();
  } catch (err) {
    if (err instanceof JobsStartError) logger.fatal(err.message);
    else logger.fatal({ err: safeErr(err) }, 'background jobs could not start');
    logger.fatal('Background jobs not started: refusing to start.');
    await vault.close().catch(() => undefined);
    await db.destroy().catch(() => undefined);
    process.exit(1);
  }

  // Modules' boot tasks: awaited, before any request can reach the API (a
  // boot task may send a job).
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

  // Modules' start tasks (lifecycle.ts): in registration order.
  await runStartTasks({ server, io });

  // Job workers (JOBS_MODE=all), after Socket.io: handlers emit real-time
  // events (approvals expired, fleet snapshots…).
  await jobs.startWorkers();

  server.listen(config.port, () => {
    logger.info({ port: config.port, env: config.nodeEnv, jobsMode: jobs.mode() }, 'Obligarth MDM started');
  });

  // Shutdown (SIGTERM, SIGINT; once): forced exit past 25 s; no new HTTP
  // connection (5 s at most for the open ones); the jobs stop gracefully
  // (running handlers finish, or their jobs are failed and retried later);
  // the modules' stop tasks; the vault (KEK zeroed, online lock released);
  // the database pool.
  let stopping = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    logger.info({ signal }, 'Shutting down...');
    setTimeout(() => process.exit(1), SHUTDOWN_DEADLINE_MS).unref();
    await Promise.race([
      new Promise<void>((resolve) => server.close(() => resolve())),
      new Promise<void>((resolve) => setTimeout(resolve, HTTP_CLOSE_WAIT_MS).unref()),
    ]);
    await jobs.stop().catch((err) => logger.error({ err: safeErr(err) }, 'jobs stop failed'));
    await runStopTasks();
    await vault.close().catch(() => undefined);
    await db.destroy().catch(() => undefined);
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
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

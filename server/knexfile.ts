import path from 'path';
import type { Knex } from 'knex';
import { config as appConfig, DATABASE_URL_MISSING } from './src/config';
import { ContextAwarePgClient } from './src/db/contextPgClient';

const isCompiled = __filename.endsWith('.js');

// No fallback outside NODE_ENV=development (src/config.ts): without
// DATABASE_URL, the first query fails with an explicit message. The server
// refuses to start before that (index.ts).
function missingDatabaseUrl(): never {
  throw new Error(DATABASE_URL_MISSING);
}

// Schema and roles (rls-tenant §3): every table of the server lives in the
// schema `obligarth`, owned by `obligarth_owner`; the server runs as
// `obligarth` (no superuser, no BYPASSRLS, owner of nothing). The
// migrations (src/db/migrate.ts) run at start, before it, with the
// administration DSN, which the server forgets once they are done.

/** The migrations of this image, as Knex loads them. */
export const MIGRATIONS: Knex.MigratorConfig = {
  directory: path.join(__dirname, 'src/db/migrations'),
  extension: isCompiled ? 'js' : 'ts',
  loadExtensions: isCompiled ? ['.js'] : ['.ts'],
  schemaName: 'obligarth',
  // Obligarth's own tracking table (and obligarth_migrations_lock), not
  // Knex's default knex_migrations: pointed by mistake at a database of
  // another product (an Obliance one), the migration finds none of its
  // migrations applied, fails on the base schema's first CREATE TABLE and
  // stops, instead of "migrating" that database.
  tableName: 'obligarth_migrations',
  // Rolling the server image back to an OLDER version must still migrate
  // and boot: the tracking table then lists migrations the old image does
  // not ship, which Knex's list validation would refuse ("The migration
  // directory is corrupt"). Newer tables / columns / triggers are simply
  // ignored by older code.
  disableMigrationsListValidation: true,
};

/**
 * The server's pool (src/db/index.ts): the context-aware client sets the
 * database context at every lease (src/db/contextPgClient.ts).
 */
export const runtimeConfig: Knex.Config = {
  client: ContextAwarePgClient,
  connection: appConfig.databaseUrl || missingDatabaseUrl,
  searchPath: ['obligarth'],
  pool: {
    // Sized for the push traffic of the former RMM agent (2000+ devices, where
    // max:10 kept the pool saturated and every UI request queued behind it);
    // kept until the load of the MDM is measured.
    // NOTE: keep pool.max × server-replicas comfortably under the Postgres
    // max_connections — docker-compose sets it to 256, shared with apple-edge
    // (about 40 per replica) and pg-boss; the session store keeps its own
    // small pool, so 60 leaves ample margin.
    min: 4,
    max: 60,
  },
  // Fail fast instead of hanging a request forever when the pool is starved,
  // so a transient spike surfaces as a logged error rather than a silent stall
  // on an unrelated UI call. (Knex top-level option; default is 60s.)
  acquireConnectionTimeout: 20_000,
};

/**
 * The migrations' pool (src/db/migrate.ts): the
 * administration DSN, one connection, every object created by the owner
 * role (SET ROLE obligarth_owner when the connection opens).
 */
export function migrationConfig(adminUrl: string): Knex.Config {
  return {
    client: 'pg',
    connection: adminUrl,
    searchPath: ['obligarth'],
    pool: {
      min: 0,
      max: 1,
      afterCreate: (conn: { query: (sql: string, cb: (err: Error | null) => void) => void }, done: (err: Error | null, conn: unknown) => void) => {
        conn.query('SET ROLE obligarth_owner', (err) => done(err, conn));
      },
    },
    acquireConnectionTimeout: 60_000,
    migrations: MIGRATIONS,
  };
}

// Knex CLI (npm run migrate:make): only the migrations settings are used.
const cliConfig: Knex.Config = { client: 'pg', migrations: MIGRATIONS };
export default cliConfig;

import path from 'path';
import type { Knex } from 'knex';
import { config as appConfig, DATABASE_URL_MISSING } from './src/config';

const isCompiled = __filename.endsWith('.js');

// No fallback outside NODE_ENV=development (src/config.ts): without
// DATABASE_URL, the first query fails with an explicit message. The server
// refuses to start before that (index.ts).
function missingDatabaseUrl(): never {
  throw new Error(DATABASE_URL_MISSING);
}

const config: Knex.Config = {
  client: 'pg',
  connection: appConfig.databaseUrl || missingDatabaseUrl,
  searchPath: ['public'],
  migrations: {
    directory: isCompiled
      ? path.join(__dirname, 'src/db/migrations')
      : './src/db/migrations',
    extension: isCompiled ? 'js' : 'ts',
    loadExtensions: isCompiled ? ['.js'] : ['.ts'],
    schemaName: 'public',
    // Rolling the server image back to an OLDER version must still boot:
    // knex_migrations then lists migrations the old image does not ship, and
    // knex's list validation ("The migration directory is corrupt") would
    // make db.migrate.latest() — run at every boot (index.ts) — exit the
    // server. Newer tables / columns / triggers are simply ignored by older
    // code (docs/mobile/device-bound-2fa.md §11). Only helps images built
    // from this version on; for an image older than this change, see §11.
    disableMigrationsListValidation: true,
  },
  seeds: {
    directory: isCompiled
      ? path.join(__dirname, 'src/db/seeds')
      : './src/db/seeds',
    extension: isCompiled ? 'js' : 'ts',
    loadExtensions: isCompiled ? ['.js'] : ['.ts'],
  },
  pool: {
    // Sized for the push traffic of the former RMM agent (2000+ devices, where
    // max:10 kept the pool saturated and every UI request queued behind it);
    // kept until the load of the MDM is measured.
    // NOTE: keep pool.max × server-replicas comfortably under the Postgres
    // max_connections — docker-compose sets it to 200; the session store keeps
    // its own small pool, so 60 leaves ample margin.
    min: 4,
    max: 60,
  },
  // Fail fast instead of hanging a request forever when the pool is starved,
  // so a transient spike surfaces as a logged error rather than a silent stall
  // on an unrelated UI call. (Knex top-level option; default is 60s.)
  acquireConnectionTimeout: 20_000,
};

export default config;

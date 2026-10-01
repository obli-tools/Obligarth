// Vault settings and start-up checks (docs: coffre-secrets §5.8, §6.1,
// annexe A). vaultConfigErrors() is called next to startupConfigErrors(),
// before anything touches the database: the server refuses to start without
// a usable KEK. The KEK itself is only ever a file (a Docker secret), never an
// environment variable: those are visible to `docker inspect` and to every
// process of the container.
//
// Self-contained (no import of ../config, ../env or the logger), so that the
// unit tests run under `node --test` with Node's native type stripping.
import fs from 'node:fs';
import path from 'node:path';
import { newKey } from './envelope';
import { inspectKekFile } from './kek';

/** Where the Docker secret server_kek is mounted. */
export const DOCKER_KEK_FILE = '/run/secrets/server_kek';
/** Largest plaintext of one sealed value (1 MiB). */
export const MAX_PLAINTEXT_BYTES = 1024 * 1024;
const DEFAULT_DEK_CACHE_TTL_SECONDS = 300;
const MAX_DEK_CACHE_TTL_SECONDS = 86_400;

/** Where the KEK path comes from: SERVER_KEK_FILE, the Docker secret, or the
 *  development file (NODE_ENV=development explicitly, no SERVER_KEK_FILE). */
export type KekFileSource = 'env' | 'docker' | 'development';

export interface VaultConfig {
  /** 'file' (MVP) or 'transit' (v1, refused by vaultConfigErrors()). */
  provider: 'file' | 'transit';
  /** Path of the KEK file, resolved: SERVER_KEK_FILE, else
   *  /run/secrets/server_kek; in explicit development only,
   *  <repository>/.secrets/server_kek (created when missing). */
  kekFile: string;
  kekFileSource: KekFileSource;
  /** Previous KEK: read by the kek-rotate command only, never by the server. */
  kekPreviousFile: string;
  /** NaN when VAULT_DEK_CACHE_TTL is not a whole number (refused). */
  dekCacheTtlSeconds: number;
  maxPlaintextBytes: number;
  /** Laboratory only (V14): lifts the escrow guard. */
  allowUnescrowed: boolean;
  /** OpenBao or Vault Transit (v1, coffre-secrets §9.4). */
  transit: {
    addr: string;
    mount: string;
    key: string;
    tokenFile: string;
    roleIdFile: string;
    secretIdFile: string;
    caFile: string;
  };
}

export interface VaultConfigOptions {
  /** Root of the repository, for the development KEK (default: the folder of
   *  the monorepo's package.json, found from this file's folder, else from
   *  the working directory). */
  repoRoot?: string;
}

type Env = Record<string, string | undefined>;

function setting(env: Env, name: string): string {
  return (env[name] ?? '').trim();
}

/** The closest folder at or above `startDir` whose package.json declares
 *  workspaces (the monorepo root), or null. */
export function findRepoRoot(startDir: string): string | null {
  let dir = path.resolve(startDir);
  for (;;) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')) as { workspaces?: unknown };
      if (pkg && typeof pkg === 'object' && pkg.workspaces != null) return dir;
    } catch { /* no package.json here, or not JSON: keep walking up */ }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function defaultRepoRoot(): string {
  // From this file's folder (CommonJS: tsc, tsx), else from the working
  // directory (ES module under node --test, or a build outside the
  // repository), else the working directory itself.
  const here = typeof __dirname === 'string' ? findRepoRoot(__dirname) : null;
  return here ?? findRepoRoot(process.cwd()) ?? process.cwd();
}

/** The vault settings of an environment (process.env by default). */
export function readVaultConfig(env: Env = process.env, options: VaultConfigOptions = {}): VaultConfig {
  const kekFileSetting = setting(env, 'SERVER_KEK_FILE');
  const development = env.NODE_ENV === 'development';
  let kekFile = kekFileSetting;
  let kekFileSource: KekFileSource = 'env';
  if (!kekFile && development) {
    kekFile = path.join(options.repoRoot ?? defaultRepoRoot(), '.secrets', 'server_kek');
    kekFileSource = 'development';
  } else if (!kekFile) {
    kekFile = DOCKER_KEK_FILE;
    kekFileSource = 'docker';
  }
  const ttl = setting(env, 'VAULT_DEK_CACHE_TTL');
  return {
    provider: (setting(env, 'KEK_PROVIDER') || 'file') as 'file' | 'transit',
    kekFile,
    kekFileSource,
    kekPreviousFile: setting(env, 'SERVER_KEK_PREVIOUS_FILE'),
    dekCacheTtlSeconds: ttl === '' ? DEFAULT_DEK_CACHE_TTL_SECONDS : /^[0-9]+$/.test(ttl) ? Number(ttl) : NaN,
    maxPlaintextBytes: MAX_PLAINTEXT_BYTES,
    allowUnescrowed: env.VAULT_ALLOW_UNESCROWED === 'true',
    transit: {
      addr: setting(env, 'KEK_TRANSIT_ADDR'),
      mount: setting(env, 'KEK_TRANSIT_MOUNT') || 'transit',
      key: setting(env, 'KEK_TRANSIT_KEY'),
      tokenFile: setting(env, 'KEK_TRANSIT_TOKEN_FILE'),
      roleIdFile: setting(env, 'KEK_TRANSIT_ROLE_ID_FILE'),
      secretIdFile: setting(env, 'KEK_TRANSIT_SECRET_ID_FILE'),
      caFile: setting(env, 'KEK_TRANSIT_CA_FILE'),
    },
  };
}

/** Refusal for a missing or unusable KEK file (coffre-secrets §5.8), then the
 *  cause in fixed words (never the content of the file). */
export function kekFileRefusal(file: string, cause: string): string {
  return `The KEK file ${file} is missing or invalid: create it (openssl rand -base64 32) `
    + `and mount it as the Docker secret server_kek. Cause: ${cause}.`;
}

/** A kek_id read from the database, made safe for a log line. */
function printableKekId(id: string): string {
  return String(id).slice(0, 128).replace(/[^A-Za-z0-9:/_.-]/g, '?') || '(none)';
}

/** Message A (coffre-secrets §6.1): the loaded KEK does not open this
 *  database's keys (canary of vault.init()). */
export function kekMismatchRefusal(loadedKekId: string, expectedKekId: string): string {
  return `The KEK (kek_id ${printableKekId(loadedKekId)}) does not open this database's keys `
    + `(expected kek_id ${printableKekId(expectedKekId)}). Mount the KEK of this database, reconstituted `
    + 'from escrow (vault escrow combine), or restore the backup that matches this KEK. Refusing to start.';
}

/** Message B (coffre-secrets §6.1): data keys wrapped by another KEK remain. */
export function interruptedRotationRefusal(otherKekId: string): string {
  return `Data keys wrapped by another KEK (kek_id ${printableKekId(otherKekId)}) remain: a KEK rotation `
    + 'was interrupted. Run "vault kek-rotate --resume" with SERVER_KEK_PREVIOUS_FILE. Refusing to start.';
}

export interface VaultConfigCheckOptions extends VaultConfigOptions {
  env?: Env;
  /** Warnings for the operator (default: process.emitWarning); index.ts
   *  passes the logger. */
  warn?: (message: string) => void;
}

function defaultWarn(message: string): void {
  process.emitWarning(message, 'VaultWarning');
}

/** In explicit development only, without SERVER_KEK_FILE: creates the
 *  development KEK when the file does not exist (never overwrites one). */
function ensureDevelopmentKek(file: string, warn: (message: string) => void): void {
  if (fs.existsSync(file)) return;
  const key = newKey();
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, `${key.toString('base64')}\n`, { mode: 0o600, flag: 'wx' });
    warn(`NODE_ENV=development: no KEK file, a new one was created in ${file} (32 random bytes). `
      + 'The secrets of this development database depend on it: keep it with the database, '
      + 'and never use it outside development.');
  } catch {
    // Created meanwhile, or not creatable: the check that follows says which.
  } finally {
    key.fill(0);
  }
}

/**
 * Settings of the vault the server refuses to start with, as messages for the
 * operator (empty: none). Unlike startupConfigErrors(), they also apply in
 * development, where a missing development KEK is created. Called before
 * anything touches the database.
 */
export function vaultConfigErrors(options: VaultConfigCheckOptions = {}): string[] {
  const env = options.env ?? process.env;
  const warn = options.warn ?? defaultWarn;
  const errors: string[] = [];
  const cfg = readVaultConfig(env, options);

  if (setting(env, 'SERVER_KEK')) {
    errors.push('SERVER_KEK is set: the KEK is never read from an environment variable (visible to '
      + 'docker inspect and to every process of the container). Remove it and mount the key as the '
      + 'Docker secret server_kek (SERVER_KEK_FILE).');
  }
  // The value is not repeated: a misplaced key must not reach the logs.
  const provider = setting(env, 'KEK_PROVIDER') || 'file';
  if (provider === 'transit') {
    errors.push('KEK_PROVIDER=transit (OpenBao or Vault Transit) is not available in this version: '
      + 'use KEK_PROVIDER=file with the Docker secret server_kek.');
  } else if (provider !== 'file') {
    errors.push('KEK_PROVIDER must be "file" (the Docker secret server_kek, the default).');
  }
  const ttl = cfg.dekCacheTtlSeconds;
  if (!Number.isInteger(ttl) || ttl < 0 || ttl > MAX_DEK_CACHE_TTL_SECONDS) {
    errors.push(`VAULT_DEK_CACHE_TTL must be a whole number of seconds between 0 and ${MAX_DEK_CACHE_TTL_SECONDS} `
      + `(${DEFAULT_DEK_CACHE_TTL_SECONDS} by default).`);
  }

  if (provider === 'file') {
    if (cfg.kekFileSource === 'development') ensureDevelopmentKek(cfg.kekFile, warn);
    const check = inspectKekFile(cfg.kekFile);
    if (!check.ok) {
      errors.push(kekFileRefusal(cfg.kekFile, check.reason));
    } else {
      check.kek.key.fill(0);   // only checked here: vault.init() loads the provider
      // Bind mounts do not always carry the host's permissions: a warning only.
      if (process.platform !== 'win32' && (check.mode & 0o044) !== 0) {
        warn(`The KEK file ${cfg.kekFile} is readable by other users (mode `
          + `${(check.mode & 0o777).toString(8).padStart(3, '0')}): restrict it to its owner (chmod 400).`);
      }
    }
  }

  if (cfg.allowUnescrowed) {
    warn('VAULT_ALLOW_UNESCROWED=true: the escrow guard is lifted, Apple secrets can be stored before '
      + 'the vault keys are escrowed (laboratory instances only).');
  }
  return errors;
}

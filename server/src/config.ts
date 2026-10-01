import './env';
import path from 'node:path';
import { readJobsConfig } from './jobs/config';

// Background jobs (JOBS_*, docs: file-durable annex A): parsed once, refused
// at start when invalid (startupConfigErrors), in every environment.
const jobsEnv = readJobsConfig(process.env);

function publicUrlFromEnv(): string {
  const appUrl = (process.env.APP_URL || '').trim();
  if (appUrl) return appUrl.replace(/\/+$/, '');
  const clientOrigin = (process.env.CLIENT_ORIGIN || '').trim();
  try {
    const host = new URL(clientOrigin).hostname;
    if (host === 'localhost' || host.endsWith('.localhost') || host === '[::1]' || /^127\./.test(host)) return '';
  } catch {
    return '';
  }
  return clientOrigin.replace(/\/+$/, '');
}

// Only an explicit NODE_ENV=development accepts the local fallbacks below
// (database URL, session secret) and weak secrets. Any other value, unset
// included, is a deployment: see startupConfigErrors(). `nodeEnv` and
// `isDev` (logging, static files, cookie flag) are no such signal: they
// treat an unset NODE_ENV as development.
const explicitDevelopment = process.env.NODE_ENV === 'development';
const DEV_DATABASE_URL = 'postgres://obligarth:changeme@localhost:5432/obligarth';
const DEV_SESSION_SECRET = 'change-this-secret';

/** An integer variable, or `fallback` when unset or not an integer. */
function intEnv(name: string, fallback: number): number {
  const raw = (process.env[name] ?? '').trim();
  return /^-?[0-9]+$/.test(raw) ? parseInt(raw, 10) : fallback;
}

// Row level security (docs: rls-tenant §7.10). DB_CONTEXT_MODE: 'strict'
// (default) refuses a query without a database context; 'audit' logs it and
// runs it in the context 'none' (only while the RLS migration C is not
// applied: the boot guard refuses it afterwards). DB_CONTEXT_ASSERT: what a
// query on a lease opened in another context does ('throw' in development
// and test, 'log' in production).
function dbContextModeFromEnv(): 'strict' | 'audit' | 'invalid' {
  const raw = (process.env.DB_CONTEXT_MODE ?? '').trim();
  if (raw === '' || raw === 'strict') return 'strict';
  return raw === 'audit' ? 'audit' : 'invalid';
}

function dbContextAssertFromEnv(): 'throw' | 'log' | 'off' {
  const raw = (process.env.DB_CONTEXT_ASSERT ?? '').trim();
  if (raw === 'throw' || raw === 'log' || raw === 'off') return raw;
  const env = process.env.NODE_ENV;
  return env === 'development' || env === 'test' ? 'throw' : 'log';
}

interface AuditConfig {
  /** Local spool of the entries not written (standard and protective). */
  spoolDir: string;
  /** Hourly seal (UTC). */
  sealCron: string;
  /** RFC 3161 time-stamping authority; empty: disabled. */
  tsaUrl: string;
  /** File (Docker secret) holding the Authorization header of a paid authority. */
  tsaAuthFile: string;
  /** SHA-256 (hex) of the authority's certificate, pinned; empty: no pinning. */
  tsaCertSha256: string;
  tsaTimeoutMs: number;
  /** 'off' stops the SIEM exporter (laboratory only). */
  export: 'on' | 'off' | 'invalid';
  /** Refusal to start beyond this drift with the database clock. */
  maxClockSkewSeconds: number;
  /** An undeclared action refuses its body (development, test,
   *  AUDIT_STRICT_CATALOG=true) instead of a warning. */
  strictCatalog: boolean;
  /** Laboratory only: a SIEM destination on the loopback (the test bench
   *  receivers). Refused by default (SSRF towards the host's own services). */
  siemAllowLoopback: boolean;
}

function auditConfigFromEnv(): AuditConfig {
  const customDir = process.env.CUSTOM_DIR || './custom';
  const exp = (process.env.AUDIT_EXPORT ?? '').trim();
  const strict = (process.env.AUDIT_STRICT_CATALOG ?? '').trim();
  return {
    spoolDir: process.env.AUDIT_SPOOL_DIR || path.join(customDir, 'audit-spool'),
    sealCron: (process.env.AUDIT_SEAL_CRON || '12 * * * *').trim(),
    tsaUrl: (process.env.AUDIT_TSA_URL || '').trim(),
    tsaAuthFile: (process.env.AUDIT_TSA_AUTH_FILE || '').trim(),
    tsaCertSha256: (process.env.AUDIT_TSA_CERT_SHA256 || '').trim().toLowerCase().replace(/:/g, ''),
    tsaTimeoutMs: intEnv('AUDIT_TSA_TIMEOUT_MS', 10_000),
    export: exp === '' || exp === 'on' ? 'on' : exp === 'off' ? 'off' : 'invalid',
    maxClockSkewSeconds: intEnv('AUDIT_MAX_CLOCK_SKEW_SECONDS', 240),
    strictCatalog: strict === '' ? (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') : strict === 'true',
    siemAllowLoopback: process.env.AUDIT_SIEM_ALLOW_LOOPBACK === 'true',
  };
}

export const config = {
  port: parseInt(process.env.PORT || '3001', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isDev: process.env.NODE_ENV !== 'production',
  /** Empty when DATABASE_URL is unset outside development (refused at start).
   *  The runtime role `obligarth`: no superuser, no BYPASSRLS, owner of
   *  nothing (db/bootGuard.ts refuses to start otherwise). */
  databaseUrl: process.env.DATABASE_URL || (explicitDevelopment ? DEV_DATABASE_URL : ''),
  /** Administration DSN (obligarth_admin): read by server-migrate
   *  (db/migrate.ts) only, and by the server itself with MIGRATE_ON_BOOT in
   *  development. Never given to the `server` service in production. */
  databaseAdminUrl: process.env.DATABASE_ADMIN_URL || '',
  /** Development only (NODE_ENV=development and DATABASE_ADMIN_URL): the
   *  server runs the migrations itself at start, as server-migrate would. */
  migrateOnBoot: process.env.MIGRATE_ON_BOOT === 'true',
  /** 'strict' | 'audit' | 'invalid' (refused at start): see above. */
  dbContextMode: dbContextModeFromEnv(),
  dbContextAssert: dbContextAssertFromEnv(),
  /** Signed database context (rls-tenant §4.6, R12): key file of the
   *  current key and, during a rotation, of the previous one. */
  rlsContextKeyFile: process.env.RLS_CONTEXT_KEY_FILE || '',
  rlsContextKeyPreviousFile: process.env.RLS_CONTEXT_KEY_PREVIOUS_FILE || '',
  /** Lifetime of a cross-tenant read grant (60 to 3600 s, 900 by default),
   *  and how long the grants journal is kept (30 days at least). */
  platformGrantTtlSeconds: intEnv('PLATFORM_GRANT_TTL_SECONDS', 900),
  platformGrantRetentionDays: intEnv('PLATFORM_GRANT_RETENTION_DAYS', 365),
  /** Empty when SESSION_SECRET is unset outside development (refused at start). */
  sessionSecret: process.env.SESSION_SECRET || (explicitDevelopment ? DEV_SESSION_SECRET : ''),
  // Own session cookie name (Oblimap model): Obli* apps sharing a host name
  // would otherwise overwrite each other's connect.sid (cookies ignore ports).
  sessionCookieName: process.env.SESSION_COOKIE_NAME || 'obligarth.sid',
  /** Background jobs (pg-boss, schema pgboss): mode, pool, stop budget,
   *  health threshold. See jobs/config.ts. */
  jobs: jobsEnv.config,
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  forceHttps: process.env.FORCE_HTTPS === 'true',
  appName: process.env.APP_NAME || 'Obligarth',
  appUrl: process.env.APP_URL || '',
  // The public address of this instance: APP_URL, else CLIENT_ORIGIN when the
  // operator set it explicitly (in the Docker deployment both name the same
  // origin: nginx serves the web client and proxies the API). Never the dev
  // default above, never derived from a request header.
  publicUrl: publicUrlFromEnv(),
  // Initial administrator (index.ts:ensureDefaultAdmin), created only while
  // no administrator exists. No default password: when
  // DEFAULT_ADMIN_PASSWORD is empty, a random one is generated and printed
  // once in the startup logs. Outside development, a weak value (under 12
  // characters or a known default) makes the server refuse to start.
  defaultAdminUsername: process.env.DEFAULT_ADMIN_USERNAME || 'admin',
  defaultAdminPassword: process.env.DEFAULT_ADMIN_PASSWORD || '',
  disable2faForce: process.env.DISABLE_2FA_FORCE === 'true',
  customDir: process.env.CUSTOM_DIR || './custom',
  /** Hardened audit journal (docs: audit-durci §13.1). Not configurable on
   *  purpose: floors, delays, retention bounds (a new version changes them). */
  audit: auditConfigFromEnv(),
  // Device-bound 2FA (docs/mobile/device-bound-2fa.md §9). Parsed and
  // validated by services/deviceKey/deviceKey.service.ts.
  deviceKeys: {
    /** Emergency switch, overrides the platform settings. */
    disabled: process.env.DEVICE_KEYS_DISABLED === 'true',
    /** Extra enrolment origins (comma-separated), next to APP_URL [D17]. */
    origins: process.env.DEVICE_KEY_ORIGINS || '',
    /** Accepted app packages (comma-separated); default tools.obli.obligarth.next. */
    appIds: process.env.DEVICE_KEY_APP_IDS || '',
    /** Accepted APK signer SHA-256 digests (comma-separated, ':' ignored);
     *  default: the release signer. A debug signer is added here only on a
     *  development server [D19]. */
    appSigners: process.env.DEVICE_KEY_APP_SIGNERS || '',
    /** Secret of the request-binding body key (HMAC, §4.5 v2); empty →
     *  derived from SESSION_SECRET. Never stored in the database. */
    bindingSecret: process.env.DEVICE_KEY_BINDING_SECRET || '',
    /** Lot O opt-in (SSO / Obligate accounts): OFF unless exactly 'true'.
     *  While off, Obligate's capabilities are never read and SSO accounts
     *  keep today's behaviour (no phone key, no consuming verify-totp). */
    ssoEnabled: process.env.DEVICE_KEYS_SSO_ENABLED === 'true',
  },
};

// Placeholders shipped at one time or another by the install files
// (changeme, change-this-…, admin123) and their variants: refused outside
// development, whatever the length.
const PLACEHOLDER_RE = /change[-_. ]?(?:me|this)|admin123/i;
const MIN_SESSION_SECRET_LENGTH = 32;
const MIN_ADMIN_PASSWORD_LENGTH = 12;

function isWeakSecret(value: string, minLength: number): boolean {
  return value.length < minLength || PLACEHOLDER_RE.test(value);
}

export const DATABASE_URL_MISSING =
  'DATABASE_URL is not set: point it at the PostgreSQL database (postgres://user:password@host:5432/name). ' +
  'The local development database is only used with NODE_ENV=development.';

/** Under 12 characters or a known default. */
export function isWeakAdminPassword(password: string): boolean {
  return isWeakSecret(password, MIN_ADMIN_PASSWORD_LENGTH);
}

/** Why the session secret is refused (sessions would be forgeable), or null.
 *  Always null in development. */
export function sessionSecretError(): string | null {
  if (explicitDevelopment) return null;
  if (!config.sessionSecret) {
    return 'SESSION_SECRET is not set: set it to a random value of at least 32 characters ' +
      '(e.g. openssl rand -hex 32). The built-in development secret is only accepted with NODE_ENV=development.';
  }
  if (isWeakSecret(config.sessionSecret, MIN_SESSION_SECRET_LENGTH)) {
    return 'SESSION_SECRET is too weak: use a random value of at least 32 characters, not a placeholder ' +
      '(e.g. openssl rand -hex 32).';
  }
  return null;
}

/**
 * Settings the server refuses to start with, as messages for the operator
 * (empty: none, always in development). Checked by index.ts before anything
 * touches the database.
 */
export function startupConfigErrors(): string[] {
  // Database context settings: refused in every environment (a typo must
  // never silently weaken the row level security).
  const errors: string[] = [];
  if (config.dbContextMode === 'invalid') {
    errors.push('DB_CONTEXT_MODE must be "strict" (the default) or "audit".');
  }
  const ttl = config.platformGrantTtlSeconds;
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > 3600) {
    errors.push('PLATFORM_GRANT_TTL_SECONDS must be an integer between 60 and 3600 (900 by default).');
  }
  const keep = config.platformGrantRetentionDays;
  if (!Number.isInteger(keep) || keep < 30) {
    errors.push('PLATFORM_GRANT_RETENTION_DAYS must be an integer of at least 30 (365 by default).');
  }
  // Hardened audit journal (audit-durci §13.1): refused in every environment.
  const a = config.audit;
  if (a.export === 'invalid') errors.push('AUDIT_EXPORT must be "on" (the default) or "off".');
  if (!Number.isInteger(a.maxClockSkewSeconds) || a.maxClockSkewSeconds < 5 || a.maxClockSkewSeconds > 270) {
    errors.push('AUDIT_MAX_CLOCK_SKEW_SECONDS must be an integer from 5 to 270 (240 by default): the database refuses entries beyond 5 minutes.');
  }
  if (!Number.isInteger(a.tsaTimeoutMs) || a.tsaTimeoutMs < 1_000 || a.tsaTimeoutMs > 60_000) {
    errors.push('AUDIT_TSA_TIMEOUT_MS must be an integer from 1000 to 60000 (10000 by default).');
  }
  if (a.tsaUrl && !/^https?:\/\/[^\s]+$/i.test(a.tsaUrl)) errors.push('AUDIT_TSA_URL must be an http(s) URL of an RFC 3161 time-stamping authority.');
  if (a.tsaCertSha256 && !/^[0-9a-f]{64}$/.test(a.tsaCertSha256)) errors.push('AUDIT_TSA_CERT_SHA256 must be the SHA-256 of a certificate (64 hexadecimal characters).');
  if (a.sealCron.split(/\s+/).length !== 5) errors.push('AUDIT_SEAL_CRON must be a 5-field cron expression (12 * * * * by default).');
  // Background jobs: refused in every environment as well.
  errors.push(...jobsEnv.errors);
  if (config.migrateOnBoot && (!explicitDevelopment || !config.databaseAdminUrl)) {
    errors.push('MIGRATE_ON_BOOT=true is accepted only with NODE_ENV=development and DATABASE_ADMIN_URL set: ' +
      'outside development, the migrations run in the server-migrate service.');
  }
  if (explicitDevelopment) return errors;
  if (!config.databaseUrl) errors.push(DATABASE_URL_MISSING);
  if (config.databaseAdminUrl) {
    errors.push('DATABASE_ADMIN_URL is set: the server never holds the administration credentials outside ' +
      'development (only the server-migrate service does). Remove it from the server\'s environment.');
  }
  const secretError = sessionSecretError();
  if (secretError) errors.push(secretError);
  if (config.defaultAdminPassword && isWeakAdminPassword(config.defaultAdminPassword)) {
    errors.push(
      'DEFAULT_ADMIN_PASSWORD is too weak: use at least 12 characters and not a default value, or leave it ' +
      'empty to get a random password printed once in the startup logs.',
    );
  }
  return errors;
}

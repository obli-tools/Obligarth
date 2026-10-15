// Settings of the Android integration (Android Management API called directly by the instance). Read from the
// environment by readAndroidConfig(), which throws AndroidConfigError on any refused value: the server does not
// start with a broken Android setting. No database import and only erasable TypeScript: the unit tests run under
// node --test. No secret is ever read from the environment: the service account key lives in the vault.
import { GOOGLE_AMAPI_BASE_URL, GOOGLE_PUBSUB_BASE_URL, GOOGLE_TOKEN_URL } from './google/endpoints';

export type AndroidMode = 'off' | 'google' | 'fake';
export type AndroidAuthMode = 'vault_key' | 'adc';

export interface AndroidConfig {
  mode: AndroidMode;
  auth: AndroidAuthMode;
  /** Google Cloud project of this environment (google mode); the fake's project in fake mode. */
  projectId: string | null;
  /** projects/<projectId>/topics/<name> */
  topic: string | null;
  /** projects/<projectId>/subscriptions/<name> */
  subscription: string | null;
  /** Public HTTPS origin of the console (signup callback, signed logo URLs, parentFrameUrl). */
  publicOrigin: string | null;
  /** Base URLs of the REST APIs: frozen Google URLs in google mode, the fake's in fake mode. */
  amapiBaseUrl: string;
  pubsubBaseUrl: string;
  tokenUrl: string;
  pullMaxMessages: number;
  pullMaxBytes: number;
  pushConcurrencyPerTenant: number;
  commandConcurrency: number;
  inboxMaxBytes: number;
  rateProjectPer100s: number;
}

export class AndroidConfigError extends Error {
  constructor(message: string) {
    super(`Android settings: ${message}`);
    this.name = 'AndroidConfigError';
  }
}

export const INBOX_MAX_BYTES = 8 * 1024 * 1024;

const PROJECT_RE = /^[a-z][a-z0-9-]{4,62}[a-z0-9]$/;
const RESOURCE_NAME_RE = /^[A-Za-z][A-Za-z0-9._~%+-]{2,254}$/;
const FAKE_BASE_RE = /^http:\/\/127\.0\.0\.1:([0-9]{1,5})\/?$/;

type Env = Record<string, string | undefined>;

function intSetting(env: Env, name: string, dflt: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === '') return dflt;
  if (!/^[0-9]{1,9}$/.test(raw.trim())) throw new AndroidConfigError(`${name} must be an integer`);
  const n = Number(raw.trim());
  if (n < min || n > max) throw new AndroidConfigError(`${name} must be between ${min} and ${max}`);
  return n;
}

function httpsOrigin(value: string, name: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AndroidConfigError(`${name} is not a URL`);
  }
  if (url.protocol !== 'https:') throw new AndroidConfigError(`${name} must be an https origin`);
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new AndroidConfigError(`${name} must be a bare origin (https://host[:port])`);
  }
  return url.origin;
}

/** Validates projects/<projectId>/<kind>/<name>. */
function projectResource(value: string | undefined, name: string, projectId: string, kind: 'topics' | 'subscriptions'): string {
  if (!value) throw new AndroidConfigError(`${name} is required`);
  const parts = value.split('/');
  if (parts.length !== 4 || parts[0] !== 'projects' || parts[2] !== kind || !RESOURCE_NAME_RE.test(parts[3])) {
    throw new AndroidConfigError(`${name} must be projects/<project>/${kind}/<name>`);
  }
  if (parts[1] !== projectId) throw new AndroidConfigError(`${name} must belong to the project ANDROID_GCP_PROJECT_ID`);
  return value;
}

/** The Android settings of `env` (process.env by default). Throws AndroidConfigError. */
export function readAndroidConfig(env: Env = process.env): AndroidConfig {
  const mode = (env.ANDROID_MODE ?? 'off').trim() || 'off';
  if (mode !== 'off' && mode !== 'google' && mode !== 'fake') {
    throw new AndroidConfigError('ANDROID_MODE must be off, google or fake');
  }
  const auth = (env.ANDROID_GOOGLE_AUTH ?? 'vault_key').trim() || 'vault_key';
  if (auth !== 'vault_key' && auth !== 'adc') throw new AndroidConfigError('ANDROID_GOOGLE_AUTH must be vault_key or adc');
  const common = {
    pullMaxMessages: intSetting(env, 'ANDROID_PULL_MAX_MESSAGES', 100, 1, 1000),
    pullMaxBytes: intSetting(env, 'ANDROID_PULL_MAX_BYTES', 12 * 1024 * 1024, 1024, 12 * 1024 * 1024),
    pushConcurrencyPerTenant: intSetting(env, 'ANDROID_PUSH_CONCURRENCY_PER_TENANT', 2, 1, 8),
    commandConcurrency: intSetting(env, 'ANDROID_COMMAND_CONCURRENCY', 4, 1, 16),
    inboxMaxBytes: intSetting(env, 'ANDROID_INBOX_MAX_BYTES', INBOX_MAX_BYTES, 1024, INBOX_MAX_BYTES),
    rateProjectPer100s: intSetting(env, 'ANDROID_RATE_PROJECT_PER_100S', 900, 1, 1000),
  };
  if (env.ANDROID_FAKE_BASE_URL && mode !== 'fake') {
    throw new AndroidConfigError('ANDROID_FAKE_BASE_URL is only allowed with ANDROID_MODE=fake');
  }
  const gac = env.GOOGLE_APPLICATION_CREDENTIALS;
  if (gac && auth !== 'adc') throw new AndroidConfigError('GOOGLE_APPLICATION_CREDENTIALS is only read with ANDROID_GOOGLE_AUTH=adc');

  if (mode === 'off') {
    return {
      mode, auth, projectId: null, topic: null, subscription: null, publicOrigin: null,
      amapiBaseUrl: GOOGLE_AMAPI_BASE_URL, pubsubBaseUrl: GOOGLE_PUBSUB_BASE_URL, tokenUrl: GOOGLE_TOKEN_URL, ...common,
    };
  }

  const projectId = (env.ANDROID_GCP_PROJECT_ID ?? '').trim();
  if (!PROJECT_RE.test(projectId)) throw new AndroidConfigError('ANDROID_GCP_PROJECT_ID must be a Google Cloud project id');
  const topic = projectResource(env.ANDROID_PUBSUB_TOPIC?.trim(), 'ANDROID_PUBSUB_TOPIC', projectId, 'topics');
  const subscription = projectResource(env.ANDROID_PUBSUB_SUBSCRIPTION?.trim(), 'ANDROID_PUBSUB_SUBSCRIPTION', projectId, 'subscriptions');

  if (mode === 'fake') {
    const nodeEnv = env.NODE_ENV ?? '';
    if (nodeEnv !== 'test' && nodeEnv !== 'development') {
      throw new AndroidConfigError('ANDROID_MODE=fake is refused unless NODE_ENV is test or development');
    }
    const base = (env.ANDROID_FAKE_BASE_URL ?? '').trim();
    const m = FAKE_BASE_RE.exec(base);
    if (!m || Number(m[1]) < 1 || Number(m[1]) > 65535) {
      throw new AndroidConfigError('ANDROID_FAKE_BASE_URL must be http://127.0.0.1:<port>');
    }
    const root = base.replace(/\/$/, '');
    const origin = env.ANDROID_PUBLIC_ORIGIN?.trim();
    let publicOrigin: string | null = null;
    if (origin) {
      // The fake accepts a loopback http origin (the testbed's app), never a remote one.
      if (/^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(origin)) publicOrigin = origin;
      else publicOrigin = httpsOrigin(origin, 'ANDROID_PUBLIC_ORIGIN');
    }
    return {
      mode, auth, projectId, topic, subscription, publicOrigin,
      amapiBaseUrl: `${root}/amapi/v1/`, pubsubBaseUrl: `${root}/pubsub/v1/`, tokenUrl: `${root}/oauth2/token`, ...common,
    };
  }

  const origin = env.ANDROID_PUBLIC_ORIGIN?.trim();
  if (!origin) throw new AndroidConfigError('ANDROID_PUBLIC_ORIGIN is required with ANDROID_MODE=google');
  return {
    mode, auth, projectId, topic, subscription, publicOrigin: httpsOrigin(origin, 'ANDROID_PUBLIC_ORIGIN'),
    amapiBaseUrl: GOOGLE_AMAPI_BASE_URL, pubsubBaseUrl: GOOGLE_PUBSUB_BASE_URL, tokenUrl: GOOGLE_TOKEN_URL, ...common,
  };
}

let current: AndroidConfig | null = null;

/** The settings of this process (read once from process.env), or those configured by configureAndroid(). */
export function androidConfig(): AndroidConfig {
  if (!current) current = readAndroidConfig();
  return current;
}

/** Replaces the settings of this process (start, tests). */
export function configureAndroid(cfg: AndroidConfig): void {
  current = Object.freeze({ ...cfg });
}

export function androidEnabled(): boolean {
  return androidConfig().mode !== 'off';
}

import { AppleSecretError, readApiTokenFile, readHmacKeyFile } from './edge/secrets';

// =============================================================================
// Settings of the apple-edge integration (docs: integration-apple-edge annex
// A): parsed once (config.ts, config.apple), checked at start by
// startupConfigErrors() — a value out of its bounds is refused in every
// environment, development included. With APPLE_EDGE_MODE=on, the secret
// files (API token, DDM relay key) must be readable and well-formed and
// MDM_PUBLIC_BASE set. No secret in an environment variable: files only.
// Self-contained (no import of the server's config, env or logger): the unit
// tests run under node --test.
// =============================================================================

export type AppleEdgeMode = 'off' | 'on';

export interface AppleConfig {
  /** off (default): no call to apple-edge, device surface 404, console 503. */
  mode: AppleEdgeMode;
  /** Internal API of apple-edge (backend network), never public; no trailing slash. */
  edgeUrl: string;
  apiTokenFile: string;
  /** Default timeout of a call (1 000 to 60 000 ms). */
  timeoutMs: number;
  /** Accept the version 'dev' of apple-edge (laboratory); refused with NODE_ENV=production. */
  allowDevVersion: boolean;
  ddmHmacKeyFile: string;
  ddmHmacKeyNextFile: string | null;
  /** https://mdm.<domain>, no path, no trailing slash; same as apple-edge's. */
  mdmPublicBase: string | null;
  requireSignedProfiles: boolean;
  /** APPLE_ALLOW_DEFAULT_NOTICE: read for the existing .env files, without effect since P0-13 (the privacy profiles and the
   *  generated notice are always installed; P0-13 T11 refuses it outside the stage lab). */
  allowDefaultNotice: boolean;
  allowPushKeyImport: boolean;
  /** APPLE_MDM_VENDOR_CERT_SHA256: SHA-256 fingerprints (lower-case hex) of the instance's "MDM Vendor" certificates,
   *  the only ones a signed push request may carry (the vendor is the single operator). Empty: none pinned, refused
   *  with NODE_ENV=production, accepted elsewhere without any deadline of the instance (vendorPinRequired). */
  vendorCertPins: string[];
  vppBaseUrl: string;
  setupTimeoutS: number;
  /** Push relaunch steps, seconds, increasing (4 at most). */
  pushRelaunchSteps: number[];
  pushMaxPerTarget: number;
  enrollmentSpikeCount: number;
  inactiveDays: number;
  /** APPLE_RECONCILE_SPREAD_S: spread of the per-tenant reconciliations sent by apple-edge.reconcile-all (§13.1). */
  reconcileSpreadS: number;
}

export const APPLE_DEFAULTS = Object.freeze({
  edgeUrl: 'http://apple-edge:9100',
  apiTokenFile: '/run/secrets/apple_edge_api_token',
  timeoutMs: 10_000,
  ddmHmacKeyFile: '/run/secrets/apple_edge_ddm_hmac',
  vppBaseUrl: 'https://vpp.itunes.apple.com/mdm/v2/',
  setupTimeoutS: 600,
  pushRelaunchSteps: '15m,1h,4h,24h',
  pushMaxPerTarget: 8,
  enrollmentSpikeCount: 50,
  inactiveDays: 14,
  reconcileSpreadS: 600,
});

type Env = Record<string, string | undefined>;

function intIn(env: Env, name: string, min: number, max: number, fallback: number, errors: string[]): number {
  const raw = (env[name] ?? '').trim();
  if (raw === '') return fallback;
  if (!/^[0-9]+$/.test(raw) || Number(raw) < min || Number(raw) > max) {
    errors.push(`${name} must be an integer between ${min} and ${max} (${fallback} by default).`);
    return fallback;
  }
  return Number(raw);
}

function bool(env: Env, name: string, errors: string[]): boolean {
  const raw = (env[name] ?? '').trim();
  if (raw === '' || raw === 'false') return false;
  if (raw === 'true') return true;
  errors.push(`${name} must be "true" or "false" (false by default).`);
  return false;
}

const UNITS: Record<string, number> = { s: 1, m: 60, h: 3_600, d: 86_400 };

/** '15m,1h,4h,24h' → seconds; null when malformed (not increasing, more than 4, unknown unit). */
export function parseRelaunchSteps(text: string): number[] | null {
  const parts = text.split(',').map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0 || parts.length > 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    const m = /^([0-9]{1,5})([smhd])$/.exec(p);
    if (!m) return null;
    const s = Number(m[1]) * UNITS[m[2]];
    if (s <= 0 || (out.length > 0 && s <= out[out.length - 1])) return null;
    out.push(s);
  }
  return out;
}

/** APPLE_MDM_VENDOR_CERT_SHA256 → fingerprints (lower-case, no colon, no duplicate); [] when empty; null when malformed. */
export function parseVendorPins(text: string): string[] | null {
  const parts = text.split(',').map((p) => p.trim().replace(/:/g, '').toLowerCase()).filter(Boolean);
  if (parts.length > 8 || parts.some((p) => !/^[0-9a-f]{64}$/.test(p))) return null;
  return [...new Set(parts)];
}

/** Must a signed push request carry a pinned vendor certificate even when none is configured (production)? */
export function vendorPinRequired(nodeEnv: string): boolean {
  return nodeEnv === 'production';
}

/** MDM_PUBLIC_BASE: https, a host, no credentials, no path (but '/'), no query nor fragment, no trailing slash. */
export function mdmPublicBaseError(value: string): string | null {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return 'MDM_PUBLIC_BASE must be an absolute URL (https://mdm.example.net).';
  }
  if (u.protocol !== 'https:') return 'MDM_PUBLIC_BASE must be an https URL: devices only talk to an ATS-compliant TLS endpoint.';
  if (u.username || u.password || u.search || u.hash || (u.pathname !== '/' && u.pathname !== '') || value.endsWith('/')) {
    return 'MDM_PUBLIC_BASE must be https://<host>[:port], without path, query, credentials nor trailing slash (as apple-edge has it).';
  }
  return null;
}

/** APPLE_EDGE_URL: http(s), a host, no credentials, no path, query nor fragment. */
export function edgeUrlError(value: string): string | null {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return 'APPLE_EDGE_URL must be an absolute URL (http://apple-edge:9100).';
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return 'APPLE_EDGE_URL must be an http or https URL.';
  if (u.username || u.password || u.search || u.hash || (u.pathname !== '/' && u.pathname !== '')) {
    return 'APPLE_EDGE_URL must be http(s)://<host>[:port], without path, query nor credentials (the client adds /internal/v1).';
  }
  return null;
}

/** The settings of `env`, and why some are refused (empty: none). `nodeEnv`: NODE_ENV. Files are not read
 *  here (appleStartupErrors does it at start). */
export function readAppleConfig(env: Env = process.env, nodeEnv = env.NODE_ENV ?? ''): { config: AppleConfig; errors: string[] } {
  const errors: string[] = [];
  const modeRaw = (env.APPLE_EDGE_MODE ?? '').trim();
  let mode: AppleEdgeMode = 'off';
  if (modeRaw === 'on' || modeRaw === 'off') mode = modeRaw;
  else if (modeRaw !== '') errors.push('APPLE_EDGE_MODE must be "off" (the default) or "on".');

  const edgeUrl = ((env.APPLE_EDGE_URL ?? '').trim() || APPLE_DEFAULTS.edgeUrl).replace(/\/+$/, '');
  const urlError = edgeUrlError(edgeUrl);
  if (urlError) errors.push(urlError);

  const allowDevVersion = bool(env, 'APPLE_EDGE_ALLOW_DEV_VERSION', errors);
  if (allowDevVersion && nodeEnv === 'production') {
    errors.push('APPLE_EDGE_ALLOW_DEV_VERSION=true is refused with NODE_ENV=production (laboratory only).');
  }

  const baseRaw = (env.MDM_PUBLIC_BASE ?? '').trim();
  let mdmPublicBase: string | null = null;
  if (baseRaw !== '') {
    const e = mdmPublicBaseError(baseRaw);
    if (e) errors.push(e);
    else mdmPublicBase = baseRaw;
  } else if (mode === 'on') {
    errors.push('MDM_PUBLIC_BASE is required with APPLE_EDGE_MODE=on (https://mdm.<domain>, the same value as apple-edge).');
  }

  const vppRaw = (env.APPLE_VPP_BASE_URL ?? '').trim();
  let vppBaseUrl: string = APPLE_DEFAULTS.vppBaseUrl;
  if (vppRaw !== '' && vppRaw !== APPLE_DEFAULTS.vppBaseUrl) {
    if (nodeEnv !== 'test' && nodeEnv !== 'development') {
      errors.push('APPLE_VPP_BASE_URL may differ from Apple\'s URL only with NODE_ENV test or development.');
    } else if (!/^https?:\/\/[^\s]+\/$/.test(vppRaw)) {
      errors.push('APPLE_VPP_BASE_URL must be an http(s) URL ending with "/".');
    } else {
      vppBaseUrl = vppRaw;
    }
  }

  const stepsRaw = (env.APPLE_PUSH_RELAUNCH_STEPS ?? '').trim() || APPLE_DEFAULTS.pushRelaunchSteps;
  let pushRelaunchSteps = parseRelaunchSteps(stepsRaw);
  if (!pushRelaunchSteps) {
    errors.push('APPLE_PUSH_RELAUNCH_STEPS must list 1 to 4 increasing delays (15m,1h,4h,24h by default; units s, m, h, d).');
    pushRelaunchSteps = parseRelaunchSteps(APPLE_DEFAULTS.pushRelaunchSteps) as number[];
  }

  const vendorCertPins = parseVendorPins(env.APPLE_MDM_VENDOR_CERT_SHA256 ?? '');
  if (!vendorCertPins) errors.push('APPLE_MDM_VENDOR_CERT_SHA256 must list 1 to 8 SHA-256 fingerprints (64 hexadecimal digits, colons allowed), separated by commas.');

  const nextFile = (env.APPLE_EDGE_DDM_HMAC_KEY_NEXT_FILE ?? '').trim();
  return {
    config: {
      mode,
      edgeUrl,
      apiTokenFile: (env.APPLE_EDGE_API_TOKEN_FILE ?? '').trim() || APPLE_DEFAULTS.apiTokenFile,
      timeoutMs: intIn(env, 'APPLE_EDGE_TIMEOUT_MS', 1_000, 60_000, APPLE_DEFAULTS.timeoutMs, errors),
      allowDevVersion,
      ddmHmacKeyFile: (env.APPLE_EDGE_DDM_HMAC_KEY_FILE ?? '').trim() || APPLE_DEFAULTS.ddmHmacKeyFile,
      ddmHmacKeyNextFile: nextFile || null,
      mdmPublicBase,
      requireSignedProfiles: bool(env, 'APPLE_REQUIRE_SIGNED_PROFILES', errors),
      allowDefaultNotice: bool(env, 'APPLE_ALLOW_DEFAULT_NOTICE', errors),
      allowPushKeyImport: bool(env, 'APPLE_ALLOW_PUSH_KEY_IMPORT', errors),
      vendorCertPins: vendorCertPins ?? [],
      vppBaseUrl,
      setupTimeoutS: intIn(env, 'APPLE_SETUP_TIMEOUT_S', 120, 3_600, APPLE_DEFAULTS.setupTimeoutS, errors),
      pushRelaunchSteps,
      pushMaxPerTarget: intIn(env, 'APPLE_PUSH_MAX_PER_TARGET', 1, 20, APPLE_DEFAULTS.pushMaxPerTarget, errors),
      enrollmentSpikeCount: intIn(env, 'APPLE_ENROLLMENT_SPIKE_COUNT', 5, 10_000, APPLE_DEFAULTS.enrollmentSpikeCount, errors),
      inactiveDays: intIn(env, 'APPLE_INACTIVE_DAYS', 1, 365, APPLE_DEFAULTS.inactiveDays, errors),
      reconcileSpreadS: intIn(env, 'APPLE_RECONCILE_SPREAD_S', 0, 3_600, APPLE_DEFAULTS.reconcileSpreadS, errors),
    },
    errors,
  };
}

/** The checks that read the secret files (start-up, APPLE_EDGE_MODE=on only): readable, well-formed. The
 *  messages never carry a secret. */
export function appleStartupErrors(c: AppleConfig): string[] {
  if (c.mode !== 'on') return [];
  const errors: string[] = [];
  const attempt = (fn: () => unknown): void => {
    try {
      fn();
    } catch (err) {
      errors.push(err instanceof AppleSecretError ? err.message : 'an apple-edge secret file could not be read');
    }
  };
  attempt(() => readApiTokenFile(c.apiTokenFile));
  attempt(() => readHmacKeyFile(c.ddmHmacKeyFile));
  if (c.ddmHmacKeyNextFile) attempt(() => readHmacKeyFile(c.ddmHmacKeyNextFile as string, 'APPLE_EDGE_DDM_HMAC_KEY_NEXT_FILE'));
  return errors;
}

/** May the default notice and privacy rules serve an enrollment (section 10.7)? Without effect since P0-13 T5: no start-up
 *  check reads it any more (the default notices are replaced in every process, privacy/notice). */
export function defaultNoticeAllowed(c: AppleConfig, nodeEnv: string): boolean {
  return c.allowDefaultNotice || nodeEnv === 'development' || nodeEnv === 'test';
}

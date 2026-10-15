// OAuth 2.0 access token of the instance's Google identity, kept in the memory of the process only (never in the
// database, a job, a log or a response). vault_key: the sealed key is opened at most every 10 minutes (cache), the
// JWT assertion signed and exchanged at the token endpoint, the token (one hour) reused until 60 s before its
// expiry. adc: the metadata server, or a federation configuration through google-auth-library when it is
// installed. fake mode without a key: a fixed fake token (the testbed's fake AMAPI accepts it).
import { readFileSync } from 'node:fs';
import { request } from 'undici';
import type { AndroidConfig } from '../config';
import { AndroidAuthError, AndroidUnavailableError } from '../gateway/errors';
import { AndroidCredentialError, checkAdcFile, parseServiceAccountKey, signAssertion, type ServiceAccountKey } from './credentials';
import { GOOGLE_METADATA_EMAIL_URL, GOOGLE_METADATA_TOKEN_URL, GOOGLE_SCOPES } from './endpoints';

export const FAKE_ACCESS_TOKEN = 'fake-access-token-for-the-testbed';
const KEY_CACHE_MS = 10 * 60_000;
const TOKEN_MARGIN_MS = 60_000;
const TOKEN_TIMEOUT_MS = 15_000;

export interface IdentityStatus {
  mode: 'vault_key' | 'adc' | 'fake';
  configured: boolean;
  fingerprint: string | null;
  account: string | null;
  lastTokenAt: number | null;
  lastError: string | null;
}

/** Reads the sealed key (vault instance secret), or null when none is deposited. */
export type SealedKeyLoader = () => Promise<string | null>;

async function readJson(res: Awaited<ReturnType<typeof request>>, max = 64 * 1024): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of res.body) {
    size += (c as Buffer).length;
    if (size > max) { res.body.destroy(); throw new AndroidUnavailableError('token answer too large'); }
    chunks.push(c as Buffer);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return null; }
}

export class GoogleTokenProvider {
  private token: { value: string; expiresAt: number } | null = null;
  private key: { key: ServiceAccountKey; at: number } | null = null;
  private inflight: Promise<string> | null = null;
  private status: IdentityStatus;
  private readonly cfg: AndroidConfig;
  private readonly loadKey: SealedKeyLoader;

  constructor(cfg: AndroidConfig, loadKey: SealedKeyLoader) {
    this.cfg = cfg;
    this.loadKey = loadKey;
    this.status = {
      mode: cfg.mode === 'fake' && cfg.auth === 'vault_key' ? 'fake' : cfg.auth,
      configured: false, fingerprint: null, account: null, lastTokenAt: null, lastError: null,
    };
  }

  identity(): IdentityStatus {
    return { ...this.status };
  }

  /** Forgets the cached key and token (a new key was deposited, or Google refused the token). */
  reset(): void {
    this.token = null;
    this.key = null;
  }

  async accessToken(): Promise<string> {
    if (this.token && this.token.expiresAt - TOKEN_MARGIN_MS > Date.now()) return this.token.value;
    if (!this.inflight) {
      this.inflight = this.fetchToken().finally(() => { this.inflight = null; });
    }
    return this.inflight;
  }

  private async sealedKey(): Promise<ServiceAccountKey | null> {
    if (this.key && Date.now() - this.key.at < KEY_CACHE_MS) return this.key.key;
    this.key = null;
    const text = await this.loadKey();
    if (text === null) return null;
    const key = parseServiceAccountKey(text, { projectId: String(this.cfg.projectId), tokenUrl: this.cfg.tokenUrl });
    this.key = { key, at: Date.now() };
    return key;
  }

  private async fetchToken(): Promise<string> {
    try {
      const value = await this.obtain();
      this.status.lastTokenAt = Date.now();
      this.status.lastError = null;
      return value;
    } catch (err) {
      this.status.lastError = (err as { code?: string; kind?: string }).code ?? (err as { kind?: string }).kind ?? 'error';
      if (err instanceof AndroidCredentialError) throw new AndroidAuthError(`identity: ${err.code}`);
      throw err;
    }
  }

  private async obtain(): Promise<string> {
    if (this.cfg.auth === 'adc') return this.obtainAdc();
    const key = await this.sealedKey();
    if (!key) {
      if (this.cfg.mode === 'fake') {
        this.status.configured = true;
        this.status.fingerprint = 'fake';
        this.token = { value: FAKE_ACCESS_TOKEN, expiresAt: Date.now() + 3600_000 };
        return FAKE_ACCESS_TOKEN;
      }
      this.status.configured = false;
      throw new AndroidAuthError('identity: no service account key deposited');
    }
    this.status.configured = true;
    this.status.fingerprint = key.privateKeyId;
    this.status.account = key.clientEmail;
    const assertion = signAssertion(key, GOOGLE_SCOPES);
    const body = new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }).toString();
    let res;
    try {
      res = await request(key.tokenUri, {
        method: 'POST', body, headers: { 'content-type': 'application/x-www-form-urlencoded' },
        headersTimeout: TOKEN_TIMEOUT_MS, bodyTimeout: TOKEN_TIMEOUT_MS,
      });
    } catch {
      throw new AndroidUnavailableError('token endpoint unreachable');
    }
    const json = await readJson(res) as { access_token?: unknown; expires_in?: unknown } | null;
    if (res.statusCode >= 500) throw new AndroidUnavailableError(`token endpoint answered ${res.statusCode}`);
    if (res.statusCode !== 200 || typeof json?.access_token !== 'string') {
      this.key = null;
      throw new AndroidAuthError(`identity: token refused (${res.statusCode})`);
    }
    const ttl = typeof json.expires_in === 'number' && json.expires_in > 0 ? Math.min(json.expires_in, 3600) : 3600;
    this.token = { value: json.access_token, expiresAt: Date.now() + ttl * 1000 };
    return json.access_token;
  }

  private async obtainAdc(): Promise<string> {
    const file = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    let content: string | null = null;
    if (file) {
      try { content = readFileSync(file, 'utf8'); } catch { throw new AndroidCredentialError('adc_unreadable', 'GOOGLE_APPLICATION_CREDENTIALS is unreadable'); }
    }
    const source = checkAdcFile(content);
    this.status.configured = true;
    if (source === 'external_account') {
      // Federation: google-auth-library (pinned) when installed; the instance writes no STS exchange of its own.
      let lib: { GoogleAuth: new (o: unknown) => { getAccessToken(): Promise<string | null | undefined> } };
      try {
        lib = await import('google-auth-library' as string) as typeof lib;
      } catch {
        throw new AndroidCredentialError('adc_unsupported', 'workload identity federation needs google-auth-library');
      }
      const auth = new lib.GoogleAuth({ scopes: [...GOOGLE_SCOPES] });
      const value = await auth.getAccessToken();
      if (!value) throw new AndroidAuthError('identity: federation gave no token');
      this.status.fingerprint = 'external_account';
      this.token = { value, expiresAt: Date.now() + 3000_000 };
      return value;
    }
    let res;
    try {
      res = await request(`${GOOGLE_METADATA_TOKEN_URL}?scopes=${encodeURIComponent(GOOGLE_SCOPES.join(','))}`, {
        method: 'GET', headers: { 'metadata-flavor': 'Google' }, headersTimeout: 5_000, bodyTimeout: 5_000,
      });
    } catch {
      throw new AndroidUnavailableError('metadata server unreachable');
    }
    const json = await readJson(res) as { access_token?: unknown; expires_in?: unknown } | null;
    if (res.statusCode !== 200 || typeof json?.access_token !== 'string') throw new AndroidAuthError(`identity: metadata server refused (${res.statusCode})`);
    if (!this.status.account) {
      try {
        const r = await request(GOOGLE_METADATA_EMAIL_URL, { method: 'GET', headers: { 'metadata-flavor': 'Google' }, headersTimeout: 5_000, bodyTimeout: 5_000 });
        const email = (await r.body.text()).trim();
        if (/^[a-z0-9-]+@[a-z0-9.-]+$/.test(email)) { this.status.account = email; this.status.fingerprint = email.slice(0, 64); }
      } catch { /* the principal is informative only */ }
    }
    const ttl = typeof json.expires_in === 'number' && json.expires_in > 0 ? Math.min(json.expires_in, 3600) : 3000;
    this.token = { value: json.access_token, expiresAt: Date.now() + ttl * 1000 };
    return json.access_token;
  }
}

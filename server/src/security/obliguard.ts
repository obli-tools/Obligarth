import { logger } from '../utils/logger';

// =============================================================================
// Obliguard reporting of the MCP server's blocks (docs: specs mcp-server §3.7):
// a port of Oblimint's services/security/obliguard.ts (itself Oblihub's
// obliguardHub.service.ts), with injectable fetch and configuration.
//   - target: the URL of the MCP settings, else discovered through Obligate's
//     connected apps (appType 'obliguard'), cached 60 s;
//   - auth: a FRESH Obligate delegation token per call (POST <obligate>/api/
//     delegation/token, audience 'obliguard', subjectType 'app', tenant
//     'master'): Obliguard accepts each jti once, so a token is never cached
//     nor reused. No shared secret. The token is never logged nor put in an
//     error;
//   - POST /api/external-bans {ip, source:'obligarth', reason, proxy_host_domain,
//     source_type, first_seen_at, hit_count, banned_until}, DELETE
//     /api/external-bans/:ip (404 counts as done), GET /api/external-bans/ping;
//     5 s timeout each. The methods never throw.
// =============================================================================

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface ObliguardConfig {
  /** The URL of the MCP settings (null: discover). */
  manualUrl: string | null;
  /** Obligate URL and API key (app_config), null when Obligate is not configured. */
  obligate: { url: string; apiKey: string } | null;
  /** Obligate's connected apps (obligateService.getConnectedApps). */
  connectedApps(): Promise<Array<{ appType?: string; name?: string; baseUrl?: string }>>;
}

export interface ObliguardBanPayload {
  ip: string;
  source: 'obligarth';
  reason: string;
  proxy_host_domain: string | null;
  source_type: 'mcp-strict' | 'mcp-failures' | 'mcp-manual';
  first_seen_at: string;
  hit_count: number;
  /** null: permanent (Obliguard caps a ban at 7 days). */
  banned_until: string | null;
}

export type ObliguardResult = { ok: true } | { ok: false; error: string };

const TARGET_TTL_MS = 60_000;
const TIMEOUT_MS = 5_000;
const TENANT_SLUG = 'master';

/** http(s) origin and path without a trailing slash, or null (never a token sent to a non-http URL nor with credentials). */
export function cleanBaseUrl(v: unknown): string | null {
  if (typeof v !== 'string' || !v.trim()) return null;
  try {
    const u = new URL(v.trim());
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (u.username || u.password) return null;
    return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
  } catch {
    return null;
  }
}

/** A short error text without any token. */
export function errorText(err: unknown): string {
  const msg = err instanceof Error ? (err.name === 'TimeoutError' || err.name === 'AbortError' ? 'timeout' : err.message) : String(err);
  return msg.replace(/Bearer\s+\S+/gi, 'Bearer ***').slice(0, 300);
}

export class ObliguardClient {
  private target: { url: string; at: number } | null = null;

  constructor(
    private readonly loadConfig: () => Promise<ObliguardConfig>,
    private readonly fetchFn: FetchLike = (url, init) => fetch(url, init),
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** Forgets the cached target (settings changed). */
  reset(): void {
    this.target = null;
  }

  async resolveTarget(): Promise<string | null> {
    const now = this.now();
    if (this.target && now - this.target.at < TARGET_TTL_MS) return this.target.url;
    const cfg = await this.loadConfig();
    let url = cleanBaseUrl(cfg.manualUrl);
    if (!url && cfg.obligate) {
      try {
        const apps = await cfg.connectedApps();
        const guard = apps.find((a) => (a.appType ?? '').toLowerCase() === 'obliguard');
        url = cleanBaseUrl(guard?.baseUrl);
      } catch {
        url = null;
      }
    }
    if (url) this.target = { url, at: now };
    return url;
  }

  /** A fresh delegation token, never cached (one jti per call), null when Obligate refuses or is not configured. */
  async delegationToken(): Promise<string | null> {
    const cfg = await this.loadConfig();
    const base = cfg.obligate ? cleanBaseUrl(cfg.obligate.url) : null;
    if (!base || !cfg.obligate?.apiKey) return null;
    try {
      const res = await this.fetchFn(`${base}/api/delegation/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${cfg.obligate.apiKey}` },
        body: JSON.stringify({ audience: 'obliguard', subjectType: 'app', tenantSlug: TENANT_SLUG, scope: 'read' }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) {
        logger.warn({ status: res.status }, 'Obliguard: delegation token refused by Obligate');
        return null;
      }
      const body = await res.json() as { success?: boolean; data?: { token?: unknown } };
      const token = body?.data?.token;
      if (!body?.success || typeof token !== 'string' || !token) return null;
      return token;
    } catch (err) {
      logger.warn({ err: errorText(err) }, 'Obliguard: delegation token request failed');
      return null;
    }
  }

  private async call(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown): Promise<ObliguardResult> {
    try {
      const target = await this.resolveTarget();
      if (!target) return { ok: false, error: 'Obliguard not configured or not discovered through Obligate' };
      const token = await this.delegationToken();
      if (!token) return { ok: false, error: 'Obligate delegation token unavailable' };
      const res = await this.fetchFn(`${target}${path}`, {
        method,
        headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), Authorization: `Bearer ${token}` },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (res.ok || (method === 'DELETE' && res.status === 404)) return { ok: true };
      const text = await res.text().catch(() => '');
      return { ok: false, error: `HTTP ${res.status}${text ? `: ${errorText(text).slice(0, 200)}` : ''}` };
    } catch (err) {
      return { ok: false, error: errorText(err) };
    }
  }

  sendBan(payload: ObliguardBanPayload): Promise<ObliguardResult> {
    return this.call('POST', '/api/external-bans', payload);
  }

  deleteBan(ip: string): Promise<ObliguardResult> {
    return this.call('DELETE', `/api/external-bans/${encodeURIComponent(ip)}`);
  }

  ping(): Promise<ObliguardResult> {
    return this.call('GET', '/api/external-bans/ping');
  }
}

// ── Push queue (concurrency 1, at most 30 per minute) ───────────────────────

type Job = () => Promise<void>;

/** In-process queue of the Obliguard pushes: one at a time, at most `perMinute` per minute; the surplus waits (the
 *  5-minute retry of the MCP module picks up rows still pending). Never throws. */
export class PushQueue {
  private queue: Job[] = [];
  private running = false;
  private stamps: number[] = [];

  constructor(private readonly perMinute = 30, private readonly maxQueued = 1000) {}

  /** False when the queue is full (the row stays pending for the retry). */
  push(job: Job): boolean {
    if (this.queue.length >= this.maxQueued) return false;
    this.queue.push(job);
    void this.drain();
    return true;
  }

  get size(): number { return this.queue.length; }

  private async drain(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      while (this.queue.length > 0) {
        const now = Date.now();
        this.stamps = this.stamps.filter((t) => now - t < 60_000);
        if (this.stamps.length >= this.perMinute) {
          await new Promise((r) => setTimeout(r, Math.max(1_000, 60_000 - (now - this.stamps[0]))).unref?.());
          continue;
        }
        const job = this.queue.shift()!;
        this.stamps.push(now);
        try { await job(); } catch (err) { logger.warn({ err: errorText(err) }, 'Obliguard push failed'); }
      }
    } finally {
      this.running = false;
    }
  }
}

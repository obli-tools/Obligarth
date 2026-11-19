import { cleanBaseUrl, errorText, type FetchLike } from '../../security/obliguard';
import { logger } from '../../utils/logger';
import { OBLIWATCH_APP } from './config';

// =============================================================================
// The outbound client of the push to Obliwatch (brief GTH-01, §3; plan L3), on the model of security/obliguard.ts:
//   - target: Obliwatch's URL discovered through Obligate's connected apps (app type 'obliwatch'), cached 60 s;
//   - auth: a FRESH Obligate delegation token for EVERY HTTP request, retries included (Obliwatch burns each jti):
//     POST <obligate>/api/delegation/token {audience:'obliwatch', subjectType:'app', tenantSlug:<the tenant's slug>,
//     scope:'read'} (pair obligarth:obliwatch at Obligate). Never cached, never logged, never put in an error;
//   - GET /api/ingest/v1/producer-config (cached 5 minutes per tenant): the modules and disabled rule prefixes;
//   - POST /api/ingest/v1/alerts {alerts:[1..500]}: one result per item. 503 and 429 carry Retry-After (honoured).
//   GET /api/external/v1/catalogues/ai-domains (lot L4, GTH-06): the AI catalog, read by the daily job catalog-sync
//   (catalog.ts parses it), with the same token pattern, conditional (If-None-Match / 304 with the stored ETag).
// The producer-config also carries (lot L4) the attestation of the tenant for the nominative view of the AI apps:
// data.attestations.nominativeAiApps (boolean; data.nominativeAiApps accepted too); absent: null (not attested).
// 10 s timeout per request, answers of 4 MiB at most. The methods never throw: they answer a result.
// =============================================================================

export interface ObliwatchClientConfig {
  /** Obligate URL and API key, null when Obligate is not configured. */
  obligate: { url: string; apiKey: string } | null;
  /** Obligate's connected apps (obligateService.getConnectedApps). */
  connectedApps(): Promise<Array<{ appType?: string; baseUrl?: string }>>;
}

export interface ProducerConfig {
  modules: Record<string, boolean>;
  ruleIdPrefixesDisabled: string[];
  maxBatch: number;
  minIntervalSec: number;
  /** Lot L4: Obliwatch attests the tenant may see the AI apps by device (null: the field is absent). */
  nominativeAiAppsAttested: boolean | null;
}

export interface IngestResult { eventId: string; status: string; code?: string }

/** A failed call: retryable unless stated, with the delay Obliwatch asked (Retry-After, seconds). */
export interface CallFailure { ok: false; error: string; status: number | null; retryAfterSeconds: number | null }

export type AlertsResult = { ok: true; results: IngestResult[] } | CallFailure;
export type ConfigResult = { ok: true; config: ProducerConfig } | CallFailure;

const TARGET_TTL_MS = 60_000;
const CONFIG_TTL_MS = 5 * 60_000;
const TIMEOUT_MS = 10_000;
const MAX_ANSWER_BYTES = 4 * 1024 * 1024;

function retryAfterOf(v: string | null): number | null {
  if (!v) return null;
  const n = Number(v.trim());
  if (Number.isFinite(n) && n >= 0) return Math.min(Math.ceil(n), 86_400);
  const t = Date.parse(v);
  return Number.isFinite(t) ? Math.min(Math.max(0, Math.ceil((t - Date.now()) / 1000)), 86_400) : null;
}

/**
 * The body of an answer, `max` BYTES at most, never buffered beyond: a Content-Length above the bound is refused before
 * any read, and the stream is counted as it comes and cancelled once the bound is passed (null: too large). A body that
 * cannot be read is ''. Decoded as UTF-8 afterwards.
 */
async function readBounded(res: Response, max: number): Promise<string | null> {
  const declared = Number(res.headers?.get?.('content-length') ?? NaN);
  if (Number.isFinite(declared) && declared > max) {
    await res.body?.cancel().catch(() => undefined);
    return null;
  }
  if (!res.body) return res.text().then((t) => (Buffer.byteLength(t, 'utf8') > max ? null : t)).catch(() => '');
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return '';
  }
  return new TextDecoder('utf-8').decode(Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength))));
}

const fail = (error: string, status: number | null = null, retryAfterSeconds: number | null = null): CallFailure =>
  ({ ok: false, error: errorText(error).slice(0, 300), status, retryAfterSeconds });

/** The attestation of the nominative view of the AI apps in a producer-config (lot L4); null when absent. */
function attestedOf(d: Record<string, unknown>): boolean | null {
  const a = d.attestations && typeof d.attestations === 'object' ? (d.attestations as Record<string, unknown>).nominativeAiApps : undefined;
  if (typeof a === 'boolean') return a;
  return typeof d.nominativeAiApps === 'boolean' ? d.nominativeAiApps : null;
}

export class ObliwatchClient {
  private target: { url: string; at: number } | null = null;
  private readonly configs = new Map<string, { config: ProducerConfig; at: number }>();

  constructor(
    private loadConfig: () => Promise<ObliwatchClientConfig>,
    private fetchFn: FetchLike = (url, init) => fetch(url, init),
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** Tests: another configuration or fetch; forgets every cache. */
  configure(o: { loadConfig?: () => Promise<ObliwatchClientConfig>; fetchFn?: FetchLike }): void {
    if (o.loadConfig) this.loadConfig = o.loadConfig;
    if (o.fetchFn) this.fetchFn = o.fetchFn;
    this.reset();
  }

  reset(): void {
    this.target = null;
    this.configs.clear();
  }

  async resolveTarget(): Promise<string | null> {
    const now = this.now();
    if (this.target && now - this.target.at < TARGET_TTL_MS) return this.target.url;
    const cfg = await this.loadConfig();
    if (!cfg.obligate) return null;
    let url: string | null = null;
    try {
      const apps = await cfg.connectedApps();
      url = cleanBaseUrl(apps.find((a) => (a.appType ?? '').toLowerCase() === OBLIWATCH_APP)?.baseUrl);
    } catch {
      url = null;
    }
    if (url) this.target = { url, at: now };
    return url;
  }

  /** A fresh delegation token for the tenant (one jti per HTTP request), null when Obligate refuses. */
  private async delegationToken(tenantSlug: string): Promise<string | null> {
    const cfg = await this.loadConfig();
    const base = cfg.obligate ? cleanBaseUrl(cfg.obligate.url) : null;
    if (!base || !cfg.obligate?.apiKey) return null;
    try {
      const res = await this.fetchFn(`${base}/api/delegation/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${cfg.obligate.apiKey}` },
        body: JSON.stringify({ audience: OBLIWATCH_APP, subjectType: 'app', tenantSlug, scope: 'read' }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) {
        logger.warn({ status: res.status }, 'obliwatch push: delegation token refused by Obligate');
        return null;
      }
      const body = await res.json() as { success?: boolean; data?: { token?: unknown } };
      const token = body?.data?.token;
      return body?.success && typeof token === 'string' && token ? token : null;
    } catch (err) {
      logger.warn({ err: errorText(err) }, 'obliwatch push: delegation token request failed');
      return null;
    }
  }

  private async call(tenantSlug: string, method: 'GET' | 'POST', path: string, body?: unknown, ifNoneMatch?: string | null):
    Promise<{ ok: true; json: unknown; etag: string | null; notModified: boolean } | CallFailure> {
    try {
      const target = await this.resolveTarget();
      if (!target) return fail('Obliwatch not discovered through Obligate (connected app obliwatch)');
      const token = await this.delegationToken(tenantSlug);
      if (!token) return fail('Obligate delegation token unavailable');
      const res = await this.fetchFn(`${target}${path}`, {
        method,
        headers: {
          Accept: 'application/json',
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
          ...(ifNoneMatch ? { 'If-None-Match': ifNoneMatch } : {}),
          Authorization: `Bearer ${token}`,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(TIMEOUT_MS),
        redirect: 'error',
      });
      const etagRaw = res.headers?.get?.('etag') ?? null;
      // An ETag is an opaque, printable token (RFC 9110 entity-tag, weak or strong); anything else is ignored.
      const etag = etagRaw && /^(W\/)?"[\x21\x23-\x7e]{0,250}"$/.test(etagRaw.trim()) ? etagRaw.trim() : null;
      if (res.status === 304 && ifNoneMatch) {
        await res.body?.cancel().catch(() => undefined);
        return { ok: true, json: null, etag: etag ?? ifNoneMatch, notModified: true };
      }
      const text = await readBounded(res, MAX_ANSWER_BYTES);
      if (text === null) return fail('answer too large', res.status);
      if (!res.ok) {
        let code = '';
        try { code = String((JSON.parse(text) as { code?: unknown; error?: unknown })?.code ?? ''); } catch { /* not JSON */ }
        return fail(`HTTP ${res.status}${code ? ` ${code.slice(0, 60)}` : ''}`, res.status, retryAfterOf(res.headers.get('retry-after')));
      }
      try {
        return { ok: true, json: text ? JSON.parse(text) : null, etag, notModified: false };
      } catch {
        return fail('invalid JSON answer', res.status);
      }
    } catch (err) {
      return fail(errorText(err));
    }
  }

  /** The producer configuration of the tenant (cached 5 minutes per tenant). */
  async producerConfig(tenantSlug: string): Promise<ConfigResult> {
    const now = this.now();
    const c = this.configs.get(tenantSlug);
    if (c && now - c.at < CONFIG_TTL_MS) return { ok: true, config: c.config };
    const r = await this.call(tenantSlug, 'GET', '/api/ingest/v1/producer-config');
    if (!r.ok) return r;
    const d = (r.json as { data?: Record<string, unknown> } | null)?.data;
    if (!d || typeof d !== 'object') return fail('invalid producer-config answer');
    const modules: Record<string, boolean> = {};
    if (d.modules && typeof d.modules === 'object') {
      for (const [k, v] of Object.entries(d.modules as Record<string, unknown>)) if (typeof v === 'boolean') modules[k] = v;
    }
    const config: ProducerConfig = {
      modules,
      ruleIdPrefixesDisabled: Array.isArray(d.ruleIdPrefixesDisabled) ? d.ruleIdPrefixesDisabled.filter((x): x is string => typeof x === 'string').slice(0, 200) : [],
      maxBatch: Number.isInteger(d.maxBatch) && (d.maxBatch as number) > 0 ? Math.min(d.maxBatch as number, 500) : 500,
      minIntervalSec: Number.isInteger(d.minIntervalSec) && (d.minIntervalSec as number) >= 0 ? Math.min(d.minIntervalSec as number, 300) : 10,
      nominativeAiAppsAttested: attestedOf(d),
    };
    if (this.configs.size > 10_000) this.configs.clear();
    this.configs.set(tenantSlug, { config, at: now });
    return { ok: true, config };
  }

  /**
   * The AI catalog of Obliwatch (raw JSON, parsed by catalog.ts), with a token of `tenantSlug` (a consenting tenant).
   * `etag`: the ETag of the stored catalog, sent as If-None-Match; a 304 answers notModified (json null).
   */
  async aiCatalog(tenantSlug: string, etag?: string | null):
    Promise<{ ok: true; json: unknown; etag: string | null; notModified: boolean } | CallFailure> {
    return this.call(tenantSlug, 'GET', '/api/external/v1/catalogues/ai-domains', undefined, etag);
  }

  /**
   * Lot L5 (GTH-05): one batch of results of action requests (1 to 100) of the tenant, POST /api/ingest/v1/action-results
   * {results: [...]}. Obliwatch had not built the route when this was written: any 2xx counts as delivered for the whole
   * batch; a failure carries its HTTP status (404 included) for the caller's retries.
   */
  async postActionResults(tenantSlug: string, results: unknown[]): Promise<{ ok: true } | CallFailure> {
    const r = await this.call(tenantSlug, 'POST', '/api/ingest/v1/action-results', { results });
    return r.ok ? { ok: true } : r;
  }

  /** One batch of alerts (1 to 500) of the tenant. */
  async postAlerts(tenantSlug: string, alerts: unknown[]): Promise<AlertsResult> {
    const r = await this.call(tenantSlug, 'POST', '/api/ingest/v1/alerts', { alerts });
    if (!r.ok) return r;
    const results = (r.json as { results?: unknown } | null)?.results;
    if (!Array.isArray(results)) return fail('invalid ingest answer');
    return {
      ok: true,
      results: results.map((x) => {
        const o = (x ?? {}) as Record<string, unknown>;
        return { eventId: String(o.eventId ?? ''), status: String(o.status ?? ''), ...(typeof o.code === 'string' ? { code: o.code.slice(0, 40) } : {}) };
      }),
    };
  }
}

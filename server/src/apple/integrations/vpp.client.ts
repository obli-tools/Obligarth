import { setTimeout as wait } from 'node:timers/promises';
import { config } from '../../config';
import { logger } from '../../utils/logger';

// =============================================================================
// Client of the Apps and Books API v2 (docs: integration-apple-edge §11.3;
// research 06 §4.9), called by the brain directly (APPLE_VPP_BASE_URL; Apple's
// https://vpp.itunes.apple.com/mdm/v2/ by default). The content token (sToken)
// is the bearer of every call but service/config; it is handed by the caller,
// opened from the vault for the call, and never logged nor kept here.
//   service/config   no authentication; cached 5 minutes in memory; its limits
//                    (maxAssets, maxSerialNumbers, maxClientUserIds,
//                    maxRequestPerSecond…) split the operations and feed the
//                    token bucket of each content token
//   429, error 9646  exponential wait, then again (3 attempts at most)
//   5xx              Retry-After, then again (3 attempts at most)
//   token refused    VppApiError kind 'token_rejected' (401, 403, or one of
//                    the error numbers of a token Apple no longer accepts)
// The shapes read from Apple are parsed leniently: a field Apple does not send
// is null, never a crash; a token expiry it sends (tokenExpirationDate) is
// returned with every answer so that the caller moves the deadline on.
// [J1]: error numbers, field names of the answers and of the notifications are
// those of Apple's documentation, to confirm with a real organisation.
// =============================================================================

export type VppErrorKind = 'rate_limited' | 'unavailable' | 'token_rejected' | 'protocol' | 'request' | 'network';

export class VppApiError extends Error {
  readonly kind: VppErrorKind;
  readonly status: number;
  readonly errorNumber: number | null;
  readonly retryAfterMs: number | null;
  constructor(kind: VppErrorKind, status: number, errorNumber: number | null, message: string, retryAfterMs: number | null = null) {
    super(message);
    this.name = 'VppApiError';
    this.kind = kind;
    this.status = status;
    this.errorNumber = errorNumber;
    this.retryAfterMs = retryAfterMs;
  }
  /** A short code for a log line, a column or an alert (never a text of Apple's). */
  get code(): string {
    return this.errorNumber !== null ? `vpp_${this.errorNumber}` : `${this.kind}_${this.status}`;
  }
}

export const isVppApiError = (e: unknown): e is VppApiError => e instanceof VppApiError;

/** Error numbers of a token Apple no longer accepts (invalid, expired, revoked, another location) [J1]. */
const TOKEN_ERRORS = new Set([9621, 9622, 9624, 9625]);
/** Error number of a rate limit (06 §4.9). */
const RATE_LIMIT_ERROR = 9646;
const ATTEMPTS = 3;
const TIMEOUT_MS = 15_000;
/** First wait of a rate limit, then doubled; a Retry-After is capped by MAX_WAIT_MS. */
export const vppTiming = { baseWaitMs: 1_000, maxWaitMs: 30_000 };

export interface VppLimits {
  maxAssets: number;
  maxSerialNumbers: number;
  maxClientUserIds: number;
  maxUsers: number;
  maxRequestPerSecond: number;
}

/** Bounds used until service/config was read (the most prudent of Apple's documented values). */
export const DEFAULT_VPP_LIMITS: Readonly<VppLimits> = Object.freeze({
  maxAssets: 25, maxSerialNumbers: 1000, maxClientUserIds: 25, maxUsers: 25, maxRequestPerSecond: 10,
});

const SERVICE_CONFIG_TTL_MS = 5 * 60_000;
let serviceCache: { base: string; at: number; limits: VppLimits } | null = null;

/** The limits last read from service/config (the defaults when never read or older than its cache): no network. */
export function cachedLimits(): VppLimits {
  return serviceCache && serviceCache.base === config.apple.vppBaseUrl ? serviceCache.limits : { ...DEFAULT_VPP_LIMITS };
}

/** Tests: forget the cached service configuration and the buckets. */
export function resetVppClientForTests(): void {
  serviceCache = null;
  buckets.clear();
}

// ── Token bucket per content token (maxRequestPerSecond) ─────────────────────────
interface Bucket { tokens: number; at: number }
const buckets = new Map<string, Bucket>();

async function takeToken(key: string, perSecond: number): Promise<void> {
  const rate = Math.max(1, perSecond);
  for (;;) {
    const now = Date.now();
    const b = buckets.get(key) ?? { tokens: rate, at: now };
    b.tokens = Math.min(rate, b.tokens + ((now - b.at) / 1000) * rate);
    b.at = now;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      buckets.set(key, b);
      return;
    }
    buckets.set(key, b);
    await wait(Math.ceil(((1 - b.tokens) / rate) * 1000));
  }
}

const sleep = (ms: number): Promise<void> => wait(ms).then(() => undefined);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : typeof v === 'string' && /^-?[0-9]+$/.test(v) ? Number(v) : null);
const str = (v: unknown, max = 200): string | null => (typeof v === 'string' && v !== '' ? v.slice(0, max) : typeof v === 'number' ? String(v) : null);
const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null);

function retryAfterOf(h: string | null): number | null {
  if (!h) return null;
  const s = Number(h);
  if (Number.isFinite(s) && s >= 0) return Math.min(s * 1000, vppTiming.maxWaitMs);
  const d = Date.parse(h);
  return Number.isFinite(d) ? Math.min(Math.max(0, d - Date.now()), vppTiming.maxWaitMs) : null;
}

interface CallOptions {
  /** The content token (bearer); absent for service/config. */
  sToken?: string;
  /** The bucket of the call (the token's id). */
  bucket?: string;
  query?: Record<string, string | number | undefined>;
  body?: unknown;
}

async function call(method: 'GET' | 'POST', path: string, o: CallOptions = {}): Promise<Record<string, unknown>> {
  const url = new URL(path, config.apple.vppBaseUrl);
  for (const [k, v] of Object.entries(o.query ?? {})) if (v !== undefined) url.searchParams.set(k, String(v));
  let wait = vppTiming.baseWaitMs;
  for (let attempt = 1; ; attempt++) {
    if (o.bucket) await takeToken(o.bucket, cachedLimits().maxRequestPerSecond);
    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers: {
          accept: 'application/json',
          ...(o.body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...(o.sToken ? { authorization: `Bearer ${o.sToken}` } : {}),
        },
        body: o.body !== undefined ? JSON.stringify(o.body) : undefined,
        signal: AbortSignal.timeout(TIMEOUT_MS),
        redirect: 'error',
      });
    } catch (err) {
      if (attempt < ATTEMPTS) { await sleep(wait); wait *= 2; continue; }
      throw new VppApiError('network', 0, null, `Apps and Books unreachable (${(err as { name?: string })?.name ?? 'error'})`);
    }
    const text = await res.text();
    let body: Record<string, unknown> = {};
    if (text.trim()) {
      try { body = obj(JSON.parse(text)) ?? {}; } catch { body = {}; }
    }
    const errorNumber = num(body.errorNumber);
    if (res.ok && errorNumber === null) return body;
    const retryAfter = retryAfterOf(res.headers.get('retry-after'));
    if (res.status === 429 || errorNumber === RATE_LIMIT_ERROR) {
      if (attempt < ATTEMPTS) { await sleep(retryAfter ?? wait); wait = Math.min(wait * 2, vppTiming.maxWaitMs); continue; }
      throw new VppApiError('rate_limited', res.status, errorNumber, 'Apps and Books rate limit', retryAfter ?? wait);
    }
    if (res.status >= 500) {
      if (attempt < ATTEMPTS) { await sleep(retryAfter ?? wait); wait = Math.min(wait * 2, vppTiming.maxWaitMs); continue; }
      throw new VppApiError('unavailable', res.status, errorNumber, 'Apps and Books unavailable', retryAfter);
    }
    if (res.status === 401 || res.status === 403 || (errorNumber !== null && TOKEN_ERRORS.has(errorNumber))) {
      throw new VppApiError('token_rejected', res.status, errorNumber, 'Apple refused the content token');
    }
    throw new VppApiError('request', res.status, errorNumber, `Apps and Books refused the request (${res.status}${errorNumber !== null ? `, ${errorNumber}` : ''})`);
  }
}

/** The token expiry an answer carries (tokenExpirationDate), null when absent or unreadable. */
export function tokenExpiryOf(body: Record<string, unknown>): Date | null {
  const s = str(body.tokenExpirationDate, 64);
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

// ── service/config ─────────────────────────────────────────────────────────────

/** service/config, cached 5 minutes in memory. */
export async function serviceConfig(): Promise<VppLimits> {
  const base = config.apple.vppBaseUrl;
  if (serviceCache && serviceCache.base === base && Date.now() - serviceCache.at < SERVICE_CONFIG_TTL_MS) return serviceCache.limits;
  const body = await call('GET', 'service/config');
  const l = obj(body.limits) ?? {};
  const pick = (k: keyof VppLimits): number => {
    const n = num(l[k]);
    return n !== null && n > 0 ? Math.floor(n) : DEFAULT_VPP_LIMITS[k];
  };
  const limits: VppLimits = {
    maxAssets: pick('maxAssets'), maxSerialNumbers: pick('maxSerialNumbers'), maxClientUserIds: pick('maxClientUserIds'),
    maxUsers: pick('maxUsers'), maxRequestPerSecond: pick('maxRequestPerSecond'),
  };
  serviceCache = { base, at: Date.now(), limits };
  return limits;
}

// ── client/config ──────────────────────────────────────────────────────────────

export interface VppClientConfig {
  mdmInfo: { id: string | null; name: string | null; metadata: string | null } | null;
  locationName: string | null;
  uId: string | null;
  countryCode: string | null;
  notificationUrl: string | null;
  tokenExpiry: Date | null;
}

function clientConfigOf(body: Record<string, unknown>): VppClientConfig {
  const m = obj(body.mdmInfo);
  return {
    mdmInfo: m ? { id: str(m.id, 128), name: str(m.name, 200), metadata: str(m.metadata, 200) } : null,
    locationName: str(body.locationName, 200),
    uId: str(body.uId, 64),
    countryCode: str(body.countryISO2ACode, 8),
    notificationUrl: str(body.notificationUrl, 1000),
    tokenExpiry: tokenExpiryOf(body),
  };
}

export interface VppClientConfigUpdate {
  mdmInfo: { id: string; name: string; metadata: string };
  notificationTypes: string[];
  notificationUrl: string;
  notificationAuthToken: string;
}

// ── Assets and assignments ─────────────────────────────────────────────────────

export interface VppAssetRow {
  adamId: string;
  pricingParam: string;
  productType: string;
  deviceAssignable: boolean;
  revocable: boolean;
  supportedPlatforms: string[];
  totalCount: number;
  assignedCount: number;
  availableCount: number;
  retiredCount: number;
}

export interface VppAssignmentRow {
  adamId: string;
  pricingParam: string;
  serialNumber: string | null;
  clientUserId: string | null;
}

export interface VppPage<T> { items: T[]; nextPageIndex: number | null; versionId: string | null; tokenExpiry: Date | null }

const ADAM_RE = /^[0-9]{1,20}$/;
const PRICING_RE = /^[A-Z]{2,8}$/;

function assetOf(a: Record<string, unknown>): VppAssetRow | null {
  const adamId = str(a.adamId, 32);
  const pricingParam = str(a.pricingParam, 8) ?? 'STDQ';
  if (!adamId || !ADAM_RE.test(adamId) || !PRICING_RE.test(pricingParam)) return null;
  const n = (v: unknown): number => Math.max(0, Math.floor(num(v) ?? 0));
  return {
    adamId, pricingParam, productType: str(a.productType, 16) ?? 'App', deviceAssignable: a.deviceAssignable !== false,
    revocable: a.revocable !== false,
    supportedPlatforms: (Array.isArray(a.supportedPlatforms) ? a.supportedPlatforms : []).filter((x): x is string => typeof x === 'string').map((x) => x.slice(0, 32)).slice(0, 10),
    totalCount: n(a.totalCount), assignedCount: n(a.assignedCount), availableCount: n(a.availableCount), retiredCount: n(a.retiredCount),
  };
}

function assignmentOf(a: Record<string, unknown>): VppAssignmentRow | null {
  const adamId = str(a.adamId, 32);
  const pricingParam = str(a.pricingParam, 8) ?? 'STDQ';
  const serialNumber = str(a.serialNumber, 64);
  const clientUserId = str(a.clientUserId, 64);
  if (!adamId || !ADAM_RE.test(adamId) || !PRICING_RE.test(pricingParam) || (serialNumber === null) === (clientUserId === null)) return null;
  return { adamId, pricingParam, serialNumber, clientUserId };
}

function pageOf<T>(body: Record<string, unknown>, field: string, each: (x: Record<string, unknown>) => T | null): VppPage<T> {
  const items = (Array.isArray(body[field]) ? body[field] as unknown[] : []).map((x) => (obj(x) ? each(obj(x)!) : null)).filter((x): x is T => x !== null);
  const next = num(body.nextPageIndex);
  return { items, nextPageIndex: next !== null && next >= 0 ? next : null, versionId: str(body.versionId, 64), tokenExpiry: tokenExpiryOf(body) };
}

// ── Events ─────────────────────────────────────────────────────────────────────

export type VppEventStatus = 'PENDING' | 'COMPLETE' | 'FAILED';

export interface VppEvent {
  status: VppEventStatus;
  numCompleted: number | null;
  numRequested: number | null;
  /** The targets of a failure, as codes and counts (never a serial number nor a user in a summary). */
  failures: Array<{ adamId: string | null; serialNumber: string | null; clientUserId: string | null; errorNumber: number | null }>;
  tokenExpiry: Date | null;
}

function failuresOf(v: unknown): VppEvent['failures'] {
  return (Array.isArray(v) ? v : []).slice(0, 10_000).flatMap((f) => {
    const o = obj(f);
    if (!o) return [];
    return [{ adamId: str(o.adamId, 32), serialNumber: str(o.serialNumber, 64), clientUserId: str(o.clientUserId, 64), errorNumber: num(o.errorNumber) }];
  });
}

export function eventOf(body: Record<string, unknown>): VppEvent {
  const s = str(body.eventStatus, 16)?.toUpperCase();
  return {
    status: s === 'COMPLETE' || s === 'FAILED' ? s : 'PENDING',
    numCompleted: num(body.numCompleted), numRequested: num(body.numRequested), failures: failuresOf(body.failures),
    tokenExpiry: tokenExpiryOf(body),
  };
}

/** The calls of one content token. */
export interface VppTokenCalls {
  getClientConfig(): Promise<VppClientConfig>;
  setClientConfig(u: VppClientConfigUpdate): Promise<VppClientConfig>;
  assets(pageIndex: number): Promise<VppPage<VppAssetRow>>;
  assignments(pageIndex: number, sinceVersionId: string | null): Promise<VppPage<VppAssignmentRow>>;
  /** associate, disassociate, revoke: the eventId of the operation. */
  assetsOperation(kind: 'associate' | 'disassociate' | 'revoke', req: { assets: Array<{ adamId: string; pricingParam: string }>;
    serialNumbers?: string[]; clientUserIds?: string[] }): Promise<{ eventId: string; tokenExpiry: Date | null }>;
  usersOperation(kind: 'users_create' | 'users_update' | 'users_retire',
    users: Array<{ clientUserId: string; managedAppleId?: string }>): Promise<{ eventId: string; tokenExpiry: Date | null }>;
  status(eventId: string): Promise<VppEvent>;
}

function eventIdOf(body: Record<string, unknown>): string {
  const id = str(body.eventId, 64);
  if (!id || !/^[A-Za-z0-9_.:-]{1,64}$/.test(id)) throw new VppApiError('protocol', 200, null, 'Apps and Books gave no event id');
  return id;
}

/** The calls of the content token `sToken` (its bucket: `tokenId`). */
export function vppClient(tokenId: string, sToken: string): VppTokenCalls {
  const o = { sToken, bucket: tokenId };
  return {
    async getClientConfig() { return clientConfigOf(await call('GET', 'client/config', o)); },
    async setClientConfig(u) { return clientConfigOf(await call('POST', 'client/config', { ...o, body: u })); },
    async assets(pageIndex) { return pageOf(await call('GET', 'assets', { ...o, query: { pageIndex } }), 'assets', assetOf); },
    async assignments(pageIndex, sinceVersionId) {
      return pageOf(await call('GET', 'assignments', { ...o, query: { pageIndex, sinceVersionId: sinceVersionId ?? undefined } }), 'assignments', assignmentOf);
    },
    async assetsOperation(kind, req) {
      const path = kind === 'associate' ? 'assets/associate' : kind === 'disassociate' ? 'assets/disassociate' : 'assets/revoke';
      const body: Record<string, unknown> = kind === 'revoke' ? {} : { assets: req.assets };
      if (req.serialNumbers?.length) body.serialNumbers = req.serialNumbers;
      if (req.clientUserIds?.length) body.clientUserIds = req.clientUserIds;
      const r = await call('POST', path, { ...o, body });
      return { eventId: eventIdOf(r), tokenExpiry: tokenExpiryOf(r) };
    },
    async usersOperation(kind, users) {
      const path = kind === 'users_create' ? 'users/create' : kind === 'users_update' ? 'users/update' : 'users/retire';
      const r = await call('POST', path, { ...o, body: { users } });
      return { eventId: eventIdOf(r), tokenExpiry: tokenExpiryOf(r) };
    },
    async status(eventId) { return eventOf(await call('GET', 'status', { ...o, query: { eventId } })); },
  };
}

/** A log line of a failed call: the code only. */
export function logVppFailure(what: string, tokenId: string, err: unknown): void {
  logger.warn({ vppToken: tokenId, code: isVppApiError(err) ? err.code : (err as { code?: unknown })?.code ?? null }, `apps and books: ${what} failed`);
}

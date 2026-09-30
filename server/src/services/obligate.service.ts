import crypto from 'crypto';
import { appConfigService } from './appConfig.service';
import { logger } from '../utils/logger';
import { config } from '../config';
import { safeEqualSecret } from '../utils/safeCompare';
import { db } from '../db';
import { MASTER_TENANT_ID } from '@obliance/shared';

/**
 * Public OAuth client id of this app for Obligate: lowercase hex SHA-256 of
 * the API key. Cross-repo contract with Obligate (publicClientId() in its
 * app.service.ts) — change it on both sides or not at all.
 */
export function obligatePublicClientId(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey, 'utf8').digest('hex');
}

/** One user of Obligate's roster for this app (GET /api/apps/users). */
export interface ObligateRosterEntry {
  /** The role Obligate gives this user on this app ('admin' = platform admin). */
  role: string;
  tenants: Array<{ slug: string; role: string }>;
  teams: string[];
}
/** Obligate user id → roster entry. */
export type ObligateRoster = Map<number, ObligateRosterEntry>;

/** Normalised `scheme://host[:port]` of an http(s) URL (lower-case host, no default port), or null. */
function toHttpOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.origin : null;
  } catch {
    return null;
  }
}

/** localhost / loopback origin: for another machine's browser, that is itself. */
function isLoopbackOrigin(origin: string): boolean {
  const { hostname } = new URL(origin);
  return hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '[::1]' || /^127\./.test(hostname);
}

/** Public origin set by the operator (APP_URL / CLIENT_ORIGIN, read at call time), or null when unset. */
function envOrigin(name: 'APP_URL' | 'CLIENT_ORIGIN'): string | null {
  const value = process.env[name]?.trim();
  return value ? toHttpOrigin(value) : null;
}

const ORIGIN_CACHE_TTL_MS = 5 * 60 * 1000;
const ORIGIN_CACHE_MIN_REFRESH_MS = 30 * 1000;
const APP_ORIGINS_TTL_MS = 60 * 1000;
/** Obligate allows its sso-user-sync pushes 5 s: the roster read stays under it. */
const ROSTER_TIMEOUT_MS = 4_000;

// ── Lot O: device-bound 2FA for SSO accounts ─────────────────────────────────
// docs/mobile/device-bound-2fa.md §4.10, §6.10, annex C. Every value below
// comes from a call WE make to the configured Obligate (never from an inbound
// push, whose Bearer secret may be public), and every failure closes: no
// capability, no epoch → SSO accounts cannot use a phone key.

/** Flags GET /api/oauth/capabilities must announce, each with the value 1 (O5). */
export const LOT_O_CAPABILITY_FLAGS = ['stepUpEpoch', 'reauth', 'totpReplayGuard'] as const;
/**
 * Lot O availability, three ways (§4.10, §6.10):
 *  - 'on'      the Obliance switch is on AND Obligate announces the three flags;
 *  - 'off'     EXPLICITLY off: the Obliance switch (DEVICE_KEYS_SSO_ENABLED),
 *              Obligate SSO disabled / not configured, or Obligate answered 2xx
 *              without the three flags == 1 (OAUTH_LOT_O_CAPABILITIES=false, a
 *              flag missing or with another value);
 *  - 'unknown' Obligate could not say: network error, timeout, non-2xx,
 *              unreadable answer. Never treated as 'off' (a network glitch must
 *              not relax anything): every lot-O path stays closed.
 */
export type LotOState = 'on' | 'off' | 'unknown';
/** Why lot O is in its state (Settings status for platform admins). */
export type LotOReason = 'switch_off' | 'sso_off' | 'announced' | 'withdrawn' | 'unreachable';
/** §9: capabilities cached 10 min (announced or withdrawn); an unreadable
 *  answer / Obligate down is re-tried after 1 min. */
const CAPABILITIES_TTL_MS = 10 * 60 * 1000;
const CAPABILITIES_RETRY_MS = 60 * 1000;
/** §9: MFA epoch cached 5 min (errors are never cached). */
const MFA_EPOCH_TTL_MS = 5 * 60 * 1000;
/** Outbound lot-O calls (also run inside an sso-user-sync push: under 5 s). */
const LOT_O_TIMEOUT_MS = 4_000;

/** GET /api/oauth/users/:id/mfa-epoch (O2), as read by us. */
export interface ObligateMfaEpoch {
  mfaEpoch: number;
  /** false when Obligate says the user is disabled (optional field, default true). */
  active: boolean;
}

/** POST /api/oauth/verify-totp (O1) with the lot-O fields. */
export interface ObligateTotpCheck {
  /** 'replayed': right code whose step was already used (consume:true). */
  result: 'valid' | 'invalid' | 'replayed' | 'unavailable';
  step: number | null;
  mfaEpoch: number | null;
}

/** Obligate's answer to GET /api/oauth/capabilities: 'on' / 'off' (2xx, flags
 *  missing) / 'unknown' (no usable answer). The Obliance switch is not in it. */
type CapabilitiesAnswer = LotOState;
let capabilitiesCache: { key: string; state: CapabilitiesAnswer; at: number; ttl: number } | null = null;
let capabilitiesInflight: { key: string; promise: Promise<CapabilitiesAnswer> } | null = null;
const mfaEpochCache = new Map<string, { at: number; value: ObligateMfaEpoch }>();
// Per Obligate user, bumped by forgetMfaEpoch(): a read that started before
// the bump never writes its (possibly pre-change) value into the cache.
const mfaEpochGen = new Map<number, number>();
const epochGenOf = (obligateUserId: number): number => mfaEpochGen.get(obligateUserId) ?? 0;

/**
 * GET /api/oauth/users/:id/mfa-epoch, three ways:
 *  - 'ok'         the epoch and whether Obligate lets the user use this app;
 *  - 'not_found'  Obligate's own JSON 404 {success:false}: no such user, or no
 *                 SSO sign-in of the user to this app (no user_app_links row,
 *                 or one created by report-provision only) — for an og_
 *                 account, which exists here only after such a sign-in: the
 *                 identity is gone at Obligate;
 *  - 'unavailable' anything else (not configured, network, timeout, 5xx,
 *                 another 4xx, a 404 that is not Obligate's JSON — an older
 *                 Obligate without the route —, unreadable 2xx).
 */
export type ObligateEpochRead =
  | { kind: 'ok'; value: ObligateMfaEpoch }
  | { kind: 'not_found' }
  | { kind: 'unavailable' };

/** A read started by an inbound sso-user-sync push: 'throttled' = not started (budget, see PUSH_READ_BUDGET). */
export type PushEpochRead = ObligateEpochRead | { kind: 'throttled' };
export type PushRosterRead = { kind: 'ok'; roster: ObligateRoster } | { kind: 'unavailable' } | { kind: 'throttled' };

/**
 * Outbound reads started by inbound sso-user-sync pushes — whose Bearer
 * secret may be public — share this budget: a token bucket over time (not
 * only a concurrency cap), so that no stream of pushes, however paced, can
 * spend Obliance's request budget at Obligate (its apiLimiter: 500 requests
 * per 5 min per client IP, shared with the sign-in code exchange, verify-totp,
 * the capabilities, the use-time epoch reads). A read joined to one already
 * in flight or queued costs nothing. Beyond the budget the read is not made
 * ('throttled'): credentials-changed answers 503 (Obligate's queue retries),
 * the roster actions are re-checked later.
 * Per Obligate user, a push-triggered epoch read is not repeated within
 * `userGapMs` of the previous one (the concurrent pushes of a burst share one
 * read in flight + one queued).
 * Mutable for the verification harnesses only.
 */
export const PUSH_READ_BUDGET = { capacity: 20, refillPerMinute: 12, userGapMs: 10_000 };
let pushReadTokens = PUSH_READ_BUDGET.capacity;
let pushReadRefilledAt = 0;
function takePushReadToken(): boolean {
  const now = Date.now();
  const elapsed = pushReadRefilledAt === 0 ? 0 : Math.max(0, now - pushReadRefilledAt);
  pushReadRefilledAt = now;
  pushReadTokens = Math.min(PUSH_READ_BUDGET.capacity, pushReadTokens + (elapsed * PUSH_READ_BUDGET.refillPerMinute) / 60_000);
  if (pushReadTokens < 1) return false;
  pushReadTokens -= 1;
  return true;
}
// Epoch reads triggered by pushes (see mfaEpochForPush): per Obligate user,
// one in flight plus one queued, and when the last one ended.
const pushEpochReads = new Map<number, { inflight: Promise<ObligateEpochRead>; queued: Promise<PushEpochRead> | null }>();
const pushEpochDoneAt = new Map<number, number>();
const THROTTLED = { kind: 'throttled' } as const;

/** Obligate's usual envelope {success, data}; a bare object is read as is. */
function lotOData(body: unknown): Record<string, unknown> | null {
  if (!body || typeof body !== 'object') return null;
  const b = body as { success?: unknown; data?: unknown };
  if (b.success === false) return null;
  if (b.data && typeof b.data === 'object' && !Array.isArray(b.data)) return b.data as Record<string, unknown>;
  return b as Record<string, unknown>;
}

function nonNegativeInt(v: unknown): number | null {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : null;
}

/** Cache key of an Obligate installation (a URL / key change drops the cached values). */
function lotOKey(raw: { url: string | null; apiKey: string | null }): string {
  return `${raw.url ?? ''}|${crypto.createHash('sha256').update(raw.apiKey ?? '').digest('hex').slice(0, 16)}`;
}

async function fetchCapabilities(raw: { url: string; apiKey: string }): Promise<CapabilitiesAnswer> {
  try {
    const res = await fetch(`${raw.url}/api/oauth/capabilities`, {
      headers: { 'Authorization': `Bearer ${raw.apiKey}` },
      signal: AbortSignal.timeout(LOT_O_TIMEOUT_MS),
    });
    if (!res.ok) return 'unknown';
    // A 2xx that is not a JSON object (an HTML page, say) or says
    // success:false is no statement at all: 'unknown', not 'off'.
    const data = lotOData(await res.json().catch(() => null));
    if (!data || Array.isArray(data)) return 'unknown';
    return LOT_O_CAPABILITY_FLAGS.every((f) => data[f] === 1) ? 'on' : 'off';
  } catch {
    return 'unknown';
  }
}

/**
 * Obligate's capabilities answer for this installation, cached 10 min when
 * it said something ('on' / 'off'), 1 min when it could not ('unknown'); one
 * read in flight at a time. The Obliance switch is checked by the caller.
 */
function readCapabilities(raw: { url: string; apiKey: string }): Promise<CapabilitiesAnswer> {
  const key = lotOKey(raw);
  const now = Date.now();
  const c = capabilitiesCache;
  if (c && c.key === key && now - c.at < c.ttl) return Promise.resolve(c.state);
  if (capabilitiesInflight?.key === key) return capabilitiesInflight.promise;
  const was = c && c.key === key ? c.state : null;
  const promise = fetchCapabilities(raw).then((state) => {
    capabilitiesCache = { key, state, at: Date.now(), ttl: state === 'unknown' ? CAPABILITIES_RETRY_MS : CAPABILITIES_TTL_MS };
    if (state === 'on' && was !== 'on') logger.info('Obligate lot O capabilities announced: device keys open to SSO accounts');
    if (state === 'off' && was !== 'off') logger.warn('Obligate does not announce the lot O capabilities: SSO device keys closed, bound SSO sessions accept the code alone');
    if (state === 'unknown' && was === 'on') logger.warn('Obligate lot O capabilities unreadable: SSO device keys closed until Obligate answers');
    return state;
  }).finally(() => {
    if (capabilitiesInflight?.promise === promise) capabilitiesInflight = null;
  });
  capabilitiesInflight = { key, promise };
  return promise;
}

// Roster reads (see getAppRoster): at most one in flight, plus one queued
// behind it that every caller arriving meanwhile shares.
let rosterInflight: { promise: Promise<ObligateRoster | null> } | null = null;
let rosterQueued: Promise<ObligateRoster | null> | null = null;

async function fetchRoster(): Promise<ObligateRoster | null> {
  const raw = await appConfigService.getObligateRaw();
  if (!raw.url || !raw.apiKey) return null;
  try {
    const res = await fetch(`${raw.url}/api/apps/users`, {
      headers: { 'Authorization': `Bearer ${raw.apiKey}` },
      signal: AbortSignal.timeout(ROSTER_TIMEOUT_MS),
    });
    if (!res.ok) {
      logger.warn(`Obligate roster fetch failed: HTTP ${res.status}`);
      return null;
    }
    const data = await res.json() as { success?: boolean; data?: unknown };
    if (!data?.success || !Array.isArray(data.data)) return null;
    const roster: ObligateRoster = new Map();
    for (const item of data.data) {
      const u = item as { obligateUserId?: unknown; role?: unknown; tenants?: unknown; teams?: unknown } | null;
      const id = u?.obligateUserId;
      if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) continue;
      if (typeof u!.role !== 'string' || !u!.role) continue; // no role = no access here
      const tenants = Array.isArray(u!.tenants)
        ? (u!.tenants as unknown[])
          .filter((t): t is { slug: string; role: string } => !!t && typeof (t as any).slug === 'string' && typeof (t as any).role === 'string')
          .map((t) => ({ slug: t.slug, role: t.role }))
        : [];
      const teams = Array.isArray(u!.teams) ? (u!.teams as unknown[]).filter((s): s is string => typeof s === 'string') : [];
      roster.set(id, { role: u!.role, tenants, teams });
    }
    return roster;
  } catch (err) {
    logger.warn(err, 'Obligate roster fetch error');
    return null;
  }
}

function startRosterFetch(): Promise<ObligateRoster | null> {
  const entry = { promise: fetchRoster() };
  rosterInflight = entry;
  const clear = () => { if (rosterInflight === entry) rosterInflight = null; };
  entry.promise.then(clear, clear);
  return entry.promise;
}

/** The read queued behind the one in flight (created once, shared). */
function queueRosterFetch(inflight: { promise: Promise<ObligateRoster | null> }): Promise<ObligateRoster | null> {
  if (!rosterQueued) {
    rosterQueued = inflight.promise.then(() => {
      rosterQueued = null;
      return startRosterFetch();
    });
  }
  return rosterQueued;
}

/**
 * One mfa-epoch read (see ObligateEpochRead). `fresh` bypasses the 5-min
 * cache; a successful read refreshes it, unless forgetMfaEpoch() ran for the
 * user since the read started (its value may predate the change that made
 * someone forget it).
 */
async function readMfaEpoch(obligateUserId: number, opts: { fresh?: boolean } = {}): Promise<ObligateEpochRead> {
  const unavailable = { kind: 'unavailable' } as const;
  if (!Number.isSafeInteger(obligateUserId) || obligateUserId <= 0) return unavailable;
  const raw = await appConfigService.getObligateRaw();
  if (!raw.url || !raw.apiKey) return unavailable;
  const cacheKey = `${lotOKey(raw)}#${obligateUserId}`;
  const hit = mfaEpochCache.get(cacheKey);
  if (!opts.fresh && hit && Date.now() - hit.at < MFA_EPOCH_TTL_MS) return { kind: 'ok', value: hit.value };
  const gen = epochGenOf(obligateUserId);
  try {
    const res = await fetch(`${raw.url}/api/oauth/users/${encodeURIComponent(String(obligateUserId))}/mfa-epoch`, {
      headers: { 'Authorization': `Bearer ${raw.apiKey}` },
      signal: AbortSignal.timeout(LOT_O_TIMEOUT_MS),
    });
    const body = await res.json().catch(() => null) as { success?: unknown } | null;
    if (res.status === 404 && body && typeof body === 'object' && body.success === false) {
      logger.warn({ obligateUserId }, 'Obligate mfa-epoch: 404 — no such user, or no SSO sign-in of the user to this app');
      return { kind: 'not_found' };
    }
    if (!res.ok) {
      logger.warn({ obligateUserId, status: res.status }, 'Obligate mfa-epoch: non-2xx (SSO device keys refused meanwhile)');
      return unavailable;
    }
    const data = lotOData(body);
    const mfaEpoch = nonNegativeInt(data?.mfaEpoch);
    if (!data || mfaEpoch === null) return unavailable;
    const value: ObligateMfaEpoch = { mfaEpoch, active: data.active !== false };
    if (epochGenOf(obligateUserId) === gen) {
      if (mfaEpochCache.size >= 10_000) mfaEpochCache.clear();
      mfaEpochCache.set(cacheKey, { at: Date.now(), value });
    }
    return { kind: 'ok', value };
  } catch (err) {
    logger.warn({ err, obligateUserId }, 'Obligate mfa-epoch: unreachable (SSO device keys refused meanwhile)');
    return unavailable;
  }
}

export interface ObligateUserAssertion {
  obligateUserId: number;
  username: string;
  email: string | null;
  displayName: string | null;
  role: string;
  tenants: Array<{ slug: string; role: string; capabilities?: string[] }>;
  teams: string[];
  capabilities?: string[];
  authSource: 'local' | 'ldap';
  linkedLocalUserId: number | null;
  /** Lot O (O4): when the Obligate session that issued the code authenticated (unix s). */
  authTime?: number | null;
  /** Lot O (O4): how (RFC 8176): ['pwd'] or ['pwd', 'otp']. */
  amr?: string[];
  preferences?: {
    preferredTheme?: string;
    toastEnabled?: boolean;
    toastPosition?: string;
    profilePhotoUrl?: string | null;
    preferredLanguage?: string;
    anonymousMode?: boolean;
    appSpecific?: Record<string, string>;
  };
}

// ── Counters of the Obligate dashboard card (GET /api/auth/dashboard-stats) ─
// The core counts the devices; a module adds its own counters after them
// (registerDashboardStat). A fleet-wide count only: the route answers a
// Bearer secret that may be public.

export interface ObligateDashboardStat {
  label: string;
  color: string;
  count: () => Promise<number>;
}

const dashboardStats: ObligateDashboardStat[] = [];

export function registerDashboardStat(stat: ObligateDashboardStat): void {
  if (dashboardStats.some((s) => s.label === stat.label)) throw new Error(`Dashboard stat '${stat.label}' registered twice`);
  dashboardStats.push(stat);
}

/** The modules' counters, in registration order. */
export function moduleDashboardStats(): readonly ObligateDashboardStat[] {
  return dashboardStats;
}

export const obligateService = {
  /**
   * Check if Obligate is configured and reachable.
   */
  async getSsoConfig(): Promise<{ obligateUrl: string | null; obligateReachable: boolean; obligateEnabled: boolean }> {
    const cfg = await appConfigService.getObligateConfig();
    if (!cfg.url || !cfg.enabled) {
      return { obligateUrl: cfg.url, obligateReachable: false, obligateEnabled: cfg.enabled };
    }

    // Quick reachability check (2s timeout)
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(`${cfg.url}/health`, { signal: controller.signal });
      clearTimeout(timeout);
      return { obligateUrl: cfg.url, obligateReachable: res.ok, obligateEnabled: true };
    } catch {
      return { obligateUrl: cfg.url, obligateReachable: false, obligateEnabled: true };
    }
  },

  /**
   * client_id for the browser-facing /authorize URL (it goes through the
   * browser: Location header, history, Referer, access logs — it is PUBLIC):
   * always obligatePublicClientId(apiKey), the key never leaves the server.
   * Obligate refuses the raw key as client_id (OAUTH_ACCEPT_RAW_CLIENT_ID).
   */
  authorizeClientId(raw: { apiKey: string | null }): string | null {
    if (!raw.apiKey) return null;
    return obligatePublicClientId(raw.apiKey);
  },

  /**
   * Authenticate a server-to-server call made by Obligate to this server
   * (`Authorization: Bearer <secret>`): sso-user-sync, app-info,
   * dashboard-stats.
   *
   * The expected secret is the distinct inbound secret when one is set
   * (setting or OBLIGATE_INBOUND_SECRET), else the API key (today's wire
   * behaviour). Constant-time, and fails closed when nothing is configured.
   *
   * While the client_id is the raw API key, that key is PUBLIC (it is in the
   * /auth/sso-redirect Location header): these routes must never grant more
   * than a key holder may do — see /sso-user-sync.
   */
  async verifyInboundBearer(authHeader: string | string[] | undefined): Promise<boolean> {
    if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) return false;
    const raw = await appConfigService.getObligateRaw();
    const expected = raw.inboundSecret ?? raw.apiKey;
    return safeEqualSecret(authHeader.slice(7), expected);
  },

  /**
   * The local account linked to an Obligate identity, from OUR records only:
   *   1. the sso_foreign_users row of that identity — written by this server
   *      alone (SSO provisioning), never from anything Obligate says;
   *   2. else the og_ account provisioned for it (users.foreign_source =
   *      'obligate' AND foreign_id), e.g. when the link row went missing.
   *
   * Obligate's `linkedLocalUserId` / `remoteUserId` are only its copy of the
   * id we reported through report-provision, and anyone holding the API key
   * can rewrite them (report-provision): they are never trusted on their own.
   * Returns null when no existing local account is linked.
   */
  async getLinkedLocalUserId(obligateUserId: number): Promise<number | null> {
    if (!Number.isSafeInteger(obligateUserId) || obligateUserId <= 0) return null;

    const link = await db('sso_foreign_users as l')
      .join('users as u', 'u.id', 'l.local_user_id')
      .where({ 'l.foreign_source': 'obligate', 'l.foreign_user_id': obligateUserId })
      .first('u.id') as { id: number } | undefined;
    if (link) return link.id;

    const provisioned = await db('users')
      .where({ foreign_source: 'obligate', foreign_id: obligateUserId })
      .orderBy('id', 'desc')
      .first('id') as { id: number } | undefined;
    return provisioned?.id ?? null;
  },

  /**
   * Obligate's CURRENT roster for this app (GET /api/apps/users, read with our
   * key from the configured Obligate URL): every Obligate user who may sign in
   * here right now (active, not disabled on this app, with a role), with the
   * role / tenants / teams Obligate gives them. Whoever calls our inbound
   * routes cannot forge it — the read goes out from here.
   *
   * Used to confirm what an inbound sso-user-sync push asks for: the push
   * proves nothing, since its secret may be public (the key may have leaked)
   * and anyone holding the key can enumerate Obligate user ids.
   *
   * At most one read in flight. A caller arriving while one runs waits for the
   * NEXT read (shared by every caller arriving meanwhile): the running one may
   * have started before the change being confirmed was made in Obligate. So a
   * burst of pushes costs Obligate at most one read at a time; the pushes go
   * through rosterForPush(), which also bounds the reads over time.
   * Returns null when Obligate is not configured or does not answer.
   */
  getAppRoster(): Promise<ObligateRoster | null> {
    if (!rosterInflight) return startRosterFetch();
    return queueRosterFetch(rosterInflight);
  },

  /**
   * getAppRoster() for an inbound sso-user-sync push or its re-check: same
   * coalescing, and starting a NEW read (none in flight, or no read queued
   * yet) takes a token of PUSH_READ_BUDGET — 'throttled' when none is left
   * (nothing is sent to Obligate). Joining a queued read is free.
   */
  async rosterForPush(): Promise<PushRosterRead> {
    let p: Promise<ObligateRoster | null>;
    if (!rosterInflight) {
      if (!takePushReadToken()) return THROTTLED;
      p = startRosterFetch();
    } else if (rosterQueued) {
      p = rosterQueued;
    } else {
      if (!takePushReadToken()) return THROTTLED;
      p = queueRosterFetch(rosterInflight);
    }
    const roster = await p.catch(() => null);
    return roster ? { kind: 'ok', roster } : { kind: 'unavailable' };
  },

  /**
   * Public origin this app is registered under in Obligate: the base URL of
   * the active connected app of type 'obliance' (the URL Obligate and the
   * other Obli* apps send browsers to).
   * Obligate does not tell an app which registration is its own, so this is
   * only usable when there is exactly ONE such app. With several (e.g. prod +
   * staging on one Obligate) none is trusted and APP_URL must name this
   * instance.
   * Cached 5 min; `refresh` bypasses the cache unless it is under 30 s old.
   */
  _originCache: null as { origin: string | null; at: number } | null,
  async getRegisteredAppOrigin(refresh = false): Promise<string | null> {
    const now = Date.now();
    const cached = this._originCache;
    if (cached && now - cached.at < (refresh ? ORIGIN_CACHE_MIN_REFRESH_MS : ORIGIN_CACHE_TTL_MS)) {
      return cached.origin;
    }
    const apps = await this.getConnectedApps();
    // No app at all is a failed fetch (we are registered ourselves): not cached
    if (apps.length === 0) return null;
    const own = apps.filter((a) => a.appType === 'obliance');
    if (own.length > 1) {
      logger.error({ baseUrls: own.map((a) => a.baseUrl) },
        'Obligate SSO: several Obliance apps are registered in Obligate, so their base URLs are not trusted — set APP_URL to this instance\'s public URL');
    }
    const origin = own.length === 1 ? toHttpOrigin(own[0].baseUrl) : null;
    this._originCache = { origin, at: now };
    return origin;
  },

  /**
   * Check the public origin a browser reached us through — derived from the
   * Host / X-Forwarded-* request headers, which any client can forge (nginx
   * relays X-Forwarded-Proto as received) — against the origins this app is
   * really published under: APP_URL / CLIENT_ORIGIN when set, and its base URL
   * in Obligate (getRegisteredAppOrigin). Matching is on host[:port], or on the
   * hostname alone when the candidate has no port (nginx's `$host`, forwarded
   * by client/nginx.conf, drops it). Only a trusted origin is ever returned —
   * its scheme and port win over the headers — so a forged Host can at most
   * pick another of our own origins. Null when the host is none of them.
   *
   * Why it matters: the OAuth redirect_uri is built from this origin, and
   * Obligate issues a code for any redirect_uri. Taken from the headers, a
   * forged Host made us exchange (with our key) a code Obligate had delivered
   * to an attacker's URL — and sign the attacker in as the victim.
   */
  async verifyPublicOrigin(candidate: string): Promise<string | null> {
    const origin = toHttpOrigin(candidate);
    if (!origin) return null;
    const { host, hostname, port } = new URL(origin);
    const match = (trusted: Array<string | null>): string | null => {
      const list = trusted.filter((o): o is string => o !== null);
      if (list.includes(origin)) return origin;
      return list.find((o) => new URL(o).host === host)
        ?? (port === '' ? list.find((o) => new URL(o).hostname === hostname) : undefined)
        ?? null;
    };
    return match([envOrigin('APP_URL'), envOrigin('CLIENT_ORIGIN')])
      ?? match([await this.getRegisteredAppOrigin()])
      // The base URL may just have been changed in Obligate — retry uncached
      ?? match([await this.getRegisteredAppOrigin(true)]);
  },

  /**
   * Where to restart the SSO flow when the browser reached us through a host
   * this app is not published under (LAN IP, second DNS name…): APP_URL, else
   * its base URL in Obligate, else CLIENT_ORIGIN. Loopback origins are skipped
   * (they would point the browser at its own machine — e.g. the docker-compose
   * default CLIENT_ORIGIN=http://localhost). Null when none is known.
   */
  async getCanonicalOrigin(): Promise<string | null> {
    const usable = (o: string | null): o is string => o !== null && !isLoopbackOrigin(o);
    const appUrl = envOrigin('APP_URL');
    if (usable(appUrl)) return appUrl;
    const registered = await this.getRegisteredAppOrigin();
    if (usable(registered)) return registered;
    const clientOrigin = envOrigin('CLIENT_ORIGIN');
    return usable(clientOrigin) ? clientOrigin : null;
  },

  /**
   * Origins of the active connected apps, by app type (cached 1 min): what a
   * cross-app device link may point to (see getDeviceLinks).
   */
  _appOriginsCache: null as { at: number; map: Map<string, Set<string>> } | null,
  async getConnectedAppOrigins(): Promise<Map<string, Set<string>>> {
    const now = Date.now();
    if (this._appOriginsCache && now - this._appOriginsCache.at < APP_ORIGINS_TTL_MS) return this._appOriginsCache.map;
    const map = new Map<string, Set<string>>();
    for (const a of await this.getConnectedApps()) {
      const o = typeof a.baseUrl === 'string' ? toHttpOrigin(a.baseUrl) : null;
      if (!o || typeof a.appType !== 'string') continue;
      if (!map.has(a.appType)) map.set(a.appType, new Set());
      map.get(a.appType)!.add(o);
    }
    if (map.size > 0) this._appOriginsCache = { at: now, map };
    return map;
  },

  /**
   * Step-up authentication: verify a fresh TOTP code against an SSO user's
   * Obligate account. Used by the restriction service when a user flagged
   * as `foreign_source='obligate'` (no local TOTP secret) tries to invoke
   * a sensitive action.
   *
   * Returns true if the code is accepted, false if rejected / Obligate
   * unreachable / SSO user without TOTP configured. Failing closed is
   * deliberate — a sensitive action must never go through on a silent
   * verification failure.
   */
  async verifyTotp(obligateUserId: number, code: string): Promise<boolean> {
    return (await this.verifyTotpDetailed(obligateUserId, code)) === 'valid';
  },

  /**
   * Same check, telling a rejected code ('invalid') apart from a failed
   * verification ('unavailable': Obligate not configured, unreachable,
   * non-2xx, unreadable answer). Only 'valid' ever passes. The step-up caps
   * count 'invalid' only, so an Obligate outage never locks SSO users' code
   * entry (an unavailable check cannot succeed either, so nothing is gained
   * by an attacker).
   */
  async verifyTotpDetailed(obligateUserId: number, code: string): Promise<'valid' | 'invalid' | 'unavailable'> {
    const r = await this.checkTotp(obligateUserId, code, { consume: false });
    return r.result === 'replayed' ? 'invalid' : r.result;
  },

  /**
   * POST /api/oauth/verify-totp with the lot-O fields (O1). `consume:true`
   * (only once lotOSupported()): Obligate accepts the code only if its step
   * is newer than every step already used for this user (sign-in included),
   * then records it — a code seen at an Obligate sign-in can no longer serve
   * here (R3). Without `consume` the body is exactly the historical one.
   * A 'valid' answer to a consuming call without a step is a protocol
   * violation: 'unavailable' (fail closed). The mfaEpoch Obligate returns
   * refreshes the epoch cache (our own outbound call).
   */
  async checkTotp(obligateUserId: number, code: string, opts: { consume: boolean }): Promise<ObligateTotpCheck> {
    const unavailable: ObligateTotpCheck = { result: 'unavailable', step: null, mfaEpoch: null };
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) {
      logger.warn('[Obligate verifyTotp] not configured — returning false');
      return unavailable;
    }

    const url = `${raw.url}/api/oauth/verify-totp`;
    const epochGen = epochGenOf(obligateUserId);
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify(opts.consume
          ? { userId: obligateUserId, code, consume: true }
          : { userId: obligateUserId, code }),
        // A hung Obligate must not hold the caller (and its reserved
        // step-up attempt): 5 s, then 'unavailable'.
        signal: AbortSignal.timeout(5_000),
      });
      if (res.status === 429) {
        // Obligate locked this user's code checks (too many failures). That
        // lock can be triggered on purpose by whoever holds the API key (it
        // authenticates verify-totp alone): make it visible, it blocks the
        // user's step-up here (answered as 'unavailable').
        logger.warn({ obligateUserId }, '[Obligate verifyTotp] 429 — Obligate locked this user\'s code checks');
        const { auditService } = await import('./audit.service');
        const linked = await this.getLinkedLocalUserId(obligateUserId).catch(() => null);
        void auditService.log({
          tenantId: MASTER_TENANT_ID, userId: linked ?? undefined, action: 'sso.totp_verifier_locked',
          resourceType: 'user', resourcePath: linked ? String(linked) : undefined,
          details: { obligateUserId },
        });
        return unavailable;
      }
      if (!res.ok) {
        // Dump the response body for diagnosis — the #1 cause of silent
        // failures here is an outdated Obligate deployment that doesn't
        // know the /verify-totp route yet (returns 404 HTML).
        const text = await res.text().catch(() => '');
        logger.warn(
          { url, status: res.status, body: text.slice(0, 200) },
          '[Obligate verifyTotp] non-2xx — is Obligate rebuilt with the /verify-totp route?',
        );
        return unavailable;
      }
      const data = await res.json() as {
        success?: boolean; data?: { valid?: boolean; step?: unknown; mfaEpoch?: unknown; reason?: unknown };
      };
      if (!data?.success) {
        logger.warn({ data }, '[Obligate verifyTotp] response success=false');
        return unavailable;
      }
      const step = nonNegativeInt(data.data?.step);
      const mfaEpoch = nonNegativeInt(data.data?.mfaEpoch);
      if (opts.consume && mfaEpoch !== null) this.noteMfaEpoch(obligateUserId, mfaEpoch, raw, epochGen);
      if (data.data?.valid === true) {
        if (opts.consume && step === null) {
          logger.warn({ obligateUserId }, '[Obligate verifyTotp] consume:true accepted without a step — refused (fail closed)');
          return unavailable;
        }
        return { result: 'valid', step, mfaEpoch };
      }
      if (opts.consume && data.data?.reason === 'replayed') return { result: 'replayed', step, mfaEpoch };
      return { result: 'invalid', step: null, mfaEpoch };
    } catch (err) {
      logger.error({ err, url }, '[Obligate verifyTotp] exception');
      return unavailable;
    }
  },

  /**
   * Lot O (§4.10, O5): does the configured Obligate announce the three
   * capabilities {stepUpEpoch:1, reauth:1, totpReplayGuard:1}? SSO accounts
   * may use a phone key only then. False when SSO is off or not configured,
   * Obligate unreachable, a flag missing or not exactly 1 (fail closed).
   * Cached 10 min per Obligate installation (1 min after a failure); one
   * read in flight at a time.
   *
   * Obliance-side opt-in FIRST (DEVICE_KEYS_SSO_ENABLED, off by default):
   * Obligate announcing the flags is not enough — the owner turns lot O on
   * only after checking the Obligate build. While off: false, no I/O, so
   * every lot-O path (SSO enrolment, SSO key use, sso-redirect?reauth=1,
   * the consuming verify-totp) keeps the pre-lot-O behaviour.
   */
  async lotOSupported(): Promise<boolean> {
    return (await this.lotOState()) === 'on';
  },

  /**
   * Lot O availability with its three outcomes (see LotOState). Only an
   * EXPLICIT 'off' (the Obliance switch, Obligate SSO off / not configured, or
   * Obligate answering 2xx without the three flags) may relax anything — the
   * bound SSO session then accepts the code alone again (stepUpProof). A
   * failed read is 'unknown' and keeps every lot-O path closed.
   * No I/O while the switch is off or SSO is not configured.
   */
  async lotOState(): Promise<LotOState> {
    return (await this.lotOStatus()).state;
  },

  /** lotOState() with the reason (Settings status for platform admins). */
  async lotOStatus(): Promise<{ state: LotOState; reason: LotOReason }> {
    if (!config.deviceKeys.ssoEnabled) return { state: 'off', reason: 'switch_off' };
    if ((await appConfigService.get('obligate_enabled')) !== 'true') return { state: 'off', reason: 'sso_off' };
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return { state: 'off', reason: 'sso_off' };
    const state = await readCapabilities({ url: raw.url, apiKey: raw.apiKey });
    return { state, reason: state === 'on' ? 'announced' : state === 'off' ? 'withdrawn' : 'unreachable' };
  },

  /** Last known lotOSupported() answer, without any I/O (false when unknown or stale). */
  lotOSupportedCached(): boolean {
    if (!config.deviceKeys.ssoEnabled) return false;
    const c = capabilitiesCache;
    return !!c && c.state === 'on' && Date.now() - c.at < c.ttl;
  },

  /**
   * Lot O (O2): the Obligate MFA epoch of a user — it changes at every
   * password / TOTP / activation change and admin MFA reset. Read with our
   * key from the configured Obligate; cached 5 min (`fresh` bypasses and
   * refreshes the cache). Null on ANY failure (not configured, unreachable,
   * non-2xx — a 404 included —, unreadable): the callers fail closed.
   * readMfaEpochDetailed() tells Obligate's 404 apart.
   */
  async getMfaEpoch(obligateUserId: number, opts: { fresh?: boolean } = {}): Promise<ObligateMfaEpoch | null> {
    const r = await readMfaEpoch(obligateUserId, opts);
    return r.kind === 'ok' ? r.value : null;
  },

  /** getMfaEpoch() with the three outcomes (see ObligateEpochRead). */
  readMfaEpochDetailed(obligateUserId: number, opts: { fresh?: boolean } = {}): Promise<ObligateEpochRead> {
    return readMfaEpoch(obligateUserId, opts);
  },

  /**
   * Fresh (uncached) epoch read started by an inbound sso-user-sync push,
   * whose secret may be public — it must not be an outbound-call amplifier:
   *   - concurrent pushes for one user share one read in flight plus ONE
   *     queued read. The queued read starts once the running one ended, so
   *     every caller gets a read begun after its own push arrived: a genuine
   *     change is never answered with a value read before it;
   *   - otherwise, no new read for a user within PUSH_READ_BUDGET.userGapMs of
   *     the previous one, and every new read takes a token of the global
   *     PUSH_READ_BUDGET: 'throttled' (nothing sent) beyond them.
   */
  mfaEpochForPush(obligateUserId: number): Promise<PushEpochRead> {
    const id = obligateUserId;
    const start = (): Promise<PushEpochRead> => {
      if (!takePushReadToken()) {
        pushEpochReads.delete(id); // (a queued start: its slot ends here)
        return Promise.resolve(THROTTLED);
      }
      const p = readMfaEpoch(id, { fresh: true }).catch((): ObligateEpochRead => ({ kind: 'unavailable' }));
      const entry: { inflight: Promise<ObligateEpochRead>; queued: Promise<PushEpochRead> | null } = { inflight: p, queued: null };
      pushEpochReads.set(id, entry);
      void p.then(() => {
        if (pushEpochDoneAt.size >= 10_000) pushEpochDoneAt.clear();
        pushEpochDoneAt.set(id, Date.now());
        if (pushEpochReads.get(id) === entry && !entry.queued) pushEpochReads.delete(id);
      });
      return p;
    };
    const slot = pushEpochReads.get(id);
    if (slot) {
      if (!slot.queued) slot.queued = slot.inflight.then(() => start());
      return slot.queued;
    }
    const last = pushEpochDoneAt.get(id);
    if (last !== undefined && Date.now() - last < PUSH_READ_BUDGET.userGapMs) return Promise.resolve(THROTTLED);
    return start();
  },

  /**
   * Drops the cached epoch of a user: the next use re-reads Obligate (an
   * inbound credentials-changed push does this — it can only tighten). A read
   * already in flight (use-time check, verify-totp) will not write its value,
   * which may predate the change, into the cache afterwards.
   */
  forgetMfaEpoch(obligateUserId: number): void {
    if (mfaEpochGen.size >= 10_000) { mfaEpochGen.clear(); mfaEpochCache.clear(); }
    mfaEpochGen.set(obligateUserId, epochGenOf(obligateUserId) + 1);
    for (const k of [...mfaEpochCache.keys()]) {
      if (k.endsWith(`#${obligateUserId}`)) mfaEpochCache.delete(k);
    }
  },

  /**
   * An epoch returned by one of OUR verify-totp calls refreshes the cache —
   * unless forgetMfaEpoch() ran for the user since that call started (`gen`).
   */
  noteMfaEpoch(obligateUserId: number, mfaEpoch: number, raw: { url: string | null; apiKey: string | null }, gen?: number): void {
    if (gen !== undefined && epochGenOf(obligateUserId) !== gen) return;
    const cached = mfaEpochCache.get(`${lotOKey(raw)}#${obligateUserId}`);
    mfaEpochCache.set(`${lotOKey(raw)}#${obligateUserId}`, {
      at: Date.now(), value: { mfaEpoch, active: cached?.value.active ?? true },
    });
  },

  /** Tests / investigation: clears the lot-O caches and the push-read budget. */
  resetLotOCaches(): void {
    capabilitiesCache = null;
    capabilitiesInflight = null;
    mfaEpochCache.clear();
    mfaEpochGen.clear();
    pushEpochReads.clear();
    pushEpochDoneAt.clear();
    pushReadTokens = PUSH_READ_BUDGET.capacity;
    pushReadRefilledAt = 0;
  },

  /**
   * Exchange an authorization code with Obligate for user info (server to
   * server, Bearer API key, one-time 60 s code bound to the redirect_uri).
   */
  async exchangeCode(code: string, redirectUri: string): Promise<ObligateUserAssertion | null> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) {
      logger.warn('Obligate exchange failed: not configured');
      return null;
    }

    try {
      const res = await fetch(`${raw.url}/api/oauth/token/exchange`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ code, redirect_uri: redirectUri }),
      });

      if (!res.ok) {
        logger.warn(`Obligate exchange failed: HTTP ${res.status}`);
        return null;
      }

      const data = await res.json() as { success: boolean; data?: ObligateUserAssertion };
      if (!data.success || !data.data) return null;

      return data.data;
    } catch (err) {
      logger.error(err, 'Obligate exchange error');
      return null;
    }
  },

  /**
   * Report a provisioned user back to Obligate.
   */
  async reportProvision(obligateUserId: number, remoteUserId: number): Promise<void> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    try {
      await fetch(`${raw.url}/api/apps/report-provision`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ obligateUserId, remoteUserId }),
      });
    } catch (err) {
      logger.error(err, 'Failed to report provision to Obligate');
    }
  },

  /**
   * Register app-specific preference schemas with Obligate.
   */
  async syncPreferenceSchemas(): Promise<void> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    const schemas = [
      {
        key: 'preferredCodec',
        label: 'Preferred video codec',
        fieldType: 'select',
        options: ['h264', 'h265', 'vp9', 'av1', 'jpeg'],
        defaultValue: 'h264',
        sortOrder: 0,
      },
    ];

    try {
      const res = await fetch(`${raw.url}/api/apps/sync-preference-schemas`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ schemas }),
      });
      if (res.ok) {
        logger.info('Obligate: preference schemas synced');
      } else {
        logger.warn(`Obligate: schema sync failed (HTTP ${res.status})`);
      }
    } catch (err) {
      logger.warn(err, 'Obligate: schema sync failed');
    }
  },

  // syncCapabilitySchemas REMOVED. The capabilities Obliance used to
  // push (monitor / execute / remote / files / power) are row-scoped
  // on team_permissions and never made sense as user-level toggles on
  // an Obligate user-tenant binding. The three legacy
  // `supervision_*` / `manage_reports` keys were renamed to
  // `supervision:read` / `agent_config:*` long ago — pushing them
  // wrote phantom toggles that didn't gate anything.
  //
  // The new model:
  //   - Role (admin / user / viewer / custom) defines WHAT a user can do
  //   - Team membership defines WHERE (which groups / devices)
  //   - Tenant-wide page gates are toggled per-team in Obliance UI
  // Obligate-side schema cleanup is handled separately.

  /**
   * Get cross-app links for a device UUID from Obligate.
   */
  async getDeviceLinks(uuid: string): Promise<Array<{ appType: string; name: string; url: string; icon: string | null; color: string | null }>> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return [];

    try {
      const res = await fetch(`${raw.url}/api/devices/links?uuid=${encodeURIComponent(uuid)}`, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
        signal: AbortSignal.timeout(5_000),
      });
      if (!res.ok) return [];
      const data = await res.json() as { success: boolean; data?: Array<{ appType: string; name: string; url: string; icon: string | null; color: string | null }> };
      const links = Array.isArray(data.data) ? data.data : [];
      if (links.length === 0) return [];
      // A link is `<app base URL><path>`, and the path is whatever the app
      // registered (POST /api/devices/register, authenticated by an app key
      // alone — some are public while their client_id is raw). A path like
      // "@evil.example/x" or ".evil.example" turns it into a link to another
      // site, shown on our device page: keep only http(s) links without
      // credentials whose origin is the registered base URL of their app.
      const origins = await this.getConnectedAppOrigins();
      return links.filter((l) => {
        if (!l || typeof l.url !== 'string' || typeof l.appType !== 'string') return false;
        try {
          const u = new URL(l.url);
          if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
          if (u.username || u.password) return false;
          return origins.get(l.appType)?.has(u.origin) ?? false;
        } catch {
          return false;
        }
      });
    } catch {
      return [];
    }
  },

  /**
   * Fetch latest preferences from Obligate and sync to local DB.
   * Throttled: once per 60s per user. Runs in background, never throws.
   */
  _prefThrottle: new Map<number, number>(),
  async syncUserPreferences(localUserId: number, obligateUserId: number): Promise<void> {
    const now = Date.now();
    if (now - (this._prefThrottle.get(localUserId) ?? 0) < 60 * 1000) return;

    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    try {
      const res = await fetch(`${raw.url}/api/apps/user-preferences/${obligateUserId}`, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
      });
      if (!res.ok) return;
      this._prefThrottle.set(localUserId, now);

      const { success, data } = await res.json() as { success: boolean; data?: {
        preferredTheme?: string; toastEnabled?: boolean; toastPosition?: string;
        preferredLanguage?: string; anonymousMode?: boolean; profilePhotoUrl?: string | null;
      } };
      if (!success || !data) return;

      // Sync language + avatar columns
      const colUpdate: Record<string, unknown> = {};
      if (data.preferredLanguage) colUpdate.preferred_language = data.preferredLanguage;
      if (data.profilePhotoUrl !== undefined) colUpdate.avatar = data.profilePhotoUrl;
      if (Object.keys(colUpdate).length > 0) {
        await db('users').where({ id: localUserId }).update(colUpdate);
      }

      // Sync UI prefs into preferences JSON
      const uiPrefs: Record<string, unknown> = {};
      if (data.preferredTheme) uiPrefs.preferredTheme = data.preferredTheme;
      if (data.toastEnabled !== undefined) uiPrefs.toastEnabled = data.toastEnabled;
      if (data.toastPosition) uiPrefs.toastPosition = data.toastPosition;
      if (data.anonymousMode !== undefined) uiPrefs.anonymousMode = data.anonymousMode;
      if (Object.keys(uiPrefs).length > 0) {
        const row = await db('users').where({ id: localUserId }).select('preferences').first() as { preferences: unknown } | undefined;
        const existing = (typeof row?.preferences === 'string' ? JSON.parse(row.preferences) : row?.preferences) ?? {};
        await db('users').where({ id: localUserId }).update({
          preferences: JSON.stringify({ ...existing, ...uiPrefs }),
        });
      }
    } catch { /* non-critical */ }
  },

  /**
   * Get the list of connected apps from Obligate (for cross-app nav buttons).
   */
  async getConnectedApps(
    obligateUserId?: number | null,
  ): Promise<Array<{ appType: string; name: string; baseUrl: string; icon: string | null; color: string | null }>> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return [];

    // Scope to the user's Obligate entitlements when we know who they are.
    // Without the userId, Obligate returns EVERY connected app, so the
    // header app switcher would show apps the user has no access to (the
    // whole point of the switcher is to only surface reachable apps).
    const url = obligateUserId
      ? `${raw.url}/api/apps/connected?userId=${encodeURIComponent(obligateUserId)}`
      : `${raw.url}/api/apps/connected`;
    try {
      const res = await fetch(url, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
        // Also on the SSO redirect path (getRegisteredAppOrigin): never hang it
        signal: AbortSignal.timeout(5_000),
      });
      if (!res.ok) return [];
      const data = await res.json() as { success: boolean; data?: Array<{ appType: string; name: string; baseUrl: string; icon: string | null; color: string | null }> };
      return data.data ?? [];
    } catch {
      return [];
    }
  },
};

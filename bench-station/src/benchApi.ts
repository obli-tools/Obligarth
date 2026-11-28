import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import type { BenchAppsPlanAnswer, BenchRequiredAppView } from '../../shared/src/mdm/bench';
import { ServerClock } from './clock';
import type { ServedAgent } from './provision/apk';

/**
 * Obligarth bench station — the client of the /api/bench/v1 surface (lot BANC §3.5), read off
 * server/src/bench/api.routes.ts and provisioning.service.ts (T1). Envelope `{success, data}` /
 * `{success:false, error, code}`.
 *
 * Every request: `Authorization: Bench <token>` from the station (never another URL's), `redirect: 'manual'` (a 3xx is
 * the error `redirected`, never followed), a timeout, the server's `Date` read into the clock. A 401 or a 403 is always
 * the station guard's (`station_refused` and its code); every other refusal carries its own code.
 */

export interface BenchTarget {
  tenantId: number;
  tenantName: string;
  groupId: number;
  groupPath: string;
  rolePolicy: 'owner_required' | 'owner_preferred' | 'admin_only';
  allowLegacyOwner: boolean;
  namePrefix: string | null;
  /** Lot BANC-T §10: the template of the suggested name ({site.code}, {site.code:N}, {n}); null or absent: none. */
  nameTemplate?: string | null;
  disableDevOptions: boolean;
}

/** GET /v1/tenants: the tenants of the station's targets (lot BANC-T §9). */
export interface BenchTenant { id: number; name: string }

/** GET /v1/tenants/:id/sites?search=: a site inside one of the station's targets (200 at most, by code). */
export interface BenchSite {
  id: string;
  code: string;
  name: string;
  city: string | null;
  groupId: number | null;
  groupPath: string | null;
  /** The devices of the site under management (0: a new site). */
  deviceCount: number;
  /** The groups of the station's targets this site may be planned into. */
  targetGroupIds: number[];
}

/** A name already used in the site: a device under management, or an open provisioning of a bench. */
export interface BenchSiteDevice {
  kind: 'device' | 'provisioning';
  label: string;
  model: string | null;
  serialTail: string | null;
  lastSeenAt: string | null;
}

/** GET /v1/sites/:id/devices[?groupId=]: the names used in the site, the name the target's template suggests. */
export interface BenchSiteDevices {
  site: BenchSite & { tenantId: number };
  devices: BenchSiteDevice[];
  nameTemplate: string | null;
  suggestedName: string | null;
}

export interface PlanRequest {
  tenantId: number;
  groupId: number;
  /** Lot BANC-T §9: the site chosen on the card (one of the target's). */
  siteId?: string | null;
  /** Lot BANC-T Q3: the exception D3 decided on the bench (an open session is required; the server audits it). */
  allowLegacyOwner?: boolean;
  device: { adbSerial: string; hwSerial: string | null; model: string; manufacturer: string; sdkInt: number; osRelease: string | null; oneUi: string | null };
  agentInstalled: { versionCode: number; signerSha256: string | null; adminActive: boolean; phase: string | null } | null;
  deviceName: string | null;
  preflight: { users: number; accounts: number; accountTypes: string[]; deviceOwner: string | null; profileOwners: number; agentAdminActive: boolean; setupComplete: boolean | null };
}

export interface PlanAnswer {
  provisioningId: string;
  /** apps (lot BANC-A): « compléter les apps » of a device already enrolled (POST /v1/provisionings/apps), or such a
   *  provisioning found open again. */
  kind: 'new' | 'convert' | 'apps';
  roleTarget: 'device_owner' | 'device_admin';
  fallbackAllowed: boolean;
  fallbackConfirm: boolean;
  deviceName: string | null;
  existingDeviceUuid?: string;
  /** Lot BANC-T: the name the target's template suggests in the site (null: none). */
  suggestedName?: string | null;
  siteId?: string | null;
  warnings: string[];
}

export interface ProvisioningState {
  state: 'planned' | 'token_issued' | 'enrolled' | 'completed' | 'failed' | 'abandoned' | 'expired';
  kind: 'new' | 'convert' | 'apps';
  deviceUuid: string | null;
  managementMode: string | null;
  identityState: string | null;
  agent: { deviceOwner: boolean; adminActive: boolean; versionCode: number; lastSeenAt: string | null; knoxState: string; adbEnabled: boolean | null } | null;
  tokenExpiresAt: string | null;
  errorCode: string | null;
  /** Lot BANC-T (absent from an older server): what the provisioning was planned with. */
  deviceName?: string | null;
  site?: { id: string; code: string; name: string } | null;
  roleTarget?: 'device_owner' | 'device_admin';
  legacyOwnerBench?: boolean;
  /** Lot BANC-A (absent from an older server): the target the provisioning was planned in. */
  tenantId?: number;
  groupId?: number;
}

export interface StepEntry {
  step: string;
  status: 'running' | 'ok' | 'warn' | 'failed' | 'skipped';
  at: string;
  code?: string;
  /** packageId (lot BANC-A, step apps): the package of the tenant's store the entry is about. */
  detail?: { code?: string; counts?: Record<string, number>; accountTypes?: string[]; sdk?: number; versionCode?: number; attempt?: number; packageId?: string };
}

/** POST /v1/provisionings/apps (lot BANC-A, « compléter les apps »): what the bench reads of a device already enrolled.
 *  The server proves the identity with it (apps.service.ts, planAppsCompletion); the station only reports. */
export interface AppsPlanRequest {
  device: PlanRequest['device'];
  /** `settings get secure android_id` (hexadecimal, lower case), null when none is read. Never shown nor logged here. */
  androidId: string | null;
  /** The bench channel of the agent (`content call … --method state`); null when it does not answer (agent < 1.4.0). */
  agent: { phase: 'ENROLLED'; role: 'NONE' | 'ADMIN' | 'OWNER'; versionCode: number } | null;
}

export interface ResultRequest {
  outcome: 'completed' | 'failed' | 'abandoned';
  roleDeclared?: 'device_owner' | 'device_admin';
  errorCode?: string;
  detail?: StepEntry['detail'];
}

/** What the provisioning sequence needs from the platform (faked by the harness). */
export interface BenchApi {
  targets(): Promise<BenchTarget[]>;
  /** Lot BANC-T §9: the choice of the card, tenant → site → name. */
  tenants(): Promise<BenchTenant[]>;
  sites(tenantId: number, search: string | null): Promise<BenchSite[]>;
  siteDevices(siteId: string, groupId: number | null): Promise<BenchSiteDevices>;
  agent(): Promise<ServedAgent>;
  downloadApk(sha256: string, dest: string): Promise<void>;
  plan(body: PlanRequest): Promise<PlanAnswer>;
  provisioning(id: string): Promise<ProvisioningState>;
  token(id: string): Promise<{ config: string; expiresAt: string }>;
  step(id: string, entry: StepEntry): Promise<void>;
  result(id: string, body: ResultRequest): Promise<{ state: string; warnings: string[] }>;
  /** Lot BANC-A: the required apps the bench installs on the enrolled device of this provisioning. A server older than
   *  the lot answers 404 `not_found` (no such route). */
  requiredApps(id: string): Promise<BenchRequiredAppView[]>;
  /** Lot BANC-A: the file of one of THOSE apps (by its SHA-256), written to `dest`; refusals keep their code (404
   *  apk_unavailable, 429 rate_limited with details.retryAfter in seconds, 500 apk_mismatch). */
  downloadPackage(sha256: string, provisioningId: string, dest: string): Promise<void>;
  /** Lot BANC-A: « compléter les apps » of a device already enrolled (an open bench session is required). */
  planApps(body: AppsPlanRequest): Promise<BenchAppsPlanAnswer>;
  /** The server's time, ISO (the steps are stamped with it). */
  nowIso(): string;
}

export class BenchApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly details: Record<string, unknown> | null = null) {
    super(message);
    this.name = 'BenchApiError';
  }
}

const TIMEOUT_MS = 20_000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface HttpBenchApiOptions {
  baseUrl: string;
  headers: () => Promise<Record<string, string>>;
  clock?: ServerClock;
  fetchImpl?: typeof fetch;
}

export class HttpBenchApi implements BenchApi {
  private readonly f: typeof fetch;
  readonly clock: ServerClock;

  constructor(private readonly o: HttpBenchApiOptions) {
    this.f = o.fetchImpl ?? fetch;
    this.clock = o.clock ?? new ServerClock();
  }

  nowIso(): string { return this.clock.iso(); }

  private async raw(path: string, init: { method?: string; body?: unknown; timeoutMs?: number } = {}): Promise<Response> {
    let res: Response;
    try {
      res = await this.f(`${this.o.baseUrl}/api/bench${path}`, {
        method: init.method ?? 'GET',
        headers: { ...(await this.o.headers()), ...(init.body !== undefined ? { 'content-type': 'application/json' } : {}), 'cache-control': 'no-store' },
        body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
        redirect: 'manual',
        signal: AbortSignal.timeout(init.timeoutMs ?? TIMEOUT_MS),
      });
    } catch (err) {
      if (err instanceof BenchApiError) throw err;
      throw new BenchApiError(0, 'server_unreachable', (err as Error)?.name === 'TimeoutError' ? 'timeout' : 'network');
    }
    this.clock.observe(res.headers.get('date'));
    if (res.status >= 300 && res.status < 400) {
      await res.text().catch(() => '');
      throw new BenchApiError(res.status, 'redirected', 'redirect not followed');
    }
    return res;
  }

  private async call<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
    const res = await this.raw(path, init);
    const text = await res.text();
    let body: { success?: boolean; data?: unknown; error?: unknown; code?: unknown; details?: unknown } | null = null;
    try { body = JSON.parse(text); } catch { body = null; }
    if (res.ok && body?.success === true) return body.data as T;
    const serverCode = typeof body?.code === 'string' && /^[a-z_]{1,48}$/.test(body.code) ? body.code : null;
    const details = body?.details && typeof body.details === 'object' ? body.details as Record<string, unknown> : null;
    if (res.status === 401 || res.status === 403) {
      throw new BenchApiError(res.status, 'station_refused', serverCode ?? 'refused', { stationCode: serverCode });
    }
    throw new BenchApiError(res.status, serverCode ?? (res.status >= 500 ? 'internal' : 'refused'),
      typeof body?.error === 'string' ? body.error.slice(0, 200) : `HTTP ${res.status}`, details);
  }

  targets(): Promise<BenchTarget[]> { return this.call('/v1/targets'); }
  tenants(): Promise<BenchTenant[]> { return this.call('/v1/tenants'); }
  sites(tenantId: number, search: string | null): Promise<BenchSite[]> {
    const q = search ? `?search=${encodeURIComponent(search.slice(0, 100))}` : '';
    return this.call(`/v1/tenants/${encodeURIComponent(String(tenantId))}/sites${q}`);
  }
  siteDevices(siteId: string, groupId: number | null): Promise<BenchSiteDevices> {
    return this.call(`/v1/sites/${encodeURIComponent(siteId)}/devices${groupId !== null ? `?groupId=${groupId}` : ''}`);
  }
  agent(): Promise<ServedAgent> { return this.call('/v1/agent'); }

  async downloadApk(sha256: string, dest: string): Promise<void> {
    if (!/^[0-9a-f]{64}$/.test(sha256)) throw new BenchApiError(0, 'apk_mismatch', 'bad sha256');
    const res = await this.raw(`/v1/agent/apk/${sha256}`, { timeoutMs: 300_000 });
    if (!res.ok || !res.body) throw new BenchApiError(res.status, 'apk_mismatch', `HTTP ${res.status}`);
    await this.streamTo(res, sha256, dest);
  }

  async downloadPackage(sha256: string, provisioningId: string, dest: string): Promise<void> {
    if (!/^[0-9a-f]{64}$/.test(sha256)) throw new BenchApiError(0, 'apk_mismatch', 'bad sha256');
    if (!UUID_RE.test(provisioningId)) throw new BenchApiError(0, 'bad_request', 'bad provisioning id');
    const res = await this.raw(`/v1/packages/${sha256}?provisioning=${encodeURIComponent(provisioningId)}`, { timeoutMs: 300_000 });
    if (!res.ok || !res.body) {
      // The refusal keeps its code (404 apk_unavailable, 429 rate_limited, 500 apk_mismatch): the card says which.
      const text = await res.text().catch(() => '');
      let code: string | null = null;
      try {
        const b = JSON.parse(text) as { code?: unknown } | null;
        code = typeof b?.code === 'string' && /^[a-z_]{1,48}$/.test(b.code) ? b.code : null;
      } catch { code = null; }
      if (res.status === 401 || res.status === 403) throw new BenchApiError(res.status, 'station_refused', code ?? 'refused', { stationCode: code });
      const retry = Number.parseInt(res.headers.get('retry-after') ?? '', 10);
      throw new BenchApiError(res.status, code ?? (res.status >= 500 ? 'internal' : 'refused'), `HTTP ${res.status}`,
        Number.isSafeInteger(retry) && retry > 0 ? { retryAfter: retry } : null);
    }
    await this.streamTo(res, sha256, dest);
  }

  /** The body of a download into `dest` (created, never overwritten), its SHA-256 checked against the one asked. */
  private async streamTo(res: Response, sha256: string, dest: string): Promise<void> {
    if (!res.body) throw new BenchApiError(res.status, 'apk_mismatch', 'no body');
    const header = res.headers.get('x-content-sha256');
    if (header && header.toLowerCase() !== sha256) throw new BenchApiError(res.status, 'apk_mismatch', 'header sha256');
    const h = createHash('sha256');
    const out = createWriteStream(dest, { flags: 'wx' });
    // Any error of the file (EEXIST, a full disk…) rejects this download: never an unhandled 'error' event, which would
    // stop the whole station.
    let failure: Error | null = null;
    const failed = new Promise<never>((_, reject) => out.on('error', (err) => { failure = err; reject(err); }));
    failed.catch(() => undefined);
    const reader = res.body.getReader();
    // The stream cut mid-way (the network, the time-out): temporary, server_unreachable, never the file's fault.
    let cut: Error | null = null;
    try {
      await Promise.race([new Promise<void>((r) => out.once('open', () => r())), failed]);
      for (;;) {
        let chunk: Awaited<ReturnType<typeof reader.read>>;
        try { chunk = await reader.read(); } catch (e) { cut = e instanceof Error ? e : new Error('network'); throw cut; }
        const { done, value } = chunk;
        if (done) break;
        h.update(value);
        if (failure) throw failure;
        if (!out.write(value)) await Promise.race([new Promise<void>((r) => out.once('drain', () => r())), failed]);
      }
    } catch (err) {
      await reader.cancel().catch(() => undefined);
      const cutErr = cut as Error | null;
      if (cutErr && !failure) throw new BenchApiError(0, 'server_unreachable', cutErr.name === 'TimeoutError' ? 'timeout' : 'network');
      throw new BenchApiError(0, 'apk_mismatch', err instanceof Error ? err.message.slice(0, 60) : 'write');
    } finally {
      await Promise.race([new Promise<void>((r) => out.end(() => r())), failed.catch(() => undefined)]);
    }
    if (failure) throw new BenchApiError(0, 'apk_mismatch', 'write');
    if (h.digest('hex') !== sha256) throw new BenchApiError(200, 'apk_mismatch', 'sha256');
  }

  plan(body: PlanRequest): Promise<PlanAnswer> { return this.call('/v1/provisionings', { method: 'POST', body }); }
  provisioning(id: string): Promise<ProvisioningState> { return this.call(`/v1/provisionings/${encodeURIComponent(id)}`); }
  token(id: string): Promise<{ config: string; expiresAt: string }> { return this.call(`/v1/provisionings/${encodeURIComponent(id)}/token`, { method: 'POST', body: {} }); }
  async step(id: string, entry: StepEntry): Promise<void> { await this.call(`/v1/provisionings/${encodeURIComponent(id)}/steps`, { method: 'POST', body: entry }); }
  result(id: string, body: ResultRequest): Promise<{ state: string; warnings: string[] }> {
    return this.call(`/v1/provisionings/${encodeURIComponent(id)}/result`, { method: 'POST', body });
  }
  requiredApps(id: string): Promise<BenchRequiredAppView[]> { return this.call(`/v1/provisionings/${encodeURIComponent(id)}/apps`); }
  planApps(body: AppsPlanRequest): Promise<BenchAppsPlanAnswer> { return this.call('/v1/provisionings/apps', { method: 'POST', body }); }
}

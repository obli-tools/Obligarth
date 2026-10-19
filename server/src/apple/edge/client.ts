import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { Agent, request, type Dispatcher } from 'undici';
import type { z } from 'zod';
import { AppleEdgeError, isRetryableAnswer } from './errors';
import {
  EdgeAcceptedW, EdgeAccountDrivenW, EdgeAdeAssignW, EdgeAdeProfileW, EdgeAdeTokenListW, EdgeAdeTokenW, EdgeCancelResponseW,
  EdgeCaRotationW, EdgeChallengeW, EdgeEnqueueResponseW, EdgeEnrollmentConfigW, EdgeEnrollmentDetailW, EdgeEnrollmentListW,
  EdgeFreezeW, EdgeLogRefsW, EdgeMachineInfoCheckW, EdgePushCertInfoW, EdgePushCertListW, EdgePushCsrW, EdgePushResultsW,
  EdgeReleaseResultW, EdgeRevealedSecretW, EdgeRevokeW, EdgeStatusW, EdgeTenantCreatedW, EdgeTenantInfoW, EdgeTenantListW,
  EdgeTenantStateW, EdgeTransferW,
  type EdgeAdeToken, type EdgeCaRotation, type EdgeChallenge, type EdgeChallengeRequest, type EdgeEnqueueRequest,
  type EdgeEnqueueResponse, type EdgeEnrollment, type EdgeEnrollmentConfig, type EdgeEnrollmentDetail, type EdgeMachineInfoCheck,
  type EdgePushCertInfo, type EdgePushCsr, type EdgePushOutcome, type EdgeReleaseResult, type EdgeRevealedSecret, type EdgeStatus,
  type EdgeTenantCreated, type EdgeTenantInfo, type EdgeTenantSummary, type EdgeTransferRequest,
} from './wire';

// =============================================================================
// Client of the internal API v1 of apple-edge (docs: integration-apple-edge
// §5.1 to §5.4, §5.6; apple-edge §5.2, §5.3). The only door of the brain to
// apple-edge besides the outbox and the DDM relay (EX-01).
//   - Bearer token (APPLE_EDGE_API_TOKEN_FILE, never logged), X-Request-ID,
//     X-Obligarth-Actor (100 characters at most), JSON in snake_case; every
//     answer read through a NOT strict schema (wire.ts), 8 MiB at most.
//   - Delays per call (§5.2); one retry after 250 ms ± 50 % for an idempotent
//     call that failed on the transport, a timeout, 502 or 503 (longer
//     retries belong to the jobs); no proxy, no redirect followed.
//   - Circuit breaker (per process): 5 transport or timeout failures in a row
//     open it for 15 s (AppleEdgeError 'unavailable' at once), then one trial
//     call; any answer closes it. The status probe always goes through.
//   - A version out of the matrix (compat.ts) refuses every call but the
//     probe ('incompatible'); APPLE_EDGE_MODE=off refuses every call
//     ('disabled').
//   - Every command_uuid sent (enqueue, cancel) goes through
//     toEdgeCommandUuid(): upper case, as apple-edge compares it byte for byte
//     with the plist's CommandUUID (review INT-RC2).
// No import of the server's config or logger: edge/instance.ts builds the
// process's client from them; the unit tests build their own.
// =============================================================================

/** Largest answer read (larger: AppleEdgeError 'protocol'). */
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
/** Transport or timeout failures in a row that open the circuit. */
export const CIRCUIT_FAILURES = 5;
/** How long the circuit stays open before a trial call. */
export const CIRCUIT_OPEN_MS = 15_000;
/** Base wait before the single retry of an idempotent call (± 50 %). */
export const RETRY_BASE_MS = 250;

const UUID_RE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
const REQUEST_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

/** The CommandUUID as apple-edge expects it: canonical, upper case (v4 random, or v8 of a guarded action).
 *  Throws a TypeError for anything that is not a UUID (a programming defect). */
export function toEdgeCommandUuid(id: string): string {
  const s = String(id ?? '').trim();
  if (!UUID_RE.test(s)) throw new TypeError('toEdgeCommandUuid: not a UUID');
  return s.toUpperCase();
}

export interface EdgeCallOptions {
  /** X-Obligarth-Actor: 'user:12', 'job:mdm.commands.submit', 'integration:apple-edge', 'enrollment:enroll'. */
  actor: string;
  /** X-Request-ID; a new one when absent. */
  requestId?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface EdgePage<T> { items: T[]; nextCursor: string | null }
export type EdgeCancelOutcome = 'cancelled' | 'already_delivered' | 'completed' | 'expired';
export type EdgeTenantState = 'active' | 'suspended' | 'retiring' | 'retired';

export interface AppleEdgeClient {
  // ── Platform ──────────────────────────────────────────────────────────────
  status(o: EdgeCallOptions): Promise<{ status: EdgeStatus; version: string }>;
  createTenant(externalRef: string, o: EdgeCallOptions): Promise<{ created: boolean; tenant: EdgeTenantCreated }>;
  listTenants(page: { cursor?: string; limit?: number }, o: EdgeCallOptions): Promise<EdgePage<EdgeTenantSummary>>;
  createTransfer(req: EdgeTransferRequest, o: EdgeCallOptions): Promise<{ id: string; expires_at: string }>;
  logRefs(enrollmentIds: string[], o: EdgeCallOptions): Promise<Record<string, string>>;
  // ── Tenant ────────────────────────────────────────────────────────────────
  getTenant(key: string, o: EdgeCallOptions): Promise<EdgeTenantInfo>;
  setTenantState(key: string, state: 'active' | 'suspended', o: EdgeCallOptions): Promise<void>;
  setCommandsFrozen(key: string, frozen: boolean, o: EdgeCallOptions): Promise<void>;
  retireTenant(key: string, o: EdgeCallOptions): Promise<void>;
  restoreTenant(key: string, o: EdgeCallOptions): Promise<void>;
  enrollmentConfig(key: string, o: EdgeCallOptions): Promise<EdgeEnrollmentConfig>;
  rotateCa(key: string, o: EdgeCallOptions): Promise<EdgeCaRotation>;
  // ── Push certificate ──────────────────────────────────────────────────────
  createPushCsr(key: string, o: EdgeCallOptions): Promise<EdgePushCsr>;
  importPushCertificate(key: string, body: { cert_pem: string; key_pem?: string; allow_topic_change?: boolean },
    o: EdgeCallOptions): Promise<EdgePushCertInfo>;
  listPushCertificates(key: string, o: EdgeCallOptions): Promise<EdgePushCertInfo[]>;
  pushRequests(key: string, enrollmentIds: string[], o: EdgeCallOptions): Promise<Record<string, EdgePushOutcome>>;
  // ── Enrollment and identity ───────────────────────────────────────────────
  createScepChallenge(key: string, body: EdgeChallengeRequest, o: EdgeCallOptions): Promise<EdgeChallenge>;
  verifyMachineInfo(key: string, machineInfoB64: string, o: EdgeCallOptions): Promise<EdgeMachineInfoCheck>;
  signProfile(key: string, unsignedProfile: Buffer, o: EdgeCallOptions): Promise<Buffer>;
  listEnrollments(key: string, q: { cursor?: string; limit?: number; seenSince?: Date }, o: EdgeCallOptions): Promise<EdgePage<EdgeEnrollment>>;
  getEnrollment(key: string, enrollmentId: string, o: EdgeCallOptions): Promise<EdgeEnrollmentDetail>;
  releaseEnrollment(key: string, enrollmentId: string, o: EdgeCallOptions): Promise<EdgeReleaseResult>;
  purgeEnrollment(key: string, enrollmentId: string, o: EdgeCallOptions): Promise<void>;
  revokeCertificate(key: string, sha256: string, reason: string, o: EdgeCallOptions): Promise<void>;
  revealDeviceSecret(key: string, ref: string, body: { reason: string; approval_ref: string }, o: EdgeCallOptions): Promise<EdgeRevealedSecret>;
  // ── Commands ──────────────────────────────────────────────────────────────
  enqueueCommand(key: string, body: EdgeEnqueueRequest, o: EdgeCallOptions): Promise<{ created: boolean; result: EdgeEnqueueResponse }>;
  cancelCommand(key: string, commandUuid: string, targets: string[] | undefined, o: EdgeCallOptions): Promise<Record<string, EdgeCancelOutcome>>;
  // ── ADE ───────────────────────────────────────────────────────────────────
  createAdeToken(key: string, o: EdgeCallOptions): Promise<EdgeAdeToken>;
  listAdeTokens(key: string, o: EdgeCallOptions): Promise<EdgeAdeToken[]>;
  getAdeToken(key: string, id: string, o: EdgeCallOptions): Promise<EdgeAdeToken>;
  uploadAdeToken(key: string, id: string, p7m: Buffer, o: EdgeCallOptions): Promise<EdgeAdeToken>;
  deleteAdeToken(key: string, id: string, o: EdgeCallOptions): Promise<void>;
  defineAdeProfile(key: string, id: string, usage: string, body: { profile: Record<string, unknown>; default: boolean },
    o: EdgeCallOptions): Promise<{ usage: string; profile_uuid: string; is_default: boolean }>;
  assignAdeProfile(key: string, id: string, body: { usage: string; serials: string[] },
    o: EdgeCallOptions): Promise<{ usage: string; profile_uuid: string; results: Record<string, string> }>;
  syncAdeToken(key: string, id: string, o: EdgeCallOptions): Promise<void>;
  declareAccountDrivenEnrollment(key: string, id: string, o: EdgeCallOptions): Promise<{ mdm_service_discovery_url: string }>;
  /** Circuit state (metrics, administration). */
  circuitOpen(): boolean;
}

export interface AppleEdgeClientOptions {
  /** APPLE_EDGE_URL, without trailing slash. */
  baseUrl: string;
  /** The bearer token (read from its file once). */
  token: () => string;
  /** Default timeout (APPLE_EDGE_TIMEOUT_MS). */
  timeoutMs: number;
  /** APPLE_EDGE_MODE=on; false: every call refused ('disabled'). */
  enabled?: () => boolean;
  /** Version compatibility known so far; false: every call but the probe refused ('incompatible'). */
  compatible?: () => boolean;
  /** The X-Apple-Edge-Version of every answer. */
  onVersion?: (version: string) => void;
  /** Every failed call (after its retry): logs, alerts, metrics. Never throws. */
  onFailure?: (e: AppleEdgeError, call: { method: string; route: string }) => void;
  /** Every answered call: metrics. */
  onCall?: (call: { method: string; route: string; status: number | null; ms: number }) => void;
  dispatcher?: Dispatcher;
  maxResponseBytes?: number;
  /** Tests: clock of the circuit, wait of the retry, jitter. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
}

interface CallSpec<S extends z.ZodTypeAny | null> {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** Path under /internal/v1, its variable segments already encoded. */
  path: string;
  /** Route pattern (no identifier), for metrics and logs. */
  route: string;
  body?: unknown;
  rawBody?: Buffer;
  schema: S;
  timeoutMs?: number;
  idempotent: boolean;
  /** The status probe: always goes through the circuit and the version gate. */
  probe?: boolean;
  /** Raw answer (signed profile). */
  raw?: boolean;
}

const seg = (v: string): string => encodeURIComponent(String(v));

/** A printable actor of 100 characters at most (never a header injection). */
function actorHeader(actor: string): string {
  const a = String(actor ?? '').replace(/[^\x20-\x7e]/g, '').slice(0, 100);
  return a || 'unknown';
}

class Circuit {
  private failures = 0;
  private openUntil = 0;
  private probing = false;
  private readonly now: () => number;

  constructor(now: () => number) {
    this.now = now;
  }

  isOpen(): boolean {
    return this.failures >= CIRCUIT_FAILURES && this.now() < this.openUntil;
  }

  /** May a call go through? Throws 'unavailable' while open, or while a trial call runs. */
  admit(): void {
    if (this.failures < CIRCUIT_FAILURES) return;
    if (this.now() < this.openUntil || this.probing) {
      throw new AppleEdgeError(null, 'unavailable', 'apple-edge is unreachable (circuit open)', true);
    }
    this.probing = true;
  }

  answered(): void {
    this.failures = 0;
    this.openUntil = 0;
    this.probing = false;
  }

  failed(): void {
    this.failures += 1;
    this.probing = false;
    if (this.failures >= CIRCUIT_FAILURES) this.openUntil = this.now() + CIRCUIT_OPEN_MS;
  }

  released(): void {
    this.probing = false;
  }
}

/** Reads a body of `max` bytes at most. */
async function readCapped(body: Dispatcher.ResponseData['body'], max: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of body) {
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    size += b.length;
    if (size > max) {
      body.destroy();
      throw new AppleEdgeError(null, 'protocol', `apple-edge answered more than ${max} bytes`, false);
    }
    chunks.push(b);
  }
  return Buffer.concat(chunks, size);
}

export function createAppleEdgeClient(opts: AppleEdgeClientOptions): AppleEdgeClient {
  const base = String(opts.baseUrl).replace(/\/+$/, '');
  const dispatcher = opts.dispatcher ?? new Agent({ keepAliveTimeout: 30_000, connections: 16 });
  const maxBytes = opts.maxResponseBytes ?? MAX_RESPONSE_BYTES;
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? ((ms: number) => delay(ms).then(() => undefined));
  const random = opts.random ?? Math.random;
  const circuit = new Circuit(now);

  async function once<S extends z.ZodTypeAny | null>(spec: CallSpec<S>, o: EdgeCallOptions): Promise<{ status: number; data: unknown }> {
    if (!spec.probe) circuit.admit();
    const timeoutMs = Math.max(1, o.timeoutMs ?? spec.timeoutMs ?? opts.timeoutMs);
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = o.signal ? AbortSignal.any([timeout, o.signal]) : timeout;
    const requestId = o.requestId && REQUEST_ID_RE.test(o.requestId) ? o.requestId : randomUUID();
    const headers: Record<string, string> = {
      authorization: `Bearer ${opts.token()}`,
      'x-request-id': requestId,
      'x-obligarth-actor': actorHeader(o.actor),
      accept: spec.raw ? '*/*' : 'application/json',
    };
    let body: string | Buffer | undefined;
    if (spec.rawBody !== undefined) {
      body = spec.rawBody;
      headers['content-type'] = 'application/octet-stream';
    } else if (spec.body !== undefined) {
      body = JSON.stringify(spec.body);
      headers['content-type'] = 'application/json';
    }
    const t0 = now();
    let res: Dispatcher.ResponseData;
    try {
      res = await request(`${base}/internal/v1${spec.path}`, { method: spec.method, headers, body, signal, dispatcher });
    } catch (err) {
      const callerAborted = !!o.signal?.aborted && !timeout.aborted;
      if (callerAborted) circuit.released();
      else circuit.failed();
      opts.onCall?.({ method: spec.method, route: spec.route, status: null, ms: now() - t0 });
      if (timeout.aborted) throw new AppleEdgeError(null, 'timeout', `apple-edge did not answer within ${timeoutMs} ms`, true);
      void err;
      throw new AppleEdgeError(null, 'transport', callerAborted ? 'call to apple-edge aborted' : 'apple-edge is unreachable', !callerAborted);
    }
    circuit.answered();
    const version = res.headers['x-apple-edge-version'];
    if (typeof version === 'string' && version) opts.onVersion?.(version);
    let buf: Buffer;
    try {
      const declared = Number(res.headers['content-length']);
      if (Number.isFinite(declared) && declared > maxBytes) {
        res.body.destroy();
        throw new AppleEdgeError(res.statusCode, 'protocol', `apple-edge announced more than ${maxBytes} bytes`, false);
      }
      buf = await readCapped(res.body, maxBytes);
    } catch (err) {
      opts.onCall?.({ method: spec.method, route: spec.route, status: res.statusCode, ms: now() - t0 });
      if (err instanceof AppleEdgeError) throw err;
      if (timeout.aborted) throw new AppleEdgeError(null, 'timeout', `apple-edge did not finish its answer within ${timeoutMs} ms`, true);
      throw new AppleEdgeError(null, 'transport', 'the answer of apple-edge was cut', true);
    }
    opts.onCall?.({ method: spec.method, route: spec.route, status: res.statusCode, ms: now() - t0 });
    const status = res.statusCode;
    if (status >= 200 && status < 300) {
      if (spec.raw) return { status, data: buf };
      if (status === 204 || spec.schema === null) return { status, data: undefined };
      let json: unknown;
      try {
        json = buf.length ? JSON.parse(buf.toString('utf8')) : {};
      } catch {
        throw new AppleEdgeError(status, 'protocol', 'apple-edge answered something that is not JSON', false);
      }
      const parsed = (spec.schema as z.ZodTypeAny).safeParse(json);
      if (!parsed.success) throw new AppleEdgeError(status, 'protocol', `apple-edge answered an unexpected shape (${spec.route})`, false);
      return { status, data: parsed.data };
    }
    if (status >= 300 && status < 400) throw new AppleEdgeError(status, 'protocol', 'apple-edge answered a redirection (never followed)', false);
    let code = `http_${status}`;
    let message = `apple-edge answered ${status}`;
    let targets: string[] | null = null;
    try {
      const e = JSON.parse(buf.toString('utf8')) as { error?: { code?: unknown; message?: unknown; targets?: unknown; targets_truncated?: unknown } };
      if (typeof e?.error?.code === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(e.error.code)) code = e.error.code;
      if (typeof e?.error?.message === 'string') message = e.error.message.slice(0, 300);
      // The refused targets of an enqueue (point 19), when apple-edge lists them all: enrollment ids only.
      const t = e?.error?.targets;
      if (Array.isArray(t) && t.length <= 1000 && e.error?.targets_truncated !== true
        && t.every((x) => typeof x === 'string' && x.length <= 300 && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(x))) targets = t as string[];
    } catch { /* not JSON: the status speaks */ }
    throw new AppleEdgeError(status, code, message, isRetryableAnswer(status, code), targets);
  }

  async function callRaw<S extends z.ZodTypeAny | null>(spec: CallSpec<S>, o: EdgeCallOptions): Promise<{ status: number; data: unknown }> {
    if (opts.enabled && !opts.enabled()) throw new AppleEdgeError(null, 'disabled', 'the Apple integration is turned off (APPLE_EDGE_MODE=off)', false);
    if (!spec.probe && opts.compatible && !opts.compatible()) {
      throw new AppleEdgeError(null, 'incompatible', 'apple-edge runs a version out of the compatibility matrix', false);
    }
    const attempts = spec.idempotent ? 2 : 1;
    for (let i = 1; ; i++) {
      try {
        return await once(spec, o);
      } catch (err) {
        const e = err instanceof AppleEdgeError ? err : new AppleEdgeError(null, 'transport', 'call to apple-edge failed', true);
        const again = i < attempts && !o.signal?.aborted
          && (e.code === 'transport' || e.code === 'timeout' || e.status === 502 || e.status === 503);
        if (!again) {
          try { opts.onFailure?.(e, { method: spec.method, route: spec.route }); } catch { /* never */ }
          throw e;
        }
        await sleep(Math.round(RETRY_BASE_MS * (0.5 + random())));
      }
    }
  }

  const call = async <S extends z.ZodTypeAny>(spec: CallSpec<S>, o: EdgeCallOptions): Promise<z.output<S>> =>
    (await callRaw(spec, o)).data as z.output<S>;
  const none = async (spec: CallSpec<z.ZodTypeAny | null>, o: EdgeCallOptions): Promise<void> => { await callRaw(spec, o); };
  const t = (key: string): string => `/tenants/${seg(key)}`;

  return {
    async status(o) {
      const status = await call({ method: 'GET', path: '/status', route: 'GET /status', schema: EdgeStatusW, timeoutMs: 3_000, idempotent: false, probe: true }, o);
      return { status, version: status.version };
    },
    async createTenant(externalRef, o) {
      const r = await callRaw({
        method: 'POST', path: '/tenants', route: 'POST /tenants', body: { external_ref: String(externalRef).toLowerCase() },
        schema: EdgeTenantCreatedW, timeoutMs: 60_000, idempotent: true,
      }, o);
      return { created: r.status === 201, tenant: r.data as EdgeTenantCreated };
    },
    async listTenants(page, o) {
      const q = new URLSearchParams();
      if (page.cursor) q.set('cursor', page.cursor);
      if (page.limit) q.set('limit', String(page.limit));
      const r = await call({ method: 'GET', path: `/tenants${q.size ? `?${q}` : ''}`, route: 'GET /tenants', schema: EdgeTenantListW, idempotent: true }, o);
      return { items: r.tenants, nextCursor: r.next_cursor ?? null };
    },
    async createTransfer(req, o) {
      const r = await call({ method: 'POST', path: '/device-id-transfers', route: 'POST /device-id-transfers', body: req, schema: EdgeTransferW, idempotent: false }, o);
      return { id: r.id, expires_at: r.expires_at };
    },
    async logRefs(enrollmentIds, o) {
      const r = await call({ method: 'POST', path: '/log-refs', route: 'POST /log-refs', body: { enrollment_ids: enrollmentIds }, schema: EdgeLogRefsW, idempotent: true }, o);
      return r.refs;
    },
    getTenant: (key, o) => call({ method: 'GET', path: t(key), route: 'GET /tenants/{key}', schema: EdgeTenantInfoW, idempotent: true }, o),
    setTenantState: (key, state, o) => none({
      method: 'POST', path: `${t(key)}/state`, route: 'POST /tenants/{key}/state', body: { state }, schema: EdgeTenantStateW, idempotent: true,
    }, o),
    setCommandsFrozen: (key, frozen, o) => none({
      method: 'POST', path: `${t(key)}/commands-freeze`, route: 'POST /tenants/{key}/commands-freeze', body: { frozen }, schema: EdgeFreezeW, idempotent: true,
    }, o),
    retireTenant: (key, o) => none({ method: 'DELETE', path: t(key), route: 'DELETE /tenants/{key}', schema: EdgeTenantStateW, idempotent: true }, o),
    restoreTenant: (key, o) => none({ method: 'POST', path: `${t(key)}/restore`, route: 'POST /tenants/{key}/restore', schema: EdgeTenantStateW, idempotent: false }, o),
    enrollmentConfig: (key, o) => call({
      method: 'GET', path: `${t(key)}/enrollment-config`, route: 'GET /tenants/{key}/enrollment-config', schema: EdgeEnrollmentConfigW, idempotent: true,
    }, o),
    rotateCa: (key, o) => call({ method: 'POST', path: `${t(key)}/ca/rotate`, route: 'POST /tenants/{key}/ca/rotate', schema: EdgeCaRotationW, idempotent: false }, o),
    createPushCsr: (key, o) => call({ method: 'POST', path: `${t(key)}/push/csr`, route: 'POST /tenants/{key}/push/csr', schema: EdgePushCsrW, idempotent: false }, o),
    importPushCertificate: (key, body, o) => call({
      method: 'PUT', path: `${t(key)}/push/certificate`, route: 'PUT /tenants/{key}/push/certificate', body, schema: EdgePushCertInfoW, idempotent: false,
    }, o),
    async listPushCertificates(key, o) {
      return (await call({ method: 'GET', path: `${t(key)}/push`, route: 'GET /tenants/{key}/push', schema: EdgePushCertListW, idempotent: true }, o)).certificates;
    },
    async pushRequests(key, enrollmentIds, o) {
      const r = await call({
        method: 'POST', path: `${t(key)}/push-requests`, route: 'POST /tenants/{key}/push-requests', body: { enrollment_ids: enrollmentIds },
        schema: EdgePushResultsW, idempotent: false,
      }, o);
      return r.results as Record<string, EdgePushOutcome>;
    },
    createScepChallenge: (key, body, o) => call({
      method: 'POST', path: `${t(key)}/scep-challenges`, route: 'POST /tenants/{key}/scep-challenges', body, schema: EdgeChallengeW, idempotent: false,
    }, o),
    verifyMachineInfo: (key, machineInfoB64, o) => call({
      method: 'POST', path: `${t(key)}/machine-info/verify`, route: 'POST /tenants/{key}/machine-info/verify', body: { machine_info: machineInfoB64 },
      schema: EdgeMachineInfoCheckW, idempotent: false,
    }, o),
    async signProfile(key, unsignedProfile, o) {
      const r = await callRaw({
        method: 'POST', path: `${t(key)}/profiles/sign`, route: 'POST /tenants/{key}/profiles/sign', rawBody: unsignedProfile, schema: null,
        idempotent: true, raw: true,
      }, o);
      return r.data as Buffer;
    },
    async listEnrollments(key, q, o) {
      const p = new URLSearchParams();
      if (q.cursor) p.set('cursor', q.cursor);
      if (q.limit) p.set('limit', String(q.limit));
      if (q.seenSince) p.set('seen_since', q.seenSince.toISOString());
      const r = await call({
        method: 'GET', path: `${t(key)}/enrollments${p.size ? `?${p}` : ''}`, route: 'GET /tenants/{key}/enrollments', schema: EdgeEnrollmentListW, idempotent: true,
      }, o);
      return { items: r.enrollments, nextCursor: r.next_cursor ?? null };
    },
    getEnrollment: (key, enrollmentId, o) => call({
      method: 'GET', path: `${t(key)}/enrollments/${seg(enrollmentId)}`, route: 'GET /tenants/{key}/enrollments/{id}', schema: EdgeEnrollmentDetailW, idempotent: true,
    }, o),
    releaseEnrollment: (key, enrollmentId, o) => call({
      method: 'POST', path: `${t(key)}/enrollments/${seg(enrollmentId)}/release`, route: 'POST /tenants/{key}/enrollments/{id}/release',
      schema: EdgeReleaseResultW, idempotent: false,
    }, o),
    purgeEnrollment: (key, enrollmentId, o) => none({
      method: 'DELETE', path: `${t(key)}/enrollments/${seg(enrollmentId)}`, route: 'DELETE /tenants/{key}/enrollments/{id}', schema: null, idempotent: true,
    }, o),
    revokeCertificate: (key, sha256, reason, o) => none({
      method: 'POST', path: `${t(key)}/certificates/${seg(sha256)}/revoke`, route: 'POST /tenants/{key}/certificates/{sha256}/revoke',
      body: { reason }, schema: EdgeRevokeW, idempotent: true,
    }, o),
    revealDeviceSecret: (key, ref, body, o) => call({
      method: 'POST', path: `${t(key)}/device-secrets/${seg(ref)}/reveal`, route: 'POST /tenants/{key}/device-secrets/{ref}/reveal', body,
      schema: EdgeRevealedSecretW, idempotent: false,
    }, o),
    async enqueueCommand(key, body, o) {
      const r = await callRaw({
        method: 'POST', path: `${t(key)}/commands`, route: 'POST /tenants/{key}/commands',
        body: { ...body, command_uuid: toEdgeCommandUuid(body.command_uuid) }, schema: EdgeEnqueueResponseW, timeoutMs: 15_000, idempotent: true,
      }, o);
      return { created: r.status === 201, result: r.data as EdgeEnqueueResponse };
    },
    async cancelCommand(key, commandUuid, targets, o) {
      const r = await call({
        method: 'POST', path: `${t(key)}/commands/${seg(toEdgeCommandUuid(commandUuid))}/cancel`, route: 'POST /tenants/{key}/commands/{uuid}/cancel',
        body: targets ? { targets } : {}, schema: EdgeCancelResponseW, idempotent: true,
      }, o);
      return r.targets as Record<string, EdgeCancelOutcome>;
    },
    createAdeToken: (key, o) => call({ method: 'POST', path: `${t(key)}/ade-tokens`, route: 'POST /tenants/{key}/ade-tokens', schema: EdgeAdeTokenW, idempotent: false }, o),
    async listAdeTokens(key, o) {
      return (await call({ method: 'GET', path: `${t(key)}/ade-tokens`, route: 'GET /tenants/{key}/ade-tokens', schema: EdgeAdeTokenListW, idempotent: true }, o)).ade_tokens;
    },
    getAdeToken: (key, id, o) => call({
      method: 'GET', path: `${t(key)}/ade-tokens/${seg(id)}`, route: 'GET /tenants/{key}/ade-tokens/{id}', schema: EdgeAdeTokenW, idempotent: true,
    }, o),
    uploadAdeToken: (key, id, p7m, o) => call({
      method: 'PUT', path: `${t(key)}/ade-tokens/${seg(id)}/token`, route: 'PUT /tenants/{key}/ade-tokens/{id}/token', rawBody: p7m,
      schema: EdgeAdeTokenW, timeoutMs: 30_000, idempotent: false,
    }, o),
    deleteAdeToken: (key, id, o) => none({
      method: 'DELETE', path: `${t(key)}/ade-tokens/${seg(id)}`, route: 'DELETE /tenants/{key}/ade-tokens/{id}', schema: EdgeAcceptedW, idempotent: false,
    }, o),
    defineAdeProfile: (key, id, usage, body, o) => call({
      method: 'PUT', path: `${t(key)}/ade-tokens/${seg(id)}/profiles/${seg(usage)}`, route: 'PUT /tenants/{key}/ade-tokens/{id}/profiles/{usage}',
      body, schema: EdgeAdeProfileW, timeoutMs: 30_000, idempotent: false,
    }, o),
    assignAdeProfile: (key, id, body, o) => call({
      method: 'POST', path: `${t(key)}/ade-tokens/${seg(id)}/assignments`, route: 'POST /tenants/{key}/ade-tokens/{id}/assignments',
      body, schema: EdgeAdeAssignW, timeoutMs: 30_000, idempotent: false,
    }, o),
    syncAdeToken: (key, id, o) => none({
      method: 'POST', path: `${t(key)}/ade-tokens/${seg(id)}/sync`, route: 'POST /tenants/{key}/ade-tokens/{id}/sync', schema: EdgeAcceptedW, idempotent: true,
    }, o),
    declareAccountDrivenEnrollment: (key, id, o) => call({
      method: 'PUT', path: `${t(key)}/ade-tokens/${seg(id)}/account-driven-enrollment`, route: 'PUT /tenants/{key}/ade-tokens/{id}/account-driven-enrollment',
      schema: EdgeAccountDrivenW, timeoutMs: 30_000, idempotent: false,
    }, o),
    circuitOpen: () => circuit.isOpen(),
  };
}

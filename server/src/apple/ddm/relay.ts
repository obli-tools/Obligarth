import express, { raw as rawBodyParser, type NextFunction, type Request, type Response, type Router } from 'express';
import type { Knex } from 'knex';
import { z } from 'zod';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { safeErr } from '../../jobs';
import { logger } from '../../utils/logger';
import { EDGE_INTEGRATION } from '../actors';
import { raiseAlert } from '../alerts/service';
import { HEADER_SIGNATURE, HEADER_TIMESTAMP, signRelay, verifyRelay } from '../edge/hmac';
import { readHmacKeyFile } from '../edge/secrets';
import { appleTenants } from '../tenants/registry';
import { isMdmKey } from '../tenants/key';
import { canonicalize, declarationBody, declarationItemsBody, syncTokensBody } from './canonical';
import type { DeclarationFamily } from './capabilities';
import { computeSet, type SetItem } from './engine';
import { reportDropped, requestStatusIngest } from './jobs';
import { ddmMetrics, type RelayEndpointKind } from './metrics';
import { MAX_REPORT_BYTES, sanitizeReport } from './report';
import { storeStatusReport } from './status';
import type { DroppedDeclaration } from './validate';

// =============================================================================
// DDM relay: POST /internal/apple-edge/ddm (docs: integration-apple-edge §9.5,
// I5, EX-11, annex C; apple-edge §5.8). apple-edge relays every
// DeclarativeManagement check-in of a device here; the brain runs the whole
// DDM engine. Mounted before the whole chain of the console (no session, no
// cookie, no JSON parser, no limiter of the API): the raw body is what the
// HMAC covers.
//   1. signature: X-Edge-Timestamp within ±60 s, X-Edge-Signature = "v1=" +
//      base64(HMAC-SHA256(key, timestamp "." body)), constant-time, against
//      the current key then the next one of a rotation; the key that verified
//      signs the answer. A request that fails gets 401, unsigned (apple-edge
//      answers 502 to the device);
//   2. body (v1; a field apple-edge adds within v1 is ignored): the tenant key,
//      an enrollment id prefixed by it, an endpoint of apple-edge's allow-list
//      (checked again), data in base64. Refused: 400, signed;
//   3. tenant of the key (context 'none', i:apple-edge); unknown: 404, signed;
//   4. device of the enrollment, in its tenant's context: user channel 404;
//      no record yet 503 (the outbox has not created it: the device retries);
//      out of management 404;
//   5. the endpoint: tokens, declaration-items, declaration/<family>/<id>,
//      status (stored in the inbox, ingested by a job: 204).
// Every answer to an authenticated request is signed over its exact bytes
// (canonical JSON, or empty). The reads a device repeats (tokens,
// declaration-items, a declaration) cost one statement in the tenant's
// context, outside any transaction; a status report and the first
// computation of a set take one transaction. Every statement is bounded to
// 2 s; one row written at most. Never logged: data_b64, a status report, and
// the enrollment id above the debug level.
// =============================================================================

export const DDM_RELAY_PATH = '/internal/apple-edge/ddm';

/** apple-edge's allow-list of the Endpoint (ddm/relay.go, EndpointRe), checked again here. */
const ENDPOINT_RE = /^(tokens|declaration-items|status|declaration\/(activation|asset|configuration|management)\/[A-Za-z0-9][A-Za-z0-9._-]{0,254})$/;
/** An enrollment id of apple-edge: '<key>_<raw id>', with the ':<user>' of a user channel (refused below). */
const ENROLLMENT_ID_RE = /^[a-km-np-z2-9]{16}_[A-Za-z0-9._:-]{1,255}$/;
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/** v1 of the relay's body. Not strict: apple-edge may add a field within v1. */
const RelayBody = z.object({
  v: z.literal(1),
  tenant_key: z.string().refine(isMdmKey),
  enrollment_id: z.string().regex(ENROLLMENT_ID_RE),
  enrollment_type: z.string().max(64).optional().nullable(),
  parent_enrollment_id: z.string().max(400).nullable().optional(),
  endpoint: z.string().max(300).regex(ENDPOINT_RE),
  data_b64: z.string().regex(BASE64_RE).nullable().optional(),
});

// ── Keys (files, never logged) ─────────────────────────────────────────────────────

const KEYS_TTL_MS = 60_000;
let keys: { at: number; list: Buffer[] } | null = null;
let keysErrorAt = 0;

/** The current key, then the next one of a rotation; read again every minute (a rotation needs no restart). The
 *  keys read last stay in use while a file is unreadable. null: no key at all. */
function relayKeys(): Buffer[] | null {
  const now = Date.now();
  if (keys && now - keys.at < KEYS_TTL_MS) return keys.list;
  try {
    const list = [readHmacKeyFile(config.apple.ddmHmacKeyFile)];
    if (config.apple.ddmHmacKeyNextFile) list.push(readHmacKeyFile(config.apple.ddmHmacKeyNextFile, 'APPLE_EDGE_DDM_HMAC_KEY_NEXT_FILE'));
    keys = { at: now, list };
  } catch (err) {
    if (now - keysErrorAt > KEYS_TTL_MS) {
      keysErrorAt = now;
      logger.error({ err: { message: (err as Error)?.message } }, 'DDM relay: the HMAC key cannot be read');
    }
    if (keys) keys = { at: now, list: keys.list };
  }
  return keys?.list ?? null;
}

/** Tests: forget the keys read (another key file). */
export function resetDdmRelayForTests(): void {
  keys = null;
  keysErrorAt = 0;
  failures.length = 0;
  alertedAt = 0;
  declarationCache.clear();
}

// ── Authentication failures: metric, platform alert beyond 10 in 5 minutes ─────────

const AUTH_WINDOW_MS = 5 * 60_000;
const AUTH_ALERT_AFTER = 10;
const failures: number[] = [];
let alertedAt = 0;

function authFailed(): void {
  ddmMetrics.relayAuthFailure();
  const now = Date.now();
  failures.push(now);
  while (failures.length > 0 && now - failures[0] > AUTH_WINDOW_MS) failures.shift();
  if (failures.length > 1000) failures.splice(0, failures.length - 1000);
  if (failures.length > AUTH_ALERT_AFTER && now - alertedAt > AUTH_WINDOW_MS) {
    alertedAt = now;
    logger.error({ count: failures.length }, 'DDM relay: requests with a refused signature (check apple_edge_ddm_hmac on both sides, and who reaches the route)');
    void raiseAlert(EDGE_INTEGRATION, MASTER_TENANT_ID, 'ddm.relay_auth_failed', { params: { count: failures.length } });
  }
}

// ── Bytes of a declaration, by content (2 000 entries, 10 minutes) ─────────────────

const CACHE_MAX = 2000;
const CACHE_TTL_MS = 10 * 60_000;
const declarationCache = new Map<string, { at: number; body: Buffer }>();

function cached(key: string): Buffer | null {
  const hit = declarationCache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > CACHE_TTL_MS) {
    declarationCache.delete(key);
    return null;
  }
  return hit.body;
}

function remember(key: string, body: Buffer): void {
  if (declarationCache.size >= CACHE_MAX) {
    // The oldest entries leave (a Map iterates in insertion order).
    let n = Math.ceil(CACHE_MAX / 10);
    for (const k of declarationCache.keys()) { declarationCache.delete(k); if (--n <= 0) break; }
  }
  declarationCache.set(key, { at: Date.now(), body });
}

// ── The request ───────────────────────────────────────────────────────────────────

interface Answer {
  status: 200 | 204 | 400 | 404 | 503;
  body: Buffer;
  /** For the log: what happened, never a value. */
  outcome: string;
  /** Declarations set aside by a computation of this request, reported after the transaction. */
  dropped?: DroppedDeclaration[];
}

const EMPTY = Buffer.alloc(0);
const error = (status: 400 | 404 | 503, code: string): Answer => ({ status, body: Buffer.from(canonicalize({ error: code }), 'utf8'), outcome: code });
const ok = (text: string, outcome: string, dropped?: DroppedDeclaration[]): Answer => ({ status: 200, body: Buffer.from(text, 'utf8'), outcome, ...(dropped?.length ? { dropped } : {}) });

const endpointKind = (endpoint: string): RelayEndpointKind =>
  (endpoint === 'tokens' || endpoint === 'declaration-items' || endpoint === 'status' ? endpoint : endpoint.startsWith('declaration/') ? 'declaration' : 'other');

/** Decodes the status report of a `status` check-in; null when it is not one. */
function reportOf(dataB64: string | null | undefined): ReturnType<typeof sanitizeReport> {
  if (!dataB64 || dataB64.length > Math.ceil(MAX_REPORT_BYTES / 3) * 4 + 4) return null;
  const raw = Buffer.from(dataB64, 'base64');
  if (raw.length === 0 || raw.length > MAX_REPORT_BYTES) return null;
  const text = raw.toString('utf8');
  // PostgreSQL's jsonb refuses U+0000 in a string or a key: such a report is not one a device sends.
  if (text.includes('\\u0000') || text.includes('\u0000')) return null;
  try {
    return sanitizeReport(JSON.parse(text));
  } catch {
    return null;
  }
}

/** Budget of a statement of the relay, milliseconds (far from the 8 s apple-edge waits); the transactions of the
 *  relay set the same budget on their statements (SET LOCAL statement_timeout = '2s'). */
const STATEMENT_BUDGET_MS = 2000;

type Queryable = Knex | Knex.Transaction;

// The statements of the relay, each written in full (no fragment assembled, every value bound). The device of an
// enrollment is read in its tenant (the context's), with its record and its set.

const deviceStatement = (q: Queryable, tenantId: number, enrollmentId: string): Knex.Raw => q.raw(`
  SELECT d.id, d.enrollment_state
    FROM obligarth.apple_devices a
    JOIN obligarth.devices d ON d.id = a.device_id AND d.tenant_id = a.tenant_id
   WHERE a.tenant_id = ? AND a.enrollment_id = ?`, [tenantId, enrollmentId]);

const tokensStatement = (q: Queryable, tenantId: number, enrollmentId: string): Knex.Raw => q.raw(`
  SELECT d.id, d.enrollment_state, s.declarations_token, s.computed_at
    FROM obligarth.apple_devices a
    JOIN obligarth.devices d ON d.id = a.device_id AND d.tenant_id = a.tenant_id
    LEFT JOIN obligarth.apple_declaration_sets s ON s.device_id = a.device_id AND s.tenant_id = a.tenant_id
   WHERE a.tenant_id = ? AND a.enrollment_id = ?`, [tenantId, enrollmentId]);

/** declaration-items: the set read and its fetch recorded in one statement. */
const itemsStatement = (q: Queryable, tenantId: number, enrollmentId: string): Knex.Raw => q.raw(`
  WITH dev AS (SELECT d.id, d.enrollment_state
                 FROM obligarth.apple_devices a
                 JOIN obligarth.devices d ON d.id = a.device_id AND d.tenant_id = a.tenant_id
                WHERE a.tenant_id = ? AND a.enrollment_id = ?),
       upd AS (UPDATE obligarth.apple_declaration_sets s SET fetched_token = s.declarations_token, fetched_at = now()
                 FROM dev WHERE s.tenant_id = ? AND s.device_id = dev.id AND dev.enrollment_state <> 'unenrolled'
               RETURNING s.declarations_token, s.items)
  SELECT dev.id, dev.enrollment_state, upd.declarations_token, upd.items FROM dev LEFT JOIN upd ON true`, [tenantId, enrollmentId, tenantId]);

/** One declaration: its ServerToken in the device's set, else in its previous set while that one is kept. */
const declarationTokenStatement = (q: Queryable, tenantId: number, enrollmentId: string, family: string, identifier: string): Knex.Raw => q.raw(`
  SELECT d.id, d.enrollment_state,
         (SELECT e->>'server_token' FROM jsonb_array_elements(s.items) e WHERE e->>'identifier' = ? AND e->>'family' = ? LIMIT 1) AS current_token,
         CASE WHEN s.previous_until > now() THEN
           (SELECT e->>'server_token' FROM jsonb_array_elements(s.previous_items) e WHERE e->>'identifier' = ? AND e->>'family' = ? LIMIT 1)
         END AS previous_token
    FROM obligarth.apple_devices a
    JOIN obligarth.devices d ON d.id = a.device_id AND d.tenant_id = a.tenant_id
    LEFT JOIN obligarth.apple_declaration_sets s ON s.device_id = a.device_id AND s.tenant_id = a.tenant_id
   WHERE a.tenant_id = ? AND a.enrollment_id = ?`, [identifier, family, identifier, family, tenantId, enrollmentId]);

const declarationStatement = (q: Queryable, tenantId: number, family: string, identifier: string, token: string): Knex.Raw => q.raw(
  'SELECT type, payload FROM obligarth.apple_declarations WHERE tenant_id = ? AND identifier = ? AND server_token = ? AND family = ?',
  [tenantId, identifier, token, family]);

/** The first row of one statement run outside a transaction (its own lease in the tenant's context), cancelled past the budget. */
async function one<T>(statement: Knex.Raw): Promise<T | undefined> {
  const res = await statement.timeout(STATEMENT_BUDGET_MS, { cancel: true }) as unknown as { rows: T[] };
  return res.rows[0];
}

/** The first row of one statement of a transaction of the relay (its statements carry the budget already). */
async function oneIn<T>(statement: Knex.Raw): Promise<T | undefined> {
  return (await statement as unknown as { rows: T[] }).rows[0];
}

interface DeviceRow { id: number; enrollment_state: string }

/** The answer for a device that cannot be served, or null. No record: the outbox has not created it yet
 *  (Authenticate not consumed), the device will retry. */
function unserved(row: DeviceRow | undefined): Answer | null {
  if (!row) return error(503, 'device_unknown');
  if (row.enrollment_state === 'unenrolled') return error(404, 'device_unenrolled');
  return null;
}

const itemsBody = (items: unknown, token: string): string =>
  declarationItemsBody((Array.isArray(items) ? items as SetItem[] : []).map((i) => ({ family: i.family, identifier: i.identifier, serverToken: i.server_token })), token);

/**
 * tokens or declaration-items of a device whose set was never computed: computed now, in one transaction (its
 * statements bounded to the budget; a failure answers 503 and the device retries).
 */
async function serveFirstSet(tenantId: number, enrollmentId: string, endpoint: 'tokens' | 'declaration-items'): Promise<Answer> {
  return db.transaction(async (trx) => {
    await trx.raw("SET LOCAL statement_timeout = '2s'");
    const row = await oneIn<DeviceRow>(deviceStatement(trx, tenantId, enrollmentId));
    const refused = unserved(row);
    if (refused || !row) return refused ?? error(503, 'device_unknown');
    const deviceId = Number(row.id);
    const set = await computeSet(trx, tenantId, deviceId);
    if (!set) return error(503, 'device_unknown');
    if (endpoint === 'tokens') return ok(syncTokensBody(set.declarationsToken, set.computedAt), 'tokens', set.dropped);
    await trx('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId }).update({ fetched_token: set.declarationsToken, fetched_at: trx.fn.now() });
    return ok(itemsBody(set.items, set.declarationsToken), 'items', set.dropped);
  });
}

/** A status report: stored in the inbox of its device with its ingestion job, in one transaction. */
async function serveStatus(tenantId: number, enrollmentId: string, dataB64: string | null | undefined): Promise<Answer> {
  const report = reportOf(dataB64);
  if (!report) return error(400, 'invalid_status_report');
  return db.transaction(async (trx) => {
    await trx.raw("SET LOCAL statement_timeout = '2s'");
    const deviceId = await storeStatusReport(trx, tenantId, enrollmentId, report);
    if (deviceId !== null) {
      await requestStatusIngest(trx, tenantId, deviceId);
      return { status: 204, body: EMPTY, outcome: 'stored' } as Answer;
    }
    // Nothing stored: no record, a device out of management, or an inbox already full (the report is dropped).
    const row = await oneIn<DeviceRow>(deviceStatement(trx, tenantId, enrollmentId));
    const refused = unserved(row);
    if (refused) return refused;
    ddmMetrics.statusReport('dropped');
    return { status: 204, body: EMPTY, outcome: 'dropped' } as Answer;
  });
}

/**
 * The endpoint, in the tenant's context. The reads a device repeats (tokens, declaration-items, a declaration)
 * take one statement outside any transaction; what writes more than its own row takes a transaction.
 */
async function serve(tenantId: number, body: z.infer<typeof RelayBody>): Promise<Answer> {
  const endpoint = body.endpoint;
  const enrollmentId = body.enrollment_id;
  return asTenant(tenantId, EDGE_INTEGRATION, async () => {
    if (endpoint === 'status') return serveStatus(tenantId, enrollmentId, body.data_b64);

    if (endpoint === 'tokens') {
      const row = await one<DeviceRow & { declarations_token: string | null; computed_at: Date | null }>(tokensStatement(db, tenantId, enrollmentId));
      const refused = unserved(row);
      if (refused) return refused;
      if (!row?.declarations_token || !row.computed_at) return serveFirstSet(tenantId, enrollmentId, 'tokens');
      return ok(syncTokensBody(row.declarations_token, new Date(row.computed_at)), 'tokens');
    }

    if (endpoint === 'declaration-items') {
      const row = await one<DeviceRow & { declarations_token: string | null; items: unknown }>(itemsStatement(db, tenantId, enrollmentId));
      const refused = unserved(row);
      if (refused) return refused;
      if (!row?.declarations_token) return serveFirstSet(tenantId, enrollmentId, 'declaration-items');
      return ok(itemsBody(row.items, row.declarations_token), 'items');
    }

    // declaration/<family>/<identifier>: served when the device's set cites it, or its previous set while it is kept.
    const [, family, identifier] = endpoint.split('/') as [string, DeclarationFamily, string];
    const row = await one<DeviceRow & { current_token: string | null; previous_token: string | null }>(
      declarationTokenStatement(db, tenantId, enrollmentId, family, identifier));
    const refused = unserved(row);
    if (refused) return refused;
    const token = row?.current_token ?? row?.previous_token ?? null;
    if (!token) return error(404, 'declaration_not_found');
    const key = `${tenantId}|${family}|${identifier}|${token}`;
    const hit = cached(key);
    if (hit) return { status: 200, body: hit, outcome: 'declaration' };
    const d = await one<{ type: string; payload: unknown }>(declarationStatement(db, tenantId, family, identifier, token));
    if (!d) return error(404, 'declaration_not_found');
    const bytes = Buffer.from(declarationBody({ identifier, type: d.type, payload: d.payload, serverToken: token }), 'utf8');
    remember(key, bytes);
    return { status: 200, body: bytes, outcome: 'declaration' };
  });
}

function send(res: Response, key: Buffer, a: Answer): void {
  const ts = String(Math.floor(Date.now() / 1000));
  res.status(a.status);
  res.setHeader(HEADER_TIMESTAMP, ts);
  res.setHeader(HEADER_SIGNATURE, signRelay(key, ts, a.body));
  if (a.status === 204) {
    res.end();
    return;
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Length', String(a.body.length));
  res.end(a.body);
}

async function handle(req: Request, res: Response): Promise<void> {
  const started = process.hrtime.bigint();
  // APPLE_EDGE_MODE=off: the integration is turned off, the route does not exist.
  if (config.apple.mode !== 'on') {
    res.status(404).end();
    return;
  }
  const raw = Buffer.isBuffer(req.body) ? req.body : EMPTY;
  const list = relayKeys();
  if (!list) {
    res.status(503).end();
    return;
  }
  const ts = String(req.get(HEADER_TIMESTAMP) ?? '');
  const sig = String(req.get(HEADER_SIGNATURE) ?? '');
  const key = list.find((k) => verifyRelay([k], ts, sig, raw));
  if (!key) {
    authFailed();
    ddmMetrics.relayRequest('other', 401);
    res.status(401).end();                              // unsigned: nothing proves who asked
    return;
  }

  let kind: RelayEndpointKind = 'other';
  let tenantId: number | null = null;
  let answer: Answer;
  try {
    let json: unknown;
    try { json = JSON.parse(raw.toString('utf8')); } catch { json = null; }
    const parsed = RelayBody.safeParse(json);
    if (!parsed.success || !parsed.data.enrollment_id.startsWith(`${parsed.data.tenant_key}_`)) {
      answer = error(400, 'invalid_request');
    } else {
      const body = parsed.data;
      kind = endpointKind(body.endpoint);
      tenantId = await appleTenants.tenantOfKey(body.tenant_key, EDGE_INTEGRATION);
      if (tenantId === null) answer = error(404, 'tenant_not_found');
      // The user channel (macOS) is not served (v1): its declarations are the device channel's.
      else if (body.parent_enrollment_id || body.enrollment_id.includes(':')) answer = error(404, 'user_channel_unsupported');
      else answer = await serve(tenantId, body);
    }
  } catch (err) {
    // A statement over its 2 s, a lock not obtained, a provider that failed: the device retries.
    logger.warn({ endpoint: kind, tenantId, err: safeErr(err) }, 'DDM relay: request failed');
    answer = error(503, 'unavailable');
  }
  send(res, key, answer);
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  ddmMetrics.relayRequest(kind, answer.status, ms);
  const fields = { endpoint: kind, tenantId, status: answer.status, outcome: answer.outcome, ms: Math.round(ms) };
  if (answer.status >= 500) logger.warn(fields, 'DDM relay');
  else if (answer.status >= 400) logger.info(fields, 'DDM relay');
  else logger.debug(fields, 'DDM relay');
  if (answer.dropped?.length && tenantId !== null) await reportDropped(EDGE_INTEGRATION, tenantId, answer.dropped);
}

/**
 * The router of the relay, to mount before every other middleware of the application (I5): its own raw body
 * parser (6 MiB: a status report of 4 MiB in base64), no session. Nothing else is served under /internal.
 */
export function createDdmRelayRouter(): Router {
  const router = express.Router();
  router.post(DDM_RELAY_PATH, rawBodyParser({ type: () => true, limit: '6mb' }), (req: Request, res: Response) => {
    handle(req, res).catch((err) => {
      logger.error({ err: safeErr(err) }, 'DDM relay: unexpected failure');
      if (!res.headersSent) res.status(503).end();
    });
  });
  // The body parser's refusals (too large, aborted): no body to verify, nothing to sign.
  router.use(DDM_RELAY_PATH, (err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const status = Number((err as { status?: unknown })?.status);
    res.status(status >= 400 && status < 500 ? status : 400).end();
  });
  // Refusal by default: no other method on the relay, no other internal route.
  router.use('/internal', (_req: Request, res: Response) => { res.status(404).end(); });
  return router;
}

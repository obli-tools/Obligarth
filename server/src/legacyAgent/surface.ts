import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { Router, type NextFunction, type Request, type Response } from 'express';
import type { LegacyAgentErrorCode } from '@obligarth/shared';
import { db } from '../db';
import { asNone } from '../db/context';
import { logger } from '../utils/logger';
import { LEGACY_AGENT_ACTOR } from './actor';
import { apkDir } from './config';
import { storedFilePath } from './files';
import { handleEnroll } from './enroll';
import { handleIcons } from './icons';
import { handleInventory } from './inventory';
import { BucketLimiter, ConcurrencyLimiter, ReplayCache, WindowLimiter } from './limits';
import { handleFile, handlePackage, type PackageReply } from './packages';
import { handlePoll } from './poll';
import { handlePull, MAX_PULL_BODY } from './pull';
import { legacyAgentRemote } from './remoteBridge';
import { WaitBody } from './schemas';
import { currentServerKey, signWith, type ServerKey } from './serverKey';
import { EMPTY_SHA256, p256PublicKey, requestString, responseString, sha256Hex, verifySignature } from './signature';
import { withAgentTransaction } from './session';

// =============================================================================
// The surface of the Android bridge agents (docs: agent-pont-android §4, PB4),
// mounted at /agent/v1 by app.ts right after helmet, before cors, the JSON
// parser, the cookies, the session and the limiter of the API: its own body
// reader (the signature covers the exact bytes), no session, no cookie.
// Reached through the edge proxy (mdm.<domain>, client/edge-proxy/mdm.conf).
//   POST /agent/v1/enroll               token + proof of possession of the key
//   POST /agent/v1/poll                 state, results, events → commands
//   POST /agent/v1/inventory            full inventory → iconsWanted
//   POST /agent/v1/icons                the icons asked for (PNG or none)
//   GET  /agent/v1/packages/<sha256>    an APK of an open command of the device
//   POST /agent/v1/remote/<id>/accept   remote assistance (P0-15 §4.3): the session taken → its stream token
//   POST /agent/v1/remote/<id>/end      the end of a session from the device's side
//   POST /agent/v1/wait                 the long wait of the armed window (Obl-Seq 0, never numbered)
//   POST /agent/v1/pull/<commandId>     a chunk of the APK of an open app.pull (agent 1.2.0, pull.ts)
//   GET  /agent/v1/files/<sha256>       a file of the device's desired agent policy (agent 1.3.0, lot PONT-POL §8.3)
// Every request of /poll, /inventory, /icons, /packages and /remote is signed by
// the agent's key (OBL-AGENT-1) and numbered (seq strictly increasing, written in
// the transaction of its processing), /wait signed with seq 0 (its signatures
// remembered over the clock window); every answer, errors included, is signed by
// the instance key (OBL-SERVER-2), except 401 badSignature and unknownAgent (and
// the clockSkew of /wait). Cache-Control: no-store. The log line:
// route template, status, duration, tenant; never the address, never a body.
// The tenant is resolved by two SECURITY DEFINER lookups in the context
// 'none' (actor i:legacy-agent), then every read and write is the tenant's.
// =============================================================================

export const MAX_BODY = 256 * 1024;
export const MAX_INVENTORY_BODY = 2 * 1024 * 1024;
/** 16 icons of 32 KiB at most, in base64, with their JSON. */
export const MAX_ICONS_BODY = 512 * 1024;
/** /agent/v1/remote/<id>/accept and /end (P0-15 §4.3); /agent/v1/wait. */
export const MAX_REMOTE_BODY = 8 * 1024;
export const MAX_WAIT_BODY = 1024;
/** Beyond the limit the body is still hashed (a signed 413), up to this size; then the connection is cut. */
const HASH_CAP = 16 * 1024 * 1024;
export const CLOCK_WINDOW_SECONDS = 300;

const UUID_LOWER = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SEQ_RE = /^[1-9][0-9]{0,14}$/;
const TS_RE = /^[0-9]{1,12}$/;

export interface Exchange {
  /** Lower-case agent id, or '-' for /enroll. */
  agentId: string;
  /** Decimal sequence number, '0' for /enroll. */
  seq: string;
  ts: number;
  signature: string;
  /** SHA-256 (hex) of the exact request body. */
  reqSha: string;
  path: string;
  method: string;
}

export interface AgentIdentity { tenantId: number; deviceId: number; agentId: string; seq: number }

export interface Reply {
  status: number;
  body: Record<string, unknown>;
  headers?: Record<string, string>;
  /** false: 401 badSignature / unknownAgent, 503 without key. */
  signed?: boolean;
}

export const errorReply = (status: number, code: LegacyAgentErrorCode, error: string, extra: Record<string, unknown> = {},
  headers?: Record<string, string>): Reply => ({ status, body: { success: false, error, code, ...extra }, ...(headers ? { headers } : {}) });

/** quiet: a held long wait answered 200 is logged at debug (2 000 waits every 50 s would flood the log). */
interface SurfaceLocals { route: string; tenantId: number | null; quiet?: boolean }
const locals = (res: Response): SurfaceLocals => res.locals as unknown as SurfaceLocals;

/** Sends a reply: JSON, signed over (status, agent, seq, request hash, response hash) when it must be. */
function send(res: Response, ex: Pick<Exchange, 'agentId' | 'seq' | 'reqSha'>, reply: Reply, key: ServerKey | null): void {
  if (res.headersSent) return;
  const text = JSON.stringify(reply.body);
  res.status(reply.status);
  for (const [k, v] of Object.entries(reply.headers ?? {})) res.setHeader(k, v);
  if (reply.signed !== false && key) {
    const message = responseString({ status: reply.status, agentId: ex.agentId, seq: ex.seq, requestSha256: ex.reqSha, responseSha256: sha256Hex(text) });
    res.setHeader('Obl-Server-Key-Id', key.keyId);
    res.setHeader('Obl-Server-Signature', signWith(key, message));
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(text);
}

/** Reads the exact body, hashing every byte; keeps it up to `limit` bytes. */
function readBody(req: Request, limit: number): Promise<{ body: Buffer | null; sha: string; size: number }> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on('data', (chunk: Buffer) => {
      if (done) return;
      size += chunk.length;
      hash.update(chunk);
      if (size <= limit) chunks.push(chunk);
      if (size > HASH_CAP) {
        done = true;
        req.destroy();
        reject(Object.assign(new Error('body too large'), { tooLarge: true }));
      }
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      resolve({ body: size <= limit ? Buffer.concat(chunks) : null, sha: hash.digest('hex'), size });
    });
    req.on('error', (err) => { if (!done) { done = true; reject(err); } });
  });
}

/** The exact path as received (no query): a non-canonical path fails the signature (§4.2 (1)). */
const rawPath = (req: Request): string => String(req.originalUrl ?? '').split('?')[0];

function headerOf(req: Request, name: string): string | null {
  const v = req.headers[name.toLowerCase()];
  return typeof v === 'string' ? v : null;
}

/** The kind of a signed request: /enroll (no agent yet, seq 0), a numbered one (seq strictly increasing), or a long
 *  wait (/wait: an agent, seq 0, neither read nor consumed: P0-15 §4.3). */
type ExchangeKind = 'enroll' | 'numbered' | 'unnumbered';

/** The headers of a signed request; null when one is missing or malformed (401 badSignature). */
function exchangeOf(req: Request, reqSha: string, kind: ExchangeKind): Exchange | null {
  const agentId = headerOf(req, 'Obl-Agent-Id');
  const seq = headerOf(req, 'Obl-Seq');
  const ts = headerOf(req, 'Obl-Ts');
  const signature = headerOf(req, 'Obl-Signature');
  if (agentId === null || seq === null || ts === null || signature === null || !TS_RE.test(ts) || signature.length > 120) return null;
  if (kind === 'enroll' ? (agentId !== '-' || seq !== '0')
    : kind === 'unnumbered' ? (!UUID_LOWER.test(agentId) || seq !== '0')
      : (!UUID_LOWER.test(agentId) || !SEQ_RE.test(seq))) return null;
  return { agentId, seq, ts: Number(ts), signature, reqSha, path: rawPath(req), method: req.method };
}

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/** §4.2 (2): the clock window, answered with the server time in the signed body (RC-6). */
export function clockReply(ex: Exchange): Reply | null {
  const now = nowSeconds();
  if (Math.abs(ex.ts - now) <= CLOCK_WINDOW_SECONDS) return null;
  return errorReply(401, 'clockSkew', 'Clock out of the allowed window', { serverTime: now }, { 'Obl-Server-Time': String(now) });
}

/** Verifies the request against a public key (SPKI DER). */
export function signatureHolds(ex: Exchange, spki: Buffer): boolean {
  const key = p256PublicKey(spki);
  if (!key) return false;
  return verifySignature(key, requestString({ method: ex.method, path: ex.path, agentId: ex.agentId, seq: ex.seq, ts: ex.ts, bodySha256: ex.reqSha }), ex.signature);
}

/**
 * §4.2 (3) and (4): the agent of the request, from the lookup in the context 'none'. Unknown: 401 unknownAgent
 * (unsigned); a signature that does not hold: 401 badSignature (unsigned); revoked: 403 agentRevoked (signed),
 * told only to the holder of the key (the signature is checked first: no oracle on a revoked id).
 */
async function identify(ex: Exchange): Promise<AgentIdentity | Reply> {
  const res = await asNone(LEGACY_AGENT_ACTOR, () => db.raw('SELECT tenant_id, device_id, public_key_spki, last_seq, revoked FROM obligarth.legacy_agent_lookup(?::uuid)', [ex.agentId])) as
    { rows: Array<{ tenant_id: number; device_id: number; public_key_spki: Buffer; last_seq: string; revoked: boolean }> };
  const row = res.rows[0];
  if (!row) return { ...errorReply(401, 'unknownAgent', 'Unknown agent'), signed: false };
  if (!signatureHolds(ex, row.public_key_spki)) return { ...errorReply(401, 'badSignature', 'Bad signature'), signed: false };
  if (row.revoked) return errorReply(403, 'agentRevoked', 'This device was removed from management');
  return { tenantId: Number(row.tenant_id), deviceId: Number(row.device_id), agentId: ex.agentId, seq: Number(ex.seq) };
}

const isReply = (x: unknown): x is Reply => typeof x === 'object' && x !== null && 'status' in x && 'body' in x;

// ── Limiters (§6) ────────────────────────────────────────────────────────────
export const surfaceLimits = {
  enrollPerAddress: new WindowLimiter(60, 60_000),
  enrollPerToken: new WindowLimiter(200, 3_600_000),
  pollPerAgent: new BucketLimiter(3, 20_000),
  inventoryPerAgent: new WindowLimiter(1, 60_000),
  iconsPerAgent: new WindowLimiter(6, 60_000),
  downloadsPerTenant: new ConcurrencyLimiter(4),
  // Lot PONT-POL (C10): the files of the policies have their own limiter, so they never starve the updates of the agent.
  policyFilesPerTenant: new ConcurrencyLimiter(4),
  // P0-15 §4.3: /accept and /end of the remote sessions; the long wait (one held at a time, again at once after its
  // answer: a burst for the wakes, one more every 10 s), and the signatures of the waits already received (its seq 0 is
  // never consumed: a replay inside the clock window is refused, it would take the place of the agent's own wait).
  remotePerAgent: new WindowLimiter(20, 60_000),
  waitPerAgent: new BucketLimiter(6, 10_000),
  waitReplays: new ReplayCache(2 * CLOCK_WINDOW_SECONDS * 1000),
  // app.pull (agent 1.2.0): chunks of 1 MiB, a burst then one every second (100 MiB in a few minutes at most).
  pullPerAgent: new BucketLimiter(20, 1_000),
};

const limited = (retryAfter: number): Reply => errorReply(429, 'rateLimited', 'Too many requests', {}, { 'Retry-After': String(retryAfter) });

export function createLegacyAgentSurface(): Router {
  const router = Router({ caseSensitive: true, strict: true });

  router.use((req: Request, res: Response, next: NextFunction) => {
    const started = process.hrtime.bigint();
    locals(res).route = 'unknown';
    locals(res).tenantId = null;
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      const line = { surface: locals(res).route, status: res.statusCode, ms: Math.round(ms), tenantId: locals(res).tenantId };
      if (locals(res).quiet && res.statusCode === 200) logger.debug(line, 'agent surface request');
      else logger.info(line, 'agent surface request');
    });
    next();
  });

  /** The common frame of a POST route: media type, body, headers, clock, the instance key. */
  const post = (template: string, limit: number, kind: ExchangeKind,
    handle: (ex: Exchange, body: Buffer, req: Request, res: Response) => Promise<Reply>) =>
    async (req: Request, res: Response): Promise<void> => {
      locals(res).route = template;
      const key = await currentServerKey();
      let raw: { body: Buffer | null; sha: string; size: number };
      try {
        raw = await readBody(req, limit);
      } catch {
        if (!res.headersSent) res.status(413).end();
        return;
      }
      const enroll = kind === 'enroll';
      const draft = { agentId: enroll ? '-' : (headerOf(req, 'Obl-Agent-Id') ?? '-'), seq: enroll ? '0' : (headerOf(req, 'Obl-Seq') ?? '0'), reqSha: raw.sha };
      if (!key) { send(res, draft, { ...errorReply(503, 'unavailable', 'Service unavailable'), headers: { 'Retry-After': '300' }, signed: false }, null); return; }
      const ex = exchangeOf(req, raw.sha, kind);
      if (!ex) { send(res, draft, { ...errorReply(401, 'badSignature', 'Missing or malformed signature headers'), signed: false }, key); return; }
      if (req.headers['content-encoding'] !== undefined) { send(res, ex, errorReply(415, 'unsupportedMediaType', 'Compressed bodies are refused'), key); return; }
      const ctype = String(req.headers['content-type'] ?? '').toLowerCase().split(';')[0].trim();
      if (ctype !== 'application/json') { send(res, ex, errorReply(415, 'unsupportedMediaType', 'Content-Type: application/json'), key); return; }
      if (raw.body === null) { send(res, ex, errorReply(413, 'tooLarge', 'Body too large'), key); return; }
      try {
        const reply = await handle(ex, raw.body, req, res);
        send(res, ex, reply, key);
      } catch (err) {
        logger.error({ surface: template, code: (err as { code?: unknown })?.code, message: (err as Error)?.message?.slice(0, 200) }, 'agent surface: request failed');
        send(res, ex, { ...errorReply(503, 'unavailable', 'Service unavailable'), headers: { 'Retry-After': '60' } }, key);
      }
    };

  /**
   * The agent of a signed request (poll, inventory, packages): identity, signature, revocation, then the clock. The
   * signature is checked BEFORE the clock window: a signed clockSkew (whose serverTime sets the agent's clock, RC-6)
   * is never given for a request the agent's key did not sign (else anyone could collect signed answers for chosen
   * agent, seq and body hash, e.g. the empty body of a download, and replay them later as a stale serverTime).
   */
  const authenticated = async (ex: Exchange): Promise<AgentIdentity | Reply> => {
    const who = await identify(ex);
    if (isReply(who)) return who;
    return clockReply(ex) ?? who;
  };

  router.post('/enroll', (req, res) => {
    void post('POST /agent/v1/enroll', MAX_BODY, 'enroll', async (ex, body) => {
      const wait = surfaceLimits.enrollPerAddress.hit(`ip:${req.ip ?? 'unknown'}`);
      if (wait) return limited(wait);
      // The clock window is checked by handleEnroll after the proof of possession (no signed clockSkew otherwise).
      const out = await handleEnroll(ex, body, (publicId) => surfaceLimits.enrollPerToken.hit(publicId));
      if ('tenantId' in out && typeof out.tenantId === 'number') locals(res).tenantId = out.tenantId;
      return out.reply;
    })(req, res);
  });

  router.post('/poll', (req, res) => {
    void post('POST /agent/v1/poll', MAX_BODY, 'numbered', async (ex, body) => {
      const who = await authenticated(ex);
      if (isReply(who)) return who;
      locals(res).tenantId = who.tenantId;
      const wait = surfaceLimits.pollPerAgent.take(who.agentId);
      if (wait) return limited(wait);
      return handlePoll(who, ex, body);
    })(req, res);
  });

  router.post('/inventory', (req, res) => {
    void post('POST /agent/v1/inventory', MAX_INVENTORY_BODY, 'numbered', async (ex, body) => {
      const who = await authenticated(ex);
      if (isReply(who)) return who;
      locals(res).tenantId = who.tenantId;
      const wait = surfaceLimits.inventoryPerAgent.hit(who.agentId);
      if (wait) return limited(wait);
      return handleInventory(who, ex, body);
    })(req, res);
  });

  router.post('/icons', (req, res) => {
    void post('POST /agent/v1/icons', MAX_ICONS_BODY, 'numbered', async (ex, body) => {
      const who = await authenticated(ex);
      if (isReply(who)) return who;
      locals(res).tenantId = who.tenantId;
      const wait = surfaceLimits.iconsPerAgent.hit(who.agentId);
      if (wait) return limited(wait);
      return handleIcons(who, ex, body);
    })(req, res);
  });

  // P0-15 §4.3: the remote assistance (server/src/remote, registered by modules/remote.ts), signed and numbered as /poll.
  //   POST /agent/v1/remote/<id>/accept   the agent takes the session → the stream token (signed answer)
  //   POST /agent/v1/remote/<id>/end      the end from the device's side
  router.post(/^\/remote\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(accept|end)$/, (req, res) => {
    const sessionId = String(req.params[0]);
    const step = req.params[1] === 'accept' ? 'accept' : 'end';
    void post(`POST /agent/v1/remote/:id/${step}`, MAX_REMOTE_BODY, 'numbered', async (ex, body) => {
      const who = await authenticated(ex);
      if (isReply(who)) return who;
      locals(res).tenantId = who.tenantId;
      const remote = legacyAgentRemote();
      if (!remote) return errorReply(404, 'notFound', 'Not found');
      const wait = surfaceLimits.remotePerAgent.hit(who.agentId);
      if (wait) return limited(wait);
      return step === 'accept' ? remote.accept(who, ex, sessionId, body) : remote.end(who, ex, sessionId, body);
    })(req, res);
  });

  // POST /agent/v1/pull/<commandId> (agent 1.2.0): a chunk of the APK of an open app.pull of this device (pull.ts).
  router.post(/^\/pull\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/, (req, res) => {
    const commandId = String(req.params[0]);
    void post('POST /agent/v1/pull/:commandId', MAX_PULL_BODY, 'numbered', async (ex, body) => {
      const who = await authenticated(ex);
      if (isReply(who)) return who;
      locals(res).tenantId = who.tenantId;
      const wait = surfaceLimits.pullPerAgent.take(who.agentId);
      if (wait) return limited(wait);
      return handlePull(who, ex, commandId, body);
    })(req, res);
  });

  // POST /agent/v1/wait (P0-15 §4.3 B, D9): the long wait of an agent in its armed window, signed with Obl-Seq 0 (the
  // sequence neither read nor consumed: no race with /poll), answered { wake, nonce } within 50 s, signed. No signed
  // clockSkew here (the agent ignores it; its next /poll sets its clock).
  router.post('/wait', (req, res) => {
    void post('POST /agent/v1/wait', MAX_WAIT_BODY, 'unnumbered', async (ex, body) => {
      locals(res).quiet = true;
      const who = await identify(ex);
      if (isReply(who)) return who;
      if (clockReply(ex)) return { ...errorReply(401, 'clockSkew', 'Clock out of the allowed window'), signed: false };
      locals(res).tenantId = who.tenantId;
      const remote = legacyAgentRemote();
      if (!remote) return errorReply(404, 'notFound', 'Not found');
      if (!surfaceLimits.waitReplays.first(`${who.agentId}:${ex.signature}`)) return errorReply(409, 'seqReplay', 'This wait was already received');
      const wait = surfaceLimits.waitPerAgent.take(who.agentId);
      if (wait) return limited(wait);
      let json: unknown;
      try { json = JSON.parse(body.toString('utf8')); } catch { return errorReply(400, 'badRequest', 'Malformed JSON'); }
      const parsed = WaitBody.safeParse(json);
      if (!parsed.success) return errorReply(400, 'badRequest', `Invalid body: ${parsed.error.issues[0]?.path.join('.') ?? ''}`.slice(0, 200));
      return remote.wait(who, ex, parsed.data.nonce, (fn) => { res.on('close', fn); });
    })(req, res);
  });

  // GET /agent/v1/packages/<sha256>: signed, empty body; the file of an open command of this device (§4.7).
  // GET /agent/v1/files/<sha256> (lot PONT-POL §8.3): the same frame, a file the device's desired policy lists among its
  // blobs, from the tenant's store, behind its own limiter.
  router.get(/^\/(packages|files)\/([0-9a-f]{64})$/, (req, res) => {
    const kind = req.params[0] === 'files' ? 'files' : 'packages';
    void (async () => {
      locals(res).route = `GET /agent/v1/${kind}/:sha256`;
      const key = await currentServerKey();
      let raw: { body: Buffer | null; sha: string; size: number };
      try { raw = await readBody(req, 0); } catch { if (!res.headersSent) res.status(413).end(); return; }
      const draft = { agentId: headerOf(req, 'Obl-Agent-Id') ?? '-', seq: headerOf(req, 'Obl-Seq') ?? '0', reqSha: raw.sha };
      if (!key) { send(res, draft, { ...errorReply(503, 'unavailable', 'Service unavailable'), signed: false }, null); return; }
      const ex = exchangeOf(req, raw.sha, 'numbered');
      if (!ex) { send(res, draft, { ...errorReply(401, 'badSignature', 'Missing or malformed signature headers'), signed: false }, key); return; }
      if (raw.size > 0) { send(res, ex, errorReply(400, 'badRequest', 'A GET has no body'), key); return; }
      let release: (() => void) | null = null;
      try {
        const who = await authenticated(ex);
        if (isReply(who)) { send(res, ex, who, key); return; }
        locals(res).tenantId = who.tenantId;
        release = (kind === 'files' ? surfaceLimits.policyFilesPerTenant : surfaceLimits.downloadsPerTenant).acquire(`t:${who.tenantId}`);
        if (!release) { send(res, ex, limited(30), key); return; }
        const sha = String(req.params[1]);
        const out: PackageReply = kind === 'files' ? await handleFile(who, ex, sha) : await handlePackage(who, ex, sha);
        if ('reply' in out) { send(res, ex, out.reply, key); return; }
        const file = kind === 'files' ? storedFilePath(who.tenantId, sha) : path.join(apkDir(), `${sha}.apk`);
        const st = await stat(file).catch(() => null);
        if (!st || !st.isFile() || st.size !== out.size) {
          logger.error({ surface: kind, tenantId: who.tenantId }, 'agent surface: the file asked for is missing from the store');
          send(res, ex, errorReply(404, 'notFound', 'Not found'), key);
          return;
        }
        // The answer's hash is the file's (known, checked at its upload): the signature goes in the headers before the bytes.
        const message = responseString({ status: 200, agentId: ex.agentId, seq: ex.seq, requestSha256: ex.reqSha, responseSha256: sha });
        res.status(200);
        res.setHeader('Content-Type', kind === 'files' ? 'application/octet-stream' : 'application/vnd.android.package-archive');
        res.setHeader('Content-Length', String(st.size));
        res.setHeader('Obl-Server-Key-Id', key.keyId);
        res.setHeader('Obl-Server-Signature', signWith(key, message));
        const stream = createReadStream(file);
        const done = release;
        release = null;
        stream.on('close', () => done());
        res.on('close', () => { done(); stream.destroy(); });
        stream.pipe(res);
      } catch (err) {
        logger.error({ surface: kind, message: (err as Error)?.message?.slice(0, 200) }, 'agent surface: download failed');
        send(res, ex, { ...errorReply(503, 'unavailable', 'Service unavailable'), headers: { 'Retry-After': '60' } }, key);
      } finally {
        if (release) release();
      }
    })();
  });

  // Anything else: a plain 404 (not a route of the contract: unsigned).
  router.use((_req: Request, res: Response) => {
    if (res.headersSent) return;
    res.status(404).setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ success: false, error: 'Not found', code: 'notFound' }));
  });
  return router;
}

/** The agent of a signed request (lookup, signature, revocation): the attachment of a remote stream (remote/upgrade.ts). */
export { identify as identifyAgent, isReply as isAgentReply };
export { withAgentTransaction, EMPTY_SHA256 };

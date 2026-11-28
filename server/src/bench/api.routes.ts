import { createReadStream } from 'node:fs';
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit } from '../audit';
import { originOfRequest } from '../audit/actor';
import { AppError } from '../middleware/errorHandler';
import { ConcurrencyLimiter, WindowLimiter } from '../legacyAgent/limits';
import { clientIp } from '../utils/clientIp';
import { BENCH_SURFACE_ACTOR, stationAuditContext } from './actor';
import { AGENT_MIN_SDK, checkedApk, servedRelease, signerAdmitted } from './apk.service';
import { assertApprovedBenchStation, requireApprovedBenchStation, requireBenchStationSelf } from './guard';
import {
  PlanBody, ResultBody, StepBody, appendStep, issueToken, planProvisioning, provisioningState, recordResult, siteDevices, stationSites,
  stationTargets, stationTenants, type Origin,
} from './provisioning.service';
import { createBenchReleaseRouter } from './release.routes';
import { AppsPlanBody, completionLimiter, isProvisioningId, packageFile, planAppsCompletion, provisioningApps } from './apps.service';
import { cleanLabel, normaliseStationToken, registerStation, stationTokenHash, stationVerificationCode } from './stations.service';

// =============================================================================
// The surface of the bench station (lot BANC §3.5), mounted at /api/bench outside the tenant router (the station has no
// session): Authorization: Bench <token> on every route but the public ones. Envelope {success, data} / {success:false,
// error, code}; Cache-Control: no-store everywhere; bodies of 64 KiB at most; no redirection ever emitted; the server's
// time in the Date header.
//   GET  /version, GET /download/:file            public (release.routes.ts)
//   POST /stations/register                       public, 20 per hour and address
//   GET  /stations/me                             the station itself (pending, approved, suspended)
//   GET  /v1/targets                              approved
//   GET  /v1/tenants                              approved: the tenants of its targets (lot BANC-T §9)
//   GET  /v1/tenants/:id/sites?search=            approved: the sites of a tenant inside its targets (200 at most, by code)
//   GET  /v1/sites/:id/devices?groupId=           approved: the names used in the site, the name a target's template suggests
//   GET  /v1/agent, GET /v1/agent/apk/:sha256     approved: the version served to the bench (404 apk_unavailable)
//   POST /v1/provisionings                        approved: the plan of a device
//   GET  /v1/provisionings/:id                    approved: its state (this station's only)
//   POST /v1/provisionings/:id/token              approved + a bench session: a single-use token (120/h, 300/day)
//   POST /v1/provisionings/:id/steps              approved: one step of the journal (never a 413: the oldest leave)
//   POST /v1/provisionings/:id/result             approved: the outcome (idempotent)
// Lot BANC-A (the required apps installed by ADB, apps.service.ts):
//   GET  /v1/provisionings/:id/apps               approved: the required apps the bench installs on its enrolled device
//                                                 (409 not_enrolled, no_session; 422 device_outside_target)
//   GET  /v1/packages/:sha256?provisioning=<id>   approved: the file of one app of THAT list (404 apk_unavailable),
//                                                 2 at once and 300 per hour per station (429), never cached
//   POST /v1/provisionings/apps                   approved + a bench session: « compléter les apps » of a device already
//                                                 enrolled, found by its proven identity (30 per hour per station)
// =============================================================================

const MAX_BODY = 64 * 1024;
const registerLimiter = new WindowLimiter(20, 3_600_000);
/** Lot BANC-A: the files of the required apps, per station (the agent's APK is not counted). */
const packageDownloads = new ConcurrencyLimiter(2);
const packageWindow = new WindowLimiter(300, 3_600_000);

/** The limiters of this surface (the tests reset them). */
export const benchSurfaceLimits = { registerLimiter, packageWindow, completionLimiter, packageDownloads };

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function body<S extends z.ZodTypeAny>(schema: S, req: Request): z.infer<S> {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new AppError(400, `Invalid body: ${issue?.path.join('.') ?? ''}`.slice(0, 200), 'bad_request');
  }
  return parsed.data;
}

const originOf = (req: Request): Origin => originOfRequest(req);

const RegisterBody = z.object({
  name: z.string().max(200),
  hostname: z.string().max(255),
  token: z.string().max(256),
  stationVersion: z.string().max(32).regex(/^[0-9A-Za-z.+_-]+$/).nullable().optional(),
}).strict();

/** The answers of this surface: never cached, never a cookie. */
function surfaceHeaders(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  const length = Number(req.get('content-length') ?? 0);
  if (Number.isFinite(length) && length > MAX_BODY) { res.status(413).json({ success: false, error: 'Body too large', code: 'too_large' }); return; }
  next();
}

/** A refusal of this surface: its code (never a 401 or a 403 but the guard's). */
function surfaceErrors(err: unknown, _req: Request, res: Response, next: NextFunction): void {
  if (err instanceof AppError && err.statusCode < 500) {
    if (res.headersSent) { next(err); return; }
    res.status(err.statusCode).json({ success: false, error: err.message, code: err.code ?? 'refused', ...(err.details ? { details: err.details } : {}) });
    return;
  }
  next(err);
}

export function createBenchStationRouter(): Router {
  const router = Router();
  router.use(surfaceHeaders);
  router.use(createBenchReleaseRouter());

  router.post('/stations/register', wrap(async (req, res) => {
    const wait = registerLimiter.hit(req.ip ?? 'unknown');
    if (wait) { res.setHeader('Retry-After', String(wait)); throw new AppError(429, 'Too many registrations from this address', 'rate_limited'); }
    const b = body(RegisterBody, req);
    const token = normaliseStationToken(b.token);
    if (!token) throw new AppError(400, 'Invalid body: token', 'bad_request');
    const name = cleanLabel(b.name, 100);
    if (!name) throw new AppError(400, 'Invalid body: name', 'bad_request');
    const hostname = cleanLabel(b.hostname, 255) ?? '';
    const ip = clientIp(req) || null;
    const out = await registerStation({ name, hostname, token, version: b.stationVersion ?? null, ip });
    if (out.refused) throw new AppError(429, 'Too many stations await their approval', 'too_many_pending');
    if (out.created) {
      const ctx = await audit.fromDbActor(BENCH_SURFACE_ACTOR, MASTER_TENANT_ID, originOf(req));
      await audit.append({
        tenantId: MASTER_TENANT_ID, action: 'bench.station_registered', target: { type: 'bench_station', id: out.id! },
        details: { stationId: out.id, name, stationVersion: b.stationVersion ?? null },
      }, { ...ctx, actor: { ...ctx.actor, label: name } });
    }
    res.status(out.created ? 201 : 200).json({
      success: true, data: { stationId: out.id, status: out.status, verificationCode: stationVerificationCode(stationTokenHash(token)) },
    });
  }));

  router.get('/stations/me', requireBenchStationSelf, wrap(async (req, res) => {
    const s = req.benchStation!;
    const session = s.status === 'approved' && s.session && s.session.expiresAt.getTime() > Date.now()
      ? { technician: s.session.technician, expiresAt: s.session.expiresAt.toISOString() } : null;
    res.json({ success: true, data: { stationId: s.id, status: s.status, name: s.name, verificationCode: stationVerificationCode(s.tokenSha256), session } });
  }));

  const v1 = Router();
  v1.use(requireApprovedBenchStation);

  v1.get('/targets', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    const targets = await stationTargets(s.id);
    res.json({ success: true, data: targets });
  }));

  v1.get('/tenants', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    res.json({ success: true, data: await stationTenants(s.id) });
  }));

  v1.get('/tenants/:id/sites', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    const tenantId = Number(req.params.id);
    if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new AppError(404, 'Tenant not found', 'not_found');
    if (!(await stationTenants(s.id)).some((t) => t.id === tenantId)) throw new AppError(404, 'Tenant not found', 'not_found');
    const search = typeof req.query.search === 'string' ? req.query.search.slice(0, 100) : null;
    res.json({ success: true, data: await stationSites(s.id, tenantId, search) });
  }));

  v1.get('/sites/:id/devices', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    const raw = req.query.groupId;
    const groupId = typeof raw === 'string' && /^[1-9][0-9]{0,9}$/.test(raw) ? Number(raw) : null;
    if (raw !== undefined && groupId === null) throw new AppError(400, 'Invalid query: groupId', 'bad_request');
    res.json({ success: true, data: await siteDevices(s.id, String(req.params.id).toLowerCase(), groupId) });
  }));

  v1.get('/agent', wrap(async (req, res) => {
    assertApprovedBenchStation(req);
    const apk = await servedRelease();
    if (!apk || !signerAdmitted(apk.signerSha256)) throw new AppError(404, 'No version of the agent is served to the bench', 'apk_unavailable');
    res.json({
      success: true,
      data: {
        versionCode: apk.versionCode, versionName: apk.versionName, sha256: apk.sha256, signerSha256: apk.signerSha256, size: apk.size,
        minSdk: AGENT_MIN_SDK, deviceOwnerCapable: apk.deviceOwnerCapable,
      },
    });
  }));

  v1.get('/agent/apk/:sha256', wrap(async (req, res) => {
    assertApprovedBenchStation(req);
    const apk = await servedRelease();
    if (!apk || !signerAdmitted(apk.signerSha256) || req.params.sha256 !== apk.sha256) throw new AppError(404, 'Not found', 'apk_unavailable');
    const check = await checkedApk(apk);
    if (!check.ok) {
      if (check.reason === 'missing') throw new AppError(404, 'Not found', 'apk_unavailable');
      res.status(500).json({ success: false, error: 'The served APK does not match its SHA-256', code: 'apk_mismatch' });
      return;
    }
    res.setHeader('Content-Type', 'application/vnd.android.package-archive');
    res.setHeader('Content-Length', String(check.size));
    res.setHeader('X-Content-SHA256', apk.sha256);
    await new Promise<void>((resolve, reject) => {
      createReadStream(apk.file).on('error', reject).on('end', () => resolve()).pipe(res);
    });
  }));

  v1.post('/provisionings', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    const out = await planProvisioning(s, body(PlanBody, req), originOf(req));
    res.status(201).json({ success: true, data: out });
  }));

  // Lot BANC-A: before /provisionings/:id (a literal segment).
  v1.post('/provisionings/apps', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    const b = body(AppsPlanBody, req);
    const wait = completionLimiter.hit(s.id);
    if (wait) { res.setHeader('Retry-After', String(wait)); throw new AppError(429, 'Too many completions from this station', 'rate_limited'); }
    res.status(201).json({ success: true, data: await planAppsCompletion(s, b, originOf(req)) });
  }));

  v1.get('/provisionings/:id/apps', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    const { items } = await provisioningApps(s, String(req.params.id).toLowerCase());
    res.json({ success: true, data: items });
  }));

  v1.get('/packages/:sha256', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    const sha = String(req.params.sha256);
    const id = typeof req.query.provisioning === 'string' ? req.query.provisioning.toLowerCase() : '';
    if (!isProvisioningId(id)) throw new AppError(400, 'Invalid query: provisioning', 'bad_request');
    if (!/^[0-9a-f]{64}$/.test(sha)) throw new AppError(404, 'Not found', 'apk_unavailable');
    // The concurrency slot first: an attempt refused for concurrency (429, Retry-After 10) never uses the hourly budget.
    let release = packageDownloads.acquire(s.id);
    if (!release) { res.setHeader('Retry-After', '10'); throw new AppError(429, 'Too many downloads at once from this station', 'rate_limited'); }
    try {
      const wait = packageWindow.hit(s.id);
      if (wait) { res.setHeader('Retry-After', String(wait)); throw new AppError(429, 'Too many downloads from this station', 'rate_limited'); }
      const found = await packageFile(s, id, sha);
      if (!found) throw new AppError(404, 'Not found', 'apk_unavailable');
      const check = await checkedApk({ file: found.file, sha256: found.app.sha256 });
      if (!check.ok) {
        if (check.reason === 'missing') throw new AppError(404, 'Not found', 'apk_unavailable');
        res.status(500).json({ success: false, error: 'The package does not match its SHA-256', code: 'apk_mismatch' });
        return;
      }
      await audit.append({
        tenantId: found.tenantId, action: 'bench.app_downloaded', target: { type: 'bench_provisioning', id, device: found.deviceId },
        details: {
          provisioningId: id, stationId: s.id, packageId: found.app.packageId, packageName: found.app.packageName,
          versionCode: found.app.versionCode, sha256: found.app.sha256,
        },
      }, await stationAuditContext(s.id, s.name, found.tenantId, originOf(req)));
      res.setHeader('Content-Type', 'application/vnd.android.package-archive');
      res.setHeader('Content-Length', String(check.size));
      res.setHeader('X-Content-SHA256', found.app.sha256);
      const done = release;
      release = null;
      await new Promise<void>((resolve, reject) => {
        const stream = createReadStream(found.file);
        res.on('close', () => { done(); stream.destroy(); resolve(); });
        stream.on('error', (e) => { done(); reject(e); }).on('end', () => { done(); resolve(); }).pipe(res);
      });
    } finally {
      if (release) release();
    }
  }));

  v1.get('/provisionings/:id', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    res.json({ success: true, data: await provisioningState(s, String(req.params.id).toLowerCase()) });
  }));

  v1.post('/provisionings/:id/token', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    res.json({ success: true, data: await issueToken(s, String(req.params.id).toLowerCase(), originOf(req)) });
  }));

  v1.post('/provisionings/:id/steps', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    res.json({ success: true, data: await appendStep(s, String(req.params.id).toLowerCase(), body(StepBody, req)) });
  }));

  v1.post('/provisionings/:id/result', wrap(async (req, res) => {
    const s = assertApprovedBenchStation(req);
    res.json({ success: true, data: await recordResult(s, String(req.params.id).toLowerCase(), body(ResultBody, req), originOf(req)) });
  }));

  router.use('/v1', v1);
  router.use(surfaceErrors);
  // Anything else under /api/bench: a JSON 404 (no fall-through to the console's routes).
  router.use((_req: Request, res: Response) => { res.status(404).json({ success: false, error: 'Not found', code: 'not_found' }); });
  return router;
}

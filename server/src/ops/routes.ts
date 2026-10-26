import { Router, type NextFunction, type Request, type Response } from 'express';
import { isMasterTenant, type OpsStatusDto } from '@obligarth/shared';
import { config } from '../config';
import { AppError } from '../middleware/errorHandler';
import { vault } from '../vault';
import { jobs } from '../jobs';
import { edgeHealth } from '../apple/edge/health';
import { serverVersion } from '../apple/edge/version';
import { androidConfig } from '../android/config';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';
import { commandBacklog, eventLoopDelay } from './collectors';
import { readiness } from './ready';
import { opsListenerStatus } from '../modules/ops';

// =============================================================================
// /api/admin/ops (P0-13 T8), mounted on the tenant router (requireAuth, requireTenant): the master tenant (404
// elsewhere), a platform administrator (403 otherwise).
//   GET /status   OpsStatusDto: readiness in detail (evaluated afresh), jobs, metrics listener, vault, apple-edge,
//                 Android, backlog of the commands (counts of every tenant, never a tenant), process.
// Read only; nothing else is served. The stage, the backups, the signed profiles and the deadlines join it with
// P0-13 T9 to T11.
// =============================================================================

function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

export async function opsStatus(): Promise<OpsStatusDto> {
  const [ready, jobsHealthy, commands] = await Promise.all([
    readiness.result(true),
    jobs.health().catch(() => false),
    commandBacklog().catch((err) => {
      logger.warn({ err: safeErr(err) }, 'ops status: command backlog not read');
      return null;
    }),
  ]);
  const edge = edgeHealth();
  const listener = opsListenerStatus();
  const m = process.memoryUsage();
  const lag = eventLoopDelay(false);
  return {
    generatedAt: new Date().toISOString(),
    version: serverVersion(),
    uptimeSeconds: Math.round(process.uptime()),
    readiness: ready,
    jobs: { mode: jobs.mode(), healthy: jobsHealthy },
    metrics: listener,
    vault: { ready: vault.isReady() },
    appleEdge: {
      mode: config.apple.mode,
      up: edge.up,
      compatible: edge.compatible,
      version: edge.version,
      signingIdentityNotAfter: edge.signingIdentity?.notAfter ?? null,
    },
    android: { mode: androidConfig().mode },
    commands,
    process: { rssBytes: m.rss, heapUsedBytes: m.heapUsed, eventLoopDelayP99Seconds: lag ? lag.p99 : null },
  };
}

export function createOpsAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);
  router.get('/status', wrap(async (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({ data: await opsStatus() });
  }));
  return router;
}

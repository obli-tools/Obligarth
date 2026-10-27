import { Router, type NextFunction, type Request, type Response } from 'express';
import { isMasterTenant, MASTER_TENANT_ID, type OpsRestoreDrillDto, type OpsStatusDto } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import { asNone, asTenant } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { vault } from '../vault';
import { jobs } from '../jobs';
import { edgeHealth } from '../apple/edge/health';
import { serverVersion } from '../apple/edge/version';
import { androidConfig } from '../android/config';
import { logger } from '../utils/logger';
import { safeErr } from '../jobs/errors';
import { opsBackups } from './backups';
import { restoreDrillDeadline, type RestoreDrillItem } from './backupRules';
import { commandBacklog, eventLoopDelay } from './collectors';
import { readiness } from './ready';
import { pilotChecks, signingIdentityOf } from './stage';
import { opsListenerStatus } from '../modules/ops';

// =============================================================================
// /api/admin/ops (P0-13 T8), mounted on the tenant router (requireAuth, requireTenant): the master tenant (404
// elsewhere), a platform administrator (403 otherwise).
//   GET /status   OpsStatusDto: readiness in detail (evaluated afresh), jobs, metrics listener, vault, apple-edge
//                 (with the state of the profile signing identity), Android, backlog of the commands (counts of every
//                 tenant, never a tenant), process, backups of the instance (P0-13 T9: last reports, codes and counts
//                 only), stage of the instance and prerequisites of a pilot, restore drill (P0-13 T11: the notices as
//                 counts of tenants, ops_notice_readiness; the deadline backup_restore_drill of the instance).
// Read only; nothing else is served. The signing identity is imported by the command of apple-edge, never here (D12).
// =============================================================================

function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

const STATUS_ACTOR = { type: 'job', name: 'ops.status' } as const;

/** Tenants, and those whose notice is incomplete (counts only). */
async function noticeReadiness(): Promise<{ tenants: number; incomplete: number }> {
  const r = await asNone(STATUS_ACTOR, () => db.raw('SELECT tenants, incomplete FROM obligarth.ops_notice_readiness()')) as
    { rows: Array<{ tenants: string | number; incomplete: string | number }> };
  return { tenants: Number(r.rows[0]?.tenants ?? 0), incomplete: Number(r.rows[0]?.incomplete ?? 0) };
}

/** The open deadlines of the restore drill of the instance; an item of the instance (tenant_id NULL) is readable from
 *  the master tenant's context (policy rls_global_read). */
async function restoreDrillItems(): Promise<RestoreDrillItem[]> {
  const rows = await asTenant(MASTER_TENANT_ID, STATUS_ACTOR, () => db('integration_deadline_items').whereNull('tenant_id')
    .where({ kind: 'backup_restore_drill' }).whereNull('retired_at').whereNotNull('not_after').orderBy('not_after', 'asc')
    .select('not_after', 'source', 'updated_at')) as Array<{ not_after: Date | string; source: string; updated_at: Date | string }>;
  return rows.map((r) => ({ notAfter: new Date(r.not_after), source: r.source, updatedAt: new Date(r.updated_at) }));
}

export async function opsStatus(): Promise<OpsStatusDto> {
  const [ready, jobsHealthy, commands, backups, notice, drillItems] = await Promise.all([
    readiness.result(true),
    jobs.health().catch(() => false),
    commandBacklog().catch((err) => {
      logger.warn({ err: safeErr(err) }, 'ops status: command backlog not read');
      return null;
    }),
    opsBackups().catch((err) => {
      logger.warn({ err: safeErr(err) }, 'ops status: backup reports not read');
      return null;
    }),
    noticeReadiness().catch((err) => {
      logger.warn({ err: safeErr(err) }, 'ops status: notices of the tenants not read');
      return null;
    }),
    restoreDrillItems().catch((err) => {
      logger.warn({ err: safeErr(err) }, 'ops status: deadline of the restore drill not read');
      return null;
    }),
  ]);
  const edge = edgeHealth();
  const now = new Date();
  const signing = signingIdentityOf(edge, now);
  const backupsCheck = ready.checks.find((c) => c.name === 'backups');
  const lastDrill = backups?.kinds.find((k) => k.kind === 'drill')?.lastSuccessAt ?? null;
  const drill = drillItems ? restoreDrillDeadline(drillItems, lastDrill) : null;
  const restoreDrill: OpsRestoreDrillDto | null = drill
    ? { dueAt: drill.dueAt ? drill.dueAt.toISOString() : null, source: drill.source, lastSuccessAt: lastDrill }
    : null;
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
      signingIdentityState: config.apple.mode === 'on' ? signing.state : 'unknown',
      requireSignedProfiles: config.apple.requireSignedProfiles,
    },
    android: { mode: androidConfig().mode },
    commands,
    process: { rssBytes: m.rss, heapUsedBytes: m.heapUsed, eventLoopDelayP99Seconds: lag ? lag.p99 : null },
    backups,
    stage: {
      stage: config.stage,
      backupsExpected: config.ops.backups.expected,
      checks: pilotChecks({
        stage: config.stage,
        appleMode: config.apple.mode,
        requireSignedProfiles: config.apple.requireSignedProfiles,
        allowDefaultNotice: config.apple.allowDefaultNotice,
        backupsExpected: config.ops.backups.expected,
        backupsReadiness: backupsCheck ? { ok: backupsCheck.ok, code: backupsCheck.code } : null,
        signing,
        notice,
        drill: drill ? { dueAt: drill.dueAt } : null,
        now,
      }),
    },
    restoreDrill,
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

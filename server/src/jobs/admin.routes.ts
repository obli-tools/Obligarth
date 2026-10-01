import { Router, type NextFunction, type Request, type Response } from 'express';
import { isMasterTenant } from '@obligarth/shared';
import { AppError } from '../middleware/errorHandler';
import { applyRestriction } from '../services/restriction.service';
import { audit as journal, registerAuditActions } from '../audit';
import { DEAD_LETTER_QUEUE } from './registry';
import { isJobListState, isQueueName, UUID_RE, type JobsAdmin } from './admin';

// =============================================================================
// /api/admin/jobs: administration of the background jobs (docs: file-durable
// §8.5), mounted on the tenant router (requireAuth, requireTenant). Every
// route: the master tenant (404 elsewhere), a platform administrator (403
// otherwise). The routes that change something pass the restrictable action
// 'jobs.manage' (no default level: a fresh instance without second factor is
// not locked out; at 'restricted', a second administrator approves the
// 'jobs_manage' request, core.jobs.ts) and are audited in the master tenant.
// /dead-letters… routes are declared before /:queue/….
// =============================================================================

const LIMIT_MAX = 200;

// The audit actions of the jobs administration (audit-durci §3.4, FD-RC5):
// critical, written as an intent before the operation (P2, threat S11).
registerAuditActions([
  { name: 'jobs.run_triggered', criticality: 'critical', label: 'Background job run by hand' },
  { name: 'jobs.cancelled', criticality: 'critical', label: 'Background job cancelled' },
  { name: 'jobs.redriven', criticality: 'critical', label: 'Dead letters redriven' },
  { name: 'jobs.dead_letter_discarded', criticality: 'critical', label: 'Dead letter discarded' },
  { name: 'outbox.dead_letter_viewed', criticality: 'critical', label: 'Outbox dead letter viewed' },
  { name: 'outbox.dead_letter_redriven', criticality: 'critical', label: 'Outbox dead letter redriven' },
  { name: 'outbox.dead_letter_discarded', criticality: 'critical', label: 'Outbox dead letter discarded' },
]);

/** How an operation's audit entry is written: P2, the intent before `fn`,
 *  the result after (with its details). */
export type JobsAuditRunner = <T>(
  action: string,
  extras: { resourceType: string; resourcePath: string; details: Record<string, unknown> },
  fn: () => Promise<T>,
  resultDetails?: (r: T) => Record<string, unknown>,
) => Promise<T>;

function limitOf(req: Request): number {
  const raw = req.query.limit;
  if (raw === undefined) return 50;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > LIMIT_MAX) throw new AppError(400, `limit must be an integer from 1 to ${LIMIT_MAX}`, 'invalidLimit');
  return n;
}

/** Master tenant (404 elsewhere: the route does not exist there), then a
 *  platform administrator (403). */
function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

/** The approval payload of a change (action 'jobs_manage'), and what the
 *  reviewers read. */
export type JobsManageOp =
  | { op: 'run'; queue: string }
  | { op: 'cancel'; queue: string; jobId: string }
  | { op: 'redrive'; ids?: string[]; source?: string }
  | { op: 'discard'; id: string };

export function describeJobsOp(o: JobsManageOp): string {
  switch (o.op) {
    case 'run': return `Run the background job ${o.queue} now`;
    case 'cancel': return `Cancel the queued job ${o.jobId} of ${o.queue}`;
    case 'redrive': return o.ids ? `Redrive ${o.ids.length} dead letter(s)${o.source ? ` of ${o.source}` : ''}` : `Redrive the dead letters of ${o.source}`;
    case 'discard': return `Discard the dead letter ${o.id}`;
    default: return 'Background jobs';
  }
}

/** Runs an operation with its audit entry (master tenant): the intent is
 *  written before the operation (critical, P2), the result after. */
export async function performJobsOp(admin: JobsAdmin, o: JobsManageOp, audit: JobsAuditRunner): Promise<{ status: number; body: unknown }> {
  switch (o.op) {
    case 'run': {
      const r = await audit('jobs.run_triggered', { resourceType: 'job_queue', resourcePath: o.queue, details: { queue: o.queue } },
        () => admin.runNow(o.queue), (x) => ({ jobId: x.jobId }));
      return { status: 202, body: { data: r } };
    }
    case 'cancel': {
      await audit('jobs.cancelled', { resourceType: 'job', resourcePath: o.jobId, details: { queue: o.queue, jobId: o.jobId } },
        () => admin.cancelJob(o.queue, o.jobId));
      return { status: 200, body: { data: { cancelled: true } } };
    }
    case 'redrive': {
      const r = await audit('jobs.redriven', {
        resourceType: 'job_queue', resourcePath: DEAD_LETTER_QUEUE,
        details: { ...(o.ids ? { ids: o.ids.length } : {}), ...(o.source ? { source: o.source } : {}) },
      }, () => admin.redrive({ ids: o.ids, source: o.source }), (x) => ({ moved: x.moved, sources: x.sources }));
      return { status: 200, body: { data: { moved: r.moved } } };
    }
    case 'discard': {
      const r = await audit('jobs.dead_letter_discarded', { resourceType: 'job', resourcePath: o.id, details: { id: o.id } },
        () => admin.discard(o.id), (x) => ({ source: x.sourceName, sourceId: x.sourceId }));
      void r;
      return { status: 200, body: { data: { deleted: true } } };
    }
    default:
      throw new AppError(400, 'Unknown operation');
  }
}

export function createJobsAdminRouter(admin: JobsAdmin): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  /** A change: restriction 'jobs.manage', then the operation and its audit. */
  const change = (build: (req: Request) => JobsManageOp) => wrap(async (req, res) => {
    const o = build(req);
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'jobs.manage',
      approvalRequestType: 'batch_command',
      approvalDescription: describeJobsOp(o),
      approvalPayload: { action: 'jobs_manage', ...o },
    });
    if (!approved) return; // answered by applyRestriction (second factor, or approval filed)
    const out = await performJobsOp(admin, o, async (action, extras, fn, resultDetails) => journal.withIntent(
      { tenantId: Number(req.tenantId), action, target: { type: extras.resourceType, id: extras.resourcePath }, details: extras.details },
      await journal.fromRequest(req, Number(req.tenantId)), fn, { resultDetails },
    ));
    res.status(out.status).json(out.body);
  });

  router.get('/', wrap(async (_req, res) => {
    res.json({ data: await admin.overview() });
  }));

  router.get('/dead-letters', wrap(async (req, res) => {
    const source = typeof req.query.source === 'string' && req.query.source !== '' ? req.query.source : null;
    res.json({ data: await admin.listDeadLetters(source, limitOf(req)) });
  }));

  // The shapes are checked before the restriction: an approval is never filed
  // for a request that could not run.
  router.post('/dead-letters/redrive', change((req) => {
    const body = (req.body ?? {}) as { ids?: unknown; source?: unknown };
    if (body.ids === undefined && body.source === undefined) throw new AppError(400, 'Give the ids or the source queue to redrive', 'redriveTargetMissing');
    if (body.ids !== undefined && (!Array.isArray(body.ids) || body.ids.length === 0 || body.ids.length > 100
      || !body.ids.every((x) => typeof x === 'string' && UUID_RE.test(x)))) {
      throw new AppError(400, 'ids: 1 to 100 job ids', 'invalidIds');
    }
    if (body.source !== undefined && (!isQueueName(body.source) || body.source === DEAD_LETTER_QUEUE)) {
      throw new AppError(400, 'Invalid source queue', 'invalidQueue');
    }
    return {
      op: 'redrive',
      ...(body.ids !== undefined ? { ids: body.ids as string[] } : {}),
      ...(body.source !== undefined ? { source: body.source as string } : {}),
    };
  }));

  router.delete('/dead-letters/:id', change((req) => {
    const id = String(req.params.id);
    if (!UUID_RE.test(id)) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
    return { op: 'discard', id };
  }));

  router.get('/:queue/jobs', wrap(async (req, res) => {
    const state = req.query.state;
    if (state !== undefined && !isJobListState(state)) throw new AppError(400, 'state: queued, active, failed, completed or cancelled', 'invalidState');
    res.json({ data: await admin.listJobs(String(req.params.queue), (state as Parameters<JobsAdmin['listJobs']>[1]) ?? null, limitOf(req)) });
  }));

  router.post('/:queue/run', change((req) => {
    const queue = String(req.params.queue);
    if (!isQueueName(queue)) throw new AppError(404, 'Queue not found', 'queueNotFound');
    return { op: 'run', queue };
  }));

  router.post('/:queue/jobs/:id/cancel', change((req) => {
    const queue = String(req.params.queue);
    const jobId = String(req.params.id);
    if (!isQueueName(queue) || queue === DEAD_LETTER_QUEUE || !UUID_RE.test(jobId)) throw new AppError(404, 'Job not found', 'jobNotFound');
    return { op: 'cancel', queue, jobId };
  }));

  return router;
}

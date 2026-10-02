import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { isMasterTenant } from '@obligarth/shared';
import { db } from '../../db';
import { asPlatform } from '../../db/context';
import { globalViewGrant } from '../../db/platformAccess';
import { AppError } from '../../middleware/errorHandler';
import { applyRestriction } from '../../services/restriction.service';
import {
  refuse, registerApprovalExecutor, requirePlatformAdmin, withAuditAs,
} from '../../services/approval.service';
import { audit as journal } from '../../audit';
import { outboxOverview, redriveDeadLetter } from './deadLetters';
import { outboxHandlers } from './handlers';

// =============================================================================
// /api/admin/outbox: administration of the apple-edge outbox consumer (docs:
// file-durable §8.5), mounted on the tenant router (requireAuth,
// requireTenant). Every route: the master tenant (404 elsewhere), a platform
// administrator (403 otherwise).
//   GET    /                            consumer state, lag, dead letters per reason, handlers
//   GET    /dead-letters                list WITHOUT payload (context 'platform', the
//                                       administrator's journaled grant)
//   GET    /dead-letters/:eventId       detail WITH payload (device data): audited
//                                       first (outbox.dead_letter_viewed, critical)
//   POST   /dead-letters/:eventId/redrive    applied again (outbox.dead_letter_redriven)
//   DELETE /dead-letters/:eventId       discarded (outbox.dead_letter_discarded:
//                                       type, reason, event id, never the payload)
// The two changes pass the restrictable action 'jobs.manage' (no default
// level; at 'restricted', a second administrator approves the 'outbox_manage'
// request, executed as the requester); their audit entries are written as an
// intent before the operation (P2). The audit actions are declared with the
// jobs administration's (jobs/admin.routes.ts).
// =============================================================================

const EVENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REASONS = ['unknown_type', 'unsupported_schema_version', 'invalid_payload', 'tenant_mismatch', 'unknown_tenant',
  'handler_error', 'permanent_error'];
const LIMIT_MAX = 200;
const iso = (d: unknown): string | null => (d instanceof Date ? d.toISOString() : d ? new Date(String(d)).toISOString() : null);

export type OutboxManageOp = { op: 'redrive'; eventId: string } | { op: 'discard'; eventId: string };

const OutboxOpPayload = z.discriminatedUnion('op', [
  z.object({ op: z.literal('redrive'), eventId: z.string().regex(EVENT_ID_RE) }),
  z.object({ op: z.literal('discard'), eventId: z.string().regex(EVENT_ID_RE) }),
]);

export function describeOutboxOp(o: OutboxManageOp): string {
  return o.op === 'redrive' ? `Apply the outbox dead letter ${o.eventId} again` : `Discard the outbox dead letter ${o.eventId}`;
}

/** How an operation's audit entry is written (the route's request, or the approval's requester). */
export type OutboxAuditRunner = <T>(
  action: string,
  extras: { resourceType: string; resourcePath: string; details: Record<string, unknown> },
  fn: () => Promise<T>,
  resultDetails?: (r: T) => Record<string, unknown>,
) => Promise<T>;

/** Runs an operation with its audit entry: the intent before, the result after. In the master tenant's
 *  context, as a platform administrator (the discard function checks both). */
export async function performOutboxOp(o: OutboxManageOp, userId: number, run: OutboxAuditRunner): Promise<{ status: number; body: unknown }> {
  const target = { resourceType: 'outbox_event', resourcePath: o.eventId };
  if (o.op === 'redrive') {
    const r = await run('outbox.dead_letter_redriven', { ...target, details: { eventId: o.eventId } },
      async () => {
        const res = await redriveDeadLetter(o.eventId, userId);
        if (!res.found) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
        return res;
      },
      (x) => (x.found ? { outcome: x.outcome, ...(x.code ? { code: x.code } : {}), type: x.type, reason: x.reason } : {}));
    if (!r.found) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
    return { status: 200, body: { data: { outcome: r.outcome, ...(r.code ? { code: r.code } : {}) } } };
  }
  const r = await run('outbox.dead_letter_discarded', { ...target, details: { eventId: o.eventId } },
    async () => {
      const res = await db.raw('SELECT event_type, reason, tenant_id FROM obligarth.outbox_dead_letter_discard(?)', [o.eventId]) as
        { rows: Array<{ event_type: string; reason: string; tenant_id: number | null }> };
      if (!res.rows[0]) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
      return res.rows[0];
    },
    (x) => ({ type: x.event_type, reason: x.reason, tenantId: x.tenant_id }));
  void r;
  return { status: 200, body: { data: { deleted: true } } };
}

function limitOf(req: Request): number {
  const raw = req.query.limit;
  if (raw === undefined) return 50;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > LIMIT_MAX) throw new AppError(400, `limit must be an integer from 1 to ${LIMIT_MAX}`, 'invalidLimit');
  return n;
}

function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

/** A function declaration (hoisted): the router may be built while this module is still loading, through
 *  the import cycle approval.service → socket → app → routes. */
function wrap(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };
}

/** Reads of the dead letters of every tenant: the context 'platform' under the administrator's grant. */
async function platformRead<T>(req: Request, fn: () => Promise<T>): Promise<T> {
  const grant = await globalViewGrant(req, 'admin.outbox.dead_letters');
  return asPlatform(grant, fn);
}

let executorRegistered = false;

/** The approval executor of an 'outbox_manage' request ('restricted' level of jobs.manage): run as the
 *  requester, still an active platform administrator, from the master tenant. */
export function registerOutboxApprovals(): void {
  if (executorRegistered) return;
  executorRegistered = true;
  registerApprovalExecutor('outbox_manage', async ({ tenantId, requesterId, payload }) => {
    await requirePlatformAdmin(requesterId);
    if (!isMasterTenant(tenantId)) refuse('The outbox is administered from the master tenant only');
    const parsed = OutboxOpPayload.safeParse({ op: (payload as { op?: unknown }).op, eventId: (payload as { eventId?: unknown }).eventId });
    if (!parsed.success) refuse('Invalid outbox request');
    try {
      await performOutboxOp(parsed.data as OutboxManageOp, requesterId,
        (action, extras, fn, resultDetails) => withAuditAs(tenantId, requesterId, action, extras, fn, resultDetails));
    } catch (err) {
      if (err instanceof AppError) refuse(err.message);
      throw err;
    }
  });
}

export function createOutboxAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/', wrap(async (_req, res) => {
    res.json({
      data: {
        ...(await outboxOverview()),
        handlers: outboxHandlers().map((h) => ({ type: h.type, scope: h.scope, module: h.module })),
      },
    });
  }));

  router.get('/dead-letters', wrap(async (req, res) => {
    const reason = typeof req.query.reason === 'string' && req.query.reason !== '' ? req.query.reason : null;
    const type = typeof req.query.type === 'string' && req.query.type !== '' ? req.query.type : null;
    const tenantRaw = typeof req.query.tenantId === 'string' && req.query.tenantId !== '' ? Number(req.query.tenantId) : null;
    if (reason !== null && !REASONS.includes(reason)) throw new AppError(400, 'Unknown reason', 'invalidReason');
    if (type !== null && !/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(type)) throw new AppError(400, 'Invalid event type', 'invalidType');
    if (tenantRaw !== null && (!Number.isSafeInteger(tenantRaw) || tenantRaw <= 0)) throw new AppError(400, 'Invalid tenant', 'invalidTenant');
    const limit = limitOf(req);
    const rows = await platformRead(req, async () => {
      let q = db('apple_edge_dead_letters')
        .select('event_id', 'seq', 'schema_version', 'scope', 'tenant_id', 'type', 'occurred_at', 'reason', 'attempts',
          'last_error_code', 'dead_lettered_at', 'redriven_at', 'redrive_outcome', 'redriven_by')
        .orderBy('dead_lettered_at', 'desc')
        .limit(limit);
      if (reason !== null) q = q.where('reason', reason);
      if (type !== null) q = q.where('type', type);
      if (tenantRaw !== null) q = q.where('tenant_id', tenantRaw);
      return q as Promise<Array<Record<string, unknown>>>;
    });
    res.json({
      data: rows.map((r) => ({
        eventId: r.event_id, seq: String(r.seq), schemaVersion: Number(r.schema_version), scope: r.scope, tenantId: r.tenant_id ?? null,
        type: r.type, occurredAt: iso(r.occurred_at), reason: r.reason, attempts: Number(r.attempts), lastErrorCode: r.last_error_code,
        deadLetteredAt: iso(r.dead_lettered_at), redrivenAt: iso(r.redriven_at), redriveOutcome: r.redrive_outcome ?? null,
        redrivenBy: r.redriven_by ?? null,
      })),
    });
  }));

  router.get('/dead-letters/:eventId', wrap(async (req, res) => {
    const eventId = String(req.params.eventId).toLowerCase();
    if (!EVENT_ID_RE.test(eventId)) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
    const tenantId = Number(req.tenantId);
    // The payload carries device data: the consultation is journaled before the read (REQ-15).
    const row = await journal.withIntent(
      { tenantId, action: 'outbox.dead_letter_viewed', target: { type: 'outbox_event', id: eventId }, details: { eventId } },
      await journal.fromRequest(req, tenantId),
      () => platformRead(req, () => db('apple_edge_dead_letters').where({ event_id: eventId }).first() as Promise<Record<string, unknown> | undefined>),
      { resultDetails: (r) => (r ? { type: r.type, reason: r.reason, tenantId: r.tenant_id ?? null } : { found: false }) },
    );
    if (!row) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
    res.json({
      data: {
        eventId: row.event_id, seq: String(row.seq), schemaVersion: Number(row.schema_version), scope: row.scope,
        tenantKey: row.tenant_key ?? null, tenantId: row.tenant_id ?? null, type: row.type, enrollmentId: row.enrollment_id ?? null,
        commandUuid: row.command_uuid ?? null, requestId: row.request_id ?? null, occurredAt: iso(row.occurred_at),
        payload: row.payload, reason: row.reason, attempts: Number(row.attempts), lastErrorCode: row.last_error_code,
        deadLetteredAt: iso(row.dead_lettered_at), redrivenAt: iso(row.redriven_at), redriveOutcome: row.redrive_outcome ?? null,
        redrivenBy: row.redriven_by ?? null,
      },
    });
  }));

  /** A change: restriction 'jobs.manage', then the operation and its audit entries. */
  const change = (build: (req: Request) => OutboxManageOp) => wrap(async (req, res) => {
    const o = build(req);
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'jobs.manage',
      approvalRequestType: 'batch_command',
      approvalDescription: describeOutboxOp(o),
      approvalPayload: { action: 'outbox_manage', ...o },
    });
    if (!approved) return;
    const userId = Number(req.session?.userId);
    const out = await performOutboxOp(o, userId, async (action, extras, fn, resultDetails) => journal.withIntent(
      { tenantId: Number(req.tenantId), action, target: { type: extras.resourceType, id: extras.resourcePath }, details: extras.details },
      await journal.fromRequest(req, Number(req.tenantId)), fn, { resultDetails },
    ));
    res.status(out.status).json(out.body);
  });

  const eventIdOf = (req: Request): string => {
    const id = String(req.params.eventId).toLowerCase();
    if (!EVENT_ID_RE.test(id)) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
    return id;
  };

  router.post('/dead-letters/:eventId/redrive', change((req) => ({ op: 'redrive', eventId: eventIdOf(req) })));
  router.delete('/dead-letters/:eventId', change((req) => ({ op: 'discard', eventId: eventIdOf(req) })));

  return router;
}

// /api/admin/android/inbox (master tenant, platform administrators; android-amapi §7.2, lot AN-C2): the dead letters of
// the Android inbox of every tenant, administered like the outbox's (file-durable §8.5):
//   GET    /dead            list WITHOUT payload (context 'platform', the administrator's journaled grant)
//   GET    /dead/:id        detail WITH payload (device data): audited first (android.inbox_dead_letter_viewed, critical)
//   POST   /dead/:id/redrive    back to pending (attempts 0, due now) and the tenant's drain sent (audited)
//   DELETE /dead/:id        discarded (audited: type, tenant, never the payload)
// The two changes pass the restrictable action 'jobs.manage' (no default level; at 'restricted', a second administrator
// approves the 'android_inbox_manage' request, executed as the requester). Mounted by routes/index.ts.
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { isMasterTenant, type AndroidDeadLetterDetail, type AndroidDeadLetterView } from '@obligarth/shared';
import { audit as journal } from '../../audit';
import { db } from '../../db';
import { asPlatform, asTenant, userActor } from '../../db/context';
import { globalViewGrant } from '../../db/platformAccess';
import { AppError } from '../../middleware/errorHandler';
import { applyRestriction } from '../../services/restriction.service';
import { refuse, registerApprovalExecutor, requirePlatformAdmin, withAuditAs } from '../../services/approval.service';
import { registerAndroidAuditActions } from '../audit';
import { sendDrainInTx } from '../link/pull';
import { masterPlatformAdmin } from './admin.routes';

const ID_RE = /^[1-9][0-9]{0,18}$/;
const LIMIT_MAX = 200;
const iso = (d: unknown): string => (d instanceof Date ? d.toISOString() : new Date(String(d)).toISOString());

export type InboxManageOp = { op: 'redrive'; id: string; tenantId: number } | { op: 'discard'; id: string; tenantId: number };

const InboxOpPayload = z.discriminatedUnion('op', [
  z.object({ op: z.literal('redrive'), id: z.string().regex(ID_RE), tenantId: z.number().int().positive() }),
  z.object({ op: z.literal('discard'), id: z.string().regex(ID_RE), tenantId: z.number().int().positive() }),
]);

type AuditRunner = <T>(action: string, extras: { resourceType: string; resourcePath: string; details: Record<string, unknown> },
  fn: () => Promise<T>, resultDetails?: (r: T) => Record<string, unknown>) => Promise<T>;

const describe = (o: InboxManageOp): string =>
  (o.op === 'redrive' ? `Apply the Android notification ${o.id} of tenant ${o.tenantId} again` : `Discard the Android notification ${o.id} of tenant ${o.tenantId}`);

const viewOf = (r: Record<string, unknown>): AndroidDeadLetterView => ({
  id: String(r.id), tenantId: Number(r.tenant_id), eventType: String(r.event_type), messageId: String(r.message_id),
  resourceName: r.resource_name ? String(r.resource_name) : null, publishedAt: iso(r.published_at), occurredAt: iso(r.occurred_at),
  attempts: Number(r.attempts ?? 0), lastError: r.last_error ? String(r.last_error) : null, receivedAt: iso(r.received_at),
  payloadBytes: Number(r.payload_bytes ?? 0),
});
const LIST_COLUMNS = ['id', 'tenant_id', 'event_type', 'message_id', 'resource_name', 'published_at', 'occurred_at', 'attempts', 'last_error',
  'received_at', 'payload_bytes'];

/** Runs an operation in the tenant of the dead letter (as the user), with its audit entry: the intent before, the
 *  result after. 404 when the row is not (or no longer) a dead letter of that tenant. */
export async function performInboxOp(o: InboxManageOp, userId: number, run: AuditRunner): Promise<{ status: number; body: unknown }> {
  const target = { resourceType: 'android_inbox_event', resourcePath: o.id };
  const action = o.op === 'redrive' ? 'android.inbox_dead_letter_redriven' : 'android.inbox_dead_letter_discarded';
  const r = await run(action, { ...target, details: { inboxId: o.id, tenantId: o.tenantId } }, () => asTenant(o.tenantId, userActor(userId),
    () => db.transaction(async (trx) => {
      const row = await trx('android_inbox').where({ tenant_id: o.tenantId, id: o.id, state: 'dead' }).forUpdate().first('event_type') as
        { event_type: string } | undefined;
      if (!row) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
      if (o.op === 'redrive') {
        await trx('android_inbox').where({ tenant_id: o.tenantId, id: o.id })
          .update({ state: 'pending', attempts: 0, next_attempt_at: trx.fn.now(), last_error: null });
        await sendDrainInTx(trx, o.tenantId);
      } else {
        await trx('android_inbox').where({ tenant_id: o.tenantId, id: o.id }).delete();
      }
      return { type: row.event_type };
    })), (x) => ({ type: x.type }));
  void r;
  return { status: 200, body: { success: true, data: o.op === 'redrive' ? { redriven: true } : { deleted: true } } };
}

let executorRegistered = false;

/** The approval executor of an 'android_inbox_manage' request: as the requester, still a platform administrator, from
 *  the master tenant. */
export function registerAndroidInboxApprovals(): void {
  if (executorRegistered) return;
  executorRegistered = true;
  registerApprovalExecutor('android_inbox_manage', async ({ tenantId, requesterId, payload }) => {
    await requirePlatformAdmin(requesterId);
    if (!isMasterTenant(tenantId)) refuse('The Android inbox is administered from the master tenant only');
    const p = payload as { op?: unknown; id?: unknown; tenantId?: unknown };
    const parsed = InboxOpPayload.safeParse({ op: p.op, id: p.id, tenantId: p.tenantId });
    if (!parsed.success) refuse('Invalid Android inbox request');
    try {
      await performInboxOp(parsed.data as InboxManageOp, requesterId,
        (action, extras, fn, resultDetails) => withAuditAs(tenantId, requesterId, action, extras, fn, resultDetails));
    } catch (err) {
      if (err instanceof AppError) refuse(err.message);
      throw err;
    }
  });
}

function wrap(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };
}

/** Reads of the dead letters of every tenant: the context 'platform' under the administrator's grant. */
async function platformRead<T>(req: Request, fn: () => Promise<T>): Promise<T> {
  const grant = await globalViewGrant(req, 'admin.android.inbox_dead_letters');
  return asPlatform(grant, fn);
}

function limitOf(req: Request): number {
  const raw = req.query.limit;
  if (raw === undefined) return 50;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > LIMIT_MAX) throw new AppError(400, `limit must be an integer from 1 to ${LIMIT_MAX}`, 'invalidLimit');
  return n;
}

const idOf = (req: Request): string => {
  const id = String(req.params.id);
  if (!ID_RE.test(id)) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
  return id;
};

export function createAndroidInboxAdminRouter(): Router {
  // The audit actions of these routes (android.inbox_dead_letter_*), declared with the router as the jobs administration
  // does (idempotent; the Android module declares them too).
  registerAndroidAuditActions();
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/dead', wrap(async (req, res) => {
    const tenantRaw = typeof req.query.tenantId === 'string' && req.query.tenantId !== '' ? Number(req.query.tenantId) : null;
    if (tenantRaw !== null && (!Number.isSafeInteger(tenantRaw) || tenantRaw <= 0)) throw new AppError(400, 'Invalid tenant', 'invalidTenant');
    const limit = limitOf(req);
    const rows = await platformRead(req, async () => {
      let q = db('android_inbox').where({ state: 'dead' }).orderBy('received_at', 'desc').limit(limit).select(LIST_COLUMNS);
      if (tenantRaw !== null) q = q.where({ tenant_id: tenantRaw });
      return q as Promise<Array<Record<string, unknown>>>;
    });
    res.json({ success: true, data: rows.map(viewOf) });
  }));

  router.get('/dead/:id', wrap(async (req, res) => {
    const id = idOf(req);
    const tenantId = Number(req.tenantId);
    // The payload carries device data: the consultation is journaled before the read (REQ-15).
    const row = await journal.withIntent(
      { tenantId, action: 'android.inbox_dead_letter_viewed', target: { type: 'android_inbox_event', id }, details: { inboxId: id } },
      await journal.fromRequest(req, tenantId),
      () => platformRead(req, () => db('android_inbox').where({ id, state: 'dead' }).first([...LIST_COLUMNS, 'payload']) as Promise<Record<string, unknown> | undefined>),
      { resultDetails: (r) => (r ? { type: r.event_type, tenantId: Number(r.tenant_id) } : { found: false }) },
    );
    if (!row) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
    const data: AndroidDeadLetterDetail = { ...viewOf(row), payload: typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload ?? null };
    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, data });
  }));

  /** A change: the tenant of the row (platform read), the restriction 'jobs.manage', then the operation. */
  const change = (op: InboxManageOp['op']) => wrap(async (req, res) => {
    const id = idOf(req);
    const found = await platformRead(req, () => db('android_inbox').where({ id, state: 'dead' }).first('tenant_id') as Promise<{ tenant_id: number } | undefined>);
    if (!found) throw new AppError(404, 'Dead letter not found', 'deadLetterNotFound');
    const o: InboxManageOp = { op, id, tenantId: Number(found.tenant_id) };
    const approved = await applyRestriction(res, {
      req, actionKey: 'jobs.manage', approvalRequestType: 'batch_command', approvalDescription: describe(o),
      approvalPayload: { action: 'android_inbox_manage', ...o },
    });
    if (!approved) return;
    const out = await performInboxOp(o, Number(req.session.userId), async (action, extras, fn, resultDetails) => journal.withIntent(
      { tenantId: Number(req.tenantId), action, target: { type: extras.resourceType, id: extras.resourcePath }, details: extras.details },
      await journal.fromRequest(req, Number(req.tenantId)), fn, { resultDetails },
    ));
    res.status(out.status).json(out.body);
  });

  router.post('/dead/:id/redrive', change('redrive'));
  router.delete('/dead/:id', change('discard'));
  return router;
}

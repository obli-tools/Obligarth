import { Router, type NextFunction, type Request, type Response } from 'express';
import { MASTER_TENANT_ID, type AuditRetentionRow } from '@obligarth/shared';
import { z } from 'zod';
import { db } from '../db';
import { asTenant } from '../db/context';
import { globalViewRead } from '../middleware/dbContext';
import { AppError } from '../middleware/errorHandler';
import { hasGlobalView } from '../services/deviceScope.service';
import { applyRestriction } from '../services/restriction.service';
import { config } from '../config';
import { auditJobHandles, wakeAuditJob } from './jobs';
import { fromRequest } from './actor';
import {
  CreateDestinationInput, UpdateDestinationInput, createDestination, destinationDto, getDestination, listDestinationRows,
  patchStopsCopy, rotateDestinationSecret, stopDescription, updateDestination,
} from './export/destinations';
import { auditExporter, exportLagSeconds } from './export/exporter';
import { RETENTION_ACTOR, applyLegalHold, legalHoldOf } from './retention';
import { runSeal, instanceId } from './seal';
import { activeKeyRow, allKeyRows, keyRowDto } from './sealKeys';
import { spoolStatus } from './spool';
import { append } from './writer';

// =============================================================================
// /api/admin/audit: administration of the journal (audit-durci §7.2, §8.1,
// §6.8, §9.2): platform administrators on the master tenant only (404
// elsewhere: the route does not exist there). Retention and legal holds,
// SIEM destinations, seal keys, immediate seal, spool. The floors of the
// restrictable actions (module.ts) are not lowerable: a retention change, the
// release of a legal hold, stopping a destination and rotating the seal key
// always need a second administrator (an approval request); creating,
// changing or testing a destination and setting a legal hold need a fresh
// second factor.
// =============================================================================

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!hasGlobalView(req)) { next(new AppError(404, 'Not found')); return; }
  next();
}

/**
 * A retention change or the release of a legal hold of a client's chain
 * (audit-durci §7.2, §10.4): when the client has a designated client
 * approver, the request is filed in the client's tenant and examined there by
 * that approver (journalReviewerPolicy, module.ts); otherwise in the master
 * tenant, by another platform administrator — unless the client lost its
 * client approver recently through someone else's act: then refused (409
 * approverFallbackHeld) until the end of the hold (AUD-A7-R4, as for the
 * guard's own requests). The floor of these actions is 'restricted': always
 * a request. True when the request was filed (202 sent).
 */
async function fileWithClientApprover(req: Request, res: Response, tenantId: number, description: string,
  payload: Record<string, unknown>): Promise<boolean> {
  if (tenantId === MASTER_TENANT_ID) return false;
  const userId = Number(req.session.userId);
  const { activeClientApprovers, fallbackHold } = await import('../guard/people');
  const { clients, hold } = await asTenant(tenantId, { type: 'user', userId }, async () => {
    const n = await activeClientApprovers(tenantId);
    return { clients: n, hold: n === 0 ? await fallbackHold(tenantId) : null };
  });
  if (hold) {
    throw new AppError(409, 'The client lost its client approver recently: the fallback on another platform administrator stays closed until '
      + `${hold.until.toISOString()} (designate a client approver, or wait)`, 'approverFallbackHeld', { until: hold.until.toISOString() });
  }
  if (clients === 0) return false;
  const { approvalService } = await import('../services/approval.service');
  const approval = await approvalService.create({ tenantId, userId, requestType: 'batch_command', description, payload });
  res.status(202).json({ data: { approvalId: approval.id, status: 'pending_approval', tenantId } });
  return true;
}

const idParam = (req: Request): number => {
  const n = Number(req.params.id);
  if (!Number.isSafeInteger(n) || n <= 0) throw new AppError(404, 'Not found');
  return n;
};

const RetentionBody = z.object({
  months: z.number().int().min(6).max(36),
  justification: z.string().trim().max(1000).optional().nullable(),
}).strict();

const LegalHoldBody = z.object({
  until: z.string().max(40).nullable(),
  reason: z.string().trim().max(500).optional().nullable(),
}).strict();

function bad(err: z.ZodError): AppError {
  return new AppError(400, err.errors.map((e) => `${e.path.join('.')} ${e.message}`).join('; '), 'invalidRequest');
}

export function createAuditAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  // ── Retention and legal holds ─────────────────────────────────────────────

  router.get('/retention', wrap(async (req, res) => {
    const chains = (await db.raw('SELECT tenant_id, last_seq, anchor_seq, tenant_exists FROM obligarth.audit_chains()') as {
      rows: Array<{ tenant_id: number; last_seq: string | number; anchor_seq: string | number; tenant_exists: boolean }>;
    }).rows;
    const tenants = await db('tenants').select('id', 'name') as Array<{ id: number; name: string }>;
    const ids = new Set([...chains.map((c) => Number(c.tenant_id)), ...tenants.map((t) => Number(t.id))]);
    const rows = await globalViewRead(req, () => db('audit_retention').select()) as Array<Record<string, any>>;
    const out: AuditRetentionRow[] = [];
    for (const id of [...ids].sort((a, b) => a - b)) {
      const c = chains.find((x) => Number(x.tenant_id) === id);
      const t = tenants.find((x) => Number(x.id) === id);
      let r = rows.find((x) => Number(x.tenant_id) === id);
      if (!r && !t) r = await asTenant(id, RETENTION_ACTOR, () => db('audit_retention').where({ tenant_id: id }).first()) as Record<string, any> | undefined;
      const months = Number((await db.raw('SELECT obligarth.audit_retention_months(?) AS m', [id]) as { rows: Array<{ m: number }> }).rows[0]?.m ?? 12);
      const pendingActive = r?.pending_effective_at && new Date(r.pending_effective_at).getTime() > Date.now();
      const holdActive = r?.legal_hold_until && new Date(r.legal_hold_until).getTime() > Date.now();
      out.push({
        tenantId: id, tenantName: t?.name ?? null, tenantExists: !!t,
        months: Number(r?.months ?? 12), effectiveMonths: months,
        pendingMonths: pendingActive ? Number(r?.pending_months) : null,
        pendingEffectiveAt: pendingActive ? new Date(r!.pending_effective_at).toISOString() : null,
        justification: r?.justification ?? null,
        legalHoldUntil: holdActive ? new Date(r!.legal_hold_until).toISOString() : null,
        legalHoldReason: holdActive ? r?.legal_hold_reason ?? null : null,
        headSeq: Number(c?.last_seq ?? 0), anchorSeq: Number(c?.anchor_seq ?? 0),
      });
    }
    res.json({ data: out });
  }));

  // PUT /retention/:tenantId { months, justification } — always an approval
  // (floor 'restricted'), reviewed by another platform administrator.
  router.put('/retention/:tenantId', wrap(async (req, res) => {
    const tenantId = Number(req.params.tenantId);
    if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new AppError(404, 'Not found');
    const parsed = RetentionBody.safeParse(req.body ?? {});
    if (!parsed.success) throw bad(parsed.error);
    const justification = parsed.data.justification?.trim() || null;
    if (parsed.data.months !== 12 && (!justification || justification.length < 10)) {
      throw new AppError(400, 'A justification of 10 characters at least is required for a retention other than 12 months', 'justificationRequired');
    }
    const exists = await db('tenants').where({ id: tenantId }).first('id');
    if (!exists) throw new AppError(404, 'Tenant not found');
    const description = `Set the audit retention of tenant ${tenantId} to ${parsed.data.months} months — justification: ${justification ?? '(default)'}`;
    const payload = { action: 'audit_retention_change', tenantId, months: parsed.data.months, justification };
    if (await fileWithClientApprover(req, res, tenantId, description, payload)) return;
    const approved = await applyRestriction(res, {
      req, actionKey: 'audit.retention_change', approvalRequestType: 'batch_command',
      approvalDescription: description, approvalPayload: payload,
    });
    if (!approved) return;
    // Reached only if the floor were lowered: never (floors are not configurable).
    throw new AppError(409, 'A retention change needs an approval', 'approvalRequired');
  }));

  // PUT /legal-hold/:tenantId { until, reason } — setting or extending: a
  // fresh second factor; lifting or shortening: an approval.
  router.put('/legal-hold/:tenantId', wrap(async (req, res) => {
    const tenantId = Number(req.params.tenantId);
    if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new AppError(404, 'Not found');
    const parsed = LegalHoldBody.safeParse(req.body ?? {});
    if (!parsed.success) throw bad(parsed.error);
    const until = parsed.data.until ? new Date(parsed.data.until) : null;
    if (until && Number.isNaN(until.getTime())) throw new AppError(400, 'Invalid date', 'invalidRequest');
    // The bounds of obligarth.audit_set_legal_hold: in the future, 5 years at most.
    const latest = new Date();
    latest.setUTCFullYear(latest.getUTCFullYear() + 5);
    if (until && (until.getTime() <= Date.now() || until.getTime() > latest.getTime())) {
      throw new AppError(400, 'A legal hold ends in the future, within 5 years', 'invalidLegalHold');
    }
    const reason = parsed.data.reason?.trim() || null;
    if (until && (!reason || reason.length < 10)) throw new AppError(400, 'A reason of 10 characters at least is required', 'reasonRequired');
    const current = await legalHoldOf(tenantId);
    const releases = until === null || (current !== null && until.getTime() < current.until.getTime());
    if (releases) {
      const description = until ? `Shorten the legal hold of tenant ${tenantId} to ${until.toISOString()}` : `Lift the legal hold of tenant ${tenantId}`;
      const payload = { action: 'audit_legal_hold_release', tenantId, until: until ? until.toISOString() : null, reason };
      if (await fileWithClientApprover(req, res, tenantId, description, payload)) return;
      const approved = await applyRestriction(res, {
        req, actionKey: 'audit.legal_hold_release', approvalRequestType: 'batch_command',
        approvalDescription: description, approvalPayload: payload,
      });
      if (!approved) return;
      throw new AppError(409, 'Lifting a legal hold needs an approval', 'approvalRequired');
    }
    const ok = await applyRestriction(res, { req, actionKey: 'audit.admin' });
    if (!ok) return;
    await applyLegalHold(tenantId, until, reason, Number(req.session.userId), { requestId: req.requestId });
    res.json({ data: { tenantId, legalHoldUntil: until!.toISOString(), legalHoldReason: reason } });
  }));

  // ── SIEM destinations ─────────────────────────────────────────────────────

  router.get('/destinations', wrap(async (_req, res) => {
    const rows = await listDestinationRows();
    const out = [];
    for (const r of rows) out.push(await destinationDto(r, r.enabled ? await exportLagSeconds(r).catch(() => null) : null));
    res.json({ data: out });
  }));

  router.post('/destinations', wrap(async (req, res) => {
    const parsed = CreateDestinationInput.safeParse(req.body ?? {});
    if (!parsed.success) throw bad(parsed.error);
    const ok = await applyRestriction(res, { req, actionKey: 'audit.destination_change' });
    if (!ok) return;
    const ctx = await fromRequest(req, MASTER_TENANT_ID);
    const out = await createDestination(parsed.data, ctx, Number(req.session.userId) || null);
    auditExporter.wake();
    res.status(201).json({ data: out.destination, ...(out.hmacSecret ? { secret: { hmacSecret: out.hmacSecret, shownOnce: true } } : {}) });
  }));

  router.patch('/destinations/:id', wrap(async (req, res) => {
    const id = idParam(req);
    const parsed = UpdateDestinationInput.safeParse(req.body ?? {});
    if (!parsed.success) throw bad(parsed.error);
    const row = await getDestination(id);
    if (!row) throw new AppError(404, 'Destination not found');
    if (patchStopsCopy(row, parsed.data)) {
      // The patch goes to an approval request, whose payload is no place for a
      // secret: the client key or the bearer token change apart.
      if (parsed.data.clientKeyPem !== undefined || parsed.data.bearerToken !== undefined) {
        throw new AppError(400, 'Change the client key or the bearer token in a separate request: this change needs an approval',
          'secretWithApproval');
      }
      const approved = await applyRestriction(res, {
        req, actionKey: 'audit.destination_stop', approvalRequestType: 'batch_command',
        approvalDescription: stopDescription(row, parsed.data),
        approvalPayload: { action: 'audit_destination_change', op: 'update', id, patch: parsed.data },
      });
      if (!approved) return;
      throw new AppError(409, 'Stopping, diverting or weakening a SIEM copy needs an approval', 'approvalRequired');
    }
    const ok = await applyRestriction(res, { req, actionKey: 'audit.destination_change' });
    if (!ok) return;
    const out = await updateDestination(id, parsed.data, await fromRequest(req, MASTER_TENANT_ID));
    auditExporter.wake();
    res.json({ data: out });
  }));

  router.delete('/destinations/:id', wrap(async (req, res) => {
    const id = idParam(req);
    const row = await getDestination(id);
    if (!row) throw new AppError(404, 'Destination not found');
    const approved = await applyRestriction(res, {
      req, actionKey: 'audit.destination_stop', approvalRequestType: 'batch_command',
      approvalDescription: `Delete the SIEM destination "${row.name}"`,
      approvalPayload: { action: 'audit_destination_change', op: 'delete', id },
    });
    if (!approved) return;
    throw new AppError(409, 'Deleting a SIEM destination needs an approval', 'approvalRequired');
  }));

  router.post('/destinations/:id/test', wrap(async (req, res) => {
    const id = idParam(req);
    const row = await getDestination(id);
    if (!row) throw new AppError(404, 'Destination not found');
    const ok = await applyRestriction(res, { req, actionKey: 'audit.destination_change' });
    if (!ok) return;
    const r = await auditExporter.test(row);
    await append({
      tenantId: MASTER_TENANT_ID, action: 'audit.destination_tested', outcome: r.ok ? 'success' : 'failure',
      target: { type: 'destination', id: String(id) }, details: { name: row.name, kind: row.kind, ...(r.ok ? {} : { code: r.code }) },
    }, await fromRequest(req, MASTER_TENANT_ID));
    res.json({ data: r.ok ? { delivered: true } : { delivered: false, code: r.code } });
  }));

  router.post('/destinations/:id/rotate-secret', wrap(async (req, res) => {
    const id = idParam(req);
    const ok = await applyRestriction(res, { req, actionKey: 'audit.destination_change' });
    if (!ok) return;
    const hmacSecret = await rotateDestinationSecret(id, await fromRequest(req, MASTER_TENANT_ID));
    res.json({ data: { hmacSecret, shownOnce: true } });
  }));

  router.get('/export-status', wrap(async (_req, res) => {
    const rows = await listDestinationRows();
    const destinations = [];
    for (const r of rows) destinations.push(await destinationDto(r, r.enabled ? await exportLagSeconds(r).catch(() => null) : null));
    const chains = (await db.raw('SELECT tenant_id, last_seq FROM obligarth.audit_chains()') as { rows: Array<{ tenant_id: number; last_seq: string | number }> }).rows;
    const cursors = await db('audit_export_cursors').select('destination_id', 'tenant_id', 'last_seq') as Array<{ destination_id: number; tenant_id: number; last_seq: string | number }>;
    const behind = chains.map((c) => {
      const mine = cursors.filter((k) => Number(k.tenant_id) === Number(c.tenant_id));
      const min = rows.filter((d) => d.enabled && (d.scope_tenant_id === null || Number(d.scope_tenant_id) === Number(c.tenant_id)))
        .map((d) => Number(mine.find((k) => Number(k.destination_id) === d.id)?.last_seq ?? 0));
      const cursor = min.length ? Math.min(...min) : Number(c.last_seq);
      return { tenantId: Number(c.tenant_id), headSeq: Number(c.last_seq), cursor, behind: Math.max(0, Number(c.last_seq) - cursor) };
    }).sort((a, b) => b.behind - a.behind).slice(0, 10);
    res.json({ data: { exporterActive: auditExporter.isActive(), destinations, chainsBehind: behind } });
  }));

  // ── Seal keys, immediate seal, sealing state, spool ──────────────────────

  router.get('/seal-keys', wrap(async (_req, res) => {
    res.json({ data: (await allKeyRows()).map(keyRowDto) });
  }));

  router.post('/seal-keys/rotate', wrap(async (req, res) => {
    const approved = await applyRestriction(res, {
      req, actionKey: 'audit.seal_key_rotate', approvalRequestType: 'batch_command',
      approvalDescription: 'Rotate the key that signs the audit seals',
      approvalPayload: { action: 'audit_seal_key_rotate' },
    });
    if (!approved) return;
    throw new AppError(409, 'Rotating the seal key needs an approval', 'approvalRequired');
  }));

  router.post('/seal-now', wrap(async (req, res) => {
    const ok = await applyRestriction(res, { req, actionKey: 'audit.admin' });
    if (!ok) return;
    const job = auditJobHandles().seal;
    let queued: string | null = null;
    if (job) {
      try { queued = await job.send({}, { priority: 10 }); } catch { queued = null; }
    }
    if (queued) { wakeAuditJob('audit.seal'); res.status(202).json({ data: { queued: true, jobId: queued } }); return; }
    // No job runtime in this process: sealed now, as the seal job would.
    const { asNone } = await import('../db/context');
    const r = await asNone({ type: 'job', name: 'audit.seal' }, () => runSeal({ requestId: req.requestId }));
    res.status(202).json({ data: { queued: false, seq: r.seq, leaves: r.leaves, tsaStatus: r.tsaStatus } });
  }));

  router.get('/sealing', wrap(async (_req, res) => {
    const last = await db('audit_seals').orderBy('seal_seq', 'desc').first('seal_seq', 'sealed_at', 'leaf_count', 'tsa_status') as
      { seal_seq: string | number; sealed_at: Date; leaf_count: number; tsa_status: 'ok' | 'disabled' | 'failed' } | undefined;
    const key = await activeKeyRow();
    res.json({
      data: {
        lastSeal: last ? { seq: Number(last.seal_seq), sealedAt: new Date(last.sealed_at).toISOString(), leaves: Number(last.leaf_count), tsaStatus: last.tsa_status } : null,
        tsaConfigured: !!config.audit.tsaUrl,
        activeKeyId: key?.keyId ?? null,
        instanceId: await instanceId().catch(() => null),
      },
    });
  }));

  router.get('/spool', wrap(async (_req, res) => {
    res.json({ data: spoolStatus() });
  }));

  return router;
}

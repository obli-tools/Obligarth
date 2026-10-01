import { Router, type NextFunction, type Request, type Response } from 'express';
import { AUDIT_ACTOR_SIDES, AUDIT_CRITICALITIES, AUDIT_OUTCOMES, MASTER_TENANT_ID } from '@obligarth/shared';
import { requireAuth } from '../middleware/auth';
import { requireTenantCapability } from '../middleware/rbac';
import { actorOfRequest, globalViewRead, globalViewScope } from '../middleware/dbContext';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import { asTenant } from '../db/context';
import { hasGlobalView } from '../services/deviceScope.service';
import { applyRestriction } from '../services/restriction.service';
import { audit } from '../audit';
import { auditJobHandles, wakeAuditJob } from '../audit/jobs';
import { allKeyRows, keyRowDto } from '../audit/sealKeys';
import {
  chainStatus, distinctActions, entryDetail, listEntries, sealsOf, verificationsOf, type ListParams,
} from '../audit/read';
import { instanceId } from '../audit/seal';
import { EXPORT_MAX_ENTRIES, exportRange, writeCsvExport, writeJsonlExport } from '../audit/export/jsonl';
import { runningVerification, startVerificationRow, verifyTenantChain } from '../audit/verify';
import { chainExportLag } from '../audit/export/exporter';
import { logger } from '../utils/logger';

// =============================================================================
// /api/audit-log: delegated reading of the hardened journal (audit-durci §9)
// =============================================================================
//
// Readers (§9.1): the holders of the tenant capability audit.read in the
// session's tenant (a tenant administrator holds it, as do the client sets
// approver and auditor), and the platform administrators. The global view
// (every chain, the chains of deleted tenants included) only opens for a
// platform administrator whose session is on the master tenant
// (globalViewScope: context 'platform'); anyone else reads the chain of the
// session's tenant only — a member of the master tenant who is not a platform
// administrator reads the master tenant's chain, never the others' (N1).
// filterTenantId is read in the global view only. Viewing (once per session,
// tenant and day) and exporting are journaled. Nothing here deletes an entry:
// only the retention job purges (D25, J28).

const router = Router();
router.use(requireAuth);
// The capability per route (not router-wide): a method the router does not
// serve falls through to the JSON 404 (DELETE /api/audit-log is gone, J28).
const canRead = requireTenantCapability('audit.read');

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

const posInt = (v: unknown): number | undefined => {
  if (v === undefined || v === null || v === '') return undefined;
  const n = Number(v);
  return Number.isSafeInteger(n) && n > 0 && n <= 2_147_483_647 ? n : undefined;
};

const dateOf = (v: unknown): Date | undefined => {
  if (typeof v !== 'string' || !v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d;
};

/** The chain a request reads: the session's tenant, or (global view) every
 *  chain, or the one of filterTenantId. */
function scopeOf(req: Request): { global: boolean; tenantId: number | null } {
  if (hasGlobalView(req)) return { global: true, tenantId: posInt(req.query.filterTenantId) ?? null };
  return { global: false, tenantId: Number(req.tenantId) };
}

/** Runs a read of one chain: in the request's context, except a deleted
 *  tenant's chain from the global view (no longer in the platform read set),
 *  read in that tenant's context by the platform administrator. */
async function readChain<T>(req: Request, tenantId: number, fn: () => Promise<T>): Promise<T> {
  if (!hasGlobalView(req) || tenantId === MASTER_TENANT_ID) return fn();
  const exists = await db('tenants').where({ id: tenantId }).first('id');
  if (exists) return fn();
  return asTenant(tenantId, actorOfRequest(req), fn);
}

/** One audit.viewed per session, tenant and UTC day (§9.5). Never blocks.
 *  A deleted tenant's chain takes no entry any more (audit_append: unknown
 *  tenant): its viewing from the global view is journaled in the master
 *  tenant's chain, naming it. */
async function noteViewed(req: Request, tenantId: number, view: 'list' | 'entry', global: boolean): Promise<void> {
  const day = new Date().toISOString().slice(0, 10);
  const seen = req.session.auditViewedOn ?? {};
  const key = global ? `g:${tenantId}` : String(tenantId);
  if (seen[key] === day) return;
  req.session.auditViewedOn = { ...seen, [key]: day };
  // A standard entry never throws (spooled at worst); the context's lookup
  // may: logged, the reading itself is not refused.
  void (async () => {
    const live = !global || tenantId === MASTER_TENANT_ID || !!(await db('tenants').where({ id: tenantId }).first('id'));
    const chain = live ? tenantId : MASTER_TENANT_ID;
    await audit.append({
      tenantId: chain, action: 'audit.viewed', onBehalfOf: live ? undefined : tenantId,
      details: { view, ...(global ? { globalView: true } : {}), ...(live ? {} : { tenantId, tenantDeleted: true }) },
    }, await audit.fromRequest(req, chain));
  })().catch((err) => logger.warn({ err: { name: (err as Error).name }, tenantId }, 'audit: viewing not journaled'));
}

function listParams(req: Request, tenantId: number | null): ListParams {
  const q = req.query;
  const pick = <T extends string>(v: unknown, allowed: readonly T[]): T | undefined =>
    (typeof v === 'string' && (allowed as readonly string[]).includes(v) ? v as T : undefined);
  const search = typeof q.search === 'string' && q.search ? q.search.slice(0, 100) : undefined;
  const action = typeof q.action === 'string' && /^[a-z0-9_.]{1,100}$/.test(q.action) ? q.action : undefined;
  return {
    tenantId,
    action,
    userId: posInt(q.userId),
    actorSide: pick(q.actorSide, AUDIT_ACTOR_SIDES),
    outcome: pick(q.outcome, AUDIT_OUTCOMES),
    criticality: pick(q.criticality, AUDIT_CRITICALITIES),
    deviceId: posInt(q.deviceId),
    resourceType: typeof q.resourceType === 'string' && /^[a-z][a-z0-9_]{0,49}$/.test(q.resourceType) ? q.resourceType : undefined,
    search,
    since: dateOf(q.since),
    until: dateOf(q.until),
    beforeSeq: posInt(q.beforeSeq),
    limit: posInt(q.limit) ?? 100,
    offset: q.offset !== undefined ? Math.max(0, Number(q.offset) || 0) : 0,
  };
}

// GET /api/audit-log — the entries of the scope, newest first.
router.get('/', canRead, globalViewScope('console.audit_log'), wrap(async (req, res) => {
  const scope = scopeOf(req);
  const params = listParams(req, scope.tenantId);
  const data = scope.tenantId !== null
    ? await readChain(req, scope.tenantId, () => listEntries(params))
    : await listEntries(params);
  await noteViewed(req, scope.global ? (scope.tenantId ?? MASTER_TENANT_ID) : Number(req.tenantId), 'list', scope.global);
  res.json({ data });
}));

// GET /api/audit-log/distinct-actions — for the filter of the console.
router.get('/distinct-actions', canRead, globalViewScope('console.audit_log'), wrap(async (req, res) => {
  const scope = scopeOf(req);
  const data = scope.tenantId !== null
    ? await readChain(req, scope.tenantId, () => distinctActions(scope.tenantId))
    : await distinctActions(null);
  res.json({ data });
}));

// GET /api/audit-log/entries/:uuid — the exact body, its links and its seal.
router.get('/entries/:uuid', canRead, globalViewScope('console.audit_log'), wrap(async (req, res) => {
  const uuid = String(req.params.uuid).toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(uuid)) throw new AppError(404, 'Not found');
  const scope = scopeOf(req);
  const detail = scope.tenantId !== null
    ? await readChain(req, scope.tenantId, () => entryDetail(uuid, scope.tenantId))
    : await entryDetail(uuid, null);
  if (!detail) throw new AppError(404, 'Not found');
  await noteViewed(req, scope.global ? detail.tenantId : Number(req.tenantId), 'entry', scope.global);
  res.json({ data: detail });
}));

/** The chain of a status, seals or verification request: the session's
 *  tenant, or filterTenantId in the global view (required there). */
function chainOf(req: Request): number {
  const scope = scopeOf(req);
  if (scope.global) return scope.tenantId ?? MASTER_TENANT_ID;
  return Number(req.tenantId);
}

// GET /api/audit-log/status — head, anchor, retention, last seal, last verification.
router.get('/status', canRead, globalViewScope('console.audit_log'), wrap(async (req, res) => {
  const tenantId = chainOf(req);
  const status = await readChain(req, tenantId, () => chainStatus(tenantId));
  if (req.session.role === 'admin' && hasGlobalView(req)) status.exportLagSeconds = await chainExportLag(tenantId);
  res.json({ data: status });
}));

// GET /api/audit-log/seals?fromSeq=&toSeq= — seals covering the range, with
// the tenant's leaf and proof.
router.get('/seals', canRead, globalViewScope('console.audit_log'), wrap(async (req, res) => {
  const scope = scopeOf(req);
  const tenantId = scope.global ? scope.tenantId : Number(req.tenantId);
  const from = posInt(req.query.fromSeq) ?? 1;
  const to = posInt(req.query.toSeq);
  const data = tenantId !== null
    ? await readChain(req, tenantId, () => sealsOf(tenantId, from, to))
    : await sealsOf(null);
  res.json({ data });
}));

// GET /api/audit-log/seal-keys — public keys of the seals.
router.get('/seal-keys', canRead, wrap(async (_req, res) => {
  res.json({ data: (await allKeyRows()).map(keyRowDto) });
}));

// GET /api/audit-log/verifications?limit=
router.get('/verifications', canRead, globalViewScope('console.audit_log'), wrap(async (req, res) => {
  const tenantId = chainOf(req);
  const data = await readChain(req, tenantId, () => verificationsOf(tenantId, posInt(req.query.limit) ?? 20));
  res.json({ data });
}));

// POST /api/audit-log/verify — one verification at a time per chain; 202.
router.post('/verify', canRead, wrap(async (req, res) => {
  const tenantId = hasGlobalView(req) ? (posInt((req.body as { filterTenantId?: unknown })?.filterTenantId) ?? MASTER_TENANT_ID) : Number(req.tenantId);
  if (await runningVerification(tenantId)) throw new AppError(409, 'A verification of this chain is already running', 'verificationRunning');
  const requestedBy = Number(req.session.userId) || null;
  const verificationId = await startVerificationRow(tenantId, 'on_demand', requestedBy);
  const job = auditJobHandles().verifyTenant;
  let queued = false;
  if (job) {
    try {
      queued = !!(await job.send({ chain: tenantId, kind: 'on_demand', verificationId, ...(requestedBy ? { requestedBy } : {}) },
        { singletonKey: `t:${tenantId}`, priority: 10 }));
      if (queued) wakeAuditJob('audit.verify-tenant');
    } catch {
      queued = false;
    }
  }
  if (!queued) {
    // No job runtime (a process without workers): verified in the background.
    void verifyTenantChain(tenantId, 'on_demand', { verificationId, requestedBy, requestId: req.requestId })
      .catch((err) => logger.warn({ err: { name: (err as Error).name } }, 'audit: on-demand verification failed'));
  }
  res.status(202).json({ data: { verificationId } });
}));

// GET /api/audit-log/export?format=jsonl|csv&fromSeq=&toSeq=&since=&until=
// One tenant per file (filterTenantId required in the global view); step-up
// without the trusted-IP shortcut (floor of audit.export); audit.exported is
// written before the stream (critical intent), its result after.
// Also POST (same parameters in the body): a step-up proof travels in a
// request body, which a browser never sends with a GET. The step-up runs in
// the request's own context (it records its attempts); the chain is then
// read in the global view's context when the request has it.
/** A read of the exported chain: the session's tenant; in the global view,
 *  the master's chain in the request's context, another tenant's under a
 *  platform grant, a deleted tenant's in that tenant's context. */
async function exportRead<T>(req: Request, tenantId: number, fn: () => Promise<T>): Promise<T> {
  if (!hasGlobalView(req) || tenantId === MASTER_TENANT_ID) return fn();
  const exists = await globalViewRead(req, () => db('tenants').where({ id: tenantId }).first('id'));
  if (exists) return globalViewRead(req, fn);
  return asTenant(tenantId, actorOfRequest(req), fn);
}

const exportHandler = wrap(async (req, res) => {
  const p = { ...req.query, ...(req.method === 'POST' && req.body && typeof req.body === 'object' ? req.body as Record<string, unknown> : {}) } as Record<string, unknown>;
  const format = p.format === 'csv' ? 'csv' : p.format === undefined || p.format === 'jsonl' ? 'jsonl' : null;
  if (!format) throw new AppError(400, 'format must be jsonl or csv', 'invalidFormat');
  const scope = hasGlobalView(req) ? { global: true, tenantId: posInt(p.filterTenantId) ?? null } : { global: false, tenantId: Number(req.tenantId) };
  if (scope.global && scope.tenantId === null) throw new AppError(400, 'Choose one tenant (filterTenantId) to export from the global view', 'tenantRequired');
  const tenantId = scope.global ? scope.tenantId as number : Number(req.tenantId);
  const allowed = await applyRestriction(res, { req, actionKey: 'audit.export' });
  if (!allowed) return;
  const range = await exportRead(req, tenantId, () => exportRange(tenantId, {
    fromSeq: posInt(p.fromSeq), toSeq: posInt(p.toSeq), since: dateOf(p.since), until: dateOf(p.until),
  }));
  if (range.toSeq - range.fromSeq + 1 > EXPORT_MAX_ENTRIES) {
    throw new AppError(400, `An export holds ${EXPORT_MAX_ENTRIES} entries at most: narrow the range`, 'exportTooLarge');
  }
  // The entry goes to the exported tenant's chain (the client sees who
  // exported its log); a deleted tenant's export is journaled by the MSP's.
  const tenant = await exportRead(req, tenantId, () => db('tenants').where({ id: tenantId }).first('slug')) as { slug: string } | undefined;
  const chain = tenant ? tenantId : MASTER_TENANT_ID;
  const ctx = await audit.fromRequest(req, chain);
  const entry = {
    tenantId: chain, action: 'audit.exported', target: { type: 'audit_log', id: String(tenantId) },
    onBehalfOf: ctx.actor.side === 'msp' && tenantId !== MASTER_TENANT_ID ? tenantId : undefined,
    details: { format, tenantId, fromSeq: range.fromSeq, toSeq: range.toSeq },
  };
  await audit.withIntent(entry, ctx, () => exportRead(req, tenantId, async () => {
    const name = `audit-${tenant?.slug ?? `tenant-${tenantId}`}-${range.fromSeq}-${Math.max(range.toSeq, 0)}.${format}`;
    res.setHeader('Content-Type', format === 'csv' ? 'text/csv; charset=utf-8' : 'application/x-ndjson; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${name.replace(/[^A-Za-z0-9._-]/g, '_')}"`);
    res.setHeader('Cache-Control', 'no-store');
    if (format === 'csv') return (await writeCsvExport(res, { tenantId, range })).entries;
    return (await writeJsonlExport(res, { tenantId, tenantSlug: tenant?.slug ?? null, instance: await instanceId(), exportedBy: ctx.actor.ref, range })).entries;
  }), { resultDetails: (entries) => ({ entries }) });
  res.end();
});
router.get('/export', canRead, exportHandler);
router.post('/export', canRead, exportHandler);

export default router;

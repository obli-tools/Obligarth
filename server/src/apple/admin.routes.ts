import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { isMasterTenant } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import { asPlatform, userActor } from '../db/context';
import { globalViewGrant } from '../db/platformAccess';
import { AppError } from '../middleware/errorHandler';
import { applyRestriction, registerRestrictableActions } from '../services/restriction.service';
import { refuse, registerApprovalExecutor, requirePlatformAdmin, withAuditAs } from '../services/approval.service';
import { audit as journal } from '../audit';
import { isAppleEdgeError } from './edge/errors';
import { toAppError } from './edge/appError';
import { edgeHealth } from './edge/health';
import { appleEdge } from './edge/instance';
import { serverVersion } from './edge/version';
import { appleTenants } from './tenants/registry';
import { provisionTenantNow } from './tenants/jobs';
import { sendRestoreCheck, sendTenantReconcile } from './reconcile/jobs';

// =============================================================================
// /api/admin/apple-edge: the tenant registry seen by the platform
// administrators (docs: integration-apple-edge §6.2, §6.3, §6.5, §11.6),
// mounted on the tenant router (requireAuth, requireTenant). Every route: the
// master tenant (404 elsewhere), a platform administrator (403 otherwise).
//   GET  /status                           apple-edge as the brain sees it (version, matrix, probe, circuit)
//   GET  /tenants                          the mirror and the MDM key of every tenant (context 'platform',
//                                          the administrator's journaled grant)
//   POST /tenants/:tenantId/provision      the provisioning again ("Retry"), idempotent
//   POST /tenants/:tenantId/state          suspend or resume at apple-edge: restriction apple_edge.tenant_state
//                                          (floor 'sensitive'), apple.tenant_state_changed (critical, P2)
//   POST /tenants/:tenantId/ca-rotate      rotation of the device CA: restriction apple_edge.ca_rotate (floor
//                                          'sensitive'), apple.tenant_ca_rotated (critical, P2)
//   POST /tenants/:tenantId/reconcile      a full reconciliation of the tenant now (§13.1, lot C5)
//   POST /restore-check                    the check after a restore (§13.2, FND-09; apple-edge.restore-check)
// The commands freeze has no route here: it belongs to the guard engine
// (POST /api/guard/freeze, job actions.edge-freeze-sync). The audit entries
// go to the chain of the tenant concerned. At 'restricted', a second platform
// administrator approves the 'apple_edge_manage' request, executed as the
// requester.
// =============================================================================

export const APPLE_EDGE_RESTRICTABLE_ACTIONS = [
  { key: 'apple_edge.tenant_state', label: 'Suspend or resume a tenant at the device service (apple-edge)', category: 'Apple devices' },
  { key: 'apple_edge.ca_rotate', label: 'Rotate the device CA of a tenant (apple-edge)', category: 'Apple devices' },
] as const;

type EdgeOp = { op: 'state'; tenantId: number; state: 'active' | 'suspended' } | { op: 'ca_rotate'; tenantId: number };

const EdgeOpPayload = z.discriminatedUnion('op', [
  z.object({ op: z.literal('state'), tenantId: z.number().int().positive(), state: z.enum(['active', 'suspended']) }),
  z.object({ op: z.literal('ca_rotate'), tenantId: z.number().int().positive() }),
]);

type AuditRunner = <T>(tenantId: number, action: string, details: Record<string, unknown>, fn: () => Promise<T>,
  resultDetails?: (r: T) => Record<string, unknown>) => Promise<T>;

function describeOp(o: EdgeOp): string {
  return o.op === 'state'
    ? `${o.state === 'suspended' ? 'Suspend' : 'Resume'} the tenant #${o.tenantId} at the device service`
    : `Rotate the device CA of the tenant #${o.tenantId}`;
}

/** Runs an operation with its audit entry (the intent before, the result after), as `userId`. */
async function performEdgeOp(o: EdgeOp, userId: number, run: AuditRunner): Promise<unknown> {
  const actor = userActor(userId);
  try {
    if (o.op === 'state') {
      await run(o.tenantId, 'apple.tenant_state_changed', { state: o.state, source: 'console' },
        () => appleTenants.setState(o.tenantId, o.state, actor));
      return { state: o.state };
    }
    const rotation = await run(o.tenantId, 'apple.tenant_ca_rotated', {}, () => appleTenants.rotateCa(o.tenantId, actor),
      (r) => ({ caId: r.ca.id, caSha256: r.ca.sha256, notAfter: r.ca.not_after, verifyOnly: r.verify_only.length }));
    return { ca: { id: rotation.ca.id, sha256: rotation.ca.sha256, notAfter: rotation.ca.not_after }, verifyOnly: rotation.verify_only.length };
  } catch (err) {
    if (isAppleEdgeError(err)) throw toAppError(err);
    throw err;
  }
}

let registered = false;

/** registerAppleModule(): the restrictable actions (floors 'sensitive') and their approval executor. */
export function registerAppleEdgeAdmin(): void {
  if (registered) return;
  registered = true;
  registerRestrictableActions(APPLE_EDGE_RESTRICTABLE_ACTIONS, {}, {
    'apple_edge.tenant_state': { level: 'sensitive' },
    'apple_edge.ca_rotate': { level: 'sensitive' },
  });
  registerApprovalExecutor('apple_edge_manage', async ({ tenantId, requesterId, payload }) => {
    await requirePlatformAdmin(requesterId);
    if (!isMasterTenant(tenantId)) refuse('The device service is administered from the master tenant only');
    const p = payload as Record<string, unknown>;
    const parsed = EdgeOpPayload.safeParse({ op: p.op, tenantId: p.targetTenantId, state: p.state });
    if (!parsed.success) refuse('Invalid device service request');
    try {
      await performEdgeOp(parsed.data as EdgeOp, requesterId,
        (target, action, details, fn, resultDetails) => withAuditAs(target, requesterId, action,
          { resourceType: 'tenant', resourcePath: String(target), details }, fn, resultDetails));
    } catch (err) {
      if (err instanceof AppError) refuse(err.message);
      throw err;
    }
  });
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

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);

function tenantIdOf(req: Request): number {
  const id = Number(req.params.tenantId);
  if (!Number.isSafeInteger(id) || id <= 0) throw new AppError(404, 'Tenant not found');
  return id;
}

/** The tenant exists (the administrator sees every tenant). */
async function requireTenantRow(tenantId: number): Promise<void> {
  const row = await db('tenants').where({ id: tenantId }).first('id');
  if (!row) throw new AppError(404, 'Tenant not found');
}

export function createAppleEdgeAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/status', wrap(async (_req, res) => {
    const h = edgeHealth();
    res.json({
      data: {
        mode: config.apple.mode,
        brainVersion: serverVersion(),
        edge: {
          up: h.up, version: h.version, compatible: h.compatible, lastOkAt: h.lastOkAt, consecutiveFailures: h.consecutiveFailures,
          checkedAt: h.checkedAt, kekId: h.kekId, signingIdentity: h.signingIdentity,
        },
        circuitOpen: config.apple.mode === 'on' ? appleEdge.circuitOpen() : false,
      },
    });
  }));

  router.get('/tenants', wrap(async (req, res) => {
    const grant = await globalViewGrant(req, 'admin.apple_edge.tenants');
    const rows = await asPlatform(grant, () => db('tenants as t')
      .leftJoin('tenant_apple_edge as m', 'm.tenant_id', 't.id')
      .select('t.id', 't.name', 't.mdm_key', 'm.edge_state', 'm.edge_state_at', 'm.commands_frozen', 'm.ca_id', 'm.ca_not_after',
        'm.provision_attempts', 'm.last_error_code', 'm.last_synced_at', 'm.enrollment_config_at')
      .orderBy('t.id')) as Array<Record<string, unknown>>;
    res.json({
      data: rows.map((r) => ({
        tenantId: Number(r.id), name: r.name, mdmKey: r.mdm_key ?? null, edgeState: r.edge_state ?? 'unprovisioned',
        edgeStateAt: iso(r.edge_state_at), commandsFrozen: r.commands_frozen === true, caId: r.ca_id ?? null,
        caNotAfter: iso(r.ca_not_after), provisionAttempts: Number(r.provision_attempts ?? 0), lastErrorCode: r.last_error_code ?? null,
        lastSyncedAt: iso(r.last_synced_at), enrollmentConfigAt: iso(r.enrollment_config_at),
      })),
    });
  }));

  router.post('/tenants/:tenantId/provision', wrap(async (req, res) => {
    const tenantId = tenantIdOf(req);
    await requireTenantRow(tenantId);
    if (config.apple.mode !== 'on') throw new AppError(503, 'The Apple integration is turned off on this instance', 'appleIntegrationDisabled');
    const jobId = await provisionTenantNow(tenantId);
    res.status(202).json({ data: { jobId } });
  }));

  /** A change: its restriction, then the operation and its audit entries (target tenant's chain). */
  const change = (actionKey: string, build: (req: Request) => EdgeOp) => wrap(async (req, res) => {
    const o = build(req);
    await requireTenantRow(o.tenantId);
    if (config.apple.mode !== 'on') throw new AppError(503, 'The Apple integration is turned off on this instance', 'appleIntegrationDisabled');
    const approved = await applyRestriction(res, {
      req,
      actionKey,
      approvalRequestType: 'batch_command',
      approvalDescription: describeOp(o),
      approvalPayload: { action: 'apple_edge_manage', op: o.op, targetTenantId: o.tenantId, ...(o.op === 'state' ? { state: o.state } : {}) },
    });
    if (!approved) return;
    const userId = Number(req.session?.userId);
    const data = await performEdgeOp(o, userId, async (target, action, details, fn, resultDetails) => journal.withIntent(
      { tenantId: target, action, target: { type: 'tenant', id: String(target) }, details },
      await journal.fromRequest(req, target), fn, { resultDetails },
    ));
    res.json({ data });
  });

  router.post('/tenants/:tenantId/state', change('apple_edge.tenant_state', (req) => {
    const state = (req.body ?? {}).state;
    if (state !== 'active' && state !== 'suspended') throw new AppError(400, 'state: "active" or "suspended"', 'invalidState');
    return { op: 'state', tenantId: tenantIdOf(req), state };
  }));

  router.post('/tenants/:tenantId/ca-rotate', change('apple_edge.ca_rotate', (req) => ({ op: 'ca_rotate', tenantId: tenantIdOf(req) })));

  router.post('/tenants/:tenantId/reconcile', wrap(async (req, res) => {
    const tenantId = tenantIdOf(req);
    await requireTenantRow(tenantId);
    if (config.apple.mode !== 'on') throw new AppError(503, 'The Apple integration is turned off on this instance', 'appleIntegrationDisabled');
    const jobId = await sendTenantReconcile(tenantId, true);
    res.status(202).json({ data: { jobId } });
  }));

  router.post('/restore-check', wrap(async (_req, res) => {
    if (config.apple.mode !== 'on') throw new AppError(503, 'The Apple integration is turned off on this instance', 'appleIntegrationDisabled');
    const jobId = await sendRestoreCheck();
    res.status(202).json({ data: { jobId } });
  }));

  return router;
}

// /api/admin/vault: state and operations of the vault (docs: coffre-secrets
// §11.1), mounted on the tenant router (requireAuth, requireTenant). Every
// route: the master tenant (404 elsewhere), a platform administrator (403
// otherwise), i.e. requireRole('admin') and hasGlobalView(req). Never a key,
// never a secret: fingerprints (kek_id), ids, counts.
//
//   GET  /status                   VaultStatus
//   GET  /operations?kind=&limit=  history of the operations
//   POST /escrow/events            escrow confirmation, test, destruction of
//                                  the old shares (strict step-up)
//   POST /kek-rotations            KEK rotation: two-step approval imposed,
//                                  outside the restrictions matrix (V12)
//   POST /dek-rotations            DEK rotation of a tenant or of the
//                                  instance (strict step-up), run by the job
//                                  vault.reencrypt-tenant
import crypto from 'node:crypto';
import { Router, type NextFunction, type Request, type Response } from 'express';
import { isMasterTenant, MASTER_TENANT_ID, type VaultOperationKind } from '@obligarth/shared';
import { AppError } from '../middleware/errorHandler';
import { approvalService } from '../services/approval.service';
import { checkSecondFactor, sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { clientIp } from '../utils/clientIp';
import { writeVaultAudit } from './events';
import { sendDekRotation } from './jobs';
import { OPERATION_KINDS, vaultOperations } from './operations';
import { vault, vaultInternals } from './vault';

function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

const KEK_ID_RE = /^[0-9a-f]{16}$/;
const ESCROW_KINDS = { confirmation: 'escrow_confirmation', test: 'escrow_test', old_shares_destroyed: 'escrow_retirement' } as const;
const ESCROW_AUDIT = {
  escrow_confirmation: 'vault.escrow_confirmed',
  escrow_test: 'vault.escrow_tested',
  escrow_retirement: 'vault.escrow_old_shares_destroyed',
} as const;

function text(v: unknown, field: string, { min = 0, max = 500 } = {}): string {
  if (v === undefined || v === null) {
    if (min > 0) throw new AppError(400, `${field} is required`, 'invalidInput');
    return '';
  }
  if (typeof v !== 'string') throw new AppError(400, `${field} must be a string`, 'invalidInput');
  const t = v.trim();
  if (t.length < min || t.length > max) throw new AppError(400, `${field}: ${min} to ${max} characters`, 'invalidInput');
  return t;
}

/** The strict step-up of the vault's changes: a current code, no trusted IP. */
async function strictStepUp(req: Request, res: Response, actionKey: string): Promise<boolean> {
  const step = await checkSecondFactor(req, { actionKey, allowTrustedIp: false, allowDevice: true });
  if (!step.ok) { sendStepUpFailure(res, step); return false; }
  return true;
}

export function createVaultAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/status', wrap(async (_req, res) => {
    res.json({ success: true, data: await vault.status() });
  }));

  router.get('/operations', wrap(async (req, res) => {
    const kind = req.query.kind;
    if (kind !== undefined && (typeof kind !== 'string' || !OPERATION_KINDS.includes(kind as VaultOperationKind))) {
      throw new AppError(400, 'Unknown operation kind', 'invalidKind');
    }
    const limit = req.query.limit === undefined ? 50 : Number(req.query.limit);
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw new AppError(400, 'limit must be an integer from 1 to 200', 'invalidLimit');
    const ops = await vaultInternals.withVaultDb({}, (q) => vaultOperations.list(q, { kind: kind as VaultOperationKind | undefined, limit }));
    res.json({ success: true, data: ops });
  }));

  // Escrow events (coffre-secrets §9.2): what the ceremony recorded. A
  // confirmation or a test names the current kek_id (409 otherwise).
  router.post('/escrow/events', wrap(async (req, res) => {
    const body = (req.body ?? {}) as { kind?: unknown; kekIds?: unknown; note?: unknown };
    if (typeof body.kind !== 'string' || !(body.kind in ESCROW_KINDS)) {
      throw new AppError(400, 'kind: confirmation, test or old_shares_destroyed', 'invalidInput');
    }
    const kind = ESCROW_KINDS[body.kind as keyof typeof ESCROW_KINDS];
    const ids = (body.kekIds ?? {}) as { server?: unknown; edge?: unknown };
    if (typeof ids !== 'object' || typeof ids.server !== 'string' || !KEK_ID_RE.test(ids.server)
      || (ids.edge !== undefined && ids.edge !== null && (typeof ids.edge !== 'string' || !KEK_ID_RE.test(ids.edge)))) {
      throw new AppError(400, 'kekIds: { server, edge? }, 16 hexadecimal characters each', 'invalidInput');
    }
    const note = text(body.note, 'note');
    const current = vault.kekId();
    if (kind !== 'escrow_retirement' && ids.server !== current) {
      throw new AppError(409, 'The escrowed KEK is not the current one: check the kek_id of the shares', 'escrowKekMismatch');
    }
    if (!(await strictStepUp(req, res, 'vault.escrow'))) return;
    const kekIds = { server: ids.server, edge: typeof ids.edge === 'string' ? ids.edge : null };
    const op = await vaultInternals.withVaultDb({}, (q) => vaultOperations.create(q, {
      kind, state: 'done', requestedBy: req.session.userId ?? null, reason: note || null,
      params: { kekIds, currentKekId: current }, startedAt: new Date(), finishedAt: new Date(),
    }));
    await writeVaultAudit([{
      tenantId: MASTER_TENANT_ID, userId: req.session.userId, action: ESCROW_AUDIT[kind], resourceType: 'vault_operation',
      resourcePath: op.id, details: { kekIds, note: note || undefined }, ipAddress: clientIp(req) || undefined,
    }]);
    res.status(201).json({ success: true, data: op });
  }));

  // KEK rotation (coffre-secrets §6.7): a second platform administrator
  // approves (no self-approval, 30 min); the approval authorizes the
  // operation for 24 h; the CLI runs it with the server stopped.
  router.post('/kek-rotations', wrap(async (req, res) => {
    const reason = text((req.body ?? {}).reason, 'reason', { min: 3, max: 500 });
    const operationId = crypto.randomUUID();
    const kekId = vault.kekId();
    const approval = await approvalService.create({
      tenantId: MASTER_TENANT_ID,
      userId: req.session.userId!,
      requestType: 'vault_kek_rotation',
      description: `Rotate the vault's key-encryption key (current kek_id ${kekId}): ${reason}`,
      payload: { reason, operationId, kekId },
    });
    await writeVaultAudit([{
      tenantId: MASTER_TENANT_ID, userId: req.session.userId, action: 'vault.kek_rotation_requested', resourceType: 'vault_operation',
      resourcePath: operationId, details: { reason, approvalId: approval.id, kekId }, ipAddress: clientIp(req) || undefined,
    }]);
    res.status(202).json({ success: true, data: { approvalId: approval.id, operationId } });
  }));

  // DEK rotation (coffre-secrets §6.6): incident only, never periodic.
  router.post('/dek-rotations', wrap(async (req, res) => {
    const body = (req.body ?? {}) as { tenantId?: unknown; reason?: unknown };
    const tenantId = body.tenantId === null ? null : Number(body.tenantId);
    if (tenantId !== null && !(Number.isSafeInteger(tenantId) && tenantId > 0 && tenantId <= 2147483647)) {
      throw new AppError(400, 'tenantId: a tenant id, or null for the instance key', 'invalidInput');
    }
    const reason = text(body.reason, 'reason', { min: 3, max: 500 });
    if (tenantId !== null) {
      const ids = await vaultInternals.withVaultDb({}, (q) => q.raw('SELECT obligarth.tenant_ids_all() AS ids')) as { rows: Array<{ ids: number[] | null }> };
      if (!(ids.rows[0]?.ids ?? []).map(Number).includes(tenantId)) throw new AppError(404, 'Tenant not found');
    }
    const busy = await vaultInternals.withVaultDb({}, (q) => q('vault_operations').where({ kind: 'dek_rotation' })
      .whereIn('state', ['authorized', 'running', 'failed'])
      .whereRaw("coalesce((params ->> 'tenantId')::int, 0) = coalesce(?::int, 0)", [tenantId]).first('id')) as { id: string } | undefined;
    if (busy) throw new AppError(409, 'A rotation of this key is already in progress (or failed and resumable)', 'rotationInProgress');
    if (!(await strictStepUp(req, res, 'vault.dek_rotation'))) return;
    // The operation and its job together (the job exists iff the operation does).
    const op = await vaultInternals.withVaultDb({}, (q) => q.transaction(async (trx) => {
      const created = await vaultOperations.create(trx, {
        kind: 'dek_rotation', state: 'authorized', tenantId, requestedBy: req.session.userId ?? null, reason,
        params: { tenantId },
      });
      await sendDekRotation(created.id, tenantId, trx);
      return created;
    }));
    const details = { operationId: op.id, tenantId, reason };
    await writeVaultAudit([
      ...(tenantId !== null ? [{ tenantId, userId: req.session.userId, action: 'vault.dek_rotation_requested', resourceType: 'vault', details }] : []),
      {
        tenantId: MASTER_TENANT_ID, userId: req.session.userId, action: 'vault.dek_rotation_requested', resourceType: 'vault_operation',
        resourcePath: op.id, details, ipAddress: clientIp(req) || undefined,
      },
    ]);
    res.status(202).json({ success: true, data: op });
  }));

  return router;
}

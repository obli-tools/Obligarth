import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import type { McpAuthorizationDetail } from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { checkSecondFactor, sendStepUpFailure } from '../../services/deviceKey/stepUpProof';
import { permissionService } from '../../services/permission.service';
import { logger } from '../../utils/logger';
import { accessKeyDetail } from '../audit';
import { effectiveTenantsOf, holdsTenantCapability, type McpCaller } from '../caller';
import { approvedGate } from '../gate';
import { assertDevicesInPerimeter, assertGroupTargetInPerimeter } from '../perimeter';
import { keyInfoOf } from '../keys/service';
import { targetsOf } from '../perimeter';
import { APPROVABLE_ARGS, checkMoveRights, executeLegacy, executeMove, movePreview, type ExecContext, type ExecResult } from '../tools/writes';
import { MCP_SCOPES } from '@obligarth/shared';
import { AUTH_COLUMNS, SCOPE_OF_TOOL, auditState, authorizationView, listOwn, notifyOwner, transition, type AuthorizationRow } from './service';

// =============================================================================
// The authorizations in the console (docs: specs mcp-server §6.2, §6.4),
// mounted at /api/mcp-authorizations after requireAuth and requireTenant:
//   GET  /                   the session user's own rows, every tenant (?state=pending|filed|all)
//   GET  /:id                one of his rows in the session's tenant: the server summary, devices, parameters, the
//                            agent's text apart, and for a move the preview with its devicesToken and impactDigest
//   POST /:id/approve        a fresh second factor (never a trusted IP, a new TOTP step each time), then the action
//                            runs ONCE, as him, rights and the key's perimeter checked again, never the global view
//   POST /:id/deny           no step-up (protective)
// =============================================================================

const router = Router();
const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const jsonOf = (v: unknown): any => { if (typeof v !== 'string') return v ?? null; try { return JSON.parse(v); } catch { return null; } };

router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

/** The keys of the stored arguments that are the agent's text. */
const AGENT_TEXT_KEYS = ['reason', 'title', 'text', 'package_name'];

/** One of the session user's rows in the session's tenant, with its key; 404 otherwise. */
async function ownRow(req: Request): Promise<AuthorizationRow & { key: Record<string, any> | null }> {
  const id = String(req.params.id ?? '');
  if (!UUID_RE.test(id)) throw new AppError(404, 'Authorization not found');
  const row = await db('mcp_authorizations as a').where({ 'a.id': id.toLowerCase(), 'a.tenant_id': req.tenantId!, 'a.user_id': req.session.userId! })
    .first(AUTH_COLUMNS) as AuthorizationRow | undefined;
  if (!row) throw new AppError(404, 'Authorization not found');
  // Its key, read as its owner (identity_self): the session user.
  const key = await db('access_keys').where({ id: row.key_id, user_id: req.session.userId! })
    .first('id', 'public_id', 'name', 'scopes', 'tenant_mode', 'group_mode', 'device_mode', db.raw('ip_allow::text[] AS ip_allow'), 'expires_at',
      'revoked_at', 'credential_version') as Record<string, any> | undefined;
  return { ...row, key: key ?? null };
}

// GET /api/mcp-authorizations?state=pending
router.get('/', wrap(async (req, res) => {
  const state = req.query.state === 'filed' || req.query.state === 'all' ? req.query.state : 'pending';
  res.json({ success: true, data: await listOwn(req.session.userId!, { state, limit: 200 }) });
}));

// GET /api/mcp-authorizations/:id
router.get('/:id', wrap(async (req, res) => {
  const row = await ownRow(req);
  const args = (jsonOf(row.args) ?? {}) as Record<string, unknown>;
  const ids = (Array.isArray(row.device_ids) ? row.device_ids : []).map(Number);
  const U = req.session.userId!;
  const isAdmin = req.session.role === 'admin';
  // Only the devices the human still reads now (a platform administrator bypasses the team checks, as the console).
  const rows = ids.length === 0 ? [] : await db('devices').where({ tenant_id: req.tenantId! }).whereIn('id', ids).select('id', 'label') as Array<{ id: number; label: string | null }>;
  const devices: typeof rows = [];
  for (const d of rows) if (isAdmin || await permissionService.canReadDevice(U, Number(d.id), false)) devices.push(d);
  const agentText: Record<string, string> = {};
  const params: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (AGENT_TEXT_KEYS.includes(k) && typeof v === 'string') agentText[k] = v;
    else params[k] = v;
  }
  const detail: McpAuthorizationDetail = {
    ...authorizationView(row, row.key?.name ?? null, row.key?.public_id ?? null),
    devices: devices.map((d) => ({ id: Number(d.id), name: d.label ?? null })), params, agentText,
  };
  if (row.tool === 'move_devices_to_group' && row.state === 'pending') {
    // The preview only while the human still holds the rights of the move (the console's routes check them before
    // changeDevicesGroup): otherwise none, and the approval ends perimeterLost.
    const groupId = args.group_id === null || args.group_id === undefined ? null : Number(args.group_id);
    const allowed = devices.length === ids.length
      && await checkMoveRights({ userId: U, isPlatformAdmin: isAdmin }, req.tenantId!, ids, groupId).then(() => true, () => false);
    if (allowed) detail.preview = await movePreview(req, req.tenantId!, ids, groupId);
  }
  res.json({ success: true, data: detail });
}));

const MoveEcho = z.object({ devicesToken: z.string().max(4000).nullable().optional(), impactDigest: z.string().regex(/^[0-9a-f]{64}$/) }).strict();

/** The key's caller as of now, for the re-check of its perimeter (the human approving, never the global view). */
function callerOfKey(req: Request, key: Record<string, any>, targets: ReturnType<typeof targetsOf>): McpCaller {
  return {
    userId: req.session.userId!, username: String(req.session.username ?? ''), isPlatformAdmin: req.session.role === 'admin', isSso: false,
    key: keyInfoOf(key), targets, ip: '', requestId: req.requestId ?? '', memo: {},
  };
}

// POST /api/mcp-authorizations/:id/approve
router.post('/:id/approve', wrap(async (req, res) => {
  const row = await ownRow(req);
  const T = req.tenantId!;
  const U = req.session.userId!;
  // 1. Still pending, before its deadline; its key still active and bound to the same credentials.
  if (row.state !== 'pending' || new Date(row.expires_at).getTime() <= Date.now()) {
    throw new AppError(409, 'This authorization is closed', 'authorizationClosed', { state: row.state });
  }
  const user = await db('users').where({ id: U }).first('credential_version') as { credential_version: number } | undefined;
  const keyAlive = !!row.key && !row.key.revoked_at && new Date(row.key.expires_at).getTime() > Date.now()
    && Number(row.key.credential_version) === Number(user?.credential_version);
  if (!keyAlive) {
    const done = await transition(db, String(row.id), ['pending'], 'cancelled', { decided: true, errorCode: 'keyInactive' });
    if (done) { await auditState(done, 'mcp.authorization.cancelled', await audit.fromRequest(req, T), { why: 'key no longer active' }); notifyOwner(done); }
    throw new AppError(409, 'The access key of this authorization is no longer active', 'authorizationClosed');
  }
  const isMove = row.tool === 'move_devices_to_group';
  let echo: z.infer<typeof MoveEcho> | undefined;
  if (isMove) {
    const p = MoveEcho.safeParse(req.body ?? {});
    if (!p.success) throw new AppError(400, 'The preview you approve is required (devicesToken, impactDigest)', 'invalidRequest');
    echo = p.data;
  }
  const deviceIds = (Array.isArray(row.device_ids) ? row.device_ids : []).map(Number);

  // 2. A fresh second factor of the human, for this authorization only (a new TOTP step; never a trusted IP).
  const step = await checkSecondFactor(req, { actionKey: 'mcp.authorization_approve', deviceIds, allowTrustedIp: false, allowDevice: true, requireNewStep: true });
  if (!step.ok) { sendStepUpFailure(res, step); return; }
  if (step.via === 'trusted_ip') throw new AppError(403, 'A second factor is required', 'stepUpRequired');

  // 3. Claimed atomically, committed on its own (a second approval answers 409).
  const claimed = await db('mcp_authorizations').where({ id: row.id, state: 'pending' }).where('expires_at', '>', new Date())
    .update({ state: 'executing', decided_at: new Date(), step_up_via: step.via }).returning('*') as AuthorizationRow[];
  if (!claimed[0]) throw new AppError(409, 'This authorization is closed', 'authorizationClosed');
  const ctx = await audit.fromRequest(req, T);
  ctx.actor.stepUp = step.via;
  await auditState(claimed[0], 'mcp.authorization.approved', ctx, { stepUp: step.via, accessKey: { id: row.key!.public_id, name: row.key!.name } });

  const finish = async (r: ExecResult): Promise<void> => {
    const to = r.state;
    const done = await transition(db, String(row.id), ['executing'], to, {
      ...(r.outcome ? { outcome: r.outcome } : {}), ...(r.errorCode ? { errorCode: r.errorCode } : {}),
    });
    if (done) {
      await auditState(done, `mcp.authorization.${to}`, ctx, { ...(r.outcome ?? {}), ...(r.errorCode ? { errorCode: r.errorCode } : {}) });
      notifyOwner(done);
    }
  };

  try {
    // 4. The key's perimeter now: the tenant, the devices, the scope on the key and its need.
    const targets = targetsOf(await db('access_key_targets').where({ key_id: row.key!.id }).select('kind', 'tenant_id', 'ref_id'));
    const caller = callerOfKey(req, row.key!, targets);
    const scope = SCOPE_OF_TOOL[String(row.tool)];
    const eff = await effectiveTenantsOf(caller);
    let lost = !scope || !eff.tenants.some((t) => t.id === T) || !caller.key.scopes.includes(scope);
    if (!lost) {
      const need = MCP_SCOPES[scope].tenantNeed;
      if (need !== 'membership' && !(await holdsTenantCapability(caller, T, need))) lost = true;
    }
    // 5. Never the global view: every device of the row in this tenant, inside the perimeter; for a move, the target
    //    group too (re-parented out of the key's groups meanwhile, or null under a group list: lost).
    if (!lost) {
      try {
        await assertDevicesInPerimeter(caller, T, deviceIds);
        if (isMove) {
          const g = (jsonOf(row.args) ?? {}) as { group_id?: unknown };
          await assertGroupTargetInPerimeter(caller, T, g.group_id === null || g.group_id === undefined ? null : Number(g.group_id));
        }
      } catch { lost = true; }
    }
    const schema = APPROVABLE_ARGS[String(row.tool)];
    const parsedArgs = isMove ? { success: true as const, data: jsonOf(row.args) } : schema?.safeParse(jsonOf(row.args));
    if (lost || !parsedArgs || !parsedArgs.success) {
      await finish({ state: 'failed', errorCode: 'perimeterLost' });
      throw new AppError(409, 'The action is no longer within the rights or the perimeter of the key', 'perimeterLost');
    }
    // 6. Executed as the human, once: the restriction's 'sensitive' step stands proven for this action key only.
    req.stepUpVia = step.via;
    req.stepUpVerified = {
      via: step.via,
      actionKeys: new Set([String(row.action_key), ...(isMove ? ['mdm.policy_publish', 'device.bulk_group_change'] : [])]),
    };
    const prefix = `[AI agent, access key ${row.key!.name} (${row.key!.public_id}), approved by its owner] `;
    let finishedInTx = false;
    const x: ExecContext = {
      req, row, args: parsedArgs.data as Record<string, any>,
      consoleCaller: { userId: U, isPlatformAdmin: req.session.role === 'admin', tenantId: T, auditCtx: ctx, idempotencyKey: `mcp-auth:${row.id}` },
      gate: approvedGate(req, prefix),
      descriptionPrefix: prefix,
      finishInTx: async (trx, outcome) => {
        await trx('mcp_authorizations').where({ id: row.id, state: 'executing' }).update({ state: 'executed', outcome: JSON.stringify(outcome) });
        await audit.appendInTx(trx, {
          tenantId: T, action: 'mcp.tool.write', targets: deviceIds.length ? { deviceIds } : undefined,
          details: { tool: row.tool, mcpAuthorizationId: String(row.id), accessKey: accessKeyDetail(caller), reasonSource: 'agent', ...outcome },
        }, ctx, { onFailure: 'spool' });
        finishedInTx = true;
      },
      echo,
    };
    const r = isMove ? await executeMove(x) : await executeLegacy(x);
    if (finishedInTx) {
      const done = await db('mcp_authorizations').where({ id: row.id }).first('*') as AuthorizationRow | undefined;
      if (done) { await auditState(done, 'mcp.authorization.executed', ctx, r.outcome ?? {}); notifyOwner(done); }
    } else {
      await finish(r);
    }
    if (r.state === 'failed' && r.errorCode === 'impactChanged') {
      throw new AppError(409, 'The impact of the move changed since you saw it: nothing was moved', 'impactChanged');
    }
    const fresh = await db('mcp_authorizations as a').where({ 'a.id': row.id }).first(AUTH_COLUMNS) as AuthorizationRow;
    res.json({ success: true, data: authorizationView(fresh, row.key!.name, row.key!.public_id) });
  } catch (err) {
    // Anything else: the row ends 'failed' (never left 'executing'); the error goes to the handler.
    const still = await db('mcp_authorizations').where({ id: row.id }).first('state') as { state: string } | undefined;
    if (still?.state === 'executing') {
      const code = err instanceof AppError ? (err.code ?? `refused${err.statusCode}`) : 'error';
      await finish({ state: 'failed', errorCode: code }).catch((e) => logger.error({ err: e }, 'mcp: authorization not closed'));
    }
    throw err;
  }
}));

// POST /api/mcp-authorizations/:id/deny
router.post('/:id/deny', wrap(async (req, res) => {
  const row = await ownRow(req);
  const done = await transition(db, String(row.id), ['pending'], 'denied', { decided: true });
  if (!done) throw new AppError(409, 'This authorization is closed', 'authorizationClosed', { state: row.state });
  await auditState(done, 'mcp.authorization.denied', await audit.fromRequest(req, req.tenantId!));
  notifyOwner(done);
  res.json({ success: true, data: authorizationView(done, row.key?.name ?? null, row.key?.public_id ?? null) });
}));

/** The authorizations of the console, mounted at /api/mcp-authorizations (routes/index.ts), after requireTenant. */
export function createMcpAuthorizationsRouter(): Router {
  return router;
}

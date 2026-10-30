import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { MASTER_TENANT_ID, isMasterTenant, type McpSettingsView } from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { switchToIdentity } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { applyRestriction } from '../services/restriction.service';
import { neverBlockReason } from '../security/neverBlock';
import { clientAddress } from '../utils/clientIp';
import { blockAddress, blockView, obliguard, unblock } from './blocks';
import { currentPolicy, invalidatePolicy, refreshPolicy } from './ipPolicy';
import { parseCidr } from './ipUtil';
import { keysOfUser, keyView, revokeKey } from './keys/service';
import { forgetMcpSettings, mcpSettings, tenantIpPolicies } from './settings';

// =============================================================================
// The platform side of the MCP server (docs: specs mcp-server §6.1), mounted at
// /api/admin/mcp: the master tenant (404 elsewhere), a platform administrator
// (403 otherwise). Changes of the settings, of a tenant's IP policy, and the
// manual blocks and unblocks go through their restriction (floor sensitive,
// strict step-up: never a trusted IP). Revoking a key is protective (no step-up).
//   GET/PUT  /settings                  instance settings (with the current IP mode, active and open keys)
//   GET/PUT  /tenant-policies/:tenantId inherit | force | exempt
//   GET      /blocks, POST /blocks (manual), POST /blocks/:id/unblock
//   GET      /keys?userId=, DELETE /keys/:publicId
//   POST     /obliguard/test
// =============================================================================

function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

const SettingsBody = z.object({
  forceIpAllowList: z.boolean(), minPrefixV4: z.number().int().min(8).max(32), minPrefixV6: z.number().int().min(32).max(128),
  failureThreshold: z.number().int().min(3).max(100), failureWindowSeconds: z.number().int().min(60).max(86_400),
  blockSeconds: z.number().int().min(300).max(31_536_000), knownIpDays: z.number().int().min(0).max(365),
  maxNewBlocksPerMinute: z.number().int().min(5).max(1000), prefixBlockThreshold: z.number().int().min(2).max(64),
  keyRequestsPerMinute: z.number().int().min(10).max(6000), authorizationMinutes: z.number().int().min(2).max(60),
  maxPendingPerKey: z.number().int().min(1).max(50), maxPendingPerUser: z.number().int().min(1).max(200),
  maxCreatedPerKeyHour: z.number().int().min(1).max(500), obliguardEnabled: z.boolean(),
  obliguardUrl: z.string().trim().max(500).regex(/^https{0,1}:\/\/[^@ ]+$/).nullable(),
  neverBlock: z.array(z.string().max(64)).max(256),
}).strict();

const PolicyBody = z.object({ forceIpAllowList: z.enum(['inherit', 'force', 'exempt']) }).strict();
const ManualBlockBody = z.object({ ip: z.string().max(64), reason: z.string().trim().min(3).max(300), days: z.number().int().min(1).max(3650).nullable() }).strict();

async function settingsView(): Promise<McpSettingsView> {
  const s = await mcpSettings(true);
  const p = currentPolicy() ?? await refreshPolicy();
  return { ...s, mode: p.mode, activeKeys: p.activeKeys, openKeys: p.openKeys };
}

export function createMcpAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);
  router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  router.get('/settings', wrap(async (_req, res) => {
    res.json({ success: true, data: await settingsView() });
  }));

  router.put('/settings', wrap(async (req, res) => {
    const p = SettingsBody.safeParse(req.body ?? {});
    if (!p.success) throw new AppError(400, p.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
    const b = p.data;
    const never = b.neverBlock.map((x) => parseCidr(x));
    if (never.some((c) => !c)) throw new AppError(422, 'Invalid address or network in the never-block list', 'invalidIpAllow');
    if (!(await applyRestriction(res, { req, actionKey: 'mcp.settings_change' }))) return;
    const before = await mcpSettings(true);
    const ctx = await audit.fromRequest(req, MASTER_TENANT_ID);
    await switchToIdentity(() => db.transaction(async (trx) => {
      await trx('mcp_settings').where({ id: 1 }).update({
        force_ip_allowlist: b.forceIpAllowList, min_prefix_v4: b.minPrefixV4, min_prefix_v6: b.minPrefixV6, failure_threshold: b.failureThreshold,
        failure_window_s: b.failureWindowSeconds, block_seconds: b.blockSeconds, known_ip_days: b.knownIpDays,
        max_new_blocks_per_min: b.maxNewBlocksPerMinute, prefix_block_threshold: b.prefixBlockThreshold, key_rpm: b.keyRequestsPerMinute,
        authorization_minutes: b.authorizationMinutes, max_pending_per_key: b.maxPendingPerKey, max_pending_per_user: b.maxPendingPerUser,
        max_created_per_key_hour: b.maxCreatedPerKeyHour, obliguard_enabled: b.obliguardEnabled, obliguard_url: b.obliguardUrl,
        never_block: trx.raw('?::cidr[]', [never.map((c) => c!.text)]), updated_at: new Date(), updated_by: req.session.userId!,
      });
      const changed = Object.keys(b).filter((k) => JSON.stringify((before as unknown as Record<string, unknown>)[k]) !== JSON.stringify((b as Record<string, unknown>)[k]));
      await audit.appendInTx(trx, { tenantId: MASTER_TENANT_ID, action: 'mcp.settings.changed', details: { changed } }, ctx);
    }));
    forgetMcpSettings();
    obliguard.reset();
    invalidatePolicy();
    res.json({ success: true, data: await settingsView() });
  }));

  router.get('/tenant-policies/:tenantId', wrap(async (req, res) => {
    const t = Number(req.params.tenantId);
    const map = await tenantIpPolicies(true);
    res.json({ success: true, data: { tenantId: t, forceIpAllowList: map.get(t) ?? 'inherit' } });
  }));

  router.put('/tenant-policies/:tenantId', wrap(async (req, res) => {
    const t = Number(req.params.tenantId);
    if (!Number.isSafeInteger(t) || t <= 0) throw new AppError(404, 'Tenant not found');
    const p = PolicyBody.safeParse(req.body ?? {});
    if (!p.success) throw new AppError(400, p.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
    const exists = await db('tenants').where({ id: t }).first('id');
    if (!exists) throw new AppError(404, 'Tenant not found');
    if (!(await applyRestriction(res, { req, actionKey: 'mcp.settings_change' }))) return;
    const ctx = await audit.fromRequest(req, t);
    await switchToIdentity(() => db('mcp_tenant_policies').insert({
      tenant_id: t, force_ip_allowlist: p.data.forceIpAllowList, updated_at: new Date(), updated_by: req.session.userId!,
    }).onConflict('tenant_id').merge(['force_ip_allowlist', 'updated_at', 'updated_by']));
    try {
      await audit.append({ tenantId: t, action: 'mcp.tenant_policy.changed', target: { type: 'tenant', id: String(t) }, details: { forceIpAllowList: p.data.forceIpAllowList } }, ctx);
    } catch (err) {
      throw new AppError(503, 'Audit unavailable: the change was written but not journaled', 'auditUnavailable', { cause: (err as Error).message?.slice(0, 100) });
    }
    forgetMcpSettings();
    invalidatePolicy();
    res.json({ success: true, data: { tenantId: t, forceIpAllowList: p.data.forceIpAllowList } });
  }));

  router.get('/blocks', wrap(async (req, res) => {
    const active = req.query.active !== '0';
    const rows = await switchToIdentity(() => {
      const q = db('mcp_ip_blocks').orderBy('id', 'desc').limit(1000).select('*');
      if (active) q.where({ active: true });
      return q;
    }) as Array<Record<string, any>>;
    res.json({ success: true, data: rows.map(blockView) });
  }));

  router.post('/blocks', wrap(async (req, res) => {
    const p = ManualBlockBody.safeParse(req.body ?? {});
    if (!p.success) throw new AppError(400, p.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
    const c = parseCidr(p.data.ip);
    if (!c || c.prefix !== (c.family === 4 ? 32 : 128)) throw new AppError(422, 'A single address is expected', 'invalidIp');
    const s = await mcpSettings();
    const operator = clientAddress(req).ip;
    const guard = neverBlockReason({ ip: c.network, relay: false, untrustedForwarder: false }, s.neverBlock, { operatorIp: operator });
    if (guard) throw new AppError(422, `This address is never blocked (${guard})`, 'neverBlock', { reason: guard });
    if (!(await applyRestriction(res, { req, actionKey: 'mcp.ip_block' }))) return;
    await blockAddress({
      ip: c.network, source: 'manual', reason: p.data.reason, until: p.data.days === null ? null : new Date(Date.now() + p.data.days * 86_400_000),
      ctx: await audit.fromRequest(req, MASTER_TENANT_ID),
    });
    res.status(201).json({ success: true, data: { blocked: c.network } });
  }));

  router.post('/blocks/:id/unblock', wrap(async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id <= 0) throw new AppError(404, 'Block not found');
    if (!(await applyRestriction(res, { req, actionKey: 'mcp.ip_unblock' }))) return;
    const done = await unblock(id, req.session.userId!, await audit.fromRequest(req, MASTER_TENANT_ID));
    if (!done) throw new AppError(404, 'Block not found');
    res.json({ success: true, data: { unblocked: true } });
  }));

  router.get('/keys', wrap(async (req, res) => {
    const userId = Number(req.query.userId);
    let users: number[];
    if (Number.isSafeInteger(userId) && userId > 0) users = [userId];
    else users = (await switchToIdentity(() => db('access_keys').distinct('user_id').limit(1000).pluck('user_id')) as number[]).map(Number);
    const out = [];
    for (const u of users) {
      const owner = await switchToIdentity(() => db('users').where({ id: u }).first('id', 'username', 'role')) as { id: number; username: string; role: string } | undefined;
      if (!owner) continue;
      for (const k of await keysOfUser(u, false)) {
        out.push({ owner: { userId: owner.id, username: owner.username }, ...(await keyView(k.row, k.targets, owner.id, owner.role === 'admin')) });
      }
    }
    res.json({ success: true, data: out });
  }));

  router.delete('/keys/:publicId', wrap(async (req, res) => {
    const publicId = String(req.params.publicId ?? '');
    if (!/^[a-z0-9]{12}$/.test(publicId)) throw new AppError(404, 'Access key not found');
    const row = await switchToIdentity(() => db('access_keys').where({ public_id: publicId }).first('id')) as { id: string } | undefined;
    if (!row) throw new AppError(404, 'Access key not found');
    const revoked = await revokeKey(String(row.id), 'admin', req.session.userId!, await audit.fromRequest(req, MASTER_TENANT_ID));
    res.json({ success: true, data: { revoked } });
  }));

  router.post('/obliguard/test', wrap(async (_req, res) => {
    obliguard.reset();
    const r = await obliguard.ping();
    res.json({ success: true, data: r });
  }));

  return router;
}

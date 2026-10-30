import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { MCP_KEY_BOUNDS, MCP_SCOPE_KEYS, type AccessKeyCreated, type AccessKeyOptions } from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { applyRestriction } from '../../services/restriction.service';
import { clientAddress } from '../../utils/clientIp';
import { currentPolicy } from '../ipPolicy';
import { mcpSettings, tenantForcesIp, tenantIpPolicies } from '../settings';
import {
  createKey, creatableTenants, excludeTenant, hasStepUpFactor, keysCoveringTenant, keysOfUser, keyView, offerableScopes, oversightView, revokeOwnKey,
} from './service';

// =============================================================================
// Personal access keys in the console (docs: specs mcp-server §6.1), mounted at
// /api/access-keys after requireAuth and requireTenant. Every answer carries
// Cache-Control: no-store.
//   GET    /                                   the session user's own keys (every tenant), never a hash
//   GET    /options                            what he may put in a key (mcp.access_keys in the current tenant)
//   POST   /                                   a new key: mcp.access_keys in every listed tenant, scopes and
//                                              perimeters within his rights, restriction access_keys.create (floor
//                                              sensitive, strict: a fresh factor); the token is answered ONCE
//   DELETE /:publicId                          his own key revoked (never deleted)
//   GET    /tenant-oversight                   users.manage: the keys whose effective perimeter covers the tenant
//                                              (no IP, no last address)
//   POST   /tenant-oversight/:publicId/exclude users.manage: the tenant excluded from that key (protective)
// =============================================================================

const router = Router();
const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };
const PUBLIC_ID_RE = /^[a-z0-9]{12}$/;

router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

const isAdmin = (req: Request): boolean => req.session.role === 'admin';

const CreateBody = z.object({
  name: z.string().trim().min(1).max(MCP_KEY_BOUNDS.nameMax),
  expiresInDays: z.number().int().min(1).max(MCP_KEY_BOUNDS.expiryDaysMax),
  scopes: z.array(z.enum(MCP_SCOPE_KEYS as [string, ...string[]])).max(32),
  tenants: z.object({ mode: z.enum(['all', 'list']), ids: z.array(z.number().int().positive()).max(500).optional() }).strict(),
  groups: z.object({
    mode: z.enum(['all', 'list']), items: z.array(z.object({ tenantId: z.number().int().positive(), groupId: z.number().int().positive() }).strict()).max(500).optional(),
  }).strict(),
  devices: z.object({
    mode: z.enum(['all', 'list']), items: z.array(z.object({ tenantId: z.number().int().positive(), deviceId: z.number().int().positive() }).strict()).max(2000).optional(),
  }).strict(),
  ipAllow: z.array(z.string().max(64)).max(MCP_KEY_BOUNDS.ipAllowMax),
}).strict();

// GET /api/access-keys
router.get('/', wrap(async (req, res) => {
  const U = req.session.userId!;
  const keys = await keysOfUser(U);
  const out = [];
  for (const k of keys) out.push(await keyView(k.row, k.targets, U, isAdmin(req)));
  res.json({ success: true, data: out });
}));

// GET /api/access-keys/options
router.get('/options', requireTenantCapability('mcp.access_keys'), wrap(async (req, res) => {
  const U = req.session.userId!;
  const s = await mcpSettings(true);
  const policies = await tenantIpPolicies(true);
  const tenants = await creatableTenants(U, isAdmin(req));
  const user = await db('users').where({ id: U }).first('totp_enabled', 'totp_secret_enc', 'foreign_source', 'foreign_id') as Record<string, unknown> | undefined;
  const out: AccessKeyOptions = {
    tenants: [], minPrefixV4: s.minPrefixV4, minPrefixV6: s.minPrefixV6, maxExpiryDays: MCP_KEY_BOUNDS.expiryDaysMax,
    ipMode: currentPolicy()?.mode ?? 'rate', hasStepUpFactor: !!user && hasStepUpFactor(user),
  };
  for (const t of tenants) {
    out.tenants.push({ tenantId: t.id, name: t.name, scopes: await offerableScopes(U, isAdmin(req), t.id), forceIpAllowList: tenantForcesIp(t.id, s, policies) });
  }
  res.json({ success: true, data: out });
}));

// POST /api/access-keys
router.post('/', requireTenantCapability('mcp.access_keys'), wrap(async (req, res) => {
  const parsed = CreateBody.safeParse(req.body ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  const body = parsed.data;
  const U = req.session.userId!;
  const tenantIds = body.tenants.mode === 'list' ? [...new Set(body.tenants.ids ?? [])] : (await creatableTenants(U, isAdmin(req))).map((t) => t.id);
  // A credential is only minted with a fresh factor (floor sensitive, strict: never a trusted IP), the level the
  // strictest of the tenants of the key.
  const ok = await applyRestriction(res, { req, actionKey: 'access_keys.create', levelTenantIds: tenantIds.slice(0, 200), approvalInRequestTenant: true });
  if (!ok) return;
  const auditCtx = await audit.fromRequest(req, req.tenantId!);
  const created = await createKey({
    userId: U, isPlatformAdmin: isAdmin(req), body: body as never, createdIp: clientAddress(req).ip || null, sessionTenantId: req.tenantId!, auditCtx,
  });
  const out: AccessKeyCreated = { key: await keyView(created.row, created.targets, U, isAdmin(req)), token: created.token };
  res.status(201).json({ success: true, data: out });
}));

// GET /api/access-keys/tenant-oversight
router.get('/tenant-oversight', requireTenantCapability('users.manage'), wrap(async (req, res) => {
  const keys = await keysCoveringTenant(req.tenantId!);
  res.json({ success: true, data: keys.map(oversightView) });
}));

// POST /api/access-keys/tenant-oversight/:publicId/exclude
router.post('/tenant-oversight/:publicId/exclude', requireTenantCapability('users.manage'), wrap(async (req, res) => {
  const publicId = String(req.params.publicId ?? '');
  if (!PUBLIC_ID_RE.test(publicId)) throw new AppError(404, 'Access key not found');
  const done = await excludeTenant(publicId, req.tenantId!, req.session.userId!, await audit.fromRequest(req, req.tenantId!));
  if (!done) throw new AppError(404, 'Access key not found');
  res.json({ success: true, data: { excluded: true } });
}));

// DELETE /api/access-keys/:publicId
router.delete('/:publicId', wrap(async (req, res) => {
  const publicId = String(req.params.publicId ?? '');
  if (!PUBLIC_ID_RE.test(publicId)) throw new AppError(404, 'Access key not found');
  const revoked = await revokeOwnKey(req.session.userId!, publicId, await audit.fromRequest(req, req.tenantId!));
  res.json({ success: true, data: { revoked } });
}));

/** The keys of the console, mounted at /api/access-keys (routes/index.ts), after requireTenant. */
export function createAccessKeysRouter(): Router {
  return router;
}

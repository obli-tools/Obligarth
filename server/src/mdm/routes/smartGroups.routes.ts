import { Router, type Request, type Response } from 'express';
import rateLimit, { MemoryStore } from 'express-rate-limit';
import { z } from 'zod';
import {
  SMART_GROUP_LIMITS, canonicalRule, ruleSha256, type SmartGroupDeletePreview, type SmartGroupGovernedOutcome,
} from '@obligarth/shared';
import { db } from '../../db';
import { audit } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { deviceService } from '../../services/device.service';
import { parseError } from '../../services/deviceListFilters';
import { permissionService } from '../../services/permission.service';
import { changeSmartGroup } from '../groups/governance';
import {
  SmartGroupCreateBody, SmartGroupPatchBody, SmartGroupPreviewBody, isTargeted, parseBody, smartGroupNotFound, smartGroupService,
  type SmartGroupCaller,
} from '../groups/smartGroupService';
import { visibleDevices, type RouteOutcome } from '../policies/publishGuard';

// =============================================================================
// Dynamic groups (P0-5 T4, §4.2; D3, D8, D10): mounted at /api/mdm/smart-groups, in the tenant of the session (one
// tenant per group: no global view). Reads and the preview of a rule: membership of the tenant (a dynamic group gives
// no team scope, D8; the counts and the sample of a non-administrator cover only the devices their teams see, D3; an
// administrator of the tenant or of the platform counts every device, as the governed circuit does). The members
// themselves are listed as the device list shows them (GET /api/mdm/devices?smartGroupId=: its team scopes, a platform
// administrator every device).
// Writes: the capability groups.manage. A group of another tenant, or unknown, answers 404 (smartGroupNotFound). The
// preview is limited in rate (30 a minute per user), and so is every route that computes a rule on the tenant or
// writes members (creation, change, deletion, release, their previews: 20 a minute per user, a bucket of their own).
// A group an assignment targets (P0-5 T7, groups/governance.ts): a new rule, its deletion and the release of a held
// group go through the governed circuit (preview of the entries, exits and keys, step-up, second approver beyond the
// thresholds of DM23, 202), by an administrator of the tenant only (D3: 403 smartGroupAdminOnly).
// =============================================================================

const router = Router();

const keyOfUser = (req: Request): string => `u:${req.session?.userId ?? 'anonymous'}`;
const limited = (res: Response): void => { res.status(429).json({ success: false, error: 'Too many requests', code: 'rateLimited' }); };
const previewStore = new MemoryStore();
const writeStore = new MemoryStore();
/** 30 previews a minute per user: each one runs the rule on the devices of the tenant. */
const previewLimiter = rateLimit({
  windowMs: 60_000, max: 30, keyGenerator: keyOfUser, store: previewStore, standardHeaders: true, legacyHeaders: false, handler: (_q, res) => limited(res),
});
/** 20 writes (and their previews) a minute per user: each one computes a rule on the devices of the tenant, writes the
 *  entries and exits with their journal, or previews their impact on the configuration. */
const writeLimiter = rateLimit({
  windowMs: 60_000, max: 20, keyGenerator: keyOfUser, store: writeStore, standardHeaders: true, legacyHeaders: false, handler: (_q, res) => limited(res),
});

/** Every budget of these routes given back (the testbed between its essays: they write more than a user would). */
export async function resetSmartGroupRateLimits(): Promise<void> {
  await previewStore.resetAll();
  await writeStore.resetAll();
}

/** ?dryRun=true (or 1): the preview of a deletion, a new rule or a release only, nothing written. */
const isDryRun = (req: Request): boolean => req.query.dryRun === 'true' || req.query.dryRun === '1';

/** The group of the route: a positive id (anything else answers like an unknown group). */
function idOf(req: Request): number {
  const s = String(req.params.id ?? '');
  if (!/^[1-9][0-9]{0,9}$/.test(s) || Number(s) > 2_147_483_647) throw smartGroupNotFound();
  return Number(s);
}

/** The caller: their tenant and account, and the devices their teams see (an administrator of the tenant or of the
 *  platform: every one, as publishGuard.visibleDevices says for the governed circuit). */
async function callerOf(req: Request): Promise<SmartGroupCaller> {
  const userId = Number(req.session.userId);
  const visible = await visibleDevices(req);
  return { tenantId: req.tenantId!, userId, visibleIds: visible === 'all' ? undefined : visible, admin: visible === 'all' };
}

const pageParam = z.preprocess((v) => (v === undefined || v === '' ? undefined : Number(v)), z.number().int().positive().max(1_000_000).optional());
const MembersQuery = z.object({
  page: pageParam,
  pageSize: z.preprocess((v) => (v === undefined || v === '' ? undefined : Number(v)),
    z.number().int().positive().max(SMART_GROUP_LIMITS.membersPageMax).optional()),
}).passthrough();

// GET /api/mdm/smart-groups — the groups of the tenant.
router.get('/', async (req, res, next) => {
  try {
    res.json({ data: await smartGroupService.list(await callerOf(req)) });
  } catch (err) { next(err); }
});

// POST /api/mdm/smart-groups/preview — { rule, smartGroupId? }: what the rule selects, nothing written.
router.post('/preview', previewLimiter, async (req, res, next) => {
  try {
    const b = parseBody(SmartGroupPreviewBody, req.body);
    res.json({ data: await smartGroupService.preview(await callerOf(req), b) });
  } catch (err) { next(err); }
});

// GET /api/mdm/smart-groups/:id
router.get('/:id', async (req, res, next) => {
  try {
    const group = await smartGroupService.get(await callerOf(req), idOf(req));
    if (!group) throw smartGroupNotFound();
    res.json({ data: group });
  } catch (err) { next(err); }
});

// GET /api/mdm/smart-groups/:id/members?page=&pageSize= — the members, as the device list shows them (its team scopes).
router.get('/:id/members', async (req, res, next) => {
  try {
    const id = idOf(req);
    const parsed = MembersQuery.safeParse(req.query);
    if (!parsed.success) throw parseError(parsed.error);
    const c = await callerOf(req);
    if (!(await smartGroupService.get(c, id))) throw smartGroupNotFound();
    // The device list's scopes: a tenant administrator lists the devices of their teams there too.
    const listed = req.session.role === 'admin' ? undefined : await permissionService.getVisibleDeviceIds(c.userId, false);
    res.json({
      data: await deviceService.listDevices(c.tenantId, {
        smartGroupId: id, page: parsed.data.page, pageSize: parsed.data.pageSize ?? 100, visibleIds: listed,
      }),
    });
  } catch (err) { next(err); }
});

// POST /api/mdm/smart-groups — { name, description?, rule }: the members computed in the request.
router.post('/', requireTenantCapability('groups.manage'), writeLimiter, async (req, res, next) => {
  try {
    const b = parseBody(SmartGroupCreateBody, req.body);
    const out = await smartGroupService.create(await callerOf(req), b, await audit.fromRequest(req, req.tenantId!));
    res.status(201).json({ data: out });
  } catch (err) { next(err); }
});

/** A governed outcome as the route answers it (its challenge headers included). */
function send(res: Response, out: RouteOutcome): void {
  if (out.headers) res.set(out.headers);
  res.status(out.status).json(out.body);
}

// PATCH /api/mdm/smart-groups/:id[?dryRun=true] — the fields to change; a new rule computes the members again in the
// request. A new rule for a group an assignment targets goes through the governed circuit (P0-5 T7: preview, step-up,
// second approver beyond DM23; a tenant administrator only, D3); ?dryRun=true previews a new rule, targeted or not.
router.patch('/:id', requireTenantCapability('groups.manage'), writeLimiter, async (req, res, next) => {
  try {
    const id = idOf(req);
    const b = parseBody(SmartGroupPatchBody, req.body);
    const c = await callerOf(req);
    const dryRun = isDryRun(req);
    if (b.rule !== undefined) {
      const g = await smartGroupService.get(c, id);
      if (!g) throw smartGroupNotFound();
      const rule = canonicalRule(b.rule);
      const sha = ruleSha256(rule);
      if (sha !== g.ruleSha256 && (g.assignmentCount > 0 || dryRun)) {
        send(res, await changeSmartGroup(req, { kind: 'smart_group_rule', smartGroupId: id, rule, ruleSha256: sha },
          { name: b.name, description: b.description }, dryRun));
        return;
      }
    }
    if (dryRun) throw new AppError(400, 'A preview is that of a new rule', 'invalidRequest', { field: 'rule' });
    const out = await smartGroupService.update(c, id, b, await audit.fromRequest(req, req.tenantId!));
    res.json({ data: out });
  } catch (err) { next(err); }
});

// POST /api/mdm/smart-groups/:id/release[?dryRun=true] — a group held by the mass guard (D4): its pending changes
// applied, through the governed circuit (P0-5 T7). 409 smartGroupNotHeld.
router.post('/:id/release', requireTenantCapability('groups.manage'), writeLimiter, async (req, res, next) => {
  try {
    const id = idOf(req);
    send(res, await changeSmartGroup(req, { kind: 'smart_group_release', smartGroupId: id }, {}, isDryRun(req)));
  } catch (err) { next(err); }
});

// DELETE /api/mdm/smart-groups/:id (?dryRun=true: what the deletion would do). A group an assignment targets goes
// through the governed circuit (P0-5 T7): its preview adds the entries and exits and the impact.
router.delete('/:id', requireTenantCapability('groups.manage'), writeLimiter, async (req, res, next) => {
  try {
    const id = idOf(req);
    const c = await callerOf(req);
    const targeted = await isTargeted(db, c.tenantId, id);
    if (isDryRun(req)) {
      const counts = await smartGroupService.deletePreview(c, id);
      if (!targeted) { res.json({ data: counts }); return; }
      const out = await changeSmartGroup(req, { kind: 'smart_group_delete', smartGroupId: id }, {}, true);
      const governed = (out.body as { data: Extract<SmartGroupGovernedOutcome, { outcome: 'preview' }> }).data;
      const data: SmartGroupDeletePreview = { ...counts, membership: governed.membership, impact: governed.impact };
      res.json({ data });
      return;
    }
    if (targeted) {
      send(res, await changeSmartGroup(req, { kind: 'smart_group_delete', smartGroupId: id }, {}, false));
      return;
    }
    await smartGroupService.remove(c, id, await audit.fromRequest(req, req.tenantId!));
    res.json({ data: { deleted: true } });
  } catch (err) { next(err); }
});

export default router;

import { createHash } from 'node:crypto';
import type { Request, Response } from 'express';
import { z } from 'zod';
import { SITE_LIMITS as L, SITE_VALUE_KEY_RE } from '@obligarth/shared';
import { audit, canonicalJson } from '../audit';
import { db } from '../db';
import { userActor } from '../db/context';
import { beyondThresholds } from '../legacyAgent/policyRoutes';
import { AppError } from '../middleware/errorHandler';
import { approvalService, refuse, requireTenantCapability as requesterHolds, type ApprovalExecution } from '../services/approval.service';
import { permissionService } from '../services/permission.service';
import { applyRestriction } from '../services/restriction.service';
import { consumeBatch, usableBatch } from './batches';
import type { SiteRow } from './model';
import { applyFromDevices, applyImport, planChanged, requireWritesOf, updateSite, type SiteWho } from './service';

// =============================================================================
// The guard of the writes of the sites that change what the bridge agent renders (lot P1-SITE, review): a value of a
// site is read by {{device.custom.<key>}} and {{site.<key>}} on every device of the site, so changing it rewrites the
// files deposited on them, as the import of per-device values does (legacyAgent/policyRoutes.ts, D18). The same rules:
//   - mdm.policies.manage on top of devices.manage;
//   - the restrictable action sites.apply (floor 'sensitive': a second factor; 'restricted': a second person);
//   - beyond the publication thresholds of its policy impact (the devices whose agent:policy changes), a second person
//     approves it (approval request site_write), executed again as its requester, his rights read again, the plan
//     compared with the one he saw (planChanged otherwise: nothing applied).
// What it guards: a change of the code, name, city or values of a site (PATCH /api/sites/:id, upsert_site), an applied
// import, the sites made from the custom fields. A new site (no device yet), its contact or its group are not guarded;
// the site of one device is a write on that device (devices.manage and write access on it, as a move of group).
// =============================================================================

export const SITES_APPLY = 'sites.apply';
export const SITE_WRITE_APPROVAL = 'site_write' as const;
export const POLICY_MANAGE = 'mdm.policies.manage' as const;
/** The tool of a console import kept for its approval (its CSV text does not fit in the sealed part). */
export const CONSOLE_IMPORT_TOOL = 'console_import';

export const SITES_RESTRICTABLE_ACTIONS = [
  { key: SITES_APPLY, label: 'Change the values of sites read by the Android agent templates (a site, an import, the sites from the custom fields)', category: 'Sites' },
] as const;

const sha256 = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');
/** The digest of a site as a change read it (the approval of a change refuses a site changed since). */
export const prevDigestOf = (s: SiteRow): string => sha256(canonicalJson(s as never));

const key = z.string().regex(SITE_VALUE_KEY_RE);
const hex = z.string().regex(/^[0-9a-f]{64}$/);
const text = (max: number) => z.string().max(max * 2);
/** The body of a change of a site, as the route validated it. */
export const SiteChangeBody = z.object({
  code: text(L.codeMax).optional(), name: text(L.nameMax).optional(), city: text(L.cityMax).nullable().optional(),
  contact: text(L.contactMax).nullable().optional(), groupId: z.number().int().positive().nullable().optional(),
  values: z.record(z.string().max(L.valueMax * 2)).optional(),
}).strict();
const Sealed = z.discriminatedUnion('op', [
  z.object({ op: z.literal('update'), siteId: z.string().uuid(), body: SiteChangeBody, prevDigest: hex, source: z.enum(['console', 'mcp']).optional() }).strict(),
  z.object({ op: z.literal('import'), batchId: z.string().uuid(), digest: hex, source: z.enum(['console', 'mcp']).optional() }).strict(),
  z.object({
    op: z.literal('from_devices'), keys: z.object({ code: key, name: key, values: z.array(key).max(L.valuesMax) }).strict(), digest: hex,
    source: z.enum(['console', 'mcp']).optional(),
  }).strict(),
]);
export type SiteWriteSealed = z.infer<typeof Sealed>;

/** Write access on the group a site names (403 otherwise), as a move into it (POST /api/mdm/devices/:id/group). */
export async function requireGroupWrite(who: SiteWho, groupId: number | null | undefined): Promise<void> {
  if (groupId === null || groupId === undefined || who.admin) return;
  if (!(await permissionService.canWriteGroup(who.userId, groupId, false))) throw new AppError(403, 'No write permission on target group');
}

/** The human of a console request. */
export const whoOf = (req: Request): SiteWho => ({ userId: req.session.userId!, admin: req.session.role === 'admin' });

/** mdm.policies.manage, for the console (403 capabilityMissing otherwise). */
export async function requirePolicyManage(req: Request, tenantId: number): Promise<void> {
  if (req.session.role === 'admin') return;
  if (!(await permissionService.userHasTenantCapability(req.session.userId!, tenantId, POLICY_MANAGE))) {
    throw new AppError(403, 'Changing the values of sites needs the right to manage the policies', 'sitePolicyRightMissing');
  }
}

export interface SiteGuardInput {
  tenantId: number;
  /** The devices the write reaches (the scope of the restriction). */
  deviceIds: number[];
  /** Devices whose agent:policy the write changes. */
  impact: number;
  description: string;
  payload: Record<string, unknown>;
  sealed: SiteWriteSealed;
}

/**
 * The console's guard of a write of the sites (sites.apply, then the thresholds): true when the route may apply it;
 * false when the answer is sent (a second factor asked, or 202 with the approval filed for a second person).
 */
export async function guardSiteWrite(req: Request, res: Response, g: SiteGuardInput): Promise<boolean> {
  const payload = { action: SITES_APPLY, ...g.payload, policyImpact: g.impact, deviceIds: g.deviceIds.slice(0, 500) };
  const ok = await applyRestriction(res, {
    req, actionKey: SITES_APPLY, deviceIds: g.deviceIds, approvalRequestType: SITE_WRITE_APPROVAL,
    approvalDescription: g.description, approvalPayload: payload, approvalSealed: g.sealed,
  });
  if (!ok) return false;
  // D18: beyond the publication thresholds of its policy impact, a second person approves it.
  if (await beyondThresholds(db, g.tenantId, g.impact)) {
    const approval = await approvalService.create({
      tenantId: g.tenantId, userId: req.session.userId!, requestType: SITE_WRITE_APPROVAL, description: g.description, payload, sealed: g.sealed,
    });
    res.status(202).json({ success: true, data: { approvalId: approval.id, status: 'pending_approval', code: 'approvalRequired', policyImpact: g.impact } });
    return false;
  }
  return true;
}

/** The request of a batch (jsonb, or its text). */
const requestOf = (b: Record<string, any>): Record<string, unknown> => (typeof b.request === 'string' ? JSON.parse(b.request) : b.request) ?? {};

/**
 * The executor of an approved site write (site_write): as its requester, whose capabilities, devices and groups are read
 * again; the plan made again under the sites lock and compared with the one he saw (refused when it changed).
 */
export async function executeSiteWrite(x: ApprovalExecution): Promise<string | void> {
  const parsed = Sealed.safeParse(x.sealed ?? {});
  if (!parsed.success) refuse('This request carries no site write any more: do it again');
  const s = parsed.data!;
  const r = await requesterHolds(x.requesterId, x.tenantId, 'devices.manage');
  await requesterHolds(x.requesterId, x.tenantId, POLICY_MANAGE);
  const who: SiteWho = { userId: x.requesterId, admin: r.isPlatformAdmin };
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  const source = s.source ?? 'console';
  try {
    switch (s.op) {
      case 'update': {
        await requireGroupWrite(who, s.body.groupId);
        const row = await updateSite(x.tenantId, s.siteId, s.body, ctx, undefined, {
          who, before: async (_trx, prev) => { if (prevDigestOf(prev) !== s.prevDigest) throw planChanged(); },
        });
        return `Site ${row.code} changed`;
      }
      case 'import': {
        const b = await usableBatch(db, x.tenantId, s.batchId, x.requesterId, [CONSOLE_IMPORT_TOOL, 'import_sites'], s.digest);
        if (!b) refuse('The file of this import is no longer kept (a day at most): import it again');
        const csv = String(requestOf(b!).csv ?? '');
        const out = await applyImport(x.tenantId, csv, ctx, { expectDigest: s.digest, source, who }, (trx) => consumeBatch(trx, x.tenantId, s.batchId));
        return `${out.created} site(s) created, ${out.updated} updated`;
      }
      case 'from_devices': {
        const visible = who.admin ? 'all' as const : await permissionService.getVisibleDeviceIds(x.requesterId, false);
        const out = await applyFromDevices(x.tenantId, s.keys, visible, ctx, {
          expectDigest: s.digest, source, who, canWrite: (ids) => requireWritesOf(who, ids),
        });
        return `${out.sites.length} site(s), ${out.attached} device(s) attached`;
      }
    }
  } catch (err) {
    if (err instanceof AppError && err.code === 'planChanged') refuse('The sites changed since this request: nothing was applied, do it again');
    if (err instanceof AppError && err.statusCode < 500) refuse(err.message);
    throw err;
  }
  return undefined;
}

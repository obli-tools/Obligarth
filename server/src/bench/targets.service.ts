import type { Request, Response } from 'express';
import { z } from 'zod';
import { BENCH_ROLE_POLICIES, checkBenchNameTemplate } from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { asTenant, userActor } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { checkSecondFactor, sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { closeTargetProvisionings } from './provisioning.service';

// =============================================================================
// The targets of a station (lot BANC §3.3, lot BANC-T §3), written in the target's tenant: by a platform administrator
// for a platform station (admin.routes.ts), by the owner tenant for its own station (owned.routes.ts). The confinement
// (a station of a client targets its tenant only, a platform station is targeted by a platform administrator only) is
// the trigger's (bench_station_targets_cap: check_violation bench_station_targets_owner); these functions write the
// row and its audit, in one transaction of the tenant.
//   add     strict second factor (the caller checks it), critical bench.target_added
//   patch   { suspended: true } alone: no second factor (protective); anything else strict (allowLegacyOwner: the
//           exception D3 from the console, bench.legacy_owner_allowed apart); a resumption is allowed, except of a
//           target the platform suspended on a client's station (suspended_by_platform, Q1: 409 suspendedByPlatform;
//           also the trigger bench_station_targets_suspension_guard): only the platform resumes it. The platform
//           suspends a target of a client's station (taking over the client's suspension if there is one) and resumes
//           only its own suspensions (409 stationOwned otherwise)
//   remove  simple second factor (the caller), protective; the owner never removes a target the platform suspended
//           (it would add it again unsuspended)
// =============================================================================

const PREFIX = z.string().regex(/^[A-Za-z0-9_-]{0,32}$/).nullable().optional();
/** A name template (shared checkBenchNameTemplate), null or '' clears it. */
const TEMPLATE = z.string().max(64).nullable().optional()
  .refine((v) => v === null || v === undefined || v === '' || checkBenchNameTemplate(v).ok, { message: 'Invalid name template' });

export const TargetFields = {
  rolePolicy: z.enum(BENCH_ROLE_POLICIES).optional(),
  namePrefix: PREFIX,
  nameTemplate: TEMPLATE,
  disableDevOptions: z.boolean().optional(),
};
export const TargetPatch = z.object({
  ...TargetFields, allowLegacyOwner: z.boolean().optional(), suspended: z.boolean().optional(),
}).strict();
export type TargetInput = { groupId: number; rolePolicy?: typeof BENCH_ROLE_POLICIES[number]; namePrefix?: string | null; nameTemplate?: string | null;
  disableDevOptions?: boolean };

/** The group of a target, in its tenant (404 otherwise). */
export async function assertGroup(tenantId: number, groupId: number, userId: number): Promise<void> {
  const ok = await asTenant(tenantId, userActor(userId), () => db('device_groups').where({ tenant_id: tenantId, id: groupId }).first('id'));
  if (!ok) throw new AppError(404, 'Group not found');
}

/** Who changes a target: the platform (admin.routes.ts) or the tenant; ownedStation: the station belongs to a client. */
export interface TargetActor { platform: boolean; ownedStation: boolean }

const suspendedByPlatform = (): AppError =>
  new AppError(409, 'The platform suspended this target: only the platform resumes it', 'suspendedByPlatform');

function mapTargetError(err: unknown): never {
  const constraint = (err as { constraint?: string })?.constraint;
  if (constraint === 'bench_station_targets_platform_suspension') throw suspendedByPlatform();
  if (constraint === 'bench_station_targets_cap') throw new AppError(422, '200 targets per station at most', 'tooManyTargets');
  if (constraint === 'bench_station_targets_owner') throw new AppError(409, 'This station cannot target this tenant', 'targetRefused');
  throw err;
}

/** A new target (the second factor checked by the caller). */
export async function insertTarget(req: Request, stationId: string, stationName: string, tenantId: number, b: TargetInput): Promise<void> {
  const userId = req.session.userId!;
  const ctx = await audit.fromRequest(req, tenantId);
  await asTenant(tenantId, userActor(userId), () => db.transaction(async (trx) => {
    if (await trx('bench_station_targets').where({ station_id: stationId, tenant_id: tenantId, group_id: b.groupId }).first('group_id')) {
      throw new AppError(409, 'This group is a target of the station already', 'targetExists');
    }
    await audit.appendInTx(trx, {
      tenantId, action: 'bench.target_added', target: { type: 'bench_station', id: stationId },
      details: {
        stationId, name: stationName, groupId: b.groupId, rolePolicy: b.rolePolicy ?? 'owner_preferred', disableDevOptions: b.disableDevOptions ?? true,
        ...(b.nameTemplate ? { nameTemplate: b.nameTemplate } : {}),
      },
    }, ctx);
    await trx('bench_station_targets').insert({
      station_id: stationId, tenant_id: tenantId, group_id: b.groupId, role_policy: b.rolePolicy ?? 'owner_preferred', name_prefix: b.namePrefix || null,
      name_template: b.nameTemplate || null, disable_dev_options: b.disableDevOptions ?? true, created_by: userId,
    });
  })).catch(mapTargetError);
}

/** A change of a target; false when the second factor answered (the response is sent). */
export async function patchTarget(req: Request, res: Response, stationId: string, tenantId: number, groupId: number,
  b: z.infer<typeof TargetPatch>, actor: TargetActor): Promise<boolean> {
  const keys = Object.keys(b);
  if (keys.length === 0) throw new AppError(400, 'Nothing to change', 'invalidRequest');
  const onlySuspend = keys.length === 1 && b.suspended === true;
  if (!onlySuspend) {
    const step = await checkSecondFactor(req, { actionKey: b.allowLegacyOwner ? 'bench.legacy_owner_allow' : 'bench.target_change', allowTrustedIp: false, allowDevice: true });
    if (!step.ok) { sendStepUpFailure(res, step); return false; }
  }
  const userId = req.session.userId!;
  const ctx = await audit.fromRequest(req, tenantId);
  await asTenant(tenantId, userActor(userId), () => db.transaction(async (trx) => {
    const t = await trx('bench_station_targets').where({ station_id: stationId, tenant_id: tenantId, group_id: groupId }).forUpdate().first('*') as Record<string, any> | undefined;
    if (!t) throw new AppError(404, 'Target not found');
    const set: Record<string, unknown> = {};
    if (b.rolePolicy !== undefined) set.role_policy = b.rolePolicy;
    if (b.namePrefix !== undefined) set.name_prefix = b.namePrefix || null;
    if (b.nameTemplate !== undefined) set.name_template = b.nameTemplate || null;
    if (b.disableDevOptions !== undefined) set.disable_dev_options = b.disableDevOptions;
    if (b.allowLegacyOwner !== undefined) set.allow_legacy_owner = b.allowLegacyOwner;
    // Q1: the platform's suspension of a target of a client's station holds against the client.
    const platformCut = actor.platform && actor.ownedStation;
    if (b.suspended === false && t.suspended_at) {
      if (t.suspended_by_platform === true && !actor.platform) throw suspendedByPlatform();
      if (platformCut && t.suspended_by_platform !== true) {
        throw new AppError(409, 'This target was suspended by the client: the client resumes it', 'stationOwned');
      }
    }
    if (b.suspended === true && !t.suspended_at) Object.assign(set, { suspended_at: new Date(), suspended_by: userId, suspended_by_platform: platformCut });
    // The client suspended it already: the platform makes that suspension its own (the cascade ran with the first one).
    const takeOver = b.suspended === true && !!t.suspended_at && platformCut && t.suspended_by_platform !== true;
    if (takeOver) Object.assign(set, { suspended_by: userId, suspended_by_platform: true });
    if (b.suspended === false && t.suspended_at) Object.assign(set, { suspended_at: null, suspended_by: null, suspended_by_platform: false });
    if (Object.keys(set).length === 0) return;
    // A suspension closes at once what the target had open: its provisionings abandoned, their tokens revoked.
    const closed = b.suspended === true && !t.suspended_at ? await closeTargetProvisionings(trx, tenantId, stationId, groupId, userId) : null;
    const entries = [];
    const target = { type: 'bench_station', id: stationId };
    if (b.allowLegacyOwner === true && t.allow_legacy_owner !== true) {
      entries.push({ tenantId, action: 'bench.legacy_owner_allowed', target, details: { stationId, groupId, decidedAt: 'console' } });
    }
    if (closed) entries.push({ tenantId, action: 'bench.target_suspended', target, details: { stationId, groupId, ...closed, ...(platformCut ? { byPlatform: true } : {}) } });
    if (takeOver) entries.push({ tenantId, action: 'bench.target_suspended', target, details: { stationId, groupId, byPlatform: true, tookOver: true } });
    if (b.suspended === false && t.suspended_at) entries.push({ tenantId, action: 'bench.target_resumed', target, details: { stationId, groupId } });
    const changed = Object.keys(set).filter((k) => !['suspended_at', 'suspended_by', 'suspended_by_platform'].includes(k));
    if (changed.length > 0) {
      entries.push({ tenantId, action: 'bench.target_changed', target, details: { stationId, groupId, changed: Object.fromEntries(changed.map((k) => [k, set[k]])) } });
    }
    if (entries.length) await audit.appendManyInTx(trx, entries, ctx, onlySuspend ? { onFailure: 'spool' } : {});
    await trx('bench_station_targets').where({ station_id: stationId, tenant_id: tenantId, group_id: groupId }).update(set);
  })).catch(mapTargetError);
  return true;
}

/** The removal of a target (the second factor checked by the caller): its open provisionings abandoned. */
export async function removeTarget(req: Request, stationId: string, tenantId: number, groupId: number, reason: 'admin' | 'tenant'): Promise<void> {
  const userId = req.session.userId!;
  const ctx = await audit.fromRequest(req, tenantId);
  await asTenant(tenantId, userActor(userId), () => db.transaction(async (trx) => {
    if (reason === 'tenant') {
      const t = await trx('bench_station_targets').where({ station_id: stationId, tenant_id: tenantId, group_id: groupId }).forUpdate()
        .first('suspended_by_platform') as { suspended_by_platform: boolean } | undefined;
      if (t?.suspended_by_platform === true) throw suspendedByPlatform();
    }
    const n = await trx('bench_station_targets').where({ station_id: stationId, tenant_id: tenantId, group_id: groupId }).delete();
    if (n === 0) throw new AppError(404, 'Target not found');
    const closed = await closeTargetProvisionings(trx, tenantId, stationId, groupId, userId);
    await audit.appendInTx(trx, { tenantId, action: 'bench.target_removed', target: { type: 'bench_station', id: stationId }, details: { stationId, groupId, reason, ...closed } },
      ctx, { onFailure: 'spool' });
  }));
}

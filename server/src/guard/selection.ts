// Targets of a guarded action (docs: audit-durci §10.3 step 2): explicit
// device ids, groups with their descendants (closure), or the tenant; in the
// tenant of the session, or — from the master tenant's global view — in the
// one tenant of the devices and groups designated (D27: never several).
// Every target must exist, belong to that tenant and be writable by the
// requester with the action's capability (team scopes; a platform
// administrator passes); otherwise 404 targetsOutsideScope, without telling
// which ones exist.
import type { Request } from 'express';
import type { GuardSelection } from '@obligarth/shared';
import { db } from '../db';
import { globalViewRead } from '../middleware/dbContext';
import { AppError } from '../middleware/errorHandler';
import { hasGlobalView, parseRequestDeviceId } from '../services/deviceScope.service';
import { permissionService } from '../services/permission.service';
import type { GuardedActionDef } from './types';

/** Largest explicit list of a request (a tenant or group selection is not
 *  limited by it). */
export const MAX_EXPLICIT_IDS = 10_000;

export interface ResolvedTargets {
  tenantId: number;
  deviceIds: number[];
  /** The selection as kept in pending_actions.selection. */
  selection: { deviceIds: number; groupIds: number[]; tenant: boolean };
  /** One target: its displayed name (devices.label). */
  singleName: string | null;
}

const outside = (): AppError => new AppError(404, 'Some targets are outside your scope', 'targetsOutsideScope');

function idList(raw: unknown, what: string): number[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) throw new AppError(400, `${what} must be an array`, 'invalidSelection');
  if (raw.length > MAX_EXPLICIT_IDS) throw new AppError(400, `${what}: ${MAX_EXPLICIT_IDS} at most`, 'invalidSelection');
  const ids = raw.map(parseRequestDeviceId);
  if (ids.some((n) => n === null)) throw outside();
  return [...new Set(ids as number[])];
}

/** The selection of a request, checked for its shape. */
export function parseSelection(raw: unknown): GuardSelection {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new AppError(400, 'selection is required', 'noTargets');
  const s = raw as Record<string, unknown>;
  const deviceIds = idList(s.deviceIds, 'selection.deviceIds');
  const groupIds = idList(s.groupIds, 'selection.groupIds');
  const tenant = s.tenant === true;
  if (!deviceIds.length && !groupIds.length && !tenant) throw new AppError(400, 'Nothing selected', 'noTargets');
  return { deviceIds, groupIds, tenant };
}

/** The one tenant of the explicit ids and groups (global view): 404 when one
 *  is unknown, 409 crossTenantBatch when they span several tenants. */
async function tenantOfSelection(req: Request, s: GuardSelection): Promise<number> {
  const own = Number(req.tenantId);
  const ids = s.deviceIds ?? [];
  const groups = s.groupIds ?? [];
  if (!ids.length && !groups.length) return own;
  const tenants = await globalViewRead(req, async () => {
    const t = new Set<number>();
    for (let i = 0; i < ids.length; i += 1000) {
      const rows = await db('devices').whereIn('id', ids.slice(i, i + 1000)).select('id', 'tenant_id') as Array<{ id: number; tenant_id: number }>;
      if (rows.length !== Math.min(1000, ids.length - i)) throw outside();
      for (const r of rows) t.add(Number(r.tenant_id));
    }
    if (groups.length) {
      const rows = await db('device_groups').whereIn('id', groups).select('id', 'tenant_id') as Array<{ id: number; tenant_id: number }>;
      if (rows.length !== groups.length) throw outside();
      for (const r of rows) t.add(Number(r.tenant_id));
    }
    return t;
  });
  if (tenants.size > 1) throw new AppError(409, 'One request acts on one tenant only', 'crossTenantBatch');
  return [...tenants][0] ?? own;
}

/** The tenant a request acts on (the session's, or the global view's one
 *  tenant of its targets). */
export async function targetTenantOf(req: Request, s: GuardSelection): Promise<number> {
  return hasGlobalView(req) ? tenantOfSelection(req, s) : Number(req.tenantId);
}

/**
 * The targets, in the context of their tenant (asTargetTenant): devices of
 * the tenant only; groups of the tenant only, with their descendants; the
 * whole tenant. Sorted ascending. 404 targetsOutsideScope, 400 noTargets.
 */
export async function resolveTargets(tenantId: number, s: GuardSelection): Promise<ResolvedTargets> {
  const out = new Set<number>();
  const explicit = s.deviceIds ?? [];
  for (let i = 0; i < explicit.length; i += 1000) {
    const chunk = explicit.slice(i, i + 1000);
    const rows = await db('devices').whereIn('id', chunk).andWhere({ tenant_id: tenantId }).pluck('id') as number[];
    if (rows.length !== chunk.length) throw outside();
    for (const id of rows) out.add(Number(id));
  }
  const groups = s.groupIds ?? [];
  if (groups.length) {
    const known = await db('device_groups').whereIn('id', groups).andWhere({ tenant_id: tenantId }).pluck('id') as number[];
    if (known.length !== groups.length) throw outside();
    const rows = await db('devices as d')
      .join('device_group_closure as c', 'c.descendant_id', 'd.group_id')
      .whereIn('c.ancestor_id', groups)
      .andWhere('d.tenant_id', tenantId)
      .distinct('d.id') as Array<{ id: number }>;
    for (const r of rows) out.add(Number(r.id));
  }
  if (s.tenant) {
    const rows = await db('devices').where({ tenant_id: tenantId }).pluck('id') as number[];
    for (const id of rows) out.add(Number(id));
  }
  const deviceIds = [...out].sort((a, b) => a - b);
  if (!deviceIds.length) throw new AppError(400, 'The selection designates no device', 'noTargets');
  let singleName: string | null = null;
  if (deviceIds.length === 1) {
    const d = await db('devices').where({ id: deviceIds[0], tenant_id: tenantId }).first('label') as
      { label: string | null } | undefined;
    singleName = (d?.label || '').trim() || null;
  }
  return {
    tenantId,
    deviceIds,
    selection: { deviceIds: explicit.length, groupIds: groups, tenant: s.tenant === true },
    singleName,
  };
}

/**
 * The requester's rights on the targets (§10.3 step 2): the action's tenant
 * capability, then write access to each device through the team scopes and
 * the action's device capability. A platform administrator passes. Returns
 * the ids the requester may NOT act on (empty: all allowed).
 */
export async function targetsWithoutRights(def: GuardedActionDef<any>, requesterId: number, platformAdmin: boolean,
  tenantId: number, deviceIds: number[]): Promise<number[]> {
  if (platformAdmin) return [];
  if (def.tenantCapability && !(await permissionService.userHasTenantCapability(requesterId, tenantId, def.tenantCapability))) {
    return [...deviceIds];
  }
  const lacking: number[] = [];
  for (const id of deviceIds) {
    if (!(await permissionService.canWriteDevice(requesterId, id, false))) lacking.push(id);
  }
  if (def.deviceCapability) {
    const noCap = await permissionService.devicesLackingCapability(requesterId, deviceIds, def.deviceCapability);
    for (const id of noCap) if (!lacking.includes(id)) lacking.push(id);
  }
  return lacking;
}

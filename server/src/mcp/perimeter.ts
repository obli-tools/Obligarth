import { db } from '../db';
import { asNone, userActor } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import { tenantService } from '../services/tenant.service';
import { normaliseTenantRole } from '../services/userScope.service';
import type { EffectiveTenants, McpCaller, McpKeyInfo, McpTarget } from './caller';
import { targetIds } from './caller';
import { mcpSettings, tenantForcesIp, tenantIpPolicies } from './settings';

// =============================================================================
// The perimeter of a key (docs: specs mcp-server §1.4), live, never a
// snapshot: "all" means all the human can reach at the time of the call, a
// list means the list ∩ what the human can reach now.
//   tenants   (all ? accessible now : list ∩ accessible now) ∩ {T: mcp.access_keys held in T}
//             ∖ {T excluded by a tenant manager} ∖ {T forcing an IP allow-list when the key has none}
//   devices   in T: visible(U) ∩ (group mode all ∨ group ∈ closure(key groups of T))
//             ∩ (device mode all ∨ id ∈ key devices of T); a tenant without a group row in list mode
//             sees no device (an empty list is never "all"); ungrouped devices are outside a group list.
// A device or a group out of the perimeter answers like an unknown one (404), never 403.
// =============================================================================

/** What the perimeter needs of a caller (the IP policy computes it for keys that are not calling). */
export type PerimeterSubject = Pick<McpCaller, 'userId' | 'isPlatformAdmin' | 'targets'> & { key: Pick<McpKeyInfo, 'tenantMode' | 'ipAllow'> };

/** The effective tenants of a key now (§1.4), with the reasons of the listed tenants left out. */
export async function effectiveTenants(subject: PerimeterSubject): Promise<EffectiveTenants> {
  const U = subject.userId;
  const settings = await mcpSettings();
  const policies = await tenantIpPolicies();
  const excluded = new Set(subject.targets.filter((t) => t.kind === 'tenant_excluded').map((t) => t.tenantId));
  const ipOpen = subject.key.ipAllow.length === 0;
  return asNone(userActor(U), async () => {
    // Accessible now: every tenant for a platform administrator (D2), the memberships otherwise.
    const accessible = new Map<number, { name: string; role: string }>();
    if (subject.isPlatformAdmin) {
      for (const t of await tenantService.getAll()) accessible.set(Number(t.id), { name: t.name, role: 'platform_admin' });
      const own = await db('user_tenants').where({ user_id: U }).select('tenant_id', 'role') as Array<{ tenant_id: number; role: string }>;
      for (const r of own) { const a = accessible.get(Number(r.tenant_id)); if (a) a.role = normaliseTenantRole(r.role); }
    } else {
      const rows = await db('tenants').join('user_tenants', 'tenants.id', 'user_tenants.tenant_id')
        .where('user_tenants.user_id', U).select('tenants.id', 'tenants.name', 'user_tenants.role') as Array<{ id: number; name: string; role: string }>;
      for (const r of rows) accessible.set(Number(r.id), { name: r.name, role: normaliseTenantRole(r.role) });
    }
    const listed = subject.key.tenantMode === 'list'
      ? [...new Set(subject.targets.filter((t) => t.kind === 'tenant').map((t) => t.tenantId))]
      : [...accessible.keys()];
    const tenants: EffectiveTenants['tenants'] = [];
    const outside: EffectiveTenants['outside'] = [];
    for (const id of listed.sort((a, b) => a - b)) {
      const a = accessible.get(id);
      let why: string | null = null;
      if (!a) why = 'tenant no longer accessible to the account';
      else if (!subject.isPlatformAdmin && !(await permissionService.userHasTenantCapability(U, id, 'mcp.access_keys'))) {
        why = 'mcp.access_keys capability lost';
      } else if (excluded.has(id)) why = 'excluded from this key by a tenant manager';
      else if (ipOpen && tenantForcesIp(id, settings, policies)) why = 'the tenant requires an IP allow-list on keys';
      if (why === null) tenants.push({ id, name: a!.name, role: a!.role });
      else if (subject.key.tenantMode === 'list') outside.push({ tenantId: id, why });
    }
    return { tenants, outside };
  });
}

/** The device ids of the key's perimeter in tenant T, or 'all' (§1.4). Inside withTenant (tenant T's context). */
export async function deviceFilter(caller: Pick<McpCaller, 'userId' | 'isPlatformAdmin' | 'targets' | 'key'>, tenantId: number):
  Promise<{ ids: number[] | 'all' }> {
  const visible = caller.isPlatformAdmin ? 'all' as const : await permissionService.getVisibleDeviceIds(caller.userId, false);
  const groupList = caller.key.groupMode === 'list';
  const deviceList = caller.key.deviceMode === 'list';
  if (visible === 'all' && !groupList && !deviceList) return { ids: 'all' };
  const q = db('devices').where('devices.tenant_id', tenantId);
  if (visible !== 'all') {
    if (visible.length === 0) return { ids: [] };
    q.whereRaw('devices.id = ANY (?::int[])', [visible]);
  }
  if (groupList) {
    const groups = targetIds(caller, 'group', tenantId);
    if (groups.length === 0) return { ids: [] };
    q.whereIn('devices.group_id', db('device_group_closure').where('tenant_id', tenantId)
      .whereRaw('ancestor_id = ANY (?::int[])', [groups]).select('descendant_id'));
  }
  if (deviceList) {
    const devices = targetIds(caller, 'device', tenantId);
    if (devices.length === 0) return { ids: [] };
    q.whereRaw('devices.id = ANY (?::int[])', [devices]);
  }
  const ids = (await q.pluck('devices.id') as number[]).map(Number);
  return { ids };
}

export const deviceNotFound = (): AppError => new AppError(404, 'Device not found', 'notFound');
export const groupNotFound = (): AppError => new AppError(404, 'Group not found', 'notFound');

/** Every id is a device of T inside the perimeter, else 404 (existence never leaks). Inside withTenant. */
export async function assertDevicesInPerimeter(caller: Pick<McpCaller, 'userId' | 'isPlatformAdmin' | 'targets' | 'key'>,
  tenantId: number, ids: number[]): Promise<void> {
  const unique = [...new Set(ids.map(Number))];
  if (unique.length === 0 || unique.some((n) => !Number.isSafeInteger(n) || n <= 0 || n > 2147483647)) throw deviceNotFound();
  const found = (await db('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [unique]).pluck('id') as number[]).map(Number);
  if (found.length !== unique.length) throw deviceNotFound();
  const f = await deviceFilter(caller, tenantId);
  if (f.ids !== 'all') {
    const inside = new Set(f.ids);
    if (unique.some((id) => !inside.has(id))) throw deviceNotFound();
  }
}

/**
 * A group a write targets (a move): in T, visible to the human and inside the key's group perimeter, else 404
 * 'Group not found' (the same text as an unknown group). Ungrouping (null) needs group mode 'all'.
 */
export async function assertGroupTargetInPerimeter(caller: Pick<McpCaller, 'userId' | 'isPlatformAdmin' | 'targets' | 'key'>,
  tenantId: number, groupId: number | null): Promise<void> {
  if (groupId === null) {
    if (caller.key.groupMode === 'list') throw groupNotFound();
    return;
  }
  if (!Number.isSafeInteger(groupId) || groupId <= 0) throw groupNotFound();
  const g = await db('device_groups').where({ tenant_id: tenantId, id: groupId }).first('id');
  if (!g) throw groupNotFound();
  if (!caller.isPlatformAdmin && !(await permissionService.canReadGroup(caller.userId, groupId, false))) throw groupNotFound();
  if (caller.key.groupMode === 'list') {
    const groups = targetIds(caller, 'group', tenantId);
    if (groups.length === 0) throw groupNotFound();
    const inside = await db('device_group_closure').where({ tenant_id: tenantId, descendant_id: groupId })
      .whereRaw('ancestor_id = ANY (?::int[])', [groups]).first('descendant_id');
    if (!inside) throw groupNotFound();
  }
}

/** The groups of T the key may see: visible to the human ∩ (all, or the key's groups with their descendants). */
export async function groupFilter(caller: Pick<McpCaller, 'userId' | 'isPlatformAdmin' | 'targets' | 'key'>, tenantId: number):
  Promise<{ ids: number[] | 'all' }> {
  const visible = caller.isPlatformAdmin ? 'all' as const : await permissionService.getVisibleGroupIds(caller.userId, false);
  if (caller.key.groupMode === 'all') return { ids: visible };
  const groups = targetIds(caller, 'group', tenantId);
  if (groups.length === 0) return { ids: [] };
  const under = (await db('device_group_closure').where({ tenant_id: tenantId }).whereRaw('ancestor_id = ANY (?::int[])', [groups])
    .pluck('descendant_id') as number[]).map(Number);
  if (visible === 'all') return { ids: [...new Set(under)] };
  const v = new Set(visible.map(Number));
  return { ids: [...new Set(under.filter((id) => v.has(id)))] };
}

/**
 * The device of a read tool (the rules of resolveRequestDevice without a request, never the global view): a device of
 * T, the human reads it (a platform administrator bypasses the team checks, as the console), inside the perimeter.
 */
export async function resolveCallerDevice(caller: Pick<McpCaller, 'userId' | 'isPlatformAdmin' | 'targets' | 'key'>,
  tenantId: number, deviceId: number): Promise<{ id: number; tenantId: number; label: string | null; managementChannel: string }> {
  if (!Number.isSafeInteger(deviceId) || deviceId <= 0 || deviceId > 2147483647) throw deviceNotFound();
  const d = await db('devices').where({ tenant_id: tenantId, id: deviceId })
    .first('id', 'tenant_id', 'label', 'management_channel') as { id: number; tenant_id: number; label: string | null; management_channel: string } | undefined;
  if (!d) throw deviceNotFound();
  if (!caller.isPlatformAdmin && !(await permissionService.canReadDevice(caller.userId, deviceId, false))) throw deviceNotFound();
  await assertDevicesInPerimeter(caller, tenantId, [deviceId]);
  return { id: Number(d.id), tenantId: Number(d.tenant_id), label: d.label ?? null, managementChannel: String(d.management_channel) };
}

/** Targets of a key, from the stored rows. */
export function targetsOf(rows: Array<{ kind: string; tenant_id: number; ref_id: number | null }>): McpTarget[] {
  return rows.map((r) => ({
    kind: r.kind as McpTarget['kind'], tenantId: Number(r.tenant_id), refId: r.ref_id === null || r.ref_id === undefined ? null : Number(r.ref_id),
  }));
}

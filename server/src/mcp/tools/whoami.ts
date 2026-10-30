import { z } from 'zod';
import { MCP_SCOPE_KEYS, MCP_SCOPES, type DeviceCapability, type McpScope } from '@obligarth/shared';
import { db } from '../../db';
import { asNone, userActor } from '../../db/context';
import { permissionService } from '../../services/permission.service';
import { restrictionService } from '../../services/restriction.service';
import { effectiveTenantsOf, holdsTenantCapability, targetIds, withTenant, type McpCaller } from '../caller';
import { currentPolicy } from '../ipPolicy';
import { deviceFilter } from '../perimeter';
import { mcpSettings } from '../settings';
import { READ, js, registerTool } from './index';

// =============================================================================
// whoami and list_tenants (owner requirement: the server TEACHES the agent its
// perimeter; docs: specs mcp-server §4.2): who it acts for, which tenants,
// groups and devices it may reach now, which scopes and device capabilities it
// holds or lacks per tenant, the IP restriction, the expiry, and what always
// needs a human. Only tenants of the current effective set are named.
// =============================================================================

/** The restrictable actions each scope can trigger (their matrix levels are reported). */
const SCOPE_ACTIONS: Partial<Record<McpScope, string[]>> = {
  'commands.message': ['legacy_agent.message'],
  'commands.restart': ['legacy_agent.restart'],
  'commands.apps': ['legacy_agent.apps', 'legacy_agent.update'],
  'groups.move': ['device.bulk_group_change', 'mdm.policy_publish'],
};

export const ALWAYS_HUMAN = [
  "Actions at the 'sensitive' level (second factor): you get an authorization id; the human approves with 2FA.",
  "Actions at the 'restricted' level: an approval request is filed for another person.",
  'Any move of devices between groups: an authorization the human approves after seeing a preview.',
  'Never available here: wipe, lock, lost mode, remove management, delete device, ownership change, remote shell, remote view/control, approving or denying requests, audit export, user/key/settings management.',
];

const ITEMS_MAX = 200;

async function tenantDetail(caller: McpCaller, t: { id: number; name: string; role: string }) {
  return withTenant(caller, t.id, async () => {
    const held: McpScope[] = [];
    const lacking: McpScope[] = [];
    for (const s of caller.key.scopes) {
      const def = MCP_SCOPES[s];
      const need = def.tenantNeed;
      const ok = need === 'membership' || (await holdsTenantCapability(caller, t.id, need));
      (ok ? held : lacking).push(s);
    }
    const wanted = [...new Set(caller.key.scopes.map((s) => ('deviceCapability' in MCP_SCOPES[s] ? (MCP_SCOPES[s] as { deviceCapability: DeviceCapability }).deviceCapability : null))
      .filter((c): c is DeviceCapability => c !== null))];
    const capsHeld: DeviceCapability[] = [];
    const capsLacking: DeviceCapability[] = [];
    for (const c of wanted) {
      const ok = caller.isPlatformAdmin || (await permissionService.userHoldsDeviceCapabilityAnywhere(caller.userId, t.id, c));
      (ok ? capsHeld : capsLacking).push(c);
    }
    // The key's listed groups the human still reads now (never the name of a group hidden from him since).
    const groupIds = targetIds(caller, 'group', t.id);
    const groupRows = groupIds.length === 0 ? [] : await db('device_groups').where({ tenant_id: t.id }).whereIn('id', groupIds).select('id', 'name') as Array<{ id: number; name: string }>;
    const groupNames: typeof groupRows = [];
    for (const g of groupRows) if (caller.isPlatformAdmin || await permissionService.canReadGroup(caller.userId, Number(g.id), false)) groupNames.push(g);
    const f = await deviceFilter(caller, t.id);
    const visibleCount = f.ids === 'all'
      ? Number((await db('devices').where({ tenant_id: t.id }).count<{ n: string }[]>('id as n').first())?.n ?? 0)
      : f.ids.length;
    let devices: Array<{ id: number; name: string | null }> | undefined;
    if (caller.key.deviceMode === 'list' && f.ids !== 'all') {
      const ids = f.ids.slice(0, ITEMS_MAX);
      devices = ids.length === 0 ? [] : (await db('devices').where({ tenant_id: t.id }).whereIn('id', ids).orderBy('id').select('id', 'label') as Array<{ id: number; label: string | null }>)
        .map((d) => ({ id: Number(d.id), name: d.label ?? null }));
    }
    const restrictions: Record<string, string> = {};
    for (const s of caller.key.scopes) {
      for (const a of SCOPE_ACTIONS[s] ?? []) restrictions[a] = await restrictionService.getLevelFor({ tenantId: t.id, actionKey: a });
    }
    return {
      tenantId: t.id, name: t.name, role: t.role,
      scopes: { held, lackingInThisTenant: lacking },
      deviceCapabilities: { heldSomewhere: capsHeld, lacking: capsLacking },
      groups: {
        mode: caller.key.groupMode,
        ...(caller.key.groupMode === 'list' ? { items: groupNames.map((g) => ({ id: Number(g.id), name: g.name, includesDescendants: true })) } : {}),
      },
      devices: {
        mode: caller.key.deviceMode, visibleCount,
        ...(devices ? { items: devices, itemsTruncated: f.ids !== 'all' && f.ids.length > ITEMS_MAX } : {}),
      },
      restrictions,
    };
  });
}

/** Tenants detailed per call (the others are listed by id, name and role, and detailed with tenant_id or offset). */
const TENANTS_DETAILED = 20;
/** Tenant details computed at once. */
const DETAIL_CONCURRENCY = 4;

export async function whoami(caller: McpCaller, o: { tenantId?: number; offset?: number } = {}): Promise<Record<string, unknown>> {
  const eff = await effectiveTenantsOf(caller);
  const s = await mcpSettings();
  const pending = await asNone(userActor(caller.userId), async () => Number((await db('mcp_authorizations')
    .where({ user_id: caller.userId, key_id: caller.key.rowId }).whereIn('state', ['pending', 'filed', 'executing'])
    .count<{ n: string }[]>('id as n').first())?.n ?? 0));
  const all = o.tenantId !== undefined ? eff.tenants.filter((t) => t.id === o.tenantId) : eff.tenants;
  const start = o.tenantId !== undefined ? 0 : Math.max(0, o.offset ?? 0);
  const chosen = all.slice(start, start + TENANTS_DETAILED);
  const tenants: Array<Awaited<ReturnType<typeof tenantDetail>>> = new Array(chosen.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, chosen.length) }, async () => {
    while (next < chosen.length) { const i = next++; tenants[i] = await tenantDetail(caller, chosen[i]); }
  }));
  const more = o.tenantId === undefined && start + chosen.length < all.length;
  const notDetailed = o.tenantId !== undefined ? [] : [...all.slice(0, start), ...all.slice(start + chosen.length)];
  return {
    actingAs: { userId: caller.userId, username: caller.username, platformAdmin: caller.isPlatformAdmin, signIn: caller.isSso ? 'obligate-sso' : 'local', globalView: false },
    key: {
      id: caller.key.publicId, name: caller.key.name, expiresAt: caller.key.expiresAt.toISOString(),
      ipAllowList: caller.key.ipAllow, ipMode: currentPolicy()?.mode ?? 'rate',
    },
    tenants,
    tenantCount: eff.tenants.length,
    ...(notDetailed.length ? { tenantsNotDetailed: notDetailed.map((t) => ({ tenantId: t.id, name: t.name, role: t.role })) } : {}),
    nextOffset: more ? start + chosen.length : null,
    ...(caller.key.tenantMode === 'list' ? { tenantsOutsideNow: eff.outside } : {}),
    scopesNotOnKey: MCP_SCOPE_KEYS.filter((k) => !caller.key.scopes.includes(k)),
    authorizations: { pending, maxPendingPerKey: s.maxPendingPerKey },
    alwaysHuman: ALWAYS_HUMAN,
  };
}

export function registerWhoamiTools(): void {
  registerTool({
    name: 'whoami', title: 'Who am I acting for', scope: null,
    description: `Your perimeter, in detail: the human you act for, the tenants you may reach now (with role, scopes held and lacking, device capabilities, groups, devices, restriction levels; ${TENANTS_DETAILED} tenants detailed per call, the others listed: pass tenant_id or offset for them), the IP restriction and expiry of this key, and what always needs a human. Call it first.`,
    inputSchema: js.obj({
      tenant_id: js.int('Only this tenant, in detail.', { minimum: 1 }), offset: js.int('Offset in the list of tenants to detail.', { minimum: 0, maximum: 100000 }),
    }),
    args: z.object({ tenant_id: z.number().int().positive().optional(), offset: z.number().int().min(0).max(100_000).optional() }).strict(),
    annotations: { title: 'Who am I acting for', ...READ },
    run: (caller, a) => whoami(caller, { tenantId: a.tenant_id, offset: a.offset }),
  });
  registerTool({
    name: 'list_tenants', title: 'List the reachable tenants', scope: null,
    description: 'The tenants this key may act in now (id, name, role). Every other tool takes one of these ids as tenant_id.',
    inputSchema: js.obj({}), args: z.object({}).strict(),
    annotations: { title: 'List the reachable tenants', ...READ },
    run: async (caller) => {
      const eff = await effectiveTenantsOf(caller);
      return { items: eff.tenants.map((t) => ({ tenantId: t.id, name: t.name, role: t.role })) };
    },
  });
}

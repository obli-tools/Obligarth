import { z } from 'zod';
import { DEVICE_LIST_SORT_KEYS } from '@obligarth/shared';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { deviceService } from '../../services/device.service';
import { deviceApps, deviceCertificates, deviceProfiles } from '../../mdm/inventory/views';
import { deviceConfiguration } from '../../mdm/policies/configuration';
import { listEpisodes } from '../../mdm/registry/episodes';
import { deviceDetail, listDevices } from '../../legacyAgent/console';
import { holdsTenantCapability, requireScope, withTenant, type McpCaller } from '../caller';
import { deviceFilter, deviceNotFound, groupFilter, resolveCallerDevice } from '../perimeter';
import { READ, js, page, registerTool } from './index';
import { deviceId, limit, offset, tenantId } from './common';

// =============================================================================
// Device reads (docs: specs mcp-server §5.1): the registry list and record, the
// inventory of a device, the bridge agent's list and record, the groups. Each
// in the tenant named, as the human, intersected with the key's perimeter;
// never the global view. A device out of reach answers like an unknown one.
// =============================================================================

const SearchArgs = z.object({
  tenant_id: tenantId,
  q: z.string().trim().max(100).optional(),
  platform: z.array(z.string().max(32)).max(10).optional(),
  enrollment_state: z.array(z.string().max(32)).max(10).optional(),
  group_id: z.number().int().positive().optional(),
  include_subgroups: z.boolean().optional(),
  ungrouped: z.boolean().optional(),
  tags: z.array(z.string().max(64)).max(10).optional(),
  lost_mode: z.boolean().optional(),
  sort_by: z.enum(DEVICE_LIST_SORT_KEYS).optional(),
  sort_order: z.enum(['asc', 'desc']).optional(),
  limit, offset,
}).strict();

const DeviceArgs = z.object({ tenant_id: tenantId, device_id: deviceId }).strict();

const InventoryArgs = z.object({
  tenant_id: tenantId, device_id: deviceId,
  section: z.enum(['apps', 'profiles', 'certificates', 'configuration', 'enrollments']),
  limit, offset,
}).strict();

const LegacyListArgs = z.object({
  tenant_id: tenantId, q: z.string().trim().max(100).optional(), conflict: z.boolean().optional(), admin_inactive: z.boolean().optional(),
  silent: z.boolean().optional(), revoked: z.boolean().optional(), limit, offset,
}).strict();

const LegacyDeviceArgs = z.object({ tenant_id: tenantId, device_id: deviceId, include_identifiers: z.boolean().optional() }).strict();

const GroupsArgs = z.object({ tenant_id: tenantId }).strict();

const slice = <T>(list: T[], o: number, l: number) => page(list.slice(o, o + l), o, l, list.length);

// ── Device identifiers (decision D10: scope devices.identifiers, tenant need devices.manage) ──

/** The key carries devices.identifiers and the human holds devices.manage in T: identifiers may be returned. */
async function identifiersAllowed(caller: McpCaller, tenantId: number): Promise<boolean> {
  return caller.key.scopes.includes('devices.identifiers') && (await holdsTenantCapability(caller, tenantId, 'devices.manage'));
}

/** Status items of the bridge agent that carry a hardware or network identifier. */
const IDENTIFIER_ITEM = /imei|meid|serial|android_?id|iccid|imsi|phone|msisdn|mac|knox/i;

/** A registry summary or record without its identifiers (serial, IMEI, UDID, phone number, ICCID, EID, MAC addresses). */
function maskRegistryDevice<T extends object>(d: T): T {
  const out = { ...(d as Record<string, any>) };
  if ('serialNumber' in out) out.serialNumber = null;
  if (out.apple && typeof out.apple === 'object') {
    const apple = { ...out.apple };
    if ('imei' in apple) apple.imei = null;
    if ('udid' in apple) apple.udid = null;
    if (apple.info && typeof apple.info === 'object') {
      const info = { ...apple.info };
      for (const k of ['phoneNumber', 'iccid', 'eid', 'wifiMac', 'bluetoothMac']) if (k in info) info[k] = null;
      apple.info = info;
    }
    out.apple = apple;
  }
  out.identifiersMasked = true;
  return out as T;
}

/** A bridge agent's list row or record without its identifiers (serials, IMEIs, Android id, Knox, identifying status). */
function maskLegacyDevice<T extends object>(d: T): T {
  const out = { ...(d as Record<string, any>) };
  if ('serialNumber' in out) out.serialNumber = null;
  for (const k of ['androidId', 'claimedSerial', 'samsungSerial', 'hints', 'knoxInfo']) if (k in out) out[k] = null;
  if ('imeis' in out) out.imeis = [];
  if (Array.isArray(out.status)) out.status = out.status.filter((s: { item?: unknown }) => !IDENTIFIER_ITEM.test(String(s.item ?? '')));
  out.identifiersMasked = true;
  return out as T;
}

export function registerDeviceTools(): void {
  registerTool({
    name: 'search_devices', title: 'Search devices', scope: 'devices.read',
    description: 'The devices of a tenant you may see (registry list: name, platform, model, OS, states, last contact), with the filters of the console. Paginated. Serial numbers only with the scope devices.identifiers.',
    inputSchema: js.obj({
      tenant_id: js.tenant, q: js.str('Free text: name, serial, model, end user.', { maxLength: 100 }),
      platform: { type: 'array', items: { type: 'string' }, maxItems: 10 }, enrollment_state: { type: 'array', items: { type: 'string' }, maxItems: 10 },
      group_id: js.int('Only this group.'), include_subgroups: js.bool('With group_id: its sub-groups too.'), ungrouped: js.bool('Only ungrouped devices.'),
      tags: { type: 'array', items: { type: 'string' }, maxItems: 10 }, lost_mode: js.bool('Only devices in lost mode.'),
      sort_by: js.enumOf(DEVICE_LIST_SORT_KEYS, 'Sort key.'), sort_order: js.enumOf(['asc', 'desc'], 'Sort order.'),
      limit: js.limit, offset: js.offset,
    }, ['tenant_id']),
    args: SearchArgs,
    annotations: { title: 'Search devices', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'devices.read');
      const f = await deviceFilter(caller, a.tenant_id);
      const l = a.limit ?? 50;
      const o = a.offset ?? 0;
      const r = await deviceService.listDevices(a.tenant_id, {
        q: a.q, platform: a.platform, enrollmentState: a.enrollment_state, groupId: a.group_id, includeSubgroups: a.include_subgroups,
        ungrouped: a.ungrouped, tags: a.tags, lostMode: a.lost_mode, sortBy: a.sort_by, sortOrder: a.sort_order,
        offset: o, pageSize: l, visibleIds: f.ids,
      }, { globalView: false });
      const items = (await identifiersAllowed(caller, a.tenant_id)) ? r.items : r.items.map(maskRegistryDevice);
      return page(items, o, l, r.total);
    }),
  });

  registerTool({
    name: 'get_device', title: 'Get a device', scope: 'devices.read',
    description: 'The registry record of one device (identity, hardware, OS, states, group, end user, last contact). Identifiers (serial, IMEI, UDID, phone number, ICCID, EID, MAC addresses) only with the scope devices.identifiers.',
    inputSchema: js.obj({ tenant_id: js.tenant, device_id: js.int('The device id.') }, ['tenant_id', 'device_id']),
    args: DeviceArgs,
    annotations: { title: 'Get a device', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'devices.read');
      await resolveCallerDevice(caller, a.tenant_id, a.device_id);
      const d = await deviceService.getDeviceById(a.device_id, a.tenant_id, { globalView: false });
      if (!d) throw deviceNotFound();
      return (await identifiersAllowed(caller, a.tenant_id)) ? d : maskRegistryDevice(d);
    }),
  });

  registerTool({
    name: 'get_device_inventory', title: 'Get the inventory of a device', scope: 'devices.read',
    description: 'One section of the inventory of a device: apps, profiles, certificates, configuration (secrets masked) or enrollments.',
    inputSchema: js.obj({
      tenant_id: js.tenant, device_id: js.int('The device id.'),
      section: js.enumOf(['apps', 'profiles', 'certificates', 'configuration', 'enrollments'], 'The section.'), limit: js.limit, offset: js.offset,
    }, ['tenant_id', 'device_id', 'section']),
    args: InventoryArgs,
    annotations: { title: 'Get the inventory of a device', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'devices.read');
      await resolveCallerDevice(caller, a.tenant_id, a.device_id);
      const l = a.limit ?? 50;
      const o = a.offset ?? 0;
      switch (a.section) {
        case 'apps': { const r = await deviceApps(a.tenant_id, a.device_id); return { collectedAt: r.collectedAt, ...slice(r.apps, o, l) }; }
        case 'profiles': return slice(await deviceProfiles(a.tenant_id, a.device_id), o, l);
        case 'certificates': return slice(await deviceCertificates(a.tenant_id, a.device_id), o, l);
        case 'configuration': return deviceConfiguration(a.tenant_id, a.device_id);
        case 'enrollments': return slice(await listEpisodes(a.tenant_id, a.device_id), o, l);
      }
      return null;
    }),
  });

  registerTool({
    name: 'list_legacy_agent_devices', title: 'List the Android agent devices', scope: 'devices.read',
    description: 'The Android bridge agents of a tenant you may see: model, Android, agent version, admin mode, Knox, battery, last interrogation and inventory. Filters: conflict, admin_inactive, silent (24 h), revoked. Serial numbers only with the scope devices.identifiers.',
    inputSchema: js.obj({
      tenant_id: js.tenant, q: js.str('Free text: name, serial, model.', { maxLength: 100 }), conflict: js.bool('Identity conflicts only.'),
      admin_inactive: js.bool('Device administrator inactive only.'), silent: js.bool('Silent for 24 hours only.'), revoked: js.bool('Include revoked agents.'),
      limit: js.limit, offset: js.offset,
    }, ['tenant_id']),
    args: LegacyListArgs,
    annotations: { title: 'List the Android agent devices', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'devices.read');
      const f = await deviceFilter(caller, a.tenant_id);
      const l = a.limit ?? 50;
      const o = a.offset ?? 0;
      const r = await listDevices(a.tenant_id, {
        q: a.q, conflict: a.conflict, adminInactive: a.admin_inactive, silent: a.silent, revoked: a.revoked, limit: l, offset: o,
      }, f.ids);
      const items = (await identifiersAllowed(caller, a.tenant_id)) ? r.items : r.items.map(maskLegacyDevice);
      return page(items, o, l, r.total);
    }),
  });

  registerTool({
    name: 'get_legacy_agent_device', title: 'Get an Android agent device', scope: 'devices.read',
    description: 'One Android bridge agent: status items, installed apps (2000 at most), Knox. Device identifiers (IMEI, Android id, serials, Knox details) only with include_identifiers and the scope devices.identifiers.',
    inputSchema: js.obj({
      tenant_id: js.tenant, device_id: js.int('The device id.'), include_identifiers: js.bool('Return IMEIs, Android id and serials (scope devices.identifiers).'),
    }, ['tenant_id', 'device_id']),
    args: LegacyDeviceArgs,
    annotations: { title: 'Get an Android agent device', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'devices.read');
      await resolveCallerDevice(caller, a.tenant_id, a.device_id);
      const d = await deviceDetail(a.tenant_id, a.device_id);
      if (!d) throw deviceNotFound();
      const allowed = a.include_identifiers === true && (await identifiersAllowed(caller, a.tenant_id));
      return allowed ? d : maskLegacyDevice(d);
    }),
  });

  registerTool({
    name: 'list_groups', title: 'List the groups', scope: 'devices.read',
    description: 'The device groups of a tenant you may see (id, name, parent), within the groups of this key (a group includes its sub-groups).',
    inputSchema: js.obj({ tenant_id: js.tenant }, ['tenant_id']),
    args: GroupsArgs,
    annotations: { title: 'List the groups', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'devices.read');
      const f = await groupFilter(caller, a.tenant_id);
      const q = db('device_groups').where({ tenant_id: a.tenant_id }).orderBy('name').limit(5000);
      if (f.ids !== 'all') {
        if (f.ids.length === 0) return { items: [] };
        q.whereIn('id', f.ids);
      }
      const rows = await q.select('id', 'name', 'parent_id') as Array<{ id: number; name: string; parent_id: number | null }>;
      return { items: rows.map((g) => ({ id: Number(g.id), name: g.name, parentId: g.parent_id === null ? null : Number(g.parent_id) })) };
    }),
  });
}

export const notSupported = (what: string): AppError => new AppError(422, `${what} is not available through the MCP server in this version`, 'notSupported');

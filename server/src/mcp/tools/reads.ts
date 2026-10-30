import { z } from 'zod';
import { audit } from '../../audit';
import { listEntries } from '../../audit/read';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { listApps } from '../../mdm/apps/appCatalogService';
import { liveAlertService } from '../../services/liveAlert.service';
import { commandOf, deviceCommands, listPackages, listReleases } from '../../legacyAgent/console';
import { requireScope, withTenant } from '../caller';
import { accessKeyDetail, mcpAuditCtx } from '../audit';
import { deviceFilter, resolveCallerDevice } from '../perimeter';
import { READ, js, page, registerTool } from './index';
import { deviceId, limit, offset, tenantId } from './common';
import { notSupported } from './devices';

// =============================================================================
// The other reads (docs: specs mcp-server §5.1): command queues and results,
// live alerts, the app catalog, the bridge agent's packages and versions, the
// audit log. In the tenant named, as the human, within the key's perimeter.
// The command queues of the Apple and Android (AMAPI) channels are not served
// by v1: their console routes have not been extracted from their requests yet.
// =============================================================================

const CommandsArgs = z.object({
  tenant_id: tenantId, device_id: deviceId, state: z.enum(['open', 'final', 'all']).optional(), limit: z.number().int().min(1).max(100).optional(),
}).strict();
const CommandArgs = z.object({
  tenant_id: tenantId, channel: z.enum(['legacy_agent', 'apple', 'android']), command_id: z.string().uuid(),
}).strict();
const AlertsArgs = z.object({ tenant_id: tenantId, limit: z.number().int().min(1).max(100).optional() }).strict();
const CatalogArgs = z.object({ tenant_id: tenantId, q: z.string().trim().max(100).optional(), archived: z.boolean().optional(), limit, offset }).strict();
const TenantArgs = z.object({ tenant_id: tenantId, limit, offset }).strict();
const AuditArgs = z.object({
  tenant_id: tenantId, device_id: deviceId.optional(), action: z.string().regex(/^[a-z][a-z0-9_.]{0,99}$/).optional(),
  since: z.string().datetime({ offset: true }).optional(), limit: z.number().int().min(1).max(200).optional(),
  offset: z.number().int().min(0).max(10_000).optional(),
}).strict();

/** The device id of a live alert, from its stable key (device:<id>:…), or null. */
const deviceOfAlert = (a: { stableKey: string | null; navigateTo: string | null }): number | null => {
  const m = /^device:(\d{1,10}):/.exec(a.stableKey ?? '') ?? /\/devices\/(\d{1,10})(\/|$|\?)/.exec(a.navigateTo ?? '');
  return m ? Number(m[1]) : null;
};

export function registerReadTools(): void {
  registerTool({
    name: 'list_device_commands', title: 'List the commands of a device', scope: 'commands.read',
    description: 'The command queue of an Android agent device (last 100, newest first): type, state, result code and detail. state: open (pending, sent), final, all.',
    inputSchema: js.obj({
      tenant_id: js.tenant, device_id: js.int('The device id.'), state: js.enumOf(['open', 'final', 'all'], 'Which commands (default all).'),
      limit: js.int('At most 100.', { minimum: 1, maximum: 100 }),
    }, ['tenant_id', 'device_id']),
    args: CommandsArgs,
    annotations: { title: 'List the commands of a device', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'commands.read');
      const d = await resolveCallerDevice(caller, a.tenant_id, a.device_id);
      if (d.managementChannel !== 'legacy_agent') throw notSupported('The command queue of this channel');
      return { items: await deviceCommands(a.tenant_id, a.device_id, a.state ?? 'all', a.limit ?? 100) };
    }),
  });

  registerTool({
    name: 'get_command', title: 'Get a command', scope: 'commands.read',
    description: 'One command of the Android agent queue, with its result (channel legacy_agent).',
    inputSchema: js.obj({
      tenant_id: js.tenant, channel: js.enumOf(['legacy_agent', 'apple', 'android'], 'The queue.'), command_id: js.str('The command id (uuid).', { format: 'uuid' }),
    }, ['tenant_id', 'channel', 'command_id']),
    args: CommandArgs,
    annotations: { title: 'Get a command', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'commands.read');
      if (a.channel !== 'legacy_agent') throw notSupported('The command queue of this channel');
      const c = await commandOf(a.tenant_id, a.command_id);
      if (!c) throw new AppError(404, 'Command not found', 'notFound');
      await resolveCallerDevice(caller, a.tenant_id, c.deviceId).catch(() => { throw new AppError(404, 'Command not found', 'notFound'); });
      return c;
    }),
  });

  registerTool({
    name: 'list_alerts', title: 'List the live alerts', scope: 'alerts.read',
    description: 'The active live alerts of a tenant (newest first), limited to the devices of this key; alerts that name no device only when the key covers every group and device.',
    inputSchema: js.obj({ tenant_id: js.tenant, limit: js.int('At most 100.', { minimum: 1, maximum: 100 }) }, ['tenant_id']),
    args: AlertsArgs,
    annotations: { title: 'List the live alerts', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'alerts.read');
      const rows = await liveAlertService.getForTenant(a.tenant_id, a.limit ?? 50, { platformAdmin: caller.isPlatformAdmin });
      const f = await deviceFilter(caller, a.tenant_id);
      const whole = caller.key.groupMode === 'all' && caller.key.deviceMode === 'all';
      const inside = f.ids === 'all' ? null : new Set(f.ids);
      const items = rows.filter((r) => {
        const d = deviceOfAlert(r);
        if (d === null) return whole;
        return inside === null || inside.has(d);
      }).map((r) => ({
        id: r.id, severity: r.severity, title: r.title, message: r.message, kind: r.kind ?? null, deviceId: deviceOfAlert(r), createdAt: r.createdAt, readAt: r.readAt,
      }));
      return { items };
    }),
  });

  registerTool({
    name: 'list_app_catalog', title: 'List the app catalog', scope: 'apps.read',
    description: 'The apps of the catalog of a tenant (Apple, Android, web): name, kind, identifiers.',
    inputSchema: js.obj({ tenant_id: js.tenant, q: js.str('Free text.', { maxLength: 100 }), archived: js.bool('Archived apps only.'), limit: js.limit, offset: js.offset }, ['tenant_id']),
    args: CatalogArgs,
    annotations: { title: 'List the app catalog', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'apps.read');
      const all = await listApps(db, a.tenant_id, { archived: a.archived, q: a.q });
      const l = a.limit ?? 50;
      const o = a.offset ?? 0;
      return page(all.slice(o, o + l), o, l, all.length);
    }),
  });

  registerTool({
    name: 'list_legacy_packages', title: 'List the Android agent packages', scope: 'apps.read',
    description: 'The APK packages of a tenant an install_app may name (needs the mdm.apps.manage capability in the tenant).',
    inputSchema: js.obj({ tenant_id: js.tenant, limit: js.limit, offset: js.offset }, ['tenant_id']),
    args: TenantArgs,
    annotations: { title: 'List the Android agent packages', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'apps.read', 'mdm.apps.manage');
      const all = await listPackages(a.tenant_id);
      const l = a.limit ?? 50;
      const o = a.offset ?? 0;
      return page(all.slice(o, o + l), o, l, all.length);
    }),
  });

  registerTool({
    name: 'list_legacy_agent_releases', title: 'List the Android agent versions', scope: 'apps.read',
    description: 'The versions of the Android bridge agent an update_agent may name (not withdrawn).',
    inputSchema: js.obj({ tenant_id: js.tenant, limit: js.limit, offset: js.offset }, ['tenant_id']),
    args: TenantArgs,
    annotations: { title: 'List the Android agent versions', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'apps.read');
      const all = await listReleases();
      const l = a.limit ?? 50;
      const o = a.offset ?? 0;
      return page(all.slice(o, o + l), o, l, all.length);
    }),
  });

  registerTool({
    name: 'read_audit_log', title: 'Read the audit log', scope: 'audit.read',
    description: "Entries of the tenant's audit log (newest first). With device_id, that device's entries; without, only when the key covers every group and device. Needs the audit.read capability.",
    inputSchema: js.obj({
      tenant_id: js.tenant, device_id: js.int('Only this device.'), action: js.str('An action, or a prefix ending with a dot.'),
      since: js.str('ISO date-time.', { format: 'date-time' }), limit: js.int('At most 200.', { minimum: 1, maximum: 200 }),
      offset: js.int('Offset in the list, newest first (at most 10000).', { minimum: 0, maximum: 10000 }),
    }, ['tenant_id']),
    args: AuditArgs,
    annotations: { title: 'Read the audit log', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'audit.read', 'audit.read');
      if (a.device_id !== undefined) await resolveCallerDevice(caller, a.tenant_id, a.device_id);
      else if (caller.key.groupMode !== 'all' || caller.key.deviceMode !== 'all') {
        throw new AppError(403, 'This key covers part of the devices only: name a device_id', 'deviceRequired');
      }
      const r = await listEntries({
        tenantId: a.tenant_id, deviceId: a.device_id, action: a.action, since: a.since ? new Date(a.since) : undefined, limit: a.limit ?? 50,
        offset: a.offset ?? 0,
      });
      // The MCP equivalent of noteViewed (no session to mark): one entry per read.
      try {
        await audit.append({
          tenantId: a.tenant_id, action: 'mcp.audit.read', target: { type: 'tenant', id: String(a.tenant_id) },
          details: { accessKey: accessKeyDetail(caller), deviceId: a.device_id ?? null, action: a.action ?? null, count: r.items.length },
        }, await mcpAuditCtx(caller, a.tenant_id, 'read_audit_log'));
      } catch { /* a standard entry is spooled by the writer */ }
      return page(r.items, a.offset ?? 0, a.limit ?? 50, r.total);
    }),
  });

}

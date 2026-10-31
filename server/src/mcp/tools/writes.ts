import { createHash } from 'node:crypto';
import type { Request } from 'express';
import type { Knex } from 'knex';
import { z } from 'zod';
import type { McpScope } from '@obligarth/shared';
import { audit, canonicalJson, type AuditWriteContext } from '../../audit';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { refreshInventoryNow } from '../../apple/commands/inventory';
import { tenantFrozen } from '../../guard/frozen';
import { changeDevicesGroup } from '../../mdm/policies/deviceMove';
import { verifyImpactToken } from '../../mdm/policies/impactToken';
import { permissionService } from '../../services/permission.service';
import { cancelCommand, commandOf, lackingCapability, requestCommand, type CommandOutcome, type ConsoleCaller } from '../../legacyAgent/console';
import { accessKeyDetail, mcpAuditCtx } from '../audit';
import { createPending, type AuthorizationRow } from '../authorizations/service';
import { holdsTenantCapability, requireScope, withTenant, type McpCaller } from '../caller';
import { mcpGate, type RestrictionGate } from '../gate';
import { assertDevicesInPerimeter, assertGroupTargetInPerimeter, groupNotFound } from '../perimeter';
import { APPROVAL_MESSAGE, AUTHORIZE_MESSAGE, deviceId, deviceIds, namesOf, reason, takeWrite, tenantId } from './common';
import { notSupported } from './devices';
import { js, registerTool } from './index';

// =============================================================================
// Write tools (docs: specs mcp-server §5.2 to §5.4): each through the console's
// own command core (legacyAgent/console.ts), the human's rights, the key's
// perimeter and the MCP gate of the restrictions matrix (owner decision 1): a
// sensitive action becomes an authorization the human approves with a second
// factor, a restricted one files the console's approval. A move of devices
// between groups is ALWAYS an authorization (its level depends on a preview
// only the human's request can carry). The text the agent writes (reason,
// message, package name) is data: stored, marked reasonSource 'agent', never
// part of a summary. The executors below run an approved authorization in the
// human's request, rights re-checked.
// Channels: the Android bridge agent for every command; the Apple queue for
// the inventory refresh; nothing on the Android (AMAPI) channel in v1.
// =============================================================================

const WRITE = { readOnlyHint: false, openWorldHint: false as const };

type GatedAnswer = Record<string, unknown>;

/** The answer of a write to the agent. */
function answer(out: CommandOutcome): GatedAnswer {
  if (out.kind === 'enqueued') {
    const o = out.outcome;
    return { status: 'queued', batchId: o.batchId, commandIds: o.commandIds, targets: o.targets, refused: o.refused, held: o.held, replayed: o.replayed };
  }
  const g = out.gate;
  if (g.kind === 'authorization') return { status: 'authorization_required', authorizationId: g.authorizationId, expiresAt: g.expiresAt, message: AUTHORIZE_MESSAGE };
  if (g.kind === 'approval') return { status: 'pending_approval', approvalId: g.approvalId, authorizationId: g.authorizationId ?? null, message: APPROVAL_MESSAGE };
  const body = (g.body ?? {}) as { error?: unknown };
  throw new AppError(g.status >= 400 && g.status < 500 ? g.status : 403, typeof body.error === 'string' ? body.error : 'Refused', 'refused');
}

/** A write refused for rights or perimeter is journaled (mcp.tool.denied); reads are not. */
async function denied(caller: McpCaller, tenant: number, tool: string, err: unknown, deviceIdsOf: number[]): Promise<void> {
  const e = err as { statusCode?: number; code?: string };
  if (!(err instanceof AppError) || (e.statusCode !== 403 && e.statusCode !== 404)) return;
  try {
    await audit.append({
      tenantId: tenant, action: 'mcp.tool.denied', outcome: 'denied', targets: deviceIdsOf.length ? { deviceIds: deviceIdsOf.slice(0, 50) } : undefined,
      details: { tool, code: e.code ?? null, status: e.statusCode, accessKey: accessKeyDetail(caller) },
    }, await mcpAuditCtx(caller, tenant, tool));
  } catch { /* spooled by the writer */ }
}

/** The devices of a write, with their names and channels (inside withTenant, after the perimeter check). */
async function devicesOf(tenant: number, ids: number[]): Promise<Array<{ id: number; label: string | null; channel: string }>> {
  const rows = await db('devices').where({ tenant_id: tenant }).whereRaw('id = ANY (?::int[])', [ids]).orderBy('id')
    .select('id', 'label', 'management_channel') as Array<{ id: number; label: string | null; management_channel: string }>;
  return rows.map((r) => ({ id: Number(r.id), label: r.label ?? null, channel: String(r.management_channel) }));
}

const consoleCallerOf = (caller: McpCaller, tenant: number, auditCtx: AuditWriteContext): ConsoleCaller =>
  ({ userId: caller.userId, isPlatformAdmin: caller.isPlatformAdmin, tenantId: tenant, auditCtx });

/** The entry of the key next to a command the queue journals itself (same transaction). */
function toolEntry(tenant: number, tool: string, ids: number[], details: Record<string, unknown>) {
  return {
    tenantId: tenant, action: 'mcp.tool.write', targets: ids.length ? { deviceIds: ids } : undefined, details: { tool, ...details },
  };
}

interface LegacySpec {
  tool: string;
  scope: McpScope;
  /** The command type and its parameters, from the validated arguments. */
  command(a: Record<string, any>): { type: string; params: Record<string, unknown> };
  /** The devices of the arguments. */
  ids(a: Record<string, any>): number[];
  /** The server-built summary (never the agent's text). */
  summary(tenant: number, a: Record<string, any>, devices: Array<{ id: number; label: string | null }>): Promise<string>;
  /** The keys of the arguments that are the agent's text. */
  agentText: string[];
}

/** A command of the bridge agent asked by an agent (§5.2). */
async function legacyWrite(caller: McpCaller, s: LegacySpec, a: Record<string, any>): Promise<GatedAnswer> {
  takeWrite(caller);
  const tenant = Number(a.tenant_id);
  const ids = s.ids(a);
  try {
    return await withTenant(caller, tenant, async () => {
      await requireScope(caller, tenant, s.scope);
      await assertDevicesInPerimeter(caller, tenant, ids);
      const devices = await devicesOf(tenant, ids);
      if (devices.some((d) => d.channel !== 'legacy_agent')) throw notSupported('This command on a device that is not an Android agent');
      const summary = await s.summary(tenant, a, devices);
      const ctx = await mcpAuditCtx(caller, tenant, s.tool);
      const { type, params } = s.command(a);
      const hasText = s.agentText.some((k) => a[k] !== undefined && a[k] !== '');
      const out = await requestCommand(consoleCallerOf(caller, tenant, ctx), {
        type, params, deviceIds: ids, reason: typeof a.reason === 'string' ? a.reason : undefined, origin: ids.length > 1 ? 'bulk' : 'console',
      }, mcpGate({ caller, tool: s.tool, args: a, summary }), {
        inTx: (trx, o) => audit.appendInTx(trx, toolEntry(tenant, s.tool, ids, {
          requestType: type, batchId: o.batchId, commandIds: o.commandIds.slice(0, 50), accessKey: accessKeyDetail(caller),
          ...(hasText ? { reasonSource: 'agent' } : {}),
        }), ctx, { onFailure: 'spool' }).then(() => undefined),
      });
      return answer(out);
    });
  } catch (err) {
    await withTenant(caller, tenant, () => denied(caller, tenant, s.tool, err, ids)).catch(() => undefined);
    throw err;
  }
}

const label = (tenant: number) => db('tenants').where({ id: tenant }).first('name') as Promise<{ name: string } | undefined>;
const inTenant = async (tenant: number): Promise<string> => { const t = await label(tenant); return t ? ` (tenant ${t.name})` : ''; };

const LEGACY: Record<string, LegacySpec> = {
  send_device_message: {
    tool: 'send_device_message', scope: 'commands.message', agentText: ['title', 'text', 'reason'],
    command: (a) => ({ type: 'device.message', params: { title: a.title, text: a.text, mode: a.mode } }),
    ids: (a) => [...new Set<number>(a.device_ids)],
    summary: async (t, a, d) => `Show a ${a.mode} message on ${d.length} Android agent device(s): ${namesOf(d)}${await inTenant(t)}`,
  },
  reboot_device: {
    tool: 'reboot_device', scope: 'commands.restart', agentText: ['reason'],
    command: () => ({ type: 'device.reboot', params: {} }),
    ids: (a) => [...new Set<number>(a.device_ids)],
    summary: async (t, _a, d) => `Restart ${d.length} Android agent device(s): ${namesOf(d)}${await inTenant(t)}`,
  },
  install_app: {
    tool: 'install_app', scope: 'commands.apps', agentText: ['reason'],
    command: (a) => ({ type: 'app.install', params: { packageId: a.package_id } }),
    ids: (a) => [...new Set<number>(a.device_ids)],
    summary: async (t, a, d) => {
      const p = await db('legacy_agent_packages').where({ tenant_id: t, id: a.package_id }).first('package_name', 'version_name', 'version_code') as Record<string, any> | undefined;
      const what = p ? `${p.package_name} ${p.version_name ?? p.version_code}` : 'a package of the tenant';
      return `Install ${what} on ${d.length} Android agent device(s): ${namesOf(d)}${await inTenant(t)}`;
    },
  },
  uninstall_app: {
    tool: 'uninstall_app', scope: 'commands.apps', agentText: ['package_name', 'reason'],
    command: (a) => ({ type: 'app.uninstall', params: { packageName: a.package_name } }),
    ids: (a) => [...new Set<number>(a.device_ids)],
    summary: async (t, _a, d) => `Uninstall an app (package named by the AI agent, see its text) from ${d.length} Android agent device(s): ${namesOf(d)}${await inTenant(t)}`,
  },
  pull_app: {
    tool: 'pull_app', scope: 'commands.apps', agentText: ['package_name', 'reason'],
    command: (a) => ({ type: 'app.pull', params: { packageName: a.package_name } }),
    ids: (a) => [Number(a.device_id)],
    summary: async (t, _a, d) => `Send back the APK of an installed app (package named by the AI agent, see its text) from ${namesOf(d)}${await inTenant(t)}`,
  },
  update_agent: {
    tool: 'update_agent', scope: 'commands.apps', agentText: ['reason'],
    command: (a) => ({ type: 'agent.update', params: { releaseId: a.release_id } }),
    ids: (a) => [...new Set<number>(a.device_ids)],
    summary: async (t, a, d) => {
      const r = await db('legacy_agent_releases').where({ id: a.release_id }).first('version_name', 'version_code') as Record<string, any> | undefined;
      return `Update the Android agent to ${r ? `${r.version_name} (${r.version_code})` : 'a version'} on ${d.length} device(s): ${namesOf(d)}${await inTenant(t)}`;
    },
  },
};

const pkgName = z.string().max(255).regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/);

const ARGS = {
  send_device_message: z.object({
    tenant_id: tenantId, device_ids: deviceIds, title: z.string().trim().min(1).max(80), text: z.string().trim().min(1).max(500),
    mode: z.enum(['notification', 'fullscreen']), reason,
  }).strict(),
  reboot_device: z.object({ tenant_id: tenantId, device_ids: deviceIds, reason }).strict(),
  install_app: z.object({ tenant_id: tenantId, device_ids: deviceIds, package_id: z.string().uuid(), reason }).strict(),
  uninstall_app: z.object({ tenant_id: tenantId, device_ids: deviceIds, package_name: pkgName, reason }).strict(),
  pull_app: z.object({ tenant_id: tenantId, device_id: deviceId, package_name: pkgName, reason }).strict(),
  update_agent: z.object({ tenant_id: tenantId, device_ids: deviceIds, release_id: z.string().uuid(), reason }).strict(),
};

const ids = js.ids('Device ids, 1 to 50.');
const why = js.str('Why (stored as your text, shown to the human apart).', { maxLength: 500 });

export function registerWriteTools(): void {
  registerTool({
    name: 'refresh_inventory', title: 'Refresh the inventory', scope: 'commands.inventory',
    description: 'Asks devices for a fresh inventory (Android bridge agent; Apple devices: the inventory commands, at most once per 5 minutes). Runs directly unless the restrictions say otherwise.',
    inputSchema: js.obj({ tenant_id: js.tenant, device_ids: ids, reason: why }, ['tenant_id', 'device_ids']),
    args: z.object({ tenant_id: tenantId, device_ids: deviceIds, reason }).strict(),
    annotations: { title: 'Refresh the inventory', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: async (caller, a) => {
      takeWrite(caller);
      const tenant = a.tenant_id;
      const wanted = [...new Set(a.device_ids)];
      try {
        return await withTenant(caller, tenant, async () => {
          await requireScope(caller, tenant, 'commands.inventory');
          await assertDevicesInPerimeter(caller, tenant, wanted);
          const devices = await devicesOf(tenant, wanted);
          if (devices.some((d) => d.channel !== 'legacy_agent' && d.channel !== 'apple_mdm')) throw notSupported('The inventory refresh of an Android (AMAPI) device');
          const ctx = await mcpAuditCtx(caller, tenant, 'refresh_inventory');
          const out: Record<string, unknown> = { status: 'queued' };
          const legacy = devices.filter((d) => d.channel === 'legacy_agent').map((d) => d.id);
          const apple = devices.filter((d) => d.channel === 'apple_mdm').map((d) => d.id);
          if (apple.length) {
            const without = await lackingCapability(caller, apple, 'mdm:inventory');
            if (without.length > 0) throw new AppError(403, "Capability 'mdm:inventory' not permitted on some devices", 'capabilityMissing', { count: without.length });
            if (await tenantFrozen(null, tenant, 'apple_mdm')) throw new AppError(423, 'The commands of this tenant are frozen', 'tenantFrozen');
          }
          if (legacy.length) {
            const r = await requestCommand(consoleCallerOf(caller, tenant, ctx), {
              type: 'inventory.refresh', params: {}, deviceIds: legacy, reason: a.reason, origin: legacy.length > 1 ? 'bulk' : 'console',
            }, mcpGate({ caller, tool: 'refresh_inventory', args: a, summary: `Refresh the inventory of ${legacy.length} device(s)` }), {
              inTx: (trx, o) => audit.appendInTx(trx, toolEntry(tenant, 'refresh_inventory', legacy, {
                requestType: 'inventory.refresh', batchId: o.batchId, accessKey: accessKeyDetail(caller), ...(a.reason ? { reasonSource: 'agent' } : {}),
              }), ctx, { onFailure: 'spool' }).then(() => undefined),
            });
            out.legacyAgent = answer(r);
          }
          if (apple.length) {
            const results: Array<Record<string, unknown>> = [];
            for (const id of apple) {
              try {
                const o = await db.transaction(async (trx) => {
                  const r = await refreshInventoryNow(trx, tenant, id, caller.userId, ctx);
                  await audit.appendInTx(trx, toolEntry(tenant, 'refresh_inventory', [id], {
                    channel: 'apple', commandIds: r.commandIds, accessKey: accessKeyDetail(caller), ...(a.reason ? { reasonSource: 'agent' } : {}),
                  }), ctx, { onFailure: 'spool' });
                  return r;
                });
                results.push({ deviceId: id, commandIds: o.commandIds, refused: o.refused });
              } catch (err) {
                if (err instanceof AppError && err.statusCode < 500) results.push({ deviceId: id, error: err.code ?? 'refused', message: err.message });
                else throw err;
              }
            }
            out.apple = results;
          }
          return out;
        });
      } catch (err) {
        await withTenant(caller, tenant, () => denied(caller, tenant, 'refresh_inventory', err, wanted)).catch(() => undefined);
        throw err;
      }
    },
  });

  registerTool({
    name: 'send_device_message', title: 'Show a message on devices', scope: 'commands.message',
    description: 'Shows a message (notification or full screen) on Android agent devices. Restriction legacy_agent.message: may need the human (authorization) or another approver.',
    inputSchema: js.obj({
      tenant_id: js.tenant, device_ids: ids, title: js.str('Title, 80 characters at most.', { maxLength: 80 }),
      text: js.str('Text, 500 characters at most.', { maxLength: 500 }), mode: js.enumOf(['notification', 'fullscreen'], 'How it is shown.'), reason: why,
    }, ['tenant_id', 'device_ids', 'title', 'text', 'mode']),
    args: ARGS.send_device_message,
    annotations: { title: 'Show a message on devices', ...WRITE, destructiveHint: false, idempotentHint: false },
    run: (caller, a) => legacyWrite(caller, LEGACY.send_device_message, a),
  });

  registerTool({
    name: 'reboot_device', title: 'Restart devices', scope: 'commands.restart',
    description: 'Restarts Android agent devices (Knox licensed). Restriction legacy_agent.restart: may need the human (authorization) or another approver.',
    inputSchema: js.obj({ tenant_id: js.tenant, device_ids: ids, reason: why }, ['tenant_id', 'device_ids']),
    args: ARGS.reboot_device,
    annotations: { title: 'Restart devices', ...WRITE, destructiveHint: true, idempotentHint: false },
    run: (caller, a) => legacyWrite(caller, LEGACY.reboot_device, a),
  });

  registerTool({
    name: 'install_app', title: 'Install an app', scope: 'commands.apps',
    description: 'Installs a package of the tenant (see list_legacy_packages) on Android agent devices. Restriction legacy_agent.apps.',
    inputSchema: js.obj({ tenant_id: js.tenant, device_ids: ids, package_id: js.str('The package id (uuid).', { format: 'uuid' }), reason: why }, ['tenant_id', 'device_ids', 'package_id']),
    args: ARGS.install_app,
    annotations: { title: 'Install an app', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => legacyWrite(caller, LEGACY.install_app, a),
  });

  registerTool({
    name: 'uninstall_app', title: 'Uninstall an app', scope: 'commands.apps',
    description: 'Uninstalls an app (Android package name) from Android agent devices. Restriction legacy_agent.apps.',
    inputSchema: js.obj({ tenant_id: js.tenant, device_ids: ids, package_name: js.str('The Android package name.', { maxLength: 255 }), reason: why }, ['tenant_id', 'device_ids', 'package_name']),
    args: ARGS.uninstall_app,
    annotations: { title: 'Uninstall an app', ...WRITE, destructiveHint: true, idempotentHint: true },
    run: (caller, a) => legacyWrite(caller, LEGACY.uninstall_app, a),
  });

  registerTool({
    name: 'pull_app', title: 'Send back the APK of an app', scope: 'commands.apps',
    description: 'Asks one Android agent device to send back the APK of an installed app, stored as a package of the tenant. Restriction legacy_agent.apps.',
    inputSchema: js.obj({ tenant_id: js.tenant, device_id: js.int('The device id.'), package_name: js.str('The Android package name.', { maxLength: 255 }), reason: why }, ['tenant_id', 'device_id', 'package_name']),
    args: ARGS.pull_app,
    annotations: { title: 'Send back the APK of an app', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => legacyWrite(caller, LEGACY.pull_app, a),
  });

  registerTool({
    name: 'update_agent', title: 'Update the Android agent', scope: 'commands.apps',
    description: 'Updates the Android bridge agent to a version (see list_legacy_agent_releases). Restriction legacy_agent.update.',
    inputSchema: js.obj({ tenant_id: js.tenant, device_ids: ids, release_id: js.str('The version id (uuid).', { format: 'uuid' }), reason: why }, ['tenant_id', 'device_ids', 'release_id']),
    args: ARGS.update_agent,
    annotations: { title: 'Update the Android agent', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => legacyWrite(caller, LEGACY.update_agent, a),
  });

  registerTool({
    name: 'cancel_command', title: 'Cancel a pending command', scope: 'commands.cancel',
    description: 'Cancels a command of the Android agent queue not delivered yet: its device must be within this key, and you its author or holding the capability of its type.',
    inputSchema: js.obj({
      tenant_id: js.tenant, channel: js.enumOf(['legacy_agent', 'apple', 'android'], 'The queue.'), command_id: js.str('The command id (uuid).', { format: 'uuid' }),
    }, ['tenant_id', 'channel', 'command_id']),
    args: z.object({ tenant_id: tenantId, channel: z.enum(['legacy_agent', 'apple', 'android']), command_id: z.string().uuid() }).strict(),
    annotations: { title: 'Cancel a pending command', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: async (caller, a) => {
      takeWrite(caller);
      const tenant = a.tenant_id;
      try {
        return await withTenant(caller, tenant, async () => {
          await requireScope(caller, tenant, 'commands.cancel');
          if (a.channel !== 'legacy_agent') throw notSupported('The cancellation in this queue');
          const c = await commandOf(tenant, a.command_id);
          if (!c) throw new AppError(404, 'Command not found', 'notFound');
          // Every target of the command inside the key's perimeter, else 404 (A6).
          await assertDevicesInPerimeter(caller, tenant, [c.deviceId]).catch(() => { throw new AppError(404, 'Command not found', 'notFound'); });
          const ctx = await mcpAuditCtx(caller, tenant, 'cancel_command');
          const r = await cancelCommand(consoleCallerOf(caller, tenant, ctx), a.command_id);
          await audit.append(toolEntry(tenant, 'cancel_command', [c.deviceId], { commandId: a.command_id, accessKey: accessKeyDetail(caller) }), ctx)
            .catch(() => undefined);
          return { status: 'cancelled', commandId: a.command_id.toLowerCase(), deviceId: r.deviceId };
        });
      } catch (err) {
        await withTenant(caller, tenant, () => denied(caller, tenant, 'cancel_command', err, [])).catch(() => undefined);
        throw err;
      }
    },
  });

  registerTool({
    name: 'move_devices_to_group', title: 'Move devices to a group', scope: 'groups.move',
    description: 'Moves devices into a group (or out of any group with group_id null). ALWAYS an authorization: the human sees the preview of what the devices inherit, then approves with a second factor.',
    inputSchema: js.obj({
      tenant_id: js.tenant, device_ids: ids, group_id: { type: ['integer', 'null'], minimum: 1, description: 'The target group, or null for no group.' }, reason: why,
    }, ['tenant_id', 'device_ids', 'group_id']),
    args: z.object({ tenant_id: tenantId, device_ids: deviceIds, group_id: z.number().int().positive().nullable(), reason }).strict(),
    annotations: { title: 'Move devices to a group', ...WRITE, destructiveHint: false, idempotentHint: false },
    run: async (caller, a) => {
      takeWrite(caller);
      const tenant = a.tenant_id;
      const wanted = [...new Set(a.device_ids)];
      try {
        return await withTenant(caller, tenant, async () => {
          await requireScope(caller, tenant, 'groups.move', 'devices.manage');
          await assertDevicesInPerimeter(caller, tenant, wanted);
          await assertGroupTargetInPerimeter(caller, tenant, a.group_id);
          await checkMoveRights(caller, tenant, wanted, a.group_id);
          const devices = await devicesOf(tenant, wanted);
          const g = a.group_id === null ? null : await db('device_groups').where({ tenant_id: tenant, id: a.group_id }).first('name') as { name: string } | undefined;
          const summary = `Move ${devices.length} device(s) ${g ? `into the group ${g.name}` : 'out of any group'}: ${namesOf(devices)}${await inTenant(tenant)}`;
          const row = await createPending(caller, {
            tenantId: tenant, tool: 'move_devices_to_group', actionKey: 'device.bulk_group_change', level: 'always_human', summary,
            args: a, deviceIds: wanted,
          });
          return { status: 'authorization_required', authorizationId: String(row.id), expiresAt: new Date(row.expires_at).toISOString(), message: AUTHORIZE_MESSAGE };
        });
      } catch (err) {
        await withTenant(caller, tenant, () => denied(caller, tenant, 'move_devices_to_group', err, wanted)).catch(() => undefined);
        throw err;
      }
    },
  });
}

/** The rights of a move, as the console's routes (devices.manage, write on every device and on the target group). */
export async function checkMoveRights(who: { userId: number; isPlatformAdmin: boolean }, tenant: number, ids: number[], groupId: number | null): Promise<void> {
  if (!(await holdsTenantCapability(who, tenant, 'devices.manage'))) throw new AppError(403, 'Insufficient permissions', 'capabilityMissing');
  if (who.isPlatformAdmin) return;
  for (const id of ids) {
    if (!(await permissionService.canWriteDevice(who.userId, id, false))) throw new AppError(403, 'Insufficient permissions', 'capabilityMissing');
  }
  if (groupId !== null && !(await permissionService.canWriteGroup(who.userId, groupId, false))) throw groupNotFound();
}

// ── Execution of an approved authorization (§6.4) ───────────────────────────

export interface ExecResult {
  state: 'executed' | 'filed' | 'failed';
  outcome?: Record<string, unknown>;
  errorCode?: string;
}

export interface ExecContext {
  /** The human's request (his session, tenant = the authorization's). */
  req: Request;
  row: AuthorizationRow;
  args: Record<string, any>;
  consoleCaller: ConsoleCaller;
  gate: RestrictionGate;
  /** Ends the row 'executed' in the transaction of the enqueue (crash-safe, exactly once). */
  finishInTx(trx: Knex.Transaction, outcome: Record<string, unknown>): Promise<void>;
  /** For a move: what the approval echoes. */
  echo?: { devicesToken?: unknown; impactDigest?: unknown };
  /** Prefixed to the description of an approval the execution files (who asked: the AI agent, its key). */
  descriptionPrefix?: string;
}

/** The tools an authorization may carry, and their re-check of the arguments (the stored ones, validated again). */
export const APPROVABLE_ARGS: Record<string, z.ZodTypeAny> = { ...ARGS };

function gatedResult(out: CommandOutcome): ExecResult {
  if (out.kind === 'enqueued') return { state: 'executed', outcome: { batchId: out.outcome.batchId, commandIds: out.outcome.commandIds } };
  const g = out.gate;
  if (g.kind === 'approval') return { state: 'filed', outcome: { approvalId: g.approvalId } };
  const body = (g.kind === 'refused' ? g.body : {}) as { error?: unknown; twoFactorRequired?: unknown };
  return { state: 'failed', errorCode: body.twoFactorRequired ? 'stepUpRequired' : g.kind === 'refused' ? `refused${g.status}` : 'refused' };
}

/** Runs an approved legacy command authorization as the human (rights re-checked by the console core). */
export async function executeLegacy(x: ExecContext): Promise<ExecResult> {
  const s = LEGACY[String(x.row.tool)];
  if (!s) return { state: 'failed', errorCode: 'unknownTool' };
  const { type, params } = s.command(x.args);
  const ids = s.ids(x.args);
  const out = await requestCommand(x.consoleCaller, {
    type, params, deviceIds: ids, reason: typeof x.args.reason === 'string' ? x.args.reason : undefined, origin: ids.length > 1 ? 'bulk' : 'console',
  }, x.gate, { inTx: (trx, o) => x.finishInTx(trx, { batchId: o.batchId, commandIds: o.commandIds }) });
  return gatedResult(out);
}

/**
 * The digest of the impact of a move, its devicesToken (the one the human echoes at approval) and its computedAt left
 * out: both change with every computation, so a digest over them never matched at approval (30/10, impactChanged).
 */
function impactDigestOf(raw: unknown): { impact: Record<string, unknown>; devicesToken: string | null; impactDigest: string } {
  const impact = { ...((raw ?? {}) as Record<string, unknown>) };
  const devicesToken = typeof impact.devicesToken === 'string' ? impact.devicesToken : null;
  delete impact.devicesToken;
  delete impact.computedAt;
  const impactDigest = createHash('sha256').update(canonicalJson(impact as never)).digest('hex');
  return { impact, devicesToken, impactDigest };
}

/** The preview of a move as the human sees it, and the digest of its impact (devicesToken left out). */
export async function movePreview(req: Request, tenant: number, ids: number[], groupId: number | null): Promise<{ impact: unknown; devicesToken: string | null; impactDigest: string }> {
  const out = await changeDevicesGroup(req, tenant, ids, groupId, true);
  return impactDigestOf((out.body as { data?: { impact?: Record<string, unknown> } }).data?.impact);
}

/** Runs an approved move as the human: rights, perimeter and the impact he approved checked again. */
export async function executeMove(x: ExecContext): Promise<ExecResult> {
  const tenant = Number(x.row.tenant_id);
  const ids = [...new Set<number>(x.args.device_ids)];
  const groupId = x.args.group_id === null ? null : Number(x.args.group_id);
  if (groupId !== null && !(await db('device_groups').where({ tenant_id: tenant, id: groupId }).first('id'))) return { state: 'failed', errorCode: 'perimeterLost' };
  await checkMoveRights({ userId: x.consoleCaller.userId, isPlatformAdmin: x.consoleCaller.isPlatformAdmin }, tenant, ids, groupId);
  const now = await movePreview(x.req, tenant, ids, groupId);
  // The token carries its expiry, signed anew each time: the echoed one must be genuine and name the same change.
  const changeOf = (t: unknown): string | null => {
    const c = typeof t === 'string' ? verifyImpactToken(t, tenant, x.consoleCaller.userId) : null;
    return c ? canonicalJson(c as never) : null;
  };
  if (typeof x.echo?.impactDigest !== 'string' || x.echo.impactDigest !== now.impactDigest
    || (now.devicesToken !== null && changeOf(x.echo.devicesToken) !== changeOf(now.devicesToken))) {
    return { state: 'failed', errorCode: 'impactChanged' };
  }
  // The approved digest is compared again under the lock of the configuration, right before the devices move (or the
  // approval is filed): a policy change committed since the check above is never applied unseen.
  const approved = String(x.echo?.impactDigest);
  let out: Awaited<ReturnType<typeof changeDevicesGroup>>;
  try {
    out = await changeDevicesGroup(x.req, tenant, ids, groupId, false, {
      expectImpact: (impact) => impactDigestOf(impact).impactDigest === approved,
      descriptionPrefix: x.descriptionPrefix,
    });
  } catch (err) {
    if (err instanceof AppError && err.code === 'impactChanged') return { state: 'failed', errorCode: 'impactChanged' };
    throw err;
  }
  const data = (out.body as { data?: { approvalId?: number; changed?: number; changedIds?: number[] } }).data;
  if (out.status === 202 && data?.approvalId) return { state: 'filed', outcome: { approvalId: Number(data.approvalId) } };
  if (out.status === 200) return { state: 'executed', outcome: { changed: Number(data?.changed ?? 0) } };
  const body = (out.body ?? {}) as { twoFactorRequired?: unknown };
  return { state: 'failed', errorCode: body.twoFactorRequired ? 'stepUpRequired' : `refused${out.status}` };
}

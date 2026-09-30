import { db } from '../db';
import { logger } from '../utils/logger';
import { getIO } from '../socket';
import { isMasterTenant, SocketEvents } from '@obliance/shared';
import { commandService, PRIVACY_BLOCKED_COMMANDS } from './command.service';
import {
  activeRequester, auditAs, refuse, requirePlatformAdmin,
  type ApprovalExecution, type BatchCommandPayload,
} from './approval.service';

// ── Approval executors of the device commands (agent) ───────────────────────
// Executed AS THE REQUESTER once a second administrator approved them
// (approval.service). Registered by modules/rmm.ts.

/** Raw device commands only a platform administrator may send (POST
 *  /api/commands ADMIN_ONLY_COMMANDS). */
const DEVICE_ADMIN_ONLY: ReadonlySet<string> = new Set([
  'update_agent',
]);

/** Commands the legacy (Go 1.20) agent cannot run — same list as POST
 *  /api/commands (LEGACY_INCOMPATIBLE there). */
const LEGACY_INCOMPATIBLE: ReadonlySet<string> = new Set([
  'enable_privacy_mode',
  'update_agent',
]);

/** Capability a non-admin requester needs on a device for this command
 *  (same mapping as POST /api/commands). */
function commandCapability(action: string): string {
  if (['reboot', 'shutdown', 'sleep', 'restart_agent', 'uninstall_agent'].includes(action)) return 'power';
  return 'execute';
}

/**
 * Dashboard "update all agents" (POST /api/devices/update-all-agents): only a
 * request of exactly that route's shape — no device list, the scope matching
 * the approval's tenant. Anything else carrying this action string (e.g. a
 * raw command filed as "update_all_agents on HOST-X") is refused rather than
 * turned into a fleet-wide rollout.
 *
 * Executed as the requester, who must still be a platform administrator.
 * The target set is re-resolved NOW and its scope is the APPROVAL's tenant
 * — never a field of the payload: a request filed in a sub-tenant updates
 * that tenant's agents only, one filed in the master tenant every tenant's
 * (same rule as the direct route).
 */
export async function executeUpdateAllAgents(x: ApprovalExecution): Promise<string | void> {
  const { tenantId, requesterId: userId } = x;
  const payload = x.payload as BatchCommandPayload;
  const p = payload.params ?? {};
  const expectedScope = isMasterTenant(tenantId) ? 'all_tenants' : 'tenant';
  if ('deviceIds' in (payload as object) || p.scope !== expectedScope || Object.keys(p).some((k) => k !== 'scope')) {
    refuse('Not a dashboard "update all agents" request (unexpected device list or scope) — nothing was executed');
  }
  await requirePlatformAdmin(userId);
  const { agentUpdateRollout } = await import('./agentUpdateRollout.service');
  const r = await agentUpdateRollout.updateAllOutdated(tenantId, userId);
  await auditAs(tenantId, userId, 'device.update_all_agents', {
    resourceType: 'device',
    details: {
      scope: r.allTenants ? 'all_tenants' : 'tenant', scopeTenantId: tenantId, targetVersion: r.latestVersion,
      targets: r.targets, queued: r.queued, alreadyQueued: r.alreadyQueued, online: r.online, offline: r.offline,
      ...(r.allTenants ? { tenants: r.byTenant.length } : {}),
    },
  });
  // Master scope: a summary row in each affected tenant's own log too.
  if (r.allTenants) {
    for (const { tenantId: t, ...counts } of r.byTenant) {
      if (t === tenantId) continue;
      await auditAs(t, userId, 'device.update_all_agents', {
        resourceType: 'device',
        details: { scope: 'all_tenants', initiatedFromTenantId: tenantId, targetVersion: r.latestVersion, ...counts },
      });
    }
  }
  if (r.targets === 0) return 'Nothing to do — every eligible agent already runs the current version';
}

/**
 * Device commands (POST /api/commands, /api/devices/batch, privacy mode,
 * airgap…): the approval executor of every 'batch_command' action no other
 * executor took. Enqueued as the requester on the devices still in the
 * tenant; a privacy-blocked command skips the devices now in privacy mode.
 */
export async function executeDeviceCommands(x: ApprovalExecution): Promise<string | void> {
  const payload = x.payload as BatchCommandPayload;
  const action = typeof payload.action === 'string' ? payload.action : '';
  if (!Array.isArray(payload.deviceIds)) {
    refuse(`Approval action '${action}' has no device list — nothing to execute`);
  }
  return deviceCommands(x.tenantId, x.requesterId, action, payload.deviceIds, payload.params ?? {});
}

async function deviceCommands(tenantId: number, userId: number, action: string, rawIds: unknown[], rawParams: Record<string, any>): Promise<string | void> {
  const requester = await activeRequester(userId);
  const ids = [...new Set(rawIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  let devices = ids.length
    ? await db('devices').where({ tenant_id: tenantId }).whereIn('id', ids).select('id', 'hostname', 'privacy_mode_enabled', 'privacy_password_set', 'agent_flavor', 'approval_status', 'status') as
      Array<{ id: number; hostname: string; privacy_mode_enabled: boolean; privacy_password_set: boolean | null; agent_flavor: string | null; approval_status: string; status: string }>
    : [];
  if (!devices.length) refuse('None of the devices of this request is still in the tenant');
  const errors: string[] = [];
  // The device-state gates of the direct routes, re-applied now (the state
  // may have changed while the request waited):
  //  - a privacy password set on the device: disable_privacy_mode is lifted
  //    on the device itself (the agent does not check the password on a raw
  //    disable);
  //  - the legacy (Go 1.20) agent lacks these handlers (POST /api/commands
  //    LEGACY_INCOMPATIBLE): the command would hang forever.
  devices = devices.filter((d) => {
    if (action === 'disable_privacy_mode' && d.privacy_password_set) {
      errors.push(`${d.hostname}: a privacy password is set on it — privacy mode can only be disabled on the device`);
      return false;
    }
    if (d.agent_flavor === 'legacy' && LEGACY_INCOMPATIBLE.has(action)) {
      errors.push(`${d.hostname}: '${action}' is not supported on the legacy agent`);
      return false;
    }
    // An agent update waits for its device: never for one that will not
    // get it (same rule as POST /api/commands and /api/devices/batch).
    if (action === 'update_agent' && (d.approval_status !== 'approved' || ['suspended', 'pending_uninstall'].includes(d.status))) {
      errors.push(`${d.hostname}: not approved, suspended or being uninstalled`);
      return false;
    }
    return true;
  });
  if (!devices.length) refuse(`Nothing was sent — ${errors.join('; ')}`);
  // Rights may have changed while the request waited: a requester that is
  // not a platform admin still needs, on each device, the capability the
  // route required (power / execute).
  if (!requester.isPlatformAdmin) {
    if (DEVICE_ADMIN_ONLY.has(action)) refuse(`Only a platform administrator can run '${action}'`);
    const { permissionService } = await import('./permission.service');
    if (action === 'enable_airgap' || action === 'disable_airgap') {
      if (!(await permissionService.userHasTenantCapability(userId, tenantId, 'devices.manage'))) {
        refuse('The requester no longer holds devices.manage in this tenant');
      }
    } else {
      const cap = commandCapability(action);
      const lacking = new Set(await permissionService.devicesLackingCapability(userId, devices.map((d) => d.id), cap));
      for (const d of devices) {
        if (lacking.has(d.id)) errors.push(`${d.hostname}: the requester no longer holds '${cap}' on it`);
      }
      devices = devices.filter((d) => !lacking.has(d.id));
    }
  }
  const params: Record<string, any> = { ...(rawParams ?? {}) };
  delete params.unlockToken; // a privacy unlock token of an old request: never sent on
  const targets = devices;
  const doneIds: number[] = [];
  if (action === 'update_agent') {
    // Queued without expiry, one per device (an update already waiting
    // counts as done), in bulk; version refreshed at delivery.
    const { agentUpdateRollout } = await import('./agentUpdateRollout.service');
    await agentUpdateRollout.enqueueBulk(targets.map((d) => ({ id: d.id, tenant_id: tenantId })), { createdBy: userId, priority: 'high' });
    doneIds.push(...targets.map((d) => d.id));
  }
  for (const d of action === 'update_agent' ? [] : targets) {
    if (d.privacy_mode_enabled && PRIVACY_BLOCKED_COMMANDS.has(action)) {
      errors.push(`${d.hostname}: privacy mode is active on it`);
      continue;
    }
    try {
      await commandService.enqueue({
        deviceId: d.id,
        tenantId,
        type: action as any,
        payload: params,
        priority: 'high',
        createdBy: userId,
      });
      doneIds.push(d.id);
    } catch (err) {
      logger.error({ err, deviceId: d.id }, 'batch approval execution: enqueue failed');
      errors.push(`${d.hostname}: ${err instanceof Error ? err.message.slice(0, 120) : 'enqueue failed'}`);
    }
  }
  if (!doneIds.length) refuse(`Nothing was sent — ${errors.join('; ') || 'no eligible device'}`);
  // Airgap: the device flag follows the command, as on the direct route.
  if (action === 'enable_airgap' || action === 'disable_airgap') {
    const on = action === 'enable_airgap';
    const at = on ? new Date() : null;
    await db('devices').where({ tenant_id: tenantId }).whereIn('id', doneIds)
      .update({ airgap_enabled: on, airgap_enabled_at: at, updated_at: new Date() });
    for (const id of doneIds) {
      try {
        getIO().to(`tenant:${tenantId}`).emit(SocketEvents.DEVICE_UPDATED, { id, airgapEnabled: on, airgapEnabledAt: at ? at.toISOString() : null });
      } catch {}
    }
  }
  for (const id of doneIds) {
    await auditAs(tenantId, userId, `command.${action}`, { deviceId: id, resourceType: 'command', details: { action } });
  }
  if (errors.length) return `Partially executed — ${errors.join('; ')}`;
}

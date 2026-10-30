import { db } from '../db';
import { forEachTenant } from '../db/tenantContext';
import { registerBootTask } from '../lifecycle';
import { registerLegacyAgentMinuteStep } from '../legacyAgent/jobs';
import { registerApprovalBeforeApproveCheck } from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { onSessionsKilled } from '../services/userSessions.service';
import { logger } from '../utils/logger';
import { registerMcpAuditActions, systemCtx } from '../mcp/audit';
import { forgetMcpUser } from '../mcp/auth';
import {
  assertFiledApprovalLive, cancelDeadKeyRows, cancelForKey, expireDue, interruptStale, retryCancelFailed,
} from '../mcp/authorizations/service';
import { expireBlocks, flushDeferred, loadBlocks, retryObliguard } from '../mcp/blocks';
import { invalidatePolicy, refreshPolicy } from '../mcp/ipPolicy';
import { revokeAllOfUser, revokeStaleKeys, setAuthorizationCancelHook } from '../mcp/keys/service';
import { registerAuthorizationTools } from '../mcp/tools/authorizations';
import { registerDeviceTools } from '../mcp/tools/devices';
import { registerReadTools } from '../mcp/tools/reads';
import { registerWhoamiTools } from '../mcp/tools/whoami';
import { registerWriteTools } from '../mcp/tools/writes';

// =============================================================================
// MCP SERVER (AI agents through personal access keys; docs: specs mcp-server):
// its hooks into the core's registries, registered here and only here;
// index.ts calls registerMcpModule() after the bridge agent's module (its
// minute job carries the MCP step, its console core serves the tools), before
// anything starts. No I/O but the boot task. /mcp is mounted by app.ts, the
// console routes by routes/index.ts.
// =============================================================================

/** The restrictable actions of the MCP server: a fresh second factor, never a trusted IP. */
export const MCP_RESTRICTABLE_ACTIONS = [
  { key: 'access_keys.create', label: 'Create a personal access key for AI agents', category: 'MCP server' },
  { key: 'mcp.authorization_approve', label: 'Approve an action asked by an AI agent', category: 'MCP server' },
  { key: 'mcp.settings_change', label: 'Change the MCP server settings (master tenant)', category: 'MCP server' },
  { key: 'mcp.ip_block', label: 'Block an address on the MCP server (master tenant)', category: 'MCP server' },
  { key: 'mcp.ip_unblock', label: 'Unblock an address on the MCP server (master tenant)', category: 'MCP server' },
] as const;

/** Sessions killed for these reasons revoke the user's keys (tenant and role losses are covered by the live re-check). */
const REVOKING_REASONS: Record<string, 'user_disabled' | 'sessions_killed'> = {
  user_disabled: 'user_disabled', user_deleted: 'user_disabled', sso_mfa_changed: 'sessions_killed',
};

let registered = false;
let minuteCount = 0;

export function registerMcpModule(): void {
  if (registered) return;
  registered = true;

  registerMcpAuditActions();
  const strict = { level: 'sensitive' as const, strictStepUp: true };
  registerRestrictableActions(MCP_RESTRICTABLE_ACTIONS, {}, {
    'access_keys.create': strict, 'mcp.authorization_approve': strict, 'mcp.settings_change': strict, 'mcp.ip_block': strict, 'mcp.ip_unblock': strict,
  });

  registerWhoamiTools();
  registerDeviceTools();
  registerReadTools();
  registerWriteTools();
  registerAuthorizationTools();

  // Revoking a key cancels its pending authorizations and its filed approvals (journaled with who caused it).
  setAuthorizationCancelHook((key, why, tenantId, cause) => cancelForKey(key, why, tenantId, cause).then(() => undefined));

  // An approval filed through a key: refused (409 authorizationClosed), and cancelled, unless its tracking row is still
  // 'filed', its key alive (not revoked nor expired, same credentials, owner active) and its tenant, scope need,
  // devices and target group still inside the key's perimeter; whatever the state of a cancellation in progress.
  registerApprovalBeforeApproveCheck((approval) => assertFiledApprovalLive(approval));

  onSessionsKilled({
    name: 'mcp', label: 'MCP access keys',
    forUser: async (userId, reason) => {
      forgetMcpUser(userId);
      const revoke = REVOKING_REASONS[reason];
      const n = revoke ? await revokeAllOfUser(userId, revoke) : 0;
      // Roles, memberships and activations feed the IP policy (open keys).
      invalidatePolicy();
      return n;
    },
  });

  // Every minute, in the job of the bridge agent: authorizations past their deadline, interrupted executions,
  // cancellations to retry; blocks past their end, blocks deferred by the per-minute cap, the IP policy (and its mode
  // change); every 5 minutes, the Obliguard reports still pending or failed.
  registerLegacyAgentMinuteStep('mcp', async (ctx) => {
    let expired = 0; let interrupted = 0; let retried = 0; let deadCancelled = 0;
    const actx = systemCtx({ requestId: 'job-mcp-minute' });
    // Keys whose owner changed his credentials, was disabled or removed: revoked now, not at their next use.
    let staleRevoked = 0;
    try { staleRevoked = await revokeStaleKeys(); } catch (err) { logger.warn({ err }, 'mcp minute step: stale keys not revoked'); }
    const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
      ctx.throwIfAborted();
      const any = await db('mcp_authorizations').where({ tenant_id: tenantId }).whereIn('state', ['pending', 'executing', 'filed']).first('id');
      if (!any) return;
      expired += await expireDue(tenantId, actx);
      interrupted += await interruptStale(tenantId, actx);
      retried += await retryCancelFailed(tenantId);
      deadCancelled += await cancelDeadKeyRows(tenantId);
    });
    const unblocked = await expireBlocks();
    const flushed = await flushDeferred();
    await refreshPolicy();
    let resent = 0;
    if (++minuteCount % 5 === 0) resent = await retryObliguard();
    if (failed > 0) logger.warn({ failed }, 'mcp minute step: tenants failed');
    return {
      mcpExpired: expired, mcpInterrupted: interrupted, mcpCancelRetried: retried, mcpStaleKeysRevoked: staleRevoked, mcpDeadKeyCancelled: deadCancelled,
      mcpUnblocked: unblocked, mcpBlocksFlushed: flushed, mcpObliguardResent: resent,
    };
  });

  // The blocks in memory and the IP policy, before the first request. A failure never stops the server: the gate
  // then never bans, it only counts, until the minute step succeeds.
  registerBootTask('mcp.blocks-and-policy', async () => {
    try {
      const n = await loadBlocks();
      const p = await refreshPolicy();
      logger.info({ blocks: n, mode: p.mode, activeKeys: p.activeKeys, openKeys: p.openKeys }, 'mcp: IP policy loaded');
    } catch (err) {
      logger.error({ message: (err as Error)?.message?.slice(0, 200) }, 'mcp: blocks and IP policy not loaded at start');
    }
  });
}

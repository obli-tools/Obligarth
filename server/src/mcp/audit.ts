import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit, registerAuditActions, type AuditWriteContext } from '../audit';
import { asIdentity, userActor } from '../db/context';
import { logger } from '../utils/logger';
import type { McpCaller } from './caller';
import { MCP_ACTOR } from './settings';

// =============================================================================
// The audit of the MCP server (docs: specs mcp-server §3.4). Every write is the
// human's (actor u:<id>) with auth 'mcp:key:<publicId>' and
// details.accessKey = { id, name }; text written by the agent is marked
// details.reasonSource = 'agent'. Reads are not journaled per call (last use
// of the key and the server log carry them), except the audit log itself.
// =============================================================================

let registered = false;

export function registerMcpAuditActions(): void {
  if (registered) return;
  registered = true;
  registerAuditActions([
    { name: 'mcp.key.created', criticality: 'critical', label: 'MCP access key created' },
    { name: 'mcp.key.revoked', criticality: 'protective', label: 'MCP access key revoked' },
    { name: 'mcp.key.tenant_excluded', criticality: 'protective', label: 'Tenant excluded from an MCP access key' },
    { name: 'mcp.key.new_network', criticality: 'standard', label: 'MCP access key used from a new network' },
    { name: 'mcp.auth.failed', criticality: 'protective', label: 'MCP authentication failed' },
    { name: 'mcp.tool.write', criticality: 'standard', label: 'MCP tool action' },
    { name: 'mcp.tool.denied', criticality: 'standard', label: 'MCP tool action refused' },
    { name: 'mcp.audit.read', criticality: 'standard', label: 'Audit log read through MCP' },
    { name: 'mcp.authorization.requested', criticality: 'standard', label: 'MCP authorization requested' },
    { name: 'mcp.authorization.filed', criticality: 'critical', label: 'MCP approval request filed' },
    { name: 'mcp.authorization.approved', criticality: 'critical', label: 'MCP authorization approved' },
    { name: 'mcp.authorization.denied', criticality: 'standard', label: 'MCP authorization denied' },
    { name: 'mcp.authorization.expired', criticality: 'standard', label: 'MCP authorization expired' },
    { name: 'mcp.authorization.cancelled', criticality: 'standard', label: 'MCP authorization cancelled' },
    { name: 'mcp.authorization.executed', criticality: 'critical', label: 'MCP authorization executed' },
    { name: 'mcp.authorization.failed', criticality: 'standard', label: 'MCP authorization failed' },
    { name: 'mcp.authorization.interrupted', criticality: 'standard', label: 'MCP authorization interrupted' },
    { name: 'mcp.ip.blocked', criticality: 'critical', label: 'Address blocked on the MCP server' },
    { name: 'mcp.ip.unblocked', criticality: 'critical', label: 'Address unblocked on the MCP server' },
    { name: 'mcp.ip.mode_changed', criticality: 'critical', label: 'IP mode of the MCP server changed' },
    { name: 'mcp.settings.changed', criticality: 'critical', label: 'MCP server settings changed' },
    { name: 'mcp.tenant_policy.changed', criticality: 'critical', label: 'MCP IP policy of a tenant changed' },
  ]);
}

/** details.accessKey of an entry. */
export const accessKeyDetail = (caller: Pick<McpCaller, 'key'>): { id: string; name: string } => ({ id: caller.key.publicId, name: caller.key.name });

/** The context of an entry written by a tool: the human, auth 'mcp:key:<publicId>', no home tenant (no session). */
export async function mcpAuditCtx(caller: McpCaller, chainTenantId: number, toolName: string): Promise<AuditWriteContext> {
  const ctx = await audit.fromDbActor(userActor(caller.userId), chainTenantId, {
    ip: caller.ip || undefined, requestId: caller.requestId, route: `MCP tools/call ${toolName}`.slice(0, 200),
  });
  ctx.actor.auth = `mcp:key:${caller.key.publicId}`;
  ctx.actor.homeTenant = undefined;
  return ctx;
}

/** The system's context of the MCP server (auth failures, blocks, mode changes). */
export function systemCtx(origin: { ip?: string; requestId?: string; route?: string } = {}): AuditWriteContext {
  return audit.system('integration', 'mcp', origin);
}

/** An entry that never breaks the caller: protective and standard entries are spooled by the writer on failure. */
export async function appendQuiet(entry: Parameters<typeof audit.append>[0], ctx: AuditWriteContext): Promise<void> {
  try {
    await asIdentity(MCP_ACTOR, () => audit.append(entry, ctx));
  } catch (err) {
    logger.warn({ err, action: entry.action }, 'mcp: audit entry not written');
  }
}

// ── mcp.auth.failed, aggregated (§3.4) ──────────────────────────────────────
// One entry per (ip, kind, minute), at most 60 entries per minute for the instance; beyond, one { dropped: n } entry
// at the next minute.

const FAILED_CAP_PER_MINUTE = 60;
let minute = 0;
let written = 0;
let dropped = 0;
let droppedMinute = 0;
const seen = new Map<string, number>();

export function auditAuthFailure(f: { kind: string; ip: string; publicId?: string; requestId?: string }): void {
  const m = Math.floor(Date.now() / 60_000);
  if (m !== minute) {
    if (dropped > 0) {
      const n = dropped;
      void appendQuiet({ tenantId: MASTER_TENANT_ID, action: 'mcp.auth.failed', outcome: 'denied', details: { dropped: n, minute: new Date(droppedMinute * 60_000).toISOString() } },
        systemCtx());
    }
    minute = m; written = 0; dropped = 0; seen.clear();
  }
  const key = `${f.ip}|${f.kind}`;
  const hits = (seen.get(key) ?? 0) + 1;
  seen.set(key, hits);
  if (hits > 1) return;
  if (written >= FAILED_CAP_PER_MINUTE) { dropped++; droppedMinute = m; return; }
  written++;
  void appendQuiet({
    tenantId: MASTER_TENANT_ID, action: 'mcp.auth.failed', outcome: 'denied',
    details: { kind: f.kind, ip: f.ip, ...(f.publicId ? { publicId: f.publicId } : {}) },
  }, systemCtx({ ip: f.ip || undefined, requestId: f.requestId, route: 'POST /mcp' }));
}

import { z } from 'zod';
import { db } from '../../db';
import { asNone, userActor } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { listOwn } from '../authorizations/service';
import { effectiveTenantsOf, type McpCaller } from '../caller';
import { READ, js, registerTool } from './index';

// The status of the authorizations a key asked (docs: specs mcp-server §5.1): the human's own rows (policy
// rls_self_read, any tenant), of this key only. Polled by the agent after an authorization_required answer. A row
// of a tenant out of the key's live perimeter shows its id and state only (no summary, no outcome).

const StatusArgs = z.object({ authorization_id: z.string().uuid() }).strict();
const ListArgs = z.object({ state: z.enum(['pending', 'filed', 'all']).optional(), limit: z.number().int().min(1).max(200).optional() }).strict();
const jsonOf = (v: unknown): any => { if (typeof v !== 'string') return v ?? null; try { return JSON.parse(v); } catch { return null; } };

export function registerAuthorizationTools(): void {
  registerTool({
    name: 'get_authorization_status', title: 'Get the status of an authorization', scope: null,
    description: 'The state of an authorization this key asked: pending (waiting for the human), executed (with the command ids), filed (another person must approve: approvalId), denied, expired, cancelled, failed or interrupted (with an error code).',
    inputSchema: js.obj({ authorization_id: js.str('The authorization id (uuid).', { format: 'uuid' }) }, ['authorization_id']),
    args: StatusArgs,
    annotations: { title: 'Get the status of an authorization', ...READ },
    run: async (caller, a) => {
      const r = await asNone(userActor(caller.userId), () => db('mcp_authorizations')
        .where({ id: a.authorization_id.toLowerCase(), user_id: caller.userId, key_id: caller.key.rowId })
        .first('id', 'tenant_id', 'tool', 'state', 'summary', 'expires_at', 'decided_at', 'outcome', 'error_code')) as Record<string, any> | undefined;
      if (!r) throw new AppError(404, 'Authorization not found', 'notFound');
      const expired = r.state === 'pending' && new Date(r.expires_at).getTime() <= Date.now();
      const state = expired ? 'expired' : r.state;
      // A tenant the key can no longer reach: its state only, never the summary (names) nor the outcome.
      if (!(await reachable(caller)).has(Number(r.tenant_id))) {
        return { authorizationId: String(r.id), tenantId: Number(r.tenant_id), state, outsidePerimeter: true };
      }
      return {
        authorizationId: String(r.id), tenantId: Number(r.tenant_id), tool: r.tool, state, summary: r.summary,
        expiresAt: new Date(r.expires_at).toISOString(), decidedAt: r.decided_at ? new Date(r.decided_at).toISOString() : null,
        outcome: jsonOf(r.outcome), errorCode: r.error_code ?? null,
      };
    },
  });

  registerTool({
    name: 'list_my_authorizations', title: 'List the authorizations of this key', scope: null,
    description: 'The authorizations this key asked, newest first (state: pending, filed or all).',
    inputSchema: js.obj({ state: js.enumOf(['pending', 'filed', 'all'], 'Which ones (default pending).'), limit: js.limit }),
    args: ListArgs,
    annotations: { title: 'List the authorizations of this key', ...READ },
    run: async (caller, a) => {
      const inside = await reachable(caller);
      return {
        items: (await listOwn(caller.userId, { state: a.state ?? 'pending', keyRowId: caller.key.rowId, limit: a.limit ?? 50 }))
          .map((v) => (inside.has(v.tenantId)
            ? { authorizationId: v.id, tenantId: v.tenantId, tool: v.tool, state: v.state, summary: v.summary, expiresAt: v.expiresAt, outcome: v.outcome, errorCode: v.errorCode }
            : { authorizationId: v.id, tenantId: v.tenantId, state: v.state, outsidePerimeter: true })),
      };
    },
  });
}

/** The tenants of the key's live perimeter (rows of other tenants show their state only). */
async function reachable(caller: McpCaller): Promise<Set<number>> {
  return new Set((await effectiveTenantsOf(caller)).tenants.map((t) => t.id));
}

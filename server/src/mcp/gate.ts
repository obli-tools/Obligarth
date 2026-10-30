import type { Request } from 'express';
import type { McpAuthorizationLevel } from '@obligarth/shared';
import { restrictionFloor, restrictionService } from '../services/restriction.service';
import type { ApprovalRequestType } from '../services/approval.service';
import type { McpCaller } from './caller';
import { createPending, fileApproval } from './authorizations/service';

// =============================================================================
// The seam of the restrictions matrix (docs: specs mcp-server §5.3), used by
// the extracted command cores (legacyAgent/console.ts):
//   mcpGate       a call of an agent: the level of the matrix (no step-up, never
//                 a trusted IP); 'sensitive' (or 'restricted' with a secret)
//                 writes an authorization the human approves with a second
//                 factor; 'restricted' files the console's approval request,
//                 tracked by a row 'filed'; nothing is ever run past a level.
//   approvedGate  the approval by the human, in his own request: the console's
//                 enforcement, the fresh factor of the approval standing for
//                 the 'sensitive' step (req.stepUpVerified); 'restricted' now
//                 files the approval as the UI would.
// The console routes keep calling applyRestriction directly (their behaviour is
// unchanged).
// =============================================================================

export interface GateInput {
  tenantId: number;
  actionKey: string;
  deviceIds: number[];
  approvalRequestType?: ApprovalRequestType;
  approvalDescription?: string;
  approvalPayload?: Record<string, unknown>;
  approvalSealed?: Record<string, unknown>;
  carriesSecret?: boolean;
}

export type GateOutcome =
  | { ok: true }
  | { ok: false; kind: 'approval'; approvalId: number; authorizationId?: string }
  | { ok: false; kind: 'authorization'; authorizationId: string; expiresAt: string }
  | { ok: false; kind: 'refused'; status: number; body: unknown };

export interface RestrictionGate {
  check(a: GateInput): Promise<GateOutcome>;
}

/** What the gate of an agent's call records for its human. */
export interface McpGateContext {
  caller: McpCaller;
  tool: string;
  /** The validated tool arguments (zod output): stored on the row, the agent's text included (shown apart). */
  args: Record<string, unknown>;
  /** Built by the server from the tool, the resolved names and the counts, never from the agent's text. */
  summary: string;
}

/** The gate of an agent's call (inside withTenant: tenant T's context, actor the human). */
export function mcpGate(g: McpGateContext): RestrictionGate {
  return {
    async check(a: GateInput): Promise<GateOutcome> {
      const level = await restrictionService.getLevelFor({ tenantId: a.tenantId, actionKey: a.actionKey, deviceIds: a.deviceIds });
      if (level === 'none') return { ok: true };
      if (level === 'sensitive' || (level === 'restricted' && a.carriesSecret === true)) {
        const row = await createPending(g.caller, {
          tenantId: a.tenantId, tool: g.tool, actionKey: a.actionKey, level: 'sensitive' as McpAuthorizationLevel, summary: g.summary,
          args: g.args, deviceIds: a.deviceIds,
        });
        return { ok: false, kind: 'authorization', authorizationId: String(row.id), expiresAt: new Date(row.expires_at).toISOString() };
      }
      // 'restricted': the approval the route files, with the same type, payload and sealed part.
      if (!a.approvalRequestType) {
        return { ok: false, kind: 'refused', status: 403, body: { error: 'This action is restricted but no approval path is configured.' } };
      }
      const filed = await fileApproval(g.caller, {
        tenantId: a.tenantId, tool: g.tool, actionKey: a.actionKey, level: 'restricted', summary: g.summary, args: g.args, deviceIds: a.deviceIds,
        requestType: a.approvalRequestType, description: a.approvalDescription ?? a.actionKey, payload: a.approvalPayload ?? {},
        ...(a.approvalSealed ? { sealed: a.approvalSealed } : {}),
      });
      return { ok: false, kind: 'approval', approvalId: filed.approvalId, authorizationId: String(filed.row.id) };
    },
  };
}

/**
 * The gate of the approval of an authorization, in the human's request (§6.4): restrictionService.enforce exactly as
 * applyRestriction does; req.stepUpVerified (set by the approve handler after its own fresh check) satisfies the
 * 'sensitive' step of the authorization's action key. A level raised to 'restricted' meanwhile files the approval,
 * its description prefixed with the key that asked.
 */
export function approvedGate(req: Request, prefix: string): RestrictionGate {
  return {
    async check(a: GateInput): Promise<GateOutcome> {
      const out = await restrictionService.enforce({
        req, actionKey: a.actionKey, deviceIds: a.deviceIds, approvalRequestType: a.approvalRequestType,
        approvalDescription: prefix + (a.approvalDescription ?? a.actionKey), approvalPayload: a.approvalPayload,
        approvalSealed: a.approvalSealed, carriesSecret: a.carriesSecret,
      });
      if (out.ok) return { ok: true };
      if ('approval' in out) return { ok: false, kind: 'approval', approvalId: Number((out.approval as { id: number }).id) };
      return { ok: false, kind: 'refused', status: out.status, body: out.body };
    },
  };
}

/** Is the action's step-up strict (never a trusted IP)? For the display of whoami. */
export const isStrict = (actionKey: string): boolean => restrictionFloor(actionKey)?.strictStepUp === true;

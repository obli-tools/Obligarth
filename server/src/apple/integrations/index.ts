import { z } from 'zod';
import { guardReviewerPolicy } from '../../guard/approvals';
import { AppError } from '../../middleware/errorHandler';
import { refuse, registerApprovalRequestType, requireTenantCapability, withAuditAs, type ApprovalExecution } from '../../services/approval.service';
import { registerRestrictableActions } from '../../services/restriction.service';
import { userActor } from '../../db/context';
import { deleteAdeServer } from './ade';
import { executeTopicChange } from './push';
import { registerIntegrationJobs } from './schedule';

// =============================================================================
// The Apple integrations of the console (docs: integration-apple-edge §11,
// lot C3): what registerAppleModule registers of them, before anything starts.
//   jobs        integrations.deadlines-all / -tenant, tls-check, ade-reconcile,
//               push-abandon (schedule.ts)
//   approvals   'apple_integration': a change of push topic and the deletion
//               of an ADE server, never without a second approver (their floors
//               'restricted' are registered with the command queue), examined
//               like the guarded actions (client approver, strict step-up),
//               executed as the requester, whose capability is read again
//   matrix      apple.integrations: recommended level 'sensitive' for the new
//               tenants (no floor, §8.11)
// =============================================================================

export { createAppleIntegrationsRouter, createAppleAdminIntegrationsRouter } from './routes';

const Payload = z.discriminatedUnion('op', [
  z.object({ action: z.literal('apple_integration'), op: z.literal('push_topic_change'), requestId: z.string().uuid() }).passthrough(),
  z.object({ action: z.literal('apple_integration'), op: z.literal('ade_token_delete'), serverId: z.string().uuid() }).passthrough(),
]);

/** A returned string is a partial outcome (execution_error): a success returns nothing. */
async function executeIntegration(x: ApprovalExecution): Promise<string | void> {
  const parsed = Payload.safeParse(x.payload ?? {});
  if (!parsed.success) refuse('Malformed integration request');
  const p = parsed.data;
  await requireTenantCapability(x.requesterId, x.tenantId, 'mdm.integrations.manage');
  const actor = userActor(x.requesterId);
  try {
    if (p.op === 'push_topic_change') {
      await withAuditAs(x.tenantId, x.requesterId, 'integration.push_certificate_imported',
        { resourceType: 'push_request', resourcePath: p.requestId, details: { purpose: 'topic_change', approvalId: x.approvalId ?? null } },
        () => executeTopicChange(x.tenantId, p.requestId.toLowerCase(), actor), (o) => ({ topic: o.topic, previousTopic: o.previousTopic, notAfter: o.notAfter }));
      return undefined;
    }
    await withAuditAs(x.tenantId, x.requesterId, 'integration.ade_token_deleted',
      { resourceType: 'ade_token', resourcePath: p.serverId, details: { approvalId: x.approvalId ?? null } },
      () => deleteAdeServer(x.tenantId, p.serverId.toLowerCase(), actor));
    return undefined;
  } catch (err) {
    if (err instanceof AppError && err.statusCode < 500) refuse(`${err.code ?? 'refused'}: ${err.message}`);
    throw err;
  }
}

let registered = false;

export function registerAppleIntegrations(): void {
  if (registered) return;
  registered = true;
  registerIntegrationJobs();
  registerApprovalRequestType('apple_integration', executeIntegration, { expiryMinutes: 240, reviewerPolicy: guardReviewerPolicy, reviewerStepUp: 'strict' });
  // The recommended level of apple.integrations (its key is listed with the command queue's actions).
  registerRestrictableActions([], { 'apple.integrations': 'sensitive' });
}

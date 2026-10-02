// Registration of the hardened journal in the core's registries (index.ts,
// with the other modules, no I/O): durable jobs, restrictable actions and
// their floors, approval executors, the SIEM exporter (start and stop
// tasks), the sealed column of the destinations and the seal key's name.
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { z } from 'zod';
import { config } from '../config';
import { userActor } from '../db/context';
import { jobs } from '../jobs';
import { registerStartTask, registerStopTask } from '../lifecycle';
import {
  platformAdminPolicy, refuse, registerApprovalExecutor, registerApprovalReviewerPolicy, requirePlatformAdmin, type ApprovalReviewCheck,
} from '../services/approval.service';
import { registerRestrictableActions } from '../services/restriction.service';
import { logger } from '../utils/logger';
import { fromDbActor } from './actor';
import { deleteDestination, registerDestinationSecretColumn, updateDestination, UpdateDestinationInput } from './export/destinations';
import { auditExporter } from './export/exporter';
import { registerAuditJobs } from './jobs';
import { applyLegalHold, applyRetentionChange } from './retention';
import { registerSealKeySecretName, rotateSealKey } from './sealKeys';

/** The restrictable actions of the journal (audit-durci §7.2, §8.1, §8.6,
 *  §6.8), with their floors: not lowerable by any matrix. */
export const AUDIT_RESTRICTABLE_ACTIONS = [
  { key: 'audit.export', label: 'Export the audit log (verifiable file or CSV)', category: 'Audit log' },
  { key: 'audit.admin', label: 'Set a legal hold, seal the audit log now', category: 'Audit log' },
  { key: 'audit.destination_change', label: 'Create, change or test a SIEM destination', category: 'Audit log' },
  { key: 'audit.destination_stop', label: 'Disable, delete or make optional a SIEM destination', category: 'Audit log' },
  { key: 'audit.retention_change', label: 'Change the retention of an audit log', category: 'Audit log' },
  { key: 'audit.legal_hold_release', label: 'Lift or shorten a legal hold', category: 'Audit log' },
  { key: 'audit.seal_key_rotate', label: 'Rotate the key that signs the audit seals', category: 'Audit log' },
] as const;

const RetentionPayload = z.object({
  action: z.literal('audit_retention_change'),
  tenantId: z.number().int().positive(),
  months: z.number().int().min(6).max(36),
  justification: z.string().max(1000).nullable(),
});
const HoldReleasePayload = z.object({
  action: z.literal('audit_legal_hold_release'),
  tenantId: z.number().int().positive(),
  until: z.string().max(40).nullable(),
  reason: z.string().max(500).nullable(),
});
const DestinationPayload = z.object({
  action: z.literal('audit_destination_change'),
  op: z.enum(['update', 'delete']),
  id: z.number().int().positive(),
  patch: UpdateDestinationInput.optional(),
});
const SealKeyPayload = z.object({ action: z.literal('audit_seal_key_rotate') });

let registered = false;

/** Who examines a retention change or the release of a legal hold: in the
 *  master tenant, another platform administrator; in a client's tenant, its
 *  designated client approver under the guard's policy, strict step-up of
 *  the reviewer included (§7.2, §10.4 point 5). */
async function journalReviewerPolicy(x: ApprovalReviewCheck): Promise<void | { reviewerStepUp: 'strict' }> {
  if (x.approval.tenantId === MASTER_TENANT_ID) {
    await platformAdminPolicy(x);
    // A client's chain examined in the master tenant (no client approver when
    // the request was filed): approved there only while that still holds
    // (integration of lot A, AUD-A7-R4): a client approver designated since
    // reviews it in the client's tenant (the request is filed again), and a
    // client approver lost since holds the fallback. A refusal stays open.
    const chain = Number((x.approval.payload as { tenantId?: unknown } | null)?.tenantId);
    if (x.decision === 'approve' && Number.isSafeInteger(chain) && chain > 0 && chain !== MASTER_TENANT_ID) {
      const { activeClientApprovers, fallbackHold } = await import('../guard/people');
      const { asTenant } = await import('../db/context');
      const now = await asTenant(chain, userActor(x.reviewerId), async () => {
        const clients = await activeClientApprovers(chain);
        return { clients, hold: clients === 0 ? await fallbackHold(chain) : null };
      });
      if (now.clients > 0) {
        throw Object.assign(new Error('The client has a client approver now: file the request again, it will be reviewed in the client\'s tenant'), {
          status: 409, code: 'approverSideRequired',
        });
      }
      if (now.hold) {
        throw Object.assign(new Error(`The client lost its client approver recently: the fallback stays closed until ${now.hold.until.toISOString()}`), {
          status: 409, code: 'approverFallbackHeld', details: { until: now.hold.until.toISOString() },
        });
      }
    }
    return;
  }
  const { guardReviewerPolicy } = await import('../guard/approvals');
  await guardReviewerPolicy({ ...x, approval: { ...x.approval, payload: { ...(x.approval.payload ?? {}), requiredSide: 'client' } } });
  return { reviewerStepUp: 'strict' };
}

export function registerAuditModule(): void {
  if (registered) return;
  registered = true;
  registerSealKeySecretName();
  registerDestinationSecretColumn();
  registerAuditJobs();
  registerRestrictableActions(AUDIT_RESTRICTABLE_ACTIONS, {}, {
    'audit.export': { level: 'sensitive', strictStepUp: true },
    'audit.admin': { level: 'sensitive' },
    'audit.destination_change': { level: 'sensitive' },
    'audit.destination_stop': { level: 'restricted' },
    'audit.retention_change': { level: 'restricted' },
    'audit.legal_hold_release': { level: 'restricted' },
    'audit.seal_key_rotate': { level: 'restricted' },
  });

  // Approved requests (executed as the requester, who must still be an
  // active platform administrator), filed from the master tenant; the
  // retention and the release of a legal hold of a client's chain, in that
  // client's tenant when it has a designated client approver (§7.2, lot A7).
  const masterAdmin = async (tenantId: number, requesterId: number, chainTenantId?: number): Promise<void> => {
    await requirePlatformAdmin(requesterId);
    if (tenantId !== MASTER_TENANT_ID && tenantId !== chainTenantId) refuse('The audit log is administered from the master tenant only');
  };
  registerApprovalExecutor('audit_retention_change', async ({ tenantId, requesterId, payload }) => {
    const p = RetentionPayload.safeParse(payload);
    if (!p.success) refuse('Invalid retention request');
    await masterAdmin(tenantId, requesterId, p.data.tenantId);
    await applyRetentionChange({ tenantId: p.data.tenantId, months: p.data.months, justification: p.data.justification }, requesterId);
  });
  registerApprovalExecutor('audit_legal_hold_release', async ({ tenantId, requesterId, payload }) => {
    const p = HoldReleasePayload.safeParse(payload);
    if (!p.success) refuse('Invalid legal hold request');
    await masterAdmin(tenantId, requesterId, p.data.tenantId);
    const until = p.data.until ? new Date(p.data.until) : null;
    if (until && Number.isNaN(until.getTime())) refuse('Invalid legal hold date');
    await applyLegalHold(p.data.tenantId, until, p.data.reason, requesterId);
  });
  // Examination (§7.2, §10.4): a request filed in the master tenant, by
  // another platform administrator; one filed in a client's tenant, by a
  // designated client approver of that tenant (the guard's policy, client side).
  registerApprovalReviewerPolicy((a) => a === 'audit_retention_change' || a === 'audit_legal_hold_release', journalReviewerPolicy);
  registerApprovalExecutor('audit_destination_change', async ({ tenantId, requesterId, payload }) => {
    await masterAdmin(tenantId, requesterId);
    const p = DestinationPayload.safeParse(payload);
    if (!p.success) refuse('Invalid SIEM destination request');
    const ctx = await fromDbActor(userActor(requesterId), MASTER_TENANT_ID);
    if (p.data.op === 'delete') await deleteDestination(p.data.id, ctx);
    else await updateDestination(p.data.id, p.data.patch ?? {}, ctx);
  });
  registerApprovalExecutor('audit_seal_key_rotate', async ({ tenantId, requesterId, payload }) => {
    await masterAdmin(tenantId, requesterId);
    if (!SealKeyPayload.safeParse(payload).success) refuse('Invalid seal key request');
    await rotateSealKey('manual', await fromDbActor(userActor(requesterId), MASTER_TENANT_ID));
  });

  // The SIEM exporter: one loop per instance (advisory lock), only where the
  // workers run (JOBS_MODE=all), unless AUDIT_EXPORT=off.
  registerStartTask('audit.exporter', () => {
    if (jobs.mode() !== 'all') return;
    if (config.audit.export === 'off') {
      logger.warn({ code: 'AUDIT_EXPORT_OFF' }, 'audit: SIEM export disabled (AUDIT_EXPORT=off)');
      // A laboratory setting: in production, the journal leaves the database
      // no more (an alert of the master tenant).
      if (config.nodeEnv === 'production') {
        void import('../jobs/alerts').then(({ raiseJobAlert }) => raiseJobAlert({ type: 'job', name: 'audit.export' }, {
          stableKey: 'audit:export-off', severity: 'warning', title: 'SIEM export disabled',
          message: 'AUDIT_EXPORT=off: the audit journal is copied to no SIEM destination (laboratory setting).',
        })).catch((err) => logger.warn({ err: { name: (err as Error).name } }, 'audit: export-off alert not raised'));
      }
      return;
    }
    void auditExporter.start();
  });
  registerStopTask('audit.exporter', () => auditExporter.stop());
}

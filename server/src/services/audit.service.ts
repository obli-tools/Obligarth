import type { Request } from 'express';
import { isMasterTenant, type AuditEntryDto } from '@obligarth/shared';
import { currentDbContext, type DbActor } from '../db/context';
import { audit, isAuditUnavailable, type AuditEntryInput } from '../audit';
import { entriesOfDevice, listEntries, registerAuditResourceName, type AuditNameTenant, type ListParams } from '../audit/read';
import { logger } from '../utils/logger';

// =============================================================================
// Compatibility facade of the hardened journal (docs: audit-durci §5.7)
// =============================================================================
//
// The calls written before the hardened journal (log, logReq, logReqAs) keep
// working: they become audit.append with the class of the catalogue, after
// the fact (P3), and never throw. A critical action written through here is a
// conversion defect: counted (obligarth_audit_post_hoc_critical_total) and
// logged as an error. The convention of the durable jobs (details.actor
// 'job:<queue>', details.jobId) is converted into the actor and the request
// id of the entry. Reads go to audit/read.ts (names resolved in the entry's
// tenant: E14).

export { registerAuditResourceName };
export type { AuditNameTenant };

export interface AuditLogEntry {
  tenantId: number;
  userId?: number;
  deviceId?: number;
  action: string;
  resourceType?: string;
  resourcePath?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
}

/** The legacy row of the existing screens (kept: GET /api/audit-log answers
 *  the new DTO, whose fields include these). */
export type AuditLogRow = AuditEntryDto;

const JOB_ACTOR_RE = /^job:([a-z][a-z0-9-]*(\.[a-z0-9-]+){1,3})$/;
const JOB_ID_RE = /^[0-9a-f-]{8,64}$/i;

/** The entry of a legacy call, and the actor it names. */
function convert(entry: AuditLogEntry): { input: AuditEntryInput; actor: DbActor; requestId?: string } {
  const details = entry.details ? { ...entry.details } : undefined;
  let actor: DbActor | null = null;
  let requestId: string | undefined;
  if (details) {
    const a = typeof details.actor === 'string' ? JOB_ACTOR_RE.exec(details.actor) : null;
    if (a) { actor = { type: 'job', name: a[1] }; delete details.actor; }
    if (typeof details.jobId === 'string' && JOB_ID_RE.test(details.jobId)) { requestId = `job-${details.jobId}`; delete details.jobId; }
  }
  const userId = Number(entry.userId);
  if (Number.isSafeInteger(userId) && userId > 0) actor = { type: 'user', userId };
  if (!actor) actor = currentDbContext()?.actor ?? { type: 'anonymous', name: 'unscoped' };
  const device = entry.deviceId !== undefined && entry.deviceId !== null ? Number(entry.deviceId) : undefined;
  const type = String(entry.resourceType || 'device').toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^[^a-z]+/, '') || 'resource';
  const target = entry.resourceType || device !== undefined
    ? {
      type,
      id: entry.resourcePath ?? (device !== undefined ? String(device) : ''),
      ...(device !== undefined && Number.isSafeInteger(device) && device > 0 ? { device } : {}),
    }
    : undefined;
  return {
    input: { tenantId: entry.tenantId, action: entry.action, target, details: details && Object.keys(details).length ? details : undefined },
    actor,
    requestId,
  };
}

async function write(input: AuditEntryInput, ctx: Parameters<typeof audit.append>[1]): Promise<void> {
  try {
    await audit.append(input, ctx, { postHoc: true });
  } catch (err) {
    // A critical entry written after the fact that fails: the action is
    // already done, the facade never throws (the writer logged it).
    if (!isAuditUnavailable(err)) logger.warn({ err: { name: (err as Error).name }, action: input.action }, 'audit entry not written');
  }
}

export const auditService = {
  /** Writes an entry after the fact. Never throws. */
  async log(entry: AuditLogEntry): Promise<void> {
    try {
      const { input, actor, requestId } = convert(entry);
      const ctx = await audit.fromDbActor(actor, entry.tenantId, { ip: entry.ipAddress, requestId });
      await write(input, ctx);
    } catch (err) {
      logger.warn({ err: { name: (err as Error).name }, action: entry.action, tenantId: entry.tenantId }, 'audit entry not written');
    }
  },

  /** Route handlers: the request's tenant, its user, origin and session. */
  async logReq(
    req: Request,
    action: string,
    extras: Partial<Omit<AuditLogEntry, 'action' | 'tenantId' | 'userId' | 'ipAddress'>> = {},
  ): Promise<void> {
    const tenantId = (req as { tenantId?: number }).tenantId;
    if (!tenantId) return;
    try {
      const { input } = convert({ tenantId, action, ...extras });
      await write(input, await audit.fromRequest(req, tenantId));
    } catch (err) {
      logger.warn({ err: { name: (err as Error).name }, action, tenantId }, 'audit entry not written');
    }
  },

  /** As logReq, filed in `tenantId` (an MSP action on a client's object, from
   *  the global view): written from asTargetTenant (one target per request). */
  async logReqAs(
    req: Request,
    tenantId: number,
    action: string,
    extras: Partial<Omit<AuditLogEntry, 'action' | 'tenantId' | 'userId' | 'ipAddress'>> = {},
  ): Promise<void> {
    try {
      const { asTargetTenant } = await import('../middleware/dbContext');
      await asTargetTenant(req, tenantId, async () => {
        const { input } = convert({ tenantId, action, ...extras });
        await write(input, await audit.fromRequest(req, tenantId));
      });
    } catch (err) {
      logger.warn({ err: { name: (err as Error).name }, action, tenantId }, 'audit entry not written');
    }
  },

  async getByDevice(deviceId: number, tenantId: number, limit = 50): Promise<AuditEntryDto[]> {
    return entriesOfDevice(deviceId, tenantId, limit);
  },

  /** Tenant-wide list; in the global view (context 'platform', the master
   *  tenant's platform administrators) every chain, or filterTenantId's. */
  async list(params: Omit<ListParams, 'tenantId'> & { tenantId: number; globalView?: boolean; filterTenantId?: number }): Promise<{ items: AuditEntryDto[]; total: number }> {
    // The master tenant's list is the global feed, as before the hardened
    // journal: in the context 'platform' every chain, in any other context
    // what the row level security shows (a single barrier, rls-tenant §11.6).
    const global = params.globalView ?? isMasterTenant(params.tenantId);
    const scope = global ? (params.filterTenantId ?? null) : params.tenantId;
    const { items, total } = await listEntries({ ...params, tenantId: scope });
    return { items, total };
  },
};

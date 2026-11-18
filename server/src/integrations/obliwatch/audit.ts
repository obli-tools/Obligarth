import type { Request } from 'express';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { audit, registerAuditActions, type AuditEntryInput, type AuditWriteContext } from '../../audit';
import { asTenant } from '../../db/context';
import { clientIp } from '../../utils/clientIp';
import { logger } from '../../utils/logger';
import { OBLIWATCH_ACTOR } from './config';

// =============================================================================
// The audit of the Obliwatch integration. Reads are journaled per call (obliwatch.read, standard: spooled by the
// writer when the journal is down, never a refusal), ping sampled to one entry per hour and per tenant; never a
// device identifier in the details of a list. Refused tokens are aggregated (obliwatch.auth.rejected, at most one
// entry per (reason, minute) and 60 per minute for the instance). The consent change is critical, written in the
// transaction of the change (consent.ts).
// =============================================================================

let registered = false;

export function registerObliwatchAuditActions(): void {
  if (registered) return;
  registered = true;
  registerAuditActions([
    { name: 'obliwatch.consent.changed', criticality: 'critical', label: 'Obliwatch consent of the tenant changed' },
    { name: 'obliwatch.read', criticality: 'standard', label: 'Data read by Obliwatch' },
    { name: 'obliwatch.auth.rejected', criticality: 'protective', label: 'Obliwatch request refused' },
  ]);
}

/** The system context of an entry written for a request of Obliwatch (actor i:obliwatch). */
export function obliwatchCtx(req: Request): AuditWriteContext {
  return audit.system('integration', 'obliwatch', {
    ip: clientIp(req) || undefined,
    requestId: req.requestId,
    route: `${req.method} ${req.baseUrl}${req.path}`.slice(0, 200),
  });
}

async function appendQuiet(entry: AuditEntryInput, ctx: AuditWriteContext): Promise<void> {
  try {
    await asTenant(entry.tenantId, OBLIWATCH_ACTOR, () => audit.append(entry, ctx));
  } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) }, action: entry.action }, 'obliwatch: audit entry not written');
  }
}

// ── obliwatch.read ──────────────────────────────────────────────────────────────

const PING_SAMPLE_MS = 60 * 60_000;
const lastPing = new Map<number, number>();

/**
 * One read of `endpoint` in `tenantId` (count: the items answered). Ping is sampled (one entry per hour and per
 * tenant). Fire and forget: a read is never refused for its audit.
 */
export function auditRead(req: Request, tenantId: number, endpoint: string, details: Record<string, unknown> = {}): void {
  if (endpoint === 'ping') {
    const now = Date.now();
    if ((lastPing.get(tenantId) ?? 0) > now - PING_SAMPLE_MS) return;
    if (lastPing.size > 10_000) lastPing.clear();
    lastPing.set(tenantId, now);
  }
  void appendQuiet({
    tenantId, action: 'obliwatch.read', outcome: 'success',
    details: { endpoint, ...details, azp: req.obliwatch?.azp ?? null, jti: req.obliwatch?.jti ?? null },
  }, obliwatchCtx(req));
}

// ── obliwatch.auth.rejected, aggregated ─────────────────────────────────────────

const REJECTED_CAP_PER_MINUTE = 60;
let minute = 0;
let written = 0;
let dropped = 0;
const seen = new Set<string>();

/**
 * A refused request: one entry per (reason, tenant, minute), in the tenant's chain when the signed `ost` resolved,
 * else the master tenant's. Only verified claims reach the details (the verifier gives none before the signature).
 */
export function auditRejected(req: Request, f: { reason: string; tenantId?: number | null; jti?: string | null; azp?: string | null; sub?: string | null }): void {
  const m = Math.floor(Date.now() / 60_000);
  if (m !== minute) {
    if (dropped > 0) {
      void appendQuiet({ tenantId: MASTER_TENANT_ID, action: 'obliwatch.auth.rejected', outcome: 'denied', details: { dropped } }, obliwatchCtx(req));
    }
    minute = m; written = 0; dropped = 0; seen.clear();
  }
  const tenantId = f.tenantId ?? MASTER_TENANT_ID;
  const key = `${f.reason}|${tenantId}`;
  if (seen.has(key)) return;
  seen.add(key);
  if (written >= REJECTED_CAP_PER_MINUTE) { dropped++; return; }
  written++;
  void appendQuiet({
    tenantId, action: 'obliwatch.auth.rejected', outcome: 'denied',
    details: { reason: f.reason, jti: f.jti ?? null, azp: f.azp ?? null, sub: f.sub ?? null },
  }, obliwatchCtx(req));
}

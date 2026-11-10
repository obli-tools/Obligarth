import type { Knex } from 'knex';
import { db } from '../db';
import { forEachTenant } from '../db/tenantContext';
import type { JobContext, JobResult } from '../jobs';
import { AppError } from '../middleware/errorHandler';

// =============================================================================
// The batches of site writes held for a human (site_batches, lot P1-SITE): the request of an MCP batch until its human
// approves it (one authorization per batch), and the CSV text of a console import held for a second person (it does
// not fit in the sealed part of an approval, 1 MiB). Kept a day at most: the hourly purge (sites.batches-purge) drops
// the expired and the consumed ones of every tenant, the values of the sites they carry with them.
// =============================================================================

/** A batch lives a day; the approval of a console import, 4 hours. */
export const BATCH_TTL_MS = 24 * 3_600_000;
/** The bound of the table (site_batches_request_check, octet_length of the jsonb's text), less a margin for the spaces
 *  jsonb's text form adds. */
const REQUEST_MAX_BYTES = 3 * 1024 * 1024 - 4096;

/** Keeps a batch, in the caller's transaction (tenant context): its request too large for the table answers 413. */
export async function insertBatch(trx: Knex.Transaction, b: { tenantId: number; userId: number; tool: string; request: Record<string, unknown>; digest: string }): Promise<string> {
  const request = JSON.stringify(b.request);
  // A CSV full of quotes or line breaks doubles in JSON: the bound is checked here rather than by the CHECK (a 500).
  if (Buffer.byteLength(request, 'utf8') > REQUEST_MAX_BYTES) {
    throw new AppError(413, 'This file is too large once encoded: split it in several imports', 'importTooLargeBytes');
  }
  const [r] = await trx('site_batches').insert({
    tenant_id: b.tenantId, user_id: b.userId, tool: b.tool, request, digest: b.digest, expires_at: new Date(Date.now() + BATCH_TTL_MS),
  }).returning('id') as Array<{ id: string }>;
  return String(r.id);
}

/** A batch of a human still usable (his, of the tenant, of this tool, not consumed nor expired, of this digest). */
export async function usableBatch(q: Knex | Knex.Transaction, tenantId: number, id: string, userId: number, tools: string[], digest: string):
  Promise<Record<string, any> | null> {
  const b = await q('site_batches').where({ tenant_id: tenantId, id, user_id: userId }).whereIn('tool', tools).first() as Record<string, any> | undefined;
  if (!b || b.consumed_at || new Date(b.expires_at).getTime() <= Date.now() || String(b.digest) !== digest) return null;
  return b;
}

/** Consumes a batch in the transaction of its write (exactly once: 409 batchGone otherwise). */
export async function consumeBatch(trx: Knex.Transaction, tenantId: number, id: string): Promise<void> {
  const used = await trx('site_batches').where({ tenant_id: tenantId, id }).whereNull('consumed_at').update({ consumed_at: new Date() });
  if (!used) throw new AppError(409, 'This batch was applied already', 'batchGone');
}

/** The batches of a tenant done with: expired, or consumed (in the tenant's context). */
export async function purgeTenantBatches(q: Knex | Knex.Transaction, tenantId: number, now = new Date()): Promise<number> {
  return q('site_batches').where({ tenant_id: tenantId })
    .where(function done() { this.where('expires_at', '<', now).orWhereNotNull('consumed_at'); }).delete();
}

/** sites.batches-purge (hourly, every tenant). */
export async function purgeBatchesJob(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  let purged = 0;
  const { ok, failed } = await forEachTenant(ctx.dbActor, async (tenantId) => { purged += await purgeTenantBatches(db, tenantId); });
  if (failed > 0) throw new Error(`sites.batches-purge: ${failed} tenant(s) failed, ${ok} done`);
  return { output: { purged, tenants: ok } };
}

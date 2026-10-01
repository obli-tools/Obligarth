import { db } from '../db';

// =============================================================================
// Tenant of a tenant job. The payload is not an authorisation: the envelope
// checks that the tenant still exists before the handler runs, and the
// handler reloads each resource by (id, tenant_id), in the job's tenant
// context (ctx.withTenant: a transaction in the tenant, rls-tenant §7.6).
// =============================================================================

/** Does the tenant still exist? Read in the run's context ('none', actor
 *  j:<queue>): the tenants registry is readable there. The tenants lifecycle
 *  (soft deletion) will also exclude the tenants being retired. */
export async function tenantIsLive(tenantId: number): Promise<boolean> {
  if (!Number.isSafeInteger(tenantId) || tenantId <= 0) return false;
  const row = await db('tenants').where({ id: tenantId }).first('id');
  return !!row;
}

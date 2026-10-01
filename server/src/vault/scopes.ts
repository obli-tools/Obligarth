// Database contexts of the rows of a sealed column, for the vault's own walks
// over the registry (backfill, DEK rotation, verification, recovery after a
// KEK loss; review COF-RC3). The rows sealed under:
//   - a tenant's DEK live in that tenant's rows: context 'tenant' of it;
//   - the instance DEK live in the rows without tenant: the identity tables
//     (users) in the context 'identity', the vault's technical tables in
//     'none', and the platform rows of a table of class tenant_or_global
//     (smtp_servers, tenant_id NULL) in 'identity', where they are writable.
// A table without tenant column holds no row sealed under a tenant's DEK.
import type { Knex } from 'knex';
import { asIdentity, asNone, asTenant, type DbActor } from '../db/context';
import { allTenantIds } from '../db/tenantContext';
import type { SecretColumnDef } from './registry';

export interface RowScope {
  /** null: the rows sealed under the instance DEK. */
  tenantId: number | null;
  /** Runs fn in the scope's database context. */
  run<T>(fn: () => Promise<T>): Promise<T>;
  /** Restricts a query on the column's table to the scope's rows. */
  filter(qb: Knex.QueryBuilder): Knex.QueryBuilder;
}

/** The scope of the rows of `def` sealed under the DEK of `tenantId` (null:
 *  the instance DEK), or null when the table holds none. */
export function scopeFor(def: SecretColumnDef, tenantId: number | null, actor: DbActor): RowScope | null {
  if (tenantId !== null) {
    if (!def.tenantColumn) return null;
    const col = def.tenantColumn;
    return {
      tenantId,
      run: (fn) => asTenant(tenantId, actor, fn),
      filter: (qb) => qb.where(col, tenantId),
    };
  }
  if (!def.tenantColumn) {
    const ctx = def.instanceContext === 'identity' ? asIdentity : asNone;
    return { tenantId: null, run: (fn) => ctx(actor, fn), filter: (qb) => qb };
  }
  if (def.tenantNullable) {
    const col = def.tenantColumn;
    return { tenantId: null, run: (fn) => asIdentity(actor, fn), filter: (qb) => qb.whereNull(col) };
  }
  return null;
}

/** Every scope of a column: the instance's (when the table has such rows),
 *  then each tenant's, in id order (or only `onlyTenant`'s). */
export async function scopesOf(def: SecretColumnDef, actor: DbActor, onlyTenant?: number | null): Promise<RowScope[]> {
  const out: RowScope[] = [];
  if (onlyTenant === undefined || onlyTenant === null) {
    const inst = scopeFor(def, null, actor);
    if (inst) out.push(inst);
    if (onlyTenant === null) return out;
  }
  if (!def.tenantColumn) return out;
  const ids = onlyTenant !== undefined && onlyTenant !== null ? [onlyTenant] : await asNone(actor, () => allTenantIds());
  for (const id of ids) {
    const s = scopeFor(def, id, actor);
    if (s) out.push(s);
  }
  return out;
}

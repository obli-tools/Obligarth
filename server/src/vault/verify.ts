// Verification of the vault (docs: coffre-secrets §11.2, §11.4): every DEK
// that is not destroyed unwraps with the loaded KEK; then, for each registered
// column (transient ones excepted), one sealed value per DEK opens — or, with
// `full`, every sealed value of the registry. Failures are counted per column,
// never a value. Used by the daily job vault.verify-daily and by the CLI
// (`vault verify [--tenant <id>] [--full]`).
//
// Also the garbage collection of tenant_secrets (vault.tenant-secrets-gc,
// coffre-secrets §6.4).
import type { Knex } from 'knex';
import { db } from '../db';
import { asNone, type DbActor } from '../db/context';
import { forEachTenant } from '../db/tenantContext';
import { logger } from '../utils/logger';
import { isVaultError } from './errors';
import { secretColumns, secretReferenceHolders } from './registry';
import { scopesOf } from './scopes';
import { vault, vaultInternals, type SecretLocator } from './vault';

export interface VerifyReport {
  deks: { checked: number; failed: number };
  /** `destroyed`: values sealed under a destroyed DEK (a tenant being
   *  deleted, past its due date): unreadable by design, not a failure. */
  columns: Record<string, { checked: number; failed: number; destroyed: number }>;
  failures: number;
}

const SLICE = 500;

interface DekLine { id: string; tenant_id: number | null; version: number; kek_id: string; dek_wrapped: string }

export async function verifyVault(o: { actor: DbActor; full?: boolean; tenantId?: number | null; signal?: AbortSignal }): Promise<VerifyReport> {
  vaultInternals.requireReady();
  const report: VerifyReport = { deks: { checked: 0, failed: 0 }, columns: {}, failures: 0 };

  // 1. Every DEK unwraps (without the cache).
  const deks = await asNone(o.actor, () => {
    const q = db('data_keys').whereNotNull('dek_wrapped').select('id', 'tenant_id', 'version', 'kek_id', 'dek_wrapped');
    if (o.tenantId !== undefined) q.whereRaw('coalesce(tenant_id, 0) = coalesce(?::int, 0)', [o.tenantId]);
    return q;
  }) as DekLine[];
  for (const d of deks) {
    o.signal?.throwIfAborted();
    report.deks.checked++;
    try {
      const key = await vaultInternals.keyring.unwrapUncached({ ...d, tenant_id: d.tenant_id ?? null });
      key.fill(0);
    } catch (err) {
      report.deks.failed++;
      logger.error({ vault: { code: (err as { code?: string }).code ?? 'error', dekId: d.id, tenantId: d.tenant_id } },
        'vault verify: a data key does not unwrap');
    }
  }

  // 2. Sealed values: one per (column, DEK), or all of them.
  for (const def of secretColumns()) {
    if (def.transient) continue;
    const label = `${def.table}.${def.column}`;
    const counts = report.columns[label] ?? (report.columns[label] = { checked: 0, failed: 0, destroyed: 0 });
    const cols = [def.pk, def.column, ...(def.tenantColumn ? [def.tenantColumn] : [])];
    const check = async (row: Record<string, unknown>, trx?: Knex.Transaction): Promise<void> => {
      const loc: SecretLocator = {
        table: def.table, column: def.column, pk: row[def.pk] as string | number,
        tenantId: def.tenantColumn && row[def.tenantColumn] != null ? Number(row[def.tenantColumn]) : null,
      };
      counts.checked++;
      try {
        const bytes = await vault.open(loc, String(row[def.column]), trx ? { trx } : {});
        bytes.fill(0);
      } catch (err) {
        if (isVaultError(err, 'dek_destroyed')) counts.destroyed++;
        else counts.failed++;
      }
    };
    for (const scope of await scopesOf(def, o.actor, o.tenantId)) {
      o.signal?.throwIfAborted();
      if (o.full) {
        let after: string | number | null = null;
        for (;;) {
          const rows = await scope.run(async () => {
            let qb = scope.filter(db(def.table).select(cols).whereNotNull(def.column));
            if (after !== null) qb = qb.where(def.pk, '>', after);
            const got = await qb.orderBy(def.pk).limit(SLICE) as Array<Record<string, unknown>>;
            for (const r of got) await check(r);
            return got;
          });
          if (rows.length < SLICE) break;
          after = rows[rows.length - 1][def.pk] as string | number;
        }
      } else {
        const scopeDeks = deks.filter((d) => (d.tenant_id ?? null) === scope.tenantId);
        await scope.run(async () => {
          for (const d of scopeDeks) {
            const row = await scope.filter(db(def.table).select(cols).where(def.column, 'like', `v1:${d.id}:%`))
              .first() as Record<string, unknown> | undefined;
            if (row) await check(row);
          }
        });
      }
    }
  }
  report.failures = report.deks.failed + Object.values(report.columns).reduce((n, c) => n + c.failed, 0);
  return report;
}

/**
 * Garbage collection of tenant_secrets: a row that no registered document
 * refers to gets orphaned_at (after a day of grace: a secret is created just
 * before the document that refers to it), and is deleted 30 days later; a
 * reference that comes back clears orphaned_at. Without any registered
 * holder, nothing is collected (no consumer yet: every row would look
 * orphaned).
 */
export async function collectTenantSecrets(actor: DbActor): Promise<{ orphaned: number; revived: number; deleted: number; tenants: number }> {
  const holders = secretReferenceHolders();
  const out = { orphaned: 0, revived: 0, deleted: 0, tenants: 0 };
  if (!holders.length) return out;
  const { failed } = await forEachTenant(actor, async (tenantId) => {
    const referenced = new Set<string>();
    for (const h of holders) {
      const rows = await db(h.table).where(h.tenantColumn, tenantId).select(h.column) as Array<Record<string, unknown>>;
      for (const r of rows) for (const id of h.refs(r[h.column])) referenced.add(id);
    }
    const secrets = await db('tenant_secrets').where({ tenant_id: tenantId })
      .select('id', 'orphaned_at', 'created_at') as Array<{ id: string; orphaned_at: Date | null; created_at: Date }>;
    const now = Date.now();
    for (const s of secrets) {
      if (referenced.has(s.id)) {
        if (s.orphaned_at) {
          await db('tenant_secrets').where({ id: s.id }).update({ orphaned_at: null });
          out.revived++;
        }
      } else if (!s.orphaned_at) {
        if (now - new Date(s.created_at).getTime() > 86_400_000) {
          await db('tenant_secrets').where({ id: s.id }).update({ orphaned_at: new Date() });
          out.orphaned++;
        }
      } else if (now - new Date(s.orphaned_at).getTime() > 30 * 86_400_000) {
        await db('tenant_secrets').where({ id: s.id }).whereNotNull('orphaned_at').delete();
        out.deleted++;
      }
    }
    out.tenants++;
  });
  if (failed) throw Object.assign(new Error(`${failed} tenant(s) failed`), { code: 'partial_failure' });
  return out;
}

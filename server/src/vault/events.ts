// Audit entries and alerts of the vault (docs: coffre-secrets §11.3, §5.7).
// Never a value nor a sealed value: identifiers, versions, kek_id, counts.
//
// Until the hardened journal (audit-durci, lot A6: audit.appendInTx), the
// entries go through auditService.log, which writes on a lease of its own:
// an entry about work done in a transaction is written once that transaction
// commits (never when it rolls back), through Knex's executionPromise.
import type { Knex } from 'knex';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { currentDbContext, type DbActor } from '../db/context';
import { raiseJobAlert } from '../jobs/alerts';
import { auditService, type AuditLogEntry } from '../services/audit.service';
import { logger } from '../utils/logger';

export type VaultAuditEntry = AuditLogEntry;

/** The user of the current database context, for the audit entries. */
export function currentUserId(): number | undefined {
  const actor = currentDbContext()?.actor;
  return actor?.type === 'user' ? actor.userId : undefined;
}

/** The actor of the current context, else the vault's own. */
export function currentOrVaultActor(): DbActor {
  return currentDbContext()?.actor ?? { type: 'job', name: 'vault' };
}

/** Writes the entries now, one after the other. Never throws (auditService.log
 *  logs a lost entry). */
export async function writeVaultAudit(entries: readonly VaultAuditEntry[]): Promise<void> {
  for (const e of entries) await auditService.log(e);
}

/** Writes the entries once `trx` commits (nothing when it rolls back), or now
 *  without a transaction. Never throws. */
export function auditAfterCommit(trx: Knex.Transaction | Knex | null | undefined, entries: readonly VaultAuditEntry[]): Promise<void> {
  if (!entries.length) return Promise.resolve();
  const exec = (trx as Knex.Transaction | undefined)?.executionPromise;
  if (trx && exec && typeof (trx as Knex.Transaction).isCompleted === 'function') {
    return exec.then(() => writeVaultAudit(entries), () => undefined).catch(() => undefined);
  }
  return writeVaultAudit(entries).catch(() => undefined);
}

/** An entry of the master tenant's log (the MSP's). */
export function masterEntry(action: string, details: Record<string, unknown>, extra: Partial<VaultAuditEntry> = {}): VaultAuditEntry {
  return { tenantId: MASTER_TENANT_ID, userId: currentUserId(), action, resourceType: 'vault', details, ...extra };
}

/** A live alert of the master tenant, deduplicated on its stable key, and an
 *  error line. Never throws, never waits. */
export function vaultAlert(stableKey: string, title: string, message: string, severity: 'warning' | 'critical' = 'critical'): void {
  void raiseJobAlert(currentOrVaultActor(), { stableKey, severity, title, message }).catch((err) => {
    logger.error({ err: { code: (err as { code?: string })?.code }, alert: stableKey }, 'vault alert not written');
  });
}

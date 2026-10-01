// Audit entries and alerts of the vault (docs: coffre-secrets §11.3, §5.7;
// audit-durci §3.4). Never a value nor a sealed value: identifiers, versions,
// kek_id, counts.
//
// Classes: the key operations are critical, written in the vault's own
// transaction (P1, writeVaultAuditInTx: the change and its entry together,
// or neither), or as an intent before an operation that has no transaction
// of its own (P2). The informational events (a key created, a backfill, a
// verification, an escrow) are standard, written after the fact: once the
// transaction commits (auditAfterCommit, never when it rolls back), or now.
import type { Knex } from 'knex';
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { currentDbContext, type DbActor } from '../db/context';
import { raiseJobAlert } from '../jobs/alerts';
import { auditService, type AuditLogEntry } from '../services/audit.service';
import { audit, registerAuditActions, type AuditEntryInput, type AuditWriteContext } from '../audit';
import { logger } from '../utils/logger';

registerAuditActions([
  { name: 'vault.kek_rotation_requested', criticality: 'critical', label: 'Key-encryption key rotation requested' },
  { name: 'vault.kek_rotated', criticality: 'critical', label: 'Key-encryption key rotated' },
  { name: 'vault.dek_rotation_requested', criticality: 'critical', label: 'Data key rotation requested' },
  { name: 'vault.dek_rotated', criticality: 'critical', label: 'Data key rotated' },
  { name: 'vault.dek_destruction_scheduled', criticality: 'critical', label: 'Data key destruction scheduled' },
  { name: 'vault.dek_destruction_cancelled', criticality: 'critical', label: 'Data key destruction cancelled' },
  { name: 'vault.dek_destroyed', criticality: 'critical', label: 'Data keys destroyed' },
  { name: 'vault.kek_loss_recovered', criticality: 'critical', label: 'Recovery after the loss of the key-encryption key' },
  { name: 'vault.instance_secret_changed', criticality: 'critical', label: 'Instance secret changed' },
  { name: 'vault.dek_created', criticality: 'standard', label: 'Data key created' },
  { name: 'vault.backfill_completed', criticality: 'standard', label: 'Inherited secrets sealed' },
  { name: 'vault.verify_failed', criticality: 'standard', label: 'Vault verification failed' },
  { name: 'vault.escrow_confirmed', criticality: 'standard', label: 'Vault escrow confirmed' },
  { name: 'vault.escrow_tested', criticality: 'standard', label: 'Vault escrow tested' },
  { name: 'vault.escrow_old_shares_destroyed', criticality: 'standard', label: 'Old escrow shares destroyed' },
  { name: 'vault.tenant_secret_created', criticality: 'standard', label: 'Tenant secret created' },
]);

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

/** A legacy-shaped vault entry as an entry of the journal (a master entry
 *  about a tenant names it as onBehalfOf). */
export function vaultEntryInput(e: VaultAuditEntry): AuditEntryInput {
  const d = e.details as { tenantId?: unknown } | undefined;
  const about = Number(d?.tenantId);
  return {
    tenantId: e.tenantId,
    action: e.action,
    target: e.resourceType ? { type: e.resourceType, id: e.resourcePath ?? '' } : undefined,
    details: e.details,
    onBehalfOf: e.tenantId === MASTER_TENANT_ID && Number.isSafeInteger(about) && about > 1 ? about : undefined,
  };
}

/** The audit context of vault entries: their user, else the current
 *  context's actor, else the vault's. */
export async function vaultAuditContext(entries: readonly VaultAuditEntry[]): Promise<AuditWriteContext> {
  const userId = entries.find((e) => e.userId)?.userId;
  const actor: DbActor = userId ? { type: 'user', userId } : currentOrVaultActor();
  return audit.fromDbActor(actor, MASTER_TENANT_ID, { ip: entries.find((e) => e.ipAddress)?.ipAddress });
}

/** P1: the entries in the vault's transaction (critical ones refuse the
 *  change when they cannot be written: the transaction is aborted). */
export async function writeVaultAuditInTx(trx: Knex.Transaction, entries: readonly VaultAuditEntry[]): Promise<void> {
  if (!entries.length) return;
  await audit.appendManyInTx(trx, entries.map(vaultEntryInput), await vaultAuditContext(entries));
}

/** P2: `entry` as an intent before `fn` (an operation without a
 *  transaction of its own), its result after. */
export async function withVaultIntent<T>(entry: VaultAuditEntry, fn: () => Promise<T>,
  resultDetails?: (r: T) => Record<string, unknown>): Promise<T> {
  return audit.withIntent(vaultEntryInput(entry), await vaultAuditContext([entry]), fn, { resultDetails });
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

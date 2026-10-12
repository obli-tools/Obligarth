import type { Knex } from 'knex';
import type { AuditEntryInput } from './types';

// =============================================================================
// Audit entries collected for the end of a transaction (docs: audit-durci
// §4.6, §5.2; file-durable §7.2, review FD-RC6; integration-apple-edge rule
// G-7, review INT-RC8). obligarth.audit_append locks the chain head of the
// tenant until the end of the transaction. A transaction that applies many
// events of many tenants (a batch of the outbox consumer) must therefore
// write no entry while it runs: a head taken at the first event would stay
// locked for the whole batch, every critical action of that tenant waiting
// behind it, and the heads would be taken in the order of the events instead
// of the ascending tenant order (lock-order deadlocks between two batches).
// The owner of such a transaction binds a collector to it for the time of
// each event; code that journals in the caller's transaction and may be
// reached from an event (the bus of the MDM commands: a command enqueued by
// the follow-up of a result, by a hook of a final target) asks for the
// collector of its transaction and hands its entry over instead of appending.
// The owner writes what was collected once, at the end (appendManyInTx:
// ascending tenant order), and drops what a failed event collected with the
// event's savepoint. Keyed by the transaction object: a nested transaction
// (another object) is not covered, and an outbox handler opens none.
// =============================================================================

export type AuditCollector = (entry: AuditEntryInput) => void;

const collectors = new WeakMap<object, AuditCollector>();

/** Binds `collect` to `trx` until the function returned is called (one collector at a time per transaction). */
export function bindTxAuditCollector(trx: Knex.Transaction, collect: AuditCollector): () => void {
  if (collectors.has(trx)) throw new Error('audit: this transaction already collects its entries');
  collectors.set(trx, collect);
  return () => {
    if (collectors.get(trx) === collect) collectors.delete(trx);
  };
}

/** The collector bound to `trx`, or null: the entries of this transaction are then appended in it. */
export function txAuditCollector(trx: Knex.Transaction): AuditCollector | null {
  return collectors.get(trx) ?? null;
}

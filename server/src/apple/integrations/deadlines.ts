import { randomUUID } from 'node:crypto';
import type { Knex } from 'knex';

// =============================================================================
// Deadlines of the integrations (docs: integration-apple-edge §11.4, I14;
// INT-05): one row of integration_deadline_items per subject (a push
// certificate by its topic, an ADE server by its token, the device CA…),
// written by its producer in the producer's transaction; the échéancier
// (integrations.deadlines-*, lot C3) raises the deadline.* alerts at J-60, 30,
// 14, 7, 3 and 1, once per expiry (last_alerted_not_after). A subject renewed
// keeps its row (its expiry moves on); a later expiry always wins over an
// older event consumed late (a renewal extends). Labels are configuration
// labels (topic, server name): never a person. In the caller's transaction and
// the tenant's context.
// =============================================================================

export type DeadlineKind = 'apns_certificate' | 'ade_token' | 'vpp_token' | 'device_ca';
/** Items of the instance (tenant_id NULL), written in the identity context (class tenant_or_global). */
export type InstanceDeadlineKind = 'mdm_tls_certificate' | 'vendor_certificate' | 'mdm_domain' | 'profile_signing_identity'
  | 'vault_escrow_test' | 'vault_kek_rotation' | 'vault_old_shares' | 'vault_dek_destruction' | 'backup_restore_drill';

export interface DeadlineItem {
  kind: DeadlineKind;
  /** Stable reference of the subject (topic, token id, CA id), 100 characters at most. */
  subjectRef: string;
  /** Configuration label shown by the échéancier, 200 characters at most. */
  label: string;
  notAfter: Date | null;
  source?: 'apple-edge' | 'brain';
}

/** Records (or moves on) the deadline of a subject of the tenant. */
export async function recordDeadline(trx: Knex.Transaction, tenantId: number, d: DeadlineItem): Promise<void> {
  const notAfter = d.notAfter && !Number.isNaN(d.notAfter.getTime()) ? d.notAfter : null;
  await trx.raw(`
    INSERT INTO obligarth.integration_deadline_items AS i (id, tenant_id, kind, subject_ref, label, not_after, source, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, now())
    ON CONFLICT ((coalesce(tenant_id, 0)), kind, subject_ref)
    DO UPDATE SET label = EXCLUDED.label,
                  not_after = CASE WHEN i.not_after IS NULL OR EXCLUDED.not_after > i.not_after THEN EXCLUDED.not_after ELSE i.not_after END,
                  retired_at = NULL, updated_at = now()`,
  [randomUUID(), tenantId, d.kind, d.subjectRef.slice(0, 100), d.label.slice(0, 200) || d.kind, notAfter, d.source ?? 'apple-edge']);
}

/** The subject is gone (a token removed): its row is kept 30 days, retired. */
export async function retireDeadline(trx: Knex.Transaction, tenantId: number, kind: DeadlineKind, subjectRef: string): Promise<void> {
  await trx('integration_deadline_items').where({ tenant_id: tenantId, kind, subject_ref: subjectRef.slice(0, 100) }).whereNull('retired_at')
    .update({ retired_at: new Date(), updated_at: new Date() });
}

export interface InstanceDeadlineItem {
  kind: InstanceDeadlineKind;
  subjectRef: string;
  label: string;
  notAfter: Date | null;
  source: 'apple-edge' | 'brain' | 'manual' | 'vault';
  /** The expiry is what the source says now (a manual entry, a computed due date), even earlier than before. */
  replace?: boolean;
}

/** Records an item of the instance (tenant_id NULL). The transaction's context is 'identity' (rls-tenant §5.3.1). */
export async function recordInstanceDeadline(trx: Knex.Transaction, d: InstanceDeadlineItem): Promise<void> {
  const notAfter = d.notAfter && !Number.isNaN(d.notAfter.getTime()) ? d.notAfter : null;
  const values = [randomUUID(), d.kind, d.subjectRef.slice(0, 100), d.label.slice(0, 200) || d.kind, notAfter, d.source];
  await trx.raw(d.replace ? INSTANCE_REPLACE_SQL : INSTANCE_EXTEND_SQL, values);
}

const INSTANCE_INSERT_SQL = `
    INSERT INTO obligarth.integration_deadline_items AS i (id, tenant_id, kind, subject_ref, label, not_after, source, updated_at)
    VALUES (?, NULL, ?, ?, ?, ?, ?, now())
    ON CONFLICT ((coalesce(tenant_id, 0)), kind, subject_ref)
    DO UPDATE SET label = EXCLUDED.label, source = EXCLUDED.source, retired_at = NULL, updated_at = now(), not_after = `;
/** The expiry is what the source says now (a manual entry, a computed due date). */
const INSTANCE_REPLACE_SQL = `${INSTANCE_INSERT_SQL}EXCLUDED.not_after`;
/** A later expiry wins (a renewal extends). */
const INSTANCE_EXTEND_SQL = `${INSTANCE_INSERT_SQL}CASE WHEN i.not_after IS NULL OR EXCLUDED.not_after > i.not_after THEN EXCLUDED.not_after ELSE i.not_after END`;

/** Retires the items of the instance of `kind` (all, or all but `keep`: one subject or several). Identity context. */
export async function retireInstanceDeadlines(trx: Knex.Transaction, kind: InstanceDeadlineKind, keep?: string | readonly string[]): Promise<void> {
  let q = trx('integration_deadline_items').whereNull('tenant_id').where({ kind }).whereNull('retired_at');
  if (typeof keep === 'string') q = q.whereNot('subject_ref', keep.slice(0, 100));
  else if (keep !== undefined && keep.length > 0) q = q.whereNotIn('subject_ref', keep.map((k) => k.slice(0, 100)));
  await q.update({ retired_at: new Date(), updated_at: new Date() });
}

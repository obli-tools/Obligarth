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

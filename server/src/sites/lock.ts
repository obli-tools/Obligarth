import type { Knex } from 'knex';

// The sites lock of a tenant (lot P1-SITE §2, P1-QR §3.2): every write of a site or of the site of devices takes it
// first (sites/service.ts), and so do an enrollment by a token that names a site (legacyAgent/enroll.ts) and the
// creation of such a token (usableSiteInTx): an archive never misses a device enrolled on the site meanwhile. Always
// taken BEFORE a row of legacy_agent_enrollment_tokens is updated (the archive revokes the tokens of its site): one
// order, no deadlock. No import of the database: enroll.ts and the sites' service share it without a cycle.

/** Serialises the writes of a tenant's sites (the plans are made again under it). */
export async function lockSites(trx: Knex.Transaction, tenantId: number): Promise<void> {
  await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`obligarth:sites:${tenantId}`]);
}

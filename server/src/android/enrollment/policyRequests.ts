// The enrollment policies of a tenant's live Android profiles requested again (android-amapi §9.3, §10.7; lot AN-C1):
// when the enterprise is set up (enterprises/setup.ts) and after each resolution of the tenant (registerTenantResolvedHook,
// modules/android.ts). One stately job per profile (android.policies.enrollment-policy); the job pushes nothing when
// the compiled policy did not change. Kept apart from profileService.ts (which writes through the profile service of
// lot C1) so that the setup does not load the Apple enrollment modules.
import type { Knex } from 'knex';
import { androidSenders } from './senders';

/** Sends android.policies.enrollment-policy for every live Android profile of the tenant, in `trx` (tenant context).
 *  Returns the number of profiles. */
export async function requestEnrollmentPolicies(trx: Knex.Transaction, tenantId: number): Promise<number> {
  const ids = await trx('enrollment_profiles').where({ tenant_id: tenantId, platform: 'android', enabled: true }).whereNull('archived_at')
    .orderBy('id').pluck('id') as string[];
  for (const profileId of ids) await androidSenders.enrollmentPolicy(trx, { tenantId, profileId: String(profileId) });
  return ids.length;
}

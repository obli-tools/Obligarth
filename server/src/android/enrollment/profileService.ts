// Android enrollment profiles written through the profile service of lot C1 (android-amapi §10.1, §10.7; lot AN-C1;
// raccords of the reports AN-C1b, AN-G1 and AN-A2): one table and one service for both platforms (enrollment_profiles,
// versions, archiving, apple/enrollment/service.ts), the Android checks here:
//   - the body: name, method (fixed once created), ownership, default group, locale, settings (validateAndroidProfile:
//     method and ownership agree, COPE at API 30 or more, a kiosk is a company device with an approval), no ADE usage
//     key, never the default ADE profile, notice always on (the BYOD notice is the device surface's, lot AN-F1);
//   - in the transaction that writes it: the kiosk app is a live Android app of the tenant's catalog
//     (checkAndroidKioskProfile), then android.policies.enrollment-policy is sent for the profile (its policy
//     e-<profile uuid> compiled again: a changed kiosk app, group, ownership or API level reaches Google before the next
//     token; rule of the 5 minutes, §10.7);
//   - archiving: refused for a kiosk profile that still has enrolled devices (G1-R4: their kiosk would lose its form,
//     compile:kiosk_form_missing); once archived, its active tokens are revoked at Google (an archived profile enrolls
//     no new device: the enrollment handler checks the token's snapshot, never the current profile).
// The enrollment policies of every live profile are also sent when the enterprise is set up (setup.ts) and after each
// resolution of the tenant (policies may have changed on the default group: §9.3 « recompilée à chaque résolution du
// groupe par défaut »); the job compiles and pushes nothing when the compiled policy did not change.
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  ANDROID_ENROLLMENT_METHODS, ENROLLMENT_LOCALES,
  type AndroidEnrollmentProfileSettings, type AndroidEnrollmentProfileView, type EnrollmentProfileView,
} from '@obligarth/shared';
import { AppError } from '../../middleware/errorHandler';
import { archiveProfile, createProfile, getProfile, listProfiles, updateProfile, type ProfileWrite } from '../../apple/enrollment/service';
import { checkAndroidKioskProfile, validateAndroidProfile } from './profiles';
import { androidSenders } from './senders';

type Q = Knex | Knex.Transaction;

export const AndroidProfileBody = z.object({
  name: z.string().trim().min(1).max(200),
  method: z.enum(ANDROID_ENROLLMENT_METHODS),
  ownership: z.enum(['corporate', 'corporate_personal', 'personal']),
  defaultGroupId: z.number().int().positive().nullable().optional(),
  locale: z.enum(ENROLLMENT_LOCALES).optional(),
  settings: z.record(z.unknown()).optional(),
  enabled: z.boolean().optional(),
}).strict();
export type AndroidProfileBodyInput = z.infer<typeof AndroidProfileBody>;

export class AndroidProfileError extends AppError {
  readonly issues: Array<{ code: string; field: string }>;
  constructor(issues: Array<{ code: string; field: string }>) {
    super(422, `Invalid Android enrollment profile: ${issues.map((i) => i.code).join(', ')}`, issues[0]?.code ?? 'invalidRequest', { issues });
    this.issues = issues;
  }
}

/** The body checked (without the tenant's data): what the service writes, or 422 with the issues. */
export function checkAndroidProfileBody(raw: unknown): ProfileWrite {
  const b = AndroidProfileBody.safeParse(raw ?? {});
  if (!b.success) {
    const i = b.error.issues[0];
    throw new AppError(400, `${i?.path.join('.') || 'request'}: ${i?.message ?? 'invalid'}`, 'invalidRequest');
  }
  const v = validateAndroidProfile({ method: b.data.method, ownership: b.data.ownership, settings: b.data.settings ?? {} });
  if (!v.ok) throw new AndroidProfileError(v.issues);
  return {
    platform: 'android', name: b.data.name, method: b.data.method, ownership: b.data.ownership, usage: null,
    defaultGroupId: b.data.defaultGroupId ?? null, noticeRequired: true, locale: b.data.locale ?? 'fr', settings: v.settings,
    isDefault: false, enabled: b.data.enabled ?? true,
  };
}

/** The checks against the tenant's data, then the enrollment policy sent, in the transaction that writes the profile. */
async function afterWrite(trx: Knex.Transaction, tenantId: number, profileId: string, p: ProfileWrite): Promise<void> {
  const issues = await checkAndroidKioskProfile(trx, tenantId, p.settings as never);
  if (issues.length) throw new AndroidProfileError(issues);
  await androidSenders.enrollmentPolicy(trx, { tenantId, profileId });
}

export async function createAndroidProfile(trx: Knex.Transaction, tenantId: number, userId: number, p: ProfileWrite): Promise<string> {
  const id = await createProfile(trx, tenantId, userId, p);
  await afterWrite(trx, tenantId, id, p);
  return id;
}

/** Has the kiosk profile still enrolled devices (amapi channel, not unenrolled)? */
async function kioskProfileInUse(trx: Knex.Transaction, tenantId: number, id: string): Promise<boolean> {
  return !!(await trx('devices').where({ tenant_id: tenantId, enrollment_profile_id: id, management_channel: 'amapi' })
    .whereNot('enrollment_state', 'unenrolled').first('id'));
}

export async function updateAndroidProfile(trx: Knex.Transaction, tenantId: number, userId: number, id: string, p: ProfileWrite): Promise<number> {
  // Review AN-C1 (G1-R4, DM23): the kiosk app of a kiosk profile is the single-app kiosk of its enrolled devices (read
  // at each push of their own policy). Changing it, or turning the profile into a standard one, would change or lift
  // the kiosk lock of those devices outside the preview and the approval of a policy (kioskLockChanges): refused while
  // the profile has enrolled devices, as its archiving is; a kiosk form is then changed by a policy.
  const cur = await trx('enrollment_profiles').where({ tenant_id: tenantId, id, platform: 'android' }).forUpdate().first('settings', 'archived_at') as
    { settings: AndroidEnrollmentProfileSettings | null; archived_at: Date | null } | undefined;
  if (cur && !cur.archived_at && cur.settings?.deviceUsage === 'kiosk') {
    const next = p.settings as AndroidEnrollmentProfileSettings;
    const changed = next.deviceUsage !== 'kiosk' || (next.kioskApp ?? null) !== (cur.settings.kioskApp ?? null);
    if (changed && await kioskProfileInUse(trx, tenantId, id)) {
      throw new AppError(409, 'This kiosk profile still has enrolled devices', 'androidKioskProfileInUse');
    }
  }
  const version = await updateProfile(trx, tenantId, userId, id, p);
  await afterWrite(trx, tenantId, id, p);
  return version;
}

/** Archives an Android profile; returns its version and its tokens to revoke at Google once committed. */
export async function archiveAndroidProfile(trx: Knex.Transaction, tenantId: number, userId: number, id: string):
  Promise<{ version: number; tokens: string[] }> {
  const p = await trx('enrollment_profiles').where({ tenant_id: tenantId, id, platform: 'android' }).forUpdate().first('settings', 'archived_at') as
    { settings: AndroidEnrollmentProfileSettings | null; archived_at: Date | null } | undefined;
  if (!p) throw new AppError(404, 'Enrollment profile not found', 'enrollmentProfileNotFound');
  if (!p.archived_at && p.settings?.deviceUsage === 'kiosk' && await kioskProfileInUse(trx, tenantId, id)) {
    throw new AppError(409, 'This kiosk profile still has enrolled devices', 'androidKioskProfileInUse');
  }
  const version = await archiveProfile(trx, tenantId, userId, id, [], 'android');
  const tokens = await trx('android_enrollment_tokens').where({ tenant_id: tenantId, profile_id: id, state: 'active' }).pluck('id') as string[];
  return { version, tokens: tokens.map(String) };
}

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);

/** The Android profiles of the tenant (the C1 view, with the Android tokens and the enrollment policy). */
export async function listAndroidProfiles(q: Q, tenantId: number, archived: boolean): Promise<AndroidEnrollmentProfileView[]> {
  return withAndroidFacts(q, tenantId, await listProfiles(q, tenantId, archived, 'android'));
}

export async function getAndroidProfile(q: Q, tenantId: number, id: string): Promise<AndroidEnrollmentProfileView> {
  return (await withAndroidFacts(q, tenantId, [await getProfile(q, tenantId, id, 'android')]))[0];
}

async function withAndroidFacts(q: Q, tenantId: number, views: EnrollmentProfileView[]): Promise<AndroidEnrollmentProfileView[]> {
  if (!views.length) return [];
  const ids = views.map((v) => v.id);
  const tokens = await q('android_enrollment_tokens').where({ tenant_id: tenantId, state: 'active' }).whereIn('profile_id', ids)
    .where('expires_at', '>', q.raw('now()')).groupBy('profile_id').select('profile_id', q.raw('count(*)::int AS n')) as
    Array<{ profile_id: string; n: number }>;
  const policies = await q('android_enrollment_policies').where({ tenant_id: tenantId }).whereIn('profile_id', ids)
    .select('profile_id', 'state', 'pushed_at', 'last_error') as Array<{ profile_id: string; state: string; pushed_at: Date | null; last_error: string | null }>;
  const t = new Map(tokens.map((r) => [String(r.profile_id), Number(r.n)]));
  const pol = new Map(policies.map((r) => [String(r.profile_id), r]));
  return views.map((v) => {
    const p = pol.get(v.id);
    return {
      id: v.id, name: v.name, method: v.method as unknown as AndroidEnrollmentProfileView['method'], ownership: v.ownership as AndroidEnrollmentProfileView['ownership'],
      defaultGroupId: v.defaultGroupId, defaultGroupName: v.defaultGroupName, locale: v.locale,
      settings: v.settings as AndroidEnrollmentProfileSettings, enabled: v.enabled, version: v.version, createdAt: v.createdAt,
      updatedAt: v.updatedAt, archivedAt: v.archivedAt, activeTokens: t.get(v.id) ?? 0,
      enrollmentPolicy: {
        state: (p?.state ?? 'pending') as AndroidEnrollmentProfileView['enrollmentPolicy']['state'],
        pushedAt: iso(p?.pushed_at ?? null), lastError: p?.last_error ?? null,
      },
    };
  });
}

export { requestEnrollmentPolicies } from './policyRequests';

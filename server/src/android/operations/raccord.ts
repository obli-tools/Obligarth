// Hooks of the Android operation for the junction AN-A2/AN-P (lot AN-H1): written as autonomous functions with the
// signatures of the points of section 22.6, so that the junction only registers them in the existing files (forbidden
// before the integration of lot C):
//   - registerDevicePurger('amapi', androidDevicePurger)            modules/privacy.ts (retention, COH-10);
//   - registerAlertDefinitions(androidAlertDefinitions())          catalogue of the alerts opened to modules;
//   - registerOnboardStep('amapi', androidOnboardStep)             onboarding assistant (Android part);
//   - tenantService.delete → assertTenantDeletable(tenantId)        409 tenantHasAndroidEnterprise (AN27);
//   - jobEffectOf(err) === 'enterprise_error' → markEnterpriseAccessLost(tenantId)  (a 403 of any Android job);
//   - the échéancier of lot C3 → listAndroidDeadlines / platformKeyDeadline;
//   - the startup after an absence of more than 5 days, and the restore of a backup → requestReconcile(tenantId, …).
import { db } from '../../db';
import { asNone, asTenant, type DbActor } from '../../db/context';
import { androidConfig } from '../config';
import { MAINTENANCE_ACTOR } from '../enterprises/orphans';
import { readPlatformState } from '../enterprises/registry';
import { purgeAndroidDevices } from './purge';
import { requestReconcile } from './reconcile';

export { androidAlertDefinitions } from '../alerts';
export { assertTenantDeletable, markEnterpriseAccessLost } from './offboarding';
export { listAndroidDeadlines, platformKeyDeadline } from './deadlines';

/** The purger of the channel amapi, in the shape of registerDevicePurger (ctx carries the tenant). */
export async function androidDevicePurger(ctx: { tenantId: number }, deviceIds: number[]): Promise<void> {
  await purgeAndroidDevices(ctx.tenantId, deviceIds);
}

/** The steps of the onboarding assistant for Android (identifiers and booleans only). */
export interface AndroidOnboardState {
  steps: Array<{ key: string; done: boolean }>;
}

const ONBOARD_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.onboarding' }) as DbActor;

/** The Android part of the onboarding assistant of a tenant: identity, link, topic, test message, profile, first device. */
export async function androidOnboardStep(tenantId: number): Promise<AndroidOnboardState> {
  const cfg = androidConfig();
  const platform = cfg.mode === 'off' ? null : await asNone(MAINTENANCE_ACTOR, () => readPlatformState());
  return asTenant(tenantId, ONBOARD_ACTOR, async () => {
    const e = await db('android_enterprises').where({ tenant_id: tenantId }).whereNot('state', 'unlinked')
      .first('state', 'topic_set_at', 'test_message_at') as { state: string; topic_set_at: Date | null; test_message_at: Date | null } | undefined;
    const profile = await db('android_enrollment_policies').where({ tenant_id: tenantId, state: 'pushed' }).first('profile_id');
    const device = await db('android_devices').where({ tenant_id: tenantId }).whereNull('released_at').first('device_id');
    return {
      steps: [
        { key: 'android.onboarding.identity', done: cfg.mode !== 'off' && (cfg.auth === 'adc' || !!platform?.credential_set_at) },
        { key: 'android.onboarding.enterprise_linked', done: e?.state === 'linked' },
        { key: 'android.onboarding.topic_set', done: !!e?.topic_set_at },
        { key: 'android.onboarding.test_message', done: !!e?.test_message_at || !!platform?.last_test_message_at },
        { key: 'android.onboarding.enrollment_profile', done: !!profile },
        { key: 'android.onboarding.first_device', done: !!device },
      ],
    };
  });
}

/** After a restore of the base or an absence of the instance of more than 5 days: a reconciliation of every tenant. */
export async function requestReconcileAll(trigger: 'absence' | 'restore'): Promise<number> {
  const tenants = await asNone(MAINTENANCE_ACTOR, async () => {
    const r = await db.raw('SELECT tenant_id FROM obligarth.android_linked_tenants()') as { rows: Array<{ tenant_id: number }> };
    return r.rows.map((x) => Number(x.tenant_id));
  });
  let n = 0;
  for (const t of tenants) if (await requestReconcile(t, trigger)) n += 1;
  return n;
}

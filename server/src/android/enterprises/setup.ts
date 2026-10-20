// android.enterprise-setup (tenant job, section 6.2 step 6): the project's topic and the notification types on the
// enterprise (the only caller of setEnterpriseNotifications with the offboarding), the display name without the
// signup marker, the reserved restrictive policy 'default'. The Pub/Sub 'test' message published by Google proves the
// topic-subscription chain of the project: android.pubsub-test-check raises android.pubsub_test_missing when none
// arrived 15 minutes after the topic was set. Then the enrollment policies of the tenant's live Android profiles are
// sent (lot AN-C1, §10.7: profiles written before the enterprise was linked, or while it was set up, get theirs).
import type { Knex } from 'knex';
import { db } from '../../db';
import { asNone, asTenant, type DbActor } from '../../db/context';
import { raiseAndroidPlatformAlert } from '../alerts';
import { androidGateway } from '../gateway';
import type { AndroidGateway } from '../gateway/types';
import { readEnterprise, readEnterpriseRow, readPlatformState } from './registry';
import { requestEnrollmentPolicies } from '../enrollment/policyRequests';

export const SETUP_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.enterprise-setup' }) as DbActor;

/** The restrictive policy every enterprise holds (no app, no secret): devices enrolled without a policy get it. */
export const DEFAULT_POLICY = Object.freeze({
  playStoreMode: 'WHITELIST',
  factoryResetDisabled: false,
  addUserDisabled: true,
  installUnknownSourcesAllowed: false,
  debuggingFeaturesAllowed: false,
  statusReportingSettings: { applicationReportsEnabled: false, deviceSettingsEnabled: true, softwareInfoEnabled: true },
});

type TestCheckSender = (trx: Knex.Transaction, tenantId: number) => Promise<unknown>;
let testCheckSender: TestCheckSender = async () => undefined;
export function setTestCheckSender(fn: TestCheckSender): void { testCheckSender = fn; }

/** Runs the setup of `tenantId`'s enterprise (idempotent). */
export async function setupEnterprise(tenantId: number, o: { gateway?: AndroidGateway; actor?: DbActor } = {}): Promise<'done' | 'no_enterprise'> {
  const gw = o.gateway ?? androidGateway();
  const actor = o.actor ?? SETUP_ACTOR;
  return asTenant(tenantId, actor, async () => {
    const e = await readEnterprise();
    const row = await readEnterpriseRow();
    if (!e || !row || e.state !== 'linked') return 'no_enterprise';
    if (!row.topic_set_at) {
      await gw.setEnterpriseNotifications(e, true);
      await db.transaction(async (trx) => {
        await trx('android_enterprises').where({ id: e.id }).update({ topic_set_at: trx.fn.now(), updated_at: trx.fn.now() });
        await testCheckSender(trx, tenantId);
      });
    }
    await gw.patchEnterprise(e, { enterpriseDisplayName: row.display_name }, ['enterpriseDisplayName']);
    await gw.putPolicy(e, 'default', { ...DEFAULT_POLICY });
    await db.transaction((trx) => requestEnrollmentPolicies(trx, tenantId));
    return 'done';
  });
}

/** android.pubsub-test-check: a 'test' message reached the instance after the topic was set, or an alert. */
export async function checkTestMessage(tenantId: number, actor: DbActor = SETUP_ACTOR): Promise<'ok' | 'missing' | 'no_topic'> {
  const row = await asTenant(tenantId, actor, () => readEnterpriseRow());
  if (!row?.topic_set_at) return 'no_topic';
  const state = await asNone(actor, () => readPlatformState());
  const proved = (state.last_test_message_at && new Date(state.last_test_message_at) >= new Date(new Date(row.topic_set_at).getTime() - 60_000))
    || row.test_message_at !== null;
  if (proved) return 'ok';
  void raiseAndroidPlatformAlert('android.pubsub_test_missing', { tenantId });
  return 'missing';
}

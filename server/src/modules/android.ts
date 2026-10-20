import { logger } from '../utils/logger';
import { registerStartTask, registerStopTask } from '../lifecycle';
import { findSecretRefs, registerInstanceSecretName, registerSecretColumn, registerSecretReferenceHolder } from '../vault';
import { registerAndroidGuardedActions } from '../android/commands/guarded';
import { registerAndroidKioskActions } from '../android/kiosk/exits';
import { registerAndroidAdoptionApprovals } from '../android/operations/adoption';
import { registerAndroidForgetAction } from '../android/operations/forget';
import { registerAndroidOffboardingApprovals } from '../android/operations/offboarding';
import { registerCommandHandler } from '../android/commands/submit';
import { db } from '../db';
import { raiseAndroidPlatformAlert } from '../android/alerts';
import { registerAndroidAuditActions } from '../android/audit';
import { androidConfig } from '../android/config';
import { checkPinnedProject } from '../android/enterprises/registry';
import { AndroidError } from '../android/gateway/errors';
import { androidGateway, GOOGLE_CREDENTIALS_SECRET } from '../android/gateway';
import { setHealthLoop } from '../android/health';
import { freezeAndroidEventHandlers } from '../android/inbox/handlers';
import { registerEnterpriseHandlers } from '../android/inbox/handlers.enterprise';
import { registerAndroidJobs } from '../android/jobs';
import { AndroidPullLoop } from '../android/link/pull';
import { registerEnrollmentHandler } from '../android/enrollment/handler';
import { registerStatusReportHandler } from '../android/inventory/statusReport';
import { registerUsageLogsHandler } from '../android/inventory/usageLogs';
import { setAndroidDeviceCounter } from '../android/gateway/google';
import { plugAndroidJunction } from '../android/junction';
import { registerFreezeHandler } from '../guard';
import { currentDbContext, type DbActor } from '../db/context';
import { endKioskExitsOnFreeze } from '../android/kiosk/exits';
import { resumeHeldCommands } from '../android/commands/submit';
import { resealMovedCommandSecrets } from '../android/commands/moved';
import { registerAndroidConsoleCommands } from '../android/commands/console';
import { registerAndroidQueueChannel } from '../android/routes/commands.routes';
import { registerDevicePurger, registerEnrollmentPurgeSlice } from './privacy';
import { purgeEndedTokensSlice } from '../android/enrollment/tokens';
import { registerAlertDefinitions } from '../services/alertCatalog';
import { androidAlertDefinitions } from '../android/alerts';
import { purgeAndroidDevices } from '../android/operations/purge';
import { registerArtifactChannel } from '../mdm/policies/artifacts';
import { amapiArtifactProvider } from '../android/policies/channel';
import { registerTenantResolvedHook } from '../mdm/policies/jobs';
import { requestEnrollmentPolicies } from '../android/enrollment/policyRequests';

// =============================================================================
// ANDROID (Android Management API, called directly by the instance) — its hooks into the core's registries,
// registered here and only here, without I/O: the vault's instance secret name, the audit actions, the handlers of
// the notifications, the hooks of the junction (android/junction.ts); the durable jobs, the start check of the Google
// identity and the pull loop only when ANDROID_MODE is not off (an instance without Android adds no queue, no
// statement at rest). index.ts calls it after registerAppleModule() and registerPrivacyModule() (lot AN-A2); its
// routes are mounted by routes/index.ts and app.ts.
// Start (google, fake): android.google-check obtains an access token, checks the permission on the subscription and
// refuses to start when ANDROID_GCP_PROJECT_ID differs from the pinned project; an absent or refused identity, or
// Google out of reach, starts degraded with a platform alert. Stop: the loop finishes its pull without acknowledging
// what is not committed.
// =============================================================================

let registered = false;
let loop: AndroidPullLoop | null = null;

export function registerAndroidModule(): void {
  if (registered) return;
  registered = true;

  plugAndroidJunction();
  // Lot AN-P (§22.6, COH-2): the channel amapi of the common artifact store (the android:* settings, one own policy
  // per device, pushed by android.policies.push-device; a no-op sender while ANDROID_MODE is off).
  registerArtifactChannel(amapiArtifactProvider);
  // Its alerts in the catalogue opened to the modules (lot AN-P, COH-22): raised by android/alerts.ts (identifiers
  // only, i18n key alerts.<key>); a platform alert is filed in the master tenant.
  registerAlertDefinitions('android', androidAlertDefinitions().map((a) => ({
    key: a.key, scope: a.scope === 'platform' ? 'master' : a.scope, severity: a.severity, title: a.title, i18nKey: a.i18nKey,
  })));
  registerInstanceSecretName(GOOGLE_CREDENTIALS_SECRET, 'JSON key of the Google service account of the Android integration (vault_key mode)');
  registerAndroidAuditActions();
  registerEnterpriseHandlers();
  // Lot AN-C1b: the enrollment and inventory handlers; the sealed values of the enrollment tokens are referenced by
  // android_enrollment_tokens.value_ref (the garbage collection of the vault never destroys the value of a token
  // that still holds it: AN17, §22.3); the device count of the last-resort caps (AN47).
  registerEnrollmentHandler();
  registerStatusReportHandler();
  // Lot AN-F2: the USAGE_LOGS of the lost mode (positions of company devices only, user exits).
  registerUsageLogsHandler();
  registerSecretReferenceHolder({
    table: 'android_enrollment_tokens', column: 'value_ref', tenantColumn: 'tenant_id',
    refs: (v) => (typeof v === 'string' && /^[0-9a-f-]{36}$/.test(v) ? [v] : []),
  });
  // Lot AN-D (section 11, §22.9): the sealed newPassword of RESET_PASSWORD lives in mdm_commands.secret_enc (a command
  // whose seal is lost keeps its row and is rejected at its submission, secret_lost: never sent without its password);
  // the seals the migration android_commands_move moved are sealed again there by the boot backfill (custom source).
  // android_commands.secret_enc stays registered for that reseal only (transient: the table is gone, no scan reads it).
  // The references of pending_actions (mdm.reset_password carries {"$secret": "<uuid>"}, purpose android.reset_password),
  // the COMMAND handler, the guarded actions that exist only for Android and the final hook of the lost mode.
  registerSecretColumn({
    table: 'mdm_commands', column: 'secret_enc', pk: 'id', pkType: 'uuid', tenantColumn: 'tenant_id', encoding: 'utf8',
    owner: 'android.commands', onLoss: 'null',
    legacy: { kind: 'custom', name: 'android_commands_moved', run: resealMovedCommandSecrets },
  });
  registerSecretColumn({
    table: 'android_commands', column: 'secret_enc', pk: 'id', pkType: 'uuid', tenantColumn: 'tenant_id', encoding: 'utf8',
    owner: 'android.commands', transient: true,
  });
  registerSecretReferenceHolder({ table: 'pending_actions', column: 'params', tenantColumn: 'tenant_id', refs: (v) => findSecretRefs(typeof v === 'string' ? JSON.parse(v) : v) });
  registerCommandHandler();
  registerAndroidGuardedActions();
  // Lot AN-D (§11.2, §11.5): the commands of the console that are not guarded (restriction keys mdm.reboot,
  // mdm.lost_mode_disable, mdm.clear_app_data, floor 'sensitive'; approval type android_action), and the routes of the
  // queue serving the amapi devices and the Android commands (registerQueueChannel).
  registerAndroidConsoleCommands();
  registerAndroidQueueChannel();
  // Lot AN-G1: the temporary exit of a kiosk (guarded action mdm.android_kiosk_exit, new restriction key).
  registerAndroidKioskActions();
  // Lot AN-H1: the operator's forget of a device presumed gone (guarded action android.device_forget), the restricted
  // requests of the unlink, of its forced end and of the adoption of an orphan enterprise (approval request types).
  registerAndroidForgetAction();
  registerAndroidOffboardingApprovals();
  registerAndroidAdoptionApprovals();
  // Lot AN-C1 (§4.8, §10.3): the ended enrollment tokens purged after 90 days by enrollment.purge-expired, with those of
  // lot C1 (whatever ANDROID_MODE: rows only, nothing at Google).
  registerEnrollmentPurgeSlice('android.enrollment_tokens', purgeEndedTokensSlice);
  setAndroidDeviceCounter(async (tenantId) => {
    const r = await db('android_devices').where({ tenant_id: tenantId }).whereNull('released_at').count<{ n: string }[]>('* as n');
    return Number(r[0]?.n ?? 0);
  });

  const cfg = androidConfig();
  if (cfg.mode === 'off') return;

  registerAndroidJobs();
  // Lot AN-C1 (§9.3): after each resolution of a tenant, the enrollment policies of its live Android profiles are sent
  // again (one stately job per profile; nothing pushed when the compiled policy did not change).
  registerTenantResolvedHook('android.enrollment-policies', (ctx, tenantId) => ctx.withTenant((trx) => requestEnrollmentPolicies(trx, tenantId)));
  // Lot AN-P (§11.4, COH-22): the Android handler of the freeze list (actions.edge-freeze-sync, the single queue of the
  // freeze): a freeze ends the running kiosk exits at once (the safest state first, AN-G1 correction), an unfreeze
  // submits again the commands it held. Nothing to propagate outside the instance: the gateway reads the freeze
  // before every destructive call (AN15). Idempotent (the job runs it again on a retry).
  registerFreezeHandler('android', async (tenantId, frozen) => {
    const actor: DbActor = currentDbContext()?.actor ?? { type: 'job', name: 'actions.edge-freeze-sync' };
    const n = frozen ? await endKioskExitsOnFreeze(tenantId, true, actor) : await resumeHeldCommands(tenantId, actor);
    return n > 0 ? 'done' : 'nothing';
  });
  // Lot AN-P (§4.8, COH-10): the purger of the channel amapi in the generic retention (privacy.retention-tenant): its
  // own policy deleted at Google, the device gone there, then its satellite; a tenant without an MDM key is not
  // skipped for these records. A device still at Google, or Google out of reach, waits for the next run.
  registerDevicePurger('amapi', {
    purge: async (ctx, deviceIds) => {
      const r = await purgeAndroidDevices(ctx.tenantId, deviceIds);
      return { purged: r.purged, deferred: r.kept.length, stopped: null };
    },
  });
  registerStartTask('android.google-check', async () => {
    freezeAndroidEventHandlers();
    await checkPinnedProject(cfg.projectId);
    try {
      const ok = await androidGateway().checkSubscription();
      if (!ok) void raiseAndroidPlatformAlert('android.google_auth_failed', { reason: 'subscription_permission' });
    } catch (err) {
      const kind = err instanceof AndroidError ? err.kind : 'error';
      logger.warn({ android: { start: 'degraded', kind } }, 'android: Google link degraded at start');
      void raiseAndroidPlatformAlert(kind === 'auth' ? 'android.google_auth_failed' : 'android.google_unreachable', { kind });
    }
    loop = new AndroidPullLoop();
    setHealthLoop(loop);
    await loop.start();
  });
  registerStopTask('android.pubsub-pull', async () => {
    await loop?.stop();
    loop = null;
    setHealthLoop(null);
  });
}

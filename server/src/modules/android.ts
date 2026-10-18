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

// =============================================================================
// ANDROID (Android Management API, called directly by the instance) — its hooks into the core's registries,
// registered here and only here, without I/O: the vault's instance secret name, the audit actions, the handlers of
// the notifications; the durable jobs, the start check of the Google identity and the pull loop only when
// ANDROID_MODE is not off (an instance without Android adds no queue, no statement at rest). index.ts calls it after
// registerAppleModule() and registerPrivacyModule() (lot AN-A2); until then only the testbed calls it.
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
  // Lot AN-D1: commands (section 11, §22.9): the sealed newPassword of RESET_PASSWORD (android_commands.secret_enc: a
  // command whose seal is lost is rejected, never sent without its password), the references of pending_actions
  // (mdm.reset_password carries {"$secret": "<uuid>"}, purpose android.reset_password), the COMMAND handler, the
  // guarded actions that exist only for Android and the final hook of the lost mode.
  registerSecretColumn({
    table: 'android_commands', column: 'secret_enc', pk: 'id', pkType: 'uuid', tenantColumn: 'tenant_id', encoding: 'utf8',
    owner: 'android.commands', onLoss: 'null', lossPatch: { state: 'rejected', reject_code: 'secret_lost', submit_state: 'failed', hold_reason: null },
  });
  registerSecretReferenceHolder({ table: 'pending_actions', column: 'params', tenantColumn: 'tenant_id', refs: (v) => findSecretRefs(typeof v === 'string' ? JSON.parse(v) : v) });
  registerCommandHandler();
  registerAndroidGuardedActions();
  // Lot AN-G1: the temporary exit of a kiosk (guarded action mdm.android_kiosk_exit, new restriction key).
  registerAndroidKioskActions();
  // Lot AN-H1: the operator's forget of a device presumed gone (guarded action android.device_forget), the restricted
  // requests of the unlink, of its forced end and of the adoption of an orphan enterprise (approval request types).
  registerAndroidForgetAction();
  registerAndroidOffboardingApprovals();
  registerAndroidAdoptionApprovals();
  setAndroidDeviceCounter(async (tenantId) => {
    const r = await db('android_devices').where({ tenant_id: tenantId }).whereNull('released_at').count<{ n: string }[]>('* as n');
    return Number(r[0]?.n ?? 0);
  });

  const cfg = androidConfig();
  if (cfg.mode === 'off') return;

  registerAndroidJobs();
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

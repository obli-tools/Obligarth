import { logger } from '../utils/logger';
import { registerStartTask, registerStopTask } from '../lifecycle';
import { registerInstanceSecretName } from '../vault';
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

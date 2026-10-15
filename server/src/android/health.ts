// Health of the Android link (GET /api/admin/android/health, platform administrators): mode, identity (fingerprint,
// never the key), last token, permission on the subscription, loop state, last pull, lag, breaker, limiter budget,
// pinned project. No tenant data (the per-tenant inbox lag comes with the platform screen of lot AN-C2).
import { asNone } from '../db/context';
import { androidConfig } from './config';
import { readPlatformState } from './enterprises/registry';
import { androidGateway } from './gateway';
import { projectBudget } from './gateway/limiter';
import type { AndroidPullLoop } from './link/pull';
import { androidMetrics } from './metrics';

let loop: AndroidPullLoop | null = null;
export function setHealthLoop(l: AndroidPullLoop | null): void { loop = l; }

export async function androidHealth() {
  const cfg = androidConfig();
  const gw = androidGateway();
  if (cfg.mode === 'off') return { mode: 'off' as const, loop: 'off' as const };
  const link = await gw.health();
  return asNone({ type: 'job', name: 'android.health' }, async () => {
    const state = await readPlatformState();
    const budget = await projectBudget({ projectPer100s: cfg.rateProjectPer100s });
    const loopStatus = loop?.status() ?? null;
    return {
      mode: cfg.mode,
      auth: cfg.auth,
      projectId: cfg.projectId,
      pinnedProjectId: state.pinned_project_id,
      identity: link.identity ? { configured: link.identity.configured, fingerprint: state.credential_fingerprint ?? link.identity.fingerprint,
        account: link.identity.account, lastTokenAt: link.identity.lastTokenAt, lastError: link.identity.lastError, setAt: state.credential_set_at } : null,
      subscriptionPermission: link.subscriptionPermission,
      breaker: link.breaker,
      loop: loopStatus ? (loopStatus.state === 'running' ? 'connected' : loopStatus.state) : 'unconfigured',
      lastPullAt: state.last_pull_at,
      lastAppliedPublishAt: state.last_applied_publish_at,
      lagSeconds: state.last_applied_publish_at ? Math.max(0, (Date.now() - new Date(state.last_applied_publish_at).getTime()) / 1000) : null,
      lastTestMessageAt: state.last_test_message_at,
      limiter: budget,
      metrics: androidMetrics.snapshot(),
    };
  });
}

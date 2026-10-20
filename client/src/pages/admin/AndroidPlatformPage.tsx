import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw, Smartphone } from 'lucide-react';
import type { AndroidQuotaView } from '@obligarth/shared';
import { androidPlatformApi, type AndroidPlatformHealth } from '@/api/android.api';
import { Button } from '@/components/common/Button';
import { PageContainer } from '@/components/common/PageContainer';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage } from '@/utils/apiError';
import { DeadLettersCard, KeyCard, OrphansCard } from './PlatformAndroidOperations';

// « Platform > Android » (android-amapi §12.1, minimal screen of lot AN-A2; platform administrators, master tenant):
// the identity of the instance at Google (mode, project, fingerprint of the service account key, never the key) and
// the health of the link (permission on the subscription, pull loop, lag, breaker, budget of the limiter), with the
// quota of the project. Lot AN-C2: the deposit of the key and its deadline, the orphan enterprises and their adoption,
// the dead letters of the inbox (PlatformAndroidOperations.tsx).

const dateOf = (v: string | null | undefined): string => (v ? formatDateTime(v) : '—');

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5 text-sm">
      <span className="text-text-muted">{label}</span>
      <span className="break-all text-right text-text-primary">{children}</span>
    </div>
  );
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="mb-2 text-sm font-semibold text-text-primary">{title}</h2>
      <div className="divide-y divide-border">{children}</div>
    </section>
  );
}

export function AndroidPlatformPage() {
  const { t } = useTranslation();
  const [health, setHealth] = useState<AndroidPlatformHealth | null>(null);
  const [quota, setQuota] = useState<AndroidQuotaView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, q] = await Promise.all([androidPlatformApi.health(), androidPlatformApi.quota()]);
      setHealth(h);
      setQuota(q);
    } catch (err) {
      setError(apiErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  const yesNo = (v: boolean | null | undefined): ReactNode => (v === null || v === undefined
    ? '—'
    : <StateBadge tone={v ? 'green' : 'red'} label={v ? (t('androidPlatform.yes') || 'Yes') : (t('androidPlatform.no') || 'No')} />);
  const loopTone = (s: string): 'green' | 'amber' | 'red' | 'gray' =>
    (s === 'connected' ? 'green' : s === 'off' || s === 'unconfigured' || s === 'stopped' ? 'gray' : s === 'degraded' ? 'red' : 'amber');
  const off = health?.mode === 'off';

  return (
    <PageContainer>
      <div className="mb-4 flex items-center gap-3">
        <Smartphone className="h-6 w-6 text-accent" />
        <div className="flex-1">
          <h1 className="text-xl font-semibold text-text-primary">{t('androidPlatform.title') || 'Platform · Android'}</h1>
          <p className="text-sm text-text-muted">
            {t('androidPlatform.description') || 'Identity of this instance at Google and health of the Android Management API link.'}
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => void load()} disabled={loading}>
          <RefreshCw className="mr-1 h-4 w-4" />{t('androidPlatform.refresh') || 'Refresh'}
        </Button>
      </div>

      {error && <p className="mb-4 rounded border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">{error}</p>}
      {loading && !health && <p className="text-sm text-text-muted">{t('androidPlatform.loading') || 'Loading…'}</p>}

      {health && (
        <div className="grid gap-4 md:grid-cols-2">
          <Card title={t('androidPlatform.identity.title') || 'Identity'}>
            <Row label={t('androidPlatform.identity.mode') || 'Mode'}>
              <StateBadge tone={off ? 'gray' : health.mode === 'google' ? 'green' : 'blue'} label={t(`androidPlatform.mode.${health.mode}`) || health.mode} />
            </Row>
            {off ? (
              <Row label={t('androidPlatform.identity.state') || 'State'}>
                {t('androidPlatform.offHint') || 'Android is turned off on this instance (ANDROID_MODE=off).'}
              </Row>
            ) : (
              <>
                <Row label={t('androidPlatform.identity.auth') || 'Google identity'}>
                  {health.auth ? (t(`androidPlatform.auth.${health.auth}`) || health.auth) : '—'}
                </Row>
                <Row label={t('androidPlatform.identity.project') || 'Project'}>{health.projectId ?? '—'}</Row>
                <Row label={t('androidPlatform.identity.pinnedProject') || 'Pinned project'}>{health.pinnedProjectId ?? '—'}</Row>
                <Row label={t('androidPlatform.identity.configured') || 'Identity configured'}>{yesNo(health.identity?.configured)}</Row>
                <Row label={t('androidPlatform.identity.fingerprint') || 'Key fingerprint'}>{health.identity?.fingerprint ?? '—'}</Row>
                <Row label={t('androidPlatform.identity.account') || 'Service account'}>{health.identity?.account ?? '—'}</Row>
                <Row label={t('androidPlatform.identity.setAt') || 'Key deposited'}>{dateOf(health.identity?.setAt)}</Row>
                <Row label={t('androidPlatform.identity.lastToken') || 'Last access token'}>{dateOf(health.identity?.lastTokenAt)}</Row>
                <Row label={t('androidPlatform.identity.lastError') || 'Last error'}>{health.identity?.lastError ?? '—'}</Row>
              </>
            )}
          </Card>

          <Card title={t('androidPlatform.health.title') || 'Health of the link'}>
            <Row label={t('androidPlatform.health.loop') || 'Pull loop'}>
              <StateBadge tone={loopTone(health.loop)} label={t(`androidPlatform.loop.${health.loop}`) || health.loop} />
            </Row>
            {!off && (
              <>
                <Row label={t('androidPlatform.health.subscription') || 'Permission on the subscription'}>{yesNo(health.subscriptionPermission)}</Row>
                <Row label={t('androidPlatform.health.lastPull') || 'Last pull'}>{dateOf(health.lastPullAt)}</Row>
                <Row label={t('androidPlatform.health.lag') || 'Lag'}>
                  {health.lagSeconds === null || health.lagSeconds === undefined ? '—' : `${Math.round(health.lagSeconds)} s`}
                </Row>
                <Row label={t('androidPlatform.health.lastTest') || 'Last test message'}>{dateOf(health.lastTestMessageAt)}</Row>
                <Row label={t('androidPlatform.health.breaker') || 'Circuit breaker'}>
                  {health.breaker ? (t(`androidPlatform.breaker.${health.breaker.state}`) || health.breaker.state) : '—'}
                </Row>
                <Row label={t('androidPlatform.health.limiter') || 'Budget of the project (100 s)'}>
                  {health.limiter ? `${Math.floor(health.limiter.tokens)} / ${health.limiter.capacity}` : '—'}
                </Row>
              </>
            )}
          </Card>

          {!off && health.auth === 'vault_key' && <KeyCard onDeposited={() => void load()} />}
          {quota && (
            <Card title={t('androidPlatform.quota.title') || 'Quota of the project'}>
              <Row label={t('androidPlatform.quota.devices') || 'Devices counted'}>{quota.count}</Row>
              <Row label={t('androidPlatform.quota.quota') || 'Quota granted'}>{quota.quota ?? (t('androidPlatform.quota.unknown') || 'not set')}</Row>
              <Row label={t('androidPlatform.quota.percent') || 'Used'}>{quota.percent === null ? '—' : `${quota.percent} %`}</Row>
              <Row label={t('androidPlatform.quota.lastRecount') || 'Last weekly recount'}>
                {quota.lastRecount ? `${dateOf(quota.lastRecount.at)} · ${t('androidPlatform.quota.gap') || 'gap'} ${quota.lastRecount.gap}` : '—'}
              </Row>
            </Card>
          )}
        </div>
      )}
      {health && !off && (
        <div className="mt-4 space-y-4">
          <OrphansCard />
          <DeadLettersCard />
        </div>
      )}
    </PageContainer>
  );
}

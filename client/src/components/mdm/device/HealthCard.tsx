import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { CheckCircle2, HeartPulse } from 'lucide-react';
import { complianceReasonLabel } from '@/components/mdm/DeviceStateBadges';
import { InfoCard } from '@/components/mdm/ui/InfoCard';
import { RingGauge, scoreTone, toneText } from '@/components/mdm/ui/Meter';
import { trCode } from '@/utils/apiError';
import type { DeviceHealth, HealthIssue, HealthIssueKey } from '@/utils/deviceHealth';

// The health of the device as the console derives it (utils/deviceHealth): the score and what lowers it, worst first.
// The card says it is computed here, not by the server.

const ISSUE_FALLBACK: Record<HealthIssueKey, string> = {
  nonCompliant: 'Not compliant', stale: 'No contact for too long', never: 'Never seen', quiet: 'Quiet for a while',
  configError: 'A configuration failed', configPending: 'Configuration pending', noPasscode: 'No passcode',
  storageFull: 'Storage almost full', batteryLow: 'Battery low', osUpdatePending: 'System update waiting',
  integrityRisk: 'Integrity at risk', adminInactive: 'Device administrator off', lostMode: 'In lost mode',
};
const DOT: Record<HealthIssue['severity'], string> = { red: 'bg-red-400', amber: 'bg-amber-400', info: 'bg-blue-400' };

export function HealthCard({ health, className }: { health: DeviceHealth; className?: string }) {
  const { t } = useTranslation();
  const issues = [...health.issues].sort((x, y) => (y.key === 'lostMode' ? 1 : 0) - (x.key === 'lostMode' ? 1 : 0) || y.penalty - x.penalty);
  const scoreText = health.score === null ? (t('deviceSummary.stats.unknown') || 'Unknown') : `${health.score} / 100`;
  return (
    <InfoCard icon={HeartPulse} title={t('deviceSummary.health.title') || 'Health'} className={className}
      action={<span className={clsx('text-sm font-semibold tabular-nums', toneText(scoreTone(health.score)))}>{scoreText}</span>}>
      <div className="flex items-start gap-4">
        <RingGauge value={health.score} size={72} label={scoreText} />
        <div className="min-w-0 flex-1">
          {issues.length === 0 ? (
            <p className="flex items-center gap-2 text-sm text-green-400">
              <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden />{t('deviceSummary.health.noIssue') || 'No issue found'}
            </p>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {issues.map((i) => (
                <li key={i.key} className="flex items-start gap-2">
                  <span className={clsx('mt-1.5 h-2 w-2 shrink-0 rounded-full', DOT[i.severity], i.key === 'lostMode' && 'animate-pulse')} aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="text-text-primary">{t(`deviceSummary.health.issue.${i.key}`) || ISSUE_FALLBACK[i.key]}</span>
                    {i.detail && <span className="ml-1.5 text-xs text-text-muted break-words">{i.detail}</span>}
                    {i.risks && i.risks.length > 0 && (
                      <span className="block text-xs text-text-muted">{i.risks.map((r) => trCode(`android.enums.securityRisk.${r}`, r)).join(' · ')}</span>
                    )}
                    {i.reasons && i.reasons.length > 0 && (
                      <span className="block text-xs text-text-muted">{i.reasons.map((r) => complianceReasonLabel(t, r)).join(' · ')}</span>
                    )}
                  </span>
                  {i.penalty > 0 && <span className="shrink-0 text-xs tabular-nums text-text-muted">−{i.penalty}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      <p className="mt-3 text-[11px] text-text-muted">{t('deviceSummary.health.derived') || 'Computed by the console from the states of the record; not stored.'}</p>
    </InfoCard>
  );
}

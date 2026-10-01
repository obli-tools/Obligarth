import { ShieldAlert, ShieldCheck, Lock, Clock } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { AuditChainStatus } from '@obligarth/shared';
import { cn } from '@/utils/cn';
import { when } from './auditLabels';

// State of a tenant's chain, above the journal: last verification, last
// seal, retention (and a decrease waiting for its 30 days), legal hold, and,
// for the platform administrators, how far behind the SIEM copy is.

export function AuditStatusBanner({ status }: { status: AuditChainStatus | null }) {
  const { t } = useTranslation();
  if (!status) return null;
  const v = status.lastVerification;
  const broken = v?.status === 'broken' || v?.status === 'error';
  const parts: string[] = [];
  if (v && v.status === 'ok') parts.push((t('audit.status.verifiedAt', { at: when(v.at) }) || `Chain verified on ${when(v.at)}`));
  else if (v && v.status === 'running') parts.push(t('audit.status.verifying') || 'Verification in progress');
  else if (!v) parts.push(t('audit.status.neverVerified') || 'Chain not verified yet');
  if (status.lastSeal) parts.push(t('audit.status.sealedAt', { at: when(status.lastSeal.sealedAt) }) || `last seal at ${when(status.lastSeal.sealedAt)}`);
  else parts.push(t('audit.status.notSealed') || 'not sealed yet');
  parts.push(t('audit.status.retention', { count: status.retention.effectiveMonths }) || `retention ${status.retention.effectiveMonths} months`);

  return (
    <div className={cn('mb-3 rounded border px-3 py-2 text-xs space-y-1',
      broken ? 'border-red-400/40 bg-red-400/10 text-red-300' : 'border-transparent bg-bg-secondary text-text-secondary')}>
      <div className="flex items-start gap-2">
        {broken ? <ShieldAlert className="w-4 h-4 shrink-0 text-red-400" /> : <ShieldCheck className="w-4 h-4 shrink-0 text-green-400" />}
        <span>
          {broken
            ? (t('audit.status.broken', { at: when(v?.at) }) || `Integrity check failed on ${when(v?.at)}: contact the platform administrators`)
            : parts.join(' · ')}
        </span>
      </div>
      {status.retention.pendingMonths !== null && status.retention.pendingEffectiveAt && (
        <div className="flex items-start gap-2 text-yellow-400">
          <Clock className="w-4 h-4 shrink-0" />
          <span>
            {t('audit.status.pendingDecrease', { count: status.retention.pendingMonths, at: when(status.retention.pendingEffectiveAt) })
              || `Retention lowered to ${status.retention.pendingMonths} months from ${when(status.retention.pendingEffectiveAt)}`}
          </span>
        </div>
      )}
      {status.retention.legalHoldUntil && (
        <div className="flex items-start gap-2 text-accent">
          <Lock className="w-4 h-4 shrink-0" />
          <span>
            {t('audit.status.legalHold', { at: when(status.retention.legalHoldUntil) }) || `Legal hold until ${when(status.retention.legalHoldUntil)}: nothing is purged`}
            {status.retention.legalHoldReason ? ` — ${status.retention.legalHoldReason}` : ''}
          </span>
        </div>
      )}
      {typeof status.exportLagSeconds === 'number' && status.exportLagSeconds > 900 && (
        <div className="flex items-start gap-2 text-yellow-400">
          <Clock className="w-4 h-4 shrink-0" />
          <span>{t('audit.status.exportLag', { minutes: Math.round(status.exportLagSeconds / 60) }) || `SIEM copy ${Math.round(status.exportLagSeconds / 60)} min behind`}</span>
        </div>
      )}
    </div>
  );
}

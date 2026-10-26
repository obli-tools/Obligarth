import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Settings2 } from 'lucide-react';
import type { CollectedField, DeviceDetail } from '@obligarth/shared';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import {
  enrollmentMethodLabel, formatDate, formatDateTime, managementModeLabel, ownershipLabel,
} from '@/components/mdm/PlatformIcon';
import { InfoCard, InfoRow, InfoRows } from '@/components/mdm/ui/InfoCard';
import { anonymize } from '@/utils/anonymize';
import { trCode } from '@/utils/apiError';

// How the device is managed and by whom: enrollment, mode, contact, compliance reasons, group, tenant, ownership, end
// user (the last three changeable), the Apple management identity and push; the privacy rules of its ownership folded
// under "Data collected".

const COLLECTED: CollectedField[] = ['serialNumber', 'hardwareIds', 'deviceName', 'phoneNumber', 'network', 'allApps', 'allCertificates'];
const COLLECTED_FALLBACK: Record<CollectedField, string> = {
  serialNumber: 'Serial number', hardwareIds: 'Hardware identifiers', deviceName: 'Device name', phoneNumber: 'Phone number',
  network: 'Network information', allApps: 'Every application', allCertificates: 'Every certificate',
};

function LinkButton({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return <button type="button" onClick={onClick} className="text-xs text-accent hover:underline coarse:min-h-9">{children}</button>;
}

export function ManagementCard({ device, tenantName, canChange, onGroup, onOwnership, onEndUser, className }: {
  device: DeviceDetail;
  tenantName: string;
  /** devices.manage and write access on the device. */
  canChange: boolean;
  onGroup: () => void;
  onOwnership: () => void;
  onEndUser: () => void;
  className?: string;
}) {
  const { t } = useTranslation();
  const managed = device.enrollmentState !== 'unenrolled';
  const collected = device.privacy?.collected ?? [];
  const apple = device.apple;
  const change = (onClick: () => void) => <LinkButton onClick={onClick}>{t('deviceSummary.change') || 'Change'}</LinkButton>;
  return (
    <InfoCard icon={Settings2} title={t('deviceSummary.cards.management') || 'Management'} className={className}>
      <InfoRows>
        <InfoRow label={t('deviceSummary.enrollmentMethod') || 'Enrollment'} value={enrollmentMethodLabel(t, device.enrollmentMethod)} />
        <InfoRow
          label={t('deviceSummary.managementMode') || 'Management mode'}
          value={`${managementModeLabel(t, device.managementMode)}${device.supervised ? ` · ${t('deviceSummary.supervised') || 'supervised'}` : ''}`}
        />
        <InfoRow label={t('deviceSummary.enrolledAt') || 'Enrolled'} value={formatDateTime(device.enrolledAt)} />
        <InfoRow label={t('deviceSummary.lastCheckin') || 'Last contact'} value={device.lastCheckinAt ? formatDateTime(device.lastCheckinAt) : (t('mdm.contactState.never') || 'Never seen')} />
        {device.unenrolledAt && (
          <InfoRow
            label={t('deviceSummary.unenrolledAt') || 'Left management'}
            value={`${formatDateTime(device.unenrolledAt)}${device.unenrollReason ? ` (${trCode(`mdm.unenrollReason.${device.unenrollReason}`, device.unenrollReason)})` : ''}`}
          />
        )}
        {device.complianceState === 'non_compliant' && device.complianceReasons.length > 0 && (
          <InfoRow
            label={t('deviceSummary.complianceReasons') || 'Non compliant because'}
            value={(
              <ul className="list-disc pl-4 text-red-400">
                {device.complianceReasons.map((r, i) => <li key={`${r.code}-${i}`}>{trCode(`mdm.complianceReason.${r.code}`, r.code)}</li>)}
              </ul>
            )}
          />
        )}
        <InfoRow
          label={t('deviceSummary.group') || 'Group'}
          value={(
            <span className="inline-flex flex-wrap items-center gap-2">
              {device.groupId != null ? (
                <Link to={`/group/${device.groupId}`} className="text-accent hover:underline">{anonymize(device.groupName) || `#${device.groupId}`}</Link>
              ) : (t('deviceSummary.ungrouped') || 'Ungrouped')}
              {canChange && change(onGroup)}
            </span>
          )}
        />
        <InfoRow label={t('deviceSummary.tenant') || 'Tenant'} value={tenantName} />
        <InfoRow
          label={t('deviceSummary.ownership') || 'Ownership'}
          value={(
            <span className="inline-flex flex-wrap items-center gap-2">
              {ownershipLabel(t, device.ownership)}
              {canChange && managed && device.managementMode === 'device' && device.ownership !== 'personal' && change(onOwnership)}
            </span>
          )}
        />
        <InfoRow
          label={t('deviceSummary.endUser') || 'End user'}
          value={(
            <span className="inline-flex flex-wrap items-center gap-2">
              {device.endUser ? anonymize(device.endUser.displayName || device.endUser.email || `#${device.endUser.id}`) : '—'}
              {canChange && change(onEndUser)}
            </span>
          )}
        />
        {apple && (
          <>
            <InfoRow
              label={t('deviceSummary.identity') || 'Management identity'}
              value={(
                <span className="inline-flex flex-wrap items-center gap-2">
                  <StateBadge
                    tone={apple.identityState === 'valid' ? 'green' : 'red'}
                    label={trCode(`mdm.identityState.${apple.identityState}`, apple.identityState)}
                    title={apple.certNotAfter ? formatDateTime(apple.certNotAfter) : undefined}
                  />
                  {apple.certNotAfter && <span className="text-[11px] text-text-muted">{t('deviceSummary.validUntil', { date: formatDate(apple.certNotAfter) }) || `until ${formatDate(apple.certNotAfter)}`}</span>}
                </span>
              )}
            />
            <InfoRow
              label={t('deviceSummary.push') || 'Push'}
              value={<StateBadge tone={apple.pushState === 'ready' ? 'green' : apple.pushState === 'unknown' ? 'gray' : 'red'} label={trCode(`mdm.pushState.${apple.pushState}`, apple.pushState)} />}
            />
            <InfoRow label={t('deviceSummary.lastInventory') || 'Last inventory'} value={formatDateTime(apple.lastInventory.deviceInfo)} />
          </>
        )}
      </InfoRows>
      <details className="mt-3 rounded-lg border border-border/60 px-3 py-2">
        <summary className="cursor-pointer select-none text-xs font-medium text-text-secondary hover:text-text-primary coarse:py-1.5">
          {t('deviceSummary.collectedToggle') || 'Data collected'} ({collected.length}/{COLLECTED.length})
        </summary>
        <div className="mt-2 flex flex-wrap gap-1">
          {COLLECTED.map((f) => (
            <span key={f} className={`px-1.5 py-0.5 rounded text-[11px] ${collected.includes(f) ? 'bg-accent/10 text-accent' : 'bg-bg-tertiary text-text-muted line-through'}`}>
              {t(`mdm.collected.${f}`) || COLLECTED_FALLBACK[f]}
            </span>
          ))}
        </div>
        <p className="mt-1.5 text-[11px] text-text-muted">{t('deviceSummary.collectedHint') || 'What is struck through is never collected for this ownership: it is absent, not empty.'}</p>
      </details>
    </InfoCard>
  );
}

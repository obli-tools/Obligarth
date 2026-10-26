import { useTranslation } from 'react-i18next';
import { ShieldCheck } from 'lucide-react';
import type { AndroidDeviceView, DeviceDetail, LegacyAgentDeviceDetail, ManagementChannel } from '@obligarth/shared';
import { InfoCard, InfoRow, InfoRows } from '@/components/mdm/ui/InfoCard';
import { trCode } from '@/utils/apiError';
import { androidAtRisk } from '@/utils/deviceHealth';
import { Flag } from './Flag';

// The security of the device, by channel. Apple: passcode (SecurityInfo, or the DDM status when newer), encryption,
// Find My, activation lock, unlock token, supervision, a system update waiting. Android Enterprise: patch level and
// posture. The bridge agent: Knox, device administrator, unknown sources, patch level.

export function SecurityCard({ device, channel, android, legacy, className }: {
  device: DeviceDetail;
  channel: ManagementChannel;
  /** undefined: loading; null: not readable. */
  android?: AndroidDeviceView | null;
  legacy?: LegacyAgentDeviceDetail | null;
  className?: string;
}) {
  const { t } = useTranslation();
  const apple = device.apple;
  const sec = apple?.security;
  const loading = <span className="text-text-muted italic">{t('common.loading') || 'Loading…'}</span>;

  // Data protection needs a passcode on iOS (hardware encryption is always there); FileVault on a Mac.
  const encryption: boolean | null = sec
    ? (sec.fdeEnabled !== undefined && sec.fdeEnabled !== null ? sec.fdeEnabled
      : sec.hardwareEncryptionCaps === null || sec.passcodePresent === null ? null
        : sec.hardwareEncryptionCaps > 0 && sec.passcodePresent)
    : null;
  const passcodeCompliant: boolean | null = sec
    ? (sec.passcodeCompliant === null ? null : sec.passcodeCompliant && sec.passcodeCompliantWithProfiles !== false)
    : null;

  return (
    <InfoCard icon={ShieldCheck} title={t('deviceSummary.security.title') || 'Security'} className={className}>
      <InfoRows>
        {apple && (
          <>
            <InfoRow label={t('deviceSummary.security.passcode') || 'Passcode'} value={<Flag value={sec?.passcodePresent} />} />
            <InfoRow label={t('deviceSummary.security.passcodeCompliant') || 'Passcode compliant'} value={<Flag value={passcodeCompliant} />} />
            <InfoRow label={t('deviceSummary.security.encryption') || 'Encryption'} value={<Flag value={encryption} />} />
            <InfoRow label={t('deviceSummary.security.findMy') || 'Find My'} value={<Flag value={apple.findMyEnabled} neutral />} />
            <InfoRow
              label={t('deviceSummary.security.activationLock') || 'Activation lock'}
              value={(
                <span className="inline-flex flex-wrap items-center gap-2">
                  <Flag value={apple.activationLockEnabled} neutral />
                  {apple.activationLockBypassEscrowed && <span className="text-[11px] text-text-muted">{t('deviceSummary.bypassEscrowed') || 'bypass code kept'}</span>}
                </span>
              )}
            />
            <InfoRow label={t('deviceSummary.security.unlockToken') || 'Unlock token'} value={<Flag value={apple.hasUnlockToken} />} />
            <InfoRow label={t('deviceSummary.security.supervision') || 'Supervision'} value={<Flag value={device.supervised} />} />
            {sec?.pendingOsVersion && (
              <InfoRow label={t('deviceSummary.security.pendingOs') || 'System update waiting'} value={<span className="text-amber-400">{sec.pendingOsVersion}</span>} />
            )}
          </>
        )}
        {channel === 'amapi' && (android === undefined ? <InfoRow label={t('deviceSummary.security.patch') || 'Security patch'} value={loading} /> : (
          <>
            <InfoRow label={t('deviceSummary.security.patch') || 'Security patch'} value={android?.securityPatchLevel ?? null} />
            <InfoRow
              label={t('deviceSummary.security.posture') || 'Security posture'}
              value={android?.posture?.devicePosture ? (
                <span className={androidAtRisk(android) ? 'text-red-400' : 'text-green-400'}>
                  {trCode(`android.enums.devicePosture.${android.posture.devicePosture}`, android.posture.devicePosture)}
                  {android.posture.risks.length > 0 && (
                    <span className="block text-xs text-amber-400">{android.posture.risks.map((r) => trCode(`android.enums.securityRisk.${r}`, r)).join(', ')}</span>
                  )}
                </span>
              ) : null}
            />
          </>
        ))}
        {channel === 'legacy_agent' && (legacy === undefined ? <InfoRow label={t('deviceSummary.security.knox') || 'Knox'} value={loading} /> : (
          <>
            <InfoRow label={t('deviceSummary.security.knox') || 'Knox'} value={legacy ? trCode(`legacyAgent.knox.${legacy.knoxState}`, legacy.knoxState) : null} />
            <InfoRow label={t('deviceSummary.security.adminActive') || 'Device administrator'} value={<Flag value={legacy?.adminActive} />} />
            <InfoRow label={t('deviceSummary.security.unknownSources') || 'Unknown sources allowed'} value={<Flag value={legacy?.unknownSources} good={false} />} />
            <InfoRow label={t('deviceSummary.security.patch') || 'Security patch'} value={legacy?.securityPatch ?? null} />
          </>
        ))}
      </InfoRows>
    </InfoCard>
  );
}

import { useTranslation } from 'react-i18next';
import { Smartphone, ShieldCheck, ShieldAlert, Trash2 } from 'lucide-react';
import type { DeviceKeyInfo, DeviceKeySecurityLevel } from '@obliance/shared';
import { cn } from '@/utils/cn';

// Phones registered for device-bound 2FA ("validation par empreinte",
// docs/mobile/device-bound-2fa.md §8): shared by the profile section and the
// administration dialog. Read-only rows + a Revoke button; enrolment happens
// in the Android app only.

export function DeviceKeyLevelBadge({ level }: { level: DeviceKeySecurityLevel }) {
  const { t } = useTranslation();
  const label = level === 'strongbox'
    ? t('deviceKeys.level.strongbox', 'Security chip (StrongBox)')
    : level === 'tee'
      ? t('deviceKeys.level.tee', 'Secure environment')
      : t('deviceKeys.level.unverified', 'Not verified');
  const unverified = level === 'unverified';
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full px-1.5 py-0.5 text-[10px] font-medium',
        unverified ? 'border border-amber-400/40 bg-amber-400/10 text-amber-300' : 'bg-green-500/10 text-green-400',
      )}
      title={unverified ? t('deviceKeys.list.unverifiedHint', 'This phone could not prove that its key is protected by hardware.') : undefined}
    >
      {unverified ? <ShieldAlert size={10} /> : <ShieldCheck size={10} />}
      {label}
    </span>
  );
}

/** Android security patch level 202609 → "2026-09" (YYYYMM or YYYYMMDD). */
function patchLabel(p: number | null): string | null {
  if (!p || !Number.isFinite(p)) return null;
  const s = String(p);
  if (s.length === 6) return `${s.slice(0, 4)}-${s.slice(4)}`;
  if (s.length === 8) return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6)}`;
  return s;
}

export function DeviceKeyList({
  keys, onRevoke, busyId,
}: {
  keys: DeviceKeyInfo[];
  onRevoke?: (key: DeviceKeyInfo) => void;
  /** Id of the key being revoked (its button shows as busy). */
  busyId?: string | null;
}) {
  const { t } = useTranslation();
  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '');

  if (keys.length === 0) {
    return <p className="text-sm text-text-muted italic">{t('deviceKeys.list.empty', 'No phone registered.')}</p>;
  }

  return (
    <div className="space-y-1.5">
      {keys.map((k) => {
        const patch = patchLabel(k.osPatchLevel);
        return (
          <div key={k.id} className="flex flex-wrap items-start gap-x-3 gap-y-1 rounded bg-bg-tertiary/30 px-3 py-2 text-xs">
            <Smartphone size={16} className="mt-0.5 shrink-0 text-text-muted" />
            <div className="min-w-0 flex-1 space-y-0.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="truncate font-medium text-text-primary">{k.label || t('deviceKeys.list.unnamed', 'Android phone')}</span>
                <DeviceKeyLevelBadge level={k.securityLevel} />
                {k.current && (
                  <span className="rounded-full bg-accent/10 px-1.5 py-0.5 text-[10px] font-medium text-accent">
                    {t('deviceKeys.list.thisSession', 'This session')}
                  </span>
                )}
              </div>
              <div className="text-text-muted">
                {t('deviceKeys.list.added', { date: fmt(k.createdAt), defaultValue: 'Added {{date}}' })}
                {patch && <> · {t('deviceKeys.list.patch', { patch, defaultValue: 'Security patch {{patch}}' })}</>}
              </div>
              <div className="text-text-muted">
                {k.lastUsedAt
                  ? (k.lastUsedIp
                    ? t('deviceKeys.list.lastUsed', { date: fmt(k.lastUsedAt), ip: k.lastUsedIp, defaultValue: 'Last used {{date}} from {{ip}}' })
                    : t('deviceKeys.list.lastUsedNoIp', { date: fmt(k.lastUsedAt), defaultValue: 'Last used {{date}}' }))
                  : t('deviceKeys.list.neverUsed', 'Never used')}
                {' · '}
                {t('deviceKeys.list.uses', { count: k.useCount, defaultValue: '{{count}} uses' })}
              </div>
            </div>
            {onRevoke && (
              <button
                type="button"
                onClick={() => onRevoke(k)}
                disabled={busyId === k.id}
                className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-red-400 hover:bg-red-400/10 hover:text-red-300 disabled:opacity-50 coarse:px-3 coarse:py-2"
              >
                <Trash2 size={12} />
                {t('deviceKeys.list.revoke', 'Revoke')}
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}

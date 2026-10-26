import { useTranslation } from 'react-i18next';
import { Smartphone } from 'lucide-react';
import type { AndroidDeviceView, DeviceDetail } from '@obligarth/shared';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { dayIsPast, formatDay, osLabel } from '@/components/mdm/PlatformIcon';
import { InfoCard, InfoRow, InfoRows } from '@/components/mdm/ui/InfoCard';

// The device as hardware and as an asset: model, system, maker (Android Enterprise), description and tags, purchase,
// warranty (green while it runs, red once over), life cycle, age and expected lifetime.

/** Whole months from a calendar day (YYYY-MM-DD) to today; null if not a day or in the future. */
function monthsSince(ymd: string | null | undefined): number | null {
  const m = typeof ymd === 'string' ? /^(\d{4})-(\d{2})-(\d{2})/.exec(ymd) : null;
  if (!m) return null;
  const now = new Date();
  let months = (now.getFullYear() - Number(m[1])) * 12 + (now.getMonth() + 1 - Number(m[2]));
  if (now.getDate() < Number(m[3])) months -= 1;
  return months >= 0 ? months : null;
}

export function HardwareAssetCard({ device, android, className }: { device: DeviceDetail; android?: AndroidDeviceView | null; className?: string }) {
  const { t } = useTranslation();
  const asset = device.asset;
  const age = monthsSince(asset.purchaseDate);
  const warrantyOver = asset.warrantyExpiry ? dayIsPast(asset.warrantyExpiry) : null;
  const maker = android?.hardware ? [android.hardware.manufacturer, android.hardware.brand].filter((x, i, all) => !!x && all.indexOf(x) === i).join(' · ') : '';
  return (
    <InfoCard icon={Smartphone} title={t('deviceSummary.asset.title') || 'Hardware and asset'} className={className}>
      <InfoRows>
        <InfoRow label={t('deviceSummary.model') || 'Model'} value={[device.modelName, device.model].filter(Boolean).join(' · ') || null} />
        {maker && <InfoRow label={t('deviceSummary.asset.maker') || 'Maker'} value={maker} />}
        <InfoRow label={t('deviceSummary.os') || 'Operating system'} value={`${osLabel(device.platform, device.osVersion)}${device.osBuild ? ` (${device.osBuild})` : ''}`} />
        {device.description && <InfoRow label={t('common.description') || 'Description'} value={device.description} />}
        {device.tags.length > 0 && (
          <InfoRow
            label={t('devices.filters.tagsLabel') || 'Tags'}
            value={<span className="flex flex-wrap gap-1">{device.tags.map((tag) => <span key={tag} className="px-1.5 py-0.5 rounded-full bg-accent/10 text-accent text-[11px]">{tag}</span>)}</span>}
          />
        )}
        {asset.purchaseDate && <InfoRow label={t('deviceSummary.asset.purchase') || 'Purchased'} value={formatDay(asset.purchaseDate)} />}
        {(asset.warrantyExpiry || asset.warrantyVendor || asset.warrantyStatus) && (
          <InfoRow
            label={t('deviceSummary.warranty') || 'Warranty'}
            value={(
              <span className="inline-flex flex-wrap items-center gap-2">
                {warrantyOver !== null && (
                  <StateBadge
                    tone={warrantyOver ? 'red' : 'green'}
                    label={warrantyOver ? (t('deviceSummary.asset.warrantyExpired') || 'Expired') : (t('deviceSummary.asset.warrantyActive') || 'Under warranty')}
                  />
                )}
                {asset.warrantyExpiry && <span>{formatDay(asset.warrantyExpiry)}</span>}
                {asset.warrantyVendor && <span className="text-text-muted">{asset.warrantyVendor}</span>}
                {asset.warrantyStatus && <span className="text-xs text-text-muted">{asset.warrantyStatus}</span>}
              </span>
            )}
          />
        )}
        {asset.lifecycleStatus && <InfoRow label={t('deviceSummary.asset.lifecycle') || 'Life cycle'} value={asset.lifecycleStatus} />}
        {age !== null && (
          <InfoRow
            label={t('deviceSummary.asset.age') || 'Age'}
            value={(
              <span className={asset.expectedLifetimeYears && age >= asset.expectedLifetimeYears * 12 ? 'text-amber-400' : undefined}>
                {t('deviceSummary.asset.ageValue', { years: Math.floor(age / 12), months: age % 12 }) || `${Math.floor(age / 12)} y ${age % 12} m`}
              </span>
            )}
          />
        )}
        {asset.expectedLifetimeYears && (
          <InfoRow
            label={t('deviceSummary.asset.lifetime') || 'Expected lifetime'}
            value={t('deviceSummary.asset.lifetimeValue', { count: asset.expectedLifetimeYears }) || `${asset.expectedLifetimeYears} years`}
          />
        )}
      </InfoRows>
    </InfoCard>
  );
}

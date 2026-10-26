import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Fingerprint } from 'lucide-react';
import type { DeviceDetail, LegacyAgentDeviceDetail } from '@obligarth/shared';
import { InfoCard, InfoRow, InfoRows } from '@/components/mdm/ui/InfoCard';
import { anonymize } from '@/utils/anonymize';

// The identifiers of the device, each copyable: serial number, UDID, IMEI, EID, model number, name on the device; the
// Android ID and the Samsung serial of the bridge agent. A field the privacy rules never collect is absent.

export function IdentifiersCard({ device, legacy, className }: { device: DeviceDetail; legacy?: LegacyAgentDeviceDetail | null; className?: string }) {
  const { t } = useTranslation();
  const apple = device.apple;
  const rows: ReactNode[] = [];
  const add = (key: string, label: string, value: string | null | undefined, mono = true) => {
    if (value === undefined) return;
    rows.push(<InfoRow key={key} label={label} value={value ? anonymize(value) : null} copy={value || undefined} mono={mono} />);
  };
  add('serial', t('deviceSummary.serial') || 'Serial number', device.serialNumber);
  add('udid', t('deviceSummary.ids.udid') || 'UDID', apple?.udid);
  const imeis = apple?.imei ? [apple.imei] : legacy?.imeis?.length ? legacy.imeis : apple && apple.imei !== undefined ? null : undefined;
  if (imeis !== undefined) add('imei', t('deviceSummary.ids.imei') || 'IMEI', imeis ? imeis.join(', ') : null);
  add('eid', t('deviceSummary.ids.eid') || 'EID', apple?.info?.eid);
  add('modelNumber', t('deviceSummary.ids.modelNumber') || 'Model number', apple?.info?.modelNumber);
  add('deviceName', t('deviceSummary.deviceName') || 'Name on the device', device.deviceName, false);
  if (legacy) {
    add('androidId', t('deviceSummary.ids.androidId') || 'Android ID', legacy.androidId);
    add('samsungSerial', t('deviceSummary.ids.samsungSerial') || 'Samsung serial', legacy.samsungSerial);
  }
  if (rows.length === 0) return null;
  return (
    <InfoCard icon={Fingerprint} title={t('deviceSummary.ids.title') || 'Identifiers'} className={className}>
      <InfoRows>{rows}</InfoRows>
    </InfoCard>
  );
}

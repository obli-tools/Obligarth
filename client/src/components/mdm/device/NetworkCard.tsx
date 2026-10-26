import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Signal } from 'lucide-react';
import type { AndroidDeviceView, CollectedField, DeviceDetail, LegacyAgentDeviceDetail, ManagementChannel } from '@obligarth/shared';
import { InfoCard, InfoRow, InfoRows } from '@/components/mdm/ui/InfoCard';
import { anonymize } from '@/utils/anonymize';
import { trCode } from '@/utils/apiError';
import { Flag } from './Flag';

// Network and cellular: carrier, roaming, phone number, ICCID, Wi-Fi and Bluetooth addresses (Apple DeviceInformation,
// as the privacy rules of the device let them through: a field never collected is absent, not empty), the operator
// (Android Enterprise), the connection and address the bridge agent reports. Hidden when there is nothing to show.

const statusValue = (legacy: LegacyAgentDeviceDetail | null | undefined, item: string): unknown =>
  legacy?.status.find((s) => s.item === item)?.value;

export function NetworkCard({ device, channel, android, legacy, className }: {
  device: DeviceDetail;
  channel: ManagementChannel;
  android?: AndroidDeviceView | null;
  legacy?: LegacyAgentDeviceDetail | null;
  className?: string;
}) {
  const { t } = useTranslation();
  const info = device.apple?.info;
  const rows: ReactNode[] = [];
  const text = (key: string, label: string, value: string | null | undefined, opts: { copy?: boolean; mono?: boolean } = {}) => {
    if (value === undefined) return;
    rows.push(<InfoRow key={key} label={label} value={value ? anonymize(value) : null} copy={opts.copy && value ? value : undefined} mono={opts.mono} />);
  };
  if (info) {
    text('carrier', t('deviceSummary.network.carrier') || 'Carrier', info.carrier);
    text('subscriberCarrier', t('deviceSummary.network.subscriberCarrier') || 'Subscriber carrier', info.subscriberCarrier);
    if (info.roaming !== undefined) rows.push(<InfoRow key="roaming" label={t('deviceSummary.network.roaming') || 'Roaming'} value={<Flag value={info.roaming} neutral />} />);
    text('phoneNumber', t('deviceSummary.network.phoneNumber') || 'Phone number', info.phoneNumber, { copy: true });
    text('iccid', t('deviceSummary.network.iccid') || 'ICCID', info.iccid, { copy: true, mono: true });
    text('wifiMac', t('deviceSummary.network.wifiMac') || 'Wi-Fi address', info.wifiMac, { copy: true, mono: true });
    text('bluetoothMac', t('deviceSummary.network.bluetoothMac') || 'Bluetooth address', info.bluetoothMac, { copy: true, mono: true });
  }
  if (channel === 'amapi' && android?.network) text('operator', t('deviceSummary.network.operator') || 'Operator', android.network.operatorName);
  if (channel === 'legacy_agent' && legacy) {
    const type = statusValue(legacy, 'agent.network.type');
    const ip = statusValue(legacy, 'agent.network.ip');
    // The agent's tokens (wifi, cellular, none…) translated; an unknown one as reported. Not an identifier: not masked.
    if (type !== undefined) {
      rows.push(<InfoRow key="connection" label={t('deviceSummary.network.connection') || 'Connection'}
        value={typeof type === 'string' && type ? trCode(`deviceSummary.network.type.${type}`, type) : null} />);
    }
    if (ip !== undefined) text('ip', t('deviceSummary.network.ip') || 'IP address', typeof ip === 'string' ? ip : null, { copy: true, mono: true });
  }
  if (rows.length === 0) return null;

  // What the privacy rules of this ownership leave out (Apple and Android Enterprise collect by these rules).
  const collected = device.privacy?.collected ?? [];
  const missing = channel === 'legacy_agent' ? [] : (['network', 'phoneNumber'] as CollectedField[]).filter((f) => !collected.includes(f));
  return (
    <InfoCard icon={Signal} title={t('deviceSummary.network.title') || 'Network'} className={className}>
      <InfoRows>{rows}</InfoRows>
      {missing.length > 0 && (
        <p className="mt-2 text-[11px] text-text-muted">
          {t('deviceSummary.network.notCollected', { fields: missing.map((f) => t(`mdm.collected.${f}`) || f).join(', ') })
            || `Not collected for this ownership: ${missing.join(', ')}`}
        </p>
      )}
    </InfoCard>
  );
}

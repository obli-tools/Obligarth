import { useEffect, useState } from 'react';
import type { AndroidDeviceView, DeviceDetail, LegacyAgentDeviceDetail } from '@obligarth/shared';
import { androidApi } from '@/api/android.api';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { DeviceRetirementCard } from '@/components/mdm/DeviceRetirementCard';
import { deviceHealth } from '@/utils/deviceHealth';
import { DdmCard } from './DdmCard';
import { HardwareAssetCard } from './HardwareAssetCard';
import { HealthCard } from './HealthCard';
import { IdentifiersCard } from './IdentifiersCard';
import { LocationCard } from './LocationCard';
import { LostDevicePanel } from './LostDevicePanel';
import { ManagementCard } from './ManagementCard';
import { NetworkCard } from './NetworkCard';
import { SecurityCard } from './SecurityCard';
import { StatTiles } from './StatTiles';
import type { DeviceActions } from './useDeviceActions';

// The overview of a device record: four figures, then the cards — health, the lost device panel and the location,
// security, management, hardware and asset, identifiers, network, declarative management and retirement (Apple).
// One column on a phone, two from md, three from xl. The Android Enterprise view and the bridge agent's record are
// read here, once, for the cards that need them.

export const LOCATION_ANCHOR = 'device-location';

export function DeviceOverview({
  device, tenantName, actions, canWrite, canManageDevices, canSyncDdm, onGroup, onOwnership, onEndUser, locationReveal, onLocationRevealed,
}: {
  device: DeviceDetail;
  tenantName: string;
  actions: DeviceActions;
  canWrite: boolean;
  canManageDevices: boolean;
  /** The DDM synchronisation is offered (write access, the device in the current tenant). */
  canSyncDdm: boolean;
  onGroup: () => void;
  onOwnership: () => void;
  onEndUser: () => void;
  /** A request of the lost mode banner to show the positions (a timestamp; 0: none). */
  locationReveal?: number;
  onLocationRevealed?: () => void;
}) {
  const channel = actions.channel;
  // undefined: loading; null: not readable (another tenant, the integration off).
  const [android, setAndroid] = useState<AndroidDeviceView | null | undefined>(undefined);
  const [legacy, setLegacy] = useState<LegacyAgentDeviceDetail | null | undefined>(undefined);
  const lastCheckinAt = device.lastCheckinAt;
  useEffect(() => {
    let cancelled = false;
    if (channel === 'amapi') androidApi.device(device.id).then((v) => { if (!cancelled) setAndroid(v); }).catch(() => { if (!cancelled) setAndroid(null); });
    if (channel === 'legacy_agent') legacyAgentApi.device(device.id).then((v) => { if (!cancelled) setLegacy(v); }).catch(() => { if (!cancelled) setLegacy(null); });
    return () => { cancelled = true; };
  }, [device.id, channel, lastCheckinAt]);

  const managed = device.enrollmentState !== 'unenrolled';
  const apple = device.apple;
  const health = deviceHealth(device, { android, legacy });
  const storageFree = legacy?.status.find((s) => s.item === 'agent.storage.free')?.value;

  return (
    <div className="space-y-4">
      <StatTiles device={device} health={health} agentStorageFree={typeof storageFree === 'number' ? storageFree : null} />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <HealthCard health={health} />
        {managed && <LostDevicePanel device={device} actions={actions} className="md:col-span-2 xl:col-span-2" />}
        {/* The agent asks for no location permission (agent-pont-android, AndroidFacts): no card, the panel says why. */}
        {channel !== 'legacy_agent' && (
          <LocationCard
            id={LOCATION_ANCHOR}
            device={device}
            locate={actions.actions.locate}
            reveal={locationReveal}
            onRevealed={onLocationRevealed}
            className="scroll-mt-20"
          />
        )}
        <SecurityCard device={device} channel={channel} android={android} legacy={legacy} />
        <ManagementCard
          device={device}
          tenantName={tenantName}
          canChange={canManageDevices && canWrite}
          onGroup={onGroup}
          onOwnership={onOwnership}
          onEndUser={onEndUser}
        />
        <HardwareAssetCard device={device} android={android} />
        <IdentifiersCard device={device} legacy={legacy} />
        <NetworkCard device={device} channel={channel} android={android} legacy={legacy} />
        {apple && <DdmCard deviceId={device.id} enabled={apple.ddmEnabled} canSync={canSyncDdm} />}
        {apple && <DeviceRetirementCard deviceId={device.id} canAct={canWrite} isApple />}
      </div>
    </div>
  );
}

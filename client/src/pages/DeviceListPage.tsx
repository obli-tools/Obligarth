import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DevicesPageLayout } from '@/components/devices/DevicesPageLayout';
import type { InitialDeviceFilters } from '@/components/devices/DeviceTable';

// The inventory (modele-donnees-mdm §11.3). A link may land on a filtered list: the cards of the dashboard
// (?state=, ?contact=stale, ?compliance=non_compliant, ?config=error, ?platform=ios), the end users
// (?endUserId=), the groups (?groupId=).
export function DeviceListPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const groupIdParam = searchParams.get('groupId');
  const initialGroupId = groupIdParam ? parseInt(groupIdParam, 10) : null;
  const key = searchParams.toString();
  const initialFilters = useMemo((): InitialDeviceFilters => {
    const p = new URLSearchParams(key);
    const endUser = Number.parseInt(p.get('endUserId') ?? '', 10);
    return {
      state: p.get('state') || undefined,
      contact: p.get('contact') || undefined,
      compliance: p.get('compliance') || undefined,
      config: p.get('config') || undefined,
      platform: p.get('platform') || undefined,
      ownership: p.get('ownership') || undefined,
      endUserId: Number.isInteger(endUser) && endUser > 0 ? endUser : undefined,
    };
  }, [key]);

  return (
    <DevicesPageLayout
      initialFilters={initialFilters}
      initialGroupId={Number.isInteger(initialGroupId) ? initialGroupId : null}
      onGroupChange={(gid) => {
        setSearchParams((prev) => {
          const next = new URLSearchParams(prev);
          if (gid == null) next.delete('groupId');
          else next.set('groupId', String(gid));
          return next;
        }, { replace: true });
      }}
    />
  );
}

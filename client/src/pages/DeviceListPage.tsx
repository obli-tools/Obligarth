import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DevicesPageLayout } from '@/components/devices/DevicesPageLayout';
import type { InitialDeviceFilters } from '@/components/devices/DeviceTable';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// The inventory (modele-donnees-mdm §11.3). A link may land on a filtered list: the cards of the dashboard
// (?state=, ?contact=stale, ?compliance=non_compliant, ?config=error, ?platform=ios, ?lost=1), the end users
// (?endUserId=), the groups (?groupId=), a saved view (?view=<uuid>, P0-5).
export function DeviceListPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const groupIdParam = searchParams.get('groupId');
  const initialGroupId = groupIdParam ? parseInt(groupIdParam, 10) : null;
  const viewParam = searchParams.get('view');
  const initialViewUuid = viewParam && UUID_RE.test(viewParam) ? viewParam.toLowerCase() : null;
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
      lost: p.get('lost') === '1' || p.get('lost') === 'true' ? true : undefined,
    };
  }, [key]);

  // One parameter of the link changed, from the current address (two changes in a row, the group and the view of a
  // saved view, both land).
  const setParam = useCallback((name: string, value: string | null) => {
    setSearchParams(() => {
      const next = new URLSearchParams(window.location.search);
      if (value == null) next.delete(name);
      else next.set(name, value);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  return (
    <DevicesPageLayout
      initialFilters={initialFilters}
      initialGroupId={Number.isInteger(initialGroupId) ? initialGroupId : null}
      onGroupChange={(gid) => setParam('groupId', gid == null ? null : String(gid))}
      initialViewUuid={initialViewUuid}
      onViewChange={(uuid) => {
        if ((new URLSearchParams(window.location.search).get('view') ?? null) !== uuid) setParam('view', uuid);
      }}
    />
  );
}

import { useEffect, useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Activity, ArrowLeft, Building2, Clock, FolderOpen, Monitor, RefreshCw } from 'lucide-react';
import { deviceApi } from '@/api/device.api';
import { useDeviceStore } from '@/store/deviceStore';
import { useTenantStore } from '@/store/tenantStore';
import { DeviceStatusBadge } from '@/components/devices/DeviceStatusBadge';
import { OsIcon } from '@/components/devices/OsIcon';
import { PageContainer } from '@/components/common/PageContainer';
import { anonymize } from '@/utils/anonymize';

// Minimal device record, built from the device registry only (name, OS,
// group, status, tenant). Placeholder until the MDM device page.
export function DeviceSummaryPage() {
  const { id } = useParams<{ id: string }>();
  const deviceId = Number.parseInt(id ?? '', 10);
  const validId = Number.isInteger(deviceId) && deviceId > 0;
  const { t } = useTranslation();
  const fetchDevice = useDeviceStore((s) => s.fetchDevice);
  // Selector: the store is kept live by the device socket events.
  const device = useDeviceStore((s) => (validId ? s.devices.get(deviceId) : undefined));
  const tenants = useTenantStore((s) => s.tenants);
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const [isLoading, setIsLoading] = useState(validId);
  const [tenantSwitchTarget, setTenantSwitchTarget] = useState<string | null>(null);

  // Runs again after a tenant change, so that the load is retried under the
  // tenant it switched to.
  useEffect(() => {
    if (!validId) {
      setIsLoading(false);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setIsLoading(true);
      setTenantSwitchTarget(null);
      const found = await fetchDevice(deviceId);
      if (cancelled) return;
      if (found) {
        setIsLoading(false);
        return;
      }
      // Not visible under the current tenant (shared link, alert opened from
      // another tenant): the server names its tenant only when the caller has
      // access to it, then the page switches there silently. AppLayout keeps
      // the URL across that switch (skipTenantSwitchRedirect).
      const located = await deviceApi.locate(deviceId);
      if (cancelled) return;
      if (located && located.currentTenantId !== located.tenantId) {
        setTenantSwitchTarget(located.tenantName);
        sessionStorage.setItem('skipTenantSwitchRedirect', '1');
        await useTenantStore.getState().setCurrentTenant(located.tenantId);
        // A refused switch leaves the tenant unchanged: no re-run, so stop
        // here with "not found".
        if (!cancelled && useTenantStore.getState().currentTenantId !== located.tenantId) {
          sessionStorage.removeItem('skipTenantSwitchRedirect');
          setTenantSwitchTarget(null);
          setIsLoading(false);
        }
        return;
      }
      setIsLoading(false);
    };
    void load();
    return () => { cancelled = true; };
  }, [deviceId, validId, fetchDevice, currentTenantId]);

  const backLink = (
    <Link
      to="/devices"
      className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary coarse:min-h-10"
    >
      <ArrowLeft size={14} className="shrink-0" />
      {t('deviceSummary.back') || 'Back to devices'}
    </Link>
  );

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <RefreshCw className="w-6 h-6 animate-spin text-text-muted" />
        {tenantSwitchTarget && (
          <p className="text-sm text-text-muted">
            {t('deviceSummary.switchingTenant', { tenant: tenantSwitchTarget }) || `Switching to ${tenantSwitchTarget}…`}
          </p>
        )}
      </div>
    );
  }

  if (!device) {
    return (
      <PageContainer className="space-y-4 text-center">
        <p className="text-text-muted">{t('deviceSummary.notFound') || 'Device not found'}</p>
        {backLink}
      </PageContainer>
    );
  }

  const name = anonymize(device.displayName || device.hostname);
  const hostname = anonymize(device.hostname);
  const os = [device.osName || device.osType, device.osVersion].filter(Boolean).join(' ');
  const tenantName = device.tenantName
    ?? tenants.find((tn) => tn.id === device.tenantId)?.name
    ?? `#${device.tenantId}`;

  return (
    <PageContainer className="space-y-6">
      {backLink}

      <div className="flex items-center gap-3 min-w-0">
        <OsIcon osType={device.osType} className="w-6 h-6 shrink-0 text-text-muted" />
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold text-text-primary truncate">{name}</h1>
          {device.displayName && device.displayName !== device.hostname && (
            <p className="text-sm text-text-muted truncate">{hostname}</p>
          )}
        </div>
      </div>

      <dl className="rounded-lg bg-bg-secondary divide-y divide-border">
        <Field icon={<Monitor size={15} />} label={t('deviceSummary.os') || 'Operating system'}>
          {os || '—'}
        </Field>
        <Field icon={<FolderOpen size={15} />} label={t('deviceSummary.group') || 'Group'}>
          {device.groupId != null ? (
            <Link to={`/group/${device.groupId}`} className="text-accent hover:underline">
              {anonymize(device.groupName) || `#${device.groupId}`}
            </Link>
          ) : (
            t('deviceSummary.ungrouped') || 'Ungrouped'
          )}
        </Field>
        <Field icon={<Activity size={15} />} label={t('deviceSummary.status') || 'Status'}>
          <DeviceStatusBadge status={device.status} approvalStatus={device.approvalStatus} size="sm" />
        </Field>
        <Field icon={<Clock size={15} />} label={t('deviceSummary.lastSeen') || 'Last seen'}>
          {device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : (t('common.never') || 'Never')}
        </Field>
        <Field icon={<Building2 size={15} />} label={t('deviceSummary.tenant') || 'Tenant'}>
          {tenantName}
        </Field>
      </dl>
    </PageContainer>
  );
}

function Field({ icon, label, children }: { icon: ReactNode; label: string; children: ReactNode }) {
  return (
    <div className="flex items-center gap-3 px-4 py-3 max-sm:flex-col max-sm:items-start max-sm:gap-1">
      <dt className="flex items-center gap-2 w-48 shrink-0 text-sm text-text-muted max-sm:w-auto">
        <span className="shrink-0">{icon}</span>
        {label}
      </dt>
      <dd className="min-w-0 text-sm text-text-primary break-words">{children}</dd>
    </div>
  );
}

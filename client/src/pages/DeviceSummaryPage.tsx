import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  ArrowLeft, Briefcase, Building2, FolderOpen, History, KeyRound, LayoutGrid, Package, Pencil, RefreshCw,
  ScrollText, SlidersHorizontal, TerminalSquare, User, Zap,
} from 'lucide-react';
import type { CollectedField, DeviceDeclarationsView, DeviceDetail, DeviceStatusItemView, EndUser } from '@obligarth/shared';
import { SocketEvents } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { appleApi } from '@/api/apple.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { registerSocketListener } from '@/socket/socketListeners';
import { PageContainer } from '@/components/common/PageContainer';
import { SegmentedTabs, type SegmentedTab } from '@/components/common/SegmentedTabs';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { GroupTreePicker } from '@/components/devices/GroupTreePicker';
import { DeviceStateBadges, StateBadge } from '@/components/mdm/DeviceStateBadges';
import {
  PlatformIcon, enrollmentMethodLabel, formatBytes, formatDate, formatDateTime, managementModeLabel, osLabel, ownershipLabel,
} from '@/components/mdm/PlatformIcon';
import { DeviceConfigurationTab } from '@/components/mdm/DeviceConfigurationTab';
import { DeviceAppsTab, DeviceCertificatesTab, DeviceProfilesTab } from '@/components/mdm/DeviceInventoryTabs';
import { DeviceActionsTab, DeviceCommandsTab } from '@/components/mdm/DeviceCommands';
import { DeviceHistoryTab } from '@/components/mdm/DeviceHistoryTab';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The record of a device (modele-donnees-mdm §11.3): overview (states, ownership and privacy rules, end user,
// hardware, identity, push, declarative management), effective configuration, applications, profiles,
// certificates, commands (the queue of the integration), history (episodes and timeline), actions.

type Tab = 'overview' | 'configuration' | 'apps' | 'profiles' | 'certificates' | 'commands' | 'history' | 'actions';
const TABS: Tab[] = ['overview', 'configuration', 'apps', 'profiles', 'certificates', 'commands', 'history', 'actions'];

const COLLECTED: CollectedField[] = ['serialNumber', 'hardwareIds', 'deviceName', 'phoneNumber', 'network', 'allApps', 'allCertificates'];
const COLLECTED_FALLBACK: Record<CollectedField, string> = {
  serialNumber: 'Serial number', hardwareIds: 'Hardware identifiers', deviceName: 'Device name', phoneNumber: 'Phone number',
  network: 'Network information', allApps: 'Every application', allCertificates: 'Every certificate',
};

export function DeviceSummaryPage() {
  const { id } = useParams<{ id: string }>();
  const deviceId = Number.parseInt(id ?? '', 10);
  const validId = Number.isInteger(deviceId) && deviceId > 0;
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const tenants = useTenantStore((s) => s.tenants);
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const { isAdmin, canWriteDevice, permissions } = useAuthStore();
  const caps = permissions?.tenantCapabilities ?? [];
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [isLoading, setIsLoading] = useState(validId);
  const [tenantSwitchTarget, setTenantSwitchTarget] = useState<string | null>(null);
  const asked = searchParams.get('tab') as Tab | null;
  const [tab, setTabState] = useState<Tab>(asked && TABS.includes(asked) ? asked : 'overview');
  const setTab = (next: Tab) => {
    setTabState(next);
    setSearchParams((prev) => { const p = new URLSearchParams(prev); p.set('tab', next); return p; }, { replace: true });
  };
  const [editOpen, setEditOpen] = useState(false);
  const [groupOpen, setGroupOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const [ownershipOpen, setOwnershipOpen] = useState(false);

  const reload = useCallback(async (): Promise<DeviceDetail | null> => {
    try {
      const d = await mdmApi.getDevice(deviceId);
      setDevice(d);
      return d;
    } catch {
      return null;
    }
  }, [deviceId]);

  // Runs again after a tenant change, so that the load is retried under the tenant it switched to.
  useEffect(() => {
    if (!validId) { setIsLoading(false); return; }
    let cancelled = false;
    const load = async () => {
      setIsLoading(true);
      setTenantSwitchTarget(null);
      setDevice(null);
      const found = await reload();
      if (cancelled) return;
      if (found) { setIsLoading(false); return; }
      // Not visible under the current tenant (shared link, alert opened from another tenant): the server names
      // its tenant only when the caller has access to it, then the page switches there. AppLayout keeps the URL
      // across that switch (skipTenantSwitchRedirect).
      const located = await mdmApi.locate(deviceId);
      if (cancelled) return;
      if (located && located.currentTenantId !== located.tenantId) {
        setTenantSwitchTarget(located.tenantName);
        sessionStorage.setItem('skipTenantSwitchRedirect', '1');
        await useTenantStore.getState().setCurrentTenant(located.tenantId);
        // A refused switch leaves the tenant unchanged: no re-run, so stop here with "not found".
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
  }, [deviceId, validId, reload, currentTenantId]);

  // Live: the registry or the Apple satellite of this device changed.
  useEffect(() => {
    const onChange = (p: { deviceId?: number; deviceIds?: number[] }) => {
      const ids = Array.isArray(p?.deviceIds) ? p.deviceIds.map(Number) : p?.deviceId !== undefined ? [Number(p.deviceId)] : null;
      if (ids === null || ids.includes(deviceId)) void reload();
    };
    const offs = [SocketEvents.DEVICE_UPDATED, SocketEvents.APPLE_DEVICE_CHANGED, SocketEvents.DEVICE_CONFIG_CHANGED]
      .map((ev) => registerSocketListener(ev, onChange));
    return () => offs.forEach((off) => off());
  }, [deviceId, reload]);

  const backLink = (
    <Link to="/devices" className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary coarse:min-h-10">
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

  const canWrite = canWriteDevice(device.id, device.groupId);
  const canManageDevices = isAdmin() || caps.includes('devices.manage');
  const canManagePolicies = isAdmin() || caps.includes('mdm.policies.manage');
  const managed = device.enrollmentState !== 'unenrolled';
  const collected = device.privacy?.collected ?? [];
  const tenantName = device.tenantName ?? tenants.find((tn) => tn.id === device.tenantId)?.name ?? `#${device.tenantId}`;
  const apple = device.apple;
  const tabs: SegmentedTab<Tab>[] = [
    { id: 'overview', label: t('deviceSummary.tabs.overview') || 'Overview', icon: <LayoutGrid size={15} /> },
    { id: 'configuration', label: t('deviceSummary.tabs.configuration') || 'Configuration', icon: <SlidersHorizontal size={15} /> },
    { id: 'apps', label: t('deviceSummary.tabs.apps') || 'Applications', icon: <Package size={15} /> },
    { id: 'profiles', label: t('deviceSummary.tabs.profiles') || 'Profiles', icon: <ScrollText size={15} /> },
    { id: 'certificates', label: t('deviceSummary.tabs.certificates') || 'Certificates', icon: <KeyRound size={15} /> },
    { id: 'commands', label: t('deviceSummary.tabs.commands') || 'Commands', icon: <TerminalSquare size={15} /> },
    { id: 'history', label: t('deviceSummary.tabs.history') || 'History', icon: <History size={15} /> },
    { id: 'actions', label: t('deviceSummary.tabs.actions') || 'Actions', icon: <Zap size={15} /> },
  ];

  return (
    <PageContainer className="space-y-5">
      {backLink}

      <div className="flex flex-wrap items-start gap-3">
        <PlatformIcon platform={device.platform} className="w-7 h-7 shrink-0 text-text-muted mt-1" />
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold text-text-primary break-words">{anonymize(device.label)}</h1>
          <p className="text-sm text-text-muted">
            {[osLabel(device.platform, device.osVersion), device.modelName || device.model, tenantName].filter(Boolean).join(' · ')}
          </p>
          <div className="mt-2"><DeviceStateBadges device={device} size="md" all={managed} /></div>
        </div>
        {canWrite && (
          <Button variant="secondary" size="sm" onClick={() => setEditOpen(true)}>
            <Pencil size={14} className="mr-1.5" />{t('common.edit') || 'Edit'}
          </Button>
        )}
      </div>

      <SegmentedTabs tabs={tabs} value={tab} onChange={setTab} ariaLabel={t('deviceSummary.tabs.label') || 'Sections of the device'} />

      {tab === 'overview' && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title={t('deviceSummary.cards.management') || 'Management'}>
            <Field label={t('deviceSummary.enrollmentMethod') || 'Enrollment'}>{enrollmentMethodLabel(t, device.enrollmentMethod)}</Field>
            <Field label={t('deviceSummary.managementMode') || 'Management mode'}>
              {managementModeLabel(t, device.managementMode)}{device.supervised ? ` · ${t('deviceSummary.supervised') || 'supervised'}` : ''}
            </Field>
            <Field label={t('deviceSummary.enrolledAt') || 'Enrolled'}>{formatDateTime(device.enrolledAt)}</Field>
            <Field label={t('deviceSummary.lastCheckin') || 'Last contact'}>{device.lastCheckinAt ? formatDateTime(device.lastCheckinAt) : (t('mdm.contactState.never') || 'Never seen')}</Field>
            {device.unenrolledAt && (
              <Field label={t('deviceSummary.unenrolledAt') || 'Left management'}>
                {formatDateTime(device.unenrolledAt)}{device.unenrollReason ? ` (${trCode(`mdm.unenrollReason.${device.unenrollReason}`, device.unenrollReason)})` : ''}
              </Field>
            )}
            {device.complianceState === 'non_compliant' && device.complianceReasons.length > 0 && (
              <Field label={t('deviceSummary.complianceReasons') || 'Non compliant because'}>
                <ul className="list-disc pl-4">
                  {device.complianceReasons.map((r, i) => <li key={`${r.code}-${i}`}>{trCode(`mdm.complianceReason.${r.code}`, r.code)}</li>)}
                </ul>
              </Field>
            )}
            <Field label={t('deviceSummary.group') || 'Group'} icon={<FolderOpen size={14} />}>
              <span className="inline-flex flex-wrap items-center gap-2">
                {device.groupId != null ? (
                  <Link to={`/group/${device.groupId}`} className="text-accent hover:underline">{anonymize(device.groupName) || `#${device.groupId}`}</Link>
                ) : (t('deviceSummary.ungrouped') || 'Ungrouped')}
                {canManageDevices && canWrite && <LinkButton onClick={() => setGroupOpen(true)}>{t('deviceSummary.change') || 'Change'}</LinkButton>}
              </span>
            </Field>
            <Field label={t('deviceSummary.tenant') || 'Tenant'} icon={<Building2 size={14} />}>{tenantName}</Field>
          </Card>

          <Card title={t('deviceSummary.cards.ownership') || 'Ownership and privacy'}>
            <Field label={t('deviceSummary.ownership') || 'Ownership'} icon={<Briefcase size={14} />}>
              <span className="inline-flex flex-wrap items-center gap-2">
                {ownershipLabel(t, device.ownership)}
                {canManageDevices && canWrite && managed && device.managementMode === 'device' && device.ownership !== 'personal' && (
                  <LinkButton onClick={() => setOwnershipOpen(true)}>{t('deviceSummary.change') || 'Change'}</LinkButton>
                )}
              </span>
            </Field>
            <Field label={t('deviceSummary.collected') || 'Collected on this device'}>
              <span className="flex flex-wrap gap-1">
                {COLLECTED.map((f) => (
                  <span key={f} className={`px-1.5 py-0.5 rounded text-[11px] ${collected.includes(f) ? 'bg-accent/10 text-accent' : 'bg-bg-tertiary text-text-muted line-through'}`}>
                    {t(`mdm.collected.${f}`) || COLLECTED_FALLBACK[f]}
                  </span>
                ))}
              </span>
              <span className="mt-1 block text-[11px] text-text-muted">{t('deviceSummary.collectedHint') || 'What is struck through is never collected for this ownership: it is absent, not empty.'}</span>
            </Field>
            <Field label={t('deviceSummary.endUser') || 'End user'} icon={<User size={14} />}>
              <span className="inline-flex flex-wrap items-center gap-2">
                {device.endUser ? anonymize(device.endUser.displayName || device.endUser.email || `#${device.endUser.id}`) : '—'}
                {canManageDevices && canWrite && <LinkButton onClick={() => setUserOpen(true)}>{t('deviceSummary.change') || 'Change'}</LinkButton>}
              </span>
            </Field>
          </Card>

          <Card title={t('deviceSummary.cards.hardware') || 'Hardware'}>
            <Field label={t('deviceSummary.model') || 'Model'}>{[device.modelName, device.model].filter(Boolean).join(' · ') || '—'}</Field>
            <Field label={t('deviceSummary.os') || 'Operating system'}>{osLabel(device.platform, device.osVersion)}{device.osBuild ? ` (${device.osBuild})` : ''}</Field>
            {device.serialNumber !== undefined && <Field label={t('deviceSummary.serial') || 'Serial number'}><span className="font-mono">{anonymize(device.serialNumber) || '—'}</span></Field>}
            {device.deviceName !== undefined && <Field label={t('deviceSummary.deviceName') || 'Name on the device'}>{anonymize(device.deviceName) || '—'}</Field>}
            <Field label={t('deviceSummary.storage') || 'Storage'}>
              {device.storageCapacityBytes ? `${formatBytes(device.storageAvailableBytes)} ${t('deviceSummary.storageFree') || 'free of'} ${formatBytes(device.storageCapacityBytes)}` : '—'}
            </Field>
            {device.description && <Field label={t('common.description') || 'Description'}>{device.description}</Field>}
            {device.tags.length > 0 && (
              <Field label={t('devices.filters.tagsLabel') || 'Tags'}>
                <span className="flex flex-wrap gap-1">{device.tags.map((tag) => <span key={tag} className="px-1.5 py-0.5 rounded-full bg-accent/10 text-accent text-[11px]">{tag}</span>)}</span>
              </Field>
            )}
            {(device.asset.warrantyExpiry || device.asset.purchaseDate) && (
              <Field label={t('deviceSummary.warranty') || 'Warranty'}>
                {[device.asset.warrantyVendor, device.asset.warrantyExpiry && formatDate(device.asset.warrantyExpiry)].filter(Boolean).join(' · ') || '—'}
              </Field>
            )}
          </Card>

          {apple && (
            <Card title={t('deviceSummary.cards.identity') || 'Identity and push'}>
              <Field label={t('deviceSummary.identity') || 'Management identity'}>
                <StateBadge
                  tone={apple.identityState === 'valid' ? 'green' : 'red'}
                  label={trCode(`mdm.identityState.${apple.identityState}`, apple.identityState)}
                  title={apple.certNotAfter ? formatDateTime(apple.certNotAfter) : undefined}
                />
                {apple.certNotAfter && <span className="ml-2 text-[11px] text-text-muted">{t('deviceSummary.validUntil', { date: formatDate(apple.certNotAfter) }) || `until ${formatDate(apple.certNotAfter)}`}</span>}
              </Field>
              <Field label={t('deviceSummary.push') || 'Push'}>
                <StateBadge tone={apple.pushState === 'ready' ? 'green' : apple.pushState === 'unknown' ? 'gray' : 'red'} label={trCode(`mdm.pushState.${apple.pushState}`, apple.pushState)} />
              </Field>
              {apple.udid !== undefined && <Field label="UDID"><span className="font-mono break-all">{anonymize(apple.udid) || '—'}</span></Field>}
              {apple.imei !== undefined && apple.imei && <Field label="IMEI"><span className="font-mono">{anonymize(apple.imei)}</span></Field>}
              <Field label={t('deviceSummary.activationLock') || 'Activation lock'}>
                {apple.activationLockEnabled === null ? '—' : apple.activationLockEnabled ? (t('common.enable') || 'Enabled') : (t('common.disable') || 'Disabled')}
                {apple.activationLockBypassEscrowed && <span className="ml-2 text-[11px] text-text-muted">{t('deviceSummary.bypassEscrowed') || 'bypass code kept'}</span>}
              </Field>
              <Field label={t('deviceSummary.unlockToken') || 'Unlock token'}>
                {apple.hasUnlockToken ? (t('deviceSummary.present') || 'Present') : (t('deviceSummary.absent') || 'Absent')}
              </Field>
              <Field label={t('deviceSummary.lastInventory') || 'Last inventory'}>{formatDateTime(apple.lastInventory.deviceInfo)}</Field>
            </Card>
          )}

          {apple && <DdmCard deviceId={device.id} enabled={apple.ddmEnabled} canSync={canWrite} />}
        </div>
      )}

      {tab === 'configuration' && <DeviceConfigurationTab deviceId={device.id} groupId={device.groupId} canManagePolicies={canManagePolicies && canWrite} />}
      {tab === 'apps' && <DeviceAppsTab deviceId={device.id} collected={collected} lastAt={apple?.lastInventory.apps} />}
      {tab === 'profiles' && <DeviceProfilesTab deviceId={device.id} lastAt={apple?.lastInventory.profiles} />}
      {tab === 'certificates' && <DeviceCertificatesTab deviceId={device.id} collected={collected} lastAt={apple?.lastInventory.certificates} />}
      {tab === 'commands' && <DeviceCommandsTab deviceId={device.id} canAct={canWrite} />}
      {tab === 'history' && <DeviceHistoryTab deviceId={device.id} />}
      {tab === 'actions' && <DeviceActionsTab deviceId={device.id} managed={managed} canAct={canWrite} onQueued={() => { void reload(); }} />}

      <EditDeviceDialog open={editOpen} onClose={() => setEditOpen(false)} device={device} onSaved={setDevice} />
      <GroupDialog open={groupOpen} onClose={() => setGroupOpen(false)} device={device} onDone={() => { void reload(); }} />
      <EndUserDialog open={userOpen} onClose={() => setUserOpen(false)} device={device} onDone={() => { void reload(); }} />
      <OwnershipDialog open={ownershipOpen} onClose={() => setOwnershipOpen(false)} device={device} onDone={() => { void reload(); }} />
    </PageContainer>
  );
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg bg-bg-secondary">
      <h2 className="px-4 pt-3 pb-1 text-xs font-semibold uppercase tracking-wider text-text-muted">{title}</h2>
      <dl className="divide-y divide-border/50">{children}</dl>
    </section>
  );
}

function Field({ icon, label, children }: { icon?: ReactNode; label: string; children: ReactNode }) {
  return (
    <div className="flex items-start gap-3 px-4 py-2.5 max-sm:flex-col max-sm:gap-1">
      <dt className="flex items-center gap-2 w-44 shrink-0 text-sm text-text-muted max-sm:w-auto">
        {icon && <span className="shrink-0">{icon}</span>}
        {label}
      </dt>
      <dd className="min-w-0 flex-1 text-sm text-text-primary break-words">{children}</dd>
    </div>
  );
}

function LinkButton({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return <button type="button" onClick={onClick} className="text-xs text-accent hover:underline coarse:min-h-9">{children}</button>;
}

const inputCls = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';

/** Declarative management: the set the engine serves, what the device reported, the status items. */
function DdmCard({ deviceId, enabled, canSync }: { deviceId: number; enabled: boolean; canSync: boolean }) {
  const { t } = useTranslation();
  const [view, setView] = useState<DeviceDeclarationsView | null>(null);
  const [items, setItems] = useState<DeviceStatusItemView[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => {
    // 503 when the integration is off: the card then shows the satellite's flag alone.
    appleApi.declarations(deviceId).then(setView).catch(() => setView(null));
    appleApi.statusItems(deviceId).then(setItems).catch(() => setItems([]));
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);
  const sync = async () => {
    setBusy(true);
    try {
      const r = await appleApi.ddmSync(deviceId);
      toast.success(r.requested
        ? (t('deviceSummary.ddm.syncRequested') || 'Synchronisation requested')
        : (t('deviceSummary.ddm.syncAlready') || 'A synchronisation was already requested within the minute'));
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const inSync = view ? !!view.declarationsToken && view.declarationsToken === view.fetchedToken : null;
  const invalid = view?.declarations.filter((d) => d.status?.valid === 'invalid').length ?? 0;
  return (
    <Card title={t('deviceSummary.cards.ddm') || 'Declarative management'}>
      <Field label={t('common.status') || 'Status'}>
        <span className="inline-flex flex-wrap items-center gap-2">
          <StateBadge tone={enabled ? 'green' : 'gray'} label={enabled ? (t('deviceSummary.ddm.enabled') || 'Enabled') : (t('deviceSummary.ddm.disabled') || 'Not enabled')} />
          {view && inSync !== null && (
            <StateBadge
              tone={inSync ? 'green' : view.syncOpen ? 'blue' : 'amber'}
              label={inSync ? (t('deviceSummary.ddm.inSync') || 'In sync') : view.syncOpen ? (t('deviceSummary.ddm.syncing') || 'Synchronising') : (t('deviceSummary.ddm.outOfSync') || 'Not fetched yet')}
            />
          )}
          {canSync && enabled && <Button size="sm" variant="secondary" loading={busy} onClick={sync}>{t('deviceSummary.ddm.sync') || 'Synchronise'}</Button>}
        </span>
      </Field>
      {view && (
        <Field label={t('deviceSummary.ddm.declarations') || 'Declarations'}>
          {view.declarations.length}
          {invalid > 0 && <span className="ml-2 text-red-400">{t('deviceSummary.ddm.invalid', { count: invalid }) || `${invalid} invalid`}</span>}
          {view.fetchedAt && <span className="ml-2 text-[11px] text-text-muted">{t('deviceSummary.ddm.fetchedAt', { at: formatDateTime(view.fetchedAt) }) || `fetched ${formatDateTime(view.fetchedAt)}`}</span>}
          {view.declarations.length > 0 && (
            <ul className="mt-1 space-y-0.5 text-[11px]">
              {view.declarations.slice(0, open ? 200 : 5).map((d) => (
                <li key={d.identifier} className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono break-all text-text-secondary">{d.identifier}</span>
                  <span className={d.status === null ? 'text-text-muted' : d.status.valid === 'invalid' ? 'text-red-400' : d.status.active ? 'text-green-400' : 'text-text-muted'}>
                    {d.status === null ? (t('deviceSummary.ddm.notReported') || 'not reported yet')
                      : d.status.valid === 'invalid' ? (t('deviceSummary.ddm.invalidOne') || 'invalid')
                        : d.status.active ? (t('deviceSummary.ddm.active') || 'active') : (t('deviceSummary.ddm.inactive') || 'inactive')}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Field>
      )}
      {items.length > 0 && (
        <Field label={t('deviceSummary.ddm.statusItems') || 'Status items'}>
          <ul className="space-y-0.5 text-[11px]">
            {items.slice(0, open ? 200 : 6).map((i) => (
              <li key={i.item} className="flex flex-wrap gap-1.5">
                <span className="text-text-secondary">{trCode(i.i18nKey, i.item)}</span>
                <span className="font-mono break-all text-text-primary">{typeof i.value === 'object' ? JSON.stringify(i.value).slice(0, 80) : String(i.value)}</span>
              </li>
            ))}
          </ul>
        </Field>
      )}
      {((view?.declarations.length ?? 0) > 5 || items.length > 6) && (
        <div className="px-4 py-2">
          <LinkButton onClick={() => setOpen(!open)}>{open ? (t('approvals.showLess') || 'Show less') : (t('approvals.showMore') || 'Show more')}</LinkButton>
        </div>
      )}
    </Card>
  );
}

/** The operator's fields of a record: name, description, tags. */
function EditDeviceDialog({ open, onClose, device, onSaved }: { open: boolean; onClose: () => void; device: DeviceDetail; onSaved: (d: DeviceDetail) => void }) {
  const { t } = useTranslation();
  const [displayName, setDisplayName] = useState('');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!open) return;
    setDisplayName(device.displayName ?? '');
    setDescription(device.description ?? '');
    setTags(device.tags.join(', '));
  }, [open, device]);
  const save = async () => {
    setBusy(true);
    try {
      const saved = await mdmApi.updateDevice(device.id, {
        displayName: displayName.trim() || null,
        description: description.trim() || null,
        tags: [...new Set(tags.split(',').map((x) => x.trim()).filter(Boolean))].slice(0, 50),
      });
      onSaved(saved);
      toast.success(t('common.saved') || 'Saved');
      onClose();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      size="md"
      title={t('deviceSummary.edit.title') || 'Edit the record'}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={save} loading={busy}>{t('common.save') || 'Save'}</Button>
        </>
      )}
    >
      <div className="space-y-3 text-sm">
        <label className="block">
          <span className="text-xs text-text-muted">{t('deviceSummary.edit.displayName') || 'Display name (replaces the name reported by the device)'}</span>
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={500} className={inputCls} />
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('common.description') || 'Description'}</span>
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} maxLength={10000} className={inputCls} />
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('deviceSummary.edit.tags') || 'Tags (comma-separated)'}</span>
          <input value={tags} onChange={(e) => setTags(e.target.value)} className={inputCls} autoCapitalize="off" />
        </label>
      </div>
    </Modal>
  );
}

function GroupDialog({ open, onClose, device, onDone }: { open: boolean; onClose: () => void; device: DeviceDetail; onDone: () => void }) {
  const { t } = useTranslation();
  const [groupId, setGroupId] = useState<number | null>(device.groupId);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) setGroupId(device.groupId); }, [open, device.groupId]);
  const save = async () => {
    setBusy(true);
    try {
      await mdmApi.setGroup(device.id, groupId);
      toast.success(t('devices.batch.groupChanged', { count: 1 }) || 'Moved 1 device');
      onDone();
      onClose();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      size="sm"
      title={t('deviceSummary.groupDialog.title') || 'Change the group'}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={save} loading={busy} disabled={groupId === device.groupId}>{t('devices.batch.moveHere') || 'Move'}</Button>
        </>
      )}
    >
      <p className="mb-2 text-xs text-amber-400">
        {t('devices.batch.changeGroupPolicies') || 'The devices then receive the policies assigned to their new group, and lose those of the group they leave.'}
      </p>
      <GroupTreePicker value={groupId} onChange={(id) => setGroupId(id)} />
    </Modal>
  );
}

function EndUserDialog({ open, onClose, device, onDone }: { open: boolean; onClose: () => void; device: DeviceDetail; onDone: () => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  const [users, setUsers] = useState<EndUser[]>([]);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    const timer = setTimeout(() => {
      mdmApi.listEndUsers({ status: 'active', q: q.trim() || undefined, pageSize: 20 })
        .then((r) => { if (!cancelled) setUsers(r.items); }).catch(() => { if (!cancelled) setUsers([]); });
    }, 200);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [open, q]);
  const assign = async (endUserId: number | null) => {
    setBusy(true);
    try {
      await mdmApi.setEndUser(device.id, endUserId);
      toast.success(t('common.saved') || 'Saved');
      onDone();
      onClose();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      size="sm"
      title={t('deviceSummary.endUserDialog.title') || 'End user of the device'}
      footer={(
        <>
          {device.endUser && <Button variant="secondary" className="mr-auto" disabled={busy} onClick={() => assign(null)}>{t('deviceSummary.endUserDialog.unassign') || 'Unassign'}</Button>}
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
        </>
      )}
    >
      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('common.search') || 'Search'} className={inputCls} autoCapitalize="off" spellCheck={false} />
      <ul className="mt-2 max-h-64 overflow-auto rounded border border-border text-sm">
        {users.map((u) => (
          <li key={u.id}>
            <button type="button" disabled={busy} onClick={() => assign(u.id)}
              className={`w-full text-left px-2 py-1.5 hover:bg-bg-tertiary coarse:py-2.5 ${device.endUser?.id === u.id ? 'bg-accent/10' : ''}`}>
              <span className="text-text-primary">{anonymize(u.displayName || u.email || u.managedAppleAccount || u.externalId || `#${u.id}`)}</span>
              {u.email && u.displayName && <span className="ml-2 text-xs text-text-muted">{anonymize(u.email)}</span>}
            </button>
          </li>
        ))}
        {users.length === 0 && <li className="px-2 py-3 text-text-muted">{t('endUsers.none') || 'No end user.'}</li>}
      </ul>
    </Modal>
  );
}

/** Between corporate and corporate, personally enabled (modele-donnees-mdm §4.3): a reason, a ticket to widen the
 *  collection; a second approver by default. Any other change is a new enrollment. */
function OwnershipDialog({ open, onClose, device, onDone }: { open: boolean; onClose: () => void; device: DeviceDetail; onDone: () => void }) {
  const { t } = useTranslation();
  const to = device.ownership === 'corporate' ? 'corporate_personal' : 'corporate';
  const [reason, setReason] = useState('');
  const [ticket, setTicket] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) { setReason(''); setTicket(''); } }, [open]);
  const widening = to === 'corporate';
  const ok = reason.trim().length > 0 && (!widening || ticket.trim().length > 0);
  const save = async () => {
    setBusy(true);
    try {
      const r = await mdmApi.changeOwnership(device.id, { to, reason: reason.trim(), ticket: ticket.trim() || null });
      if (r === null) toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
      else toast.success(t('deviceSummary.ownershipDialog.done') || 'Ownership changed');
      onDone();
      onClose();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      size="md"
      title={t('deviceSummary.ownershipDialog.title') || 'Change the ownership'}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={save} loading={busy} disabled={!ok}>{t('common.confirm') || 'Confirm'}</Button>
        </>
      )}
    >
      <div className="space-y-3 text-sm">
        <p className="text-text-secondary">
          {ownershipLabel(t, device.ownership)} → <span className="font-medium text-text-primary">{ownershipLabel(t, to)}</span>
        </p>
        <p className="text-xs text-amber-400">
          {widening
            ? (t('deviceSummary.ownershipDialog.widen') || 'More data will be collected on this device (every application, the phone number…): a ticket is required.')
            : (t('deviceSummary.ownershipDialog.narrow') || 'Less data will be collected: what is no longer collected is erased from the record.')}
        </p>
        <label className="block">
          <span className="text-xs text-text-muted">{t('guard.dialog.reason') || 'Reason (required)'}</span>
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} maxLength={500} className={inputCls} />
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{widening ? (t('deviceSummary.ownershipDialog.ticketRequired') || 'Ticket number (required)') : (t('guard.dialog.ticket') || 'Ticket number (optional)')}</span>
          <input value={ticket} onChange={(e) => setTicket(e.target.value)} maxLength={100} className={inputCls} autoCapitalize="off" spellCheck={false} />
        </label>
      </div>
    </Modal>
  );
}

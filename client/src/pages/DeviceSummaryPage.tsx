import { useCallback, useEffect, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  ArrowLeft, History, KeyRound, LayoutGrid, Package, ScrollText, SlidersHorizontal, Smartphone, TerminalSquare, Zap,
} from 'lucide-react';
import type { DeviceDetail, EndUser, ManagementChannel } from '@obligarth/shared';
import { SocketEvents } from '@obligarth/shared';
import { useDeviceMove } from '@/components/mdm/DeviceMoveChange';
import { mdmApi } from '@/api/mdm.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { registerSocketListener } from '@/socket/socketListeners';
import { PageContainer } from '@/components/common/PageContainer';
import { SegmentedTabs, type SegmentedTab } from '@/components/common/SegmentedTabs';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { GroupTreePicker } from '@/components/devices/GroupTreePicker';
import { ownershipLabel } from '@/components/mdm/PlatformIcon';
import { DeviceConfigurationTab } from '@/components/mdm/DeviceConfigurationTab';
import { DeviceAppsTab, DeviceCertificatesTab, DeviceProfilesTab } from '@/components/mdm/DeviceInventoryTabs';
import { DeviceActionsTab, DeviceCommandsTab } from '@/components/mdm/DeviceCommands';
import { AndroidDeviceActions, AndroidDeviceTab } from '@/components/android/AndroidDeviceTab';
import { DeviceHistoryTab } from '@/components/mdm/DeviceHistoryTab';
import { DeviceHero } from '@/components/mdm/device/DeviceHero';
import { DeviceOverview, LOCATION_ANCHOR } from '@/components/mdm/device/DeviceOverview';
import { LegacyActionsTab, LegacyCommandsTab } from '@/components/mdm/device/LegacyActionsTab';
import { LostModeBanner } from '@/components/mdm/device/LostModeBanner';
import { channelOf, useDeviceActions } from '@/components/mdm/device/useDeviceActions';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage } from '@/utils/apiError';

// The record of a device (modele-donnees-mdm §11.3): a header with its states and the quick actions of a lost or
// stolen device, the lost mode banner, then the tabs of its channel — the overview (figures, health, lost device panel,
// location, security, management, hardware, identifiers, network, declarative management), the Android Enterprise
// view, applications, configuration, profiles, certificates, commands (the queue of the channel), history, actions.

type Tab = 'overview' | 'android' | 'configuration' | 'apps' | 'profiles' | 'certificates' | 'commands' | 'history' | 'actions';
const TABS: Tab[] = ['overview', 'android', 'configuration', 'apps', 'profiles', 'certificates', 'commands', 'history', 'actions'];
/** The tabs of each channel, in their order. */
const CHANNEL_TABS: Record<ManagementChannel, Tab[]> = {
  apple_mdm: ['overview', 'apps', 'configuration', 'profiles', 'certificates', 'commands', 'history', 'actions'],
  amapi: ['overview', 'android', 'apps', 'configuration', 'commands', 'history', 'actions'],
  legacy_agent: ['overview', 'apps', 'commands', 'history', 'actions'],
};

/** The shape of the record while it loads: header, figures, cards (no spinner in the middle of the page). */
function DeviceSkeleton({ note }: { note?: string | null }) {
  const block = 'animate-pulse rounded-xl border border-border bg-bg-secondary';
  return (
    <PageContainer className="space-y-5" aria-busy>
      <div className="h-5 w-32 animate-pulse rounded bg-bg-secondary" />
      <div className={`${block} p-4 sm:p-5`}>
        <div className="flex items-start gap-4">
          <div className="h-12 w-12 shrink-0 rounded-xl bg-bg-tertiary sm:h-14 sm:w-14" />
          <div className="flex-1 space-y-2">
            <div className="h-6 w-1/2 rounded bg-bg-tertiary" />
            <div className="h-4 w-2/3 rounded bg-bg-tertiary" />
            <div className="h-4 w-1/3 rounded bg-bg-tertiary" />
          </div>
        </div>
      </div>
      {note && <p className="text-center text-sm text-text-muted">{note}</p>}
      <div className="h-11 animate-pulse rounded-lg bg-bg-secondary" />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => <div key={i} className={`${block} h-28`} />)}
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {[0, 1, 2, 3, 4, 5].map((i) => <div key={i} className={`${block} h-48`} />)}
      </div>
    </PageContainer>
  );
}

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
  const reloadQuietly = useCallback(() => { void reload(); }, [reload]);

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

  // Live: the registry or the Apple satellite of this device changed, or one of its commands (an acknowledged lost
  // mode changes the record without a DEVICE_UPDATED).
  useEffect(() => {
    const onChange = (p: { deviceId?: number; deviceIds?: number[] }) => {
      const ids = Array.isArray(p?.deviceIds) ? p.deviceIds.map(Number) : p?.deviceId !== undefined ? [Number(p.deviceId)] : null;
      if (ids === null || ids.includes(deviceId)) void reload();
    };
    const offs = [SocketEvents.DEVICE_UPDATED, SocketEvents.APPLE_DEVICE_CHANGED, SocketEvents.DEVICE_CONFIG_CHANGED, SocketEvents.MDM_COMMAND_CHANGED]
      .map((ev) => registerSocketListener(ev, onChange));
    return () => offs.forEach((off) => off());
  }, [deviceId, reload]);

  const canWrite = device ? canWriteDevice(device.id, device.groupId) : false;
  // The actions of a lost or stolen device, whatever its channel (header, banner, panel, location card).
  const deviceActions = useDeviceActions(device, { canAct: canWrite, onQueued: reloadQuietly });
  // "See the location" of the lost mode banner: the location card shows its positions once (an explicit request,
  // journaled by the server), then the request is consumed so that coming back to the overview reads nothing.
  const [locationReveal, setLocationReveal] = useState(0);

  const backLink = (
    <Link to="/devices" className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary coarse:min-h-10">
      <ArrowLeft size={14} className="shrink-0" />
      {t('deviceSummary.back') || 'Back to devices'}
    </Link>
  );

  if (isLoading) {
    return (
      <DeviceSkeleton
        note={tenantSwitchTarget ? (t('deviceSummary.switchingTenant', { tenant: tenantSwitchTarget }) || `Switching to ${tenantSwitchTarget}…`) : null}
      />
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

  const canManageDevices = isAdmin() || caps.includes('devices.manage');
  const canManagePolicies = isAdmin() || caps.includes('mdm.policies.manage');
  const managed = device.enrollmentState !== 'unenrolled';
  const collected = device.privacy?.collected ?? [];
  const tenantName = device.tenantName ?? tenants.find((tn) => tn.id === device.tenantId)?.name ?? `#${device.tenantId}`;
  const apple = device.apple;
  const channel = channelOf(device);
  const shownTabs = CHANNEL_TABS[channel];
  // A ?tab= of a tab this channel does not have falls back on the overview.
  const current: Tab = shownTabs.includes(tab) ? tab : 'overview';
  const pending = deviceActions.pendingCount ?? 0;
  const pendingBadge = pending > 0 ? (
    <span className={`min-w-5 rounded-full px-1.5 text-[11px] leading-5 tabular-nums ${current === 'commands' ? 'bg-white/20 text-white' : 'bg-accent/15 text-accent'}`}>
      {pending}{deviceActions.pendingMore ? '+' : ''}
    </span>
  ) : undefined;
  const allTabs: Record<Tab, SegmentedTab<Tab>> = {
    overview: { id: 'overview', label: t('deviceSummary.tabs.overview') || 'Overview', icon: <LayoutGrid size={15} /> },
    android: { id: 'android', label: t('deviceSummary.tabs.android') || 'Android', icon: <Smartphone size={15} /> },
    configuration: { id: 'configuration', label: t('deviceSummary.tabs.configuration') || 'Configuration', icon: <SlidersHorizontal size={15} /> },
    apps: { id: 'apps', label: t('deviceSummary.tabs.apps') || 'Applications', icon: <Package size={15} /> },
    profiles: { id: 'profiles', label: t('deviceSummary.tabs.profiles') || 'Profiles', icon: <ScrollText size={15} /> },
    certificates: { id: 'certificates', label: t('deviceSummary.tabs.certificates') || 'Certificates', icon: <KeyRound size={15} /> },
    commands: { id: 'commands', label: t('deviceSummary.tabs.commands') || 'Commands', icon: <TerminalSquare size={15} />, badge: pendingBadge },
    history: { id: 'history', label: t('deviceSummary.tabs.history') || 'History', icon: <History size={15} /> },
    actions: { id: 'actions', label: t('deviceSummary.tabs.actions') || 'Actions', icon: <Zap size={15} /> },
  };
  const tabs = shownTabs.map((k) => allTabs[k]);
  const showLocation = () => {
    setTab('overview');
    setLocationReveal(Date.now());
    window.requestAnimationFrame(() => document.getElementById(LOCATION_ANCHOR)?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  };

  return (
    <PageContainer className="space-y-5">
      {backLink}

      <DeviceHero device={device} tenantName={tenantName} actions={deviceActions} canWrite={canWrite} onEdit={() => setEditOpen(true)} />
      <LostModeBanner device={device} actions={deviceActions} onShowLocation={showLocation} />

      <SegmentedTabs tabs={tabs} value={current} onChange={setTab} ariaLabel={t('deviceSummary.tabs.label') || 'Sections of the device'} />

      {current === 'overview' && (
        <DeviceOverview
          device={device}
          tenantName={tenantName}
          actions={deviceActions}
          canWrite={canWrite}
          canManageDevices={canManageDevices}
          canSyncDdm={canWrite && device.tenantId === currentTenantId}
          onGroup={() => setGroupOpen(true)}
          onOwnership={() => setOwnershipOpen(true)}
          onEndUser={() => setUserOpen(true)}
          locationReveal={locationReveal}
          onLocationRevealed={() => setLocationReveal(0)}
        />
      )}
      {current === 'configuration' && <DeviceConfigurationTab deviceId={device.id} groupId={device.groupId} canManagePolicies={canManagePolicies && canWrite} />}
      {current === 'apps' && <DeviceAppsTab deviceId={device.id} collected={collected} />}
      {current === 'profiles' && <DeviceProfilesTab deviceId={device.id} lastAt={apple?.lastInventory.profiles} />}
      {current === 'certificates' && <DeviceCertificatesTab deviceId={device.id} collected={collected} lastAt={apple?.lastInventory.certificates} />}
      {current === 'commands' && (channel === 'legacy_agent'
        ? <LegacyCommandsTab deviceId={device.id} canAct={canWrite} onChanged={deviceActions.reload} />
        : <DeviceCommandsTab deviceId={device.id} canAct={canWrite} />)}
      {current === 'history' && <DeviceHistoryTab deviceId={device.id} />}
      {current === 'android' && channel === 'amapi' && <AndroidDeviceTab deviceId={device.id} canAct={canWrite} />}
      {current === 'actions' && (channel === 'amapi'
        ? <AndroidDeviceActions deviceId={device.id} ownership={device.ownership} canAct={canWrite} onQueued={() => { void reload(); deviceActions.reload(); }} />
        : channel === 'legacy_agent'
          ? <LegacyActionsTab deviceId={device.id} canAct={canWrite} onQueued={() => { void reload(); deviceActions.reload(); }} />
          : <DeviceActionsTab deviceId={device.id} managed={managed} canAct={canWrite} onQueued={() => { void reload(); deviceActions.reload(); }} />)}

      {deviceActions.dialogs}
      <EditDeviceDialog open={editOpen} onClose={() => setEditOpen(false)} device={device} onSaved={setDevice} />
      <GroupDialog open={groupOpen} onClose={() => setGroupOpen(false)} device={device} onDone={() => { void reload(); }} />
      <EndUserDialog open={userOpen} onClose={() => setUserOpen(false)} device={device} onDone={() => { void reload(); }} />
      <OwnershipDialog open={ownershipOpen} onClose={() => setOwnershipOpen(false)} device={device} onDone={() => { void reload(); }} />
    </PageContainer>
  );
}

const inputCls = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';

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
      if (saved === null) {
        toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
      } else {
        onSaved(saved);
        toast.success(t('common.saved') || 'Saved');
      }
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
  // The move is previewed and guarded like a change of assignments (S12): useDeviceMove asks for its confirmation
  // when it touches the configuration of the device.
  const move = useDeviceMove((_m, outcome) => { if (outcome !== 'failed') { onDone(); onClose(); } });
  const save = async () => {
    setBusy(true);
    try {
      await move.request({ deviceIds: [device.id], groupId, single: true });
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
    {move.dialog}
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
    </>
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

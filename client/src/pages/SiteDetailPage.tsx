import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { Archive, ArchiveRestore, ArrowLeft, FolderOpen, MapPin, MonitorSmartphone, Pencil, Phone, Plus, QrCode, Smartphone, Unlink } from 'lucide-react';
import type { SiteDetail, SiteDeviceView } from '@obligarth/shared';
import { sitesApi } from '@/api/sites.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { DeviceMultiSelect } from '@/components/common/DeviceMultiSelect';
import { PlatformIcon, formatBytes, shortAge } from '@/components/mdm/PlatformIcon';
import { useDeviceMove } from '@/components/mdm/DeviceMoveChange';
import { FileNotCreatedBadge, SiteCountsPills, SiteStateBadge, SortHeader, compareSort, reasonSentence, useSiteChange, useSort } from '@/components/sites/siteUi';
import { SiteEditDialog, siteErrorMessage } from '@/components/sites/SiteEditDialog';
import { SiteSheetDialog } from '@/components/sites/SiteSheetDialog';
import { SiteScreenQrDialog } from '@/components/sites/SiteScreenQrDialog';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage } from '@/utils/apiError';

// The page of a site (lot P1-SITE §2.4): its name, city, contact, group and values (editable), its phones with their
// state and what to do in plain words, and the buttons "Enroll a phone" (the printable sheet with its QR code: lot
// P1-QR, SiteSheetDialog) and "Add existing phones". A phone attached to a site with a group is offered the guarded move into it. The
// phones sort by name, state (not answering, to do, ready) or last contact.

type PhoneSort = 'label' | 'state' | 'contact';
const STATE_RANK: Record<SiteDeviceView['state'], number> = { stale: 0, todo: 1, ready: 2 };
const phoneValue = (d: SiteDeviceView, f: PhoneSort): string | number | null =>
  (f === 'label' ? d.label : f === 'state' ? STATE_RANK[d.state] : d.lastCheckinAt ? new Date(d.lastCheckinAt).getTime() : null);

export function SiteDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { t } = useTranslation();
  const confirm = useConfirm();
  const { isAdmin, permissions } = useAuthStore();
  const canManage = isAdmin() || (permissions?.tenantCapabilities ?? []).includes('devices.manage');
  // The enrollment sheet is a token of the bridge agent (lot P1-QR): the capability of the tokens.
  const canEnroll = isAdmin() || (permissions?.tenantCapabilities ?? []).includes('mdm.enrollment.manage');
  const [site, setSite] = useState<SiteDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editOpen, setEditOpen] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [sheetOpen, setSheetOpen] = useState(false);
  // The QR code on screen (no printing): for the platform's users (the MSP technicians), on top of the capability.
  const canScreenQr = canEnroll && isAdmin();
  const [screenOpen, setScreenOpen] = useState(false);
  const sort = useSort<PhoneSort>('state');

  const load = useCallback(() => {
    if (!id) return;
    sitesApi.get(id).then((s) => { setSite(s); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
  }, [id]);
  useEffect(() => { load(); }, [load]);
  const siteChange = useSiteChange(load);
  const phones = useMemo(() => [...(site?.devices ?? [])]
    .sort((a, b) => compareSort(phoneValue(a, sort.sortBy), phoneValue(b, sort.sortBy), sort.sortOrder) || a.label.localeCompare(b.label)),
  [site, sort.sortBy, sort.sortOrder]);
  const groupMove = useDeviceMove((_m, outcome) => { if (outcome !== 'failed') load(); });

  const backLink = (
    <Link to="/sites" className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary coarse:min-h-10">
      <ArrowLeft size={14} className="shrink-0" />{t('sites.back') || 'Back to the sites'}
    </Link>
  );
  if (error && !site) return <PageContainer className="space-y-4">{backLink}<p className="text-sm text-red-400">{error}</p></PageContainer>;
  if (!site) return <PageContainer className="space-y-4">{backLink}<p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p></PageContainer>;

  const archived = !!site.archivedAt;
  const outside = site.groupId === null ? [] : site.devices.filter((d) => d.groupId !== site.groupId).map((d) => d.id);
  const toggleArchive = async () => {
    if (!archived) {
      const ok = await confirm({ message: t('sites.archiveConfirm', { name: site.name }) || `Archive the site ${site.name}? It keeps its values; an archived site takes no phone, and its enrollment sheets stop working.`, danger: true });
      if (!ok) return;
    }
    try {
      setSite(await sitesApi.archive(site.id, !archived));
      toast.success(archived ? (t('sites.restored') || 'Site restored') : (t('sites.archivedToast') || 'Site archived'));
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    }
  };
  const detach = async (deviceId: number, label: string) => {
    const ok = await confirm({ message: t('sites.detachConfirm', { name: label }) || `Detach ${label} from the site? Its files stop reading the values of the site.` });
    if (!ok) return;
    await siteChange.change(() => sitesApi.setDeviceSite(deviceId, null), { single: true });
  };

  const valueEntries = Object.entries(site.values).sort(([a], [b]) => a.localeCompare(b));
  return (
    <PageContainer className="space-y-5">
      {backLink}

      <div className="rounded-xl bg-bg-secondary p-4 sm:p-5">
        <div className="flex flex-wrap items-start gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-accent/15 text-accent"><MapPin className="h-6 w-6" /></div>
          <div className="min-w-0 flex-1">
            <h1 className="flex flex-wrap items-center gap-2 text-xl font-bold text-text-primary">
              {anonymize(site.name)}
              <span className="font-mono text-sm font-normal text-text-muted">{anonymize(site.code)}</span>
              {archived && <span className="rounded-full bg-bg-tertiary px-2 py-0.5 text-[11px] font-normal text-text-muted">{t('sites.archived') || 'Archived'}</span>}
            </h1>
            <p className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-text-secondary">
              {site.city && <span className="inline-flex items-center gap-1"><MapPin className="h-3.5 w-3.5" />{anonymize(site.city)}</span>}
              {site.contact && <span className="inline-flex items-center gap-1"><Phone className="h-3.5 w-3.5" />{anonymize(site.contact)}</span>}
              <span className="inline-flex items-center gap-1"><FolderOpen className="h-3.5 w-3.5" />{site.groupName ? anonymize(site.groupName) : (t('sites.noGroup') || 'No group')}</span>
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2"><SiteCountsPills counts={site.counts} /><FileNotCreatedBadge count={site.counts.fileNotCreated} /></div>
          </div>
          {(canManage || canEnroll) && (
            <div className="flex flex-wrap gap-2">
              {/* The printable sheet with its QR code (lot P1-QR §3.2). */}
              {canEnroll && !archived && (
                <Button size="sm" onClick={() => setSheetOpen(true)}>
                  <QrCode className="mr-1 h-4 w-4" />{t('sites.enroll') || 'Enroll a phone'}
                </Button>
              )}
              {canScreenQr && !archived && (
                <Button size="sm" variant="secondary" onClick={() => setScreenOpen(true)}>
                  <MonitorSmartphone className="mr-1 h-4 w-4" />{t('sites.screen.button') || 'QR code on screen'}
                </Button>
              )}
              {canManage && !archived && <Button size="sm" variant="secondary" onClick={() => setAddOpen(true)}><Plus className="mr-1 h-4 w-4" />{t('sites.addExisting') || 'Add existing phones'}</Button>}
              {canManage && !archived && <Button size="sm" variant="secondary" onClick={() => setEditOpen(true)}><Pencil className="mr-1 h-4 w-4" />{t('common.edit') || 'Edit'}</Button>}
              {canManage && (
                <Button size="sm" variant="ghost" onClick={() => { void toggleArchive(); }}>
                  {archived ? <ArchiveRestore className="mr-1 h-4 w-4" /> : <Archive className="mr-1 h-4 w-4" />}
                  {archived ? (t('sites.restore') || 'Restore') : (t('sites.archive') || 'Archive')}
                </Button>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-xl bg-bg-secondary p-4 lg:col-span-1">
          <h2 className="text-[10px] uppercase tracking-wider text-text-muted">{t('sites.fields.values') || 'Values of the site'}</h2>
          {valueEntries.length === 0 ? (
            <p className="mt-2 text-sm text-text-muted">{t('sites.noValues') || 'No value. The file templates read them as {{site.<key>}}.'}</p>
          ) : (
            <dl className="mt-2 space-y-1">
              {valueEntries.map(([k, v]) => (
                <div key={k} className="flex items-baseline gap-3 rounded-lg px-2 py-1 text-sm hover:bg-bg-tertiary">
                  <dt className="w-28 shrink-0 truncate font-mono text-xs text-text-muted">{k}</dt>
                  <dd className="min-w-0 flex-1 break-words text-text-primary">{anonymize(v)}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>

        <div className="rounded-xl bg-bg-secondary py-1 lg:col-span-2">
          <div className="flex items-center justify-between px-4 py-2">
            <h2 className="text-[10px] uppercase tracking-wider text-text-muted">{t('sites.phones', { count: site.devices.length }) || `Phones (${site.devices.length})`}</h2>
            {canManage && outside.length > 0 && site.groupId !== null && (
              <Button size="sm" variant="ghost" onClick={() => { void groupMove.request({ deviceIds: outside, groupId: site.groupId }); }}>
                <FolderOpen className="mr-1 h-4 w-4" />{t('sites.fileInGroup', { count: outside.length }) || `File ${outside.length} phone(s) in the group of the site`}
              </Button>
            )}
          </div>
          {site.devices.length > 1 && (
            <div className="flex items-center gap-4 px-4 pb-1 text-[10px] text-text-muted">
              <SortHeader field="label" label={t('sites.sortPhones.label') || 'Name'} sortBy={sort.sortBy} sortOrder={sort.sortOrder} onClick={sort.toggle} />
              <SortHeader field="state" label={t('sites.sortPhones.state') || 'State'} sortBy={sort.sortBy} sortOrder={sort.sortOrder} onClick={sort.toggle} />
              <SortHeader field="contact" label={t('sites.sortPhones.contact') || 'Last contact'} sortBy={sort.sortBy} sortOrder={sort.sortOrder} onClick={sort.toggle} />
            </div>
          )}
          {site.devices.length === 0 ? (
            <p className="px-4 pb-4 text-sm text-text-muted">{t('sites.noPhones') || 'No phone on this site yet.'}</p>
          ) : phones.map((d) => (
            <div key={d.id} className="group px-4 py-2.5 transition-colors hover:bg-bg-tertiary">
              <div className="flex items-center gap-3">
                <PlatformIcon platform={d.platform} className="h-4 w-4 shrink-0 text-text-muted" />
                <Link to={`/devices/${d.id}`} className="min-w-0 flex-1 truncate text-sm font-medium text-text-primary hover:text-accent">{anonymize(d.label)}</Link>
                <SiteStateBadge state={d.state} />
                <span className="hidden text-xs tabular-nums text-text-muted sm:inline" title={d.lastCheckinAt ?? undefined}>
                  {d.lastCheckinAt ? shortAge(d.lastCheckinAt) : (t('mdm.contactState.never') || 'Never seen')}
                </span>
                {canManage && (
                  <button type="button" onClick={() => { void detach(d.id, d.label); }} aria-label={t('sites.detach') || 'Detach from the site'} title={t('sites.detach') || 'Detach from the site'}
                    className="rounded p-1.5 text-text-muted opacity-0 hover:bg-bg-secondary hover:text-red-400 group-hover:opacity-100 coarse:min-h-10 coarse:min-w-10 coarse:opacity-100">
                    <Unlink className="h-4 w-4" />
                  </button>
                )}
              </div>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-3 pl-7 text-[11px] text-text-muted">
                {d.agentVersionName && <span><Smartphone className="mr-1 inline h-3 w-3" />{t('sites.agentVersion', { version: d.agentVersionName }) || `Agent ${d.agentVersionName}`}</span>}
                {d.storageAvailableBytes !== null && <span>{t('sites.freeStorage', { size: formatBytes(d.storageAvailableBytes) }) || `${formatBytes(d.storageAvailableBytes)} free`}</span>}
                {site.groupId !== null && d.groupId !== site.groupId && <span className="text-amber-400">{t('sites.outsideGroup') || 'Not in the group of the site'}</span>}
              </div>
              {d.reasons.length > 0 && (
                <ul className="mt-1 space-y-0.5 pl-7">
                  {d.reasons.map((r) => (
                    <li key={r} className={clsx('text-xs', r === 'no_contact' || r === 'file_not_created' || r === 'appconfig_unresolved' ? 'text-red-400' : 'text-amber-400')}>
                      {reasonSentence(t, r, r === 'appconfig_unresolved' ? d.missingAppConfigVariables ?? [] : d.missingVariables)}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      </div>

      {siteChange.dialog}
      {groupMove.dialog}
      {sheetOpen && <SiteSheetDialog site={site} onClose={() => setSheetOpen(false)} />}
      {screenOpen && <SiteScreenQrDialog site={site} onClose={() => setScreenOpen(false)} />}
      <SiteEditDialog open={editOpen} site={site} onClose={() => setEditOpen(false)} onSaved={(s) => { setSite(s); setEditOpen(false); }} />
      <AddPhonesDialog open={addOpen} site={site} onClose={() => setAddOpen(false)}
        onAdd={async (ids) => { setAddOpen(false); await siteChange.change(() => sitesApi.attach(site.id, ids)); }} />
    </PageContainer>
  );
}

/** Existing phones attached to the site (500 at most at once). */
function AddPhonesDialog({ open, site, onClose, onAdd }: { open: boolean; site: SiteDetail; onClose: () => void; onAdd: (ids: number[]) => Promise<void> }) {
  const { t } = useTranslation();
  const [ids, setIds] = useState<number[]>([]);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) setIds([]); }, [open]);
  const add = async () => {
    setBusy(true);
    try { await onAdd(ids.filter((i) => !site.devices.some((d) => d.id === i)).slice(0, 500)); } catch (err) { toast.error(siteErrorMessage(err)); } finally { setBusy(false); }
  };
  return (
    <Modal open={open} onClose={() => { if (!busy) onClose(); }} size="lg" title={t('sites.addExistingTitle', { name: site.name }) || `Add phones to ${site.name}`}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={add} loading={busy} disabled={ids.length === 0}>{t('sites.addCount', { count: ids.length }) || `Add (${ids.length})`}</Button>
        </>
      )}>
      <p className="mb-2 text-xs text-text-muted">
        {t('sites.addExistingHint') || 'Their files are made again with the values of the site. A phone already on another site moves to this one.'}
      </p>
      <DeviceMultiSelect selectedIds={ids} onChange={setIds} />
    </Modal>
  );
}

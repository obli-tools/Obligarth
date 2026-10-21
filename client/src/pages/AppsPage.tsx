import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AppWindow, Archive, Plus, RefreshCw, Search, ShoppingBag } from 'lucide-react';
import { SocketEvents, type AppCatalogEntry, type AppDetail, type VppAssetView } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { integrationsApi } from '@/api/integrations.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { registerSocketListener } from '@/socket/socketListeners';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Drawer } from '@/components/common/Drawer';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { AssignmentsPanel } from '@/components/mdm/Assignments';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The catalog of apps (modele-donnees-mdm §8, lot C4): the apps of the tenant (App Store and Custom Apps of Apple
// Business, licensed by Apps and Books), their licences, what the inventory shows of them, their delivery, and their
// assignments (with their options) through the impact preview like a policy's. Reading: any member; writing:
// mdm.apps.manage. An app is added from a licence of the tenant (the content tokens of the Integrations tab) or by
// its App Store id; its bundle identifier and name are typed (no call to Apple from the console). The Android apps of
// the tenant (lot AN-E) are listed here too; they are added from managed Google Play and opened on their own page
// (/apps/android).

const fieldCls = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';

function errorToast(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 8000 });
}

export function AppsPage() {
  const { t } = useTranslation();
  const { isAdmin, permissions } = useAuthStore();
  const caps = permissions?.tenantCapabilities ?? [];
  const canManage = isAdmin() || caps.includes('mdm.apps.manage');
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [apps, setApps] = useState<AppCatalogEntry[] | null>(null);
  const [q, setQ] = useState('');
  const [archived, setArchived] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const selected = Number(params.get('app')) || null;
  const select = (id: number | null) => setParams((prev) => {
    const p = new URLSearchParams(prev);
    if (id) p.set('app', String(id)); else p.delete('app');
    return p;
  }, { replace: true });

  const load = useCallback(() => {
    mdmApi.listApps({ archived, q: q.trim() || undefined })
      .then((list) => { setApps(list); setError(null); })
      .catch((err) => { setApps([]); setError(apiErrorMessage(err)); });
  }, [archived, q]);
  useEffect(() => {
    const timer = setTimeout(load, 200);
    return () => clearTimeout(timer);
  }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.POLICY_CHANGED, () => load()), [load]);
  useEffect(() => registerSocketListener(SocketEvents.INTEGRATION_CHANGED, () => load()), [load]);

  return (
    <PageContainer className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{t('apps.title') || 'Apps'}</h1>
        <p className="mt-1 text-sm text-text-muted">{t('apps.subtitle') || 'The apps of the tenant, licensed by Apps and Books, and the devices they are installed on.'}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('apps.search') || 'Search an app…'}
            className="w-full pl-9 pr-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
        </div>
        <label className="flex items-center gap-1.5 text-xs text-text-muted">
          <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} />{t('apps.showArchived') || 'Show the archived apps'}
        </label>
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
        {canManage && (
          <span className="ml-auto flex flex-wrap gap-2">
            <Link to="/apps/android" className="inline-flex items-center rounded-md px-3 py-1.5 text-sm font-medium bg-bg-tertiary text-text-primary hover:bg-bg-hover coarse:min-h-10">
              <ShoppingBag className="w-4 h-4 mr-1" />{t('androidApps.openCatalog') || 'Android apps'}
            </Link>
            <Button size="sm" onClick={() => setAdding(true)}><Plus className="w-4 h-4 mr-1" />{t('apps.add') || 'Add an app'}</Button>
          </span>
        )}
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {apps === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : apps.length === 0 ? (
          <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">
            <p className="font-medium text-text-primary mb-1">{t('apps.empty') || 'No app yet'}</p>
            <p className="text-sm">{t('apps.emptyHint') || 'Connect a content token of Apps and Books in the Integrations tab, then add the apps whose licences the tenant holds.'}</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl bg-bg-secondary">
            <table className="w-full text-sm">
              <thead className="text-xs text-text-muted">
                <tr className="text-left">
                  <th className="font-medium px-4 py-2">{t('apps.name') || 'Name'}</th>
                  <th className="font-medium px-3 py-2">{t('apps.identifier') || 'Identifier'}</th>
                  <th className="font-medium px-3 py-2">{t('apps.licences') || 'Licences'}</th>
                  <th className="font-medium px-3 py-2 text-right">{t('apps.assignments') || 'Assignments'}</th>
                  <th className="font-medium px-4 py-2">{t('apps.updated') || 'Updated'}</th>
                </tr>
              </thead>
              <tbody>
                {apps.map((a) => (
                  <tr key={a.id} className="border-t border-border/50 hover:bg-bg-tertiary cursor-pointer"
                    onClick={() => (a.platformFamily === 'android' ? (canManage ? navigate(`/apps/android?app=${a.uuid}`) : undefined) : select(a.id))}>
                    <td className="px-4 py-2.5">
                      <span className="font-medium text-text-primary">{a.name}</span>
                      {a.platformFamily === 'android' && <span className="ml-2"><StateBadge tone="green" label={t('androidApps.badge') || 'Android'} /></span>}
                      {a.archivedAt && <span className="ml-2"><StateBadge tone="gray" label={t('apps.archived') || 'Archived'} /></span>}
                      {a.publisher && <span className="block text-xs text-text-muted">{a.publisher}</span>}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs text-text-secondary">{a.identifier}</td>
                    <td className="px-3 py-2.5 text-text-secondary">
                      {a.platformFamily === 'android' ? <span className="text-text-muted">—</span> : a.licenses ? (t('apps.licenceCounts', { available: a.licenses.available, total: a.licenses.total }) || `${a.licenses.available} available of ${a.licenses.total}`)
                        : <span className="text-amber-500">{t('apps.noLicence') || 'No licence'}</span>}
                    </td>
                    <td className="px-3 py-2.5 text-right tabular-nums text-text-secondary">{a.assignments}</td>
                    <td className="px-4 py-2.5 text-xs text-text-muted">{formatDateTime(a.updatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      {adding && <AddAppModal onClose={() => setAdding(false)} onCreated={(a) => { setAdding(false); load(); select(a.id); }} />}
      <Drawer open={selected !== null} onClose={() => select(null)} size="lg" title={t('apps.detailTitle') || 'App'} icon={<AppWindow className="w-5 h-5 text-accent" />}>
        {selected !== null && <AppDetailPanel id={selected} canManage={canManage} onChanged={load} onArchived={() => { select(null); load(); }} />}
      </Drawer>
    </PageContainer>
  );
}

function AddAppModal({ onClose, onCreated }: { onClose: () => void; onCreated: (a: AppCatalogEntry) => void }) {
  const { t } = useTranslation();
  const [assets, setAssets] = useState<VppAssetView[]>([]);
  const [assetId, setAssetId] = useState<number | ''>('');
  const [storeId, setStoreId] = useState('');
  const [kind, setKind] = useState<'app_store' | 'custom'>('app_store');
  const [identifier, setIdentifier] = useState('');
  const [name, setName] = useState('');
  const [publisher, setPublisher] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { integrationsApi.vppAssets().then((l) => setAssets(l.filter((a) => a.productType !== 'Book' && a.appId === null))).catch(() => setAssets([])); }, []);
  useEffect(() => {
    const a = assets.find((x) => x.id === assetId);
    if (a) setStoreId(a.adamId);
  }, [assetId, assets]);
  const ok = /^[0-9]{1,20}$/.test(storeId) && /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(identifier) && name.trim().length > 0;
  const create = async () => {
    setBusy(true);
    try {
      const a = await mdmApi.createApp({ kind, storeId, identifier: identifier.trim(), name: name.trim(), publisher: publisher.trim() || null });
      toast.success(t('apps.created') || 'App added to the catalog');
      onCreated(a);
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={() => { if (!busy) onClose(); }} title={t('apps.add') || 'Add an app'}
      footer={<Button size="sm" loading={busy} disabled={!ok} onClick={create}>{t('common.create') || 'Create'}</Button>}>
      <div className="space-y-3 text-sm">
        <label className="block">{t('apps.fromLicence') || 'From a licence of the tenant'}
          <select className={fieldCls} value={assetId} onChange={(e) => setAssetId(e.target.value ? Number(e.target.value) : '')}>
            <option value="">{assets.length ? (t('apps.pickLicence') || 'Pick a licence…') : (t('apps.noFreeLicence') || 'No licence without an app of the catalog')}</option>
            {assets.map((a) => (
              <option key={a.id} value={a.id}>{`${a.adamId} · ${a.pricingParam} · ${t('apps.licenceCounts', { available: a.availableCount, total: a.totalCount }) || `${a.availableCount} available of ${a.totalCount}`}`}</option>
            ))}
          </select>
        </label>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block">{t('apps.storeId') || 'App Store id'}
            <input className={fieldCls} inputMode="numeric" value={storeId} onChange={(e) => { setStoreId(e.target.value.trim()); setAssetId(''); }} placeholder="361309726" />
          </label>
          <label className="block">{t('apps.kind') || 'Kind'}
            <select className={fieldCls} value={kind} onChange={(e) => setKind(e.target.value as 'app_store' | 'custom')}>
              <option value="app_store">{t('apps.kindAppStore') || 'App Store'}</option>
              <option value="custom">{t('apps.kindCustom') || 'Custom App (Apple Business)'}</option>
            </select>
          </label>
        </div>
        <label className="block">{t('apps.identifier') || 'Identifier'}
          <input className={`${fieldCls} font-mono`} value={identifier} onChange={(e) => setIdentifier(e.target.value)} placeholder="com.example.app" autoCapitalize="off" spellCheck={false} />
        </label>
        <label className="block">{t('apps.name') || 'Name'}
          <input className={fieldCls} maxLength={255} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="block">{t('apps.publisher') || 'Publisher'}
          <input className={fieldCls} maxLength={255} value={publisher} onChange={(e) => setPublisher(e.target.value)} />
        </label>
        <p className="text-xs text-text-muted">{t('apps.addHelp') || 'The identifier is the bundle identifier of the app; it must match what the devices report. Without a licence, the app is listed but not installed.'}</p>
      </div>
    </Modal>
  );
}

const DELIVERY_TONE: Record<string, 'green' | 'gray' | 'amber' | 'red' | 'blue'> = {
  applied: 'green', pending: 'blue', delivering: 'blue', error: 'red', not_applicable: 'amber', removing: 'gray',
};

function AppDetailPanel({ id, canManage, onChanged, onArchived }: { id: number; canManage: boolean; onChanged: () => void; onArchived: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [app, setApp] = useState<AppDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    mdmApi.getApp(id).then((a) => { setApp(a); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
  }, [id]);
  useEffect(() => { load(); }, [load]);
  const delivery = useMemo(() => Object.entries(app?.delivery ?? {}).sort(([a], [b]) => a.localeCompare(b)), [app]);
  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!app) return <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>;
  return (
    <div className="space-y-4 text-sm">
      <div>
        <p className="text-lg font-semibold text-text-primary">{app.name}</p>
        <p className="font-mono text-xs text-text-muted">{app.identifier} · {app.storeId}</p>
        {app.publisher && <p className="text-xs text-text-muted">{app.publisher}</p>}
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
        <div><dt className="text-text-muted">{t('apps.kind') || 'Kind'}</dt><dd>{trCode(`apps.kinds.${app.kind}`, app.kind)}</dd></div>
        <div><dt className="text-text-muted">{t('apps.platforms') || 'Platforms'}</dt><dd>{app.supportedPlatforms.length ? app.supportedPlatforms.join(', ') : '—'}</dd></div>
        <div><dt className="text-text-muted">{t('apps.licences') || 'Licences'}</dt>
          <dd>{app.licenses ? (t('apps.licenceDetail', { available: app.licenses.available, assigned: app.licenses.assigned, total: app.licenses.total }) || `${app.licenses.available} available, ${app.licenses.assigned} assigned, ${app.licenses.total} in all`) : (t('apps.noLicence') || 'No licence')}</dd></div>
        <div><dt className="text-text-muted">{t('apps.metadataRefreshed') || 'Synchronised'}</dt><dd>{app.metadataRefreshedAt ? formatDateTime(app.metadataRefreshedAt) : '—'}</dd></div>
      </dl>
      <section className="space-y-1">
        <h3 className="text-sm font-semibold text-text-primary">{t('apps.inventory') || 'On the devices'}</h3>
        <p className="text-xs text-text-secondary">
          {t('apps.installCounts', { installed: app.installs.installed, managed: app.installs.managed, failed: app.installs.failed })
            || `${app.installs.installed} device(s), ${app.installs.managed} managed, ${app.installs.failed} in error`}
        </p>
        {app.installs.versions.length > 0 && (
          <p className="text-xs text-text-muted">{app.installs.versions.map((v) => `${v.version} (${v.devices})`).join(' · ')}</p>
        )}
        {delivery.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            {delivery.map(([state, n]) => <StateBadge key={state} tone={DELIVERY_TONE[state] ?? 'gray'} label={`${trCode(`apps.delivery.${state}`, state)} · ${n}`} />)}
          </div>
        )}
      </section>
      {!app.archivedAt && (
        <AssignmentsPanel resource={{ id: app.id, tenantId: app.tenantId, name: app.name, type: 'app', published: true }} canManage={canManage}
          onChanged={() => { load(); onChanged(); }} />
      )}
      {canManage && !app.archivedAt && (
        <Button size="sm" variant="ghost" disabled={app.assignments > 0}
          title={app.assignments > 0 ? (t('apps.archiveBlocked') || 'Remove the assignments of this app first') : undefined}
          onClick={async () => {
            if (!(await confirm({ message: t('apps.confirmArchive', { name: app.name }) || `Archive the app ${app.name}?`, danger: true }))) return;
            try {
              await mdmApi.archiveApp(app.id);
              toast.success(t('apps.archivedDone') || 'App archived');
              onArchived();
            } catch (err) { errorToast(err); }
          }}><Archive className="w-4 h-4 mr-1" />{t('apps.archive') || 'Archive'}</Button>
      )}
    </div>
  );
}
